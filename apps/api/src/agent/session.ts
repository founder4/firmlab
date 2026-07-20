/**
 * The agent-session orchestrator — the deterministic skeleton the Phase-3 decision nodes reason within. This
 * code, not an LLM, drives the flow: triage ① → (deterministic extraction, if the agent chose it) → deterministic
 * preflight → target selection ② → pause for human approval before any emulation. The agent only picks branches
 * and interprets; every mechanical action (extraction, emulation) runs through the SAME job system the user
 * drives by hand, so nothing here is a bespoke, fragile path.
 *
 * A governor caps the run (steps/tokens/USD/time). Every node writes an auditable agent_step. An active session
 * pins its image against retention. All of this is behind FIRMLAB_AGENT via the caller's LlmConfig.
 */
import { randomUUID } from 'node:crypto';
import type { Architecture } from '@firmlab/core';
import type { LlmConfig } from '../llm.js';
import { runChrootService, runFullSystem } from '../providers/emulate-system.js';
import { runUserModeEmulation } from '../providers/emulate.js';
import { type ExtractResult, runExtraction } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { type RuntimeCapabilities, computeRuntimeCapabilities } from '../providers/preflight.js';
import {
  type AgentSessionRow,
  type AgentSessionStatus,
  type AgentStepRow,
  getDb,
  getImage,
  getJob,
  getSession,
  hasActiveSession,
  insertSession,
  insertStep,
  listJobs,
  listSteps,
  updateBinaryEmulationStatus,
  updateSession,
} from '../store.js';
import { Governor, ZERO_CONSUMED, loadGovernorBudget } from './governor.js';
import {
  type EmulationRung,
  type TargetSelectionDecision,
  gatherTargetSelectionContext,
  gatherTriageContext,
  runTargetSelectionNode,
  runTriageNode,
} from './nodes.js';

/** Poll a fire-and-forget job to a terminal state. Jobs are in-process, so a short poll is enough. */
async function waitForJob(
  jobId: string,
  timeoutMs = 15 * 60_000,
): Promise<{ status: string; result: unknown; error: string | null }> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const row = getJob(jobId);
    if (row && (row.status === 'done' || row.status === 'error')) {
      return { status: row.status, result: row.resultJson ? JSON.parse(row.resultJson) : null, error: row.error };
    }
    if (Date.now() > deadline) return { status: 'error', result: null, error: 'job timed out' };
    await new Promise((r) => setTimeout(r, 250));
  }
}

/** Append one transcript entry and return the row (seq is derived from what's already recorded). */
function recordStep(
  sessionId: string,
  node: string,
  status: string,
  input: unknown,
  output: unknown,
  rationale: string | null,
  model: string | null,
  inputTokens: number,
  outputTokens: number,
): void {
  const seq = listSteps(sessionId).length + 1;
  const row: AgentStepRow = {
    id: randomUUID().slice(0, 12),
    sessionId,
    seq,
    node,
    status,
    inputJson: input === undefined ? null : JSON.stringify(input),
    outputJson: output === undefined ? null : JSON.stringify(output),
    rationale,
    model,
    inputTokens,
    outputTokens,
    createdAt: Date.now(),
  };
  insertStep(row);
}

/** Persist the session's status + the governor's running tally in one place. */
function persist(session: AgentSessionRow, status: AgentSessionStatus, gov: Governor, haltReason: string | null): void {
  updateSession(session.id, status, JSON.stringify(gov.snapshot()), haltReason);
}

/**
 * Start a conscious-autonomy session over an image. Returns the created row immediately and drives the flow in
 * the background. Rejects (throws) if the image is missing or already has an active session (one at a time).
 */
export function startAgentSession(imageId: string, cfg: LlmConfig, goal: string | null = null): AgentSessionRow {
  if (!getImage(imageId)) throw new Error('Image not found');
  if (hasActiveSession(imageId)) throw new Error('An agent session is already active for this image');

  const budget = loadGovernorBudget();
  const now = Date.now();
  const session: AgentSessionRow = {
    id: randomUUID().slice(0, 12),
    imageId,
    status: 'running',
    goal,
    budgetJson: JSON.stringify(budget),
    consumedJson: JSON.stringify(ZERO_CONSUMED),
    haltReason: null,
    createdAt: now,
    updatedAt: now,
  };
  insertSession(session);
  void orchestrate(session, cfg).catch((err) => {
    const message = err instanceof Error ? err.message : String(err);
    recordStep(session.id, 'error', 'error', undefined, undefined, message, null, 0, 0);
    updateSession(session.id, 'error', session.consumedJson, message);
  });
  return session;
}

/** The deterministic flow. LLM calls happen only inside the two decision nodes. */
async function orchestrate(session: AgentSessionRow, cfg: LlmConfig): Promise<void> {
  const budget = loadGovernorBudget();
  const gov = new Governor(budget);
  const imageId = session.imageId;
  const imagePath = getImage(imageId)?.path;
  if (!imagePath) throw new Error('Image path missing');

  // --- Node ① Triage ---
  if (!gov.check().ok) return void persist(session, 'halted', gov, gov.check().reason);
  const triageCtx = await gatherTriageContext(imageId);
  if (!triageCtx) throw new Error('No static analysis for this image — cannot triage');
  const triage = await runTriageNode(triageCtx, cfg);
  gov.record(triage.result.model, triage.result.inputTokens ?? 0, triage.result.outputTokens ?? 0);
  recordStep(
    session.id,
    'triage',
    'ok',
    triageCtx,
    triage.decision,
    triage.decision.rationale,
    triage.result.model,
    triage.result.inputTokens ?? 0,
    triage.result.outputTokens ?? 0,
  );
  persist(session, 'running', gov, null);

  // --- Deterministic extraction, if the agent chose it and it hasn't run (same job the user would click) ---
  if (triage.decision.shouldExtract && !triageCtx.alreadyExtracted) {
    const jobId = startJob(imageId, 'extract', { by: 'agent', session: session.id }, (h) =>
      runExtraction(imageId, imagePath, h),
    );
    const job = await waitForJob(jobId);
    const ex = job.result as ExtractResult | null;
    const ok = job.status === 'done' && Boolean(ex?.rootfsPath);
    recordStep(
      session.id,
      'extraction',
      ok ? 'ok' : 'skipped',
      { cascade: triage.decision.extractionCascade },
      {
        extractor: ex?.extractor ?? null,
        rootfs: Boolean(ex?.rootfsPath),
        detectedArch: ex?.detectedArch ?? null,
        files: ex?.summary?.totalFiles ?? null,
      },
      ok
        ? 'Rootfs extracted deterministically.'
        : `Extraction did not yield a rootfs (${job.error ?? 'no tool / not extractable'}); continuing static-only.`,
      null,
      0,
      0,
    );
    persist(session, 'running', gov, null);
  }

  // --- Deterministic preflight — the honest ceiling that bounds node ② ---
  const caps = await computeRuntimeCapabilities(imageId);
  if (!caps) throw new Error('No identity for this image — cannot compute runtime capabilities');
  recordStep(
    session.id,
    'preflight',
    'ok',
    undefined,
    { strategy: caps.strategy, proofCeiling: caps.proofCeiling, reason: caps.reason },
    caps.reason,
    null,
    0,
    0,
  );

  // --- Node ② Target selection ---
  const budgetCheck = gov.check();
  if (!budgetCheck.ok) return void persist(session, 'halted', gov, budgetCheck.reason);
  const targetCtx = await gatherTargetSelectionContext(imageId, caps);
  const selection = await runTargetSelectionNode(targetCtx, caps, cfg);
  gov.record(selection.result.model, selection.result.inputTokens ?? 0, selection.result.outputTokens ?? 0);
  recordStep(
    session.id,
    'target-selection',
    'ok',
    targetCtx,
    selection.decision,
    selection.decision.rationale,
    selection.result.model,
    selection.result.inputTokens ?? 0,
    selection.result.outputTokens ?? 0,
  );

  // --- Pause for human approval if emulation is proposed; otherwise the session is complete ---
  if (selection.decision.emulationPlan.length > 0) {
    persist(session, 'awaiting_approval', gov, null);
  } else {
    persist(session, 'done', gov, null);
  }
}

/** Look up the emulation plan the target-selection node produced for a session. */
function planFor(sessionId: string): TargetSelectionDecision['emulationPlan'] {
  const step = [...listSteps(sessionId)].reverse().find((s) => s.node === 'target-selection' && s.outputJson);
  if (!step?.outputJson) return [];
  return (JSON.parse(step.outputJson) as TargetSelectionDecision).emulationPlan;
}

/** Map a completed emulation to an honest proof state, capped by what the deterministic preflight allows. */
function proofStateForEmulation(rung: EmulationRung, ran: boolean, cleanExit: boolean): string {
  if (!ran) return 'blocked_by_platform';
  if (rung === 'full-system') return cleanExit ? 'confirmed_full_system' : 'confirmed_in_emulation';
  return cleanExit ? 'confirmed_in_emulation' : 'needs_runtime_reproduction';
}

/**
 * Approve (and run) a proposed emulation for an awaiting session — the human-in-the-loop gate of Phase 3. The
 * mechanics are the existing deterministic emulation providers, run via the job system. On completion the
 * session is done; its proof state is capped by the preflight ceiling.
 */
export async function approveEmulation(sessionId: string, binary: string | null): Promise<AgentSessionRow> {
  const session = getSession(sessionId);
  if (!session) throw new Error('Session not found');
  if (session.status !== 'awaiting_approval')
    throw new Error(`Session is not awaiting approval (status: ${session.status})`);

  const plan = planFor(sessionId);
  const chosen = binary ? plan.find((p) => p.binary === binary) : plan[0];
  if (!chosen) throw new Error('No approved emulation target in the session plan');
  // Claim the session so a concurrent approve can't double-run the emulation.
  updateSession(sessionId, 'running', session.consumedJson, null);

  try {
    return await runApprovedEmulation(session, chosen);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    recordStep(
      sessionId,
      'emulation',
      'error',
      { binary: chosen.binary, rung: chosen.rung },
      undefined,
      message,
      null,
      0,
      0,
    );
    updateSession(sessionId, 'error', session.consumedJson, message);
    throw err;
  }
}

async function runApprovedEmulation(
  session: AgentSessionRow,
  chosen: TargetSelectionDecision['emulationPlan'][number],
): Promise<AgentSessionRow> {
  const sessionId = session.id;
  const caps = await computeRuntimeCapabilities(session.imageId);
  const arch = (caps?.arch ?? 'unknown') as Architecture;
  const extractJobResult = latestRootfs(session.imageId);
  const rootfsPath = extractJobResult?.rootfsPath ?? null;
  if (!rootfsPath) throw new Error('No extracted rootfs — cannot emulate');

  const jobId = startJob(
    session.imageId,
    'emulate',
    { by: 'agent', session: sessionId, binary: chosen.binary, rung: chosen.rung },
    async (h) => {
      if (chosen.rung === 'chroot-service') return runChrootService(arch, rootfsPath, chosen.binary, h);
      if (chosen.rung === 'full-system') return runFullSystem(arch, rootfsPath, 8080, h);
      return runUserModeEmulation(arch, rootfsPath, chosen.binary, h);
    },
  );
  const job = await waitForJob(jobId);

  const res = job.result as { ran?: boolean; exitCode?: number | null; proofState?: string; timedOut?: boolean } | null;
  const ran = Boolean(res?.ran);
  const cleanExit = res?.exitCode === 0;
  // System runners already return an honest proofState; the user-mode runner does not, so derive one.
  const proofState = res?.proofState ?? proofStateForEmulation(chosen.rung, ran, cleanExit);
  updateBinaryEmulationStatus(session.imageId, chosen.binary, proofState);

  recordStep(
    sessionId,
    'emulation',
    job.status === 'done' ? 'ok' : 'error',
    { binary: chosen.binary, rung: chosen.rung },
    { ran, exitCode: res?.exitCode ?? null, proofState, timedOut: Boolean(res?.timedOut) },
    `Approved ${chosen.rung} emulation of ${chosen.binary} → ${proofState} (proves the sandbox, not the device).`,
    null,
    0,
    0,
  );
  // Emulation runs no LLM turn, so the consumed budget is unchanged — persist it verbatim, session complete.
  updateSession(sessionId, 'done', session.consumedJson, null);
  return getSession(sessionId) as AgentSessionRow;
}

/** Operator declines the proposed emulation — the session closes, honestly, with nothing run. */
export function declineEmulation(sessionId: string): AgentSessionRow {
  const session = getSession(sessionId);
  if (!session) throw new Error('Session not found');
  if (session.status !== 'awaiting_approval')
    throw new Error(`Session is not awaiting approval (status: ${session.status})`);
  recordStep(
    sessionId,
    'emulation',
    'skipped',
    undefined,
    undefined,
    'Operator declined the proposed emulation.',
    null,
    0,
    0,
  );
  updateSession(sessionId, 'done', session.consumedJson, 'operator declined emulation');
  return getSession(sessionId) as AgentSessionRow;
}

/** Find the latest successfully-extracted rootfs for an image via the extract job result. */
function latestRootfs(imageId: string): ExtractResult | null {
  const job = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return job?.resultJson ? (JSON.parse(job.resultJson) as ExtractResult) : null;
}

/**
 * On startup, any session left `running` was interrupted by a restart (its async is gone) — mark it errored so
 * the transcript stays honest. `awaiting_approval` sessions are a legitimate durable pause and are kept.
 */
export function reconcileSessions(): void {
  getDb()
    .prepare(
      "UPDATE agent_session SET status = 'error', haltReason = 'interrupted by restart', updatedAt = ? WHERE status = 'running'",
    )
    .run(Date.now());
}
