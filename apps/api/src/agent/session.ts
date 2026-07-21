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
import { runCopilot } from '../copilot.js';
import { deviceFamilyKey, recordReachabilityPrior } from '../corpus.js';
import { type FindingDraft, syncFindings } from '../findings.js';
import { loadLlmConfig } from '../llm.js';
import type { LlmConfig } from '../llm.js';
import { type DecompileResult, resolveInsideRootfs, runDecompile } from '../providers/decompile.js';
import { runChrootService, runFullSystem } from '../providers/emulate-system.js';
import { runUserModeEmulation } from '../providers/emulate.js';
import { type ExtractResult, runExtraction } from '../providers/extract.js';
import { detectIsolation, runIsolated } from '../providers/isolate.js';
import { startJob } from '../providers/jobs.js';
import { QEMU_USER_BY_ARCH, type RuntimeCapabilities, computeRuntimeCapabilities } from '../providers/preflight.js';
import { type RenodeResult, renodeHintsFrom, runRenode } from '../providers/renode.js';
import { interpretTriggerRun, planDelivery } from '../providers/trigger.js';
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
  listBinaries,
  listFindings,
  listJobs,
  listSteps,
  updateBinaryEmulationStatus,
  updateFindingProofState,
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
import { type ZerodayCandidate, gatherZerodayContext, runZerodayNode } from './zeroday.js';

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

  // --- Node ④ Zero-day + Phase-4 emulation gate (auto-run under isolation, or human approval) ---
  await runPhase4(session, gov, caps, selection.decision.emulationPlan, cfg);

  // --- Node ⑤ Synthesis: a cited narrative over the session's findings, when the run actually completed ---
  if (getSession(session.id)?.status === 'done') await runClosingSynthesis(session, cfg, gov);
}

/**
 * Node ⑤ (debt #5) — the session's closing synthesis: a cited narrative over the confirmed findings (zero-day
 * candidates, emulation proof-states). Reuses the read-only copilot, which now sees the session's outputs. Skipped
 * silently if out of budget or unavailable — it never fails the run.
 */
async function runClosingSynthesis(session: AgentSessionRow, cfg: LlmConfig, gov?: Governor): Promise<void> {
  const governor = gov ?? seededGovernor(session);
  if (!governor.check().ok) return;
  try {
    const result = await runCopilot(session.imageId, cfg);
    if (!result) return;
    governor.record(result.model, result.inputTokens ?? 0, result.outputTokens ?? 0);
    recordStep(
      session.id,
      'synthesis',
      'ok',
      undefined,
      { model: result.model, provider: result.provider },
      result.text,
      result.model,
      result.inputTokens ?? 0,
      result.outputTokens ?? 0,
    );
    persist(session, 'done', governor, null);
  } catch (err) {
    recordStep(
      session.id,
      'synthesis',
      'skipped',
      undefined,
      undefined,
      `Synthesis skipped: ${err instanceof Error ? err.message : String(err)}`,
      null,
      0,
      0,
    );
  }
}

/** Rebuild a governor from a session's persisted budget + consumed (for steps that run outside orchestrate). */
function seededGovernor(session: AgentSessionRow): Governor {
  const gov = new Governor(JSON.parse(session.budgetJson));
  gov.seed(JSON.parse(session.consumedJson));
  return gov;
}

/**
 * Phase 4 — node ④ (zero-day) on the top target, then the emulation gate. When the deployment can FULLY isolate a
 * run (network namespace + rlimits + guaranteed teardown) the run happens automatically, without a human approval,
 * because the blast radius is contained. Otherwise the Phase-3 approval gate is kept, honestly.
 */
async function runPhase4(
  session: AgentSessionRow,
  gov: Governor,
  caps: RuntimeCapabilities,
  plan: TargetSelectionDecision['emulationPlan'],
  cfg: LlmConfig,
): Promise<void> {
  const imageId = session.imageId;
  const target = plan[0]?.binary ?? topNetworkBinary(imageId);
  let topCandidate: ZerodayCandidate | undefined;

  // Node ④ needs a binary triage; run/reuse one for the top target.
  if (target && gov.check().ok) {
    const decompile = await ensureDecompile(imageId, target);
    if (decompile?.available) {
      const zctx = await gatherZerodayContext(imageId, decompile);
      const z = await runZerodayNode(zctx, cfg);
      gov.record(z.result.model, z.result.inputTokens ?? 0, z.result.outputTokens ?? 0);
      recordStep(
        session.id,
        'zero-day',
        'ok',
        zctx,
        z.decision,
        z.decision.rationale,
        z.result.model,
        z.result.inputTokens ?? 0,
        z.result.outputTokens ?? 0,
      );
      recordZerodayFindings(imageId, target, z.decision.candidates);
      topCandidate = z.decision.candidates[0];
    } else {
      recordStep(
        session.id,
        'zero-day',
        'skipped',
        { binary: target },
        { available: false },
        'No binary triage (radare2 absent or no rootfs) — cannot reason about sinks; nothing invented.',
        null,
        0,
        0,
      );
    }
    persist(session, 'running', gov, null);
  }

  const isolation = await detectIsolation();
  // Best path: drive node ④'s top candidate's TRIGGER into the sink under isolation and confirm it (debt #3).
  if (topCandidate && target && isolation === 'full') {
    await confirmTrigger(session, gov, caps, target, topCandidate);
  } else if (plan.length > 0 && isolation === 'full') {
    await autoRunIsolated(session, gov, caps, plan[0] as TargetSelectionDecision['emulationPlan'][number]);
  } else if (plan.length > 0) {
    recordStep(
      session.id,
      'isolation',
      'skipped',
      { isolation },
      { isolation },
      `Isolation level '${isolation}' can't fully contain a run here — emulation still needs your approval.`,
      null,
      0,
      0,
    );
    persist(session, 'awaiting_approval', gov, null);
  } else {
    persist(session, 'done', gov, null);
  }
}

/**
 * Debt #3 — deliver a candidate's constructed trigger into the sink under FULL isolation, then upgrade the
 * SPECIFIC finding honestly: a command-injection marker in output, or a crash signal, is confirmed_in_emulation
 * (proves the sandbox, never the device); anything else leaves the candidate needs_runtime_reproduction.
 */
async function confirmTrigger(
  session: AgentSessionRow,
  gov: Governor,
  caps: RuntimeCapabilities,
  target: string,
  candidate: ZerodayCandidate,
): Promise<void> {
  const imageId = session.imageId;
  const rootfs = latestRootfs(imageId)?.rootfsPath;
  const emulator = QEMU_USER_BY_ARCH[caps.arch];
  const abs = rootfs ? resolveInsideRootfs(rootfs, target) : null;
  if (!rootfs || !emulator || !abs) {
    recordStep(
      session.id,
      'emulation',
      'skipped',
      { binary: target },
      { isolation: 'full' },
      'No rootfs/emulator for this arch — cannot deliver the trigger.',
      null,
      0,
      0,
    );
    return void persist(session, 'done', gov, null);
  }

  const marker = `FIRMLABTRIG${randomUUID().slice(0, 8)}`;
  const delivery = planDelivery(candidate, marker);
  const argv = [emulator, '-L', rootfs, abs, ...(delivery.args ?? [])];
  const env: NodeJS.ProcessEnv = { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: '/tmp', ...(delivery.env ?? {}) };
  const res = await runIsolated(argv, { env, ...(delivery.input != null ? { input: delivery.input } : {}) });
  const verdict = interpretTriggerRun(delivery, {
    stdout: res.stdout,
    signal: res.signal,
    exitCode: res.exitCode,
    timedOut: res.timedOut,
  });

  if (verdict.confirmed) {
    const finding = listFindings(imageId).find(
      (f) => f.source === `zeroday:${target}` && f.evidenceJson?.includes(`"sink":${JSON.stringify(candidate.sink)}`),
    );
    if (finding) updateFindingProofState(finding.id, verdict.proofState, verdict.note);
    updateBinaryEmulationStatus(imageId, target, verdict.proofState);
    const row = getImage(imageId);
    if (row?.identityJson) {
      recordReachabilityPrior(
        deviceFamilyKey(JSON.parse(row.identityJson)),
        `${target}:${candidate.sink}`,
        verdict.proofState,
        imageId,
      );
    }
  }

  recordStep(
    session.id,
    'emulation',
    'ok',
    {
      binary: target,
      candidate: { sink: candidate.sink, vulnClass: candidate.vulnClass },
      delivery: delivery.mode,
      isolation: res.isolation,
      autoApproved: true,
    },
    { confirmed: verdict.confirmed, proofState: verdict.proofState, signal: res.signal, exitCode: res.exitCode },
    verdict.note,
    null,
    0,
    0,
  );
  persist(session, 'done', gov, null);
}

/** When the plan is empty, the best target for node ④ is a network-facing binary, else the first. */
function topNetworkBinary(imageId: string): string | null {
  const bins = listBinaries(imageId);
  return (bins.find((b) => b.networkFacing === 1) ?? bins[0])?.path ?? null;
}

/** Reuse the latest completed decompile for a binary, or run one now. Null if there is no extracted rootfs. */
async function ensureDecompile(imageId: string, binary: string): Promise<DecompileResult | null> {
  const existing = listJobs(imageId).find(
    (j) =>
      j.kind === 'decompile' && j.status === 'done' && j.resultJson?.includes(`"binary":${JSON.stringify(binary)}`),
  );
  if (existing?.resultJson) return JSON.parse(existing.resultJson) as DecompileResult;
  const rootfs = latestRootfs(imageId)?.rootfsPath;
  if (!rootfs) return null;
  const jobId = startJob(imageId, 'decompile', { by: 'agent', binary }, (h) => runDecompile(rootfs, binary, h));
  const job = await waitForJob(jobId);
  return (job.result as DecompileResult | null) ?? null;
}

/** Persist node ④'s candidates as findings — every one a hypothesis to test, never a proven bug. */
function recordZerodayFindings(imageId: string, binary: string, candidates: ZerodayCandidate[]): void {
  const drafts: FindingDraft[] = candidates.map((c) => ({
    kind: 'zeroday-candidate',
    title: `${c.vulnClass} via ${c.sink} in ${binary} (${c.reachability})`,
    severity: c.severity,
    proofState: 'needs_runtime_reproduction',
    evidence: { binary, sink: c.sink, source: c.source, trigger: c.trigger, reachability: c.reachability },
    rationale: c.rationale,
  }));
  syncFindings(imageId, `zeroday:${binary}`, drafts);
}

/**
 * Auto-run the top emulation target under FULL isolation (fresh network namespace + rlimits + guaranteed
 * teardown) — no human approval needed because the blast radius is contained. The proof state is capped at
 * emulation-level (proves the sandbox, never the device) and a Level-2 reachability prior is recorded.
 */
/** Boot an RTOS/Cortex-M image under Renode for the agent: the raw firmware + MCU hints, no rootfs needed. */
async function runRenodeForImage(imageId: string): Promise<RenodeResult> {
  const row = getImage(imageId);
  if (!row) throw new Error('Image not found');
  const hints = renodeHintsFrom(row.identityJson ?? null, row.analysisJson ?? null);
  return runRenode(row.path, hints);
}

async function autoRunIsolated(
  session: AgentSessionRow,
  gov: Governor,
  caps: RuntimeCapabilities,
  entry: TargetSelectionDecision['emulationPlan'][number],
): Promise<void> {
  const imageId = session.imageId;

  // The RTOS track boots the whole firmware under Renode (its own isolation) — a different emulator, no rootfs.
  if (entry.rung === 'rtos-renode') {
    const rn = await runRenodeForImage(imageId);
    updateBinaryEmulationStatus(imageId, entry.binary, rn.proofState);
    const row = getImage(imageId);
    if (row?.identityJson) {
      recordReachabilityPrior(deviceFamilyKey(JSON.parse(row.identityJson)), entry.binary, rn.proofState, imageId);
    }
    recordStep(
      session.id,
      'emulation',
      rn.booted ? 'ok' : rn.available ? 'error' : 'skipped',
      { binary: entry.binary, rung: entry.rung, isolation: rn.isolation ?? 'full', autoApproved: true },
      { booted: rn.booted, proofState: rn.proofState, platform: rn.platform, uartExcerpt: rn.uartExcerpt },
      `Auto-booted the firmware under Renode → ${rn.proofState}. ${rn.reason} Proves the sandbox, not the device.`,
      null,
      0,
      0,
    );
    persist(session, 'done', gov, null);
    return;
  }

  const rootfs = latestRootfs(imageId)?.rootfsPath;
  const emulator = QEMU_USER_BY_ARCH[caps.arch];
  const abs = rootfs ? resolveInsideRootfs(rootfs, entry.binary) : null;
  if (!rootfs || !emulator || !abs) {
    recordStep(
      session.id,
      'emulation',
      'skipped',
      { binary: entry.binary },
      { isolation: 'full' },
      'No rootfs/emulator for this arch — cannot auto-run even under isolation.',
      null,
      0,
      0,
    );
    persist(session, 'done', gov, null);
    return;
  }
  const res = await runIsolated([emulator, '-L', rootfs, abs]);
  const proofState = res.ran ? 'confirmed_in_emulation' : 'blocked_by_platform';
  updateBinaryEmulationStatus(imageId, entry.binary, proofState);
  const row = getImage(imageId);
  if (row?.identityJson) {
    recordReachabilityPrior(deviceFamilyKey(JSON.parse(row.identityJson)), entry.binary, proofState, imageId);
  }
  recordStep(
    session.id,
    'emulation',
    res.ran ? 'ok' : 'error',
    { binary: entry.binary, rung: entry.rung, isolation: res.isolation, autoApproved: true },
    { ran: res.ran, exitCode: res.exitCode, timedOut: res.timedOut, proofState },
    `Auto-ran ${entry.binary} under ${res.isolation} isolation (no approval — network-namespaced + rlimited) → ${proofState}. Proves the sandbox, not the device.`,
    null,
    0,
    0,
  );
  persist(session, 'done', gov, null);
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
    const done = await runApprovedEmulation(session, chosen);
    // Node ⑤ — close with a cited synthesis over the (now emulation-confirmed) findings.
    const cfg = loadLlmConfig();
    if (cfg) await runClosingSynthesis(done, cfg);
    return getSession(sessionId) as AgentSessionRow;
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
  // The RTOS rung boots the whole firmware under Renode and needs no rootfs; every qemu rung does.
  if (chosen.rung !== 'rtos-renode' && !rootfsPath) throw new Error('No extracted rootfs — cannot emulate');

  const jobId = startJob(
    session.imageId,
    chosen.rung === 'rtos-renode' ? 'renode' : 'emulate',
    { by: 'agent', session: sessionId, binary: chosen.binary, rung: chosen.rung },
    async (h) => {
      if (chosen.rung === 'rtos-renode') return runRenodeForImage(session.imageId);
      if (!rootfsPath) throw new Error('No extracted rootfs — cannot emulate');
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
