/**
 * W9 — the *opacidad* orchestrator (the "opacity controller").
 *
 * The operator drops a firmware and hits "Autonomous scan"; from W0's device class this plans the right chain of
 * workers, runs them in order (feeding each stage's output into the next — extraction recovers the rootfs the
 * later stages need), and composes the findings into an attack-path narrative. It is the Phase-2 skeleton from
 * docs/AUTONOMOUS-WORKERS.md §6: it *chains the existing providers* (no new analysis code) and writes the
 * reasoning trace the flat-rows UI is missing.
 *
 * Honesty is structural: a class whose dedicated deep worker is not built yet (W6 ESP, W8 encrypted, W4 web-taint)
 * is reported as `not-built`, not silently skipped; a stage that needs a rootfs it does not have is `skipped`; a
 * tool that is absent `degrades`. "Zero findings" is never dressed up as "clean" — the per-worker outcomes and the
 * honest-gaps list say exactly what did and did not run. The provider runners are pure w.r.t. findings (the routes
 * sync them), so this orchestrator syncs each provider's findings under the SAME source the manual route uses —
 * re-running opacidad re-syncs idempotently rather than duplicating.
 */
import type { ImageIdentity } from '@firmlab/core';
import { normalizeSbom, rowToFinding, syncFindings } from './findings.js';
import type { LlmConfig } from './llm.js';
import { complete } from './llm.js';
import {
  type FindingsSummary,
  type OpacidadContext,
  type OpacidadPlanEntry,
  type OpacidadStep,
  buildAttackPath,
  buildLlmPrompt,
  composeDeterministicNarrative,
  honestGaps,
  summarizeFindings,
} from './opacidad-narrative.js';
import { type ProviderId, planEntries, specsForClass } from './opacidad-plan.js';
import { runCertAnalysis } from './providers/certs.js';
import { runChipsec } from './providers/chipsec.js';
import { runComponentMap } from './providers/compmap.js';
import { runEspAnalysis } from './providers/esp.js';
import { type ExtractResult, runExtraction } from './providers/extract.js';
import { runFccLookup } from './providers/fcc.js';
import { runFsAudit } from './providers/fsaudit.js';
import type { JobHandle } from './providers/jobs.js';
import { runRtosAnalysis } from './providers/rtos.js';
import { runSbom } from './providers/sbom.js';
import { runServiceMap } from './providers/servicemap.js';
import { runUbootAnalysis } from './providers/uboot.js';
import { getImage, listFindings, listJobs } from './store.js';

/** Mutable run context threaded through the plan — extraction fills `rootfsPath`/`carveTrace` for later stages. */
interface RunCtx {
  imageId: string;
  imagePath: string;
  analysisJson: string | null;
  rootfsPath: string | null;
  carveTrace?: ExtractResult['carveTrace'];
  handle: JobHandle;
}

interface StepOutcome {
  summary: string;
  findingCount: number;
  degraded?: boolean;
  note?: string;
}

// === Per-provider executors (call the pure runner, then sync findings under the route's source) ===

async function extractRun(c: RunCtx): Promise<StepOutcome> {
  if (c.rootfsPath) return { summary: 'reused the already-extracted rootfs', findingCount: 0 };
  const ex = await runExtraction(c.imageId, c.imagePath, c.handle);
  c.rootfsPath = ex.rootfsPath;
  c.carveTrace = ex.carveTrace;
  if (ex.rootfsPath) {
    return {
      summary: `rootfs recovered via ${ex.extractor} (${ex.summary?.totalFiles ?? '?'} files)`,
      findingCount: 0,
    };
  }
  const last = ex.carveTrace?.[ex.carveTrace.length - 1];
  return {
    summary: `no rootfs (${ex.extractor})`,
    findingCount: 0,
    degraded: true,
    note: last ? `carve stopped: ${last.detail}` : 'no extractor installed / not a Linux container',
  };
}

async function fsauditRun(c: RunCtx): Promise<StepOutcome> {
  const r = runFsAudit(c.rootfsPath as string);
  syncFindings(c.imageId, 'fsaudit', r.findings);
  return { summary: `rootfs security audit: ${r.findings.length} findings`, findingCount: r.findings.length };
}

async function sbomRun(c: RunCtx): Promise<StepOutcome> {
  const r = await runSbom(c.imageId, c.rootfsPath as string, c.handle);
  const drafts = normalizeSbom(r);
  syncFindings(c.imageId, 'sbom', drafts);
  if (!r.available)
    return { summary: 'SBOM unavailable', findingCount: 0, degraded: true, note: 'syft/grype not installed' };
  return {
    summary: `${r.packageCount} packages · ${r.vulnerabilities.length} CVEs (Crit ${r.counts.Critical}, High ${r.counts.High})`,
    findingCount: drafts.length,
  };
}

async function servicemapRun(c: RunCtx): Promise<StepOutcome> {
  const r = runServiceMap(c.rootfsPath as string);
  syncFindings(c.imageId, 'services', r.findings);
  return { summary: `network-service attack surface: ${r.findings.length} findings`, findingCount: r.findings.length };
}

async function certsRun(c: RunCtx): Promise<StepOutcome> {
  const r = runCertAnalysis(c.rootfsPath, c.imagePath);
  syncFindings(c.imageId, 'certs', r.findings);
  return { summary: `embedded certificates: ${r.findings.length} findings`, findingCount: r.findings.length };
}

async function compmapRun(c: RunCtx): Promise<StepOutcome> {
  const r = await runComponentMap(c.rootfsPath as string);
  syncFindings(c.imageId, 'compmap', r.findings);
  return { summary: `component dependency map: ${r.findings.length} findings`, findingCount: r.findings.length };
}

async function ubootRun(c: RunCtx): Promise<StepOutcome> {
  const r = runUbootAnalysis(c.imagePath);
  syncFindings(c.imageId, 'uboot', r.findings);
  return { summary: `U-Boot / boot posture: ${r.findings.length} findings`, findingCount: r.findings.length };
}

async function fccRun(c: RunCtx): Promise<StepOutcome> {
  const r = runFccLookup(c.imagePath, c.analysisJson);
  syncFindings(c.imageId, 'fcc', r.findings);
  return { summary: `FCC-ID recon: ${r.findings.length} findings`, findingCount: r.findings.length };
}

async function rtosRun(c: RunCtx): Promise<StepOutcome> {
  const r = runRtosAnalysis(c.imagePath);
  syncFindings(c.imageId, 'rtos', r.findings);
  return { summary: `bare-metal / RTOS analysis: ${r.findings.length} findings`, findingCount: r.findings.length };
}

async function chipsecRun(c: RunCtx): Promise<StepOutcome> {
  const r = await runChipsec(c.imagePath);
  syncFindings(c.imageId, 'chipsec', r.findings);
  return { summary: `UEFI offline decode + posture: ${r.findings.length} findings`, findingCount: r.findings.length };
}

async function espRun(c: RunCtx): Promise<StepOutcome> {
  const r = runEspAnalysis(c.imagePath);
  syncFindings(c.imageId, 'esp', r.findings);
  if (!r.isEsp) return { summary: 'not an ESP dump', findingCount: 0, degraded: true, note: r.reason };
  const keys = r.findings.filter((f) => f.kind === 'esp-nvs-key').length;
  return {
    summary: `ESP SoC: ${r.partitions.length} partitions, ${r.nvsEntries.length} NVS entries${keys ? `, ${keys} key(s) recovered` : ''}; Flash-Enc ${r.posture.flashEncryption}/Secure-Boot ${r.posture.secureBoot}`,
    findingCount: r.findings.length,
  };
}

/** Bind each plan `provider` tag to its concrete executor. Tags with no executor are the not-built workers. */
const EXECUTORS: Record<ProviderId, (c: RunCtx) => Promise<StepOutcome>> = {
  extract: extractRun,
  fsaudit: fsauditRun,
  sbom: sbomRun,
  servicemap: servicemapRun,
  certs: certsRun,
  compmap: compmapRun,
  uboot: ubootRun,
  fcc: fccRun,
  rtos: rtosRun,
  chipsec: chipsecRun,
  esp: espRun,
};

// === The orchestrator ===

export interface OpacidadResult {
  firmwareClass: string;
  arch: string;
  classRationale?: string;
  plan: OpacidadPlanEntry[];
  steps: OpacidadStep[];
  findings: FindingsSummary;
  attackPath: string[];
  narrative: string;
  narrativeSource: 'llm' | 'deterministic';
  honestGaps: string[];
  llm?: { provider: string; model: string };
}

/** The latest successfully-extracted rootfs + its carve trace, if extraction already ran for this image. */
function latestExtract(imageId: string): ExtractResult | null {
  const job = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return job?.resultJson ? (JSON.parse(job.resultJson) as ExtractResult) : null;
}

/**
 * Run a full autonomous scan: plan from the class, execute each worker (feeding extraction forward), sync findings,
 * then compose the narrative — deterministically, or via the LLM when one is configured (it only reorganizes the
 * real facts, never invents). Returns the structured result the job stores and the panel renders.
 */
export async function runOpacidad(
  imageId: string,
  imagePath: string,
  handle: JobHandle,
  cfg: LlmConfig | null,
): Promise<OpacidadResult> {
  const row = getImage(imageId);
  if (!row?.identityJson) throw new Error('No identity for this image — analyze it first');
  const identity = JSON.parse(row.identityJson) as ImageIdentity;

  const specs = specsForClass(identity.firmwareClass);
  const plan = planEntries(specs);
  handle.log(`Class '${identity.firmwareClass}' → plan: ${specs.map((s) => s.worker).join(' → ')}`);

  const prior = latestExtract(imageId);
  const ctx: RunCtx = {
    imageId,
    imagePath,
    analysisJson: row.analysisJson,
    rootfsPath: prior?.rootfsPath ?? null,
    ...(prior?.carveTrace ? { carveTrace: prior.carveTrace } : {}),
    handle,
  };

  const steps: OpacidadStep[] = [];
  for (const spec of specs) {
    const executor = spec.provider ? EXECUTORS[spec.provider] : undefined;
    if (!spec.built || !executor) {
      steps.push({
        worker: spec.worker,
        status: 'not-built',
        summary: spec.reason,
        ...(spec.note ? { note: spec.note } : {}),
      });
      handle.log(`▢ ${spec.worker}: not built`);
      continue;
    }
    if (spec.needsRootfs && !ctx.rootfsPath) {
      steps.push({
        worker: spec.worker,
        status: 'skipped',
        summary: spec.reason,
        note: 'no extracted rootfs available',
      });
      handle.log(`⚠ ${spec.worker}: skipped (no rootfs)`);
      continue;
    }
    try {
      handle.log(`▶ ${spec.worker}`);
      const out = await executor(ctx);
      steps.push({
        worker: spec.worker,
        status: out.degraded ? 'degraded' : 'ran',
        summary: out.summary,
        findingCount: out.findingCount,
        ...(out.note ? { note: out.note } : {}),
      });
      handle.log(`✓ ${spec.worker}: ${out.summary}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      steps.push({ worker: spec.worker, status: 'degraded', summary: spec.reason, note: `error: ${msg}` });
      handle.log(`⚠ ${spec.worker}: ${msg}`);
    }
  }

  const findings = listFindings(imageId).map(rowToFinding);
  const narrativeCtx: OpacidadContext = {
    filename: row.filename,
    firmwareClass: identity.firmwareClass,
    arch: identity.arch,
    ...(identity.classRationale ? { classRationale: identity.classRationale } : {}),
    ...(ctx.carveTrace
      ? { carveTrace: ctx.carveTrace.map((s) => ({ format: s.format, action: s.action, detail: s.detail })) }
      : {}),
    plan,
    steps,
    findings,
  };

  let narrative = composeDeterministicNarrative(narrativeCtx);
  let narrativeSource: 'llm' | 'deterministic' = 'deterministic';
  let llm: { provider: string; model: string } | undefined;
  if (cfg) {
    try {
      const { system, user } = buildLlmPrompt(narrativeCtx);
      const res = await complete(system, user, cfg);
      if (res.text.trim()) {
        narrative = res.text.trim();
        narrativeSource = 'llm';
        llm = { provider: res.provider, model: res.model };
        handle.log(`Narrative synthesized via ${res.provider} (${res.model}).`);
      }
    } catch (err) {
      handle.log(
        `LLM narrative failed — using the deterministic narrative: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  return {
    firmwareClass: identity.firmwareClass,
    arch: identity.arch,
    ...(identity.classRationale ? { classRationale: identity.classRationale } : {}),
    plan,
    steps,
    findings: summarizeFindings(findings),
    attackPath: buildAttackPath(findings),
    narrative,
    narrativeSource,
    honestGaps: honestGaps(narrativeCtx),
    ...(llm ? { llm } : {}),
  };
}
