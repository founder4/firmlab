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
import fs from 'node:fs';
import type { ImageIdentity } from '@firmlab/core';
import { normalizeBinaryHardening, normalizeSbom, rowToFinding, syncFindings } from './findings.js';
import type { LlmConfig } from './llm.js';
import { complete } from './llm.js';
import { daemonLeads, handlerLeads } from './opacidad-leads.js';
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
import {
  type Lead,
  type PlanSpec,
  type ProviderId,
  type ScheduleState,
  planEntries,
  scheduleLeads,
  specKey,
  specsForClass,
} from './opacidad-plan.js';
import { runAuxSecrets } from './providers/auxsecrets.js';
import { runBinVuln } from './providers/binvuln.js';
import { runCertAnalysis } from './providers/certs.js';
import { runChipsec } from './providers/chipsec.js';
import { runComponentMap } from './providers/compmap.js';
import { runComponentCve } from './providers/component-cve.js';
import { runDecompile } from './providers/decompile.js';
import { assessDecoy, decoyFinding } from './providers/decoy.js';
import { runEncryptedAnalysis } from './providers/encrypted.js';
import { runEspAnalysis } from './providers/esp.js';
import { type ExtractResult, runExtraction } from './providers/extract.js';
import { runFccLookup } from './providers/fcc.js';
import { runFsAudit } from './providers/fsaudit.js';
import type { JobHandle } from './providers/jobs.js';
import { runRtosAnalysis } from './providers/rtos.js';
import { runSbom } from './providers/sbom.js';
import { runServiceMap } from './providers/servicemap.js';
import { buildTaintScaffold } from './providers/taint.js';
import { runUbootAnalysis } from './providers/uboot.js';
import { runWebTaint } from './providers/webtaint.js';
import { getImage, listFindings, listJobs } from './store.js';

/** Mutable run context threaded through the plan — extraction fills `rootfsPath`/`outputDir`/`carveTrace` for later stages. */
interface RunCtx {
  imageId: string;
  imagePath: string;
  analysisJson: string | null;
  rootfsPath: string | null;
  /** The extraction output dir (all carved partitions) — the aux-secret scan reads sibling partitions from here. */
  outputDir: string | null;
  carveTrace?: ExtractResult['carveTrace'];
  handle: JobHandle;
}

interface StepOutcome {
  summary: string;
  findingCount: number;
  degraded?: boolean;
  note?: string;
  /** Leads this worker surfaced — W9 re-plans the agenda to schedule the follow-up workers they name. */
  leads?: Lead[];
}

// === Per-provider executors (call the pure runner, then sync findings under the route's source) ===

/** Did W0 claim this image carries a filesystem (a strong fs signature fired, or a Linux/FIT-UBI class)? */
function fsClaimed(analysisJson: string | null): boolean {
  if (!analysisJson) return false;
  try {
    const a = JSON.parse(analysisJson) as { identity?: ImageIdentity };
    const id = a.identity;
    if (!id) return false;
    return (
      (Array.isArray(id.filesystems) && id.filesystems.length > 0) ||
      id.firmwareClass === 'embedded-linux' ||
      id.firmwareClass === 'openwrt-fit-ubi'
    );
  } catch {
    return false;
  }
}

/** Read a bounded prefix of the image for the zero-density (decoy) check — representative for a hollow image. */
function readImagePrefix(imagePath: string, cap = 64 * 1024 * 1024): Uint8Array {
  try {
    const fd = fs.openSync(imagePath, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, cap);
      const b = Buffer.allocUnsafe(size);
      fs.readSync(fd, b, 0, size, 0);
      return b;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return new Uint8Array(0);
  }
}

async function extractRun(c: RunCtx): Promise<StepOutcome> {
  if (c.rootfsPath) return { summary: 'reused the already-extracted rootfs', findingCount: 0 };
  const ex = await runExtraction(c.imageId, c.imagePath, c.handle);
  c.rootfsPath = ex.rootfsPath;
  c.outputDir = ex.outputDir;
  c.carveTrace = ex.carveTrace;
  if (ex.rootfsPath) {
    return {
      summary: `rootfs recovered via ${ex.extractor} (${ex.summary?.totalFiles ?? '?'} files)`,
      findingCount: 0,
    };
  }
  // No rootfs. Before reporting a bare "no rootfs", check for a hollow/decoy image (a claimed filesystem whose
  // payload is mostly zeros) so "0 findings" is not mistaken for "clean" (docs/AUTONOMOUS-WORKERS.md §9 gap #6).
  const decoy = assessDecoy(readImagePrefix(c.imagePath), {
    fsClaimed: fsClaimed(c.analysisJson),
    rootfsRecovered: false,
  });
  const decoyDrafts = decoyFinding(decoy);
  syncFindings(c.imageId, 'triage', decoyDrafts);
  const last = ex.carveTrace?.[ex.carveTrace.length - 1];
  if (decoy.isDecoy) {
    return {
      summary: `corrupt/decoy image — ${decoy.reason}`,
      findingCount: decoyDrafts.length,
      degraded: true,
      note: 'payload unextractable (hollow image), not a clean scan',
    };
  }
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

async function auxsecretsRun(c: RunCtx): Promise<StepOutcome> {
  const r = runAuxSecrets(c.outputDir, c.rootfsPath);
  syncFindings(c.imageId, 'auxsecrets', r.findings);
  return {
    summary: `sibling-partition secrets: ${r.findings.length} embedded private key(s) in ${r.filesScanned} key-ish file(s)`,
    findingCount: r.findings.length,
    ...(r.available ? {} : { degraded: true, note: r.reason }),
  };
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

async function compcveRun(c: RunCtx): Promise<StepOutcome> {
  const r = runComponentCve(c.rootfsPath);
  syncFindings(c.imageId, 'compcve', r.findings);
  const cves = r.findings.filter((f) => f.kind === 'component-cve').length;
  return {
    summary: `bundled-component fingerprint: ${r.hits.length} component(s), ${cves} n-day CVE(s) a manifest SBOM misses`,
    findingCount: r.findings.length,
    ...(r.hits.length === 0 ? { degraded: true, note: r.reason } : {}),
  };
}

async function servicemapRun(c: RunCtx): Promise<StepOutcome> {
  const r = runServiceMap(c.rootfsPath as string);
  syncFindings(c.imageId, 'services', r.findings);
  const leads = daemonLeads(r.services, c.rootfsPath as string);
  return {
    summary: `network-service attack surface: ${r.findings.length} findings${leads.length ? `, ${leads.length} daemon(s) to decompile` : ''}`,
    findingCount: r.findings.length,
    ...(leads.length ? { leads } : {}),
  };
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

async function encryptedRun(c: RunCtx): Promise<StepOutcome> {
  const r = runEncryptedAnalysis(c.imagePath);
  syncFindings(c.imageId, 'encrypted', r.findings);
  const iv = r.header.ivBlock ? `, IV @ 0x${r.header.ivBlock.offset.toString(16)}` : '';
  return {
    summary: `encrypted body: ${r.verdict.cipher} ${r.verdict.mode}${iv} — unrecoverable without the key`,
    findingCount: r.findings.length,
  };
}

async function webtaintRun(c: RunCtx): Promise<StepOutcome> {
  const r = runWebTaint(c.rootfsPath);
  syncFindings(c.imageId, 'webtaint', r.findings);
  const tainted = r.handlers.filter((h) => h.tainted).length;
  const leads = handlerLeads(r.handlers, c.rootfsPath as string);
  return {
    summary: `web attack-surface: ${r.handlers.length} handlers, ${tainted} tainted → ${r.findings.length} findings`,
    findingCount: r.findings.length,
    ...(leads.length ? { leads } : {}),
    ...(r.handlers.length === 0 ? { degraded: true, note: r.reason } : {}),
  };
}

/** W5 breadth — sweep every rootfs ELF for stack-overflow candidates (unbounded-copy + no canary). */
async function binvulnRun(c: RunCtx): Promise<StepOutcome> {
  const r = runBinVuln(c.rootfsPath);
  syncFindings(c.imageId, 'binvuln', r.findings);
  return {
    summary: `binary-vuln sweep: ${r.binariesScanned} ELFs, ${r.candidates} stack-overflow candidate(s)`,
    findingCount: r.findings.length,
    ...(r.binariesScanned === 0 ? { degraded: true, note: r.reason } : {}),
  };
}

/** W5 — targeted binary-vuln, scheduled by W9's re-planning. Decompile one daemon, sync its hardening findings. */
async function decompileRun(c: RunCtx, spec: PlanSpec): Promise<StepOutcome> {
  const binary = spec.target;
  if (!binary)
    return { summary: 'no target binary', findingCount: 0, degraded: true, note: 'decompile spec missing target' };
  const r = await runDecompile(c.rootfsPath as string, binary, c.handle);
  if (!r.available) {
    return {
      summary: `decompile ${binary}: unavailable`,
      findingCount: 0,
      degraded: true,
      note: r.reason ?? 'unavailable',
    };
  }
  const hardening = normalizeBinaryHardening(r);
  // Same idempotent source the manual decompile route uses (routes/decompile.ts) → re-runs re-sync, not duplicate.
  syncFindings(c.imageId, `binary:${binary}`, hardening);
  const scaffold = buildTaintScaffold(r);
  const surface = scaffold.hasTaintSurface
    ? `, taint surface (${scaffold.sinks.length} sinks / ${scaffold.sources.length} sources)`
    : '';
  return {
    summary: `decompiled ${binary}: ${r.functionCount} fns, ${hardening.length} hardening findings${surface}`,
    findingCount: hardening.length,
  };
}

/** Bind each plan `provider` tag to its concrete executor. Tags with no executor are the not-built workers. */
const EXECUTORS: Record<ProviderId, (c: RunCtx, spec: PlanSpec) => Promise<StepOutcome>> = {
  extract: extractRun,
  fsaudit: fsauditRun,
  auxsecrets: auxsecretsRun,
  sbom: sbomRun,
  compcve: compcveRun,
  servicemap: servicemapRun,
  certs: certsRun,
  compmap: compmapRun,
  uboot: ubootRun,
  fcc: fccRun,
  rtos: rtosRun,
  chipsec: chipsecRun,
  esp: espRun,
  encrypted: encryptedRun,
  webtaint: webtaintRun,
  binvuln: binvulnRun,
  decompile: decompileRun,
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

  const seed = specsForClass(identity.firmwareClass);
  const plan = planEntries(seed);
  handle.log(`Class '${identity.firmwareClass}' → seed plan: ${seed.map((s) => s.worker).join(' → ')}`);

  const prior = latestExtract(imageId);
  const ctx: RunCtx = {
    imageId,
    imagePath,
    analysisJson: row.analysisJson,
    rootfsPath: prior?.rootfsPath ?? null,
    outputDir: prior?.outputDir ?? null,
    ...(prior?.carveTrace ? { carveTrace: prior.carveTrace } : {}),
    handle,
  };

  // W9 re-planning: the class DAG is only the SEED. A worker can surface a lead mid-run (a network daemon, the
  // httpd serving a tainted handler) that schedules a follow-up worker — so the fixed plan becomes a dynamic
  // worklist. Growth is deduped + capped so re-planning always terminates; a lead past the cap is surfaced, not
  // silently dropped.
  const MAX_DYNAMIC_STEPS = 8;
  const agenda: PlanSpec[] = [...seed];
  const sched: ScheduleState = { planned: new Set(seed.map(specKey)), dynamicCount: 0, capped: 0 };

  const steps: OpacidadStep[] = [];
  for (let i = 0; i < agenda.length; i++) {
    const spec = agenda[i];
    if (!spec) continue;
    const meta = {
      ...(spec.origin ? { origin: spec.origin } : {}),
      ...(spec.trigger ? { trigger: spec.trigger } : {}),
    };
    const executor = spec.provider ? EXECUTORS[spec.provider] : undefined;
    if (!spec.built || !executor) {
      steps.push({
        worker: spec.worker,
        status: 'not-built',
        summary: spec.reason,
        ...(spec.note ? { note: spec.note } : {}),
        ...meta,
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
        ...meta,
      });
      handle.log(`⚠ ${spec.worker}: skipped (no rootfs)`);
      continue;
    }
    try {
      handle.log(`${spec.origin === 'replan' ? '↳ ▶' : '▶'} ${spec.worker}`);
      const out = await executor(ctx, spec);
      steps.push({
        worker: spec.worker,
        status: out.degraded ? 'degraded' : 'ran',
        summary: out.summary,
        findingCount: out.findingCount,
        ...(out.note ? { note: out.note } : {}),
        ...meta,
      });
      handle.log(`✓ ${spec.worker}: ${out.summary}`);
      if (out.leads?.length) {
        const added = scheduleLeads(out.leads, sched, MAX_DYNAMIC_STEPS);
        for (const ns of added) handle.log(`↳ re-plan: scheduled ${ns.worker} — ${ns.trigger}`);
        agenda.push(...added);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      steps.push({ worker: spec.worker, status: 'degraded', summary: spec.reason, note: `error: ${msg}`, ...meta });
      handle.log(`⚠ ${spec.worker}: ${msg}`);
    }
  }
  if (sched.capped > 0) {
    steps.push({
      worker: 'W9 · Re-plan (cap reached)',
      status: 'degraded',
      summary: `${sched.capped} further daemon lead(s) not scheduled — dynamic step cap ${MAX_DYNAMIC_STEPS} reached`,
      note: 'honest bound: raise the cap or triage the remaining daemons manually',
    });
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
