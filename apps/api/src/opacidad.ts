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
import type { Architecture, ImageIdentity } from '@firmlab/core';
import { normalizeBinaryHardening, normalizeSbom, rowToFinding, syncFindings } from './findings.js';
import type { LlmConfig } from './llm.js';
import { complete } from './llm.js';
import {
  CMDEXEC_LEAD_CAP,
  type ProbeInterest,
  REACHABILITY_LEAD_CAP,
  cmdexecLeads,
  daemonLeads,
  handlerLeads,
  interestingBinaries,
  reachabilityLeads,
  reproductionLeads,
  taintReachabilityLeads,
} from './opacidad-leads.js';
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
  LEAD_KIND_LABEL,
  type Lead,
  type PlanSpec,
  type ProviderId,
  type ScheduleState,
  countCmdexecProbes,
  countReachabilityProbes,
  planEntries,
  scheduleLeads,
  specKey,
  specsForClass,
} from './opacidad-plan.js';
import { partitionByProvenance } from './operator-findings.js';
import { runAuxSecrets } from './providers/auxsecrets.js';
import { runBinVuln } from './providers/binvuln.js';
import { type CmdlineSource, type UbootScriptCmdlines, crossCheckBootCmdlines } from './providers/boot-cmdline.js';
import { runCertAnalysis } from './providers/certs.js';
import { runChipsec } from './providers/chipsec.js';
import { runComponentMap } from './providers/compmap.js';
import { runComponentCve } from './providers/component-cve.js';
import { runDecompile } from './providers/decompile.js';
import { assessDecoy, decoyFinding } from './providers/decoy.js';
import { runDeviceTreeAnalysis } from './providers/devicetree.js';
import { runDynProbe } from './providers/dynprobe-run.js';
import { runEncryptedAnalysis } from './providers/encrypted.js';
import { runEspAnalysis } from './providers/esp.js';
import { neuteredFindings } from './providers/extract-neutered.js';
import { type ExtractResult, runExtraction } from './providers/extract.js';
import { runFccLookup } from './providers/fcc.js';
import { runFsAudit } from './providers/fsaudit.js';
import { runFwHunt } from './providers/fwhunt.js';
import type { JobHandle } from './providers/jobs.js';
import { runKernelPosture } from './providers/kernelposture.js';
import { runNvramScan } from './providers/nvram.js';
import { runRtosAnalysis } from './providers/rtos.js';
import { runSbom } from './providers/sbom.js';
import { type Service, runServiceMap } from './providers/servicemap.js';
import { runSymReach } from './providers/symreach.js';
import { buildTaintScaffold } from './providers/taint.js';
import { runUbootAnalysis } from './providers/uboot.js';
import { runUpdatePath } from './providers/updatepath.js';
import { type HandlerAnalysis, runWebTaint } from './providers/webtaint.js';
import { getImage, listFindings, listJobs } from './store.js';

/**
 * The two halves of the kernel-command-line question, and whether each provider has run at all.
 *
 * Neither provider can see the interesting case on its own: the device tree holds what the build expects and the
 * U-Boot side holds what the board would pass, and only something with both in hand can notice they disagree. So
 * each executor deposits its half here and the `bootcmdline` stage — planned after both — performs the check.
 * `ubootRan` / `deviceTreeRan` exist so "ran and found no command line" is never read as "has not run yet": the
 * difference is whether the question was answerable or merely unasked, and the cross-check stage reports the two
 * differently.
 */
interface BootCmdlineState {
  ubootRan: boolean;
  /** The env's `bootargs`, when the stored environment declared a non-empty one. */
  uboot: CmdlineSource | null;
  /** What a `bootcmd`/`preboot` script ASSEMBLES — the operative line when the script re-sets `bootargs`. */
  ubootScript: UbootScriptCmdlines | null;
  deviceTreeRan: boolean;
  /** One per device tree whose `/chosen` declared a command line — a FIT ships one tree per board variant. */
  deviceTree: CmdlineSource[];
}

/** Mutable run context threaded through the plan — extraction fills `rootfsPath`/`outputDir`/`carveTrace` for later stages. */
interface RunCtx {
  imageId: string;
  imagePath: string;
  analysisJson: string | null;
  rootfsPath: string | null;
  /** The extraction output dir (all carved partitions) — the aux-secret scan reads sibling partitions from here. */
  outputDir: string | null;
  carveTrace?: ExtractResult['carveTrace'];
  /** Architecture read from the rootfs ELF headers — authoritative for emulating a binary out of it. */
  detectedArch?: Architecture;
  /**
   * The live set of spec keys already on the agenda. Executors read it to size the shared, per-run angr budget:
   * symbolic reachability costs real wall-clock, so the cap is global across lead sources, not per source.
   */
  planned: ReadonlySet<string>;
  /**
   * What W3 and W4 established about this rootfs, deposited for the stages planned after them. `binvulnRun` reads
   * both to rank its probes by exposure as well as by size (`ProbeInterest` in opacidad-leads.ts).
   *
   * UNDEFINED means the stage has not run — never "nothing is exposed". Both are read by a ranking that treats an
   * absent signal as silence and falls back to its size order, so a class whose plan omits the web-taint stage, or
   * a run where extraction produced no rootfs, gets exactly the ordering it got before these fields existed.
   */
  services?: Service[];
  handlers?: HandlerAnalysis[];
  /** Both halves of the kernel command line, filled by `ubootRun` / `devicetreeRun` and cross-checked by them. */
  bootCmdlines: BootCmdlineState;
  handle: JobHandle;
}

/** Reachability probes still affordable this run — W4's chains run first, so they claim the slots they deserve. */
function reachabilityBudget(c: RunCtx): number {
  return REACHABILITY_LEAD_CAP - countReachabilityProbes(c.planned);
}

/** The command-exec question's own allowance, counted separately so it cannot eat the one above. */
function cmdexecBudget(c: RunCtx): number {
  return CMDEXEC_LEAD_CAP - countCmdexecProbes(c.planned);
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
  if (ex.detectedArch) c.detectedArch = ex.detectedArch;
  if (ex.rootfsPath) {
    // What the extractor CUT is part of the extraction's own account of itself, so it is reported here rather than
    // left for each reader to rediscover as an empty file. Synced under its own source so a re-extraction replaces
    // it idempotently.
    const cutDrafts = ex.neuteredPaths ? neuteredFindings(ex.neuteredPaths) : [];
    syncFindings(c.imageId, 'extract-integrity', cutDrafts);
    const cut = ex.neuteredPaths?.entries.filter((e) => e.state === 'neutered').length ?? 0;
    return {
      summary: `rootfs recovered via ${ex.extractor} (${ex.summary?.totalFiles ?? '?'} files)${
        cut ? `, ${cut} path(s) cut by the extractor` : ''
      }`,
      findingCount: cutDrafts.length,
      // Not "degraded": the extraction succeeded and the rootfs is usable. The cut paths bound what the LATER
      // stages can see, which is what the finding says; calling the stage degraded would misattribute it.
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

/**
 * W3 breadth — the flash key-value store, read from the RAW image.
 *
 * The only stage here that deliberately ignores `rootfsPath`: an nvram partition sits in the upload's flash
 * layout, outside any filesystem, which is exactly why every rootfs-walking scan has missed it.
 */
async function nvramRun(c: RunCtx): Promise<StepOutcome> {
  const r = runNvramScan(c.imagePath);
  syncFindings(c.imageId, 'nvram', r.findings);
  const creds = r.findings.filter((f) => f.kind === 'nvram-credential' || f.kind === 'nvram-wifi-key').length;
  return {
    summary: `nvram store: ${r.stores.length} store(s), ${r.stores.reduce((n, s) => n + s.recordCount, 0)} record(s)${creds ? `, ${creds} credential/key finding(s)` : ''}`,
    findingCount: r.findings.length,
    // No store is a real negative for this image only — most firmware keeps its environment elsewhere — so it is
    // reported rather than treated as a stage that failed.
    ...(r.stores.length === 0 ? { note: r.reason } : {}),
  };
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
  // Deposited for W5's probe ranking, which asks about an exposed daemon ahead of a smaller binary nothing
  // flagged. Set even when the map is empty: "W3 ran and found no service" and "W3 did not run" rank the same
  // way here, but only because the ranking reads an empty map as silence rather than as a negative.
  c.services = r.services;
  const leads = daemonLeads(r.services, c.rootfsPath as string);
  return {
    summary: `network-service attack surface: ${r.findings.length} findings${leads.length ? `, ${leads.length} daemon(s) to decompile` : ''}`,
    findingCount: r.findings.length,
    ...(leads.length ? { leads } : {}),
  };
}

/**
 * The kernel underneath the userland. Runs with or without a rootfs — without one it still recovers the version
 * from a carved blob and reports every posture question as explicitly undetermined, which is the honest degraded
 * answer, not a skip.
 */
async function kernelRun(c: RunCtx): Promise<StepOutcome> {
  const r = runKernelPosture(c.imagePath, c.rootfsPath, c.outputDir);
  syncFindings(c.imageId, 'kernel', r.findings);
  if (!r.located) {
    return {
      summary: 'kernel posture: no kernel located',
      findingCount: r.findings.length,
      degraded: true,
      note: r.reason,
    };
  }
  const undetermined = r.answers.filter((a) => a.verdict === 'unknown').length;
  return {
    summary: `kernel posture: Linux ${r.version}, ${r.answers.length - undetermined}/${r.answers.length} questions answered, ${r.findings.length} findings`,
    findingCount: r.findings.length,
    ...(undetermined > 0 ? { note: `${undetermined} posture question(s) undetermined — each records why.` } : {}),
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

/**
 * Cross-check the device tree's `/chosen` command line against the U-Boot side's — its own stage, planned after
 * both halves (see `BOOT_CMDLINE_CROSSCHECK` in opacidad-plan.ts for why it is not folded into them).
 *
 * It syncs under its own source whenever the check was actually made — including with no drafts, so a disagreement
 * recorded by an earlier run cannot outlive a re-run that no longer sees one. When a half never ran it syncs
 * NOTHING: clearing a finding a complete earlier run established, because this run could not repeat the question,
 * would turn an unasked question into a retraction.
 */
async function bootCmdlineRun(c: RunCtx): Promise<StepOutcome> {
  const state = c.bootCmdlines;
  if (!state.ubootRan || !state.deviceTreeRan) {
    const missing = [!state.ubootRan ? 'the U-Boot env stage' : '', !state.deviceTreeRan ? 'the device-tree stage' : '']
      .filter((s) => s !== '')
      .join(' and ');
    return {
      summary: 'cmdline cross-check: not made',
      findingCount: 0,
      degraded: true,
      note: `${missing} did not run in this scan, so the two lines could not be compared. That is the question going unasked — not agreement between them.`,
    };
  }
  const r = crossCheckBootCmdlines({
    deviceTree: state.deviceTree,
    ubootEnv: state.uboot,
    ...(state.ubootScript ? { ubootScript: state.ubootScript } : {}),
  });
  syncFindings(c.imageId, 'boot-cmdline', r.findings);
  c.handle.log(`↔ kernel cmdline cross-check: ${r.verdict} — ${r.reason}`);
  const lineClause = r.comparedUbootLine === 'none' ? '' : ` (compared the ${r.comparedUbootLine} U-Boot line)`;
  return {
    summary: `cmdline cross-check: ${r.verdict}${lineClause}`,
    findingCount: r.findings.length,
    // `unresolved-variables` is the check REFUSING to answer, which is a stage that could not do its job. The
    // absence verdicts are the stage doing its job and reporting that a source carried nothing — a real result.
    ...(r.verdict === 'unresolved-variables' ? { degraded: true } : {}),
    note: r.reason,
  };
}

async function ubootRun(c: RunCtx): Promise<StepOutcome> {
  const r = runUbootAnalysis(c.imagePath);
  syncFindings(c.imageId, 'uboot', r.findings);
  c.bootCmdlines.ubootRan = true;
  const bootargs = r.vars.bootargs;
  // `capVars` keeps `bootargs` first whatever the cap, so the audit input is never the thing that gets dropped.
  // The whole variable map goes with it: a real `bootargs` is routinely a template of `${…}` references (the
  // Tenda camera's is nothing else), and without the store the cross-check cannot tell a differing value from an
  // unexpanded one. What the cap DID drop shows up as an unresolved reference, which refuses the comparison —
  // unless the provider can state the map is complete, in which case an absent name is the board's own answer.
  const variables = r.vars;
  const complete = r.varsComplete === true;
  c.bootCmdlines.uboot = bootargs
    ? {
        value: bootargs,
        origin: { where: 'the stored U-Boot environment', evidence: { var: 'bootargs' } },
        variables,
        variablesComplete: complete,
      }
    : null;
  // The stored variable is not necessarily the operative line: a `bootcmd` script may re-set it before booting.
  const script = r.bootScript;
  c.bootCmdlines.ubootScript = script
    ? {
        assembled: script.variants.map((v) => ({
          value: v.value,
          origin: {
            where: `the kernel command line \`${v.via.join(' → ')}\` assembles`,
            evidence: {
              var: 'bootargs',
              via: v.via,
              statement: v.statement,
              ...(v.conditional ? { conditional: true } : {}),
            },
          },
          variables,
          variablesComplete: complete,
          conditional: v.conditional,
        })),
        ambiguous: script.ambiguous,
        note: script.reason,
      }
    : null;
  const assembledClause = script?.variants.length
    ? ` · ${script.variants.length} assembled cmdline variant(s) from ${script.roots.join('/')}`
    : '';
  return {
    summary: `U-Boot / boot posture: ${r.findings.length} findings${assembledClause}`,
    findingCount: r.findings.length,
    ...(script?.variants.length ? { note: script.reason } : {}),
  };
}

/**
 * ISTG-FW update-path integrity. Runs with or without a rootfs — without one only the image container is read, and
 * the step reports itself degraded rather than letting the unasked half read as a clean pass.
 */
async function updatepathRun(c: RunCtx): Promise<StepOutcome> {
  const r = runUpdatePath(c.imagePath, c.rootfsPath);
  syncFindings(c.imageId, 'updatepath', r.findings);
  const sig = r.imageIntegrity.items.filter((i) => i.strength === 'signature').length;
  return {
    summary: `update-path integrity: ${r.updaters.length} updater(s), ${sig} image signature structure(s), rollback ${r.rollback.state}`,
    findingCount: r.findings.length,
    ...(c.rootfsPath
      ? {}
      : { degraded: true, note: 'no rootfs — only the image container was read, so the updater half is unanswered' }),
  };
}

/**
 * The board description the image carries. Reads the raw image (and the FIT/UBI chain inside it) plus, when W1 has
 * already run, the extraction output — so a `*.dtb` written out by the carve is picked up too. A degraded step when
 * no tree could be read: that is `blocked_by_platform` naming where it looked, never a clean stage.
 */
async function devicetreeRun(c: RunCtx): Promise<StepOutcome> {
  const r = runDeviceTreeAnalysis(c.imagePath, c.outputDir);
  syncFindings(c.imageId, 'devicetree', r.findings);
  // The tree's half of the cross-check. `where`/`evidence` are byte-identical to what `deviceTreeFindings` hands
  // `auditKernelCommandLine`, so a reader sees one provenance dialect across both findings; `bootargs` is already
  // the ASSEMBLED line (`bootargs` + the OpenWrt `bootargs-append`), which is what a board would boot with. Set
  // before the not-found branch: "the tree declared none" is an input to the cross-check, not a reason to skip it.
  c.bootCmdlines.deviceTreeRan = true;
  c.bootCmdlines.deviceTree = r.blobs
    .filter((b) => b.bootargs)
    .map((b) => ({
      value: b.bootargs as string,
      origin: {
        where: `the device tree's /chosen node (${b.origin})`,
        evidence: { origin: b.origin, node: '/chosen', properties: b.bootargsFrom },
      },
    }));
  const models = r.blobs.map((b) => b.model ?? b.compatible[0] ?? b.origin).join(', ');
  if (!r.found) {
    return {
      summary: 'device tree: none readable in this image',
      findingCount: r.findings.length,
      degraded: true,
      note: r.reason,
    };
  }
  return {
    summary: `device tree (${models}): ${r.findings.length} findings`,
    findingCount: r.findings.length,
  };
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

/** UEFI depth — run the upstream FwHunt rule corpus. A clean scan is never an empty result (see the provider). */
async function fwhuntRun(c: RunCtx): Promise<StepOutcome> {
  const r = await runFwHunt(c.imagePath, c.handle);
  syncFindings(c.imageId, 'fwhunt', r.findings);
  if (!r.available) {
    return {
      summary: 'FwHunt implant scan: unavailable',
      findingCount: r.findings.length,
      degraded: true,
      note: r.reason,
    };
  }
  // Coverage is now TWO fractions and the step has to degrade on the weaker one. `rulesRun` used to mean the rules
  // the whole-image pass exercised, and a low count meant thin coverage; since the per-module pass landed it is the
  // union of both passes and runs near the whole corpus, so the old `rulesRun * 2 < rulesInCorpus` test can no
  // longer trip — a scan that ran 106 of 108 rules over 2 of 125 carved modules would have reported as a clean
  // stage. Module coverage is the fraction that can still be thin, so that is the one that decides.
  const mp = r.modulePass;
  const moduleCoverageThin = !!mp && mp.ran && mp.modulesCarved > 0 && mp.modulesScanned.length * 2 < mp.modulesCarved;
  const modulePassBlocked = !mp || !mp.ran;
  const moduleNote = mp?.ran
    ? `${mp.modulesScanned.length}/${mp.modulesCarved} carved module(s) scanned — ${mp.modulesSkipped.length} dropped by a bound (${mp.skipReason}); the rest is coverage you did not get`
    : `the per-module pass did not run: ${mp?.reason || 'no module pass'} — only the whole-image rules were exercised`;
  return {
    summary: `FwHunt implant scan: ${r.matches.length} match(es), ${r.rulesRun}/${r.rulesInCorpus} rule(s) over ${mp?.ran ? `${mp.modulesScanned.length}/${mp.modulesCarved}` : '0'} carved module(s)`,
    findingCount: r.findings.length,
    ...(moduleCoverageThin || modulePassBlocked ? { degraded: true, note: moduleNote } : {}),
  };
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
  c.handlers = r.handlers; // the other half of W5's probe ranking — see the note on `services` above.
  const tainted = r.handlers.filter((h) => h.tainted).length;
  // Two lead kinds from one worker: decompile the httpd that SERVES the tainted handler, and ask angr about the
  // native helpers that handler EXECS. The second is the sharpest reachability question the pipeline can pose —
  // the argv the prober makes symbolic is literally the channel W4 just proved is attacker-controlled — so it is
  // scheduled before the binvuln sweep gets to spend the shared budget on syntactic candidates.
  const probes = taintReachabilityLeads(r.handlers, c.rootfsPath as string, reachabilityBudget(c));
  const leads = [...handlerLeads(r.handlers, c.rootfsPath as string), ...probes];
  const probeNote = probes.length ? `, ${probes.length} exec'd helper(s) queued for reachability` : '';
  return {
    summary: `web attack-surface: ${r.handlers.length} handlers, ${tainted} tainted → ${r.findings.length} findings${probeNote}`,
    findingCount: r.findings.length,
    ...(leads.length ? { leads } : {}),
    ...(r.handlers.length === 0 ? { degraded: true, note: r.reason } : {}),
  };
}

/** W5 breadth — sweep every rootfs ELF for stack-overflow candidates (unbounded-copy + no canary). */
async function binvulnRun(c: RunCtx): Promise<StepOutcome> {
  // The exposure signal has to be built BEFORE the sweep, not after it. It used to be assembled below, purely for
  // the probe ranking, which meant the finding cap chose its list without it — and the cap's smallest-first rule
  // drops the largest candidate, which is always the exposed daemon. So the rank that exists to promote
  // `usr/bin/httpd` never saw it: `runBinVuln` had already deleted it from the list the rank reads.
  //
  // UNDEFINED when neither stage ran, and that is load-bearing rather than a convenience: it is the difference
  // between "nothing is exposed here" (a measured property — DVRF really does have zero services) and "nobody
  // asked", which rank the same way and are opposite facts. The sweep's reason says which of the two it had.
  const interest: ProbeInterest = {
    ...(c.services ? { services: c.services } : {}),
    ...(c.handlers ? { handlers: c.handlers } : {}),
    planned: c.planned,
  };
  const exposed =
    c.rootfsPath && (c.services || c.handlers)
      ? new Set(interestingBinaries(c.rootfsPath, interest).keys())
      : undefined;
  const r = runBinVuln(c.rootfsPath, exposed);
  syncFindings(c.imageId, 'binvuln', r.findings);
  // Each candidate is a precondition, not a bug. Hand as many as the run's remaining angr budget allows to the
  // symbolic prober so it can settle whether the sink is on a live path instead of leaving a list of maybes. The
  // budget may already be spent by W4's better-founded questions — that is the intent, not a shortfall, but the
  // unasked candidates must still be visible as unasked.
  const budget = reachabilityBudget(c);
  // Ranked on two axes, not one. Size says which questions RESOLVE; W3's service map and W4's handler analysis say
  // which are worth ASKING, and the ranking draws from both queues round-robin so neither can take the whole
  // allowance. `interest` is built above, because the finding cap needs the same signal.
  const copyLeads = c.rootfsPath ? reachabilityLeads(r.findings, c.rootfsPath, budget, interest) : [];
  // The other question this sweep's rows support, and until now nothing asked it: 127 command-exec sink rows sat in
  // the corpus with no lead kind at all. Its own budget, so scheduling it takes nothing from the line above.
  const execLeads = c.rootfsPath ? cmdexecLeads(r.findings, c.rootfsPath, cmdexecBudget(c), interest) : [];
  const leads = [...copyLeads, ...execLeads];
  const unasked = Math.max(0, r.candidates - copyLeads.length);
  // A probe that jumped the queue says so in its own `reason`, but the sweep's line is where a reader learns the
  // ordering was not purely by size — otherwise a 1.4 MB binary at the head of a smallest-first list reads as a bug.
  const promoted = leads.filter((l) => l.reason.includes('ranked ahead of smaller candidates')).length;
  const probeNote = r.candidates
    ? ` — ${copyLeads.length} queued for reachability${promoted ? ` (${promoted} ranked ahead on exposure)` : ''}${
        unasked ? `, ${unasked} left as unproven candidate(s)` : ''
      }`
    : '';
  // Counted and stated separately from the line above, because they are a different question against a different
  // budget: rolling them into one number would make a run look like it asked more of the candidates than it did.
  const execSinks = r.findings.filter((f) => f.kind === 'binary-cmdexec-sink').length;
  const execNote = execSinks
    ? `, ${execSinks} command-exec sink(s)${execLeads.length ? ` — ${execLeads.length} queued for reachability` : ''}`
    : '';
  // The sweep counts every candidate it found but lists only what fits its finding cap, so when the two differ the
  // summary has to say which number the ledger below it actually holds.
  const listed = r.findings.filter((f) => f.kind === 'binary-pwnable-candidate').length;
  const listedNote = listed < r.candidates ? ` (${listed} smallest listed)` : '';
  return {
    summary: `binary-vuln sweep: ${r.binariesScanned} ELFs, ${r.candidates} stack-overflow candidate(s)${listedNote}${probeNote}${execNote}`,
    findingCount: r.findings.length,
    ...(leads.length ? { leads } : {}),
    ...(r.binariesScanned === 0 ? { degraded: true, note: r.reason } : {}),
  };
}

/**
 * W5 depth — symbolic reachability, scheduled by W9's re-planning off a binvuln candidate. Answers one question per
 * sink: is the call site reachable from the entry point under symbolic input? A reached sink is a `static_confirmed`
 * reachability claim; a sink not reached inside the budget stays inconclusive and is recorded as such.
 */
async function symreachRun(c: RunCtx, spec: PlanSpec): Promise<StepOutcome> {
  const binary = spec.target;
  if (!binary)
    return { summary: 'no target binary', findingCount: 0, degraded: true, note: 'symreach spec missing target' };
  // The POLICY has to follow the question, and getting this wrong is not a subtle failure — it is a silent one.
  // `pickSinks` defaults to `unsafe-copy`, which keeps only the unbounded-copy names; handed `system/popen/execve`
  // it keeps NOTHING, and `runSymReach` then returns `unavailable('no sink to ask about')` — which composes a
  // `blocked_by_platform` row reading *"the deployment could not answer it"*. Measured on the deployed build: the
  // WR940N's `usr/bin/httpd` came back blocked from the scan minutes after the manual route proved `system`
  // REACHED in the same binary in 11 s. The deployment could answer perfectly well; this caller was asking with a
  // filter that deleted its own question, and the honest-sounding row hid it.
  // The provider no longer absorbs the blame — a question that cannot be POSED comes back `blockedBy: 'request'`
  // and writes no row — so the same mistake would now surface here, as this step's own defect. Keeping the policy
  // right remains this function's job; what changed is that getting it wrong is no longer silent.
  const r = await runSymReach(
    c.rootfsPath,
    binary,
    spec.sinks ?? [],
    c.handle,
    spec.sinkClass === 'cmdexec' ? { policy: 'as-given' } : {},
  );
  // Per-binary idempotent source, mirroring `binary:<path>` — a re-run re-syncs rather than duplicating. Taken from
  // `specKey` rather than rebuilt here, so the string that DEDUPS the spec and the string that OWNS its rows cannot
  // drift: one binary now carries two independent questions, and a copy of this expression that forgot the second
  // one would have the command-exec answer delete the unbounded-copy answer on every image carrying both.
  syncFindings(c.imageId, specKey(spec), r.findings);
  if (!r.available) {
    // `request` is THIS orchestrator's defect, not a limit it ran into: the spec named a binary that is not in the
    // rootfs, or sinks the policy discards. Reporting it as "unavailable" beside the genuinely unavailable ones is
    // the same conflation the provider just stopped committing, one layer up — it reads as a deployment short of a
    // capability, which is exactly the sentence that hid the last instance.
    const specDefect = r.blockedBy === 'request';
    return {
      summary: specDefect
        ? `reachability ${binary}: the spec could not be posed — nothing was asked`
        : `reachability ${binary}: unavailable`,
      findingCount: r.findings.length,
      degraded: true,
      note: specDefect ? `spec defect, not a capability limit: ${r.reason}` : r.reason,
    };
  }
  // Answered and cheap: the binary carries no unbounded-copy symbol, so the derived question had no subject. No
  // budget was spent and nothing was left inconclusive, so the "no sink reached inside the budget" sentence below
  // would invent a search that never ran.
  if (r.asked?.length === 0) {
    return {
      summary: `reachability ${binary}: no unbounded-copy sink to ask about (answered, not blocked)`,
      findingCount: r.findings.length,
      note: r.reason,
    };
  }
  const reached = r.sinks.filter((s) => s.outcome === 'reached');
  // A proven-reachable sink is the best possible candidate for actually running the thing.
  const leads = c.rootfsPath ? reproductionLeads(r.findings, c.rootfsPath) : [];
  // Name the sinks that were asked about: a bare "no sink reached" hides whether one question or four were posed.
  const askedNote = r.asked?.length ? ` [asked: ${r.asked.join('/')}${r.derivedSinks ? ', derived' : ''}]` : '';
  const summary = reached.length
    ? `reachability ${binary}: ${reached.map((s) => s.sink).join('/')} reachable from entry${askedNote}`
    : `reachability ${binary}: no sink reached inside the budget (inconclusive, not clean)${askedNote}`;
  return {
    summary,
    findingCount: r.findings.length,
    ...(leads.length ? { leads } : {}),
    ...(reached.length === 0 ? { degraded: true, note: r.reason } : {}),
  };
}

/**
 * W5 depth — dynamic reproduction, scheduled off a sink `symreach` proved reachable. Runs the binary under
 * qemu-user with a breakpoint on that call site and a cyclic input, so a lead that static analysis can only
 * establish as *reachable* gets a chance to be settled as *faulting* — the one step that moves a finding off
 * `needs_runtime_reproduction`.
 */
async function dynprobeRun(c: RunCtx, spec: PlanSpec): Promise<StepOutcome> {
  const binary = spec.target;
  const sink = spec.sink;
  if (!binary || !sink) {
    return { summary: 'no target', findingCount: 0, degraded: true, note: 'dynprobe spec missing binary/sink' };
  }
  // Prefer the arch measured from the rootfs ELF headers over the whole-image guess: the guess is routinely
  // `unknown` (DVRF's is) while the measurement is the actual class of the binary about to be emulated.
  const identity = c.analysisJson ? (JSON.parse(c.analysisJson) as { identity?: ImageIdentity }).identity : undefined;
  const arch = c.detectedArch ?? (identity?.arch !== 'unknown' ? identity?.arch : undefined);
  if (!arch) {
    return {
      summary: `reproduce ${binary}:${sink}`,
      findingCount: 0,
      degraded: true,
      note: 'no architecture known for this rootfs — cannot choose a user-mode emulator',
    };
  }
  const r = await runDynProbe(c.rootfsPath, binary, sink, spec.addresses ?? [], arch, c.handle);
  syncFindings(c.imageId, `dynprobe:${binary}#${sink}`, r.findings);
  const settled = r.probe?.verdict === 'crash_input_controlled' || r.probe?.verdict === 'crash';
  return {
    summary: `reproduce ${binary}:${sink} → ${r.probe?.verdict ?? 'unavailable'}`,
    findingCount: r.findings.length,
    // Anything short of an observed fault leaves the candidate exactly where it was, and says so.
    ...(settled ? {} : { degraded: true, note: r.reason }),
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
  nvram: nvramRun,
  sbom: sbomRun,
  compcve: compcveRun,
  kernel: kernelRun,
  servicemap: servicemapRun,
  certs: certsRun,
  compmap: compmapRun,
  uboot: ubootRun,
  updatepath: updatepathRun,
  devicetree: devicetreeRun,
  bootcmdline: bootCmdlineRun,
  fcc: fccRun,
  rtos: rtosRun,
  chipsec: chipsecRun,
  fwhunt: fwhuntRun,
  esp: espRun,
  encrypted: encryptedRun,
  webtaint: webtaintRun,
  binvuln: binvulnRun,
  symreach: symreachRun,
  dynprobe: dynprobeRun,
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

  // W9 re-planning: the class DAG is only the SEED. A worker can surface a lead mid-run (a network daemon, the
  // httpd serving a tainted handler, a native helper a tainted handler execs) that schedules a follow-up worker —
  // so the fixed plan becomes a dynamic worklist. Growth is deduped + capped so re-planning always terminates; a
  // lead past the cap is surfaced, not silently dropped.
  const MAX_DYNAMIC_STEPS = 8;
  const agenda: PlanSpec[] = [...seed];
  const sched: ScheduleState = { planned: new Set(seed.map(specKey)), dynamicCount: 0, capped: 0 };

  const prior = latestExtract(imageId);
  const ctx: RunCtx = {
    imageId,
    imagePath,
    analysisJson: row.analysisJson,
    rootfsPath: prior?.rootfsPath ?? null,
    outputDir: prior?.outputDir ?? null,
    ...(prior?.carveTrace ? { carveTrace: prior.carveTrace } : {}),
    ...(prior?.detectedArch ? { detectedArch: prior.detectedArch } : {}),
    // Live view of the agenda — executors size the shared reachability budget off it as the run grows.
    planned: sched.planned,
    bootCmdlines: { ubootRan: false, uboot: null, ubootScript: null, deviceTreeRan: false, deviceTree: [] },
    handle,
  };

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
    // Name what was actually dropped. This said "daemon lead(s)" for every kind, so a run that ran out of budget
    // on crash reproductions sent the operator to triage daemons instead — the count was right and the noun was
    // wrong, which is the worst shape for a bound to take.
    const byKind = Object.entries(sched.cappedByKind ?? {})
      .map(([kind, n]) => `${n} ${LEAD_KIND_LABEL[kind as keyof typeof LEAD_KIND_LABEL] ?? kind}`)
      .join(', ');
    steps.push({
      worker: 'W9 · Re-plan (cap reached)',
      status: 'degraded',
      summary: `${sched.capped} further lead(s) not scheduled — dynamic step cap ${MAX_DYNAMIC_STEPS} reached${byKind ? ` (${byKind})` : ''}`,
      note: 'honest bound: raise the cap, or run the named rung by hand on the leads it did not reach',
    });
  }

  // Measured rows only. The scan reports what IT established; an operator assertion that happens to sit on the
  // same image was not produced by any worker here, and letting one into the narrative's evidence would let a
  // human sentence become part of an attack path the scan claims to have traced.
  const findings = partitionByProvenance(listFindings(imageId).map(rowToFinding)).measured;
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
