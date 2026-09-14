/**
 * What would change a degraded stage — the field a coverage campaign cannot be planned without.
 *
 * A `degraded` cell says a stage covered less than its name suggests. It does not say whether anything can be done
 * about it, and measured on the deployed corpus the difference is most of the number: of 85 degraded cells among
 * 411 applicable ones, 22 are "this image carries no device tree, and every place one could be was read" — which
 * no re-run will ever change — while others are a tool this deployment does not have, a cap that truncated a walk
 * that CAN complete, a harness that broke, or a symbolic search that is inconclusive by construction. Ranked
 * together they rank noise: a campaign that re-runs all 85 spends its budget on the 22 that are already answered.
 *
 * So every degradation declares its remedy, derived from the state its provider already returns — never from
 * parsing the English note, which is how the campaign would inherit a defect every time a sentence is reworded.
 * The mappers are pure and live here rather than in `opacidad.ts` because that module imports `store.js`, and a
 * test file that imports it does not load at all (vitest cannot resolve `node:sqlite`).
 *
 * **`remedy` is optional forever, and absent means UNKNOWN.** Step outcomes are persisted on a job row and re-read
 * for as long as the image exists, so every stored run predates this field. An absent remedy is never read as
 * `settled` and never counted as executable work: the campaign reports it as undeclared, and the thing that fills
 * it in is re-running that stage. Where a site genuinely cannot tell — an extractor gap and a truncated volume
 * reach `runExtract` as the same absence — it emits nothing rather than guessing, which is the same rule the
 * providers already follow for a bound they cannot describe.
 */
import type { CredMatchState } from './providers/credmatch.js';
import type { ExtractedDeviceTreeScan } from './providers/devicetree.js';
import type { ProbeVerdict } from './providers/dynprobe.js';
import type { SymReachBlockedBy } from './providers/symreach.js';
import type { YaraScanState } from './providers/yarascan.js';

/**
 * The closed vocabulary of "what would change this cell". Four of the eight are executable by a campaign, and the
 * split is the whole point of the type:
 *
 * - `retry` — the run itself broke (harness failure, a racing dedicated campaign, a thrown executor). The same
 *   question against the same bytes may settle it. EXECUTABLE.
 * - `raise-bound` — a cap truncated a search that *can* finish. Raising it covers strictly more. EXECUTABLE.
 * - `install-tool` — this deployment lacks the binary, venv or rule corpus the stage needs. Fix the deployment,
 *   then re-run. EXECUTABLE, but not by a scan alone.
 * - `escalate-full-system` — qemu-user reached its environment ceiling. A new W9 run schedules the image-wide
 *   full-system rung instead of repeating that process-level question. EXECUTABLE.
 * - `reacquire-input` — the input is not in these bytes (no rootfs recovered, a truncated volume, no kernel). A
 *   different artifact is needed; re-running the same image cannot change it. NOT executable.
 * - `settled` — the stage looked everywhere it can and this is its answer for this image. NOT executable, and
 *   emphatically not a defect: a great many images carry no device tree and no web handlers.
 * - `unbounded-search` — inconclusive by construction (symbolic exploration, a per-module timeout that does not
 *   converge). More budget asks more, but no budget completes it and no run proves the negative. NOT executable
 *   as coverage debt, because "done" is not a state it has.
 * - `defect` — the degradation is FirmLab's, not the image's: a spec that could not be posed, a request built with
 *   a filter that deleted its own question. The fix is code. NOT executable as a re-run.
 */
export type DegradedRemedy =
  | 'retry'
  | 'raise-bound'
  | 'install-tool'
  | 'reacquire-input'
  | 'settled'
  | 'unbounded-search'
  | 'escalate-full-system'
  | 'defect';

/**
 * Stamped on every persisted run, so "did this run declare remedies?" is READ rather than inferred. Inferring it
 * from the steps — "some degraded cell declares one, so the run must" — is wrong in a way that was measured the
 * first time the campaign ran: the coverage report recomputes the FwHunt cell from its durable campaign result, so
 * a run stored months ago can show exactly one declared cell, and the inference then labels its genuinely stale
 * neighbours as sites that cannot tell. Two UEFI images dropped out of the queue that way.
 */
export const REMEDY_SCHEMA = 2;

/**
 * Remedies a coverage campaign can act on by scheduling work. The rest are reported, never queued.
 *
 * `escalate-full-system` is executable because a `defect` was the WRONG label for a probe that hit qemu-user's
 * ceiling (no NVRAM, no device nodes): re-running the scan now routes it to the full-system rung, which supplies
 * exactly the environment the probe lacked. It is the only executable remedy that schedules a heavier rung rather
 * than a retry of the same one.
 */
export const EXECUTABLE_REMEDIES: readonly DegradedRemedy[] = [
  'retry',
  'raise-bound',
  'install-tool',
  'escalate-full-system',
];

export function isExecutableRemedy(remedy: DegradedRemedy | undefined): boolean {
  return remedy !== undefined && EXECUTABLE_REMEDIES.includes(remedy);
}

/**
 * Credential cross-reference. The provider's four blocked states already name four different responses (see the
 * comment on `blockedResult`), and only the first is about missing input: DVRF symlinks its whole account database
 * to /dev/null, and an image whose every account is locked or passwordless has been *answered*, not blocked.
 */
export function remedyForCredMatch(state: Exclude<CredMatchState, 'scanned'>): DegradedRemedy {
  switch (state) {
    case 'no_target':
      return 'reacquire-input';
    case 'no_account_files':
    case 'no_hashes':
      return 'settled';
    case 'no_candidates':
      // No printable strings were harvested from the image. Re-running the same bytes harvests the same nothing.
      return 'reacquire-input';
  }
}

/** YARA. Four of the six blocked states are this deployment's rule corpus, not the firmware. */
export function remedyForYaraScan(state: Exclude<YaraScanState, 'scanned'>): DegradedRemedy {
  switch (state) {
    case 'tool_absent':
    case 'no_corpus':
    case 'corpus_empty':
    case 'no_rules_applied':
      return 'install-tool';
    case 'no_target':
      return 'reacquire-input';
    case 'scan_failed':
      return 'retry';
  }
}

/**
 * A blocked reachability probe, symbolic or export-graph. `blockedBy` is the discriminant `symreach` grew after a
 * `request` defect spent months reading as a deployment limit — keep the three apart here too, or the campaign
 * re-runs a question that this orchestrator asked wrong. `exportreach` carries the same three.
 */
export function remedyForBlockedProbe(blockedBy: SymReachBlockedBy | undefined): DegradedRemedy | undefined {
  switch (blockedBy) {
    case 'platform':
      return 'install-tool';
    case 'harness':
      return 'retry';
    case 'request':
      return 'defect';
    default:
      return undefined; // an older result with no discriminant: unknown, not assumed
  }
}

/**
 * One export-reachability step covers several objects, and they can be blocked for different reasons at once. The
 * worst-to-best order is deliberate: a deployment without angr is what a reader must act on first, and a summary
 * that reported the mildest cause would hide it behind a budget note.
 */
export function remedyForBlockedProbes(blocked: readonly (SymReachBlockedBy | undefined)[]): DegradedRemedy {
  if (blocked.some((b) => b === 'platform')) return 'install-tool';
  if (blocked.some((b) => b === 'harness')) return 'retry';
  if (blocked.some((b) => b === 'request')) return 'defect';
  // Every object answered within its budget and simply reached nothing: the search, not the deployment.
  return 'unbounded-search';
}

/**
 * Dynamic reproduction. Only `not_attached` is a harness failure; the rest observed the program and did not see it
 * misbehave, which is a result about the probe's reach, not a gap in coverage.
 *
 * `emulation_artifact` is FirmLab's rung, not the firmware: the provider's own reason says so — "a limit of
 * qemu-user (no NVRAM, no device nodes, no peripherals), not a result about the code". It was briefly mapped to
 * `reacquire-input`, which reads as "get a different firmware" and is plainly the wrong instruction; DVRF carried
 * two such cells and neither has anything to do with the bytes. It then read as `defect` — also wrong, because a
 * defect is FirmLab's dead-end and this is a rung mismatch with a known escalation: the full-system rung boots the
 * whole firmware and provides the NVRAM and device nodes qemu-user cannot. So it is `escalate-full-system`, and W9
 * schedules that rung off the same verdict (see `dynprobeRun`).
 */
export function remedyForProbeVerdict(verdict: ProbeVerdict | undefined): DegradedRemedy | undefined {
  switch (verdict) {
    case 'not_attached':
      return 'retry';
    case 'emulation_artifact':
      return 'escalate-full-system';
    case 'sink_executed':
    case 'ran_clean':
      return 'unbounded-search';
    case 'crash':
    case 'crash_input_controlled':
      return undefined; // settled outcomes: the step is not degraded at all
    default:
      return undefined; // no probe ran; the step reports its own unavailability
  }
}

/**
 * Device tree. The one that matters most by volume, and the one most easily mislabelled: "no FDT magic anywhere in
 * the inputs that were read" is a real negative about these bytes — a great many vendor builds describe their board
 * in compiled-in C — and stays `blocked_by_platform` as a finding while being `settled` as coverage debt. It is
 * only unlockable when the *search* was short: extracted candidates left unread, or a walk that did not finish.
 *
 * A validated FDT header that could not be read to completion is deliberately undeclared. It is either a truncated
 * tree (reacquire) or a parser that stops early (defect) and nothing at this layer can tell which.
 */
export function remedyForDeviceTree(input: {
  extractionScan?: ExtractedDeviceTreeScan | undefined;
  rejectedCount: number;
  /** True when extraction output existed to be walked — an unwalked rootfs is an unexamined place, not a negative. */
  extractionAvailable: boolean;
}): DegradedRemedy | undefined {
  const { extractionScan, rejectedCount, extractionAvailable } = input;
  if (extractionScan) {
    const unexamined =
      extractionScan.skippedByFileCap + extractionScan.skippedOversize + extractionScan.skippedUnreadable;
    if (!extractionScan.traversalComplete || unexamined > 0) return 'raise-bound';
  } else if (extractionAvailable) {
    return undefined; // output existed but no walk was recorded: unknown coverage, not a settled negative
  }
  if (rejectedCount > 0) return undefined;
  return 'settled';
}

/**
 * Web attack surface. Same shape as the device tree: a rootfs with no rpcd/luci/cgi handler at all is an answer,
 * and only an incomplete or capped walk leaves something to ask.
 */
export function remedyForWebTaint(input: { partialWalk: boolean; handlers: number }): DegradedRemedy {
  if (input.partialWalk) return 'raise-bound';
  return input.handlers === 0 ? 'settled' : 'raise-bound';
}

/**
 * FwHunt. Carving no EFI modules from a variable store is that store's answer; leaving modules unattempted is the
 * dedicated campaign's work; a module that exhausts its per-module timeout never converges however often it runs.
 */
export function remedyForFwHunt(input: {
  available: boolean;
  modulePassRan: boolean;
  modulesCarved: number;
  modulesScanned: number;
  modulesFailed: number;
  modulesSkipped: number;
}): DegradedRemedy {
  if (!input.available) return 'install-tool';
  if (!input.modulePassRan) return input.modulesCarved === 0 ? 'settled' : 'raise-bound';
  if (input.modulesSkipped > 0 || input.modulesScanned * 2 < input.modulesCarved) return 'raise-bound';
  if (input.modulesFailed > 0) return 'unbounded-search';
  return 'settled';
}

/**
 * Kernel-module surface. Found by running the campaign against the deployed corpus, not by a test: the step
 * degrades on `!callSitePass.available`, which is radare2's availability — EXCEPT on a rootfs with no `.ko` file
 * at all, where the pass was never reached and the same flag is false. Every module-less image was therefore
 * reporting a missing disassembler, which is a deployment gap a reader would go and act on.
 *
 * A module-less rootfs declares nothing, deliberately: the provider's own reason says a monolithic kernel and a
 * carve that missed `lib/modules` produce this result identically, and they need opposite responses.
 */
export function remedyForKmod(input: {
  modulesFound: number;
  callSitePassAvailable: boolean;
  symbolTableUnreadable: number;
}): DegradedRemedy | undefined {
  if (input.modulesFound === 0) return undefined;
  if (!input.callSitePassAvailable) return 'install-tool';
  // Modules were read and disassembled; some carry a symbol table that cannot be parsed. That is their shape.
  return input.symbolTableUnreadable > 0 ? 'settled' : undefined;
}

/**
 * Extraction that recovered no rootfs. Volumes that came out and hold no `bin`/`etc`/`lib` are a data dump and are
 * answered; everything else — a carved filesystem nobody could open, a stream that died mid-decompression, nothing
 * at all — reaches this layer as the same absence, and `extract-diagnose` separates them only in prose. Undeclared
 * is the honest answer there: see the backlog entry for structuring that verdict.
 */
export function remedyForNoRootfs(input: {
  isDecoy: boolean;
  diagnosed: boolean;
  volumes: number;
  unopenedBlobs: number;
}): DegradedRemedy | undefined {
  if (input.isDecoy) return 'reacquire-input';
  if (input.diagnosed && input.volumes > 0 && input.unopenedBlobs === 0) return 'settled';
  return undefined;
}
