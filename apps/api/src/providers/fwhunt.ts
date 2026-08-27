/**
 * fwhunt-scan provider — the honest route to UEFI implant detection.
 *
 * The UEFI track already parses firmware volumes and enumerates modules (providers/chipsec.ts), and it carries a
 * `FIRMLAB_UEFI_IOC` hook for operator-supplied indicators. What it deliberately does NOT carry is a curated feed
 * of "known implant" GUIDs, and the reason is recorded in docs/BACKLOG.md: the advanced implants people actually
 * care about — LoJax, MoonBounce, CosmicStrand, BlackLotus — are not reliably GUID-detectable, and there are no
 * stable public file-GUIDs for those families. A hand-assembled GUID list would have looked like threat
 * intelligence and been fabrication. That is precisely why Binarly's FwHunt rules match on CODE PATTERNS (esil
 * expressions, hex strings, NVRAM variable usage) rather than identity.
 *
 * So FirmLab ships the SCANNER and the upstream RULES as data, and authors neither. This provider runs
 * `fwhunt_scan_analyzer.py` over a UEFI image with the rule corpus and turns its verdicts into findings.
 *
 * TWO PASSES, because one of them barely covers anything. `scan-firmware` offers a rule only to the modules that
 * live inside the firmware volume GUIDs the rule's author declared, so most of the corpus never runs: on the OVMF
 * build shipped with this deployment's QEMU, 17 of 108 rules ran and they touched 6 of the 125 EFI modules in the
 * image. The other 91 rules examined nothing, and the provider's own reason string said so. `scan-module` (an
 * alias of `scan` in the installed analyzer) takes ONE carved EFI file and an explicit rule list, applies no
 * scoping test at all, and lifts that to 102 rules — every rule in the corpus whose target is a module. So the
 * provider carves the image into modules (with the analyzer's own `extract`, or from a directory a caller already
 * carved — chipsec's `<img>.dir` tree works) and runs the module-target corpus against them.
 *
 * The honesty contract:
 *
 *  - A rule match is `static_confirmed` and the claim is *this rule matched these bytes*, attributed to the rule's
 *    own name and category. FirmLab is not the author of the detection and does not restate it as its own verdict.
 *  - NO match is NOT "no implant". The corpus covers the families someone wrote a rule for; everything else is
 *    unexamined by construction. The result therefore always carries how many rules ran, and a clean scan emits an
 *    explicit `info` finding saying what was and was not covered, rather than an empty result that reads as clean.
 *  - fwhunt-scan / rizin absent ⇒ `blocked_by_platform` with the reason, never a silent skip.
 *  - The per-module pass buys RULE coverage by spending MODULE coverage, and both numbers are reported. It scans a
 *    bounded number of modules (a rizin analysis per module, ~10-30 s each) and it runs rules OUTSIDE the volume
 *    scoping their authors set, so a match seen only there is graded a step lower and says why. The bound spends
 *    its slots on the modules nothing has looked at yet, the ones the loaded corpus was written about, and the
 *    ones that run at the highest privilege — never on the ones the carver happened to write first. A module that
 *    was not reached, a rule no pass could offer, a scan that crashed — each is reported as what it is.
 *
 * The output parser, the rule-corpus reader, the module ranking and the finding builder are PURE and unit-tested;
 * the runners only shell out under a timeout.
 */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import type { FindingDraft } from '../findings-normalize.js';
import { fwhuntPython, fwhuntRulesDir, isToolAvailable } from '../tools.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

/** Scanning a full image against the whole corpus is minutes of rizin analysis, not seconds. */
export const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;

/**
 * How many carved modules the per-module pass scans by default. Measured in-container against OVMF: one module
 * against the 102 module-target rules costs 10-30 s of rizin analysis, so scanning all 125 would be an hour. This
 * is a real bound on module coverage, not a claim about it — `rankModulesForScan` decides WHICH ones and the
 * coverage note states how many were left unexamined.
 */
export const DEFAULT_MODULE_CAP = 12;

/** Wall-clock ceiling for the whole per-module pass, so a slow module cannot eat the job on its own. */
export const DEFAULT_MODULE_BUDGET_MS = 6 * 60 * 1000;

/** Per-module ceiling. A module that blows through this is reported as unscanned, never as clean. */
export const DEFAULT_MODULE_TIMEOUT_MS = 90 * 1000;

/** The first deterministic slice of the global ranking. Batches are zero-based at the API boundary. */
export const DEFAULT_MODULE_BATCH = 0;

/** Bump this whenever the ordering keys change; stored campaigns from another ordering must not be merged. */
export const MODULE_RANKING_VERSION = 1;

/**
 * `FIRMLAB_FWHUNT_MODULE_CAP` — how many carved modules the per-module pass scans. `0` turns the pass off, which
 * is an honest answer for a deployment that cannot spend the minutes; the coverage note then says the pass did not
 * run rather than quietly reporting the whole-image numbers as the whole story.
 */
export function fwhuntModuleCap(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.FIRMLAB_FWHUNT_MODULE_CAP;
  if (raw === undefined || raw.trim() === '') return DEFAULT_MODULE_CAP;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_MODULE_CAP;
}

/**
 * `FIRMLAB_FWHUNT_MODULE_BATCH` — zero-based window in the globally ranked module list. Keeping this separate
 * from the cap lets repeated bounded runs cover disjoint modules without giving any one job a larger CPU budget.
 */
export function fwhuntModuleBatch(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.FIRMLAB_FWHUNT_MODULE_BATCH;
  if (raw === undefined || raw.trim() === '') return DEFAULT_MODULE_BATCH;
  const n = Number(raw);
  return Number.isSafeInteger(n) && n >= 0 ? n : DEFAULT_MODULE_BATCH;
}

/** One rule variant's verdict, as the analyzer reports it. */
export interface RuleVerdict {
  rule: string;
  /** Rules ship variants (`default`, `variant1`…); each is scanned and reported separately. */
  variant?: string;
  matched: boolean;
  /** The EFI module the rule was evaluated against, when the scanner names one. */
  module?: string;
}

/**
 * An EFI module carved out of a UEFI image — a file on disk that `scan-module` can be pointed at directly.
 */
export interface CarvedModule {
  path: string;
  /** Display label: the carved file's name with the GUID and extension the carver appended stripped off. */
  name: string;
  /** File GUID, when the carver put one somewhere in the path. */
  guid?: string;
  /** Path below the carve root, stable across temporary carve directories and therefore usable for resumption. */
  relativePath?: string;
}

/** A rule as it sits in the corpus: what the scanner will PRINT for it, and the scoping its author declared. */
export interface CorpusRule {
  /** Path relative to the rules dir — the category is read from it. */
  path: string;
  /** `meta.name`, which is what the scanner prints and is NOT always the filename. */
  name: string;
  /** `meta.target`: `firmware` or `bootloader`; absent means the rule is about a module. */
  target?: string;
  /**
   * `meta.description` — free prose, and the place the corpus most often names the module a rule is about when
   * neither the name nor the filename does (`CVE-2023-45230` names `Dhcp6Dxe` only here). Absent when the rule
   * declares none, which most do not.
   */
  description?: string;
  /** How many volume GUIDs the rule declares — the scoping the per-module pass deliberately bypasses. */
  volumeGuids: number;
  /** SHA-256 of the full YAML bytes; metadata equality is not enough to prove two detector versions are equal. */
  contentDigest: string;
}

/** A rule no pass could offer to a module, and the target that disqualified it. */
export interface ExcludedRule {
  rule: string;
  target: string;
}

/** One bounded ranking window, retained so re-running a window replaces/extends it rather than double-counting. */
export interface ModuleBatchRecord {
  index: number;
  rangeStart: number;
  rangeEnd: number;
  complete: boolean;
  modulesScanned: CarvedModule[];
  modulesFailed: CarvedModule[];
  verdicts: RuleVerdict[];
  unreadableLines: number;
}

/**
 * What the per-module pass actually did. Every field here exists so the caller can state a limit instead of
 * letting it read as coverage: modules it never reached, modules whose scan failed, rules it was not allowed to
 * run, and the rules it ran outside the scope their authors set.
 */
export interface ModulePass {
  ran: boolean;
  /** Why the pass did not run, when it did not. Empty once it has. */
  reason: string;
  verdicts: RuleVerdict[];
  unreadableLines: number;
  /** Modules found in the carve — the denominator module coverage is measured against. */
  modulesCarved: number;
  /** Zero-based deterministic ranking window requested for the latest run. */
  batchIndex: number;
  /** Number of cap-sized windows needed to cover the carve. */
  batchCount: number;
  /** Maximum modules selected by one window. */
  batchSize: number;
  /** Fully attempted windows whose results are accumulated in this result. */
  batchesCompleted: number[];
  /** Per-window provenance needed to merge retries without double-counting them. */
  batches: ModuleBatchRecord[];
  /** Successfully scanned modules added by the latest window, separate from the accumulated numerator below. */
  modulesScannedThisBatch: number;
  /** Ordering contract used for the stored campaign. */
  rankingVersion: number;
  /** Digest of the fully ordered module identities; proves two windows refer to the same ranges. */
  rankingFingerprint: string;
  /** Digest of rule identity/scoping; a changed corpus starts a new campaign rather than mixing verdicts. */
  corpusFingerprint: string;
  modulesScanned: CarvedModule[];
  /** Modules the bound dropped before they were scanned. */
  modulesSkipped: CarvedModule[];
  /** Modules the analyzer was pointed at and failed on — tried and unknown, not clean. */
  modulesFailed: CarvedModule[];
  /** The bound that dropped `modulesSkipped`, named. */
  skipReason: string;
  /** Module-target rules offered to every scanned module. */
  rulesOffered: number;
  rulesExcluded: ExcludedRule[];
  /** Offered rules that declare volume GUIDs — i.e. ones this pass ran outside their author's scoping. */
  scopedRuleNames: string[];
  /** Directories the walk refused to descend into, so an unreachably deep carve is visible rather than silent. */
  deepDirsSkipped: number;
  /** Why an earlier campaign was not resumed, when the caller supplied one that was incompatible. */
  campaignResetReason?: string;
}

export interface FwHuntResult {
  available: boolean;
  reason: string;
  /** Distinct rules that examined something here — the union of both passes. */
  rulesRun: number;
  /** Rules present in the corpus that examined nothing (no matching volume, and no pass could offer them). */
  rulesNotApplicable: number;
  rulesInCorpus: number;
  matches: RuleVerdict[];
  /** The per-module pass, or null when it was never attempted. */
  modulePass: ModulePass | null;
  findings: FindingDraft[];
}

/** The durable job fields needed to recover the newest dedicated FwHunt campaign. Jobs must be newest first. */
export interface FwHuntJobRecord {
  kind: string;
  status: string;
  resultJson: string | null;
}

/** A running dedicated job owns the FwHunt findings namespace until it reaches a terminal state. */
export function hasActiveFwHuntJob(jobs: ReadonlyArray<Pick<FwHuntJobRecord, 'kind' | 'status'>>): boolean {
  return jobs.some((job) => job.kind === 'fwhunt' && (job.status === 'queued' || job.status === 'running'));
}

/** An active autonomous UEFI scan may be inside its inline FwHunt stage and therefore owns the same namespace. */
export function hasActiveOpacidadJob(jobs: ReadonlyArray<Pick<FwHuntJobRecord, 'kind' | 'status'>>): boolean {
  return jobs.some((job) => job.kind === 'opacidad' && (job.status === 'queued' || job.status === 'running'));
}

/**
 * Pure: recover the newest completed FwHunt result that carries module-pass provenance.
 *
 * Keeping this lookup shared matters: the HTTP campaign route and the autonomous orchestrator must agree on
 * which durable result owns the campaign. Otherwise an autonomous scan can run an isolated batch zero and
 * overwrite findings accumulated by the dedicated route.
 */
export function latestFwHuntResult(jobs: readonly FwHuntJobRecord[]): FwHuntResult | null {
  for (const job of jobs) {
    if (job.kind !== 'fwhunt' || job.status !== 'done' || !job.resultJson) continue;
    try {
      const candidate = JSON.parse(job.resultJson) as FwHuntResult;
      const pass = candidate?.modulePass;
      // Accept useful legacy results as safe ledger snapshots; `accumulateModulePass` will deliberately reset
      // them when a new provenance-aware batch starts. Skip cap=0/no-carve/all-failed attempts so they cannot hide
      // an older campaign that actually examined modules.
      if (candidate.available && pass?.ran && Array.isArray(pass.modulesScanned) && pass.modulesScanned.length > 0) {
        return candidate;
      }
    } catch {
      // A malformed result proves nothing; an older well-formed campaign may still be usable.
    }
  }
  return null;
}

/** Severity by rule category — a live threat rule is not the same claim as a mitigation-hygiene rule. */
const CATEGORY_SEVERITY: Record<string, FindingDraft['severity']> = {
  Threats: 'critical',
  SupplyChain: 'high',
  Vulnerabilities: 'high',
  MitigationFailures: 'medium',
};

/** Strip the ANSI colour click emits when it thinks it has a terminal. */
function stripAnsi(s: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: matching the ESC of an ANSI SGR sequence is the point.
  return s.replace(/\[[0-9;]*m/g, '');
}

/** The two verdicts the analyzer prints. Anything else on a `Scanner result` line is an unknown, not a negative. */
const VERDICT_MATCHED = /^FwHunt rule has been triggered and threat detected!/i;
const VERDICT_CLEAN = /^No threat detected\b/i;

/**
 * Read one `Scanner result` line, or return null so the caller can count it as an unknown.
 *
 * The line is an f-string with three unquoted, unescaped interpolations:
 *
 *   Scanner result {rule.name} (variant: {variant_label}) {verdict}
 *   Scanner result {rule.name} (variant: {variant_label}) {verdict} ({module or the path we passed})
 *
 * and TWO of those interpolations contain the delimiters. `meta.name` is free text — the pinned corpus has
 * `BRLY-2022-028 (RsbStuffingCheck)`, which has both a space and parentheses — and variant labels are worse:
 * `informational (the patch from EDK2 is missing)`. So the rule cannot be `\S+` and the variant group cannot end
 * at the first `)`; it ends at the one that closes it, found by depth. This is not hypothetical tidiness: the
 * previous regex dropped every line of that one rule, and that rule is the only one that TRIGGERED on real OVMF
 * bytes. A parser that silently discards its own positives is worse than no parser.
 */
function parseVerdictLine(line: string): RuleVerdict | null {
  const body = line.slice('Scanner result'.length);
  const marker = body.indexOf('(variant:');
  if (marker < 0) return null;
  const rule = body.slice(0, marker).trim();
  if (!rule) return null;

  const after = body.slice(marker + '(variant:'.length);
  let depth = 1;
  let close = -1;
  for (let i = 0; i < after.length; i++) {
    const c = after[i];
    if (c === '(') depth++;
    else if (c === ')' && --depth === 0) {
      close = i;
      break;
    }
  }
  if (close < 0) return null;

  const variant = after.slice(0, close).trim();
  const tail = after.slice(close + 1).trim();
  const matched = VERDICT_MATCHED.test(tail);
  const clean = !matched && VERDICT_CLEAN.test(tail);
  // An unrecognised verdict is not a negative one.
  if (!matched && !clean) return null;

  const trailer = tail.replace(matched ? VERDICT_MATCHED : VERDICT_CLEAN, '').trim();
  const mod = /^\((.+)\)$/.exec(trailer);
  return {
    rule,
    matched,
    ...(variant ? { variant } : {}),
    ...(mod?.[1] ? { module: mod[1] } : {}),
  };
}

/**
 * Pure: normalize the analyzer's stdout into per-rule-variant verdicts.
 *
 * A line that carries the `Scanner result` prefix but cannot be read is COUNTED rather than dropped silently: a
 * verdict we could not parse is an unknown, and an unknown must not be quietly folded into "nothing matched".
 */
export function parseFwHuntOutput(stdout: string): { verdicts: RuleVerdict[]; unreadableLines: number } {
  const verdicts: RuleVerdict[] = [];
  let unreadableLines = 0;

  for (const raw of stdout.split('\n')) {
    const line = stripAnsi(raw).trim();
    if (!line.startsWith('Scanner result')) continue;
    const verdict = parseVerdictLine(line);
    if (verdict) verdicts.push(verdict);
    else unreadableLines++;
  }

  return { verdicts, unreadableLines };
}

/**
 * Pure: the corpus category a rule belongs to, from its path (`.../Threats/BlackLotusBootkit.yml` → `Threats`).
 * The scanner reports only the rule NAME, so the caller resolves the path from the corpus listing.
 */
export function ruleCategory(rulePath: string): string | undefined {
  const parts = rulePath.split('/').filter(Boolean);
  const known = Object.keys(CATEGORY_SEVERITY);
  return parts.find((p) => known.includes(p));
}

/**
 * Pure: read the `meta:` block of a FwHunt rule.
 *
 * Four fields there decide what a rule can be asked to do, or what it is about, and none of them is visible from
 * the filename. `name` is what the scanner PRINTS — five rules in the pinned corpus print something other than
 * their filename, so indexing matches by filename alone loses exactly those five rules' categories and grades
 * their matches with the fallback severity. `target` says whether the rule is about a whole firmware image, an OS
 * bootloader or a module, which is the only thing standing between `scan-module` and evaluating a whole-image hex
 * string against one driver. `volume guids` is the scoping its author set, which the per-module pass bypasses and
 * must therefore disclose. `description` is prose, and it is read for one reason only: it is where the corpus most
 * often names the module a rule was written about when the name and the filename do not (`CVE-2023-45230` says
 * `Dhcp6Dxe` here and nowhere else), which is the strongest key `rankModulesForScan` has and was starving without
 * it. Read by hand rather than with a YAML parser because the API has no YAML dependency and this needs four
 * scalars, not a document model — the block is delimited by indentation, so `variants:` cannot leak in.
 *
 * A description written as a folded/literal block (`description: >`) yields its indicator rather than the prose,
 * so the rule simply contributes nothing to the ranking. That is a miss, not a wrong answer, and it is the same
 * shape of miss as a rule that names no module at all — which is the majority of the corpus.
 */
export function parseRuleMeta(text: string): {
  name?: string;
  target?: string;
  description?: string;
  volumeGuids: number;
} {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => /^\s*meta:\s*$/.test(l));
  if (start < 0) return { volumeGuids: 0 };
  const indentOf = (l: string): number => (/^(\s*)/.exec(l)?.[1] ?? '').length;
  const metaIndent = indentOf(lines[start] as string);

  const block: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i] as string;
    if (!line.trim()) continue;
    if (indentOf(line) <= metaIndent) break;
    block.push(line);
  }

  const scalar = (key: string): string | undefined => {
    for (const line of block) {
      const m = new RegExp(`^\\s*${key}:\\s*(.*?)\\s*$`).exec(line);
      if (m?.[1]) return m[1].replace(/^['"]|['"]$/g, '');
    }
    return undefined;
  };

  // `volume guids:` heads a list; count the `- <guid>` items that follow it inside the block.
  let volumeGuids = 0;
  const guidsAt = block.findIndex((l) => /^\s*volume guids:\s*$/.test(l));
  if (guidsAt >= 0) {
    for (let i = guidsAt + 1; i < block.length; i++) {
      if (!/^\s*-\s*\S/.test(block[i] as string)) break;
      volumeGuids++;
    }
  }

  const name = scalar('name');
  const target = scalar('target');
  const description = scalar('description');
  return {
    ...(name ? { name } : {}),
    ...(target ? { target } : {}),
    ...(description ? { description } : {}),
    volumeGuids,
  };
}

/**
 * How much of a rule file is read to find its `meta:` block. `meta` is the first key of every rule in the corpus
 * and some rules carry hundreds of kilobytes of leaked-key hex strings after it that nothing here needs.
 */
const RULE_META_READ_BYTES = 16 * 1024;

/** Read at most `bytes` from the head of a file; unreadable ⇒ empty, and the caller falls back to the filename. */
function readHead(file: string, bytes: number): string {
  let fd: number;
  try {
    fd = fs.openSync(file, 'r');
  } catch {
    return '';
  }
  try {
    const buf = Buffer.allocUnsafe(bytes);
    const n = fs.readSync(fd, buf, 0, bytes, 0);
    return buf.subarray(0, n).toString('utf8');
  } catch {
    return '';
  } finally {
    fs.closeSync(fd);
  }
}

/** Hash the complete rule without retaining leaked-key rule bodies in memory. Unreadable is a distinct identity. */
function digestFile(file: string): string {
  let fd: number;
  try {
    fd = fs.openSync(file, 'r');
  } catch {
    return 'unreadable';
  }
  const hash = createHash('sha256');
  const chunk = Buffer.allocUnsafe(64 * 1024);
  try {
    let position = 0;
    for (;;) {
      const read = fs.readSync(fd, chunk, 0, chunk.length, position);
      if (read === 0) break;
      hash.update(chunk.subarray(0, read));
      position += read;
    }
    return hash.digest('hex');
  } catch {
    return 'unreadable';
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * The rule corpus as data: for every `.yml` under `rulesDir`, the path a match is attributed through and the
 * `meta` fields that decide which pass, if any, is allowed to run it. Sorted by path so two runs over the same
 * corpus offer the same rules in the same order.
 */
export function loadRuleCorpus(rulesDir: string): CorpusRule[] {
  const out: CorpusRule[] = [];
  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) walk(abs);
      else if (e.isFile() && /\.ya?ml$/i.test(e.name)) {
        const meta = parseRuleMeta(readHead(abs, RULE_META_READ_BYTES));
        out.push({
          path: path.relative(rulesDir, abs),
          name: meta.name ?? e.name.replace(/\.ya?ml$/i, ''),
          ...(meta.target ? { target: meta.target } : {}),
          ...(meta.description ? { description: meta.description } : {}),
          volumeGuids: meta.volumeGuids,
          contentDigest: digestFile(abs),
        });
      }
    }
  };
  walk(rulesDir);
  out.sort((a, b) => a.path.localeCompare(b.path));
  return out;
}

/** Stable identity for the rule set whose per-module verdicts may be accumulated across bounded runs. */
export function fingerprintRuleCorpus(corpus: CorpusRule[]): string {
  const canonical = corpus
    .map((r) => [r.path, r.name, r.target ?? '', r.volumeGuids, r.contentDigest])
    .sort((a, b) => String(a[0]).localeCompare(String(b[0])));
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

/**
 * Pure: split the corpus into the rules a single carved module may be scanned with and the rules it may not.
 *
 * `scan-firmware` applies this same test internally (anything whose target is not `module` or absent is skipped);
 * `scan-module` applies NO test at all and will happily evaluate a `target: firmware` rule — a hex string meant to
 * be searched across a whole flash image — against one driver and print a verdict for it. That verdict would be
 * meaningless, so the split happens here, and the excluded rules are RETURNED rather than dropped: a rule that no
 * pass in this deployment can offer to anything is a coverage hole and has to be counted as one.
 */
export function selectModuleRules(corpus: CorpusRule[]): { rules: CorpusRule[]; excluded: ExcludedRule[] } {
  const rules: CorpusRule[] = [];
  const excluded: ExcludedRule[] = [];
  for (const r of corpus) {
    if (r.target === undefined || r.target === 'module') rules.push(r);
    else excluded.push({ rule: r.name, target: r.target });
  }
  return { rules, excluded };
}

const GUID_IN_PATH = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
/** Extensions the two carvers append to a module file; stripped for the display label only. */
const MODULE_EXT = /\.(efi|dxe|peim|sec|core|app|smm|te|pe32|bin)$/i;

/**
 * Pure: name a carved module from its path. The two carvers that produce these files disagree on layout — the
 * analyzer's own `extract` writes `<Name>-<file guid><ext>` into one flat directory, chipsec writes `<Name>.efi`
 * inside a `<nn>_<file guid>.FV_<TYPE>.dir` directory — so both are read. A file matching neither convention still
 * gets a usable label instead of being dropped for failing to look the way one carver happens to write.
 */
export function describeCarvedModule(filePath: string): CarvedModule {
  const stem = path.basename(filePath).replace(MODULE_EXT, '');
  const inName = GUID_IN_PATH.exec(stem);
  if (inName) {
    const name = stem.slice(0, inName.index).replace(/[-_\s]+$/, '');
    return { path: filePath, name: name || stem, guid: inName[0].toLowerCase() };
  }
  const inParent = GUID_IN_PATH.exec(path.basename(path.dirname(filePath)));
  return { path: filePath, name: stem, ...(inParent ? { guid: inParent[0].toLowerCase() } : {}) };
}

/** PE (`MZ`) and TE (`VZ`) — the two headers an EFI module actually starts with. */
const MODULE_MAGIC = new Set(['MZ', 'VZ']);
/** chipsec nests a module seven directories inside its `.dir` tree; the analyzer's `extract` writes them flat. */
const MODULE_WALK_DEPTH = 12;

/** Does this file start with an EFI module header? Unreadable ⇒ no, and it simply is not offered to the scanner. */
function hasModuleMagic(file: string): boolean {
  return MODULE_MAGIC.has(readHead(file, 2));
}

/**
 * Collect the carved EFI modules under `dir` by their header bytes, not by extension or naming convention: the two
 * carvers name their output differently, and chipsec's tree holds ~900 sections, digests and padding blobs next to
 * the 125 real modules. Reading two bytes is the only test both trees agree with.
 *
 * The depth bound is a bound, so it reports what it refused to enter rather than returning a short list that reads
 * as a complete one.
 */
export function findCarvedModules(dir: string): { modules: CarvedModule[]; deepDirsSkipped: number } {
  const modules: CarvedModule[] = [];
  let deepDirsSkipped = 0;
  const walk = (d: string, depth: number): void => {
    if (depth > MODULE_WALK_DEPTH) {
      deepDirsSkipped++;
      return;
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = path.join(d, e.name);
      if (e.isDirectory()) walk(abs, depth + 1);
      else if (e.isFile() && hasModuleMagic(abs)) {
        modules.push({ ...describeCarvedModule(abs), relativePath: path.relative(dir, abs) });
      }
    }
  };
  walk(dir, 0);
  modules.sort((a, b) => a.name.localeCompare(b.name) || a.path.localeCompare(b.path));
  return { modules, deepDirsSkipped };
}

/**
 * What a carved module is, ranked by the privilege the code inside it runs at. This is an ORDERING, not a
 * taxonomy: `unclassified` sits below every tier that was actually read off the carve because guessing UP from a
 * name nothing could be read out of would invent the evidence the tier exists to carry, and above `application`
 * because a UEFI application is the one thing here that is definitely not privileged firmware.
 */
export type ModulePrivilege =
  | 'smm'
  | 'boot-core'
  | 'peim'
  | 'runtime-dxe'
  | 'dxe-driver'
  | 'unclassified'
  | 'application';

/** Most privileged first. `rankModulesForScan` orders on this index; nothing else depends on the numbering. */
const PRIVILEGE_ORDER: ModulePrivilege[] = [
  'smm',
  'boot-core',
  'peim',
  'runtime-dxe',
  'dxe-driver',
  'unclassified',
  'application',
];

/** Lowercase alphanumerics only — the one shape a carve path, a module label and a rule name are comparable in. */
function normalizeToken(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

/**
 * chipsec stamps the FFS file type into the directory it carves a module into (`…FV_SMM_CORE.dir`,
 * `…FV_PEI_CORE.dir`), which is the file type byte out of the image rather than a guess about a name. Order
 * matters: `FV_COMBINED_PEIM_DRIVER` is a PEIM that also runs as a driver, and the PEIM half is the earlier one.
 */
const FV_TYPE_PRIVILEGE: Array<[RegExp, ModulePrivilege]> = [
  [/smm/, 'smm'],
  [/seccore|peicore|dxecore/, 'boot-core'],
  [/peim/, 'peim'],
  [/driver/, 'dxe-driver'],
  [/application/, 'application'],
];

/** The extension the analyzer's own `extract` appends, which it takes from the same file type. */
const EXT_PRIVILEGE: Record<string, ModulePrivilege> = {
  smm: 'smm',
  sec: 'boot-core',
  core: 'boot-core',
  peim: 'peim',
  pei: 'peim',
  dxe: 'dxe-driver',
  app: 'application',
};

/**
 * EDK2 naming convention, tested against the normalized label. Weaker evidence than the two above — it is a
 * convention, not a header — but it is the only signal that survives a carver which names files `<Name>.efi`.
 */
const NAME_PRIVILEGE: Array<[RegExp, ModulePrivilege]> = [
  [/smm|^smi/, 'smm'],
  [/seccore|peicore|dxecore|coredxe|secmain/, 'boot-core'],
  [/peim|pei$/, 'peim'],
  [/runtime/, 'runtime-dxe'],
  [/dxe$|driver$/, 'dxe-driver'],
  [/^shell|app$/, 'application'],
];

/**
 * Pure: what privilege the code in a carved module runs at, read off the carve rather than the bytes.
 *
 * Three independent signals are consulted — the FFS type chipsec puts in the directory name, the extension the
 * analyzer's `extract` appends, and the EDK2 naming convention — and when they disagree the MOST privileged of
 * them wins. That asymmetry is deliberate: over-ranking a module costs one scan slot, under-ranking one costs the
 * highest-privilege code in the image its only look. A module none of the three can speak to is `unclassified`,
 * which is an admission and not a tier — it is never promoted to a privileged one on a hunch.
 *
 * This claims nothing about the module's contents. It orders a queue.
 */
export function classifyModulePrivilege(module: CarvedModule): ModulePrivilege {
  const signals: ModulePrivilege[] = [];

  // Only directory segments: a module *named* `FvSimpleFileSystemDxe` is not a statement about its file type.
  for (const segment of path.dirname(module.path).split(/[\\/]+/)) {
    const token = normalizeToken(segment);
    if (!token.includes('fv')) continue;
    const hit = FV_TYPE_PRIVILEGE.find(([re]) => re.test(token))?.[1];
    if (hit) signals.push(hit);
  }

  const ext = /\.([a-z0-9]+)$/i.exec(path.basename(module.path))?.[1]?.toLowerCase();
  const byExt = ext ? EXT_PRIVILEGE[ext] : undefined;
  if (byExt) signals.push(byExt);

  const byName = NAME_PRIVILEGE.find(([re]) => re.test(normalizeToken(module.name)))?.[1];
  if (byName) signals.push(byName);

  if (signals.length === 0) return 'unclassified';
  return signals.reduce((best, s) => (PRIVILEGE_ORDER.indexOf(s) < PRIVILEGE_ORDER.indexOf(best) ? s : best));
}

/**
 * A module label shorter than this is not tested against the corpus at all. `Dxe`, `Pei` and `Smm` occur in most
 * of the corpus, so matching them would rank every driver in the image first and the signal would be noise
 * wearing the shape of evidence. The rule binds descriptions harder than it binds names, not less: a description
 * is a sentence, and a short label finds a substring in prose far more readily than in an identifier.
 */
const CORPUS_NAME_MIN_CHARS = 5;

/**
 * What one mention of a module is worth, by where in the rule it was found.
 *
 * A name or filename mention counts DOUBLE a description mention, and the asymmetry is the point. A rule's
 * `meta.name` and its filename are identifiers its author chose to say what the rule is *about* — `LojaxSecDxe`
 * is a rule about `SecDxe`. A description is prose written for a human, and prose names modules it is not about:
 * as context, as contrast, as the place a bug is *not*. It is also two orders of magnitude longer than a name, so
 * an incidental substring hit is correspondingly likelier. Halving it keeps a description mention doing the job
 * it exists for — a module the corpus has written *something* about outranks one it has written nothing about,
 * which is how `CVE-2023-45230` finally buys `Dhcp6Dxe` a slot — without ever letting prose outrank a rule that
 * carries the module's name.
 *
 * The consequence worth stating: two rules describing a module tie with one rule named after it. That is
 * deliberate rather than an artifact of the numbers — two independent authors writing the label down is about as
 * much as one author naming the rule for it — and the tie then falls to privilege, which is a defensible order.
 */
const NAME_MENTION_WEIGHT = 2;
const DESCRIPTION_MENTION_WEIGHT = 1;

/** One rule reduced to the two normalized texts a module label is looked for in. */
interface RuleMentionText {
  /** `meta.name` and the filename, joined. */
  label: string;
  /** `meta.description`, or empty when the rule declares none. */
  description: string;
}

/**
 * How much the offered corpus has to say about this module — key 2 of `rankModulesForScan`.
 *
 * A rule contributes AT MOST ONCE: a rule that names the module in its name and describes it again scores the
 * name weight, not the sum. Otherwise a single rule that repeats itself would outweigh two rules that agree, and
 * the key would be measuring verbosity instead of attention.
 */
function scoreCorpusMentions(module: CarvedModule, rules: readonly RuleMentionText[]): number {
  const key = normalizeToken(module.name);
  if (key.length < CORPUS_NAME_MIN_CHARS) return 0;
  let score = 0;
  for (const r of rules) {
    if (r.label.includes(key)) score += NAME_MENTION_WEIGHT;
    else if (r.description.includes(key)) score += DESCRIPTION_MENTION_WEIGHT;
  }
  return score;
}

/**
 * Pure: choose which carved modules the per-module pass scans, and hand back the ones the cap dropped.
 *
 * The order is deliberately NOT the walk order, which would make the scanned set an artifact of how the carver
 * laid the tree out. Four keys decide it, and only the last is arbitrary:
 *
 *  1. COVERAGE DEBT. A module the whole-image pass never printed a verdict for had ZERO rules run against it, so
 *     that is where the extra pass buys the most. Modules the image pass did reach follow — it offered them only
 *     the rules scoped to their volume, so they are not covered either, just less starved.
 *  2. WHAT THE CORPUS NAMES. A module whose label appears in a rule this pass is about to offer is a module
 *     somebody wrote a detection about: `LojaxSecDxe` names `SecDxe`, `CosmicStrandDxeCore` names `DxeCore`, and
 *     `CVE-2023-45230` names `Dhcp6Dxe` in its DESCRIPTION and in neither its name nor its filename. Twelve slots
 *     spent where the corpus has something to say beat twelve spent where it has nothing, and modules the corpus
 *     says more about go first. Three fields are read — `name`, `path` and `description` — and a description
 *     mention is worth half a name mention, for the reasons on `NAME_MENTION_WEIGHT`. This is not a prediction
 *     that the rule will match, and a rule that names no module at all (`BRLY-2022-009`, most of the corpus)
 *     contributes nothing here rather than a guess.
 *  3. PRIVILEGE, from `classifyModulePrivilege`: SMM first, because it runs at ring -2, stays resident after the
 *     OS has booted, and is what the largest share of the module-target corpus (SMM callouts, SMI entry code) was
 *     written against; then the dispatch cores, which decide what runs after them; then PEIMs, which run before
 *     DXE exists; then runtime DXE, which stays mapped at OS runtime; then ordinary drivers; then applications.
 *  4. Name, then path. Arbitrary, and here for one reason: two runs over the same carve must scan the same
 *     modules. Two modules CAN carry the same label in different volumes, which is why the path has the last word
 *     — without it the tie would fall back to walk order, i.e. to directory layout.
 *
 * None of this is a verdict about a module. It decides ORDER ONLY: every module the cap drops comes back in
 * `skipped`, whole, and the caller states the rule that dropped it. A module ranked last is not a module cleared.
 */
export function rankModulesForScan(input: {
  modules: CarvedModule[];
  /** Module labels the whole-image pass printed — those already had SOME rules run against them. */
  coveredByImageScan: string[];
  cap: number;
  /** Zero-based cap-sized window in the global ordering. */
  batch?: number;
  /**
   * The rules this pass will offer, when the caller has them. Optional: a caller without a corpus loses key 2 and
   * ranks on privilege alone, which is a weaker order and never a wrong one.
   */
  rules?: CorpusRule[];
}): {
  selected: CarvedModule[];
  skipped: CarvedModule[];
  batchIndex: number;
  batchCount: number;
  batchStart: number;
  rankingFingerprint: string;
} {
  const { modules, coveredByImageScan, cap, batch = DEFAULT_MODULE_BATCH, rules = [] } = input;
  const covered = new Set(coveredByImageScan.map((m) => path.basename(m).replace(MODULE_EXT, '').toLowerCase()));
  // The scanner prints `meta.name`, which for five rules in the pinned corpus is not the filename, so both are
  // searched. Joined with a space the two cannot form a match across their boundary — normalized keys have none.
  // The description is kept SEPARATE rather than joined in, because where the label was found is what decides
  // what the mention is worth.
  const ruleTexts: RuleMentionText[] = rules.map((r) => ({
    label: `${normalizeToken(r.name)} ${normalizeToken(path.basename(r.path).replace(/\.ya?ml$/i, ''))}`,
    description: normalizeToken(r.description ?? ''),
  }));

  const ranked = modules.map((m) => ({
    module: m,
    debt: covered.has(m.name.toLowerCase()) ? 1 : 0,
    mentions: scoreCorpusMentions(m, ruleTexts),
    privilege: PRIVILEGE_ORDER.indexOf(classifyModulePrivilege(m)),
  }));
  ranked.sort(
    (a, b) =>
      a.debt - b.debt ||
      b.mentions - a.mentions ||
      a.privilege - b.privilege ||
      a.module.name.localeCompare(b.module.name) ||
      a.module.path.localeCompare(b.module.path),
  );

  const ordered = ranked.map((r) => r.module);
  const batchIndex = Number.isSafeInteger(batch) && batch >= 0 ? batch : DEFAULT_MODULE_BATCH;
  const rankingFingerprint = fingerprintModuleRanking(ordered);
  if (cap <= 0) return { selected: [], skipped: ordered, batchIndex, batchCount: 0, batchStart: 0, rankingFingerprint };
  const batchCount = Math.ceil(ordered.length / cap);
  const batchStart = batchIndex * cap;
  const selected = ordered.slice(batchStart, batchStart + cap);
  // Keep every module outside this window in the denominator. This includes earlier batches: a standalone batch
  // result must never imply that modules before its offset disappeared merely because another run may have them.
  const skipped = [...ordered.slice(0, batchStart), ...ordered.slice(batchStart + selected.length)];
  return { selected, skipped, batchIndex, batchCount, batchStart, rankingFingerprint };
}

/** Stable across temporary carve roots; the relative path disambiguates duplicate GUID/name pairs in nested FVs. */
function moduleIdentity(module: CarvedModule): string {
  return [module.guid ?? '', module.relativePath ?? path.basename(module.path), module.name]
    .join('\u0000')
    .toLowerCase();
}

/** The order is part of the digest: equal members in a different rank are not compatible batch ranges. */
export function fingerprintModuleRanking(modules: CarvedModule[]): string {
  return createHash('sha256').update(modules.map(moduleIdentity).join('\n')).digest('hex');
}

function uniqueModules(modules: CarvedModule[]): CarvedModule[] {
  const out = new Map<string, CarvedModule>();
  for (const module of modules) out.set(moduleIdentity(module), module);
  return [...out.values()];
}

function uniqueVerdicts(verdicts: RuleVerdict[]): RuleVerdict[] {
  const out = new Map<string, RuleVerdict>();
  for (const verdict of verdicts) {
    const key = [verdict.rule, verdict.variant ?? '', verdict.module ?? '', verdict.matched ? '1' : '0'].join('\u0000');
    out.set(key, verdict);
  }
  return [...out.values()];
}

function mergeBatchRecord(previous: ModuleBatchRecord, current: ModuleBatchRecord): ModuleBatchRecord {
  // A full rerun is authoritative for this range. Partial retries traverse the same deterministic range from its
  // start, so a superset supersedes the shorter prefix without double-counting verdicts or unreadable lines.
  if (current.complete) return current;
  if (previous.complete) return previous;
  const previousKeys = new Set(previous.modulesScanned.map(moduleIdentity));
  const currentKeys = new Set(current.modulesScanned.map(moduleIdentity));
  const previousIsSubset = [...previousKeys].every((key) => currentKeys.has(key));
  const currentIsSubset = [...currentKeys].every((key) => previousKeys.has(key));
  if (previousIsSubset) return current;
  if (currentIsSubset) return previous;
  // Two disjoint partial attempts can be accumulated exactly. Partially overlapping non-prefix attempts should not
  // arise from this runner; refusing to blend their unattributable line counts is safer than inventing a total.
  const disjoint = [...previousKeys].every((key) => !currentKeys.has(key));
  if (!disjoint) return current.modulesScanned.length > previous.modulesScanned.length ? current : previous;
  const modulesScanned = uniqueModules([...previous.modulesScanned, ...current.modulesScanned]);
  const scanned = new Set(modulesScanned.map(moduleIdentity));
  const modulesFailed = uniqueModules([...previous.modulesFailed, ...current.modulesFailed]).filter(
    (module) => !scanned.has(moduleIdentity(module)),
  );
  return {
    ...current,
    complete: false,
    modulesScanned,
    modulesFailed,
    verdicts: uniqueVerdicts([...previous.verdicts, ...current.verdicts]),
    unreadableLines: previous.unreadableLines + current.unreadableLines,
  };
}

function campaignIncompatibility(previous: ModulePass, current: ModulePass): string | null {
  if (!previous.corpusFingerprint || previous.corpusFingerprint !== current.corpusFingerprint)
    return 'the rule corpus fingerprint changed or was not recorded';
  if (previous.rankingVersion !== current.rankingVersion)
    return `the ranking contract changed (${previous.rankingVersion} → ${current.rankingVersion})`;
  if (!previous.rankingFingerprint || previous.rankingFingerprint !== current.rankingFingerprint)
    return 'the carved-module ranking or its order changed';
  if (previous.modulesCarved !== current.modulesCarved)
    return `the carve denominator changed (${previous.modulesCarved} → ${current.modulesCarved})`;
  if (previous.rulesOffered !== current.rulesOffered)
    return `the module-rule count changed (${previous.rulesOffered} → ${current.rulesOffered})`;
  if (previous.batchSize !== current.batchSize || previous.batchCount !== current.batchCount)
    return `the batch geometry changed (${previous.batchSize}×${previous.batchCount} → ${current.batchSize}×${current.batchCount})`;
  return null;
}

/**
 * Pure: accumulate compatible batch results, replacing/extending a repeated batch instead of counting it twice.
 * A missing fingerprint or changed cap/denominator/rules/order refuses the merge and records why on the new result.
 */
export function accumulateModulePass(previous: ModulePass | null | undefined, current: ModulePass): ModulePass {
  if (!previous) return current;
  if (!Array.isArray(previous.batches)) {
    return { ...current, campaignResetReason: 'the earlier result predates batch provenance and cannot be merged' };
  }
  if (previous.batches.length === 0) return current;
  const incompatibility = campaignIncompatibility(previous, current);
  if (incompatibility) return { ...current, campaignResetReason: incompatibility };

  const batches = new Map(previous.batches.map((batch) => [batch.index, batch]));
  for (const batch of current.batches) {
    const old = batches.get(batch.index);
    batches.set(batch.index, old ? mergeBatchRecord(old, batch) : batch);
  }
  const orderedBatches = [...batches.values()].sort((a, b) => a.index - b.index);
  const modulesScanned = uniqueModules(orderedBatches.flatMap((batch) => batch.modulesScanned));
  const scanned = new Set(modulesScanned.map(moduleIdentity));
  const modulesFailed = uniqueModules(orderedBatches.flatMap((batch) => batch.modulesFailed)).filter(
    (module) => !scanned.has(moduleIdentity(module)),
  );
  const failed = new Set(modulesFailed.map(moduleIdentity));
  const universe = uniqueModules([
    ...current.modulesScanned,
    ...current.modulesFailed,
    ...current.modulesSkipped,
    ...previous.modulesScanned,
    ...previous.modulesFailed,
    ...previous.modulesSkipped,
  ]);
  const modulesSkipped = universe.filter((module) => {
    const identity = moduleIdentity(module);
    return !scanned.has(identity) && !failed.has(identity);
  });
  const verdicts = uniqueVerdicts(orderedBatches.flatMap((batch) => batch.verdicts));
  const batchesCompleted = orderedBatches.filter((batch) => batch.complete).map((batch) => batch.index);
  const ran = modulesScanned.length > 0;

  return {
    ...current,
    ran,
    reason: ran ? '' : current.reason,
    verdicts,
    unreadableLines: orderedBatches.reduce((sum, batch) => sum + batch.unreadableLines, 0),
    batchesCompleted,
    batches: orderedBatches,
    modulesScannedThisBatch: current.batches.flatMap((batch) => batch.modulesScanned).length,
    modulesScanned,
    modulesSkipped,
    modulesFailed,
    skipReason: modulesSkipped.length
      ? `${current.skipReason}; accumulated across batch(es) ${orderedBatches.map((batch) => batch.index + 1).join(', ')}`
      : '',
  };
}

/** Pure campaign cursor: retry an incomplete latest window; otherwise take the first range not yet completed. */
export function nextModuleBatch(pass: ModulePass | null | undefined): number | null {
  if (!pass || !Number.isSafeInteger(pass.batchCount) || pass.batchCount <= 0) return 0;
  const batches = Array.isArray(pass.batches) ? pass.batches : [];
  const latest = batches.find((batch) => batch.index === pass.batchIndex);
  if (latest && !latest.complete) return pass.batchIndex;
  const completed = new Set(Array.isArray(pass.batchesCompleted) ? pass.batchesCompleted : []);
  for (let index = 0; index < pass.batchCount; index++) {
    if (!completed.has(index)) return index;
  }
  return null;
}

/**
 * Pure: turn the verdicts into findings.
 *
 * A match is the only outcome that makes a positive claim, and it is phrased as the RULE's claim — FirmLab did not
 * author the detection and says so. Every run, matched or not, also emits one coverage note: without it a scan
 * that matched nothing would be an empty result, and an empty result reads as "no implant" when what it actually
 * means is "no rule for whatever might be in here fired". Skipped rules are named in that note because they are
 * coverage the operator did not get.
 */
export function buildFwHuntFindings(input: {
  verdicts: RuleVerdict[];
  unreadableLines?: number;
  /** Rule name → its path in the corpus, so a match can be attributed to a category. */
  rulePaths?: Record<string, string>;
  /** Total rules present in the corpus — the denominator the run's coverage is measured against. */
  rulesInCorpus?: number;
  rulesDir?: string;
  /** The per-module pass, when one was attempted. Its verdicts are folded in; its limits are stated. */
  modulePass?: ModulePass | null;
}): FindingDraft[] {
  const {
    verdicts,
    unreadableLines = 0,
    rulePaths = {},
    rulesInCorpus = 0,
    rulesDir = fwhuntRulesDir(),
    modulePass = null,
  } = input;
  const drafts: FindingDraft[] = [];
  const matched = verdicts.filter((v) => v.matched);
  const distinctRun = new Set(verdicts.map((v) => v.rule));

  for (const v of matched) {
    const category = ruleCategory(rulePaths[v.rule] ?? v.rule);
    drafts.push({
      kind: 'uefi-fwhunt-match',
      title: `FwHunt rule ${v.rule} matched this firmware${category ? ` (${category})` : ''}`,
      severity: (category && CATEGORY_SEVERITY[category]) || 'high',
      proofState: 'static_confirmed',
      evidence: {
        rule: v.rule,
        ...(v.variant ? { variant: v.variant } : {}),
        ...(v.module ? { module: v.module } : {}),
        ...(category ? { category } : {}),
      },
      rationale: [
        `The FwHunt rule '${v.rule}' matched the code patterns it looks for in this image. FwHunt rules match on`,
        'code (esil expressions, hex strings, NVRAM usage) rather than on file GUIDs, which is what makes them',
        "usable against implants that have no stable identity. The claim here is the RULE's, not FirmLab's:",
        'FirmLab runs the upstream corpus and does not author detections. Read the rule to see exactly what it',
        'asserts before acting on it — a match on a Vulnerabilities or MitigationFailures rule describes a',
        'weakness, not an active implant.',
      ].join(' '),
    });
  }

  const moduleMatches = modulePass?.ran ? modulePass.verdicts.filter((v) => v.matched) : [];
  drafts.push(...buildModuleMatchFindings(moduleMatches, modulePass, rulePaths));

  // The denominator matters more than the numerator. `scan-firmware` only offers a rule to the modules inside the
  // firmware volumes that rule declares, so most of the corpus never runs — on real OVMF, 17 of 108. Reporting
  // "no matches" without that ratio would present a 16%-coverage scan as a clean bill of health. The per-module
  // pass is folded in here rather than reported beside it, because "how many rules examined these bytes" is one
  // number and two half-answers would let a reader take either as the whole.
  const examined = new Set([...distinctRun, ...(modulePass?.ran ? modulePass.verdicts.map((v) => v.rule) : [])]);
  const notApplicable = Math.max(0, rulesInCorpus - examined.size);
  const allMatched = matched.length + moduleMatches.length;
  const scopeNote =
    rulesInCorpus > 0
      ? ` ${examined.size} of the ${rulesInCorpus} rule(s) in the corpus examined these bytes; the other ${notApplicable} examined nothing.`
      : '';
  const unreadableNote =
    unreadableLines + (modulePass?.unreadableLines ?? 0)
      ? ` ${unreadableLines + (modulePass?.unreadableLines ?? 0)} verdict line(s) could not be parsed, so those results are unknown rather than negative.`
      : '';

  // The per-module pass raises the rule count by spending module coverage, so the headline has to carry BOTH
  // fractions. "106 of 108 rules ran" over three of a hundred and twenty-five modules is the exact shape this
  // codebase has been bitten by three times: a headline that absorbs its own caveat.
  const moduleCoverage =
    modulePass?.ran && modulePass.modulesCarved > 0
      ? ` over ${modulePass.modulesScanned.length}/${modulePass.modulesCarved} carved module(s)`
      : '';
  const rulesFraction = rulesInCorpus > 0 ? `${examined.size}/${rulesInCorpus}` : `${examined.size}`;

  drafts.push({
    kind: 'uefi-fwhunt-coverage',
    title: allMatched
      ? `FwHunt: ${allMatched} rule match(es) — ${rulesFraction} rule(s) ran${moduleCoverage}`
      : `FwHunt: no rule matched — ${rulesFraction} rule(s) ran${moduleCoverage}, which is not "no implant"`,
    severity: 'info',
    proofState: 'static_confirmed',
    evidence: {
      rulesRun: examined.size,
      rulesInCorpus,
      rulesNotApplicable: notApplicable,
      rulesRunWholeImage: distinctRun.size,
      variantsEvaluated: verdicts.length + (modulePass?.verdicts.length ?? 0),
      rulesMatched: allMatched,
      unreadableLines: unreadableLines + (modulePass?.unreadableLines ?? 0),
      rulesDir,
      ...modulePassEvidence(modulePass),
    },
    rationale: [
      `${allMatched} rule(s) matched.${scopeNote}`,
      `${describeModulePass(modulePass, distinctRun.size, examined.size)}${unreadableNote}`,
      'Beyond that, a rule corpus only covers what someone wrote a rule for, so a scan with no matches means the',
      'KNOWN families were not found — never that the firmware carries no implant. Everything the corpus has no',
      'rule for is unexamined by construction, and no amount of scanning changes that.',
    ].join(' '),
  });

  return drafts;
}

/** How many module names one rule's match finding lists before it starts counting them instead. */
const MATCHED_MODULE_LIST_CAP = 12;

/** One step down the severity ladder — what a match found outside its rule's declared scope is worth. */
function stepDown(s: FindingDraft['severity']): FindingDraft['severity'] {
  const ladder: FindingDraft['severity'][] = ['info', 'low', 'medium', 'high', 'critical'];
  const i = ladder.indexOf(s);
  return i > 0 ? (ladder[i - 1] as FindingDraft['severity']) : s;
}

/**
 * Pure: one finding per matching (rule, variant) of the per-module pass, carrying the modules it fired on.
 *
 * Grouping is not cosmetic. Rules written as `not-any` fire on every module that simply does not contain the
 * pattern they want present — on OVMF one MitigationFailures rule matched essentially every module scanned — and
 * emitting a finding per (rule, module) would bury the ledger under one rule's shape. The module list is what
 * makes the match actionable, so it is carried, capped, and the cap says how many it did not name.
 */
function buildModuleMatchFindings(
  matches: RuleVerdict[],
  pass: ModulePass | null,
  rulePaths: Record<string, string>,
): FindingDraft[] {
  if (!pass?.ran || matches.length === 0) return [];
  const scoped = new Set(pass.scopedRuleNames);
  const groups = new Map<string, { rule: string; variant?: string; modules: string[] }>();
  for (const v of matches) {
    // NUL as the separator, written as an escape so the source stays text: it cannot occur inside a rule name or
    // a variant label, so the composite key cannot collide the way a comma or a colon could.
    const key = `${v.rule}\u0000${v.variant ?? ''}`;
    const g = groups.get(key) ?? { rule: v.rule, ...(v.variant ? { variant: v.variant } : {}), modules: [] };
    if (v.module) g.modules.push(v.module);
    groups.set(key, g);
  }

  const drafts: FindingDraft[] = [];
  for (const g of [...groups.values()].sort((a, b) => a.rule.localeCompare(b.rule))) {
    const category = ruleCategory(rulePaths[g.rule] ?? g.rule);
    const base = (category && CATEGORY_SEVERITY[category]) || 'high';
    const outOfScope = scoped.has(g.rule);
    const listed = g.modules.slice(0, MATCHED_MODULE_LIST_CAP);
    drafts.push({
      kind: 'uefi-fwhunt-module-match',
      title: `FwHunt rule ${g.rule} matched ${g.modules.length} carved EFI module(s)${category ? ` (${category})` : ''}`,
      severity: outOfScope ? stepDown(base) : base,
      proofState: 'static_confirmed',
      evidence: {
        rule: g.rule,
        ...(g.variant ? { variant: g.variant } : {}),
        ...(category ? { category } : {}),
        modules: listed,
        modulesMatched: g.modules.length,
        modulesNotListed: Math.max(0, g.modules.length - listed.length),
        modulesScanned: pass.modulesScanned.length,
        ranOutsideDeclaredVolumeScope: outOfScope,
      },
      rationale: [
        `The FwHunt rule '${g.rule}' matched ${g.modules.length} of the ${pass.modulesScanned.length} carved EFI`,
        'module(s) this pass scanned. FwHunt rules match on code (esil expressions, hex strings, NVRAM usage)',
        'rather than on file GUIDs, which is what makes them usable against implants that have no stable identity.',
        outOfScope
          ? 'This rule declares the firmware volumes it is meant for, and the per-module pass ignored that scoping — that bypass is what let the rule run at all here, and it also means the author never intended it against these modules. Treat this as a lead to verify against the rule text, not as a match made inside the scope its author set.'
          : 'The rule declares no volume scoping, so running it per module asked exactly what its author wrote it to ask.',
        "The claim is the RULE's, not FirmLab's: FirmLab runs the upstream corpus and does not author detections.",
        'Read the rule before acting on it — a match on a Vulnerabilities or MitigationFailures rule describes a',
        'weakness, not an active implant.',
      ].join(' '),
    });
  }
  return drafts;
}

/** Evidence keys describing the per-module pass, including the one saying it did not happen. */
function modulePassEvidence(pass: ModulePass | null): Record<string, unknown> {
  if (!pass) return { modulePass: 'not attempted' };
  const batchEvidence = {
    moduleBatchIndex: pass.batchIndex,
    moduleBatchNumber: pass.batchCount > 0 ? pass.batchIndex + 1 : 0,
    moduleBatchCount: pass.batchCount,
    moduleBatchSize: pass.batchSize,
    batchesCompleted: pass.batchesCompleted,
    modulesScannedThisBatch: pass.modulesScannedThisBatch,
    modulesScannedInherited: Math.max(0, pass.modulesScanned.length - pass.modulesScannedThisBatch),
    moduleBatchWindowsStored: pass.batches.length,
    rankingVersion: pass.rankingVersion,
    rankingFingerprint: pass.rankingFingerprint,
    corpusFingerprint: pass.corpusFingerprint,
    ...(pass.campaignResetReason ? { moduleCampaignResetReason: pass.campaignResetReason } : {}),
  };
  if (!pass.ran)
    return {
      modulePass: 'did not run',
      modulePassReason: pass.reason,
      modulesCarved: pass.modulesCarved,
      modulesSkipped: pass.modulesSkipped.length,
      modulesFailed: pass.modulesFailed.length,
      moduleRulesOffered: pass.rulesOffered,
      ...batchEvidence,
    };
  return {
    modulePass: 'ran',
    modulesCarved: pass.modulesCarved,
    modulesScanned: pass.modulesScanned.length,
    modulesSkipped: pass.modulesSkipped.length,
    modulesFailed: pass.modulesFailed.length,
    moduleRulesOffered: pass.rulesOffered,
    rulesExcludedFromModulePass: pass.rulesExcluded,
    rulesRunOutsideDeclaredScope: pass.scopedRuleNames.length,
    ...batchEvidence,
    ...(pass.deepDirsSkipped ? { carveDirsTooDeepToWalk: pass.deepDirsSkipped } : {}),
  };
}

/**
 * The sentences that keep the per-module pass from reading as free coverage: what it added, what it did not reach,
 * what it was not allowed to run, and the scoping it broke to get there.
 */
function describeModulePass(pass: ModulePass | null, wholeImageRules: number, unionRules: number): string {
  if (!pass) return 'No per-module pass was attempted, so only the rules scoped to this image’s volumes ran.';
  if (!pass.ran)
    return `The per-module pass did not run (${pass.reason}); its carve denominator was ${pass.modulesCarved}, so only volume-scoped rules examined anything.`;

  const inherited = Math.max(0, pass.modulesScanned.length - pass.modulesScannedThisBatch);
  const parts: string[] = [
    `Per-module batch ${pass.batchIndex + 1}/${pass.batchCount} added ${pass.modulesScannedThisBatch} successful module scan(s); this result accumulates ${pass.modulesScanned.length} of the ${pass.modulesCarved} carved EFI module(s) across ${pass.batches.length} distinct stored batch window(s) (${inherited} module scan(s) inherited from compatible earlier runs), lifting the rules that examined something from ${wholeImageRules} to ${unionRules}.`,
  ];
  const currentBatch = pass.batches.find((batch) => batch.index === pass.batchIndex);
  if (currentBatch && !currentBatch.complete) {
    const attempted = currentBatch.modulesScanned.length + currentBatch.modulesFailed.length;
    const budgetMisses = Math.max(0, currentBatch.rangeEnd - currentBatch.rangeStart - attempted);
    parts.push(
      `Batch ${pass.batchIndex + 1} is incomplete (${currentBatch.modulesFailed.length} failed module scan(s), ${budgetMisses} module(s) not reached before the wall-clock budget); the next run must resume this batch rather than advance past it.`,
    );
  }
  if (pass.campaignResetReason)
    parts.push(`Earlier batch evidence was not inherited because ${pass.campaignResetReason}.`);
  if (pass.modulesSkipped.length)
    parts.push(
      `${pass.modulesSkipped.length} module(s) were never scanned (${pass.skipReason}) and no rule examined them.`,
    );
  if (pass.modulesFailed.length)
    parts.push(
      `${pass.modulesFailed.length} module(s) were scanned and the analyzer failed on them, so those are unknown, not clean.`,
    );
  if (pass.rulesExcluded.length) {
    const targets = [...new Set(pass.rulesExcluded.map((r) => r.target))].sort().join('/');
    parts.push(
      `${pass.rulesExcluded.length} rule(s) could not be offered to a module at all (target: ${targets}) and remain a hole this deployment does not fill.`,
    );
  }
  if (pass.scopedRuleNames.length)
    parts.push(
      `${pass.scopedRuleNames.length} of the offered rules declare firmware-volume scoping that this pass ignored, which is what bought the coverage and is also why a match seen only here is graded one step lower.`,
    );
  if (pass.deepDirsSkipped)
    parts.push(`${pass.deepDirsSkipped} carve director(ies) were too deeply nested to walk and were not searched.`);
  return parts.join(' ');
}

/**
 * Every rule in the corpus, as `printed name → path`. The scanner prints `meta.name`, which for five rules in the
 * pinned corpus is NOT the filename, so the index carries both keys: attributing by filename alone loses exactly
 * those rules' categories and silently grades their matches with the fallback severity.
 */
export function indexRuleCorpus(rulesDir: string): Record<string, string> {
  const index: Record<string, string> = {};
  for (const rule of loadRuleCorpus(rulesDir)) {
    index[path.basename(rule.path).replace(/\.ya?ml$/i, '')] = rule.path;
    index[rule.name] = rule.path;
  }
  return index;
}

function unavailable(reason: string): FwHuntResult {
  return {
    available: false,
    reason,
    rulesRun: 0,
    rulesNotApplicable: 0,
    rulesInCorpus: 0,
    matches: [],
    modulePass: null,
    findings: [
      {
        kind: 'uefi-fwhunt-blocked',
        title: 'UEFI implant scan (FwHunt) could not run',
        severity: 'info',
        proofState: 'blocked_by_platform',
        evidence: { reason },
        rationale:
          'The implant-rule scan was requested but this deployment could not perform it. Recorded so the absence ' +
          'of implant findings is visible as a missing capability rather than mistaken for a clean firmware.',
      },
    ],
  };
}

/** How the caller can tune (or switch off) the per-module pass without touching the whole-image scan. */
export interface FwHuntModuleOptions {
  /**
   * A directory of already-carved EFI modules to reuse — chipsec's `<img>.dir` tree qualifies. Absent ⇒ this
   * provider carves the image itself with the analyzer's own `extract`.
   */
  modulesDir?: string;
  /** How many carved modules to scan. Defaults to `FIRMLAB_FWHUNT_MODULE_CAP`; `0` turns the pass off. */
  moduleCap?: number;
  /** Zero-based deterministic window. Defaults to `FIRMLAB_FWHUNT_MODULE_BATCH`; each window keeps the same cap. */
  moduleBatch?: number;
  /** Wall-clock ceiling for the whole pass. */
  moduleBudgetMs?: number;
  /** Compatible accumulated result from earlier windows of this image. Never merged without matching fingerprints. */
  previousModulePass?: ModulePass | null;
  env?: NodeJS.ProcessEnv;
}

/** The analyzer is a console script inside the same venv as the library, next to its interpreter. */
function analyzerArgv(subcommand: string[]): string[] {
  const analyzer = path.join(path.dirname(fwhuntPython()), 'fwhunt_scan_analyzer.py');
  return fs.existsSync(analyzer)
    ? [analyzer, ...subcommand]
    : ['-m', 'fwhunt_scan.fwhunt_scan_analyzer', ...subcommand];
}

/** A pass that never started. `ran: false` plus the reason — an unattempted pass must not read as an empty one. */
function modulePassNotRun(reason: string): ModulePass {
  return {
    ran: false,
    reason,
    verdicts: [],
    unreadableLines: 0,
    modulesCarved: 0,
    batchIndex: 0,
    batchCount: 0,
    batchSize: 0,
    batchesCompleted: [],
    batches: [],
    modulesScannedThisBatch: 0,
    rankingVersion: MODULE_RANKING_VERSION,
    rankingFingerprint: '',
    corpusFingerprint: '',
    modulesScanned: [],
    modulesSkipped: [],
    modulesFailed: [],
    skipReason: '',
    rulesOffered: 0,
    rulesExcluded: [],
    scopedRuleNames: [],
    deepDirsSkipped: 0,
  };
}

/**
 * Run the module-target corpus against individual carved EFI modules.
 *
 * This is where the coverage the whole-image scan admitted it was missing actually comes from: `scan-module` takes
 * one EFI file and an explicit rule list and applies no volume-GUID test, so every module rule runs against every
 * module it is pointed at. What that costs is a full rizin analysis per module, which is why the pass is bounded
 * three ways — a module cap, a wall-clock budget and a per-module timeout — and why each bound reports the modules
 * it dropped instead of returning a short list that reads like the whole image.
 */
async function runModulePass(
  imagePath: string,
  rulesDir: string,
  coveredByImageScan: string[],
  handle: JobHandle,
  opts: FwHuntModuleOptions,
): Promise<ModulePass> {
  const cap = opts.moduleCap ?? fwhuntModuleCap(opts.env ?? process.env);
  if (cap <= 0) return modulePassNotRun('the per-module cap is 0 (FIRMLAB_FWHUNT_MODULE_CAP)');

  const corpus = loadRuleCorpus(rulesDir);
  const corpusFingerprint = fingerprintRuleCorpus(corpus);
  const { rules, excluded } = selectModuleRules(corpus);
  if (rules.length === 0) return modulePassNotRun('the corpus holds no module-target rules');

  // Reuse a carve the caller already paid for, or make our own in a directory we own and delete. A caller-supplied
  // directory that is not there is a wiring mistake, and it must not be reported as "this image has no modules".
  let carveDir = opts.modulesDir;
  let ownedCarve: string | null = null;
  if (carveDir && !fs.existsSync(carveDir)) {
    return modulePassNotRun(`the caller-supplied module directory ${carveDir} does not exist`);
  }
  if (!carveDir) {
    ownedCarve = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-fwhunt-'));
    carveDir = path.join(ownedCarve, 'modules');
    try {
      await execFileAsync(fwhuntPython(), analyzerArgv(['extract', imagePath, carveDir]), {
        timeout: DEFAULT_MODULE_TIMEOUT_MS,
        maxBuffer: 32 * 1024 * 1024,
      });
    } catch (err) {
      fs.rmSync(ownedCarve, { recursive: true, force: true });
      return modulePassNotRun(`the image could not be carved into modules: ${(err as Error).message}`);
    }
  }

  try {
    const { modules, deepDirsSkipped } = findCarvedModules(carveDir);
    if (modules.length === 0) {
      return { ...modulePassNotRun('the carve produced no EFI modules to scan'), deepDirsSkipped };
    }

    const requestedBatch = opts.moduleBatch ?? fwhuntModuleBatch(opts.env ?? process.env);
    const { selected, skipped, batchIndex, batchCount, batchStart, rankingFingerprint } = rankModulesForScan({
      modules,
      coveredByImageScan,
      cap,
      batch: requestedBatch,
      rules,
    });
    if (selected.length === 0 && batchIndex >= batchCount) {
      return {
        ...modulePassNotRun(
          `module batch ${batchIndex} is outside the ${batchCount} batch(es) in this ${modules.length}-module carve`,
        ),
        modulesCarved: modules.length,
        batchIndex,
        batchCount,
        batchSize: cap,
        rankingFingerprint,
        corpusFingerprint,
        modulesSkipped: modules,
        skipReason: `the requested zero-based batch ${batchIndex} has no range in this carve`,
        rulesOffered: rules.length,
        rulesExcluded: excluded,
        scopedRuleNames: rules.filter((r) => r.volumeGuids > 0).map((r) => r.name),
        deepDirsSkipped,
      };
    }
    const budgetMs = opts.moduleBudgetMs ?? DEFAULT_MODULE_BUDGET_MS;
    const ruleArgs = rules.flatMap((r) => ['-r', path.join(rulesDir, r.path)]);
    handle.log(
      `fwhunt: per-module batch ${batchIndex + 1}/${batchCount} — ${rules.length} module rule(s) against ranking positions ${batchStart + 1}-${batchStart + selected.length} of ${modules.length}.`,
    );

    const verdicts: RuleVerdict[] = [];
    const scanned: CarvedModule[] = [];
    const failed: CarvedModule[] = [];
    const outOfBudget: CarvedModule[] = [];
    let unreadableLines = 0;
    const deadline = Date.now() + budgetMs;

    for (const mod of selected) {
      const left = deadline - Date.now();
      if (left <= 0) {
        outOfBudget.push(mod);
        continue;
      }
      let stdout = '';
      try {
        const r = await execFileAsync(fwhuntPython(), analyzerArgv(['scan-module', mod.path, ...ruleArgs]), {
          timeout: Math.min(left, DEFAULT_MODULE_TIMEOUT_MS),
          maxBuffer: 32 * 1024 * 1024,
        });
        stdout = r.stdout;
      } catch (err) {
        stdout = (err as { stdout?: string }).stdout ?? '';
      }
      const parsed = parseFwHuntOutput(stdout);
      unreadableLines += parsed.unreadableLines;
      if (parsed.verdicts.length === 0) {
        failed.push(mod);
        continue;
      }
      scanned.push(mod);
      // The analyzer echoes back the PATH we handed it; re-stamp with the module's own label, which is what a
      // reader can act on and what the ranking already keyed on.
      for (const v of parsed.verdicts) verdicts.push({ ...v, module: mod.name });
    }

    const dropped = [...outOfBudget, ...skipped];
    const skipReason = outOfBudget.length
      ? `the ${Math.round(budgetMs / 1000)}s pass budget ran out after ${scanned.length} module(s) in batch ${batchIndex + 1}/${batchCount}; every other ranking window remains explicit`
      : `batch ${batchIndex + 1}/${batchCount}, a cap-sized ranking window selected after ordering by coverage debt, corpus mentions and module privilege — never carve order`;
    const batchRecord: ModuleBatchRecord = {
      index: batchIndex,
      rangeStart: batchStart,
      rangeEnd: batchStart + selected.length,
      // A failed module remains unknown and must keep this window resumable; "attempted" is not "complete".
      complete: outOfBudget.length === 0 && failed.length === 0,
      modulesScanned: scanned,
      modulesFailed: failed,
      verdicts,
      unreadableLines,
    };

    const current: ModulePass = {
      ran: scanned.length > 0,
      // A pass where every module failed reports `ran: false`, so the failure count has to travel in the reason —
      // otherwise the only trace of "we tried N modules and the analyzer died on all of them" is a bare false.
      reason:
        scanned.length > 0
          ? ''
          : `all ${failed.length} module(s) the pass tried produced no readable verdict — unknown, not clean`,
      verdicts,
      unreadableLines,
      modulesCarved: modules.length,
      batchIndex,
      batchCount,
      batchSize: cap,
      batchesCompleted: batchRecord.complete ? [batchIndex] : [],
      batches: [batchRecord],
      modulesScannedThisBatch: scanned.length,
      rankingVersion: MODULE_RANKING_VERSION,
      rankingFingerprint,
      corpusFingerprint,
      modulesScanned: scanned,
      modulesSkipped: dropped,
      modulesFailed: failed,
      skipReason: dropped.length ? skipReason : '',
      rulesOffered: rules.length,
      rulesExcluded: excluded,
      scopedRuleNames: rules.filter((r) => r.volumeGuids > 0).map((r) => r.name),
      deepDirsSkipped,
    };
    return accumulateModulePass(opts.previousModulePass, current);
  } finally {
    if (ownedCarve) fs.rmSync(ownedCarve, { recursive: true, force: true });
  }
}

/**
 * Scan a UEFI image with the FwHunt rule corpus — whole-image first, then per carved module. Degrades honestly at
 * every step: scanner absent, rules missing, or a crashing analyzer each produce a `blocked` finding naming the
 * reason instead of an empty result, and a per-module pass that could not run says so rather than leaving the
 * whole-image numbers to stand in for the whole answer.
 */
export async function runFwHunt(
  imagePath: string,
  handle: JobHandle,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  opts: FwHuntModuleOptions = {},
): Promise<FwHuntResult> {
  if (!(await isToolAvailable('fwhunt'))) {
    handle.log('fwhunt-scan not available — rebuild the tools base with the optional fwhunt layer.');
    return unavailable('fwhunt-scan (or its rizin backend) is not installed in this deployment');
  }

  const rulesDir = fwhuntRulesDir();
  if (!fs.existsSync(rulesDir)) {
    return unavailable(`FwHunt rule corpus not found at ${rulesDir} — set FIRMLAB_FWHUNT_RULES`);
  }

  // `--force` lets rules that declare no volume GUID run instead of being silently skipped — strictly more
  // coverage, and the residual gap is reported rather than hidden.
  const args = analyzerArgv(['scan-firmware', imagePath, '-d', rulesDir, '--force']);

  handle.log(`fwhunt: scanning ${path.basename(imagePath)} against the rule corpus at ${rulesDir}.`);
  let stdout = '';
  try {
    const r = await execFileAsync(fwhuntPython(), args, { timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024 });
    stdout = r.stdout;
  } catch (err) {
    // The analyzer exits non-zero on a match in some versions, so partial stdout is a normal success path — only
    // a run that produced nothing readable is a real failure.
    const e = err as { stdout?: string; message?: string };
    stdout = e.stdout ?? '';
    if (!stdout.trim()) {
      const message = e.message ?? String(err);
      handle.log(`fwhunt failed: ${message}`);
      return unavailable(`fwhunt-scan failed: ${message}`);
    }
  }

  const { verdicts, unreadableLines } = parseFwHuntOutput(stdout);
  if (verdicts.length === 0) {
    return unavailable('fwhunt-scan produced no readable rule verdicts — treat the scan as not performed');
  }

  const corpus = loadRuleCorpus(rulesDir);
  const rulePaths = indexRuleCorpus(rulesDir);
  const rulesInCorpus = corpus.length;

  let modulePass: ModulePass;
  try {
    const covered = verdicts.map((v) => v.module).filter((m): m is string => Boolean(m));
    modulePass = await runModulePass(imagePath, rulesDir, covered, handle, opts);
  } catch (err) {
    // A pass that threw is a pass that did not happen; it must not be able to take the whole-image result with it.
    modulePass = modulePassNotRun(`the per-module pass failed: ${(err as Error).message}`);
  }
  if (!modulePass.ran) handle.log(`fwhunt: per-module pass did not run — ${modulePass.reason}`);

  const moduleMatches = modulePass.ran ? modulePass.verdicts.filter((v) => v.matched) : [];
  const matched = verdicts.filter((v) => v.matched);
  const examined = new Set([
    ...verdicts.map((v) => v.rule),
    ...(modulePass.ran ? modulePass.verdicts.map((v) => v.rule) : []),
  ]);
  const wholeImageRules = new Set(verdicts.map((v) => v.rule)).size;
  const passNote = modulePass.ran
    ? `, plus ${modulePass.rulesOffered} module rule(s) over ${modulePass.modulesScanned.length}/${modulePass.modulesCarved} carved module(s) accumulated across ${modulePass.batches.length} distinct batch window(s); latest batch ${modulePass.batchIndex + 1}/${modulePass.batchCount} added ${modulePass.modulesScannedThisBatch}`
    : `; the per-module pass did not run — ${modulePass.reason}`;
  const reason = [
    `FwHunt: ${matched.length + moduleMatches.length} match(es) across ${examined.size}/${rulesInCorpus} rule(s)`,
    `that examined these bytes (${wholeImageRules} whole-image${passNote}).`,
    'No match means the known families were not found, never that the firmware is implant-free.',
  ].join(' ');
  handle.log(reason);

  return {
    available: true,
    reason,
    rulesRun: examined.size,
    rulesNotApplicable: Math.max(0, rulesInCorpus - examined.size),
    rulesInCorpus,
    matches: [...matched, ...moduleMatches],
    modulePass,
    findings: buildFwHuntFindings({ verdicts, unreadableLines, rulePaths, rulesInCorpus, rulesDir, modulePass }),
  };
}
