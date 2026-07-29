/**
 * YARA rootfs scan — the rule-based implant sweep the embedded-Linux path did not have.
 *
 * `providers/fwhunt.ts` is the same recipe one layer up: ship the SCANNER and somebody else's RULES as data,
 * attribute a hit to the rule that made it, and spend most of the code on the DENOMINATOR. That provider only ever
 * looks at UEFI images, and the corpus this workbench actually holds is embedded Linux — where nothing had ever
 * asked whether a rootfs contains a known implant, a webshell, a Mirai variant or a backdoor account. This is that
 * question, asked the same way.
 *
 * **FirmLab authors no signatures, and the built-in corpus is EMPTY.** The precedent is `FIRMLAB_UEFI_IOC` in
 * `chipsec.ts` and the reason is recorded in docs/BACKLOG.md: a hand-assembled detection list looks exactly like
 * threat intelligence and is fabrication. So the corpus is operator-supplied through `FIRMLAB_YARA_RULES`, and with
 * nothing configured this provider scans nothing and says so. "Nobody supplied rules" and "rules ran and matched
 * nothing" are DIFFERENT ANSWERS to the same question, and this codebase has shipped that conflation before (three
 * panels reporting "no device tree has been read" for an image whose device-tree run had completed and found
 * nothing). They are kept apart here by an explicit `state`, never by an empty list.
 *
 * The honesty contract:
 *
 *  - A match is `static_confirmed` and the claim is *rule X, from corpus Y, matched these bytes*. The rule's NAME
 *    may say `Mirai` or `Backdoor`; that is the rule author's label, not an established fact about this firmware,
 *    and the title never restates it as FirmLab's verdict. Severity comes from the rule's own `meta` when it
 *    declares one and is otherwise a PLACEMENT, marked as such — FirmLab does not grade a rule it did not write.
 *  - The denominator is the point. Rules are counted where they are DECLARED, not where they fired, so the result
 *    carries N of M applied and why the difference: rules in a file this yara build refused to compile (with the
 *    compiler's own message and a classification), rules declared `private` — which in YARA can never report a
 *    match on their own, so counting them as applied would inflate coverage — and files under the corpus root that
 *    the `.yar`/`.yara` extension filter never opened.
 *  - A clean scan is not "no implant". `describeCoverage` states what was scanned, with which rules, and that the
 *    result is bounded by the corpus: a rule that does not exist cannot match.
 *  - yara absent ⇒ `blocked_by_platform` with the reason, never a silent skip and never an empty findings list.
 *  - The file cap RANKS. A rootfs has more files than a cap, and taking the first N of a directory walk makes the
 *    scanned *set* an artifact of tree layout — the defect `selectFindings` in `binvuln.ts` was written to fix.
 *    `rankScanTargets` orders on what the first four bytes say the file IS and on where it sits, then on path so
 *    two runs over the same rootfs scan the same files; every file it drops comes back in `skipped` and the rule
 *    that dropped it is stated on the result.
 *
 * The masker, the rule-declaration reader, the corpus summary, the output parser, the compile-error classifier,
 * the target ranking and the finding builder are PURE and unit-tested. The runner only walks the disk and shells
 * out under a timeout. Nothing here needs the real `yara` binary to be tested, which is this repo's rule.
 *
 * A note for whoever adds a field to `YaraScanResult`: results are JSON on a job row and re-read for as long as
 * the image exists, so a stored result is data written by an older build. Any field added after this commit is
 * OPTIONAL FOREVER.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import type { FindingDraft } from '../findings-normalize.js';
import { isToolAvailable } from '../tools.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

/** A corpus of thousands of rules over a full rootfs is minutes of scanning, not seconds. */
export const DEFAULT_TIMEOUT_MS = 20 * 60 * 1000;

/** Handed to `yara -a`: per-file scan ceiling, so one pathological file cannot hold the whole sweep. */
export const DEFAULT_PER_FILE_TIMEOUT_S = 60;

/** How many files the scan covers by default before `rankScanTargets` has to choose. */
export const DEFAULT_FILE_CAP = 20000;

/** Files above this are not offered to yara. A cap on bytes, not on interest — and it is reported as a cap. */
export const DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024;

/** How deep the rootfs walk descends before it refuses and counts what it refused. */
const MAX_WALK_DEPTH = 24;

/**
 * The extension filter applied to the corpus root. Named on the result, because it is a coverage decision: a
 * corpus root full of `.yarc` bundles or an unextracted archive yields zero rules, and that must not look like a
 * scan that ran. Written as the exact two extensions rather than a loose pattern, so `RULE_FILE_FILTER` below is
 * a true description of it and not an approximation of one.
 */
const RULE_FILE_EXT = /\.(yar|yara)$/i;

/** Human name of the filter above, so the result can say what it skipped by. */
export const RULE_FILE_FILTER = '.yar/.yara';

/** How much of a rule file is read. Public corpora carry rules with megabytes of hex strings in one file. */
const RULE_FILE_READ_BYTES = 4 * 1024 * 1024;

/** How many matched file paths one rule's finding lists before it starts counting them instead. */
const MATCHED_FILE_LIST_CAP = 20;

/**
 * `FIRMLAB_YARA_RULES` — the operator's rule corpus, as `path.delimiter`-separated files or directories. There is
 * deliberately NO default: an empty built-in is the whole point, and a fabricated one would be worse than nothing.
 */
export function yaraCorpusSources(env: NodeJS.ProcessEnv = process.env): string[] {
  const raw = env.FIRMLAB_YARA_RULES;
  if (!raw || !raw.trim()) return [];
  return raw
    .split(path.delimiter)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** `FIRMLAB_YARA_FILE_CAP` — how many files the scan covers. `0` means "no cap"; a negative value is ignored. */
export function yaraFileCap(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.FIRMLAB_YARA_FILE_CAP;
  if (raw === undefined || raw.trim() === '') return DEFAULT_FILE_CAP;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_FILE_CAP;
}

/** `FIRMLAB_YARA_MAX_FILE_BYTES` — the per-file size ceiling. */
export function yaraMaxFileBytes(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.FIRMLAB_YARA_MAX_FILE_BYTES;
  if (raw === undefined || raw.trim() === '') return DEFAULT_MAX_FILE_BYTES;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_FILE_BYTES;
}

/** One rule as the corpus DECLARES it — which is the only place a denominator can honestly be counted. */
export interface DeclaredRule {
  name: string;
  /** `private rule` — YARA never reports it on its own, so it cannot be counted as coverage. */
  isPrivate: boolean;
  /** `global rule` — applies to every scanned file in its namespace. */
  isGlobal: boolean;
  tags: string[];
  /** The rule's own `meta:` block, verbatim. This is the attribution: author, reference, description, severity. */
  meta: Record<string, string>;
}

/** One file of the corpus, and the namespace it is compiled into so a match can name the file it came from. */
export interface RuleFile {
  path: string;
  /** The `FIRMLAB_YARA_RULES` entry this file came from — the "corpus Y" a match is attributed to. */
  corpus: string;
  /** Path relative to that entry. */
  relPath: string;
  /** The YARA namespace this file is given on the command line, unique per file. */
  namespace: string;
  rules: DeclaredRule[];
  /** `import "pe"` and friends — what a "missing module" compile failure will have been about. */
  imports: string[];
  /** True when the file is on disk and could not be read. Its rules are unknown, not zero. */
  unreadable: boolean;
}

/** How a rule file failed to compile, classified from the compiler's own message. */
export type CompileFailureReason = 'missing-module' | 'syntax' | 'undefined-identifier' | 'unreadable' | 'other';

/** A rule file that could not be offered to the scan, and the rules it took with it. */
export interface RejectedRuleFile {
  path: string;
  corpus: string;
  namespace: string;
  /** Rules declared in the file that consequently examined nothing. */
  rulesLost: number;
  reason: CompileFailureReason;
  message: string;
}

/** What the corpus is, before anything is scanned with it. Every field here is a denominator or a hole in one. */
export interface CorpusSummary {
  /** The `FIRMLAB_YARA_RULES` entries, as the operator wrote them. */
  sources: string[];
  /** Entries that are not on disk at all — a wiring mistake, not an empty corpus. */
  missingSources: string[];
  filesFound: number;
  filesCompiled: number;
  /** Files under a corpus root the `.yar`/`.yara` filter never opened. Coverage the operator did not get. */
  filesSkippedByFilter: number;
  filesUnreadable: number;
  rejected: RejectedRuleFile[];
  rulesDeclared: number;
  /** Declared `private`: they can never report a match on their own, so they are not applied coverage. */
  rulesPrivate: number;
  /** Rules actually offered to the scan — declared, minus private, minus every rule in a rejected file. */
  rulesApplied: number;
  /** The extension filter that produced `filesSkippedByFilter`, named. */
  fileFilter: string;
}

/** What the first four bytes say a file IS. Read off the bytes, so it is evidence rather than a naming guess. */
export type ContentClass = 'elf' | 'script' | 'other';

/** Where a file sits in a rootfs. A convention, and weaker than `ContentClass` — weighted accordingly. */
export type LocationClass = 'startup' | 'web-root' | 'executable-path' | 'writable' | 'library-path' | 'other';

/** One candidate file, with the two signals `rankScanTargets` orders on. */
export interface ScanTarget {
  path: string;
  /** Path relative to the scan root — what a reader can act on. */
  relPath: string;
  size: number;
  content: ContentClass;
  location: LocationClass;
}

/** What the scan actually covered, and every bound that kept it from covering more. */
export interface ScanSummary {
  root: string;
  /** Regular files under the root — the denominator file coverage is measured against. */
  filesFound: number;
  /** Files handed to yara. */
  filesListed: number;
  /** Files yara read without erroring. `filesListed` minus the ones it printed a scan error for. */
  filesScanned: number;
  /** Files the size ceiling dropped. */
  filesTooLarge: number;
  /** Files the count cap dropped, after ranking. */
  filesOverCap: number;
  /** Files whose path holds a newline, which a yara scan list cannot express. Excluded and counted, not hidden. */
  filesUnrepresentable: number;
  /** Files yara was pointed at and failed on — tried and unknown, never clean. */
  filesFailed: string[];
  bytesListed: number;
  maxFileBytes: number;
  fileCap: number;
  /** The rule that produced `filesOverCap`, stated. Empty when the cap dropped nothing. */
  skipReason: string;
  dirsUnreadable: number;
  deepDirsSkipped: number;
}

/** Every match of one rule, grouped — a rule that fires on 400 files is one claim, not 400. */
export interface RuleMatchGroup {
  rule: string;
  namespace: string;
  /** The corpus entry and the file inside it, when the namespace resolved. Absent ⇒ yara named a rule we did not
   *  index, which is reported rather than dropped. */
  corpus?: string;
  ruleFile?: string;
  tags: string[];
  meta: Record<string, string>;
  files: string[];
}

/**
 * Which question this run answered — or which one it could not. These are NOT interchangeable, and none of them
 * may be represented by an empty `matches` array.
 */
export type YaraScanState =
  | 'tool_absent'
  | 'no_corpus'
  | 'corpus_empty'
  | 'no_rules_applied'
  | 'no_target'
  | 'scan_failed'
  | 'scanned';

export interface YaraScanResult {
  available: boolean;
  state: YaraScanState;
  reason: string;
  corpus: CorpusSummary;
  /** Null whenever no scan was performed — which is a different thing from a scan that found nothing. */
  scan: ScanSummary | null;
  matches: RuleMatchGroup[];
  findings: FindingDraft[];
}

// ---------------------------------------------------------------------------------------------------------------
// Reading the corpus (pure)
// ---------------------------------------------------------------------------------------------------------------

/**
 * Pure: blank out everything in a YARA source that is not grammar — comments, text-string bodies and regex bodies —
 * preserving offsets and newlines so the caller can index back into the ORIGINAL text.
 *
 * This is not tidiness. `rule` at the start of a line inside a comment is not a rule, and a regex quantifier
 * (`/a{2,3}/`) or a `[{]` character class would otherwise unbalance the brace scan that finds a rule's body. The
 * regex case is decided by the preceding non-space character: a `/` after `=`, `(` or `,` opens a regex literal,
 * and anywhere else it is a comment or a division that YARA's grammar does not have.
 */
export function maskYaraSource(src: string): string {
  const out = src.split('');
  const blank = (from: number, to: number): void => {
    for (let i = from; i < to && i < out.length; i++) {
      if (out[i] !== '\n') out[i] = ' ';
    }
  };
  let prev = '';
  for (let i = 0; i < src.length; i++) {
    const c = src[i] as string;
    const next = src[i + 1];
    if (c === '/' && next === '/') {
      let j = i + 2;
      while (j < src.length && src[j] !== '\n') j++;
      blank(i, j);
      i = j - 1;
      continue;
    }
    if (c === '/' && next === '*') {
      const end = src.indexOf('*' + '/', i + 2);
      const j = end < 0 ? src.length : end + 2;
      blank(i, j);
      i = j - 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\') j++;
        j++;
      }
      blank(i + 1, j);
      i = j;
      prev = '"';
      continue;
    }
    if (c === '/' && (prev === '=' || prev === '(' || prev === ',')) {
      let j = i + 1;
      while (j < src.length && src[j] !== '/' && src[j] !== '\n') {
        if (src[j] === '\\') j++;
        j++;
      }
      blank(i + 1, j);
      i = j;
      prev = '/';
      continue;
    }
    if (c.trim()) prev = c;
  }
  return out.join('');
}

/** `rule Name : tag1 tag2` at the start of a line, with the optional `private`/`global` modifiers before it. */
const RULE_DECL = /(^|\n)[ \t]*((?:(?:private|global)[ \t]+)*)rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*(:[^\n{]*)?/g;

/** `import "pe"` — what a missing-module compile failure will have been about. */
const IMPORT_DECL = /(^|\n)[ \t]*import[ \t]+"([^"\n]+)"/g;

/** One `key = value` line of a `meta:` block. Values are single-line in YARA; quotes are stripped. */
const META_LINE = /^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.+?)[ \t]*$/;

/** Where a rule body stops being `meta:`. */
const META_END = /(^|\n)[ \t]*(strings|condition)[ \t]*:/;

/** Read the `meta:` block out of one rule body. Structure from the masked text, values from the original. */
function parseRuleMetaBlock(body: string, maskedBody: string): Record<string, string> {
  const at = /(^|\n)[ \t]*meta[ \t]*:/.exec(maskedBody);
  if (!at) return {};
  const from = at.index + at[0].length;
  const rest = maskedBody.slice(from);
  const end = META_END.exec(rest);
  const to = end ? from + end.index : maskedBody.length;
  const meta: Record<string, string> = {};
  for (const line of body.slice(from, to).split('\n')) {
    const m = META_LINE.exec(line);
    if (m?.[1] && m[2]) meta[m[1]] = m[2].replace(/^"|"$/g, '');
  }
  return meta;
}

/** Find the `{ … }` body that follows `from`, by brace depth over the masked text. */
function ruleBodyRange(masked: string, from: number): { start: number; end: number } | null {
  const open = masked.indexOf('{', from);
  if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < masked.length; i++) {
    if (masked[i] === '{') depth++;
    else if (masked[i] === '}' && --depth === 0) return { start: open, end: i + 1 };
  }
  return null;
}

/**
 * Pure: every rule a YARA source DECLARES, with its modifiers, tags and `meta:` block.
 *
 * The declaration is where a denominator can be counted honestly. Counting rules by what fired counts one, and
 * counting rule FILES counts a corpus that ships 300 rules in one file as one rule. `private` is carried because
 * YARA never reports a private rule on its own — it exists as a building block for other rules' conditions — so
 * folding it into "rules applied" would inflate the coverage number with rules that cannot, by construction,
 * produce a result.
 */
export function parseRuleDeclarations(src: string): { rules: DeclaredRule[]; imports: string[] } {
  const masked = maskYaraSource(src);
  const rules: DeclaredRule[] = [];
  RULE_DECL.lastIndex = 0;
  for (let m = RULE_DECL.exec(masked); m; m = RULE_DECL.exec(masked)) {
    const mods = (m[2] ?? '').split(/\s+/).filter(Boolean);
    const tags = (m[4] ?? '').replace(/^:/, '').split(/\s+/).filter(Boolean);
    const range = ruleBodyRange(masked, m.index + m[0].length);
    const meta = range
      ? parseRuleMetaBlock(src.slice(range.start, range.end), masked.slice(range.start, range.end))
      : {};
    rules.push({
      name: m[3] as string,
      isPrivate: mods.includes('private'),
      isGlobal: mods.includes('global'),
      tags,
      meta,
    });
  }

  // The mask is what says WHERE an import is (one inside a comment is not one), but the module name lives inside a
  // string literal, which the mask has blanked — so the position comes from the masked text and the value comes
  // from the original at the same offsets. Reading the name off the mask returns a run of spaces, which is a
  // parser quietly answering with garbage rather than failing, and the unit test above exists because it did.
  const imports: string[] = [];
  IMPORT_DECL.lastIndex = 0;
  for (let m = IMPORT_DECL.exec(masked); m; m = IMPORT_DECL.exec(masked)) {
    const name = /"([^"\n]+)"/.exec(src.slice(m.index, m.index + m[0].length))?.[1];
    if (name) imports.push(name);
  }
  return { rules, imports: [...new Set(imports)] };
}

/**
 * A YARA namespace for a rule file: unique, and readable enough that the raw scanner output still says which file
 * a rule came from. The index prefix is what guarantees uniqueness — two corpora can hold `malware/mirai.yar`.
 */
export function namespaceForRuleFile(index: number, relPath: string): string {
  const slug = relPath
    .replace(RULE_FILE_EXT, '')
    .replace(/[^A-Za-z0-9_]+/g, '_')
    .slice(0, 60);
  return `r${index}_${slug || 'rules'}`;
}

/** Read at most `bytes` from the head of a file; unreadable ⇒ null, which is a different answer from empty. */
function readHead(file: string, bytes: number): string | null {
  let fd: number;
  try {
    fd = fs.openSync(file, 'r');
  } catch {
    return null;
  }
  try {
    const buf = Buffer.allocUnsafe(bytes);
    const n = fs.readSync(fd, buf, 0, bytes, 0);
    return buf.subarray(0, n).toString('utf8');
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Walk the operator's corpus entries into rule files, counting what the extension filter refused on the way.
 *
 * The refusal count is not bookkeeping: a corpus root full of `.yarc` compiled bundles, `.txt` notes or an
 * unextracted archive produces zero rules and would otherwise look exactly like a scan that ran and found nothing.
 */
export function loadRuleCorpus(sources: string[]): {
  files: RuleFile[];
  missingSources: string[];
  filesSkippedByFilter: number;
} {
  const files: RuleFile[] = [];
  const missingSources: string[] = [];
  let filesSkippedByFilter = 0;
  let index = 0;

  const take = (abs: string, corpus: string, relPath: string): void => {
    const text = readHead(abs, RULE_FILE_READ_BYTES);
    const parsed = text === null ? { rules: [], imports: [] } : parseRuleDeclarations(text);
    files.push({
      path: abs,
      corpus,
      relPath,
      namespace: namespaceForRuleFile(index++, relPath),
      rules: parsed.rules,
      imports: parsed.imports,
      unreadable: text === null,
    });
  };

  const walk = (dir: string, corpus: string, depth: number): void => {
    if (depth > MAX_WALK_DEPTH) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) walk(abs, corpus, depth + 1);
      else if (!e.isFile()) continue;
      else if (RULE_FILE_EXT.test(e.name)) take(abs, corpus, path.relative(corpus, abs));
      else filesSkippedByFilter++;
    }
  };

  for (const source of sources) {
    let stat: fs.Stats;
    try {
      stat = fs.statSync(source);
    } catch {
      missingSources.push(source);
      continue;
    }
    if (stat.isDirectory()) walk(source, source, 0);
    else if (RULE_FILE_EXT.test(source)) take(source, source, path.basename(source));
    else filesSkippedByFilter++;
  }

  files.sort((a, b) => a.path.localeCompare(b.path));
  return { files, missingSources, filesSkippedByFilter };
}

/**
 * Pure: the corpus as a set of denominators.
 *
 * `rulesApplied` is the honest numerator and it subtracts twice: the rules in files that could not be compiled
 * (they examined nothing), and the `private` rules (they cannot report). Both differences are carried so the
 * caller can state WHY, which is the whole reason this function returns a record rather than a number.
 */
export function summarizeCorpus(input: {
  files: RuleFile[];
  sources: string[];
  missingSources?: string[];
  filesSkippedByFilter?: number;
  rejected?: RejectedRuleFile[];
}): CorpusSummary {
  const { files, sources, missingSources = [], filesSkippedByFilter = 0, rejected = [] } = input;
  const rejectedNs = new Set(rejected.map((r) => r.namespace));
  let rulesDeclared = 0;
  let rulesPrivate = 0;
  let rulesApplied = 0;
  let filesUnreadable = 0;
  for (const f of files) {
    if (f.unreadable) filesUnreadable++;
    for (const r of f.rules) {
      rulesDeclared++;
      if (r.isPrivate) rulesPrivate++;
      else if (!rejectedNs.has(f.namespace)) rulesApplied++;
    }
  }
  return {
    sources,
    missingSources,
    filesFound: files.length,
    filesCompiled: files.length - rejected.length,
    filesSkippedByFilter,
    filesUnreadable,
    rejected,
    rulesDeclared,
    rulesPrivate,
    rulesApplied,
    fileFilter: RULE_FILE_FILTER,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Reading what yara said (pure)
// ---------------------------------------------------------------------------------------------------------------

/**
 * Pure: read one match line of `yara -e -g` (and tolerate `-m`, whose meta group this codebase does not currently
 * ask for but which a future flag would add).
 *
 * The line is `[namespace:]rule [tags] [meta] path`, and every one of those interpolations is unquoted and
 * unescaped. A path may contain spaces and brackets; a meta value may contain a `]` inside its quotes. So the
 * bracket groups are consumed left-to-right by depth with quote awareness, and whatever is left is the path — the
 * same lesson `parseVerdictLine` in `fwhunt.ts` was rewritten for after a naive regex silently dropped the only
 * rule that had actually triggered.
 */
export function parseYaraMatchLine(
  line: string,
): { namespace?: string; rule: string; tags: string[]; path: string } | null {
  const trimmed = line.trimEnd();
  const sp = trimmed.indexOf(' ');
  if (sp <= 0) return null;
  const head = trimmed.slice(0, sp);
  const colon = head.lastIndexOf(':');
  const namespace = colon > 0 ? head.slice(0, colon) : undefined;
  const rule = colon > 0 ? head.slice(colon + 1) : head;
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(rule)) return null;

  let i = sp + 1;
  const groups: string[] = [];
  // At most two, because that is all yara can print (`-g` tags, then `-m` meta). Bounding it is what keeps a path
  // that legitimately begins with `[` from being eaten as a third group that cannot exist.
  while (i < trimmed.length && trimmed[i] === '[' && groups.length < 2) {
    let depth = 0;
    let quoted = false;
    let j = i;
    for (; j < trimmed.length; j++) {
      const c = trimmed[j];
      if (c === '"' && trimmed[j - 1] !== '\\') quoted = !quoted;
      else if (!quoted && c === '[') depth++;
      else if (!quoted && c === ']' && --depth === 0) break;
    }
    if (j >= trimmed.length) return null;
    groups.push(trimmed.slice(i + 1, j));
    i = j + 1;
    while (trimmed[i] === ' ') i++;
  }

  const filePath = trimmed.slice(i);
  if (!filePath) return null;
  const tags = (groups[0] ?? '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);
  return { ...(namespace ? { namespace } : {}), rule, tags, path: filePath };
}

/**
 * Pure: normalize yara's stdout into one group per rule.
 *
 * Grouping is not cosmetic. A `global` rule, or a broad packer/UPX rule, fires on every file it is offered, and one
 * finding per (rule, file) would bury the ledger under one rule's shape. A line that looks like a match and cannot
 * be read is COUNTED, never dropped: an unparsed verdict is an unknown, and an unknown must not quietly become
 * "nothing matched".
 */
export function parseYaraOutput(stdout: string): { groups: RuleMatchGroup[]; unreadableLines: number } {
  const byKey = new Map<string, RuleMatchGroup>();
  let unreadableLines = 0;
  for (const raw of stdout.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const m = parseYaraMatchLine(line);
    if (!m) {
      unreadableLines++;
      continue;
    }
    const ns = m.namespace ?? 'default';
    const key = `${ns}\\u0000${m.rule}`;
    const g = byKey.get(key) ?? { rule: m.rule, namespace: ns, tags: m.tags, meta: {}, files: [] };
    g.files.push(m.path);
    byKey.set(key, g);
  }
  const groups = [...byKey.values()].sort(
    (a, b) => a.rule.localeCompare(b.rule) || a.namespace.localeCompare(b.namespace),
  );
  for (const g of groups) g.files.sort();
  return { groups, unreadableLines };
}

/** `<file>(<line>): error: <message>` — how yara reports a rule it will not compile. */
const COMPILE_DIAGNOSTIC = /^(.*?)\((\d+)\):\s*(error|warning):\s*(.*)$/;

/** A diagnostic the compiler printed, still attached to the file it was about. */
export interface CompileDiagnostic {
  file: string;
  line: number;
  level: 'error' | 'warning';
  message: string;
}

/** Pure: read yara's compiler diagnostics off stderr. Warnings are kept — they are coverage risk, not noise. */
export function parseCompileDiagnostics(stderr: string): CompileDiagnostic[] {
  const out: CompileDiagnostic[] = [];
  for (const raw of stderr.split('\n')) {
    const m = COMPILE_DIAGNOSTIC.exec(raw.trim());
    if (!m?.[1] || !m[4]) continue;
    out.push({
      file: m[1],
      line: Number.parseInt(m[2] ?? '0', 10),
      level: m[3] === 'warning' ? 'warning' : 'error',
      message: m[4],
    });
  }
  return out;
}

/**
 * Pure: what kind of hole a compile failure is.
 *
 * The distinction is a real one for an operator. A rule that wants `import "pe"` on a yara built without the module
 * is a BUILD gap this deployment can close; a syntax error is a rule this yara version cannot parse, usually
 * because the corpus is newer than the binary; an undefined identifier is usually a private rule that lived in a
 * file the operator did not point at. Each suggests a different fix, and all three are invisible if the result only
 * says "some rules did not run".
 */
export function classifyCompileFailure(message: string): CompileFailureReason {
  const m = message.toLowerCase();
  if (/can't open include file|include file|module|import/.test(m)) return 'missing-module';
  if (/undefined identifier|undefined string|unreferenced string/.test(m)) return 'undefined-identifier';
  if (/syntax error|unexpected|invalid|unknown keyword|not enough memory/.test(m)) return 'syntax';
  return 'other';
}

/** `error scanning /path/to/file: could not open file` — a file yara was pointed at and could not read. */
const SCAN_ERROR = /^error scanning (.+?):\s*(.*)$/;

/** Pure: the files yara failed to read. Tried and unknown — they must never be counted as scanned-and-clean. */
export function parseScanErrors(stderr: string): Array<{ path: string; message: string }> {
  const out: Array<{ path: string; message: string }> = [];
  for (const raw of stderr.split('\n')) {
    const m = SCAN_ERROR.exec(raw.trim());
    if (m?.[1]) out.push({ path: m[1], message: m[2] ?? '' });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// Choosing what to scan (pure)
// ---------------------------------------------------------------------------------------------------------------

/** Directory prefixes that say what a file is FOR in a rootfs. Longest-prefix wins, so `/var/www` is a web root. */
const LOCATION_RULES: Array<[RegExp, LocationClass]> = [
  [/^(etc\/(init|init\.d|rc\.d|rc[0-9S]\.d|cron|cron\.[a-z]+|profile\.d|systemd)|lib\/systemd\/system)\//, 'startup'],
  [/^(www|web|webs|htdocs|var\/www|usr\/www|home\/httpd|cgi-bin|usr\/share\/www)\//, 'web-root'],
  [/(^|\/)cgi-bin\//, 'web-root'],
  [/^(bin|sbin|usr\/bin|usr\/sbin|usr\/libexec|usr\/local\/bin|usr\/local\/sbin)\//, 'executable-path'],
  [/^(tmp|var|mnt|opt|home|root)\//, 'writable'],
  [/^(lib|usr\/lib|lib64|usr\/lib64)\//, 'library-path'],
];

/** Pure: where in a rootfs this file sits. A convention about layout, never a claim about the file. */
export function classifyLocation(relPath: string): LocationClass {
  const p = relPath.replace(/^\.?\//, '');
  return LOCATION_RULES.find(([re]) => re.test(p))?.[1] ?? 'other';
}

/** Pure: what the first bytes say the file is. `ELF` and `#!` are facts; everything else is `other`. */
export function classifyContent(head: Buffer): ContentClass {
  if (head.length >= 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46) return 'elf';
  if (head.length >= 2 && head[0] === 0x23 && head[1] === 0x21) return 'script';
  return 'other';
}

/** Extensions that make a file a script even when it carries no shebang — a webshell rarely has one. */
const SCRIPT_EXT = /\.(sh|php|phtml|asp|aspx|jsp|cgi|pl|py|lua|rb|js|ps1)$/i;

/**
 * What one signal is worth when the cap has to choose. `elf` and `script` weigh the SAME on purpose: a compiled
 * implant and a shell webshell are both code, and this workbench has no basis for ranking one above the other. The
 * location weights are smaller than the content weights because location is a convention and content is bytes.
 */
const CONTENT_WEIGHT: Record<ContentClass, number> = { elf: 4, script: 4, other: 0 };
const LOCATION_WEIGHT: Record<LocationClass, number> = {
  startup: 3,
  'web-root': 3,
  'executable-path': 2,
  writable: 2,
  'library-path': 1,
  other: 0,
};

/** Pure: how much of the cap this file has a claim on. An ORDERING, and never a verdict about the file. */
export function targetInterest(t: ScanTarget): number {
  return CONTENT_WEIGHT[t.content] + LOCATION_WEIGHT[t.location];
}

/** The rule `rankScanTargets` applies, in words, so a truncated scan states what dropped its files. */
export function describeRankRule(cap: number): string {
  return [
    `a cap of ${cap} file(s), taken in order of what the first bytes say the file IS (ELF or a script, weighted`,
    'equally — a compiled implant and a shell webshell are both code), then where it sits (startup and web roots,',
    'then executable paths and writable trees, then libraries), then path — never walk order',
  ].join(' ');
}

/**
 * Pure: choose which files the scan covers, and hand back the ones the cap dropped.
 *
 * The order is deliberately NOT the walk order. `selectFindings` in `binvuln.ts` exists because a LIFO walk filled
 * a cap out of `usr/` and silently excluded `bin/`, `sbin/` and the whole `pwnable/` tree — the list read as a set
 * and was in fact the prefix of a reverse-alphabetical traversal. The same defect here would let an implant in
 * `/etc/init.d` go unscanned because the rootfs happened to be laid out with a large `/usr` first.
 *
 * Two keys, and the second is arbitrary only in the sense that it must be deterministic:
 *
 *  1. INTEREST, from `targetInterest` — the bytes first, the layout second.
 *  2. Path, ascending, so two runs over the same rootfs scan the same files.
 *
 * Nothing here is a statement about a file. A file ranked last is not a file cleared, and every file the cap drops
 * comes back in `skipped` so the caller can say how many and by what rule.
 */
export function rankScanTargets(input: { targets: ScanTarget[]; cap: number }): {
  selected: ScanTarget[];
  skipped: ScanTarget[];
} {
  const ordered = [...input.targets].sort(
    (a, b) => targetInterest(b) - targetInterest(a) || a.relPath.localeCompare(b.relPath),
  );
  if (input.cap <= 0) return { selected: ordered, skipped: [] };
  return { selected: ordered.slice(0, input.cap), skipped: ordered.slice(input.cap) };
}

// ---------------------------------------------------------------------------------------------------------------
// Saying what happened (pure)
// ---------------------------------------------------------------------------------------------------------------

const SEVERITY_LADDER: ReadonlyArray<FindingDraft['severity']> = ['info', 'low', 'medium', 'high', 'critical'];

/**
 * Pure: what severity a match is filed at, and where that severity came from.
 *
 * FirmLab did not write the rule and will not grade it. When the rule's own `meta:` declares a severity on the
 * ladder this ledger uses, that is the RULE AUTHOR's assessment and it is used as such. Otherwise the match is
 * filed at `high` — which is a PLACEMENT, not an assessment, and the finding says so rather than letting a default
 * read as a judgement FirmLab made.
 */
export function severityForMatch(meta: Record<string, string>): {
  severity: FindingDraft['severity'];
  source: 'rule-meta' | 'firmlab-placement';
} {
  const declared = (meta.severity ?? '').trim().toLowerCase();
  const hit = SEVERITY_LADDER.find((s) => s === declared);
  if (hit) return { severity: hit, source: 'rule-meta' };
  return { severity: 'high', source: 'firmlab-placement' };
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * Pure: the N-of-M sentence, with the difference explained.
 *
 * "412 of 540 rules ran" is only honest if the missing 128 are accounted for, because otherwise the reader has to
 * assume the difference is irrelevant, and it is exactly the part that is not.
 */
export function describeRuleDenominator(corpus: CorpusSummary): string {
  const { rulesApplied, rulesDeclared, rulesPrivate, rejected } = corpus;
  if (rulesDeclared === 0) {
    return 'The corpus declares no rules at all, so nothing was applied to these bytes.';
  }
  const missing = Math.max(0, rulesDeclared - rulesApplied);
  const verb = rulesApplied === 1 ? 'was' : 'were';
  const head = `${rulesApplied} of the ${plural(rulesDeclared, 'rule', 'rules')} declared in the corpus ${verb} applied to these bytes`;
  if (missing === 0) return `${head}.`;

  const why: string[] = [];
  if (rulesPrivate > 0) {
    why.push(
      `${rulesPrivate} declared \`private\`, which in YARA can never report a match on its own and is therefore not coverage`,
    );
  }
  const lost = rejected.reduce((n, r) => n + r.rulesLost, 0);
  if (lost > 0) {
    const byReason = new Map<CompileFailureReason, number>();
    for (const r of rejected) byReason.set(r.reason, (byReason.get(r.reason) ?? 0) + 1);
    const breakdown = [...byReason.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([reason, n]) => `${n}×${reason}`)
      .join(', ');
    why.push(
      `${lost} in ${plural(rejected.length, 'rule file', 'rule files')} this yara build refused to compile (${breakdown})`,
    );
  }
  const tail = why.length ? ` (${why.join('; ')})` : '';
  return `${head}; the other ${missing} examined nothing${tail}.`;
}

/** Pure: the file-coverage sentence — the other denominator, and the one the caps act on. */
export function describeFileDenominator(scan: ScanSummary): string {
  const head = `${scan.filesScanned} of the ${plural(scan.filesFound, 'regular file', 'regular files')} under ${scan.root} were scanned`;
  const why: string[] = [];
  if (scan.filesTooLarge > 0) {
    why.push(
      `${scan.filesTooLarge} exceeded the ${Math.round(scan.maxFileBytes / (1024 * 1024))} MiB per-file ceiling`,
    );
  }
  if (scan.filesOverCap > 0) why.push(`${scan.filesOverCap} were dropped by ${scan.skipReason}`);
  if (scan.filesUnrepresentable > 0) {
    why.push(`${scan.filesUnrepresentable} hold a newline in their path, which a yara scan list cannot express`);
  }
  if (scan.filesFailed.length > 0) {
    why.push(
      `${scan.filesFailed.length} were handed to yara and it could not read them, so those are unknown, not clean`,
    );
  }
  if (scan.dirsUnreadable > 0) why.push(`${scan.dirsUnreadable} director(ies) could not be listed`);
  if (scan.deepDirsSkipped > 0) why.push(`${scan.deepDirsSkipped} director(ies) were too deeply nested to walk`);
  return why.length ? `${head}; ${why.join(', ')}.` : `${head}.`;
}

/**
 * Pure: the sentence a clean scan is not allowed to be without.
 *
 * An empty match list has exactly one honest reading — "the rules that ran did not fire" — and several dishonest
 * ones, all of which this codebase has shipped in some form. So the coverage note names the corpus, both
 * denominators, and the bound that no amount of scanning removes: a rule that does not exist cannot match.
 */
export function describeCoverage(corpus: CorpusSummary, scan: ScanSummary, matched: number): string {
  return [
    `${plural(matched, 'rule matched', 'rules matched')}.`,
    describeRuleDenominator(corpus),
    describeFileDenominator(scan),
    'A clean YARA result is bounded by the corpus that ran: a rule that does not exist cannot match, so no match',
    'means the rules that ran did not fire — never that this rootfs carries no implant, webshell, Mirai variant or',
    'backdoor account. FirmLab authors no signatures and grades none; every rule here came from the',
    `operator-supplied corpus (${corpus.sources.join(', ') || 'none'}).`,
  ].join(' ');
}

/**
 * Pure: turn the grouped matches and the two denominators into findings.
 *
 * A match makes the only positive claim here and it is phrased as the RULE's claim. The coverage note is emitted on
 * EVERY scan, matched or not, because an empty result reads as "no implant" and what it actually means is "no rule
 * in this corpus for whatever might be in here fired".
 */
export function buildYaraFindings(input: {
  matches: RuleMatchGroup[];
  corpus: CorpusSummary;
  scan: ScanSummary;
  unreadableLines?: number;
}): FindingDraft[] {
  const { matches, corpus, scan, unreadableLines = 0 } = input;
  const drafts: FindingDraft[] = [];

  for (const g of matches) {
    const { severity, source } = severityForMatch(g.meta);
    const listed = g.files.slice(0, MATCHED_FILE_LIST_CAP);
    const attribution = g.ruleFile ? `${g.corpus ?? 'the corpus'} · ${g.ruleFile}` : `namespace ${g.namespace}`;
    drafts.push({
      kind: 'yara-rule-match',
      title: `YARA rule '${g.rule}' matched ${plural(g.files.length, 'file', 'files')} (rule from ${attribution})`,
      severity,
      proofState: 'static_confirmed',
      evidence: {
        rule: g.rule,
        namespace: g.namespace,
        ...(g.corpus ? { corpus: g.corpus } : {}),
        ...(g.ruleFile ? { ruleFile: g.ruleFile } : {}),
        ...(g.tags.length ? { tags: g.tags } : {}),
        ...(Object.keys(g.meta).length ? { ruleMeta: g.meta } : {}),
        files: listed,
        filesMatched: g.files.length,
        filesNotListed: Math.max(0, g.files.length - listed.length),
        filesScanned: scan.filesScanned,
        severityFrom: source,
      },
      rationale: [
        `The YARA rule '${g.rule}' matched ${plural(g.files.length, 'file', 'files')} of the ${scan.filesScanned}`,
        `scanned under ${scan.root}. What is confirmed is the byte-level fact of the match: this rule's patterns are`,
        'present in those files. The claim about WHAT that means belongs to the rule and its author, not to FirmLab —',
        "a rule named after a malware family is that author's label, not an established identification of this",
        `firmware. ${
          source === 'rule-meta'
            ? "The severity above is the rule's own `meta: severity`."
            : 'The rule declares no severity, so this is filed at `high` as a placement, not as an assessment FirmLab made.'
        }`,
        `Read the rule (${g.ruleFile ?? g.namespace}) before acting on it.`,
      ].join(' '),
    });
  }

  const unreadableNote =
    unreadableLines > 0
      ? ` ${plural(unreadableLines, 'output line', 'output lines')} could not be parsed, so those results are unknown rather than negative.`
      : '';

  drafts.push({
    kind: 'yara-coverage',
    title: matches.length
      ? `YARA: ${plural(matches.length, 'rule matched', 'rules matched')} — ${corpus.rulesApplied}/${corpus.rulesDeclared} rule(s) applied over ${scan.filesScanned}/${scan.filesFound} file(s)`
      : `YARA: no rule matched — ${corpus.rulesApplied}/${corpus.rulesDeclared} rule(s) applied over ${scan.filesScanned}/${scan.filesFound} file(s), which is not "no implant"`,
    severity: 'info',
    proofState: 'static_confirmed',
    evidence: {
      corpusSources: corpus.sources,
      rulesDeclared: corpus.rulesDeclared,
      rulesApplied: corpus.rulesApplied,
      rulesPrivate: corpus.rulesPrivate,
      ruleFilesFound: corpus.filesFound,
      ruleFilesCompiled: corpus.filesCompiled,
      ruleFilesRejected: corpus.rejected,
      ruleFilesSkippedByFilter: corpus.filesSkippedByFilter,
      ruleFileFilter: corpus.fileFilter,
      filesFound: scan.filesFound,
      filesListed: scan.filesListed,
      filesScanned: scan.filesScanned,
      filesTooLarge: scan.filesTooLarge,
      filesOverCap: scan.filesOverCap,
      filesUnrepresentable: scan.filesUnrepresentable,
      filesFailed: scan.filesFailed.slice(0, MATCHED_FILE_LIST_CAP),
      filesFailedCount: scan.filesFailed.length,
      fileCap: scan.fileCap,
      maxFileBytes: scan.maxFileBytes,
      capRule: scan.skipReason || describeRankRule(scan.fileCap),
      rulesMatched: matches.length,
      unreadableLines,
    },
    rationale: `${describeCoverage(corpus, scan, matches.length)}${unreadableNote}`,
  });

  return drafts;
}

/** An empty corpus summary, for the states where no corpus was ever read. */
function emptyCorpus(sources: string[]): CorpusSummary {
  return {
    sources,
    missingSources: [],
    filesFound: 0,
    filesCompiled: 0,
    filesSkippedByFilter: 0,
    filesUnreadable: 0,
    rejected: [],
    rulesDeclared: 0,
    rulesPrivate: 0,
    rulesApplied: 0,
    fileFilter: RULE_FILE_FILTER,
  };
}

/** Titles for the states where the question was asked and could not be answered. Each names a DIFFERENT cause. */
const BLOCKED_TITLE: Record<Exclude<YaraScanState, 'scanned'>, string> = {
  tool_absent: 'Rule-based rootfs scan (YARA) could not run — yara is not installed',
  no_corpus: 'Rule-based rootfs scan (YARA) had no rules — no corpus is configured',
  corpus_empty: 'Rule-based rootfs scan (YARA) had no rules — the configured corpus holds none',
  no_rules_applied: 'Rule-based rootfs scan (YARA) applied no rules — none of the corpus could be compiled',
  no_target: 'Rule-based rootfs scan (YARA) had nothing to scan',
  scan_failed: 'Rule-based rootfs scan (YARA) failed',
};

/**
 * Pure: a result for a question that could not be answered.
 *
 * Every one of these carries `blocked_by_platform`, which in this codebase means *the question was asked and could
 * not be answered* — explicitly NOT a negative result. The five causes are kept as five distinct states because
 * they need five different responses: install a tool, configure a corpus, fix the corpus, rebuild yara with the
 * modules the rules import, or run an extraction first.
 */
export function blockedResult(
  state: Exclude<YaraScanState, 'scanned'>,
  reason: string,
  corpus?: CorpusSummary,
): YaraScanResult {
  const summary = corpus ?? emptyCorpus([]);
  return {
    available: false,
    state,
    reason,
    corpus: summary,
    scan: null,
    matches: [],
    findings: [
      {
        kind: 'yara-blocked',
        title: BLOCKED_TITLE[state],
        severity: 'info',
        proofState: 'blocked_by_platform',
        evidence: {
          state,
          reason,
          corpusSources: summary.sources,
          rulesDeclared: summary.rulesDeclared,
          rulesApplied: summary.rulesApplied,
          ...(summary.rejected.length ? { ruleFilesRejected: summary.rejected } : {}),
          ...(summary.missingSources.length ? { missingCorpusSources: summary.missingSources } : {}),
          ...(summary.filesSkippedByFilter ? { ruleFilesSkippedByFilter: summary.filesSkippedByFilter } : {}),
        },
        rationale: [
          `${reason}.`,
          'The rule-based implant sweep was requested and produced no answer, which is recorded here so the absence',
          'of implant findings is visible as a missing capability rather than mistaken for a clean rootfs. This is',
          'NOT "no implant was found": nothing looked. FirmLab ships no signatures of its own, so the corpus is',
          "always the operator's — point `FIRMLAB_YARA_RULES` at one (a directory or `.yar`/`.yara` files,",
          '`path.delimiter`-separated) and the scan will state what it covered and what it did not.',
        ].join(' '),
      },
    ],
  };
}

// ---------------------------------------------------------------------------------------------------------------
// The runner (shells out; everything it decides lives above)
// ---------------------------------------------------------------------------------------------------------------

/** Options a caller can use to bound the scan without touching the corpus. */
export interface YaraScanOptions {
  /** How many files to scan. Defaults to `FIRMLAB_YARA_FILE_CAP`; `0` means no cap. */
  fileCap?: number;
  maxFileBytes?: number;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
}

/** Walk a rootfs into scan candidates, classifying each by its first bytes and its place in the tree. */
function collectScanTargets(
  root: string,
  maxFileBytes: number,
): {
  targets: ScanTarget[];
  filesFound: number;
  filesTooLarge: number;
  dirsUnreadable: number;
  deepDirsSkipped: number;
} {
  const targets: ScanTarget[] = [];
  let filesFound = 0;
  let filesTooLarge = 0;
  let dirsUnreadable = 0;
  let deepDirsSkipped = 0;

  const walk = (dir: string, depth: number): void => {
    if (depth > MAX_WALK_DEPTH) {
      deepDirsSkipped++;
      return;
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      dirsUnreadable++;
      return;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      // `isDirectory()`/`isFile()` come from lstat semantics, so a symlink is neither — the walk never follows one,
      // which keeps a loop or an escape out of the rootfs impossible and matches what is handed to yara.
      if (e.isDirectory()) {
        walk(abs, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      filesFound++;
      let size = 0;
      try {
        size = fs.statSync(abs).size;
      } catch {
        continue;
      }
      if (size > maxFileBytes) {
        filesTooLarge++;
        continue;
      }
      const relPath = path.relative(root, abs);
      const head = Buffer.alloc(4);
      try {
        const fd = fs.openSync(abs, 'r');
        try {
          fs.readSync(fd, head, 0, 4, 0);
        } finally {
          fs.closeSync(fd);
        }
      } catch {
        // Unreadable head: it is still offered to yara, which will say so itself if it cannot read it either.
      }
      const content = classifyContent(head);
      targets.push({
        path: abs,
        relPath,
        size,
        content: content === 'other' && SCRIPT_EXT.test(e.name) ? 'script' : content,
        location: classifyLocation(relPath),
      });
    }
  };

  walk(root, 0);
  return { targets, filesFound, filesTooLarge, dirsUnreadable, deepDirsSkipped };
}

/** Run yara once over a scan list with the given rule files, namespaced so a match names the file it came from. */
async function invokeYara(
  ruleFiles: RuleFile[],
  listFile: string,
  timeoutMs: number,
): Promise<{ stdout: string; stderr: string; failed: boolean; message: string }> {
  const args = [
    '-e',
    '-g',
    '-a',
    String(DEFAULT_PER_FILE_TIMEOUT_S),
    '--scan-list',
    ...ruleFiles.map((f) => `${f.namespace}:${f.path}`),
    listFile,
  ];
  try {
    const r = await execFileAsync('yara', args, { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 });
    return { stdout: r.stdout, stderr: r.stderr, failed: false, message: '' };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; message?: string };
    return {
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
      failed: true,
      message: e.message ?? String(err),
    };
  }
}

/**
 * Compile each rule file on its own against a zero-byte probe, to learn WHICH files the combined compile choked on.
 *
 * This runs only after a combined compile has already failed, because it costs one process per rule file and a
 * corpus of a thousand files is a thousand spawns. The cheap path — everything compiles — pays nothing; the
 * expensive path is the one that has something to explain, which is the right way round.
 */
async function probeRuleFiles(files: RuleFile[], probeFile: string, handle: JobHandle): Promise<RejectedRuleFile[]> {
  const rejected: RejectedRuleFile[] = [];
  for (const f of files) {
    if (f.unreadable) {
      rejected.push({
        path: f.path,
        corpus: f.corpus,
        namespace: f.namespace,
        rulesLost: f.rules.length,
        reason: 'unreadable',
        message: 'the rule file could not be read',
      });
      continue;
    }
    try {
      await execFileAsync('yara', ['-e', '-g', `${f.namespace}:${f.path}`, probeFile], {
        timeout: 30_000,
        maxBuffer: 8 * 1024 * 1024,
      });
    } catch (err) {
      const stderr = (err as { stderr?: string }).stderr ?? '';
      const errors = parseCompileDiagnostics(stderr).filter((d) => d.level === 'error');
      const message = errors[0]?.message ?? (err as Error).message;
      rejected.push({
        path: f.path,
        corpus: f.corpus,
        namespace: f.namespace,
        rulesLost: f.rules.length,
        reason: classifyCompileFailure(message),
        message,
      });
    }
  }
  if (rejected.length) handle.log(`yara: ${rejected.length} rule file(s) would not compile and were dropped.`);
  return rejected;
}

/**
 * Scan an extracted rootfs with an operator-supplied YARA corpus.
 *
 * Degrades honestly at every step, and the steps are deliberately distinguishable: yara absent, no corpus
 * configured, a corpus that holds no rules, a corpus nothing in which compiles, nothing to scan, a scan that
 * failed, and a scan that ran. Only the last of these may ever be read as a statement about the firmware, and even
 * then only together with its two denominators.
 */
export async function runYaraScan(
  scanRoot: string,
  handle: JobHandle,
  opts: YaraScanOptions = {},
): Promise<YaraScanResult> {
  const env = opts.env ?? process.env;
  const sources = yaraCorpusSources(env);

  if (!(await isToolAvailable('yara'))) {
    handle.log('yara is not installed in this deployment — the rule-based rootfs scan cannot run.');
    return blockedResult('tool_absent', 'yara is not installed in this deployment', emptyCorpus(sources));
  }
  if (sources.length === 0) {
    handle.log('yara: no rule corpus configured (FIRMLAB_YARA_RULES) — nothing was scanned.');
    return blockedResult(
      'no_corpus',
      'no rule corpus is configured: FIRMLAB_YARA_RULES is unset, and FirmLab ships no built-in signatures',
      emptyCorpus(sources),
    );
  }

  const { files, missingSources, filesSkippedByFilter } = loadRuleCorpus(sources);
  const baseCorpus = summarizeCorpus({ files, sources, missingSources, filesSkippedByFilter });
  if (baseCorpus.rulesDeclared === 0) {
    const detail = missingSources.length
      ? `${missingSources.length} configured corpus path(s) do not exist (${missingSources.join(', ')})`
      : `${baseCorpus.filesFound} rule file(s) were read and none declares a rule; ${filesSkippedByFilter} file(s) were skipped by the ${RULE_FILE_FILTER} filter`;
    handle.log(`yara: the configured corpus declares no rules — ${detail}.`);
    return blockedResult('corpus_empty', `the configured corpus declares no rules: ${detail}`, baseCorpus);
  }

  if (!fs.existsSync(scanRoot)) {
    return blockedResult('no_target', `there is nothing to scan: ${scanRoot} does not exist`, baseCorpus);
  }

  const maxFileBytes = opts.maxFileBytes ?? yaraMaxFileBytes(env);
  const cap = opts.fileCap ?? yaraFileCap(env);
  const walked = collectScanTargets(scanRoot, maxFileBytes);
  if (walked.targets.length === 0) {
    return blockedResult(
      'no_target',
      `there is nothing to scan: ${walked.filesFound} regular file(s) under ${scanRoot}, of which ${walked.filesTooLarge} exceeded the per-file size ceiling`,
      baseCorpus,
    );
  }

  const { selected, skipped } = rankScanTargets({ targets: walked.targets, cap });
  // A path holding a newline cannot be written into a scan list; it is excluded here and counted, because a file
  // silently dropped by the harness would be indistinguishable from a file that was scanned and came back clean.
  const listable = selected.filter((t) => !/[\r\n]/.test(t.path));
  const unrepresentable = selected.length - listable.length;

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-yara-'));
  try {
    const listFile = path.join(tmp, 'scan-list.txt');
    fs.writeFileSync(listFile, `${listable.map((t) => t.path).join('\n')}\n`);
    const probeFile = path.join(tmp, 'probe.bin');
    fs.writeFileSync(probeFile, '');

    handle.log(
      `yara: ${baseCorpus.rulesApplied} rule(s) from ${baseCorpus.filesFound} file(s) against ${listable.length} of ${walked.filesFound} file(s) under ${scanRoot}.`,
    );

    let run = await invokeYara(files, listFile, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    let corpus = baseCorpus;
    let usedFiles = files;

    // A single bad rule file takes the whole combined compile down, and with it every rule in the corpus. When
    // that happens, find out which files are bad, drop exactly those, and report them — losing 4 rules is a hole,
    // losing 3000 because of those 4 is a different and much larger one.
    if (run.failed && parseCompileDiagnostics(run.stderr).some((d) => d.level === 'error')) {
      handle.log('yara: the corpus did not compile as a whole — probing each rule file to find which.');
      const rejected = await probeRuleFiles(files, probeFile, handle);
      const rejectedNs = new Set(rejected.map((r) => r.namespace));
      usedFiles = files.filter((f) => !rejectedNs.has(f.namespace));
      corpus = summarizeCorpus({ files, sources, missingSources, filesSkippedByFilter, rejected });
      if (usedFiles.length === 0 || corpus.rulesApplied === 0) {
        return blockedResult(
          'no_rules_applied',
          `none of the ${baseCorpus.filesFound} rule file(s) in the corpus could be compiled by this yara build, so no rule examined anything`,
          corpus,
        );
      }
      run = await invokeYara(usedFiles, listFile, opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
      if (run.failed && !run.stdout.trim() && parseCompileDiagnostics(run.stderr).some((d) => d.level === 'error')) {
        return blockedResult(
          'scan_failed',
          `yara failed after dropping the uncompilable rule files: ${run.message}`,
          corpus,
        );
      }
    } else if (run.failed && !run.stdout.trim() && parseScanErrors(run.stderr).length === 0) {
      return blockedResult('scan_failed', `yara failed: ${run.message}`, corpus);
    }

    const { groups, unreadableLines } = parseYaraOutput(run.stdout);
    const scanErrors = parseScanErrors(run.stderr);

    // Attribute every match back to the file the rule was declared in — that is the "from corpus Y" half of the
    // claim, and without it the finding names a rule the reader has no way to go and read.
    const byNamespace = new Map(usedFiles.map((f) => [f.namespace, f]));
    const matches: RuleMatchGroup[] = groups.map((g) => {
      const file = byNamespace.get(g.namespace);
      const declared = file?.rules.find((r) => r.name === g.rule);
      return {
        ...g,
        ...(file ? { corpus: file.corpus, ruleFile: file.relPath } : {}),
        tags: g.tags.length ? g.tags : (declared?.tags ?? []),
        meta: declared?.meta ?? {},
      };
    });

    const scan: ScanSummary = {
      root: scanRoot,
      filesFound: walked.filesFound,
      filesListed: listable.length,
      filesScanned: Math.max(0, listable.length - scanErrors.length),
      filesTooLarge: walked.filesTooLarge,
      filesOverCap: skipped.length,
      filesUnrepresentable: unrepresentable,
      filesFailed: scanErrors.map((e) => e.path),
      bytesListed: listable.reduce((n, t) => n + t.size, 0),
      maxFileBytes,
      fileCap: cap,
      skipReason: skipped.length ? describeRankRule(cap) : '',
      dirsUnreadable: walked.dirsUnreadable,
      deepDirsSkipped: walked.deepDirsSkipped,
    };

    const reason = describeCoverage(corpus, scan, matches.length);
    handle.log(reason);

    return {
      available: true,
      state: 'scanned',
      reason,
      corpus,
      scan,
      matches,
      findings: buildYaraFindings({ matches, corpus, scan, unreadableLines }),
    };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}
