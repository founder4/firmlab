/**
 * Bounded, byte-only detection of Ethernet switch-family LEADS — the input `docs/EMULATION-FUTURE.md` §2.2 says
 * Phase 1 (the virtual DSA switch) depends on and that does not exist yet. It reads literals out of bytes. It does
 * not emulate a switch, does not choose a tagging format, and says nothing about whether any network works.
 *
 * **What a hit is, and what it is not.** A chip literal in an image is a STATIC LEAD: the string is present in the
 * bytes, nothing more. A vendor kernel routinely compiles in drivers for every board it ships on, so a literal can
 * belong to a driver that is never probed on this board — a dormant driver — and it never describes the hardware on
 * any physical device. The strongest verdict here, `single-family-lead`, means "one family's exact literal is in
 * these bytes and no other family's is", not "this device has that switch".
 *
 * **Every mapping is backed by the repository, not by recall.** The only repository source naming these families is
 * the design document, and it names them unevenly, so the rules do too:
 *
 *  - `QCA8337` is written as an exact part. It is the one EXACT literal accepted, and only as a whole token.
 *  - `RTL83xx` and `BCM53xx` are written only as family TEMPLATES. A token fitting a template (`RTL83` or `BCM53`
 *    plus exactly two digits) is reported, but at `family-template` standing: the repository has never verified
 *    which part numbers in that template are switch chips, so a template hit can never by itself produce
 *    `single-family-lead`. Promoting a specific member to an exact literal needs a primary source first.
 *  - Device-tree `compatible` strings and driver/module names are DEFERRED for all three families: no repository
 *    source maps any of them. They are listed in `DEFERRED_SWITCH_MAPPINGS` rather than guessed.
 *
 * **A vendor name is never family proof.** `Realtek`, `Broadcom`, `Qualcomm` and `Atheros` each make far more than
 * switches. They are counted in `vendorMentions` so a reader can see them, and they never create a candidate.
 *
 * **An empty result must say why, and a bound is not an answer.** `none-observed` is not "no switch": a compressed
 * kernel or filesystem hides every literal from a raw byte scan, and a board may name its switch in no string at
 * all. The scan stops at `maxScanBytes` and says so; hit RECORDS are capped per rule (lowest offsets first, the stated
 * rule) while hit COUNTS stay exact, and the cap is per rule so a flood of one literal cannot crowd another family
 * out of the result. Vendor offsets are capped the same way and reported in the same `recordsDropped` list.
 *
 * **A rejected near-miss is counted, never matched.** The token boundary deliberately refuses letter-suffixed or
 * longer part numbers (`RTL8367RB`, `BCM53125`, `QCA8337N`), because no repository source names them. Those are
 * also the markings most often printed on real switches, so a `none-observed` that stayed silent about them would
 * read as "the literal was absent". They are counted in `nearMisses` (with a few bounded examples) and named in the
 * summary; they never create a candidate and never change a verdict.
 *
 * **Zero bytes scanned is not a negative.** An input with no bytes yields `not-scanned`, never `none-observed`: a
 * verdict about what was in the bytes needs bytes. Matching is single-byte ASCII; a UTF-16 literal is not matched,
 * and the coverage statement says so. Pure: no I/O, no dependencies.
 */

/** The three switch families `docs/EMULATION-FUTURE.md` §1.2/§2.2 names as Phase 1's targets. */
export type SwitchFamily = 'rtl83xx' | 'bcm53xx' | 'qca8337';

/**
 * How strongly a rule's literal is backed. `exact-literal`: the repository names the part exactly.
 * `family-template`: the repository names only a family pattern, so a fitting token is a weaker lead.
 */
export type SwitchEvidenceTier = 'exact-literal' | 'family-template';

/** Where in the repository a rule's mapping comes from — a file, and text that appears in it verbatim. */
export interface SwitchRuleBacking {
  file: string;
  quote: string;
}

export interface SwitchEvidenceRule {
  id: string;
  family: SwitchFamily;
  tier: SwitchEvidenceTier;
  /** Lowercase ASCII prefix, matched case-insensitively. */
  prefix: string;
  /** Exactly this many ASCII digits must follow the prefix (0 for an exact literal). */
  digits: number;
  backing: SwitchRuleBacking;
  rationale: string;
}

const DESIGN_DOC = 'docs/EMULATION-FUTURE.md';

/** The rule table. Matching is token-exact: the byte before and after must not be an ASCII letter or digit. */
export const SWITCH_EVIDENCE_RULES: readonly SwitchEvidenceRule[] = [
  {
    id: 'qca8337-literal',
    family: 'qca8337',
    tier: 'exact-literal',
    prefix: 'qca8337',
    digits: 0,
    backing: { file: DESIGN_DOC, quote: 'Qualcomm/Atheros QCA8337' },
    rationale:
      'The design document names QCA8337 as an exact part, so the whole token is accepted as an exact literal. ' +
      'Suffixed markings and sibling parts are not in any repository source and are not matched.',
  },
  {
    id: 'rtl83xx-template',
    family: 'rtl83xx',
    tier: 'family-template',
    prefix: 'rtl83',
    digits: 2,
    backing: { file: DESIGN_DOC, quote: 'Realtek RTL83xx' },
    rationale:
      'The design document names this family only as the template RTL83xx. Which RTL83 part numbers are switch ' +
      'chips has not been verified against a primary source here, so a fitting token is a template-level lead.',
  },
  {
    id: 'bcm53xx-template',
    family: 'bcm53xx',
    tier: 'family-template',
    prefix: 'bcm53',
    digits: 2,
    backing: { file: DESIGN_DOC, quote: 'Broadcom BCM53xx' },
    rationale:
      'The design document names this family only as the template BCM53xx. Which BCM53 part numbers are switch ' +
      'chips has not been verified against a primary source here, so a fitting token is a template-level lead.',
  },
];

/** Vendor names, counted for visibility and never used as family evidence. */
export const SWITCH_VENDOR_NAMES: readonly { vendor: string; prefix: string }[] = [
  { vendor: 'Realtek', prefix: 'realtek' },
  { vendor: 'Broadcom', prefix: 'broadcom' },
  { vendor: 'Qualcomm', prefix: 'qualcomm' },
  { vendor: 'Atheros', prefix: 'atheros' },
];

/** Mappings this module refuses to make until a repository source backs them. Stated rather than invented. */
export const DEFERRED_SWITCH_MAPPINGS: readonly { what: string; reason: string }[] = [
  {
    what: 'device-tree compatible strings (all three families)',
    reason: 'No repository source names a compatible string for RTL83xx, BCM53xx or QCA8337.',
  },
  {
    what: 'driver and kernel-module names (all three families)',
    reason: 'No repository source maps a Linux driver or module name to any of the three families.',
  },
  {
    what: 'exact RTL83xx and BCM53xx part numbers',
    reason:
      'The repository names these families only as templates; until a member is verified, a template hit stays a ' +
      'template-level lead and cannot produce single-family-lead.',
  },
  {
    what: 'part numbers with letter suffixes, or more digits than a template allows',
    reason: 'Not in any repository source; such tokens fail the token boundary and are not matched.',
  },
  {
    what: 'the tagging format each family uses on the wire',
    reason: 'A static literal cannot determine how a live switch tags frames; Phase 1 must establish that itself.',
  },
];

export interface SwitchEvidenceHit {
  ruleId: string;
  family: SwitchFamily;
  tier: SwitchEvidenceTier;
  offset: number;
  length: number;
  /** The bytes as they appear in the image (original case). */
  matchedText: string;
  /** The printable-ASCII run around the match, at most `CONTEXT_RADIUS` bytes either side. */
  context: string;
  contextOffset: number;
}

export interface SwitchFamilyCandidate {
  family: SwitchFamily;
  /** The strongest tier any of this family's hits reached. */
  standing: SwitchEvidenceTier;
  /** Exact number of matches in the scanned window, including any whose records were dropped by the cap. */
  hitCount: number;
  /** Distinct tokens seen (uppercased), over every match rather than only the retained records. */
  distinctTokens: string[];
  /** Retained records: per rule, the lowest offsets up to `maxHitsPerRule`. */
  evidence: SwitchEvidenceHit[];
}

export interface SwitchVendorMention {
  vendor: string;
  count: number;
  /** Lowest offsets, up to `maxHitsPerRule`. */
  offsets: number[];
}

export type SwitchFamilyVerdict =
  | 'single-family-lead'
  | 'template-only'
  | 'ambiguous'
  | 'vendor-only'
  | 'none-observed'
  /** No byte was scanned, so nothing can be said about the bytes. Never a negative. */
  | 'not-scanned';

/** A family-shaped token the boundary rule rejected: prefix and digits, then more letters or digits. */
export interface SwitchNearMissExample {
  ruleId: string;
  /** The whole alphanumeric token as it appears in the bytes, at most `NEAR_MISS_TOKEN_MAX` characters. */
  token: string;
  /** Offset of this token's first occurrence. */
  offset: number;
}

export interface SwitchNearMisses {
  /** Exact number of rejected family-shaped tokens in the scanned window. */
  count: number;
  /** First occurrence of each distinct (uppercased) token, lowest offsets first, at most `NEAR_MISS_EXAMPLES`. */
  examples: SwitchNearMissExample[];
}

export interface SwitchFamilyCoverage {
  /** Every rule and vendor name the scan tried, so "not found" can be read against what was looked for. */
  rulesAttempted: string[];
  bytesTotal: number;
  bytesScanned: number;
  /** True only when the whole input was scanned AND the caller did not declare it a prefix of something larger. */
  completed: boolean;
  stoppedBy: 'end-of-input' | 'scan-cap' | 'input-truncated';
  maxScanBytes: number;
  maxHitsPerRule: number;
  /**
   * Matches whose records were dropped by the per-rule cap. Their counts are still in `hitCount`. Vendor offsets
   * dropped by the same cap appear as `vendor:<Name>`; their counts are still in `SwitchVendorMention.count`.
   */
  recordsDropped: { ruleId: string; dropped: number }[];
  /** Offsets where a possible match was cut off by the end of a truncated input: neither confirmed nor ruled out. */
  edgeUnresolved: number;
  statement: string;
}

export interface SwitchFamilyResult {
  verdict: SwitchFamilyVerdict;
  /** Families with evidence, in a fixed family order — never in order of first appearance. */
  candidates: SwitchFamilyCandidate[];
  vendorMentions: SwitchVendorMention[];
  /** Family-shaped tokens the boundary rule rejected. Never candidates. Absent on results stored by older builds. */
  nearMisses?: SwitchNearMisses;
  deferred: readonly { what: string; reason: string }[];
  coverage: SwitchFamilyCoverage;
  /** One sentence a UI or a report can print as is: what the verdict means and what it never means. */
  summary: string;
}

export interface SwitchFamilyOptions {
  /** Scan only the first this-many bytes. Default 64 MiB. */
  maxScanBytes?: number;
  /** Keep at most this many hit records per rule (and offsets per vendor). Default 16. */
  maxHitsPerRule?: number;
  /** The caller read only a prefix of a larger input, so the buffer's end is not the data's end. */
  inputTruncated?: boolean;
}

export const DEFAULT_SWITCH_SCAN_BYTES = 64 * 1024 * 1024;
export const DEFAULT_SWITCH_HITS_PER_RULE = 16;
const CONTEXT_RADIUS = 40;
/** Distinct near-miss tokens kept as examples; the count stays exact. */
export const NEAR_MISS_EXAMPLES = 8;
/** A near-miss token is read to at most this many characters. */
export const NEAR_MISS_TOKEN_MAX = 32;
const FAMILY_ORDER: readonly SwitchFamily[] = ['rtl83xx', 'bcm53xx', 'qca8337'];

const LITERAL_CAVEAT =
  'A literal is a static lead: it can belong to a dormant driver compiled in for other boards, and it never ' +
  'describes the hardware on a live device. Nothing here emulates a switch or shows that any network works.';

const NOT_ABSENCE =
  'That is not evidence of no switch: compressed data hides literals, a board may name its switch in no string, ' +
  'and unscanned bytes were never read.';

const VENDOR_ONLY =
  'Only vendor names are present. A vendor name is never switch-family evidence: these vendors make far more than ' +
  'switches.';

function isAlnum(b: number): boolean {
  return (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
}

function lower(b: number): number {
  return b >= 0x41 && b <= 0x5a ? b + 0x20 : b;
}

function isDigit(b: number): boolean {
  return b >= 0x30 && b <= 0x39;
}

function ascii(bytes: Uint8Array, start: number, end: number): string {
  let s = '';
  for (let i = start; i < end; i++) s += String.fromCharCode(bytes[i] as number);
  return s;
}

type MatchOutcome = { kind: 'none' } | { kind: 'edge' } | { kind: 'match'; length: number };

/**
 * Pure: does a token with this prefix (plus `digits` digits) start at `i`, bounded by non-alphanumeric bytes?
 * `edge` means the input ended before that could be decided and the caller said the input continues beyond it.
 */
export function matchTokenAt(
  bytes: Uint8Array,
  i: number,
  prefix: string,
  digits: number,
  inputTruncated: boolean,
): MatchOutcome {
  if (i > 0 && isAlnum(bytes[i - 1] as number)) return { kind: 'none' };
  const len = prefix.length + digits;
  for (let k = 0; k < len; k++) {
    const b = bytes[i + k];
    if (b === undefined) return inputTruncated ? { kind: 'edge' } : { kind: 'none' };
    if (k < prefix.length ? lower(b) !== prefix.charCodeAt(k) : !isDigit(b)) return { kind: 'none' };
  }
  const after = bytes[i + len];
  if (after === undefined) return inputTruncated ? { kind: 'edge' } : { kind: 'match', length: len };
  return isAlnum(after) ? { kind: 'none' } : { kind: 'match', length: len };
}

/**
 * Pure: is a rule's token rejected at `i` ONLY by its closing boundary — the prefix and the exact digit count are
 * there, starting at a token boundary, and a letter or digit follows? Returns the whole token, or null.
 */
export function nearMissAt(bytes: Uint8Array, i: number, prefix: string, digits: number): string | null {
  if (i > 0 && isAlnum(bytes[i - 1] as number)) return null;
  const len = prefix.length + digits;
  for (let k = 0; k < len; k++) {
    const b = bytes[i + k];
    if (b === undefined) return null;
    if (k < prefix.length ? lower(b) !== prefix.charCodeAt(k) : !isDigit(b)) return null;
  }
  const after = bytes[i + len];
  if (after === undefined || !isAlnum(after)) return null;
  let end = i + len + 1;
  while (end < bytes.length && end - i < NEAR_MISS_TOKEN_MAX && isAlnum(bytes[end] as number)) end++;
  return ascii(bytes, i, end);
}

function contextAround(bytes: Uint8Array, offset: number, length: number): { context: string; contextOffset: number } {
  const printable = (b: number | undefined) => b !== undefined && b >= 0x20 && b <= 0x7e;
  let start = offset;
  while (start > 0 && offset - start < CONTEXT_RADIUS && printable(bytes[start - 1])) start--;
  let end = offset + length;
  while (end < bytes.length && end - (offset + length) < CONTEXT_RADIUS && printable(bytes[end])) end++;
  return { context: ascii(bytes, start, end), contextOffset: start };
}

function positiveInt(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < 1) throw new RangeError(`${name} must be a positive integer, got ${value}`);
  return value;
}

/** Pure: scan `bytes` for switch-family leads under the stated bounds. */
export function detectSwitchFamily(bytes: Uint8Array, options: SwitchFamilyOptions = {}): SwitchFamilyResult {
  const maxScanBytes = positiveInt(options.maxScanBytes, DEFAULT_SWITCH_SCAN_BYTES, 'maxScanBytes');
  const maxHitsPerRule = positiveInt(options.maxHitsPerRule, DEFAULT_SWITCH_HITS_PER_RULE, 'maxHitsPerRule');
  const inputTruncated = options.inputTruncated === true;
  const scanEnd = Math.min(bytes.length, maxScanBytes);

  type RuleState = { rule: SwitchEvidenceRule; count: number; tokens: Set<string>; hits: SwitchEvidenceHit[] };
  const rules: RuleState[] = SWITCH_EVIDENCE_RULES.map((rule) => ({ rule, count: 0, tokens: new Set(), hits: [] }));
  const vendors = SWITCH_VENDOR_NAMES.map((v) => ({ ...v, count: 0, offsets: [] as number[] }));
  const firstBytes = new Set<number>();
  for (const p of [...SWITCH_EVIDENCE_RULES.map((r) => r.prefix), ...SWITCH_VENDOR_NAMES.map((v) => v.prefix)]) {
    firstBytes.add(p.charCodeAt(0));
  }
  let edgeUnresolved = 0;
  let nearMissCount = 0;
  const nearMissExamples = new Map<string, SwitchNearMissExample>();

  // Matches must START inside the window; a token's tail and its closing boundary may be read past the cap.
  for (let i = 0; i < scanEnd; i++) {
    if (!firstBytes.has(lower(bytes[i] as number))) continue;
    let edgeHere = false;
    for (const st of rules) {
      const m = matchTokenAt(bytes, i, st.rule.prefix, st.rule.digits, inputTruncated);
      if (m.kind === 'edge') edgeHere = true;
      if (m.kind === 'none') {
        const token = nearMissAt(bytes, i, st.rule.prefix, st.rule.digits);
        if (token !== null) {
          nearMissCount++;
          const key = token.toUpperCase();
          if (!nearMissExamples.has(key) && nearMissExamples.size < NEAR_MISS_EXAMPLES) {
            nearMissExamples.set(key, { ruleId: st.rule.id, token, offset: i });
          }
        }
      }
      if (m.kind !== 'match') continue;
      st.count++;
      const matchedText = ascii(bytes, i, i + m.length);
      st.tokens.add(matchedText.toUpperCase());
      if (st.hits.length < maxHitsPerRule) {
        st.hits.push({
          ruleId: st.rule.id,
          family: st.rule.family,
          tier: st.rule.tier,
          offset: i,
          length: m.length,
          matchedText,
          ...contextAround(bytes, i, m.length),
        });
      }
    }
    for (const v of vendors) {
      const m = matchTokenAt(bytes, i, v.prefix, 0, inputTruncated);
      if (m.kind === 'edge') edgeHere = true;
      if (m.kind !== 'match') continue;
      v.count++;
      if (v.offsets.length < maxHitsPerRule) v.offsets.push(i);
    }
    if (edgeHere) edgeUnresolved++;
  }

  const candidates: SwitchFamilyCandidate[] = [];
  for (const family of FAMILY_ORDER) {
    const own = rules.filter((st) => st.rule.family === family && st.count > 0);
    if (own.length === 0) continue;
    candidates.push({
      family,
      standing: own.some((st) => st.rule.tier === 'exact-literal') ? 'exact-literal' : 'family-template',
      hitCount: own.reduce((n, st) => n + st.count, 0),
      distinctTokens: [...new Set(own.flatMap((st) => [...st.tokens]))].sort(),
      evidence: own.flatMap((st) => st.hits).sort((a, b) => a.offset - b.offset),
    });
  }
  const vendorMentions = vendors
    .filter((v) => v.count > 0)
    .map((v) => ({ vendor: v.vendor, count: v.count, offsets: v.offsets }));

  let verdict: SwitchFamilyVerdict;
  if (candidates.length >= 2) verdict = 'ambiguous';
  else if (candidates.length === 1)
    verdict = candidates[0]?.standing === 'exact-literal' ? 'single-family-lead' : 'template-only';
  else if (vendorMentions.length > 0) verdict = 'vendor-only';
  else if (scanEnd === 0) verdict = 'not-scanned';
  else verdict = 'none-observed';
  const nearMisses: SwitchNearMisses = { count: nearMissCount, examples: [...nearMissExamples.values()] };

  const stoppedBy: SwitchFamilyCoverage['stoppedBy'] =
    scanEnd < bytes.length ? 'scan-cap' : inputTruncated ? 'input-truncated' : 'end-of-input';
  const completed = stoppedBy === 'end-of-input';
  const recordsDropped = [
    ...rules
      .filter((st) => st.count > st.hits.length)
      .map((st) => ({ ruleId: st.rule.id, dropped: st.count - st.hits.length })),
    ...vendors
      .filter((v) => v.count > v.offsets.length)
      .map((v) => ({ ruleId: `vendor:${v.vendor}`, dropped: v.count - v.offsets.length })),
  ];

  const coverageParts = [`Scanned ${scanEnd} of ${bytes.length} supplied byte(s) for ${rules.length} switch rule(s).`];
  if (stoppedBy === 'scan-cap') {
    coverageParts.push(
      `The scan stopped at the ${maxScanBytes}-byte cap; ${bytes.length - scanEnd} byte(s) were never read.`,
    );
  } else if (stoppedBy === 'input-truncated') {
    coverageParts.push('The caller declared the input a prefix of something larger; the rest was never read.');
  }
  if (edgeUnresolved > 0) {
    coverageParts.push(`${edgeUnresolved} possible match(es) were cut off by the end of the input and are undecided.`);
  }
  if (recordsDropped.length > 0) {
    coverageParts.push(
      `Hit records and vendor offsets were capped at ${maxHitsPerRule} per rule (lowest offsets kept); counts ` +
        `include the dropped records (${recordsDropped.map((d) => `${d.ruleId}: ${d.dropped}`).join(', ')}).`,
    );
  }
  if (nearMisses.count > 0) {
    coverageParts.push(
      nearMissSentence(
        nearMisses.count,
        nearMisses.examples.map((e) => e.token),
      ),
    );
  }
  coverageParts.push(
    'Compressed or encrypted regions are not decoded, so any literal inside them is invisible to this scan.',
    'Matching is single-byte ASCII: a literal stored as UTF-16 or another wide encoding is not matched.',
  );

  const coverage: SwitchFamilyCoverage = {
    rulesAttempted: [...rules.map((st) => st.rule.id), ...vendors.map((v) => `vendor:${v.vendor}`)],
    bytesTotal: bytes.length,
    bytesScanned: scanEnd,
    completed,
    stoppedBy,
    maxScanBytes,
    maxHitsPerRule,
    recordsDropped,
    edgeUnresolved,
    statement: coverageParts.join(' '),
  };

  return {
    verdict,
    candidates,
    vendorMentions,
    nearMisses,
    deferred: DEFERRED_SWITCH_MAPPINGS,
    coverage,
    summary: summarize(verdict, candidates, nearMisses),
  };
}

/** Pure: the sentence naming rejected family-shaped tokens. Shared with the API aggregate so both say it alike. */
export function nearMissSentence(count: number, tokens: readonly string[]): string {
  const shown = tokens.length > 0 ? ` (e.g. ${tokens.join(', ')})` : '';
  return [
    `${count} family-shaped token(s)${shown} were seen and deliberately not matched by the boundary rule:`,
    'letter-suffixed or longer part numbers are not in any repository source, so they are never candidates.',
  ].join(' ');
}

function summarize(
  verdict: SwitchFamilyVerdict,
  candidates: readonly SwitchFamilyCandidate[],
  nearMisses: SwitchNearMisses,
): string {
  const rejected =
    nearMisses.count > 0
      ? ` ${nearMissSentence(
          nearMisses.count,
          nearMisses.examples.map((e) => e.token),
        )}`
      : '';
  const named = candidates.map((c) => `${c.family} (${c.standing}: ${c.distinctTokens.join(', ')})`).join('; ');
  switch (verdict) {
    case 'single-family-lead':
      return `Only one family's exact literal is present: ${named}. ${LITERAL_CAVEAT}`;
    case 'template-only':
      return (
        `Only a family-template token is present: ${named}. The repository has not verified that part number as a ` +
        `switch chip, so this does not single out a family. ${LITERAL_CAVEAT}`
      );
    case 'ambiguous':
      return (
        `Literals from ${candidates.length} families are present: ${named}. The bytes do not say which, if any, ` +
        `the board uses; this is reported as ambiguous rather than resolved by count or order. ${LITERAL_CAVEAT}`
      );
    case 'vendor-only':
      return `${VENDOR_ONLY}${rejected} ${LITERAL_CAVEAT}`;
    case 'none-observed':
      return `No switch-family literal or vendor name was matched in the scanned bytes.${rejected} ${NOT_ABSENCE}`;
    case 'not-scanned':
      return 'The input held no bytes, so nothing was scanned. This is not a negative: no byte was examined.';
  }
}
