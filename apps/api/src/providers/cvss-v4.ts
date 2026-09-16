/**
 * CVSS v4.0 scoring — pure, and the only place in this codebase that turns a v4.0 vector string into a number.
 *
 * v3.1 computes a score from an equation; v4.0 does not. A v4.0 vector is first reduced to a six-digit
 * **MacroVector** (one digit per equivalence class), that key selects a score from a 270-entry table the
 * specification publishes as data, and the vector's distance from the most severe member of its own class is then
 * subtracted proportionally. None of that is derivable from first principles, so the table, the per-class
 * "highest severity" vectors and the per-class depths below are transcribed from FIRST's own calculator
 * (`cvss_lookup.js`, `max_composed.js`, `max_severity.js`, BSD-2-Clause) rather than reconstructed — a
 * reconstructed table would be a fabrication in exactly the sense `component-cve.ts` refuses. Those three data
 * tables are "Copyright FIRST, Red Hat, and contributors", SPDX-License-Identifier BSD-2-Clause, and the notice
 * travels with them.
 *
 * The arithmetic is deliberately written in the specification's own operation order. The interpolation divides
 * sums of 0.1 steps, so a re-association that is algebraically identical is not identical in floating point, and
 * the number this returns has to be the number the reference calculator prints for the same string.
 *
 * What it refuses to claim: nothing about THIS firmware. A score is what a vector string states, not evidence
 * that the code is present, reachable or exploitable here — that remains the proof state's job. It also refuses
 * to guess: an unparseable vector, an unknown metric value or a missing base metric returns `null` (ungraded),
 * never a default, because a fabricated 0 would rank an unreadable advisory as harmless.
 *
 * Note on nomenclature: the specification has one scoring procedure, not four. A base-only vector yields CVSS-B;
 * a vector that also carries Threat (`E`) or Environmental (`CR`/`MAV`/…) metrics yields CVSS-BT / CVSS-BE /
 * CVSS-BTE from the same procedure. This returns whatever the vector in hand asks for; Supplemental metrics
 * (`S`, `AU`, `R`, `V`, `RE`, `U`) are accepted and, per the specification, affect no score.
 */

/** Base metrics. All eleven are mandatory: a vector missing one is not a v4.0 vector and is refused. */
const BASE_METRICS = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'] as const;

/** The metrics whose all-`N` combination is the specification's shortcut to a flat 0.0. */
const IMPACT_METRICS = ['VC', 'VI', 'VA', 'SC', 'SI', 'SA'] as const;

/**
 * Every metric a v4.0 vector may carry, and the values the specification allows it. A value outside this table
 * is refused rather than ignored: `VC:X` is not "unspecified confidentiality", it is a malformed vector, and
 * silently dropping it would score a string nobody wrote.
 */
const METRIC_VALUES: Record<string, readonly string[]> = {
  // Base
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  AT: ['N', 'P'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'P', 'A'],
  VC: ['H', 'L', 'N'],
  VI: ['H', 'L', 'N'],
  VA: ['H', 'L', 'N'],
  SC: ['H', 'L', 'N'],
  SI: ['H', 'L', 'N'],
  SA: ['H', 'L', 'N'],
  // Threat
  E: ['X', 'A', 'P', 'U'],
  // Environmental — security requirements
  CR: ['X', 'H', 'M', 'L'],
  IR: ['X', 'H', 'M', 'L'],
  AR: ['X', 'H', 'M', 'L'],
  // Environmental — modified base. Only MSI/MSA take `S` (Safety); MSC does not.
  MAV: ['X', 'N', 'A', 'L', 'P'],
  MAC: ['X', 'L', 'H'],
  MAT: ['X', 'N', 'P'],
  MPR: ['X', 'N', 'L', 'H'],
  MUI: ['X', 'N', 'P', 'A'],
  MVC: ['X', 'H', 'L', 'N'],
  MVI: ['X', 'H', 'L', 'N'],
  MVA: ['X', 'H', 'L', 'N'],
  MSC: ['X', 'H', 'L', 'N'],
  MSI: ['X', 'S', 'H', 'L', 'N'],
  MSA: ['X', 'S', 'H', 'L', 'N'],
  // Supplemental — parsed and validated, scored by nothing.
  S: ['X', 'N', 'P'],
  AU: ['X', 'N', 'Y'],
  R: ['X', 'A', 'U', 'I'],
  V: ['X', 'D', 'C'],
  RE: ['X', 'L', 'M', 'H'],
  U: ['X', 'Clear', 'Green', 'Amber', 'Red'],
};

type Selection = ReadonlyMap<string, string>;

/**
 * Pure: a validated metric map, or null when the string is not a scoreable v4.0 vector.
 *
 * Metric ORDER is not enforced, deliberately. The specification prescribes one, but the score does not depend on
 * it and no metric here is positional, so refusing a readable vector over field order would drop a grade for a
 * formatting nit — the same reasoning that keeps an ungraded advisory in `parseOsvAnswer` rather than cutting it.
 * What *is* enforced is membership: a repeated metric, an unknown metric, an unknown value or a missing base
 * metric all mean the string cannot be read as written, and an unreadable string is refused.
 */
function parseCvssV4Vector(vector: string): Selection | null {
  if (!vector.startsWith('CVSS:4.0/')) return null;
  const sel = new Map<string, string>();
  for (const part of vector.split('/').slice(1)) {
    const colon = part.indexOf(':');
    if (colon <= 0) return null;
    const metric = part.slice(0, colon);
    const value = part.slice(colon + 1);
    if (sel.has(metric)) return null;
    if (!METRIC_VALUES[metric]?.includes(value)) return null;
    sel.set(metric, value);
  }
  if (!BASE_METRICS.every((m) => sel.has(m))) return null;
  for (const metric of Object.keys(METRIC_VALUES)) if (!sel.has(metric)) sel.set(metric, 'X');
  return sel;
}

/**
 * The effective value of one metric — the specification's `m()`. Three rules, and all three are "worst case":
 * an undefined Threat metric scores as `E:A` and an undefined security requirement as `H`, because a vector that
 * declines to say is not a vector claiming the best case; and a Modified metric, where given, overrides the base
 * one it shadows.
 */
function effective(sel: Selection, metric: string): string {
  const selected = sel.get(metric) ?? 'X';
  if (selected === 'X') {
    if (metric === 'E') return 'A';
    if (metric === 'CR' || metric === 'IR' || metric === 'AR') return 'H';
  }
  const modified = sel.get(`M${metric}`);
  return modified !== undefined && modified !== 'X' ? modified : selected;
}

/** The six equivalence-class digits. Their concatenation keys `LOOKUP`. */
type Macro = readonly [number, number, number, number, number, number];

/** Pure: the MacroVector of a selection, verbatim from the specification's EQ1–EQ6 definitions. */
function macroVector(sel: Selection): Macro {
  const v = (m: string): string => effective(sel, m);

  // EQ1: 0 — AV:N and PR:N and UI:N · 1 — one of them but not all three, and not AV:P · 2 — AV:P, or none of them
  const av = v('AV');
  const eq1 =
    av === 'N' && v('PR') === 'N' && v('UI') === 'N' ? 0 : av === 'P' ? 2 : anyOf(v, 'AV', 'PR', 'UI', 'N') ? 1 : 2;

  // EQ2: 0 — AC:L and AT:N · 1 — anything else
  const eq2 = v('AC') === 'L' && v('AT') === 'N' ? 0 : 1;

  // EQ3: 0 — VC:H and VI:H · 1 — not both, but one of VC/VI/VA is H · 2 — none of them is H
  const eq3 = v('VC') === 'H' && v('VI') === 'H' ? 0 : anyOf(v, 'VC', 'VI', 'VA', 'H') ? 1 : 2;

  // EQ4: 0 — MSI:S or MSA:S (Safety) · 1 — otherwise, one of SC/SI/SA is H · 2 — otherwise
  const safety = sel.get('MSI') === 'S' || sel.get('MSA') === 'S';
  const eq4 = safety ? 0 : anyOf(v, 'SC', 'SI', 'SA', 'H') ? 1 : 2;

  // EQ5: 0 — E:A (also the default for E:X) · 1 — E:P · 2 — E:U
  const e = v('E');
  const eq5 = e === 'A' ? 0 : e === 'P' ? 1 : 2;

  // EQ6: 0 — a HIGH requirement meets a HIGH impact on the same axis · 1 — otherwise
  const eq6 =
    (v('CR') === 'H' && v('VC') === 'H') || (v('IR') === 'H' && v('VI') === 'H') || (v('AR') === 'H' && v('VA') === 'H')
      ? 0
      : 1;

  return [eq1, eq2, eq3, eq4, eq5, eq6];
}

function anyOf(v: (m: string) => string, a: string, b: string, c: string, value: string): boolean {
  return v(a) === value || v(b) === value || v(c) === value;
}

/**
 * Pure: the six-digit MacroVector of a v4.0 vector string, or null when the string is not one. Exported for
 * diagnosis and for the coverage test — a score alone cannot show which of the 270 classes produced it.
 */
export function cvssV4MacroVector(vector: string): string | null {
  const sel = parseCvssV4Vector(vector);
  return sel ? macroVector(sel).join('') : null;
}

/**
 * Pure: the CVSS v4.0 score a vector string states, or null for anything that is not a readable v4.0 vector —
 * a v3.x vector (see `cvssV3BaseScore` in `osv.ts`), a v2 one, a bare number, a malformed string.
 */
export function cvssV4Score(vector: string): number | null {
  const sel = parseCvssV4Vector(vector);
  if (!sel) return null;

  // A vulnerability with no impact on any system is 0.0 by definition, and the table has no entry that says so:
  // the MacroVector of such a vector is shared with graded ones, so this shortcut is load-bearing, not an
  // optimisation.
  if (IMPACT_METRICS.every((m) => effective(sel, m) === 'N')) return 0;

  const [eq1, eq2, eq3, eq4, eq5, eq6] = macroVector(sel);
  const key = (a: number, b: number, c: number, d: number, e: number, f: number): string => `${a}${b}${c}${d}${e}${f}`;
  const value = LOOKUP[key(eq1, eq2, eq3, eq4, eq5, eq6)];
  if (value === undefined) return null;

  // The score of the next LOWER MacroVector along each axis. Where there is none, that axis contributes nothing
  // and is not counted in the mean — "no lower class" is not a distance of zero, it is an absent measurement.
  const lower1 = LOOKUP[key(eq1 + 1, eq2, eq3, eq4, eq5, eq6)];
  const lower2 = LOOKUP[key(eq1, eq2 + 1, eq3, eq4, eq5, eq6)];
  const lower4 = LOOKUP[key(eq1, eq2, eq3, eq4 + 1, eq5, eq6)];
  const lower5 = LOOKUP[key(eq1, eq2, eq3, eq4, eq5 + 1, eq6)];
  // EQ3 and EQ6 are one axis in two digits, so the step down depends on both. From 00 there are two ways down
  // (01 and 10) and the specification takes the higher-scoring one.
  let lower36: number | undefined;
  if (eq3 === 0 && eq6 === 0) {
    const left = LOOKUP[key(eq1, eq2, eq3, eq4, eq5, eq6 + 1)];
    const right = LOOKUP[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6)];
    lower36 = left !== undefined && right !== undefined ? Math.max(left, right) : (left ?? right);
  } else if (eq3 === 1 && eq6 === 0) {
    lower36 = LOOKUP[key(eq1, eq2, eq3, eq4, eq5, eq6 + 1)]; // 10 → 11
  } else if (eq3 < 2) {
    lower36 = LOOKUP[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6)]; // 01 → 11, 11 → 21
  } else {
    lower36 = LOOKUP[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)]; // 21 → 32, which does not exist
  }

  const maxes1 = MAX_COMPOSED.eq1[eq1];
  const maxes2 = MAX_COMPOSED.eq2[eq2];
  const maxes36 = MAX_COMPOSED.eq3[eq3]?.[eq6];
  const max4 = MAX_COMPOSED.eq4[eq4]?.[0];
  const depth1 = MAX_SEVERITY.eq1[eq1];
  const depth2 = MAX_SEVERITY.eq2[eq2];
  const depth36 = MAX_SEVERITY.eq3eq6[eq3]?.[eq6];
  const depth4 = MAX_SEVERITY.eq4[eq4];
  // Unreachable for a vector that parsed: every MacroVector a valid selection can produce has a maximum and a
  // depth. Refusing rather than asserting keeps a future table edit from scoring off a hole.
  if (!maxes1 || !maxes2 || !maxes36 || !max4) return null;
  if (depth1 === undefined || depth2 === undefined || depth36 === undefined || depth4 === undefined) return null;

  // The first combination of per-class maxima that is at least as severe as this vector on every metric. EQ4 and
  // EQ5 have a single maximum each and EQ5 contributes no distance at all, so only EQ1 × EQ2 × EQ3EQ6 vary —
  // the same candidates, in the same order, as the specification's five nested loops.
  //
  // `distance` is reassigned every iteration on purpose. A class always contains a member that dominates its own
  // vectors, so the loop breaks on a reachable one; keeping the last unreachable candidate otherwise is what the
  // reference implementation does, and diverging there would make this function disagree with it on an input
  // neither of us believes exists.
  let distance: Distance | null = null;
  outer: for (const max1 of maxes1) {
    for (const max2 of maxes2) {
      for (const max36 of maxes36) {
        distance = severityDistance(sel, max1, max2, max36, max4);
        if (distance.reachable) break outer;
      }
    }
  }
  if (!distance) return null;

  // Each axis contributes the drop to its lower class, scaled by how far this vector sits from its own class's
  // most severe member. The mean of the axes that HAVE a lower class is subtracted from the class score.
  const step = 0.1;
  let sum = 0;
  let axes = 0;
  if (lower1 !== undefined) {
    axes += 1;
    sum += (value - lower1) * (distance.eq1 / (depth1 * step));
  }
  if (lower2 !== undefined) {
    axes += 1;
    sum += (value - lower2) * (distance.eq2 / (depth2 * step));
  }
  if (lower36 !== undefined) {
    axes += 1;
    sum += (value - lower36) * (distance.eq3eq6 / (depth36 * step));
  }
  if (lower4 !== undefined) {
    axes += 1;
    sum += (value - lower4) * (distance.eq4 / (depth4 * step));
  }
  // EQ5 has no severity distance of its own — every member of an exploit-maturity class is equally far along it —
  // so it adds nothing to the sum while still counting as an axis that could have moved.
  if (lower5 !== undefined) axes += 1;

  const scored = value - (axes === 0 ? 0 : sum / axes);
  return Math.round(Math.min(Math.max(scored, 0), 10) * 10) / 10;
}

interface Distance {
  /** Whether this combination of maxima is at least as severe as the vector on every metric. */
  reachable: boolean;
  eq1: number;
  eq2: number;
  eq3eq6: number;
  eq4: number;
}

/** Levels are ranks, not weights: the distance between two values is their index difference in 0.1 steps. */
const AV_LEVELS: Record<string, number> = { N: 0.0, A: 0.1, L: 0.2, P: 0.3 };
const PR_LEVELS: Record<string, number> = { N: 0.0, L: 0.1, H: 0.2 };
const UI_LEVELS: Record<string, number> = { N: 0.0, P: 0.1, A: 0.2 };
const AC_LEVELS: Record<string, number> = { L: 0.0, H: 0.1 };
const AT_LEVELS: Record<string, number> = { N: 0.0, P: 0.1 };
const VULN_LEVELS: Record<string, number> = { H: 0.0, L: 0.1, N: 0.2 };
const SC_LEVELS: Record<string, number> = { H: 0.1, L: 0.2, N: 0.3 };
/** SI and SA alone can be Safety, which outranks High. */
const SUB_LEVELS: Record<string, number> = { S: 0.0, H: 0.1, L: 0.2, N: 0.3 };
const REQ_LEVELS: Record<string, number> = { H: 0.0, M: 0.1, L: 0.2 };

/** How far this vector sits below one combination of per-class maxima, summed per equivalence class. */
function severityDistance(sel: Selection, max1: Fragment, max2: Fragment, max36: Fragment, max4: Fragment): Distance {
  const d = (levels: Record<string, number>, metric: string, max: Fragment): number =>
    (levels[effective(sel, metric)] ?? Number.NaN) - (levels[max.get(metric) ?? ''] ?? Number.NaN);
  const av = d(AV_LEVELS, 'AV', max1);
  const pr = d(PR_LEVELS, 'PR', max1);
  const ui = d(UI_LEVELS, 'UI', max1);
  const ac = d(AC_LEVELS, 'AC', max2);
  const at = d(AT_LEVELS, 'AT', max2);
  const vc = d(VULN_LEVELS, 'VC', max36);
  const vi = d(VULN_LEVELS, 'VI', max36);
  const va = d(VULN_LEVELS, 'VA', max36);
  const cr = d(REQ_LEVELS, 'CR', max36);
  const ir = d(REQ_LEVELS, 'IR', max36);
  const ar = d(REQ_LEVELS, 'AR', max36);
  const sc = d(SC_LEVELS, 'SC', max4);
  const si = d(SUB_LEVELS, 'SI', max4);
  const sa = d(SUB_LEVELS, 'SA', max4);
  return {
    reachable: ![av, pr, ui, ac, at, vc, vi, va, sc, si, sa, cr, ir, ar].some((x) => x < 0),
    // Summed in the specification's own order: these are sums of 0.1 steps, and re-associating them changes the
    // last decimal place of the result.
    eq1: av + pr + ui,
    eq2: ac + at,
    eq3eq6: vc + vi + va + cr + ir + ar,
    eq4: sc + si + sa,
  };
}

type Fragment = ReadonlyMap<string, string>;

/** `AV:N/PR:N/UI:N/` → a map. The maxima below are written as the specification writes them, and parsed once. */
function fragment(spec: string): Fragment {
  const out = new Map<string, string>();
  for (const part of spec.split('/')) {
    const colon = part.indexOf(':');
    if (colon > 0) out.set(part.slice(0, colon), part.slice(colon + 1));
  }
  return out;
}

const frags = (...specs: string[]): Fragment[] => specs.map(fragment);

/**
 * The most severe vector(s) in each equivalence class — `max_composed.js`, verbatim. A class can have several,
 * because "most severe" is a partial order: `AV:A/PR:N/UI:N` and `AV:N/PR:L/UI:N` are both EQ1=1 maxima and
 * neither dominates the other, so the scorer tries them in turn.
 */
const MAX_COMPOSED: {
  eq1: Fragment[][];
  eq2: Fragment[][];
  eq3: (Fragment[] | undefined)[][];
  eq4: Fragment[][];
} = {
  eq1: [
    frags('AV:N/PR:N/UI:N/'),
    frags('AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'),
    frags('AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/'),
  ],
  eq2: [frags('AC:L/AT:N/'), frags('AC:H/AT:N/', 'AC:L/AT:P/')],
  // Indexed [eq3][eq6]. EQ3=2 (no HIGH impact) can only ever pair with EQ6=1.
  eq3: [
    [
      frags('VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'),
      frags('VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/'),
    ],
    [
      frags('VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'),
      frags(
        'VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/',
        'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/',
        'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/',
        'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/',
        'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/',
      ),
    ],
    [undefined, frags('VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/')],
  ],
  eq4: [frags('SC:H/SI:S/SA:S/'), frags('SC:H/SI:H/SA:H/'), frags('SC:L/SI:L/SA:L/')],
};

/**
 * The depth of each equivalence class in 0.1 steps — `max_severity.js`, verbatim. It is the denominator that
 * turns a severity distance into a proportion, so it is not derivable from the maxima above.
 */
const MAX_SEVERITY: { eq1: number[]; eq2: number[]; eq3eq6: (number | undefined)[][]; eq4: number[] } = {
  eq1: [1, 4, 5],
  eq2: [1, 2],
  eq3eq6: [
    [7, 6],
    [8, 8],
    [undefined, 10],
  ],
  eq4: [6, 5, 4],
};

/**
 * The MacroVector → score table — `cvss_lookup.js`, verbatim, all 270 entries, keys in ascending order so it can
 * be diffed against FIRST's file. This is the specification's data, not a model of it: there is no equation that
 * reproduces these numbers.
 */
const LOOKUP: Record<string, number> = {
  '000000': 10,
  '000001': 9.9,
  '000010': 9.8,
  '000011': 9.5,
  '000020': 9.5,
  '000021': 9.2,
  '000100': 10,
  '000101': 9.6,
  '000110': 9.3,
  '000111': 8.7,
  '000120': 9.1,
  '000121': 8.1,
  '000200': 9.3,
  '000201': 9,
  '000210': 8.9,
  '000211': 8,
  '000220': 8.1,
  '000221': 6.8,
  '001000': 9.8,
  '001001': 9.5,
  '001010': 9.5,
  '001011': 9.2,
  '001020': 9,
  '001021': 8.4,
  '001100': 9.3,
  '001101': 9.2,
  '001110': 8.9,
  '001111': 8.1,
  '001120': 8.1,
  '001121': 6.5,
  '001200': 8.8,
  '001201': 8,
  '001210': 7.8,
  '001211': 7,
  '001220': 6.9,
  '001221': 4.8,
  '002001': 9.2,
  '002011': 8.2,
  '002021': 7.2,
  '002101': 7.9,
  '002111': 6.9,
  '002121': 5,
  '002201': 6.9,
  '002211': 5.5,
  '002221': 2.7,
  '010000': 9.9,
  '010001': 9.7,
  '010010': 9.5,
  '010011': 9.2,
  '010020': 9.2,
  '010021': 8.5,
  '010100': 9.5,
  '010101': 9.1,
  '010110': 9,
  '010111': 8.3,
  '010120': 8.4,
  '010121': 7.1,
  '010200': 9.2,
  '010201': 8.1,
  '010210': 8.2,
  '010211': 7.1,
  '010220': 7.2,
  '010221': 5.3,
  '011000': 9.5,
  '011001': 9.3,
  '011010': 9.2,
  '011011': 8.5,
  '011020': 8.5,
  '011021': 7.3,
  '011100': 9.2,
  '011101': 8.2,
  '011110': 8,
  '011111': 7.2,
  '011120': 7,
  '011121': 5.9,
  '011200': 8.4,
  '011201': 7,
  '011210': 7.1,
  '011211': 5.2,
  '011220': 5,
  '011221': 3,
  '012001': 8.6,
  '012011': 7.5,
  '012021': 5.2,
  '012101': 7.1,
  '012111': 5.2,
  '012121': 2.9,
  '012201': 6.3,
  '012211': 2.9,
  '012221': 1.7,
  '100000': 9.8,
  '100001': 9.5,
  '100010': 9.4,
  '100011': 8.7,
  '100020': 9.1,
  '100021': 8.1,
  '100100': 9.4,
  '100101': 8.9,
  '100110': 8.6,
  '100111': 7.4,
  '100120': 7.7,
  '100121': 6.4,
  '100200': 8.7,
  '100201': 7.5,
  '100210': 7.4,
  '100211': 6.3,
  '100220': 6.3,
  '100221': 4.9,
  '101000': 9.4,
  '101001': 8.9,
  '101010': 8.8,
  '101011': 7.7,
  '101020': 7.6,
  '101021': 6.7,
  '101100': 8.6,
  '101101': 7.6,
  '101110': 7.4,
  '101111': 5.8,
  '101120': 5.9,
  '101121': 5,
  '101200': 7.2,
  '101201': 5.7,
  '101210': 5.7,
  '101211': 5.2,
  '101220': 5.2,
  '101221': 2.5,
  '102001': 8.3,
  '102011': 7,
  '102021': 5.4,
  '102101': 6.5,
  '102111': 5.8,
  '102121': 2.6,
  '102201': 5.3,
  '102211': 2.1,
  '102221': 1.3,
  '110000': 9.5,
  '110001': 9,
  '110010': 8.8,
  '110011': 7.6,
  '110020': 7.6,
  '110021': 7,
  '110100': 9,
  '110101': 7.7,
  '110110': 7.5,
  '110111': 6.2,
  '110120': 6.1,
  '110121': 5.3,
  '110200': 7.7,
  '110201': 6.6,
  '110210': 6.8,
  '110211': 5.9,
  '110220': 5.2,
  '110221': 3,
  '111000': 8.9,
  '111001': 7.8,
  '111010': 7.6,
  '111011': 6.7,
  '111020': 6.2,
  '111021': 5.8,
  '111100': 7.4,
  '111101': 5.9,
  '111110': 5.7,
  '111111': 5.7,
  '111120': 4.7,
  '111121': 2.3,
  '111200': 6.1,
  '111201': 5.2,
  '111210': 5.7,
  '111211': 2.9,
  '111220': 2.4,
  '111221': 1.6,
  '112001': 7.1,
  '112011': 5.9,
  '112021': 3,
  '112101': 5.8,
  '112111': 2.6,
  '112121': 1.5,
  '112201': 2.3,
  '112211': 1.3,
  '112221': 0.6,
  '200000': 9.3,
  '200001': 8.7,
  '200010': 8.6,
  '200011': 7.2,
  '200020': 7.5,
  '200021': 5.8,
  '200100': 8.6,
  '200101': 7.4,
  '200110': 7.4,
  '200111': 6.1,
  '200120': 5.6,
  '200121': 3.4,
  '200200': 7,
  '200201': 5.4,
  '200210': 5.2,
  '200211': 4,
  '200220': 4,
  '200221': 2.2,
  '201000': 8.5,
  '201001': 7.5,
  '201010': 7.4,
  '201011': 5.5,
  '201020': 6.2,
  '201021': 5.1,
  '201100': 7.2,
  '201101': 5.7,
  '201110': 5.5,
  '201111': 4.1,
  '201120': 4.6,
  '201121': 1.9,
  '201200': 5.3,
  '201201': 3.6,
  '201210': 3.4,
  '201211': 1.9,
  '201220': 1.9,
  '201221': 0.8,
  '202001': 6.4,
  '202011': 5.1,
  '202021': 2,
  '202101': 4.7,
  '202111': 2.1,
  '202121': 1.1,
  '202201': 2.4,
  '202211': 0.9,
  '202221': 0.4,
  '210000': 8.8,
  '210001': 7.5,
  '210010': 7.3,
  '210011': 5.3,
  '210020': 6,
  '210021': 5,
  '210100': 7.3,
  '210101': 5.5,
  '210110': 5.9,
  '210111': 4,
  '210120': 4.1,
  '210121': 2,
  '210200': 5.4,
  '210201': 4.3,
  '210210': 4.5,
  '210211': 2.2,
  '210220': 2,
  '210221': 1.1,
  '211000': 7.5,
  '211001': 5.5,
  '211010': 5.8,
  '211011': 4.5,
  '211020': 4,
  '211021': 2.1,
  '211100': 6.1,
  '211101': 5.1,
  '211110': 4.8,
  '211111': 1.8,
  '211120': 2,
  '211121': 0.9,
  '211200': 4.6,
  '211201': 1.8,
  '211210': 1.7,
  '211211': 0.7,
  '211220': 0.8,
  '211221': 0.2,
  '212001': 5.3,
  '212011': 2.4,
  '212021': 1.4,
  '212101': 2.4,
  '212111': 1.2,
  '212121': 0.5,
  '212201': 1,
  '212211': 0.3,
  '212221': 0.1,
};
