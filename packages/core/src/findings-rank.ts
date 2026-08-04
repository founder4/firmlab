/**
 * The two axes of a finding, and the rule that they are two.
 *
 * `severity` says **how bad this would be if true**. `ProofState` says **how much of it was established**. The
 * workbench has always had a rigorous vocabulary for the second and has been reading the first as though it
 * settled both — which is the same conflation the proof-state discipline exists to prevent, committed on the
 * other axis. Measured on this corpus: of 72 `critical` rows, 48 carry `needs_runtime_reproduction`. Those are
 * *hypotheses graded on their consequences*, and they rendered exactly like the 24 rows whose property is
 * literally in the bytes.
 *
 * Three things follow, and all three live here so they cannot drift apart:
 *
 *  1. **Severity still leads the order.** A `critical` lead on a network daemon really is worth a reader's
 *     attention before an `info` row that was proven — ranking by proof first would bury the leads that are the
 *     whole reason a workbench runs. What was wrong was never the primacy of severity; it was the tie-break.
 *  2. **The tie-break is the ladder, not the alphabet.** `FindingsLedger` broke severity ties with
 *     `a.proofState < b.proofState`, a string comparison on an identifier — under which `blocked_by_platform`
 *     sorts above `confirmed_full_system` because `b` precedes `c`. That is ordering-shaped noise, and it put
 *     the least-established rows on top of the most-established ones at every severity level in the table.
 *  3. **Establishment is a property of the row a reader must be able to see.** `isEstablished` is the one
 *     predicate that separates "the workbench found this in the image" from "the workbench found a reason to
 *     look". It is deliberately NOT a fourth severity or a confidence score: it is a boolean about provenance,
 *     and `severityCensus` exists so a headline count can never be read as N problems when 2/3 of it is leads.
 *
 * `blocked_by_platform` / `blocked_by_security` rank below a lead and above a dismissal. They are questions that
 * could not be answered — never negatives — so they must not sort as though they had been, and must not sort as
 * though they had been confirmed either. `operator_assertion` sits with them: it is testimony, and the ladder's
 * rungs are reserved for what code decided.
 *
 * Pure, zero-dependency, and in core rather than beside a renderer because three separate copies of this ranking
 * already existed — `opacidad-narrative.ts` had the composite right, `FindingsLedger.tsx` had the alphabetical
 * tie-break, and `binvuln.ts` a third for its own rows. A rule stated in three places is a rule that disagrees
 * with itself; this is the one the ledger, the narrative and the report all read.
 */
import type { Finding, FindingProvenance, FindingSeverity } from './types.js';

/** How bad, if true. Higher sorts first. Unknown severities rank below `info` rather than above `critical`. */
export const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * How much was established. Higher sorts first.
 *
 * The gap between `needs_runtime_reproduction` (3) and the blocked pair (2) is the load-bearing one: a lead is a
 * precondition someone observed, a block is a question this deployment could not put. Neither is a negative, and
 * neither may outrank a rung that actually reproduced something.
 */
export const PROOF_RANK: Record<string, number> = {
  confirmed_full_system: 6,
  confirmed_in_emulation: 5,
  static_confirmed: 4,
  needs_runtime_reproduction: 3,
  blocked_by_platform: 2,
  blocked_by_security: 2,
  operator_assertion: 1,
  false_positive: 0,
};

/**
 * The proof states under which the row asserts a property of the image, rather than a reason to go looking.
 *
 * `static_confirmed` counts: the property is literally in the bytes, and that is established even though nothing
 * ran. `confirmed_in_emulation` and `confirmed_full_system` count for the stronger reason. Everything else —
 * leads, both blocks, a dismissal, an operator's testimony — does not, and the set is written as an explicit
 * allowlist so a proof state added later is treated as unestablished until someone decides otherwise. That is
 * the safe direction: a new rung shows up as "not yet established" rather than silently inheriting a claim.
 */
const ESTABLISHED: ReadonlySet<string> = new Set<FindingProvenance>([
  'static_confirmed',
  'confirmed_in_emulation',
  'confirmed_full_system',
]);

/** Whether this row states something about the image, as opposed to a reason to investigate it. */
export function isEstablished(proofState: string): boolean {
  return ESTABLISHED.has(proofState);
}

/** The composite used to pick the highest-priority handful: severity first, establishment as the tie-break. */
export function findingRank(f: Pick<Finding, 'severity' | 'proofState'>): number {
  return (SEVERITY_RANK[f.severity] ?? 0) * 10 + (PROOF_RANK[f.proofState] ?? 0);
}

/**
 * The single deterministic display order, shared by the ledger, the narrative and the report.
 *
 * Severity desc, then proof rank desc, then title, then id. The last two are what keep the order stable across
 * runs: ties broken by arrival order would make any cap's cut an artifact of which provider happened to finish
 * first, which is the "a bound is not an answer" rule.
 */
export function compareFindings(a: Finding, b: Finding): number {
  const ra = SEVERITY_RANK[a.severity] ?? 0;
  const rb = SEVERITY_RANK[b.severity] ?? 0;
  if (ra !== rb) return rb - ra;
  const pa = PROOF_RANK[a.proofState] ?? 0;
  const pb = PROOF_RANK[b.proofState] ?? 0;
  if (pa !== pb) return pb - pa;
  if (a.title !== b.title) return a.title < b.title ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/** One severity's split between what was established and what is still a reason to look. */
export interface SeverityCount {
  severity: FindingSeverity;
  total: number;
  established: number;
  unproven: number;
}

/**
 * The census that stops a headline number from being read as a count of problems.
 *
 * Returned highest-severity-first and only for severities actually present, so a caller can print
 * "72 critical — 24 established, 48 leads" without deciding any of it itself. `unproven` deliberately lumps
 * leads with blocks and assertions: from the reader's side they share the one property that matters here —
 * the workbench has not established them — and the row's own badge says which kind it is.
 */
export function severityCensus(findings: readonly Finding[]): SeverityCount[] {
  const by = new Map<string, SeverityCount>();
  for (const f of findings) {
    let e = by.get(f.severity);
    if (!e) {
      e = { severity: f.severity, total: 0, established: 0, unproven: 0 };
      by.set(f.severity, e);
    }
    e.total += 1;
    if (isEstablished(f.proofState)) e.established += 1;
    else e.unproven += 1;
  }
  return [...by.values()].sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0));
}
