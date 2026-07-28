/**
 * Operator assertions — the only findings in this workbench that code did not decide, and the rules that keep
 * that difference impossible to lose.
 *
 * Until now 100% of FirmLab's findings were computed. That is not modesty, it is the load-bearing invariant: a
 * `ProofState` is a claim code made after looking at something, and the coverage banner, the MCP honesty
 * instructions and the disclosure draft all read it as such. The moment a person — or worse, a language model —
 * can write `static_confirmed` onto a sentence they merely believe, every one of those readers is quietly lying
 * and none of them can tell.
 *
 * But the opposite is also a failure. A result an operator confirmed on the physical device, a vendor advisory,
 * an agent's conclusion over the MCP surface — none of it had anywhere to live, so a workbench built to record
 * what is known could not record what a person knows. `asserted_from_device` in particular is knowledge FirmLab
 * *structurally cannot produce*: `confirmed_full_system` deliberately stops at emulation and never claims the
 * device, which leaves the most valuable observation in firmware work with no home in the ledger.
 *
 * So the feature is not the endpoint. It is the separation that makes the endpoint safe, and it is enforced in
 * four independent places rather than by convention:
 *
 *   1. **A disjoint vocabulary.** An operator picks an `OperatorClaim`, never a `ProofState`. Not one token is
 *      shared between the two sets, so no prefix match, substring or careless `includes()` can slide an assertion
 *      onto the ladder. `rejectProofStateAsClaim` turns the attempt into a named error instead of a coercion.
 *   2. **A self-describing sentinel.** The row's `proofState` field holds `operator_assertion`. A reader that
 *      predates this feature renders that literal string — an unfamiliar label, never a measurement. Degradation
 *      points the safe way.
 *   3. **A source prefix that deletion cannot reach.** `operator:<who>` is refused by `syncFindings` and excluded
 *      from `deleteFindingsBySource` at the SQL, so re-running any provider — now or in five years, including one
 *      nobody has written yet — cannot erase a human's record.
 *   4. **An author, always.** `assertedBy` is required and `authorKind` is decided by the transport, not the
 *      caller. An agent cannot sign as a human, which is what makes the read-back caveat in `mcp/format.ts`
 *      truthful rather than decorative.
 *
 * What an operator finding refuses to claim: it is **not a measurement**. It is not stage coverage — three
 * hand-written rows must never make an unexamined image read as examined, which is why `buildCoverage` takes the
 * two counts separately. It is not promotable: nothing here can raise a row onto the ladder, and the store
 * refuses the promotion even if a caller tries. And it is never deleted — `withdraw` retracts it in place, with a
 * reason, because a ledger that can only forget cannot record "this was wrong, and here is why".
 *
 * Pure: plain data in, plain data out, no store import, so all of the above is unit-testable.
 */
import type { FindingSeverity, OperatorAssertion, OperatorAuthorKind, OperatorClaim, ProofState } from '@firmlab/core';
import { OPERATOR_ASSERTION } from '@firmlab/core';
import type { FindingDraft } from './findings-normalize.js';

/** Sources reserved for hand-authored rows. Structurally immune to provider re-runs — see `syncFindings`. */
export const OPERATOR_SOURCE_PREFIX = 'operator:';

/** True when a source names hand-authored rows, which no provider may sync, delete or re-state. */
export function isOperatorSource(source: string): boolean {
  return source.startsWith(OPERATOR_SOURCE_PREFIX);
}

const CLAIMS = [
  'asserted_unverified',
  'asserted_from_device',
  'asserted_from_external_evidence',
  'disputes_finding',
] as const satisfies readonly OperatorClaim[];

/** The code-decided ladder, listed here only so an attempt to assert one can be refused by name. */
const PROOF_STATES: readonly string[] = [
  'needs_runtime_reproduction',
  'static_confirmed',
  'confirmed_in_emulation',
  'confirmed_full_system',
  'blocked_by_platform',
  'blocked_by_security',
  'false_positive',
];

/**
 * What each claim licenses a reader to conclude. Shipped inside every row's evidence and every MCP payload, so
 * the caveat travels with the data rather than living in a UI the next consumer may not be looking at.
 */
export const CLAIM_MEANING: Record<OperatorClaim, string> = {
  asserted_unverified:
    'A person states this is true. Nothing on this bench was measured to support it — treat it as testimony, and verify it before acting on it.',
  asserted_from_device:
    'A person reports observing this on the PHYSICAL device. FirmLab cannot measure that at all (its strongest rung, confirmed_full_system, is emulation), so this is the author’s observation and rests entirely on their credibility and method.',
  asserted_from_external_evidence:
    'A person cites evidence outside this workbench (vendor advisory, datasheet, third-party report). FirmLab did not verify the source or that it applies to this image.',
  disputes_finding:
    'A person states that a code-decided finding is wrong. This does NOT change that finding’s proof state — both rows stand, and a reader decides.',
};

const SEVERITIES: readonly FindingSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** Bounds — an assertion is a sentence a human wrote, not a payload channel. */
const MAX_AUTHOR = 80;
const MAX_TITLE = 200;
const MAX_RATIONALE = 4000;
const MAX_REFERENCES = 10;
const MAX_REFERENCE = 300;

/** The raw request body, before anything is trusted about it. */
export interface OperatorAssertionInput {
  assertedBy?: unknown;
  title?: unknown;
  claim?: unknown;
  rationale?: unknown;
  severity?: unknown;
  references?: unknown;
  disputesFindingId?: unknown;
  /** Never accepted. Present in the type so supplying one is a named refusal rather than a silent ignore. */
  proofState?: unknown;
}

/** A validated assertion: every field checked, nothing inferred. */
export interface ValidatedAssertion {
  assertedBy: string;
  title: string;
  claim: OperatorClaim;
  rationale: string;
  severity: FindingSeverity;
  references: string[];
  disputesFindingId?: string;
}

export type ValidationResult = { ok: true; value: ValidatedAssertion } | { ok: false; error: string };

function str(v: unknown): string {
  return typeof v === 'string' ? v.trim() : '';
}

/**
 * The refusal that matters most. Someone typing `static_confirmed` into the claim field is not making a typo —
 * they are reaching for the ladder — so the error explains why the ladder is not theirs to write on rather than
 * listing valid values and letting them guess again.
 */
function rejectProofStateAsClaim(claim: string): string | null {
  if (claim === OPERATOR_ASSERTION) {
    return `'${OPERATOR_ASSERTION}' is the provenance FirmLab stamps on your row automatically; it is not a claim you choose. Pick one of: ${CLAIMS.join(', ')}.`;
  }
  if (!PROOF_STATES.includes(claim)) return null;
  return `'${claim}' is a PROOF STATE, and only code may decide one — it records what an analysis measured. An operator finding records what a person asserts, which is a different kind of evidence and uses a different vocabulary: ${CLAIMS.join(', ')}.`;
}

/**
 * Pure: validate a request body into an assertion, or say exactly what is wrong with it.
 *
 * `rationale` is required, not optional. A claim with no stated basis is a rumour with a timestamp, and it is
 * precisely the row a later reader cannot evaluate — the backlog entry this feature was motivated by was withdrawn
 * because it had been written from a filename without opening the file, which the rationale would have shown.
 */
export function validateAssertion(input: OperatorAssertionInput): ValidationResult {
  if (input.proofState !== undefined) {
    return {
      ok: false,
      error:
        'This request carried a proofState. Operator findings never do: a proof state is code’s record of what it measured, and stamping one onto an assertion is the exact confusion this endpoint exists to prevent. Send a `claim` instead.',
    };
  }

  const assertedBy = str(input.assertedBy);
  if (!assertedBy)
    return { ok: false, error: 'assertedBy is required — an assertion without a named author is not an assertion.' };
  if (assertedBy.length > MAX_AUTHOR)
    return { ok: false, error: `assertedBy is longer than ${MAX_AUTHOR} characters.` };
  if (!slugify(assertedBy)) {
    return { ok: false, error: 'assertedBy must contain at least one letter or digit.' };
  }

  const title = str(input.title);
  if (!title) return { ok: false, error: 'title is required — state the claim in one line.' };
  if (title.length > MAX_TITLE) return { ok: false, error: `title is longer than ${MAX_TITLE} characters.` };

  const rawClaim = str(input.claim);
  if (!rawClaim) return { ok: false, error: `claim is required. One of: ${CLAIMS.join(', ')}.` };
  const ladderError = rejectProofStateAsClaim(rawClaim);
  if (ladderError) return { ok: false, error: ladderError };
  if (!(CLAIMS as readonly string[]).includes(rawClaim)) {
    return { ok: false, error: `Unknown claim '${rawClaim}'. One of: ${CLAIMS.join(', ')}.` };
  }
  const claim = rawClaim as OperatorClaim;

  const rationale = str(input.rationale);
  if (!rationale) {
    return {
      ok: false,
      error:
        'rationale is required — say on what basis you assert this. A claim with no stated basis cannot be evaluated by anyone who did not write it, and this ledger is read by people who did not.',
    };
  }
  if (rationale.length > MAX_RATIONALE) {
    return { ok: false, error: `rationale is longer than ${MAX_RATIONALE} characters.` };
  }

  // Unstated severity defaults to `info`, not to a middle rung: an unmeasured claim should not silently outrank a
  // measured `low` just because nobody filled the field in.
  const rawSeverity = str(input.severity);
  if (rawSeverity && !(SEVERITIES as readonly string[]).includes(rawSeverity)) {
    return { ok: false, error: `Unknown severity '${rawSeverity}'. One of: ${SEVERITIES.join(', ')}.` };
  }
  const severity = (rawSeverity || 'info') as FindingSeverity;

  const disputesFindingId = str(input.disputesFindingId);
  if (claim === 'disputes_finding' && !disputesFindingId) {
    return { ok: false, error: "claim 'disputes_finding' requires disputesFindingId — name the finding you dispute." };
  }
  if (claim !== 'disputes_finding' && disputesFindingId) {
    return {
      ok: false,
      error: "disputesFindingId only applies to claim 'disputes_finding'.",
    };
  }

  const refsRaw = Array.isArray(input.references) ? input.references : [];
  if (refsRaw.length > MAX_REFERENCES) {
    return { ok: false, error: `At most ${MAX_REFERENCES} references.` };
  }
  const references: string[] = [];
  for (const r of refsRaw) {
    const s = str(r);
    if (!s) continue;
    if (s.length > MAX_REFERENCE)
      return { ok: false, error: `A reference is longer than ${MAX_REFERENCE} characters.` };
    references.push(s);
  }

  return {
    ok: true,
    value: {
      assertedBy,
      title,
      claim,
      rationale,
      severity,
      references,
      ...(disputesFindingId ? { disputesFindingId } : {}),
    },
  };
}

/** Pure: the ledger source for one author. Stable per author, so their rows group without ever colliding. */
export function operatorSourceFor(assertedBy: string): string {
  return `${OPERATOR_SOURCE_PREFIX}${slugify(assertedBy) || 'unnamed'}`;
}

/**
 * Diacritics are folded, not dropped. A naive `[^a-z0-9]` slug turns "Aarón" into `aar-n`, so the same person
 * writing their name with and without the accent lands in two different `operator:` namespaces — and the author
 * whose rows are split by a keyboard layout is exactly the one this ledger is for.
 */
function slugify(who: string): string {
  return (
    who
      .normalize('NFD')
      // Written as escapes: combining marks are invisible in a source file, and this codebase has already paid for
      // an unprintable byte nobody could see (see CLAUDE.md on the literal NUL).
      .replace(/\p{M}/gu, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 40)
  );
}

/**
 * Pure: turn a validated assertion into the finding draft the store will stamp.
 *
 * The claim's meaning is copied into `evidence`. That is deliberate duplication: a consumer dumping the findings
 * table to JSON, or an old client that knows nothing about assertions, still reads the caveat in the same object
 * as the claim. A caveat that only exists in the renderer is a caveat that will eventually be rendered away.
 */
export function assertionToDraft(
  v: ValidatedAssertion,
  authorKind: OperatorAuthorKind,
  now: number,
): FindingDraft & { assertion: OperatorAssertion } {
  const assertion: OperatorAssertion = {
    assertedBy: v.assertedBy,
    authorKind,
    assertedAt: now,
    claim: v.claim,
    rationale: v.rationale,
    status: 'active',
    ...(v.disputesFindingId ? { disputesFindingId: v.disputesFindingId } : {}),
  };
  return {
    kind: v.claim,
    title: v.title,
    severity: v.severity,
    proofState: OPERATOR_ASSERTION,
    rationale: v.rationale,
    evidence: {
      assertedBy: v.assertedBy,
      authorKind,
      claim: v.claim,
      claimMeaning: CLAIM_MEANING[v.claim],
      notAMeasurement: NOT_A_MEASUREMENT,
      ...(v.references.length ? { references: v.references } : {}),
      ...(v.disputesFindingId ? { disputesFindingId: v.disputesFindingId } : {}),
    },
    assertion,
  };
}

/**
 * The single sentence every surface repeats verbatim. One constant rather than four paraphrases, because four
 * paraphrases drift and the weakest one becomes the one a reader happens to see.
 */
export const NOT_A_MEASUREMENT =
  'This row was asserted by a named author, not measured by FirmLab. It carries no proof state, it counts towards no analysis stage, and it is not evidence that the property holds.';

/** Pure: apply an amendment to an active assertion, keeping the original author and timestamp. */
export function amendAssertion(existing: OperatorAssertion, v: ValidatedAssertion, now: number): OperatorAssertion {
  return {
    ...existing,
    claim: v.claim,
    rationale: v.rationale,
    amendedAt: now,
    ...(v.disputesFindingId ? { disputesFindingId: v.disputesFindingId } : {}),
  };
}

/**
 * Pure: retract an assertion in place.
 *
 * Withdrawal is first-class and destructive nowhere: the row, its original author, its original rationale and the
 * reason for the retraction all survive. `who` is recorded separately from `assertedBy` because "the author
 * retracted it" and "someone else overrode it" are different events and a reader needs to tell them apart.
 */
export function withdrawAssertion(
  existing: OperatorAssertion,
  who: string,
  reason: string,
  now: number,
): { ok: true; value: OperatorAssertion } | { ok: false; error: string } {
  const by = str(who);
  const why = str(reason);
  if (!by) return { ok: false, error: 'withdrawnBy is required — name who is retracting the claim.' };
  if (!why) {
    return {
      ok: false,
      error:
        'A withdrawal needs a reason. "This was wrong, and here is why" is the most useful row a ledger can hold; a bare retraction throws away exactly the part worth keeping.',
    };
  }
  if (existing.status === 'withdrawn') return { ok: false, error: 'This assertion is already withdrawn.' };
  return {
    ok: true,
    value: { ...existing, status: 'withdrawn', withdrawnBy: by, withdrawnAt: now, withdrawnReason: why },
  };
}

/** The shape every partitioning caller needs — deliberately structural, so web/API/MCP types all satisfy it. */
export interface ProvenancedFinding {
  proofState: string;
  assertion?: OperatorAssertion | undefined;
}

/**
 * Pure: split a ledger into the three populations that must never be summed together.
 *
 * `measured` is what the coverage arithmetic and the proof-state histogram may count. `asserted` is testimony.
 * `withdrawn` is retracted testimony, which is kept and shown but counted nowhere — a withdrawn row that still
 * incremented a total would make retraction cosmetic.
 *
 * A row is classified by the sentinel in `proofState`, not by its source, so a hand-edited source string cannot
 * launder an assertion into the measured population.
 */
export function partitionByProvenance<T extends ProvenancedFinding>(
  findings: readonly T[],
): { measured: T[]; asserted: T[]; withdrawn: T[] } {
  const measured: T[] = [];
  const asserted: T[] = [];
  const withdrawn: T[] = [];
  for (const f of findings) {
    if (f.proofState !== OPERATOR_ASSERTION) {
      measured.push(f);
      continue;
    }
    if (f.assertion?.status === 'withdrawn') withdrawn.push(f);
    else asserted.push(f);
  }
  return { measured, asserted, withdrawn };
}

/** Pure: the one-line attribution shown wherever an operator row appears next to measured ones. */
export function describeAssertion(a: OperatorAssertion): string {
  const when = new Date(a.assertedAt).toISOString().slice(0, 10);
  const who = a.authorKind === 'agent' ? `${a.assertedBy} (agent)` : a.assertedBy;
  if (a.status === 'withdrawn') {
    const byWhom = a.withdrawnBy ?? 'unknown';
    return `WITHDRAWN by ${byWhom}: ${a.withdrawnReason ?? 'no reason recorded'} — originally asserted by ${who} on ${when}.`;
  }
  return `Asserted by ${who} on ${when} (${a.claim}). ${CLAIM_MEANING[a.claim]}`;
}
