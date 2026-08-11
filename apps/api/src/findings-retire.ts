/**
 * Retiring one provider source's findings — the ledger's only deletion path, and why it is safe for exactly one
 * population and no other.
 *
 * `syncFindings` already deletes: re-running a provider replaces its own rows. That delete is safe because the
 * fresh answer lands in the same call, so the ledger never holds a gap. What has no path at all is the other
 * half — a source that stops being GENERATED. `syncFindings` only ever runs for a source something plans, so rows
 * belonging to a question the app has since decided not to ask sit in the ledger forever, and every future
 * filtering fix leaves its own residue behind it.
 *
 * **The instance that forced this.** Measured 2026-08-11: four `symreach:lib/lib*.so` rows across three images,
 * written the day before by a probe queue that let uClibc's shared objects through (`isRunnableElf` read
 * `PT_INTERP` as "this is a program", and the C library carries one). `43b8d75` fixed the queue, which means
 * those four sources are now unplannable by construction — so nothing will ever re-sync them, and they go on
 * reporting an inconclusive reachability verdict for a question a shared library cannot be asked at all.
 *
 * Three rules, and each is the reason this is an explicit, authored route rather than a sweep:
 *
 * 1. **Never automatic.** The obvious implementation — retire every source the current plan does not contain —
 *    reads *"we did not ask this time"* as *"this will never be asked"*, which is the single inference the proof
 *    state vocabulary exists to prevent. A stage skipped for want of a rootfs, or a provider whose tool was absent
 *    today, would silently erase what a previous run legitimately learned. A person decides a question is retired;
 *    code does not get to conclude it from a quiet run.
 * 2. **Never an operator row.** A hand-authored assertion is somebody's claim and is retracted, never removed —
 *    see `withdrawOperatorFinding`. `deleteFindingsBySource` already refuses them in the SQL; this refuses them
 *    with a message, so a caller aiming at the wrong namespace learns which surface they wanted.
 * 3. **Never a silent gap.** Retirement writes an `image_note` naming the source, the count, every row removed and
 *    the stated reason. A note is deliberately the right home: it is never counted, never reported and never
 *    rendered as a finding, so recording the removal cannot itself become a claim about the firmware.
 *
 * Deleting a computed row is acceptable only because it is COMPUTED — re-running the provider under that source
 * restores it. That is the whole basis for the asymmetry with assertions, and the note says so out loud, because
 * the one reading a retirement must never license is "the question was asked and came back clean".
 *
 * Everything here is pure. The store-bound binder is `retireFindings` in `findings.ts`.
 */
import { isOperatorSource } from './operator-findings.js';

/** What the caller must supply. Every field is mandatory: an unattributed, unexplained deletion is a gap. */
export interface ValidatedRetirement {
  source: string;
  retiredBy: string;
  reason: string;
}

/** The part of a removed row the note preserves — enough to recognise what is gone and re-derive it. */
export interface RetiredRowSummary {
  kind: string;
  title: string;
  proofState: string;
}

export const MAX_RETIRE_REASON = 2000;
export const MAX_RETIRE_AUTHOR = 80;
/**
 * How many removed rows the note lists individually before it summarises. The COUNT is always exact; only the
 * enumeration is bounded, and the note says by what rule — a cap that truncates silently would make the note a
 * worse record than the rows it replaces.
 */
export const MAX_LISTED_ROWS = 40;

/**
 * Pure: validate a retirement request.
 *
 * The reason is required and is not decoration. It is the only thing that survives to explain a gap in a ledger
 * whose central discipline is that an absence never speaks for itself, and it is read months later by someone who
 * was not here.
 */
export function validateRetirement(
  body: unknown,
): { ok: true; value: ValidatedRetirement } | { ok: false; error: string } {
  const b = (body ?? {}) as Record<string, unknown>;
  const source = typeof b.source === 'string' ? b.source.trim() : '';
  const retiredBy = typeof b.retiredBy === 'string' ? b.retiredBy.trim() : '';
  const reason = typeof b.reason === 'string' ? b.reason.trim() : '';

  if (!source)
    return {
      ok: false,
      error: 'source is required — name the findings source to retire, e.g. `symreach:lib/libutil-0.9.30.so`.',
    };
  if (isOperatorSource(source)) {
    return {
      ok: false,
      error: `'${source}' is a hand-authored operator assertion, not a computed result. An assertion is retracted, never removed: POST /images/:id/operator-findings/:findingId/withdraw, so the claim and the reason it was wrong both stay readable.`,
    };
  }
  if (!retiredBy)
    return {
      ok: false,
      error: 'retiredBy is required — a deletion with no author is an unexplained gap in the ledger.',
    };
  if (retiredBy.length > MAX_RETIRE_AUTHOR)
    return { ok: false, error: `retiredBy is longer than ${MAX_RETIRE_AUTHOR} characters.` };
  if (!reason) {
    return {
      ok: false,
      error:
        'reason is required. These rows are removed, not answered, and the note left in their place is the only thing that stops the gap being read as "the question was asked and came back clean".',
    };
  }
  if (reason.length > MAX_RETIRE_REASON)
    return { ok: false, error: `reason is longer than ${MAX_RETIRE_REASON} characters.` };
  return { ok: true, value: { source, retiredBy, reason } };
}

/**
 * Pure: the note that replaces the rows.
 *
 * Lists proof state first on every line, because retiring a `static_confirmed` row and retiring an `info` one are
 * different acts and the record has to make that legible at a glance.
 */
export function retirementNote(v: ValidatedRetirement, rows: RetiredRowSummary[]): string {
  const listed = rows.slice(0, MAX_LISTED_ROWS);
  const lines = [
    `Retired ${rows.length} computed finding(s) under source \`${v.source}\`.`,
    '',
    `Reason given by ${v.retiredBy}: ${v.reason}`,
    '',
    'What was removed:',
    ...listed.map((r) => `  - [${r.proofState}] ${r.kind} — ${r.title}`),
  ];
  if (rows.length > listed.length) {
    lines.push(
      `  … ${rows.length - listed.length} further row(s) not listed individually (the note enumerates at most ${MAX_LISTED_ROWS}; the count above is exact).`,
    );
  }
  lines.push(
    '',
    'These rows were COMPUTED, not asserted, which is the only reason they could be deleted at all: re-running',
    `the provider under \`${v.source}\` restores them. A hand-authored assertion is retracted instead, never removed.`,
    'This note exists so the gap they leave is never read as "the question was asked and came back clean" —',
    'nothing here was answered, and the removal covers no stage.',
  );
  return lines.join('\n');
}

/**
 * Pure: the sentence the route returns. Separate from the note because a caller who mistyped a source needs to
 * see `0` and the source they actually named, rather than a `204` that looks like success.
 */
export function describeRetirement(v: ValidatedRetirement, rows: RetiredRowSummary[], dryRun: boolean): string {
  const verb = dryRun ? 'would retire' : 'retired';
  if (rows.length === 0) {
    return `No findings carry the source \`${v.source}\` on this image, so nothing ${dryRun ? 'would be' : 'was'} removed. Check the source string — a retirement that matches nothing is far more often a typo than an empty set.`;
  }
  const states = [...new Set(rows.map((r) => r.proofState))].sort().join(', ');
  return `${verb === 'retired' ? 'Retired' : 'Would retire'} ${rows.length} finding(s) under \`${v.source}\` (proof states: ${states}). They are recomputable by re-running the provider under that source.`;
}
