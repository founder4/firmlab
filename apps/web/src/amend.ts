/**
 * What an amendment actually changes — and whether it changes anything at all.
 *
 * `OperatorPanel` renders the full amendment history of an assertion: `amendedAt`, `supersedes`, every superseded
 * revision, read defensively because that column was written by older builds. All of it, and **no UI could produce
 * an amendment**. `api.amendAssertion` existed with the right shape, the route existed, and the panel displayed a
 * history nothing in the app could create — a reader for a writer that was never built, which is the inverse of the
 * defect the previous iteration closed.
 *
 * **Why a pure diff and not just a form.** The operator ledger is the most careful surface in this workbench:
 * assertions carry no proof state, count towards no analysis stage, and are returned in their own array precisely so
 * they can never be mistaken for something the workbench measured. An amendment supersedes a claim a named person
 * made. So an amendment that changes NOTHING must not be recorded: it would push the original into `supersedes` and
 * replace it with an identical claim, manufacturing a revision history out of a form submit. That is noise dressed as
 * provenance, in the one place where provenance is the entire point.
 *
 * And the two nothings are different here too, in the way this codebase keeps insisting on:
 *
 *   - **Nobody edited a field.** The form was opened and submitted untouched. No question was asked of the ledger.
 *   - **A field was edited to the value it already had.** A question WAS asked — someone considered the wording and
 *     arrived at the same claim — and the answer is that nothing changed. Worth saying, and still not worth a
 *     revision row.
 *
 * Both are refused, and they are refused with different sentences, because a person who retyped a rationale
 * character-for-character deserves to be told that rather than told they did nothing.
 *
 * Pure and dependency-free.
 */

/** The fields an amendment may change. Mirrors the body `api.amendAssertion` sends. */
export interface AmendableFields {
  title: string;
  claim: string;
  rationale: string;
  severity: string;
}

/** Which fields differ, and whether the ledger should record anything. */
export interface AmendmentDiff {
  /** Field names that actually differ, in a stable order. */
  changed: (keyof AmendableFields)[];
  /** True when there is something for the ledger to record. */
  substantive: boolean;
  /**
   * Why it is not substantive, when it is not. Two distinct cases, never one sentence:
   * `untouched` — the form was submitted as it opened; `retyped` — a field was edited and came back identical.
   */
  refusal: 'untouched' | 'retyped' | null;
}

/** Fields compared in a fixed order, so the reported list is a function of the edit and not of object key order. */
const FIELDS: (keyof AmendableFields)[] = ['title', 'claim', 'rationale', 'severity'];

/**
 * Pure: compare the assertion as it stands against the amendment being proposed.
 *
 * `touched` is the caller's own record of which inputs the person actually interacted with. It is a separate input
 * from the values because the two answer different questions, and collapsing them is the whole point of this
 * module: an untouched form and a form retyped to the same text produce identical VALUES and are not the same event.
 * Whitespace is trimmed before comparing — a trailing space is not an amendment — and the trimmed form is what the
 * caller should send, so what is compared is what is stored.
 */
export function diffAmendment(
  current: AmendableFields,
  next: AmendableFields,
  touched: ReadonlySet<keyof AmendableFields> = new Set(),
): AmendmentDiff {
  const norm = (v: string): string => v.trim();
  const changed = FIELDS.filter((f) => norm(current[f]) !== norm(next[f]));
  if (changed.length > 0) return { changed, substantive: true, refusal: null };
  return { changed: [], substantive: false, refusal: touched.size > 0 ? 'retyped' : 'untouched' };
}

/**
 * Pure: is this amendment allowed to be sent?
 *
 * Separate from `diffAmendment` so a caller cannot accidentally read "no changed fields" as "safe to send". The
 * ledger's rule is that a revision row must correspond to a real change of claim.
 */
export function amendmentIsSendable(d: AmendmentDiff): boolean {
  return d.substantive;
}

/**
 * Pure: the field list an amendment should carry into its own audit trail, as a stable string.
 *
 * Used in the confirmation the operator sees before the ledger is written, because an amendment they cannot review
 * before sending is a change to a named person's claim made blind.
 */
export function describeChangedFields(d: AmendmentDiff): string {
  return d.changed.join(', ');
}
