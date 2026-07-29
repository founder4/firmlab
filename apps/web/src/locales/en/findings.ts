/**
 * findings — the ledger table and the one thing in it a person, not code, wrote. English source of truth.
 *
 * **The dispute annotation is why this namespace is careful.** A contested row states two things and they must
 * travel together: who contested it and on what basis, AND that the proof state beside it is exactly what code
 * decided, unchanged, undowngraded, the row not removed. A bare "DISPUTED" chip invites a reader to discount the
 * measurement, which is precisely the override the design refuses. So `dispute.recordedAs` … `dispute.stands` are
 * one block, split only where the assertion id and the proof-state CODE are printed in `mono` — both identifiers,
 * both untranslated.
 *
 * Finding titles, rationales and source strings are not here at all. They are the record the providers wrote when
 * they ran, stored with the image; they render as written, in whatever language produced them.
 */
export const findings = {
  title: (n: number) => `Findings (${n})`,
  sub: 'Each carries an explicit proof state — not just what was found, but how much it is proven.',

  /** Counted, never filtered: an assertion belongs in this table — it just may never be read as a measurement. */
  asserted: (n: number) =>
    [
      `${n} of these ${n === 1 ? 'was' : 'were'} asserted by a person rather than measured;`,
      'those rows name their author and count towards no analysis stage.',
    ].join(' '),
  contested: (n: number) =>
    [
      `${n} row${n === 1 ? ' is' : 's are'} contested by an operator and annotated in place —`,
      'the annotation records the disagreement and changes nothing code decided.',
    ].join(' '),

  empty: 'No findings yet. Run extraction, SBOM and the deep scans to populate the ledger.',

  /** The cut states what it dropped and by what rule — never by the order the rows happened to be written. */
  cutRule: (shown: number, total: number, omitted: number) =>
    [
      `Showing ${shown} of ${total}.`,
      'Rows are ordered by severity (highest first, then proof state and title) and the',
      `${omitted} lowest-ranked are omitted — the cut is by that rule, never by the order the rows were written.`,
      'Every contested row is shown regardless of the cap.',
    ].join(' '),
  /** `common.showAll` exists, but the count has to agree with it grammatically, so the whole label lives here. */
  showAllCount: (n: number) => `Show all ${n}`,

  col: {
    severity: 'Sev',
    finding: 'Finding',
    source: 'Source',
    proofState: 'Proof state',
  },

  /** The author line an asserted row always carries — an assertion never appears without who made it. */
  /**
   * A finding whose subject was not the firmware as shipped: the workbench changed something to obtain it.
   *
   * Load-bearing and it must not soften in translation. The proof state on the row is honest — the rung really
   * was reached — but it was reached against an altered subject, and a reader comparing it with a row obtained
   * from an untouched image is comparing two different claims. The interventions themselves are the provider's
   * own sentences and render as written, in the tooltip.
   */
  /** The provider's own sentence for why a finding sits at its proof state — especially a downgrade. */
  why: 'Why this state',
  whyLabel: 'Show why this finding sits at this proof state',
  interventionMark: (n: number) => `⚠ obtained after ${n} change${n === 1 ? '' : 's'} to the firmware — not as shipped`,
  assertedBy: (who: string) => `asserted by ${who}`,
  agentSuffix: ' (agent)',
  withdrawnSuffix: ' — WITHDRAWN',
  /** Honest blanks: a row may carry no author and a revision no timestamp, and neither may be invented. */
  unrecordedAuthor: 'an unrecorded author',
  unrecordedDate: 'an unrecorded date',

  dispute: {
    heading: 'Contested by an operator',
    /** The title is the operator's own words and is quoted, never translated. */
    claim: (author: string, day: string, title: string) =>
      `${author} asserts on ${day} that this finding is wrong: “${title}”.`,
    /** Around the assertion id and the proof-state code, both printed verbatim in `mono`. */
    recordedAs: 'Recorded as operator assertion',
    stillStates:
      ', and listed in full in the operator ledger. This is testimony about a measurement, not a measurement: the ' +
      'proof state of this row is still',
    stands:
      ', decided by code from the evidence, and the dispute neither changes it, downgrades it nor removes the ' +
      'row. Both stand; a reader weighs them.',
  },

  dangling: {
    lead: (n: number) =>
      [
        `${n} recorded dispute${n === 1 ? '' : 's'} name${n === 1 ? 's' : ''} a finding that is not in this ledger.`,
        'Re-running a provider replaces its rows with new ids, so a dispute can outlive the row it was recorded',
        'against: the claim is kept, and what it pointed at cannot be annotated here.',
      ].join(' '),
    /** Around the missing target id. The quoted title is the operator's, and stays as written. */
    contests: (author: string) => `${author} contests`,
    quoted: (title: string) => `— “${title}”`,
  },
};
