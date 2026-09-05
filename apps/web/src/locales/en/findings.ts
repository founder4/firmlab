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

  /**
   * The fold, and why it is a different sentence from the cut.
   *
   * The cut says rows were DROPPED. The fold says the opposite — every row is still here, drawn on fewer lines —
   * and the two must never be confused, because a reader who mistakes one for the other either thinks findings are
   * missing when they are not, or stops looking for the ones that really were cut. So this sentence states both
   * halves outright: nothing dropped, nothing reordered, and expanding shows every row in a group.
   */
  foldRule: (rows: number, lines: number, folded: number) =>
    [
      `${rows} rows drawn as ${lines} line${lines === 1 ? '' : 's'}:`,
      `${folded} of them say the same thing about different subjects and are folded into a group each.`,
      'Folding drops no row and reorders none — expand a group to read every row in it.',
    ].join(' '),

  /** A folded group speaks for its members without averaging them: they share severity, proof state and source. */
  group: {
    toggle: (n: number, open: boolean) => (open ? `Collapse these ${n} findings` : `Expand these ${n} findings`),
    subjects: (n: number) => `${n} subject${n === 1 ? '' : 's'}`,
    expandAll: 'Expand every group',
    collapseAll: 'Collapse every group',
  },

  col: {
    severity: 'Sev',
    finding: 'Finding',
    source: 'Source',
    proofState: 'Proof state',
  },

  /** Every semantic census category has the identically-defined filter; card and table can never disagree. */
  filters: {
    aria: 'Filter findings',
    all: 'All',
    priority: 'Critical + high',
    established: 'Established',
    lead: 'Leads',
    blocked: 'Blocked',
    dismissed: 'Dismissed',
    asserted: 'Assertions',
    other: 'Uncategorized',
    searchLabel: 'Search findings',
    searchPlaceholder: 'Search title, source or proof state…',
    results: (shown: number, total: number) => `${shown} of ${total}`,
  },

  /**
   * The two axes said in one place, because the table shows both and used to encode only one.
   *
   * `severity` is how bad the row would be **if true**; the proof state is how much of it was established. On
   * this corpus two thirds of every severity band are leads, so "72 critical" was a sentence the workbench had
   * not earned. The census prints the exhaustive split inline and the mark carries the binary part per row — a
   * filled disc for a property of the image, a hollow ring for anything not established. The proof-state badge
   * distinguishes a lead from a block, dismissal or assertion.
   *
   * The legend is not optional decoration: fill is the only thing separating the two, and a distinction a
   * reader has to infer is a distinction that will be misread.
   */
  census: {
    split: (established: number, leads: number, blocked: number, dismissed: number, asserted: number, other: number) =>
      [
        established ? `${established} established` : '',
        leads ? `${leads} lead${leads === 1 ? '' : 's'}` : '',
        blocked ? `${blocked} blocked` : '',
        dismissed ? `${dismissed} dismissed` : '',
        asserted ? `${asserted} asserted` : '',
        other ? `${other} uncategorized` : '',
      ]
        .filter(Boolean)
        .join(' · '),
    band: (
      severity: string,
      total: number,
      established: number,
      leads: number,
      blocked: number,
      dismissed: number,
      asserted: number,
      other: number,
    ) => `${total} ${severity}: ${findings.census.split(established, leads, blocked, dismissed, asserted, other)}`,
    legend:
      'Severity says how bad a row would be if true, never that it was established. The census keeps established properties, leads, blocked questions, dismissals and operator assertions separate.',
  },

  /** Colour is never the only carrier: the mark's own label says both axes for a screen reader. */
  mark: {
    established: (severity: string) => `${severity} — established`,
    unproven: (severity: string) => `${severity} if true — not established`,
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
  /**
   * Why it was retracted.
   *
   * The row keeps its original `rationale` behind the chevron, so a retracted claim used to expand into the
   * argument FOR it with nothing anywhere saying it had been taken back — worse than a missing field. The author
   * of the retraction is named beside the reason because withdrawing someone else's claim and withdrawing your
   * own are different acts.
   */
  withdrawnBecause: (who: string) => `withdrawn by ${who}:`,
  withdrawnNoReason: (who: string) => `withdrawn by ${who} — no reason was recorded.`,
  withdrawnUnknownBy: 'an unrecorded author',
  /** Labels the expanded cell of a retracted row, so its reasoning is not read as a standing argument. */
  whyWithdrawn: 'Why this state — for the claim that was retracted',
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
