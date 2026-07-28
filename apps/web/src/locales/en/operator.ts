/**
 * operator — the one place in the workbench where a person writes a row instead of a provider. English source.
 *
 * **Nothing here may sound like a measurement.** An assertion carries no proof state, counts towards no analysis
 * stage, and is never deleted — only withdrawn, with the reason. `assertionsSub` says all three, and the badge is
 * deliberately NOT the proof-state badge: it reuses the shared `proofState.label.operator_assertion` gloss so the
 * ledger, the findings table and the report cannot word the same row three ways.
 *
 * **History is history.** `history.heading` and `history.note` exist so a superseded claim can never be read as a
 * second live claim standing beside the current one. An amendment appends; it never overwrites. A translation that
 * softens "no longer claimed" into something present-tense performs exactly the erasure the ledger refuses.
 *
 * The claim CODES (`asserted_from_device`…), the severity codes and the attribution sentence the API serves are not
 * translated: the first two are identifiers, and the third is served precisely so the UI cannot drift from the
 * report.
 */
export const operator = {
  assertionsTitle: (n: number) => `Operator assertions (${n})`,
  assertionsSub:
    'What a person knows, recorded as such. These carry no proof state, count towards no analysis stage, and are ' +
    'never deleted — only withdrawn, with the reason.',
  /** Shown only if the API served no caveat of its own; the API's wording wins so the report cannot disagree. */
  notAMeasurement: 'An operator assertion is evidence that a person asserted something. It is not a measurement.',

  /** The vocabulary this form offers instead of a proof state. The values stay the claim codes. */
  claim: {
    asserted_unverified: 'I believe this — nothing here measured it',
    asserted_from_device: 'I observed this on the physical device',
    asserted_from_external_evidence: 'An external source says so (advisory, datasheet)',
    disputes_finding: 'A code-decided finding is wrong',
  },

  form: {
    whoPlaceholder: 'who is asserting this',
    whoLabel: 'Who is asserting this',
    claimPlaceholder: 'the claim, in one line',
    claimLabel: 'The claim',
    basisLabel: 'On what basis',
    severityLabel: 'Asserted severity',
    disputesPlaceholder: 'id of the finding you dispute',
    disputesLabel: 'Disputed finding id',
    rationalePlaceholder: 'on what basis — required, because nobody else can evaluate a claim without it',
    rationaleLabel: 'Stated basis',
    record: 'Record assertion',
    recording: 'Recording…',
  },

  /** Counted separately and said so, so the two kinds of row are never read as one total. */
  measuredCount: (n: number) => `${n} measured finding(s) on this image, counted separately.`,
  noAssertions: "No assertions recorded. Everything in this image's ledger was decided by code.",

  col: {
    severity: 'Sev',
    claim: 'Claim',
    provenance: 'Provenance',
  },
  withdraw: 'Withdraw',
  withdrawnBadge: 'withdrawn',
  withdrawnHeading: (n: number) => `Withdrawn (${n})`,
  withdrawnNote: 'Kept on purpose. "This was wrong, and here is why" is a more useful record than a gap.',
  withdrawPrompt: 'Why does this claim no longer stand? (recorded with the retraction)',
  withdrawWho: 'Who is retracting it?',

  /** An honest blank: a revision written by an older build may carry no timestamp at all. */
  unrecordedDate: 'an unrecorded date',

  history: {
    /** "Amended, and the earlier claim is gone" is information; rendering it as never-amended would be erasure. */
    noneReadable: (day: string) =>
      [
        `Amended ${day}. No history is readable: this row was amended by a build that overwrote its predecessor`,
        'rather than appending it, so what stands here is the current claim only.',
      ].join(' '),
    hide: 'Hide history',
    show: (day: string, n: number) => `Amended ${day} — show ${n} superseded ${n === 1 ? 'claim' : 'claims'}`,
    heading: 'History — superseded, no longer claimed',
    note:
      'An amendment appends; it never overwrites. Nothing below stands: it is what this author previously stated, ' +
      'kept so a claim cannot be quietly restated as a weaker one.',
    /** Precedes the claim CODE, which is an identifier and stays as it is. */
    superseded: 'superseded',
    claimNotRecorded: 'claim not recorded',
    stood: (from: string, to: string) => `stood from ${from} to ${to}`,
    contested: 'contested',
    noBasis: 'No basis was recorded with this revision.',
  },

  notes: {
    title: (n: number) => `Working notes (${n})`,
    sub:
      'Reasoning that is not a claim: a hypothesis, a thread to pull next, why you ruled something out. Notes are ' +
      'never counted, never reported, and never rendered as findings.',
    authorPlaceholder: 'author',
    authorLabel: 'Note author',
    bodyPlaceholder: 'what you are thinking',
    bodyLabel: 'Note body',
    save: 'Save note',
    empty: 'No notes yet.',
  },
};
