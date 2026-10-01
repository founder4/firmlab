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
    missing: (fields: string[]) => `Fill in before recording: ${fields.join(', ')}.`,
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
  /**
   * Amending an assertion supersedes a claim a named person made, so the panel says what it is about to change and
   * refuses a change that is not one. The two refusals are separate sentences on purpose: someone who retyped a
   * rationale character-for-character is told that, not told they did nothing.
   */
  amend: {
    open: 'Amend',
    cancel: 'Cancel',
    save: 'Save amendment',
    heading: 'Amend this assertion',
    intro:
      'This supersedes the claim as it stands. The original is kept in the ledger as a superseded revision — nothing is deleted — and the row will say it was amended.',
    fields: { title: 'Title', claim: 'Claim', rationale: 'Rationale', severity: 'Severity' },
    changing: (fields: string) => `Changing: ${fields}`,
    untouched:
      'Nothing was edited, so there is nothing to amend. Submitting would push the current claim into the history and replace it with an identical one, which manufactures a revision out of a form submit.',
    retyped:
      'Every field came back identical to what is already stored. The question was asked and the answer is that the claim does not change, so no revision is recorded — that is not the same as having edited nothing.',
    who: 'Amending as',
    /**
     * The third way an amendment cannot be sent, and the only one that is about the author rather than the diff:
     * a real edit with nobody signing it. Worded as what the record needs, not as a missing form field.
     */
    unsigned:
      'Name who is making this amendment. It is recorded beside the original author, not instead of them — an edit to someone else\u2019s claim is attributed to you, and their claim stays attributed to them.',
  },
  withdraw: 'Withdraw',
  withdrawnBadge: 'withdrawn',
  withdrawnHeading: (n: number) => `Withdrawn (${n})`,
  withdrawnNote: 'Kept on purpose. "This was wrong, and here is why" is a more useful record than a gap.',
  withdrawTitle: 'Withdraw this assertion',
  withdrawBody: 'The claim stays in the ledger as history, marked withdrawn, with the reason and who withdrew it.',
  withdrawPrompt: 'Why does this claim no longer stand?',
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
    /** Only rendered when an amendment is on record as having stated it; absence is not attributed to anyone. */
    statedBy: (who: string) => `, stated by ${who}`,
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
    /** Editing replaces the note's text in place — a note is reasoning, not a claim, so it keeps no history. */
    edit: 'Edit',
    editLabel: 'Edit note body',
    saveEdit: 'Save changes',
    savingEdit: 'Saving…',
    cancelEdit: 'Cancel',
    emptyBody: 'A note cannot be empty. Delete it instead if it no longer holds anything.',
    tooLong: (max: number, n: number) => `A note holds at most ${max} characters; this one has ${n}.`,
  },

  /**
   * Retiring a computed source — the ledger's only deletion path, and the one most likely to be misread. Every
   * sentence here must keep two things apart: a COMPUTED row can be removed because re-running its provider restores
   * it, and an operator assertion can never be removed at all. And a retirement is not an answer: the gap it leaves
   * is "nobody asks this any more", never "the question came back clean".
   */
  retire: {
    title: 'Retire a computed source',
    sub:
      'Removes every finding one provider source wrote on this image and leaves a working note naming what went and ' +
      'why. Only computed rows can be retired — re-running the provider under that source restores them. Nothing ' +
      'is answered by this: the removal covers no stage.',
    open: 'Retire source…',
    close: 'Close',
    sourceLabel: 'Findings source',
    sourcePlaceholder: 'e.g. symreach:lib/libutil-0.9.30.so',
    whoLabel: 'Retired by',
    whoPlaceholder: 'who is retiring these rows',
    reasonLabel: 'Why these rows should go',
    reasonPlaceholder: 'required — the note left in their place is the only thing that explains the gap',
    dryRunLabel: 'Preview only — list what would be removed without removing it',
    preview: 'Preview retirement',
    submit: 'Retire findings',
    working: 'Working…',
    missing: (fields: string[]) => `Fill in before retiring: ${fields.join(', ')}.`,
    reasonTooLong: (max: number, n: number) => `The reason holds at most ${max} characters; this one has ${n}.`,
    whoTooLong: (max: number) => `The name holds at most ${max} characters.`,
    /** The client-side refusal of an `operator:` source. Names the surface the caller actually wanted. */
    operatorRefused: (source: string) =>
      [
        `'${source}' is a hand-authored operator assertion, not a computed result. An assertion is never removed —`,
        'withdraw it from the assertions ledger above, so the claim and the reason it was wrong both stay readable.',
      ].join(' '),
    previewHeading: 'Preview — nothing has been removed',
    doneHeading: 'Retired — a note was recorded in place of these rows',
    removedCount: (n: number) => `${n} row(s)`,
    noteHeading: 'The note left in the ledger',
  },
};
