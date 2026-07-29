/**
 * updatepath — what the updater in this rootfs checks, and where that check physically lives. English source.
 *
 * **Two sentences here are the panel's whole argument and must survive translation intact.**
 *
 * `chain.caveatBefore` … `chain.caveatAfter`: being credited with a sourced verification does NOT prove the check
 * runs. A resolved `source` edge is one static fact — this file names that file where a POSIX shell would read it.
 * Sourcing a file defines its functions; it does not call them. The emphasis is a real `<strong>`, and the negation
 * has to stay just as blunt in every language.
 *
 * `chain.followedNone*` versus `chain.unknownChain*`: "this run followed source edges and found none" is an ANSWER
 * about these scripts, and "no chain is recorded" is a gap in what the stored result knows. The Tenda camera's
 * `usr/bin/force_upgrade` genuinely sources nothing, and until the provider distinguished the two the panel could
 * only say it did not know. Collapsing them back together in translation would undo that.
 *
 * Paths, sonames, `source` / `.` / `include`, `ucert` and the reasons the provider recorded are identifiers or
 * recorded evidence: they render in `mono` exactly as stored, which is why several sentences arrive here in pieces.
 */
export const updatepath = {
  title: 'Update path — what the updater checks, and where that check lives',
  sub:
    'The files this rootfs would run to install new firmware, the verification each one performs, and — because ' +
    'an entry point routinely delegates its checking to a file it sources — the chain that reached the check.',

  /** Every kind of nothing gets its own sentence; the first two were the same absence once. */
  notRun:
    'Nobody has run the update-path provider on this image. That is not a statement about the firmware: no ' +
    'updater has been looked for, so nothing here has been cleared. Run',
  notRunFrom: 'from Deep analysis above.',
  unavailable: 'The update-path provider could not run on this image.',
  /** A bound, stated. "No updaters found" from a sweep that stopped early is a cap, not an answer. */
  budgetExhausted: (elfs: number, files: number) =>
    `The sweep STOPPED rather than finished: it examined ${elfs} ELF(s) of ${files} file(s) walked before its budget ran out. Anything below is what was found in that prefix — an updater in the remainder would not appear here, and an empty result is not a negative.`,
  budgetOk: (elfs: number, files: number) =>
    `Examined ${elfs} ELF(s) across ${files} file(s); the budget was not reached.`,
  noUpdaters:
    'The provider ran and located no updater candidate. That is a statement about what the walk read, not a ' +
    'verdict that the device has no update path — an updater outside the carved rootfs, in a second partition or ' +
    'past a walk bound was never opened.',

  /** Labels for the evidence rows. The commands themselves are `mono` and never translated. */
  row: {
    verifies: 'verifies',
    verifiesOwn: 'verifies (its own lines)',
    signatureCommands: 'authenticates origin',
    signatureFns: 'signature routines',
    digestFns: 'digest routines',
    missingVerifiers: 'invokes, but the binary is absent from the rootfs',
    flashWrites: 'writes flash',
    rollbackMarkers: 'rollback markers',
  },

  candidate: {
    noPath: '(path not recorded)',
    unknownKind: 'unknown kind',
  },

  chain: {
    heading: 'Source chain',
    noFile: '(the file was not recorded)',
    physicallyIn: '— the file these lines are physically in',
    reached: 'reached:',
    notRecorded: 'the chain that reached it was not recorded on this result',

    /** Around the candidate path and the `source` / `.` / `include` directives, in render order. */
    creditedLead: (n: number) => `${n} file${n === 1 ? '' : 's'} that`,
    creditedReadsWith: 'reads with',
    creditedTail: (n: number) =>
      `${n === 1 ? 'was' : 'were'} credited to it. The evidence is listed under the file it lives in, not under`,
    creditedTailAfter: ', which contains none of these lines.',

    /** The caveat, next to the credit it qualifies — a caveat a reader has to go and find does not travel. */
    caveatBefore:
      'A resolved source edge is one static fact: this file names that file where a POSIX shell would read it. ' +
      'Being credited with a sourced verification does',
    caveatNot: 'not',
    caveatAfter:
      'prove the check runs — sourcing a file defines its functions, it does not call them, and the call may sit ' +
      'behind a branch, behind a flag nobody sets, or inside a function that returns 0 without verifying ' +
      'anything. No source edge raises a proof state.',

    unresolved: (n: number) =>
      [
        `${n} directive${n === 1 ? '' : 's'} could not be turned into a file.`,
        'Guessing one would fabricate; dropping it silently would hide that this graph is incomplete.',
      ].join(' '),
    unresolvedNoFile: '(file not recorded)',
    unresolvedNoSpec: '(no operand recorded)',
    unresolvedNoReason: 'no reason was recorded',

    bounds:
      'Where following stopped short. A bound is not an answer: anything past it was not looked at, and is absent ' +
      'from what this candidate is credited with rather than cleared by it.',

    /** An answer about these scripts — not a gap. The `source` identifier sits between the two halves. */
    followedNone: 'No candidate below sources another file. This run followed',
    followedNoneTail: 'edges and found none — an answer about these scripts, not a gap in the analysis.',
    unknownChain:
      'No source chain is recorded on any candidate below. Two readings, and this result cannot tell them apart: ' +
      'these scripts source nothing, or the result was stored by a build that did not follow',
    unknownChainTail: 'edges at all. Re-run the provider to be sure which.',
  },

  dropped: (n: number) =>
    [
      `${n} further candidate(s) were dropped by the candidate cap — kept by entry-point/verification/flash`,
      'evidence, never by directory order — and are absent from the list above rather than cleared by it.',
    ].join(' '),
};
