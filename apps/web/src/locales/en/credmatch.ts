/**
 * credmatch — the credential cross-reference surface. English source of truth.
 *
 * Three sentences carry the honesty contract and none may soften in translation.
 *
 * `emptyNotClean` is the ceiling on every miss and on an empty result: candidates drawn from the image's own strings
 * that did not reproduce a hash is a BOUNDED NEGATIVE — it never means the password is strong, unknown, or absent
 * from a vendor default list, because no wordlist and no keyspace search took part.
 *
 * `recoveredCeiling` bounds every hit: a recovered password is a property of the BYTES — this string reproduces that
 * stored hash — and never a claim that the account is enabled, a login service is reachable, or a physical unit still
 * runs this firmware.
 *
 * `blockedCaveat` covers the states where the question was asked and could not be answered: a scheme this build
 * cannot compute, or a run blocked before it hashed anything. That is a missing capability made visible, NOT "no
 * recoverable password" — nothing was tried.
 */
export const credmatch = {
  title: 'Credential match',
  sub: 'Cross-references the password hashes this image stores against the printable strings the same image ships — a join, not a crack. Firmware very often compiles the plaintext into a binary, a provisioning script or a config line, so the candidate set is the image’s own strings and one hash per candidate settles it. It finds a password only when the firmware ships it somewhere.',
  run: 'Run credential match',
  rerun: 'Re-run',
  running: 'Cross-referencing…',
  notRun:
    'No credential cross-reference has been run for this image, so its stored hashes have not been tested against its own strings. This is “has not run”, not a clean result.',
  runLabel: 'Credential-match runs',

  // The POST was refused by the rootfs gate — the sentence it returned is the whole prerequisite answer.
  prereqHeading: 'Cannot run yet',
  prereqHint:
    'This reads the stored hashes and the candidate strings out of an extracted rootfs. The sentence above is extraction’s own account of why one is not available — a prerequisite, not a result about the firmware.',

  // The job started and the provider threw — a fault on this bench, distinct from a prerequisite and from a result.
  runFailed: 'The credential cross-reference failed to run.',
  runFailedHeading: 'The run failed',
  runFailedHint:
    'The job started and did not finish. That is a fault on this bench — a tool, a timeout, a disk — and NOT a property of the firmware: nothing was established about its credentials. Read the run log and try again.',

  // available === false: the run finished but never reached hashing. `reason` names which of the four states it was.
  blockedHeading: 'Asked, and could not be answered',
  blockedCaveat:
    'The cross-reference produced no answer, recorded here so the absence of credential findings reads as a question that was never fully asked. It is NOT “no recoverable password”: nothing was hashed.',
  persistedUnavailable:
    'This stored result predates the fields this view needs to explain its coverage. It remains unavailable here rather than being interpreted as an empty or clean scan.',

  // A scanned run. Header facts are denominators — the gaps between them are the coverage story.
  fact: {
    recovered: 'Recovered',
    targets: 'Stored hashes',
    tested: 'Candidates tested',
    distinct: 'Distinct candidates',
    dropped: 'Dropped by cap',
    strings: 'Strings harvested',
    files: 'Files read',
  },
  coverageHeading: 'Coverage',
  opensslMissing:
    'openssl is not installed in this deployment, so only traditional DES crypt hashes could be tested. Any account stored under md5crypt, sha-crypt, bcrypt or yescrypt was recorded as blocked, not as a hash that held.',
  opensslFailure: (flag: string, reason: string) =>
    `This build’s \`openssl passwd ${flag}\` did not reproduce a known answer (${reason}), so hashes needing it were not tested.`,

  col: {
    account: 'Account',
    scheme: 'Scheme',
    outcome: 'Outcome',
    detail: 'What this run established',
  },
  outcome: {
    recovered: 'recovered',
    'not-recovered': 'not recovered',
    blocked: 'not tested',
  },
  locked: 'locked',
  uidRoot: 'UID 0',
  recoveredLabel: 'Password',
  recoveredDetail: (tested: number) =>
    `Hashing this string with the salt stored beside the account reproduces the stored hash byte for byte (${tested} candidate${tested === 1 ? '' : 's'} tested). Not a guess and not from a wordlist.`,
  provenance: (derivation: string, file: string, offset: number) => {
    const where = `${file} @ 0x${offset.toString(16)}`;
    switch (derivation) {
      case 'assignment-value':
        return `from the value of a key=value line in ${where}`;
      case 'quoted':
        return `from a quoted run inside ${where}`;
      case 'token':
        return `from a whitespace-separated token in ${where}`;
      default:
        return `from a string shipped in ${where}`;
    }
  },
  recoveredCeiling:
    'What is confirmed is a property of the bytes: this plaintext maps to that stored hash. It is NOT a claim that the account is enabled, that any login service is reachable, or that a physical unit still runs this firmware.',
  notRecoveredDetail: (tested: number) =>
    `${tested} candidate${tested === 1 ? '' : 's'} drawn from this image’s own strings did not reproduce this hash.`,
  emptyNotClean:
    'A hash not recovered is a BOUNDED NEGATIVE and nothing more: the candidate set is the strings this firmware ships, so a password written down nowhere in the image cannot be found this way. It does NOT mean the password is strong, unknown, or absent from a vendor default list — no keyspace was searched and no wordlist was consulted.',

  // Proof-state codes render verbatim — they cross the API into SQLite and must read identically in every language.
  proof: {
    confirmed: 'the recovered plaintext is confirmed at',
    blocked: 'a scheme this deployment cannot compute is held at',
    negative: 'a bounded negative is recorded at',
  },
  ledgerHint:
    'Each row here also lands in the findings ledger under source `credmatch`; this panel shows the cross-reference’s own coverage, not a second copy of that ledger.',
};
