/**
 * kernelPosture — the kernel-posture table. English source of truth.
 *
 * The load-bearing words are the four class labels. `unknown` in the provider's payload is two incompatible facts —
 * a question that could not apply to this kernel version, and a question that applies and went unanswered — and the
 * labels are what keeps a reader from counting the first as a hardening failure. They must not soften in
 * translation: "not applicable" is a closed question, "unanswered" is an open one.
 *
 * Option names, version strings, evidence sources and the provider's own `detail` sentences are DATA and render
 * verbatim in both languages.
 */
export const kernelPosture = {
  title: 'Kernel posture',
  sub: 'Which hardening properties this kernel has, read from a shipped config, the kernel blob, the module set or a rootfs sysctl — and, for each question it could not settle, whether the option could even exist in this version.',
  run: 'Run kernel posture',
  rerun: 'Re-run',
  running: 'Running…',
  unknownValue: 'not recovered',
  unrecorded: 'not recorded',
  years: (n: number) => `${n} years`,
  modulesValue: (signed: number, inspected: number, total: number, complete: boolean) =>
    `${signed} signed of ${inspected} inspected${complete && inspected === total ? '' : ` (of ${complete ? total : `≥${total}`})`}`,
  class: {
    bad: 'weak',
    unanswered: 'unanswered',
    good: 'ok',
    'not-applicable': 'n/a here',
  },
  census: (c: { total: number; bad: number; unanswered: number; good: number; notApplicable: number }) =>
    `${c.total} question${c.total === 1 ? '' : 's'} — ${c.bad} weak, ${c.good} ok, ${c.unanswered} unanswered, ${c.notApplicable} not applicable to this kernel.`,
  legend:
    'Unanswered and not-applicable are different: the first is a question this image did not settle, the second a question that could not exist for this kernel version — an option that postdates it, or one upstream has removed. Neither is a statement that the hardening is off.',
  cveCensus: (c: { total: number; applicable: number; ruledOut: number; unknown: number }) =>
    `${c.total} curated, version-range kernel CVEs — ${c.applicable} leads, ${c.ruledOut} dismissed by configuration evidence, ${c.unknown} undetermined.`,
  cveLegend:
    'A lead still needs reproduction and a backport check. Dismissed means a required subsystem was proven absent; undetermined means the evidence could not decide and is not a clean result.',
  field: {
    version: 'Version',
    versionSource: 'Read from',
    age: 'Series age',
    configPath: 'Config',
    modules: 'Modules',
  },
  col: { state: 'State', question: 'Question', option: 'Option', evidence: 'Evidence' },
  empty: {
    notRun: 'Kernel posture has not been run for this image, so nothing here has been asked.',
    unavailable: (reason: string) =>
      `The questions were asked and this deployment could not answer them${reason ? `: ${reason}` : '.'} That is a gap in this workbench, not a property of the firmware.`,
    notLocated: (reason: string) =>
      `No kernel was located in this image${reason ? `: ${reason}` : '.'} That is a gap in coverage, never a statement that the image has no kernel or that its kernel is sound.`,
    searchedHeading: 'Looked in:',
    noQuestions: 'A kernel was located and no posture question was recorded against it.',
  },

  /**
   * The vendor VEX search the posture run made in the rootfs. Shown only when the result carries it: an absent block
   * means the search did not happen (an older result, or no rootfs), and the panel then says nothing at all.
   */
  vendorVex: {
    unknown: 'not recorded',
    notRecorded: 'Vendor VEX search coverage was not recorded by this result.',
    notAttempted: (reason: string) => `Vendor VEX search was not attempted: ${reason}`,
    reasonUnknown: 'reason not recorded',
    noneMatchedFirmware:
      'No vendor VEX document matched the search rule. This does not establish whether the firmware is affected or patched.',
    walk: (entries: number | string, bytes: number | string) => `Entries visited: ${entries}; bytes read: ${bytes}.`,
    rule: 'Search rule',
    selectionRule: 'Selection order',
    caps: (files: number | string, bytes: number | string, document: number | string, entries: number | string) =>
      `Search caps — files: ${files}; total bytes: ${bytes}; bytes per document: ${document}; entries: ${entries}.`,
    unreadable: (n: number | string) =>
      `Unreadable directories: ${n}. Files beneath unreadable directories were not seen; recorded paths follow.`,
    unmatchable: (n: number | string) =>
      `Unmatchable product identities: ${n}. These identities match no finding; recorded examples follow.`,
    droppedStatements: 'Statements omitted by parser caps',
    droppedProducts: 'Product references omitted by parser caps',
    ignoredNonCve: 'Non-CVE entries ignored',
    unrecognisedStatus: 'Unrecognised or unsupported statuses omitted',
    unreadStructures: 'Product structures not interpreted (counted, never matched)',
    unreadStructureRule: 'Unread-structure rule',
    otherCounter: (key: string) => `Recorded parser counter (${key})`,
    documentBounds: 'Parser bounds rule',
    author: 'Author',
    timestamp: 'Document timestamp',

    heading: 'Vendor VEX documents',
    counts: (found: number | string, examined: number | string, parsed: number | string, refused: number | string) =>
      `${found} candidate file${found === 1 ? '' : 's'} matched the search rule; ${examined} examined, ${parsed} parsed, ${refused} refused.`,
    noneMatched:
      'No vendor VEX document matched the search rule. That is not evidence of anything: not that the kernel is patched, and not that it is affected.',
    nothingRead: 'The search read nothing, so no vendor statement was looked for. That is not evidence of anything.',
    parsedHeading: 'Parsed:',
    document: (path: string, format: string, statements: number | string) =>
      `${path} — ${format}, ${statements} statement${statements === 1 ? '' : 's'}`,
    refusedHeading: 'Refused, and not used:',
    droppedFiles: (n: number | string, cap: number | string) =>
      `${n} candidate${n === 1 ? '' : 's'} beyond the ${cap}-file cap ${n === 1 ? 'was' : 'were'} not read.`,
    droppedBytes: (n: number | string) =>
      `${n} candidate${n === 1 ? '' : 's'} ${n === 1 ? 'was' : 'were'} not read: the total-byte cap was reached.`,
    walkTruncated: (n: number | string) => `The search stopped at ${n} entries; files beyond them were never seen.`,
    symlinks: (n: number | string) => `${n} symbolic link${n === 1 ? ' was' : 's were'} not followed.`,
    assertion:
      'A matched statement appears on its CVE row in the findings ledger as a vendor assertion. It never changes a proof state.',
  },
};
