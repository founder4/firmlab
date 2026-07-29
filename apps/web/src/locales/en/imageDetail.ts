/**
 * imageDetail — the per-image analysis screen. English source of truth.
 *
 * This is the densest prose in the workbench, and almost none of it is decoration. The sentences that say what a
 * stage covered, what a bound dropped, and what a proof state does *not* claim are the product; a translation that
 * softens one of them ships a different claim under the same UI. Adding a key here makes
 * `locales/es/imageDetail.ts` fail to compile until it is translated, which is the point.
 *
 * **Four things deliberately do NOT live here.**
 *
 *   - **Section names.** `t.sections` already holds a label for every id this screen routes to, and the shell's
 *     context header reads the same map. A second copy would drift the first time one of them gained a section —
 *     which is exactly what the `SECTION_TITLES` map this namespace replaced had already started to do.
 *   - **Proof states and severities.** They are identifiers that cross the API and land in SQLite. The screen
 *     prints the code verbatim and takes its gloss from `t.proofState`; nothing about them is restated here, so
 *     the ledger's wording and this screen's cannot disagree.
 *   - **Anything the API wrote.** A finding's title and rationale, a provider's `reason`, `nvd.notQueriedRule`,
 *     `caps.reason` — stored evidence, rendered as recorded. Only the FALLBACK a panel uses when a provider sent
 *     no reason is ours, and those are the `unavailable` keys below.
 *   - **Bare acronyms that are the name of the value below them.** The `CVE` column header is written into the
 *     JSX, because it is the identifier in the cell and not a word to translate.
 *
 * Entries that interpolate are FUNCTIONS, so each language builds its own agreement and word order rather than
 * being poured into English's.
 */
export const imageDetail = {
  header: {
    eyebrow: (arch: string) => `Firmware · ${arch}`,
    unknownArch: 'unknown arch',
    report: 'Report',
    disclosure: 'Disclosure',
    disclosureTitle: 'Coordinated-disclosure draft (Markdown) — review before sending',
  },

  /** Shown when a section needs the cached static bundle and the image has none. Never phrased as "nothing found". */
  emptyAnalysis: {
    title: 'No static analysis',
    body: (dashboard: string) =>
      `This image hasn’t been analyzed yet, or analysis failed. Re-upload it from the ${dashboard}.`,
  },

  findingsTab: {
    operatorPrompt: 'Know something the bench cannot measure — a result from the physical device, a vendor advisory?',
  },

  dossier: {
    signalTitle: 'Signal tape',
    signalSub: 'Entropy trace over the structure carve, findings pinned to their offset. Scrub to read any byte range.',

    statBinaries: 'Binaries',
    statBinariesValue: (total: number, triaged: number) => `${total} (${triaged} triaged)`,
    statFindings: 'Findings',
    statStrategy: 'Runtime strategy',

    copilotTitle: 'Copilot analysis',
    copilotModelTitle: 'LLM backing the copilot',
    copilotAnalyzing: 'Analyzing…',
    copilotRerun: 'Re-run',
    copilotAnalyze: 'Analyze',
    copilotSub:
      'Interpretation over the cited findings — priors and proof-states, not new truth. The copilot runs nothing and invents nothing.',

    coverageTitle: 'Coverage',
    coverageSub: 'What has run so far — the dossier never implies completeness it doesn’t have.',
    stageStatic: 'Static analysis',
    stageExtract: 'Extraction',
    stageSbom: 'SBOM & CVEs',
    stageSecrets: 'Deep secrets (gitleaks)',
    stageTriage: 'Binary triage',
    stageEmulation: 'Emulation',
    preflight: 'Runtime preflight',
    /** The highest rung this deployment could reach for this image — a ceiling, not a result. */
    proofCeiling: 'Proof ceiling',

    corpusTitle: (n: number) => `Corpus cross-references (${n})`,
    corpusSub: 'Things in this image the corpus has seen elsewhere — priors worth checking, not conclusions.',
    corpusCredentialFallback: 'credential',
    corpusCredential: (kind: string) => `${kind} — also in`,
    corpusComponent: (name: string, version: string, cveCount: number) =>
      `${name} ${version}${cveCount > 0 ? ` (${cveCount} CVE)` : ''} — also in`,
    corpusArtifact: (path: string) => `${path} — same binary in`,
  },

  structure: {
    title: 'Structure map',
    sub: (segments: number) => `Signature-carved layout across the image (${segments} segments)`,
  },

  entropy: {
    title: 'Entropy profile',
    sub: 'Shannon entropy across the image — a high band is a lead to check, not a verdict on what it holds',
    colRegion: 'High-entropy region',
    colMeanH: 'Mean H',
    colSize: 'Size',
  },

  secrets: {
    title: 'Secrets & credentials',
    sub: 'Heuristic matches in the raw image (values shown are pre-extraction)',
    /** Not "clean": the heuristics ran over the RAW image, before any extraction. */
    empty: 'No secret-like strings detected in the raw image.',
    colSeverity: 'Severity',
    colKind: 'Kind',
    colOffset: 'Offset',
    colValue: 'Value',
  },

  gitleaks: {
    title: 'Deep secret scan (gitleaks)',
    sub: 'Scans the extracted rootfs for keys, tokens, and credentials in files.',
    scanning: 'Scanning…',
    rescan: 'Re-scan rootfs',
    scan: 'Scan rootfs',
    unavailable: 'gitleaks unavailable — run extraction first, or install gitleaks.',
    count: (n: number) => `${n} finding${n === 1 ? '' : 's'} in the rootfs.`,
    colRule: 'Rule',
    colFile: 'File',
    colLine: 'Line',
    colMatch: 'Match',
  },

  filesystem: {
    statFiles: 'Files',
    statDirs: 'Directories',
    statSetuid: 'setuid binaries',
    rootfsTitle: 'Root filesystem',
    title: 'Filesystem extraction',
    sub: 'Carve the image with binwalk and model the recovered rootfs.',
    extracting: 'Extracting…',
    run: 'Run extraction',
    /** The fallback when the job left no log of its own — it names both causes rather than implying "clean". */
    noRootfs: 'Extraction produced no rootfs (binwalk unavailable or no filesystem found).',
  },

  job: {
    failed: 'Job failed',
  },

  sbom: {
    title: 'Software Bill of Materials + CVEs',
    sub: 'syft inventories the extracted rootfs; grype matches known (N-day) CVEs.',
    scanning: 'Scanning…',
    rescan: 'Re-scan',
    generate: 'Generate SBOM & scan CVEs',
    unavailable: 'SBOM unavailable — run extraction first, or install syft.',
    statPackages: 'Packages',
    statVulns: 'Vulnerabilities',
    statCritHigh: 'Critical / High',
    /** Absence of the matcher is not absence of CVEs, and the banner has to say which of the two happened. */
    grypeMissing: 'grype not present — SBOM generated, but CVE matching was skipped.',
    graphTitle: 'Component graph',
    graphSub:
      'The rootfs and its components, grouped by ecosystem around the ring and coloured by the worst CVE affecting each. Hover a node for its version and CVEs.',
    cvesTitle: 'CVEs',
    colSeverity: 'Severity',
    colPackage: 'Package',
    colVersion: 'Version',
    colFixedIn: 'Fixed in',
    packagesTitle: (n: number) => `Packages (${n})`,
    colName: 'Name',
    colType: 'Type',
    /** The noun the run history uses for these runs — the panel's word, not the job kind. */
    runLabel: 'SBOM',
  },

  diff: {
    title: 'Compare firmware',
    sub: 'Diff identity, packages/CVEs (needs SBOM on both), and rootfs files (needs extraction).',
    needSecond: 'Upload a second image to compare against.',
    selectPlaceholder: 'Select an image to compare against…',
    comparing: 'Comparing…',
    compare: 'Compare',
    identityTitle: 'Identity',
    identityNone: 'No identity differences.',
    colField: 'Field',
    packagesTitle: 'Packages',
    packagesNeedSbom: 'Run SBOM on both images to diff packages.',
    statAdded: 'Added',
    statRemoved: 'Removed',
    statVersionChanged: 'Version-changed',
    colPackage: 'Package',
    cvesTitle: 'CVEs',
    cvesNeedSbom: 'Run SBOM on both images to diff CVEs.',
    added: (n: number) => `+${n} added`,
    removed: (n: number) => `−${n} removed`,
    bySeverity: (n: number, severity: string) => `+${n} ${severity}`,
    /** Only about the two images compared — it says nothing about either image's absolute exposure. */
    noNewCves: 'No newly-introduced CVEs.',
    filesTitle: 'Root filesystem',
    filesNeedExtract: 'Run extraction on both images to diff files.',
    statFilesChanged: 'Changed (size)',
    runLabel: 'diff',
  },

  research: {
    offTitle: 'External intelligence',
    offBadge: 'off',
    offBodyBefore: 'The only feature that leaves this machine. Enable with ',
    offBodyAfter:
      ' to correlate the SBOM against public advisories (OSV) and draft responsible-disclosure notes. Off by default — FirmLab stays local-only.',

    title: 'External intelligence',
    sourceBadge: 'public sources',
    sourceTitle: 'Correlated from public sources; reachability unverified',
    researching: 'Researching…',
    rerun: 'Re-run',
    run: 'Run research',
    /** Two claims, and both have to survive translation: what leaves, and that an advisory is a lead. */
    sub: 'Sends only component names + versions to the vuln databases (OSV, NVD); downloads the CISA KEV catalog to flag known-exploited CVEs locally. Never firmware bytes, secrets, or keys. A published advisory for a present component is a lead, not a confirmed bug (reachability is decided per-image).',

    osvBadge: (n: number) => `OSV ${n} queried`,
    osvBadgeTitle: 'OSV: ecosystem-mapped SBOM components queried',
    /**
     * The denominators. Both lanes counted what they never asked about, and neither number reached the screen —
     * so "0 advisories" read as "no advisories exist" when it meant "no advisories among the ones we asked".
     * `unmapped` is not a failure of the component: OSV is asked per ecosystem, and a binary fingerprinted out of
     * a firmware has no ecosystem to name.
     */
    osvSkipped: (n: number) =>
      `${n} SBOM component${n === 1 ? '' : 's'} could not be mapped to an OSV ecosystem and ${n === 1 ? 'was' : 'were'} never asked about. The advisory count above does not cover ${n === 1 ? 'it' : 'them'}.`,
    nvdNotQueried: (n: number) =>
      `${n} candidate${n === 1 ? '' : 's'} went unasked at NVD. The advisory count above does not cover ${n === 1 ? 'it' : 'them'}.`,
    /** A table bound. Stated because a list that simply stops reads as the whole set. */
    componentsShown: (shown: number, total: number) =>
      `Showing ${shown} of ${total} components. The rest are in the run's stored result.`,
    osvAdvisories: (n: number) => `${n} OSV advisories`,
    nvdBadge: (queried: number, advisories: number) => `NVD ${queried} queried · ${advisories} advisories`,
    nvdTitleUnknown:
      'NVD, for components OSV could not map. This result predates the CPE/keyword split, so which question produced it was not recorded — re-run research to find out.',
    nvdTitle: (cpe: number, keyword: number) =>
      `NVD, for components OSV could not map: ${cpe} asked by CPE version match, ${keyword} by keyword. A keyword answer matches CVE description text only — an empty one is not evidence the component is unaffected.`,
    kevBadge: (n: number) => `KEV ${n} known-exploited`,
    /**
     * Two states, and the second is why this exists: a KEV check that did not happen used to make the whole
     * block disappear, and a missing block is indistinguishable from a clean one. The catalogue size goes in the
     * tooltip because "0 matches" is only readable against what was searched.
     */
    /**
     * The online hash lookup. Six outcomes, and two of the distinctions between them are load-bearing:
     * `skipped_salted` is a REFUSAL to ask (a miss on a salted hash proves nothing), and `miss` is a question
     * that was asked and came back empty — which is still not evidence the password is strong. Flattening either
     * into "not found" is the mistake this whole block exists to prevent.
     */
    hash: {
      heading: 'Password-hash lookup',
      disabled:
        'Not asked: the online hash-lookup lane is off. Nothing here says these hashes are unrecoverable — the question was never put.',
      noneToAsk: 'The lane is on and there was no hash to ask about.',
      manual: 'look up by hand',
      saltedNote:
        'A salted crypt hash is never sent, because a miss on one would prove nothing about the password. Those rows are a refusal to ask, not an answer.',
      outcome: {
        resolved: 'recovered',
        unverified: 'unverified',
        miss: 'no match',
        skipped_salted: 'not sent (salted)',
        skipped_cap: 'not sent (cap)',
        skipped_other: 'not sent',
      },
      outcomeMeaning: {
        resolved: 'A plaintext was recovered AND verified locally against this hash. This is a credential.',
        unverified: 'A lookup returned a candidate that did not verify against this hash. Not a credential.',
        miss: 'The hash was sent and nothing matched. That is not evidence the password is strong — only that this service has not seen it.',
        skipped_salted:
          'Never sent. The hash is salted, so a miss would prove nothing about the password, and sending it would leak firmware material for no answer.',
        skipped_cap: 'Never sent: the per-run cap was reached first. This is a bound, not a result.',
        skipped_other: 'Never sent — the scheme was not one this lane queries.',
      },
    },
    kevBadgeTitle: (catalogSize: number) =>
      `CISA Known Exploited Vulnerabilities — exploited in the wild. ${catalogSize} entries were searched.`,
    kevNotChecked: 'KEV not checked',
    kevNotCheckedTitle:
      'The Known Exploited Vulnerabilities catalogue was not consulted on this run, and the provider recorded no reason. Nothing here says these CVEs are NOT known-exploited — the question was not asked.',
    vendorTitle: 'Provenance hint (vendor)',

    kevHeading: '⚠ Known-exploited in the wild (CISA KEV) · reachability here still unverified',
    ransomware: 'ransomware',
    ransomwareTitle: 'Used in known ransomware campaigns',
    kevAdded: (date: string) => `added ${date}`,

    colComponent: 'Component',
    colAdvisories: 'Advisories (reachability unverified)',

    nvdHeading: 'NVD · components OSV couldn’t map (affected-version match; reachability unverified)',
    /** The zero is scoped to the identity that was asked. Saying only "0 CVEs" would be the wrong claim. */
    uncheckedBefore: (name: string, version: string) =>
      `${name} ${version} came back empty under its primary CPE identity. NVD also carries it as `,
    uncheckedAfter: ', not queried — the zero is scoped to the identity asked, not to the component.',
    colAskedBy: 'Asked by',
    colCves: 'CVEs (NVD)',
    askedCpe: 'CPE version',
    askedKeyword: 'keyword',
    askedUnknown: 'not recorded',
    askedCpeTitle: 'CPE version match — NVD resolved this version against each CVE’s affected range.',
    askedKeywordTitle:
      'Keyword — matched CVE description text, which names the FIXED release rather than the vulnerable one. The weaker of the two questions.',
    askedUnknownTitle:
      'This result predates the CPE/keyword split, so which question produced it was not recorded. Re-run research to find out.',
    /** A bound states what it dropped: the row lists 8, NVD may hold far more. */
    shownOf: (shown: number, total: number) => `${shown} of ${total} shown`,
    /**
     * What this lane sent, and what it never sends.
     *
     * `research/egress.ts` builds this ledger on every run — it is the reason an operator can turn the only
     * internet-touching flag on — and nothing rendered it. A privacy claim nobody can read is not a claim.
     */
    egressHeading: 'What this lookup sent, and where',
    egressNothing: 'nothing about your firmware',
    egressAtMost: (n: number) => `at most ${n}`,
    neverSentHeading: 'Never sent, on any run:',
    shownOfTitle: (shown: number, total: number, name: string, version: string) =>
      `This row lists ${shown}. NVD matches ${total} CVEs for ${name} ${version}; the rest are not shown here.`,

    keyHeading: 'Key material · embedded keys are effectively public',
    effectivelyPublic: 'effectively public',
    effectivelyPublicTitle: 'Extractable from any device running this firmware',
    reusedIn: (n: number) => `reused in ${n} other image(s)`,

    contactsHeading: 'Responsible disclosure · security.txt',
    noSecurityTxt: 'no security.txt',
    brief: (provider: string, model: string) => `Brief · ${provider} · ${model}`,
    runLabel: 'research',
  },

  agent: {
    /** The status CODES are identifiers; only these labels are prose. */
    sessionStatus: {
      running: 'running',
      awaiting_approval: 'awaiting approval',
      done: 'done',
      error: 'error',
      halted: 'halted (governor)',
    },
    /** Node ids are identifiers too — `target-selection` is what the transcript stores. */
    node: {
      triage: '① Triage',
      extraction: 'Extraction (deterministic)',
      preflight: 'Preflight (deterministic)',
      'target-selection': '② Target selection',
      emulation: 'Emulation',
      error: 'Error',
    },

    triageClass: 'class',
    triageExtract: 'extract:',
    cascade: (chain: string) => `cascade ${chain}`,
    attackSurface: (surface: string) => `attack surface: ${surface}`,
    strategy: 'strategy',
    ceiling: 'ceiling',
    rootfsYes: '✓ rootfs',
    rootfsNo: '○ no rootfs',
    arch: 'arch',
    files: (n: string) => `${n} files`,
    noTargets: 'no targets selected',
    ran: 'ran',
    exit: 'exit',
    proofState: 'proof-state',
    tokens: (n: number) => `${n} tok`,
    audit: 'audit: inputs & decision',

    budgetSteps: 'steps',
    budgetTokens: 'tokens',
    budgetCost: 'cost',
    budgetTime: 'time',

    disabledTitle: 'Agent — conscious autonomy',
    disabledBefore: 'Disabled. Set ',
    disabledAfter:
      ' and an LLM API key to enable the decision nodes. With the flag off, FirmLab stays local-only, deterministic, no-network, no-cost.',

    sessionTitle: 'Agent session',
    running: 'Running…',
    newSession: 'New session',
    startSession: 'Start session',
    sub: 'The agent reasons within a deterministic skeleton: it chooses branches (triage ①, target selection ②) and interprets — every mechanical step is deterministic, and emulation waits for your approval. A governor caps the run.',

    approvalTitle: 'Approval required — proposed emulation',
    /** Emulation proves the sandbox, never the physical device — and nothing runs unapproved. */
    approvalSub:
      'The agent proposes running these under emulation. Emulation proves the sandbox, not the device; nothing runs without your approval.',
    approve: 'Approve & run',
    declineAll: 'Decline all',
    noSession: 'No agent session yet. Start one to have the agent triage and select targets.',
  },
};
