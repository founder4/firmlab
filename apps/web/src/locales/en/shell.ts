/**
 * shell — the chrome that is on screen whatever section the reader is in. English source of truth.
 *
 * Four surfaces share this namespace because they share a failure mode: each is a FRAME around somebody else's
 * panel, each renders on every image, and a frame left in English beside a translated panel is the most visible
 * half-translation there is. The step timeline was exactly that — `Entropy · Extraction · Bootloader · Binaries`
 * running across the top of fully Spanish panels.
 *
 * **The timeline's step labels are deliberately NOT here.** Its step ids ARE section ids, and the sections
 * namespace already names every one of them. A second copy would drift the first time one of the two gained a
 * stage, and the reader would be told that one screen has two names. Only the pipeline's accessible name, the
 * node states and the tooltip's shape belong here.
 *
 * **What the two provider surfaces must never let a reader conclude.** `capabilities` reports which tools this
 * deployment has; `deep` offers the providers that use them. An absent tool is an absent ANSWER — the question
 * was not asked, and a greyed-out row is a statement about this machine, not about the firmware. That is the one
 * claim a translation can quietly invert, by letting "we could not look" read as "we looked and it was fine", so
 * both languages state it outright rather than implying it.
 *
 * Tool names (`binwalk`, `radare2`, `qemu`, `Ghidra`, `AFL++`, `Renode`, `chipsec`), job kinds, architectures,
 * env var names and file paths are identifiers. They render verbatim in every language.
 */
export const shell = {
  /**
   * StepTimeline — the pipeline strip pinned under the top bar. The labels come from the sections catalogue; what
   * is here is everything the strip says ABOUT a step rather than what it calls it.
   */
  timeline: {
    /** The nav landmark's accessible name, announced before its eight buttons. */
    label: 'Analysis pipeline',
    /**
     * The node states, as they appear in a step's tooltip. These are UI states, not proof states — `blocked` here
     * means this deployment cannot run that stage, and `blocked_by_platform` remains the identifier it always was.
     */
    state: {
      done: 'done',
      running: 'running',
      blocked: 'blocked',
      pending: 'pending',
    },
    /** `<section> — <state>`. A separate key so a language that punctuates or orders it differently can say so. */
    stepTitle: (section: string, state: string) => `${section} — ${state}`,
    /**
     * The chip under the Emulation node when the architecture cannot be emulated here. It draws the same line the
     * proof states draw: the question was asked and this deployment could not answer it — never a negative result.
     */
    blocked: 'blocked',
  },

  /**
   * Capabilities — what this deployment can and cannot do. Every tool name and version string in the table is an
   * identifier; the prose around them is what lives here.
   */
  capabilities: {
    /** Around the emphasised `no external tools`. */
    engineLead: "FirmLab's static engine (structure map, entropy, strings, identity) needs",
    engineStrong: 'no external tools',
    engineTail: [
      'The tools below are optional enhancements — build the firmware Docker image to unlock extraction,',
      'decompilation, SBOM/CVEs and emulation.',
    ].join(' '),

    title: 'Detected tools',
    probing: 'Probing…',
    counted: (available: number, total: number) => `${available} of ${total} available in this deployment`,
    /**
     * The sentence this page exists for, and the reason it is stated rather than implied. A row with no tool
     * behind it is a question this deployment cannot ask, so every provider that needs it degrades and says so.
     * Read the other way round — an absent tool as an absent problem — the page becomes a clean bill of health
     * nobody earned.
     */
    absentAnswer: [
      'A tool missing here is an absent ANSWER, not an absent problem: the providers that need it report',
      'themselves unavailable and say why, and none of them returns a clean result it did not earn.',
    ].join(' '),
    notFound: 'not found',

    /** The tool groups. The group ids (`extract`, `analyze`…) cross the API and are never translated. */
    group: {
      extract: 'Extraction',
      analyze: 'Binary analysis',
      sbom: 'SBOM & CVEs',
      secrets: 'Secret scanning',
      emulate: 'Emulation',
    },
  },

  /**
   * AnalysisActionsPanel — the offline providers, grouped by the question the reader is asking rather than by our
   * module layout. `AnalysisKind` is the key of each provider entry and is an identifier: it crosses the API.
   */
  deep: {
    title: 'Deep analysis',
    sub: [
      "Offline providers that enrich the dossier. Findings are added to the image's findings ledger; each degrades",
      'honestly when its input or tool is absent — it reports the question it could not ask rather than returning',
      'an empty result that reads as clean.',
    ].join(' '),

    group: {
      boot: 'Boot & platform',
      filesystem: 'Filesystem & configuration',
      update: 'Update & supply chain',
      device: 'Device & radio',
    },

    provider: {
      uboot: {
        title: 'U-Boot / bootloader',
        desc: 'Decode the U-Boot env and audit boot posture (root-shell args, interruptible autoboot, net-boot).',
      },
      devicetree: {
        title: 'Device tree',
        desc: 'Read the board description the image carries — SoC, flash map, peripherals and the kernel command line.',
      },
      kernel: {
        title: 'Kernel posture',
        desc: [
          'Kernel version and age, plus KASLR, /dev/kmem, module signing and RWX — each answered on, off, or not',
          'determinable.',
        ].join(' '),
      },
      fsaudit: {
        title: 'Rootfs security audit',
        desc: [
          'firmwalker-style checks: weak/empty credentials, root shells, telnetd, permissive service configs, key',
          'material.',
        ].join(' '),
      },
      certs: {
        title: 'Certificates (X.509)',
        desc: 'Parse embedded certificates — expired, weak RSA, test/self-signed, embedded CA.',
      },
      services: {
        title: 'Service enumeration',
        desc: [
          'Map the network daemons the rootfs is configured to start (init scripts, inetd, systemd) — the attack',
          'surface.',
        ].join(' '),
      },
      updatepath: {
        title: 'Update-path integrity',
        desc: 'Does the image carry a signature, does the updater verify anything, is there rollback protection?',
      },
      compmap: {
        title: 'Component map',
        desc: 'Map each rootfs ELF to its shared-library dependencies (needs radare2).',
      },
      rtos: {
        title: 'RTOS / bare-metal blob',
        desc: 'Recover the Cortex-M vector table + memory map and detect the RTOS kernel.',
      },
      fcc: {
        title: 'FCC ID lookup',
        desc: [
          "Extract FCC IDs and link to the device's public filings (photos, manuals, internal photos, test",
          'reports).',
        ].join(' '),
      },
    },

    /** The badge under a finished tile. A count, and — when it is zero — a word that is not a verdict. */
    findings: (n: number) => `${n} finding${n === 1 ? '' : 's'}`,
    noFindings: 'no findings',
    overviewLabel: 'Deep-analysis coverage',
    overview: (ran: number, total: number): string => `${ran} of ${total} with a stored answer`,
    running: (n: number): string => `${n} running`,
    errors: (n: number): string => `${n} failed`,
    pending: (n: number): string => `${n} not run`,
    loading: 'Reading previous runs…',
    runningBody: 'The result will appear here when the provider finishes.',
    notRun: 'Not run yet',
    notRunBody: 'There is no stored answer for this question.',
    completed: 'completed',
    runAgain: 'Run again',
    runProvider: (name: string): string => `Run ${name}`,
    runAgainProvider: (name: string): string => `Run ${name} again`,
    runningProvider: (name: string): string => `${name} is running`,
    resultDetails: 'Collected data',
    details: {
      yes: 'yes',
      no: 'no',
      unknown: 'unknown',
      environment: 'Environment variables',
      variable: 'Variable',
      variables: 'Variables',
      value: 'Value',
      bootScript: 'Boot script reading',
      roots: 'Entry variables',
      variants: 'Assembled kernel command lines',
      via: 'via',
      conditional: 'conditional branch',
      searched: 'Places searched',
      rejected: 'Rejected device-tree candidates',
      trees: 'Device trees',
      origin: 'Origin',
      model: 'Model',
      compatible: 'Compatible',
      bootargs: 'Kernel command line',
      partitions: 'Flash partitions',
      peripherals: 'Peripherals',
      kernelSummary: 'Kernel summary',
      version: 'Version',
      age: 'Kernel line age',
      years: (n: number): string => `${n} years`,
      modules: 'Modules',
      signed: 'signed',
      controls: 'Posture controls',
      option: 'Control',
      verdict: 'Verdict',
      evidence: 'Evidence',
      coverage: 'Coverage',
      files: 'Files',
      bytes: 'Bytes read',
      certificates: 'Certificates',
      subject: 'Subject',
      issuer: 'Issuer',
      validity: 'Validity',
      key: 'Key',
      bits: (n: number): string => `${n} bit`,
      selfSigned: 'Self-signed',
      services: 'Configured services',
      name: 'Name',
      binary: 'Binary',
      source: 'Configured in',
      network: 'Network-facing',
      autostart: 'Autostart',
      port: 'Port',
      updateCoverage: 'Update-path coverage',
      container: 'Container',
      integrity: 'Image-integrity mechanisms',
      updaters: 'Updater candidates',
      rollback: 'Rollback protection',
      digests: 'Digest routines',
      signatureChecks: 'Signature checks',
      componentSummary: 'Component-map summary',
      binaries: 'ELFs examined',
      dependencies: 'Dependency edges',
      unresolved: 'Unresolved libraries',
      symlinks: 'Symlinks indexed',
      orphaned: 'Unreferenced binaries',
      openComponentMap: 'Open the full component map',
      rtosSummary: 'RTOS / bare-metal reading',
      cortexM: 'Cortex-M image',
      rtosKernel: 'RTOS kernel',
      initialSp: 'Initial stack pointer',
      resetHandler: 'Reset handler',
      flashBase: 'Flash base',
      ramBase: 'RAM base',
      fccIds: 'FCC identifiers',
      filing: 'FCC filing',
      mirror: 'Public files',
      findings: 'Recorded findings',
      proof: 'Proof state',
      noItems: 'None recorded.',
      notRecorded: 'Not recorded by this run.',
      countMore: (shown: number, total: number): string =>
        `Showing ${shown} of ${total}; use the dedicated view for the complete graph.`,
    },
    lastRun: (when: string): string => `last run ${when}`,
    refreshFailed: (error: string): string => `Previous results could not be refreshed: ${error}`,
    /** Fallback when the job row carries no error text of its own. */
    failed: 'failed',
  },

  /**
   * RunHistory — the runs behind the one result a panel is showing.
   *
   * The heading used to be assembled at the render site as `{n} {label} run{s} on this image`, with the noun
   * arriving from the caller. That is English grammar with a hole in it: a Spanish noun in the hole produced
   * *"2 análisis profundo runs on this image"*, half a sentence in each language. The whole sentence is a
   * catalogue function of the count and the noun now, so each language decides its own agreement, its own word
   * order and where the noun goes.
   */
  runHistory: {
    heading: (n: number, kind: string) => `${n} ${kind} run${n === 1 ? '' : 's'} on this image`,
    show: 'show history — the panel above shows only the most recent',
    hide: 'hide history — the panel above shows only the most recent',

    /**
     * The operator's noun for a panel's runs — what the panel calls them, never the job kind, which is an
     * identifier and renders verbatim on every row below. A panel names the key; the catalogue owns the word, so
     * a panel adopting `runKind` adds its noun here rather than passing a literal through the sentence.
     */
    kind: {
      deepAnalysis: 'deep-analysis',
    },

    /**
     * What each outcome means, in the tooltip. `empty` and `blocked` are the pair that must never converge: a
     * provider whose tool was missing and one that genuinely found nothing are different statements about the
     * world, and the ledger keeps them apart precisely so this list can.
     */
    outcome: {
      proven: { label: 'proven', means: 'A fact was established.' },
      lead: { label: 'lead', means: 'Worth pursuing. Nothing is proven yet.' },
      empty: {
        label: 'nothing found',
        means: 'This run found nothing — for its input, its budget, its question. Not a clean bill of health.',
      },
      blocked: {
        label: 'blocked',
        means: 'The question was asked and this deployment could not answer it. NOT a negative result.',
      },
      failed: { label: 'failed', means: 'The harness broke. No statement either way.' },
      running: { label: 'running', means: 'Still going.' },
    },

    /** Elapsed time, one key per unit, so a language can put its preposition wherever it belongs. */
    ago: {
      seconds: (n: number) => `${n}s ago`,
      minutes: (n: number) => `${n}m ago`,
      hours: (n: number) => `${n}h ago`,
      days: (n: number) => `${n}d ago`,
    },
  },
};
