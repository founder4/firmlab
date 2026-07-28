/**
 * panels — the worker panels: the autonomous scan (W9, `opacidad`), symbolic reachability, AFL++ fuzzing, the active
 * web probe and the saved emulation presets. English source of truth; adding a key here makes the Spanish file fail
 * to compile until it is translated.
 *
 * These five screens are where the proof ladder is explained to a reader, so four of their sentences are the product
 * rather than decoration, and none of them may soften in any language:
 *
 *  - symreach — a BOUNDED search that did not reach a sink has proven nothing about that sink. The outcome keeps the
 *    finding at `needs_runtime_reproduction`; an exhausted search is never a downgrade to `false_positive`, and a
 *    rendering in which "not reached" can be read as "not exploitable" inverts the claim the panel exists to make.
 *  - fuzz — a campaign that found no crash inside its budget is an honest negative about that harness for that long.
 *    It is not a clean binary.
 *  - webprobe — a reproduced hit is `confirmed_in_emulation`: it proves the sandbox, never the physical device. The
 *    sentence saying so is not restated here, it is used from `proofState`, so the two can never drift apart.
 *  - opacidad — a stage reported `not-built` or `skipped` is not a stage that passed. Nothing was asked of it, and
 *    the panel says which those were rather than letting a short findings list read as a clean image.
 *
 * What is never translated: proof states, finding kinds, job and run kinds, source strings, severities, worker and
 * stage ids, emulation modes (`user-qemu`, `system-qemu`…), sink names, tool names (`AFL++`, `angr`, `qemu`, `gdb`),
 * env var names and binary paths. They cross the API and land in SQLite — translating one would change data, not
 * presentation. A sentence built around one is therefore stored as the runs of prose either side of it, in render
 * order, and the panel puts the identifier back between them.
 */
export const panels = {
  opacidad: {
    title: 'Autonomous scan (opacidad)',
    sub: [
      'Plan the class-appropriate worker chain, run it end-to-end, and compose the reasoning trace — one action',
      'instead of clicking each provider by hand. Honest by design: skipped and not-yet-built workers are shown,',
      'never hidden.',
    ].join(' '),
    run: 'Run autonomous scan',
    rerun: 'Re-run autonomous scan',
    running: 'Scanning…',
    failed: 'Autonomous scan failed',
    /** Precedes `narrativeSource`, which is a value (`deterministic` / `llm`) and is printed as sent. */
    narrativeLabel: 'narrative:',
    narrativeTitle: 'How the narrative was written',
    replanned: 're-planned',
    /**
     * The gloss for a step's status, shown on the status mark. The status CODE is an identifier and opens each
     * sentence verbatim; what follows is the part that matters — `skipped` and `not-built` are stages nothing was
     * asked of, and a reader who takes either for a pass has read the scan backwards.
     */
    status: {
      ran: 'ran — the worker executed and what it reports is below.',
      degraded: 'degraded — it ran without something it wanted. Read its note before reading its silence.',
      skipped: 'skipped — it had no input to work on. The question was never asked, so nothing passed.',
      'not-built': 'not-built — this worker does not exist yet. The question was never asked, so nothing passed.',
    },
    workers: 'Workers',
    findings: (n: number) => `Findings (${n})`,
    noFindings: [
      'No findings surfaced by the workers that ran. That is a statement about the workers above — the ones skipped',
      'or not yet built asked nothing at all — and never a clean bill for this firmware.',
    ].join(' '),
    attackPath: 'Attack path (chain of evidence)',
    narrative: 'Narrative',
    honestGaps: 'Honest gaps — what did NOT run',
    /** The operator's noun for these runs, handed to `RunHistory` — which builds the whole sentence per language. */
    runLabel: 'autonomous-scan',
  },

  symreach: {
    title: 'Symbolic reachability (angr)',
    /** Around the italicised question and the emphasised `reachability`, in render order. */
    sub: {
      lead: 'One checkable question per sink:',
      question: 'is that call site reachable from the entry point under symbolic argv/stdin?',
      provesLead: 'A reached sink proves',
      reachability: 'reachability',
      provesTail: [
        ', not exploitability. A sink not reached proves nothing at all — the search is bounded, so it stays a',
        'lead.',
      ].join(' '),
    },
    /**
     * How each outcome is allowed to read. The outcome CODES (`reached`, `not_reached_in_budget`, `absent`,
     * `skipped`) are identifiers and never appear translated; these are their labels, and nothing but `reached`
     * is allowed to sound affirmative — least of all the bounded one.
     */
    outcome: {
      reached: 'reachable from entry',
      not_reached_in_budget: 'inconclusive — search bounded',
      absent: 'symbol not in this binary',
      skipped: 'not asked — run budget spent',
    },
    binaryPlaceholder: 'rootfs-relative binary, e.g. usr/sbin/bpalogin',
    sinksPlaceholder: 'sinks (blank = derive from imports)',
    sinksLabel: 'Sink symbols to ask about',
    budget: 'budget',
    budgetLabel: 'Budget in seconds',
    ask: 'Ask',
    probing: 'Probing…',
    probeFailed: 'probe failed',
    /** Around the `strcpy` · `system` · `sscanf` examples and the italicised `absent`. */
    hint: {
      lead: 'Sinks are function symbols —',
      beforeAbsent: [
        '. Leave blank to ask about whichever unbounded-copy functions this binary imports. A symbol the binary does',
        'not import comes back as',
      ].join(' '),
      absentWord: 'absent',
      afterAbsent: ', not as a clean result.',
    },
    notAnswered: 'Not answered',
    notAnsweredHint: (binary: string) =>
      `This is a missing capability, not a clean result — nothing about ${binary} was ruled out.`,
    unknownArch: 'unknown arch',
    entry: 'entry',
    reachableCount: (reached: number, total: number) => `${reached}/${total} reachable`,
    derivedSinks: 'sinks derived from imports',
    /** A bound is not an answer: it says what it dropped and by what rule. */
    dropped: (n: number) => `${n} sink(s) not asked (per-run cap)`,
    pathFound: 'path found',
    steps: (n: number) => `${n} steps`,
    pathTail: 'path tail:',
    noReason: 'no reason recorded',
    pruned: 'states pruned to stay in the memory bound',
    errors: (n: number) => `${n} state(s) lost to angr-internal errors`,
    reachedNote: [
      'A reached sink means the call site is on a feasible path from the entry point with an input that walks it.',
      'Whether the copy overflows, and whether that is exploitable, are separate questions this does not answer.',
    ].join(' '),
    /**
     * The sentence this panel exists for, built around the two proof states it must keep apart. An exhausted search
     * is an inconclusive: the sinks stay leads, and none of them becomes a false positive because a budget ran out.
     */
    notReached: {
      lead: [
        'Nothing was reached inside the budget. That is not evidence of unreachability — indirect jumps and',
        'unmodelled syscalls routinely hide real paths from a bounded search. Every sink above keeps',
      ].join(' '),
      beforeFalsePositive: '— an exhausted search is never a downgrade to',
      tail: '. Raise the budget or fuzz the binary.',
    },
    runLabel: 'reachability',
  },

  fuzz: {
    title: 'Coverage-guided fuzzing (AFL++)',
    runnable: 'runnable',
    optIn: 'opt-in layer',
    sub: [
      'Fuzz one extracted binary under the isolation sandbox (qemu mode). A reproduced crash is recorded as a',
      'confirmed finding; finding nothing is an honest result, not a pass.',
    ].join(' '),
    /** Around `Dockerfile.firmware`. An absent tool is an absent answer — the panel offers no run and fakes none. */
    notInstalled: {
      lead: "AFL++ isn't installed in this deployment — enable the opt-in layer in",
      tail: '(afl-fuzz + afl-qemu-trace). Nothing is faked without it.',
    },
    needBinary: 'Enter a rootfs binary path to fuzz (e.g. bin/busybox).',
    harnessLabel: 'Harness',
    harnessTitle: 'How the fuzzed input reaches the target',
    run: 'Fuzz',
    stat: {
      binary: 'Binary',
      execs: 'Execs',
      crashes: 'Crashes',
      isolation: 'Isolation',
    },
    /**
     * Around the `fuzz-crash` finding kind. `tail` owns whatever follows the identifier — a space and a clause in
     * English, a bare colon in Spanish — because the two languages do not want the same character there.
     */
    crashInputs: {
      lead: 'Crash inputs (first bytes) — a',
      tail: ' finding was recorded:',
    },
    noCrash: [
      'No crash in the time budget — an honest negative, not a guarantee of safety. It says this binary survived',
      'this harness for this budget, and says nothing about a longer run, another harness or another seed.',
    ].join(' '),
    /** The noun `RunHistory` puts in its sentence. English says "fuzz runs" where Spanish says "de fuzzing". */
    runLabel: 'fuzz',
  },

  webprobe: {
    title: 'Active web probe',
    /**
     * Around `confirmed_in_emulation`, whose meaning is NOT restated here: the panel prints the shared gloss from
     * `proofState`, so the sentence about proving the sandbox and never the device has exactly one wording per
     * language. `chroot-service` and `full-system` are emulation rungs the API names, and stay as they are.
     */
    sub: {
      lead: [
        'Drive a booted service (chroot-service / full-system) for command injection and path traversal. A',
        'reproduced hit is recorded as',
      ].join(' '),
      /** Introduces the shared gloss, which follows the code and is owned by `proofState`. */
      means: ', which means:',
      tail: 'Loopback / private targets only.',
    },
    probe: 'Probe',
    probeFailed: 'probe failed',
    reachable: 'reachable',
    unreachable: 'unreachable',
    requests: (n: number) => `${n} requests`,
    points: (n: number) => `${n} injection points`,
    reproduced: (n: number) => `${n} reproduced`,
    runLabel: 'web-probe',
  },

  presets: {
    title: 'Saved presets',
    sub: 'Save a named emulation config and re-run it in one click.',
    /** The MODE is an identifier the API dispatches on (`user-qemu`…); only its human label is localised. */
    mode: {
      'user-qemu': 'User-mode QEMU',
      'chroot-qemu': 'Chroot service',
      'system-qemu': 'Full-system QEMU',
      renode: 'Renode (RTOS boot)',
      'uefi-chipsec': 'chipsec (UEFI checks)',
    },
    namePlaceholder: 'preset name',
    binaryPlaceholder: 'bin/httpd (optional)',
    save: 'Save preset',
    remove: 'Delete this preset',
    started: (name: string, jobId: string) => `Started "${name}" (job ${jobId}) — see the job log in the panels above.`,
  },
};
