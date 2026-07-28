/**
 * testbench — the bench of executable questions. English source of truth.
 *
 * The wording of `outcome.means` is the claim, not decoration. `empty` must never read as "nothing is there": a
 * bounded search that ended found nothing *for this input, this budget, this question*, and `blocked` means the
 * question WAS asked and this deployment could not answer it. Both are the reason the bench separates status from
 * outcome at all, so a translation that flattens either one undoes the surface.
 *
 * Never translated: target paths, sink names, addresses, architectures, and the proof ceiling — `static_confirmed`
 * is an identifier that crosses the API. The run kinds have a human label here, but the kind itself stays as sent.
 */
export const testbench = {
  /** Panel title comes from `sections.testbench`; only what the bench itself says lives here. */
  sub: (targets: number, runs: number, examined: number) =>
    `Every executable question, grouped by what it was asked about. ${targets} target${targets === 1 ? '' : 's'} · ${runs} run${runs === 1 ? '' : 's'} · ${examined} target${examined === 1 ? '' : 's'} examined.`,

  ready: {
    filesystem: 'Filesystem',
    filesystemOk: 'extracted',
    filesystemOff: 'not extracted — no target can be run',
    arch: 'Architecture',
    archOff: 'unknown — the dynamic probe cannot pick an emulator',
    ceiling: 'Proof ceiling',
    /** The ceiling code is printed verbatim before this; the sentence is what stops it being read as a device claim. */
    ceilingNote: '— a result here describes the sandbox, never the physical device.',
  },

  filterLabel: 'Filter targets',
  filterPlaceholder: 'path contains…',

  noRootfsTitle: 'No extracted filesystem yet',
  noRootfsBody:
    "Everything on this bench runs against a binary from the image's filesystem. Run extraction on the Filesystem tab, and the binaries it recovers appear here as targets.",

  noMatchTitle: (filter: string) => `No target matches “${filter}”`,
  noMatchBody: (n: number) => `${n} binaries were recovered from this image.`,

  notExamined: 'not examined',
  runCount: (n: number) => `${n} run${n === 1 ? '' : 's'}`,
  archUnknown: 'arch unknown',
  networkFacing: ' · network-facing',
  /** Load-bearing: an empty history is a gap in the examination, never a statement about the code. */
  nothingRun:
    'Nothing has been run against this binary. An empty history means unexamined — it is not a statement about the code.',

  /** How each outcome reads. A bounded search that ended is never "nothing is there". */
  outcome: {
    label: {
      proven: 'proven',
      lead: 'lead',
      empty: 'nothing found',
      blocked: 'blocked',
      failed: 'failed',
      running: 'running',
    },
    means: {
      proven: 'A fact was established about this target.',
      lead: 'Worth pursuing. Nothing is proven yet.',
      empty: 'This run found nothing — for this input, this budget, this question. Not a clean bill of health.',
      blocked: 'The question was asked and this deployment could not answer it. This is NOT a negative result.',
      failed: 'The harness broke. No statement about the target either way.',
      running: 'Still going.',
    },
  },

  /** What each action does and what it needs, in the operator's words rather than the route's. */
  actions: {
    decompile: {
      title: 'Triage',
      gives: 'Headers, imports, symbols and strings (radare2).',
      run: 'Run triage',
    },
    symreach: {
      title: 'Reachability',
      gives: 'Whether a sink is reachable from the entry point, and at what address (angr).',
      run: 'Ask reachability',
      /** Load-bearing: a sink not reached is the end of a bounded search, not a safe sink. */
      note: 'Sinks are read from the binary’s own unbounded-copy imports. A sink not reached means the search ended, never that the sink is safe.',
    },
    dynprobe: {
      title: 'Dynamic probe',
      gives: 'Runs it under qemu with gdb on the sink: does it execute, does it crash, is the crash input-controlled.',
      needsAddress: 'Needs a sink address',
      /**
       * Split around the action name so it can be emphasised in place. `needsAddressAfter` owns whatever comes
       * between the emphasis and the rest of the sentence — a space in English, a colon in Spanish — because JSX
       * gives no space back after an element and the two languages do not want the same character there.
       */
      needsAddressBefore: 'This probe breaks on an exact call site, so it needs an address. Run',
      needsAddressAfter: ' above first — every sink it proves reachable appears here as a one-click probe.',
      probeAt: (sink: string, address: string) => `Probe ${sink} at ${address}`,
      noArch: 'Blocked: no architecture is known for this rootfs, so no user-mode emulator can be chosen.',
    },
  },

  running: 'Running…',

  /**
   * The human label for a run kind. The kind itself is an identifier and is printed as sent when unknown, and a
   * kind whose label IS a tool name (`renode`) is not here at all — the component names those.
   */
  kind: {
    dynprobe: 'Dynamic probe',
    symreach: 'Reachability',
    decompile: 'Triage',
    fuzz: 'Fuzz',
    webprobe: 'Web probe',
    emulate: 'Emulation',
  },

  ago: {
    seconds: (n: number) => `${n}s ago`,
    minutes: (n: number) => `${n}m ago`,
    hours: (n: number) => `${n}h ago`,
    days: (n: number) => `${n}d ago`,
  },
};
