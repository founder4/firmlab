/**
 * simulation — the emulation control surface. English source of truth.
 *
 * Two claims here are the panel's reason to exist and must survive translation intact. A rung that cannot run says
 * WHY — `needsTools` is a badge, `requires` is the sentence naming what this deployment would have to install —
 * because "no button" reads as "not applicable to this firmware", which is a different and false statement. And
 * `sandboxCaveat`: a rung that boots proves the emulator accepted the image. It proves nothing about the board.
 *
 * Never translated: the emulation modes (`user-qemu`, `system-qemu`, `renode`, `uefi-chipsec`), the command lines,
 * tool names, job ids and statuses, proof states, and the recipe title/description/notes the API composes — those
 * are written by the provider that planned the run.
 */
export const simulation = {
  loading: 'Loading emulation plan…',

  needsRootfs: 'User-mode emulation needs an extracted rootfs. Run extraction first (requires binwalk).',
  extractNow: 'Extract now',

  runnable: 'runnable',
  needsTools: 'needs tools',
  /** Names what is missing rather than leaving a rung silently button-less. The tool names are not translated. */
  requires: (tools: string) => `Not runnable in this deployment: it requires ${tools}.`,
  /** Load-bearing: emulation proves the sandbox, never the physical device. */
  sandboxCaveat:
    'Emulation proves the sandbox, never the physical device. A rung that boots here shows this emulator accepted the image — not that the board behaves the same way.',

  targetBinary: 'Target binary',
  selectBinary: 'Select a binary…',
  suggested: (path: string) => `suggested: ${path}`,
  binaryPlaceholder: 'run Extraction to list binaries',

  bootRenode: 'Boot under Renode',
  decodeScan: 'Decode & scan',
  runProof: 'Run proof',

  job: (id: string) => `Job ${id}`,
  booted: 'booted',
  noUart: 'no UART output',
  timedOut: 'timed out (likely a long-running daemon)',

  moduleCount: (n: number) => `${n} module${n === 1 ? '' : 's'}`,
  noUefiVolume: 'no UEFI volume',
  volumeCount: (n: number) => `${n} FV`,
  secureBoot: 'Secure Boot:',
  setupMode: (mode: string) => `${mode} mode`,
  testKey: (key: string) => `test key: ${key}`,
  nvramVars: (n: number) => `${n} NVRAM var(s)`,

  /**
   * The verdict on an empty `open` list. It is a HEADING only: the sentence under it is composed by
   * `boot-diagnose.ts` from the guest's own trace and renders as the provider wrote it, because it quotes exit
   * codes, file paths and packet counts — measurements, not chrome.
   */
  unreachableTitle: 'Why nothing answered',

  /**
   * The daemons the boot trace saw. `noneStarted` is NOT "they all died" — it is that nothing looking like a
   * network daemon was ever executed, which is a different thing to go and fix.
   */
  daemons: {
    heading: 'Network daemons on this boot',
    noneStarted: 'No network daemon was ever executed on this boot — nothing died, nothing was started.',
    crashed: (signal: string, code: number) => `${signal} (exit ${code})`,
    exited: (code: number) => `exited ${code}`,
    exitedTitle: 'This daemon is not running. Forwarding more ports cannot reach a process that already exited.',
    running: 'started, did not exit',
    runningTitle:
      'The trace saw it start and never saw it go. If its port was probed and nothing came back, the daemon is not the thing to fix.',
    lastOpen: 'last open:',
  },

  /**
   * Where the booted firmware tried to go. Two words carry this block and neither may soften in translation:
   * the firmware ADDRESSED these — a SYN into a black hole looks identical from the sending side — and whether
   * it was ALLOWED to get there is a property of the run, not of the firmware.
   *
   * Never translated: the addresses, the port numbers, the protocol names and the hostnames. Those are what was
   * on the wire.
   */
  egressTitle: 'Where it tried to go',
  egressBlocked: 'outbound blocked',
  egressOpen: 'outbound open',
  /** The state an operator must not misread as safety — this run could reach the internet. */
  egressOpenWarning:
    'This boot was NOT isolated: the firmware could reach these from this machine. Turn on FIRMLAB_EMU_ISOLATE in Settings to keep this list and drop the reachability.',
  egressIsolatedNote:
    'This boot was isolated, so nothing below was reached. Blocking the traffic does not hide the attempt — this is what the firmware asked for.',
  /**
   * Measured, not cautious boilerplate: three boots of one WDR3600 gave 15 external destinations, 0, and the same
   * 15 again — the empty one differing from its own isolated twin, not from the permissive run. A boot is a
   * sample of what this firmware does, so one list is a floor and never a total.
   */
  egressOneBoot:
    'One boot is one sample. The same firmware booted twice does not always reach the same point, so this list is a floor and not a total — a destination missing here may simply not have been tried in this run.',
  egressNames: 'Names it asked to resolve',
  egressDestinations: 'Addresses it aimed at',
  egressNone: 'The guest addressed nothing beyond the emulator during this run.',
  egressScope: {
    external: 'beyond the emulator',
    emulator: 'the emulator itself',
    local: 'its own subnet',
    multicast: 'announcement',
  },
  egressFrames: (n: number) => `${n} frame${n === 1 ? '' : 's'}`,
  /**
   * The frames the workbench itself provoked.
   *
   * A boot of the MR3220 rendered ~150 rows of `10.0.2.2:<ephemeral>` here — every one the guest ANSWERING a
   * port-forward this bench opened to probe it, listed under a heading that says the firmware aimed there. The
   * count stays visible rather than the frames simply vanishing: they were on the wire, they were the guest's,
   * and they are a measurement of what the bench did.
   */
  egressAnswered: (n: number) =>
    `${n} frame${n === 1 ? '' : 's'} were this guest ANSWERING connections opened from outside it — the probes this workbench sent — so they are not listed above. They are not destinations the firmware chose.`,
  /** A frame whose TCP flags were cut off by the capture length: kept in the list, because losing a real attempt
      is the worse error, and named so the list reads as the partly-undecided thing it is. */
  egressUndecided: (n: number) =>
    `${n} TCP frame${n === 1 ? '' : 's'} were captured too short to read the flags, so whether the guest opened those flows is undecided. They are listed above rather than dropped.`,
  /** A bound that truncates says what it dropped and by what rule — never by arrival order. */
  egressDropped: (n: number) =>
    `${n} further destination${n === 1 ? '' : 's'} went past this run's limit and are not listed. The ones shown are those with the most frames, never the first to arrive.`,
  egressQueriesDropped: (n: number) => `${n} further name${n === 1 ? '' : 's'} went past this run's limit.`,
  /** The on-screen cap, which is not the parser's. Stated for the same reason. */
  egressMore: (shown: number, total: number) =>
    `Showing the ${shown} most-addressed of ${total}. The rest are in the run's stored result.`,
  egressAskedOf: (server: string) => `asked of ${server}`,
  /** A question whose name did not survive the per-frame capture bound. Counted, never printed half-resolved. */
  egressTruncatedNames: (n: number) =>
    `${n} DNS question${n === 1 ? '' : 's'} were captured too short to read the name, and a truncated hostname is a different hostname.`,
};
