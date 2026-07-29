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
  egressAskedOf: (server: string) => `asked of ${server}`,
  /** A question whose name did not survive the per-frame capture bound. Counted, never printed half-resolved. */
  egressTruncatedNames: (n: number) =>
    `${n} DNS question${n === 1 ? '' : 's'} were captured too short to read the name, and a truncated hostname is a different hostname.`,
};
