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
};
