/**
 * rtosTasks — the FreeRTOS RAM-snapshot walk (`/rtos/tasks`). English source of truth.
 *
 * The walk reads bytes the ANALYST supplied, not bytes of the image, so every sentence here keeps it a lead: a
 * `complete` lane proves the supplied list chains back to its sentinel in the supplied bytes, nothing about a device.
 */
export const rtosTasks = {
  title: 'FreeRTOS task snapshot',
  sub: 'Walk the ready lists and pxCurrentTCB in a RAM snapshot you captured elsewhere (a debugger dump, a crash image). Nothing here reads the device or resolves symbols: you declare the base address, byte order and pointer width, and the addresses of the lists to walk.',
  collapsedHint:
    'Folded because this image is not classed as RTOS or bare-metal. Open it to walk a RAM snapshot anyway.',

  field: {
    file: 'RAM snapshot (raw bytes)',
    fileHint: (maxKiB: number) => `Raw memory, no container. At most ${maxKiB} KiB.`,
    fileLoaded: (bytes: number) => `${bytes.toLocaleString()} bytes loaded`,
    base: 'Memory base address',
    addressHint: 'Decimal, or hex with a 0x prefix.',
    endian: 'Byte order',
    endianChoose: 'Choose…',
    little: 'little-endian',
    big: 'big-endian',
    pointerWidth: 'Pointer width',
    pointerChoose: 'Choose…',
    bytes: (n: number) => `${n} bytes`,
    layoutHint: 'Both must be declared: a wrong default reads plausible-looking garbage, so the API has none.',
    pxCurrentTCB: 'pxCurrentTCB address (optional)',
    readyLists: 'Ready lists (pxReadyTasksLists[priority])',
    readyListsHint: (max: number) => `Optional, up to ${max}. Each priority once.`,
    priority: 'Priority',
    address: 'List address',
    addList: 'Add ready list',
    removeList: (i: number) => `Remove ready list ${i}`,
  },

  error: {
    fileMissing: 'Choose the RAM snapshot file.',
    fileEmpty: 'The file is empty; an empty snapshot answers nothing.',
    fileTooLarge: (bytes: number, maxKiB: number) =>
      `The file is ${bytes.toLocaleString()} bytes; the API accepts at most ${maxKiB} KiB.`,
    fileRead: (message: string) => `The file could not be read: ${message}`,
    base: 'Enter the base address as a non-negative integer (decimal, or hex with 0x).',
    baseRange: (bits: number) => `The base address and snapshot must fit in a ${bits}-bit address space.`,
    endian: 'Declare the byte order.',
    pointerWidth: 'Declare the pointer width.',
    address: (bits: number) => `Enter an address below 2^${bits} (decimal, or hex with 0x).`,
    priority: 'Enter a non-negative integer priority.',
    priorityRepeated: (p: number) => `Priority ${p} is already listed; each priority is walked once.`,
    tooManyLists: (max: number) => `At most ${max} ready lists.`,
    fixFields: 'Fix the highlighted fields before walking the snapshot.',
  },

  run: 'Walk snapshot',
  rerun: 'Walk again',
  running: 'Walking…',
  notRun:
    'No snapshot has been walked for this image. That is "not run", not "no tasks": supply a RAM snapshot above to read its task lists.',
  refusedHeading: 'The API refused this snapshot',
  refusedHint: 'Nothing was walked. Correct the declaration and submit again.',
  runFailedHeading: 'The walk failed',
  runFailed: 'The snapshot walk did not finish.',
  runFailedHint: 'The job started and did not finish. That is a fault on this bench, not a property of the snapshot.',

  result: {
    heading: 'Last walk',
    coverage: 'Coverage',
    coverageValue: { complete: 'complete', partial: 'partial', none: 'none' },
    proofLead:
      'Always a lead: the snapshot is operator-supplied, not bytes of this image, and nothing proves it matches a running device.',
    snapshot: (base: string, endian: string, width: number, bytes: number) =>
      `Snapshot at ${base}, ${endian}, ${width}-byte pointers, ${bytes.toLocaleString()} bytes.`,
    lanes: 'Lanes',
    col: {
      lane: 'Lane',
      priority: 'Priority',
      coverage: 'Coverage',
      nodes: 'Nodes (done / tried)',
      bytes: 'Bytes (read / tried)',
      tasks: 'Task TCBs',
    },
    currentLane: 'pxCurrentTCB',
    readyLane: (address: string) => `ready list @ ${address}`,
    noListSupplied: 'no ready list supplied',
    noTasks: 'none',
    limits: (maxKiB: number, maxItems: number, maxLists: number) =>
      `Limits applied: snapshot ≤ ${maxKiB} KiB, ≤ ${maxItems} nodes walked per list, ≤ ${maxLists} ready lists.`,
    notRecorded: 'not recorded',
  },
};
