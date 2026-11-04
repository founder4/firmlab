/**
 * rtosTasks — the FreeRTOS RAM-snapshot walk (`/rtos/tasks`). English source of truth.
 *
 * The walk reads bytes the ANALYST supplied, not bytes of the image, so every sentence here keeps it a lead: a
 * `complete` lane proves the supplied list chains back to its sentinel in the supplied bytes, nothing about a device.
 */
export const rtosTasks = {
  title: 'FreeRTOS task snapshot',
  sub: "Walk the ready lists and pxCurrentTCB in a RAM snapshot you captured elsewhere (a debugger dump, a crash image). Nothing here reads the device: you declare the base address, byte order and pointer width, and the addresses of the lists to walk — which you can pre-fill from the image's own ELF symbol table when it has one.",
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
    bits: (n: number) => `${n}-bit`,
    tickWidth: 'TickType_t width',
    useMiniListItem: 'Use configUSE_MINI_LIST_ITEM',
    useListDataIntegrityCheckBytes: 'Use configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES',
    listOptionsHint:
      'The initial value preserves the historical 32-bit tick layout; mini list item is on and integrity words are off. Declare the build options; they are never inferred from RAM.',
    layoutHint: 'Both must be declared: a wrong default reads plausible-looking garbage, so the API has none.',
    pxCurrentTCB: 'pxCurrentTCB address (optional)',
    uxTopReadyPriority: 'uxTopReadyPriority address (optional)',
    topReadyRepresentation: 'uxTopReadyPriority representation',
    topReadyChoose: 'Choose when an address is supplied…',
    topReadyPriorityMode: 'priority (generic task selection)',
    topReadyBitmapMode: 'bitmap (port-optimized task selection)',
    topReadyHint:
      'Declare the build mode; the same scalar has different meaning under configUSE_PORT_OPTIMISED_TASK_SELECTION and is never guessed from RAM.',
    readyLists: 'Ready lists (pxReadyTasksLists[priority])',
    readyListsHint: (max: number) => `Optional, up to ${max}. Each priority once.`,
    priority: 'Priority',
    address: 'List address',
    addList: 'Add ready list',
    removeList: (i: number) => `Remove ready list ${i}`,
    readyArray: 'Or the whole ready-list array (pxReadyTasksLists)',
    readyArrayHint:
      "Instead of individual lists: the array address and the two numbers your build declares. Every priority is then walked. sizeof(List_t) is checked against pointer and TickType_t width plus the two declared FreeRTOS list options, never used blind. The symbol's st_size, in bytes, is an optional cross-check.",
    arrayBase: 'pxReadyTasksLists address',
    maxPriorities: 'configMAX_PRIORITIES',
    listSize: 'sizeof(List_t)',
    symbolSize: 'st_size (optional)',
    stateLists: 'Other task state lists (optional)',
    stateListsHint:
      'Each is the address of a List_t, like a ready list. Leave a field empty to skip that list: the result then names it as not walked, never as empty.',
    delayedList: 'Delayed list (the List_t pxDelayedTaskList points to)',
    overflowDelayedList: 'Overflow delayed list (the List_t pxOverflowDelayedTaskList points to)',
    suspendedList: 'Suspended list (xSuspendedTaskList)',
    pendingReadyList: 'Pending-ready list (xPendingReadyList)',
    terminatedList: 'Waiting-termination list (xTasksWaitingTermination)',
    delayedHint:
      'xDelayedTaskList1 and xDelayedTaskList2 swap roles every time the tick count wraps. Read the two pointers in the snapshot to know which is the current list and which the overflow list.',
    eventLists: 'Queue/semaphore and Event Group wait lists (optional)',
    eventListsHint: (max: number) =>
      `Up to ${max} caller-resolved List_t addresses such as Queue_t.xTasksWaitingToReceive or EventGroup_t.xTasksWaitingForBits. Queue waits are priority ordered; Event Group waits are unordered and their control byte is decoded relative to TickType_t. Requires configUSE_CO_ROUTINES=0 so pvOwner is a TCB.`,
    eventName: 'Object.member name',
    eventKind: 'Wait kind',
    eventKindChoose: 'Choose…',
    queueReceive: 'receive / take',
    queueSend: 'send',
    eventGroup: 'Event Group bits',
    eventOwnersAreTcbs: 'I confirm configUSE_CO_ROUTINES=0; every pvOwner is a task TCB.',
    addEventList: 'Add wait list',
    removeEventList: (i: number) => `Remove wait list ${i}`,
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
    topReadyRepresentation: 'Choose the representation used by this FreeRTOS build.',
    bitmapPriorities: 'The supported optimized bitmap domain is at most 32 priorities.',
    priority: 'Enter a non-negative integer priority.',
    priorityRepeated: (p: number) => `Priority ${p} is already listed; each priority is walked once.`,
    tooManyLists: (max: number) => `At most ${max} ready lists.`,
    tooManyEventLists: (max: number) => `At most ${max} queue/semaphore or Event Group wait lists.`,
    eventName: 'Enter a C identifier or one object.member path.',
    eventNameRepeated: (name: string) => `${name} is already listed; each wait list needs one audit label.`,
    eventKind: 'Choose the declared wait-list semantics.',
    eventOwnersAreTcbs: 'Confirm configUSE_CO_ROUTINES=0 before interpreting pvOwner as a task TCB.',
    addressRepeated: (address: string) => `${address} is already listed; each list is walked once.`,
    arrayAndLists: 'Declare the ready-list array or individual ready lists, not both: each list is walked once.',
    arrayBase: 'The array needs its address; take it from the pxReadyTasksLists symbol.',
    maxPriorities: (max: number) => `Enter configMAX_PRIORITIES as a whole number from 1 to ${max}.`,
    listSize: (expected: number) =>
      `The declared pointer/tick ABI and FreeRTOS list options produce a ${expected}-byte List_t.`,
    listSizeNumber: 'Enter sizeof(List_t) as a positive whole number of bytes.',
    symbolSize: 'Enter st_size as a whole number of bytes, or leave it empty.',
    arrayOverflow: (base: string, bytes: number, bits: number) =>
      `An array at ${base} spanning ${bytes} bytes does not fit the ${bits}-bit address space.`,
    symbolSizeMismatch: (size: number, n: number, list: number) =>
      `st_size is ${size} bytes but ${n} × ${list} is ${n * list}; one of the three numbers is wrong.`,
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
    snapshot: (base: string, endian: string, width: number, tick: number, bytes: number) =>
      `Snapshot at ${base}, ${endian}, ${width}-byte pointers, ${tick}-byte TickType_t, ${bytes.toLocaleString()} bytes.`,
    lanes: 'Lanes',
    col: {
      lane: 'Lane',
      priority: 'Priority',
      coverage: 'Coverage',
      nodes: 'Nodes (done / tried)',
      bytes: 'Bytes (read / tried)',
      integrity: '0x5a markers',
      tasks: 'Task TCBs',
      state: 'State',
    },
    stateLanes: 'State lists',
    stateLane: (name: string, address: string) => `${name} @ ${address}`,
    kind: {
      ready: 'ready',
      delayed: 'delayed',
      delayed_overflow: 'delayed (overflow)',
      suspended: 'suspended',
      pending: 'pending ready',
      event: 'queue/semaphore wait',
      event_group: 'Event Group wait',
      terminated: 'waiting termination',
    },
    waitKind: { queue_receive: 'receive / take', queue_send: 'send', event_group: 'Event Group bits' },
    secondDelayed: 'the second delayed list',
    wakeTick: (tcb: string, tick: number | string) => `${tcb} wakes at tick ${tick}`,
    eventOrder: (tcb: string, value: number | string) =>
      `${tcb} priority key ${value} (smaller means higher priority; this is not a tick)`,
    eventBits: (tcb: string, bits: number | string, waitForAll: boolean, clearOnExit: boolean) =>
      `${tcb} waits for ${waitForAll ? 'all' : 'any'} of bits ${bits}${clearOnExit ? ', clearing them on exit' : ''}`,
    integrityValue: (reads: string, mismatches: number) => `${reads}; ${mismatches} mismatch(es)`,
    integrityDisabled: 'disabled',
    notWalked: (kinds: string) =>
      `Not walked, because not supplied: ${kinds}. Tasks in those states are not in this result.`,
    severalLists: (n: number, tcbs: string) =>
      `${n} TCB(s) appear on more than one state list (${tcbs}). A consistent snapshot cannot produce that; it may be torn.`,
    severalEventLists: (n: number, tcbs: string) =>
      `${n} TCB(s) appear on more than one xEventListItem list (${tcbs}). One xEventListItem cannot be linked twice; the snapshot may be torn.`,
    currentLane: 'pxCurrentTCB',
    readyLane: (address: string) => `ready list @ ${address}`,
    noListSupplied: 'no ready list supplied',
    readyArrayUnresolved: 'ready-list array declared, address not resolved',
    readyArray: (base: string, n: number, size: number, checked: boolean) =>
      `Ready lists derived from pxReadyTasksLists @ ${base}: ${n} declared priorities × ${size} bytes. ${
        checked
          ? 'The symbol st_size agrees.'
          : 'No st_size was supplied, so the priority count rests on the declaration alone.'
      }`,
    topReady: (
      address: string,
      representation: 'priority' | 'bitmap',
      value: number | string,
      expected: number | string,
      agrees: boolean | null | undefined,
    ) =>
      `uxTopReadyPriority @ ${address}: ${representation} value ${value}; expected ${expected} from the complete array; ${
        agrees === true ? 'agrees' : agrees === false ? 'disagrees' : 'not compared'
      }.`,
    noTasks: 'none',
    limits: (maxKiB: number, maxItems: number, maxLists: number, maxEventLists = 0) =>
      `Limits applied: snapshot ≤ ${maxKiB} KiB, ≤ ${maxItems} nodes walked per list, ≤ ${maxLists} ready lists, ≤ ${maxEventLists} ordered wait lists.`,
    notRecorded: 'not recorded',
  },

  elfSymbols: {
    heading: "Addresses from this image's ELF (optional)",
    intro:
      "Read the kernel list addresses from the image's own static symbol table and pre-fill the fields below. They are link-time addresses, not runtime proof: you still supply the RAM snapshot, and every pre-filled field stays editable.",
    read: 'Read ELF symbols',
    reread: 'Read ELF symbols again',
    reading: 'Reading symbols…',
    fill: 'Fill the form from this read',
    notRun: 'The ELF symbols of this image have not been read. Every address below can still be typed by hand.',
    failed: 'The symbol read did not finish.',
    filled: (names: string) => `Pre-filled from resolved symbols: ${names}. Check them before walking.`,
    filledNone: 'Nothing was pre-filled: no list field resolved to exactly one address.',
    verdict: {
      'symbols-read': 'Static symbol table read.',
      'no-section-headers':
        'The ELF has no section header table, so no symbol table can be located. That is not evidence the image lacks FreeRTOS.',
      'no-static-symbol-table':
        'The ELF is stripped: it has no static symbol table. That is not evidence the image lacks FreeRTOS.',
      'sections-not-examined':
        'No static symbol table among the sections examined, but some sections were beyond the cap. Undecided, not absent.',
      'static-symbol-table-unreadable':
        'A static symbol table is present but could not be read. That is not evidence the image lacks FreeRTOS.',
      refused:
        'The image could not be read as an ELF. A raw binary carries no symbols, and that says nothing about FreeRTOS.',
      'file-too-large': 'The image is above the read cap and was not read, rather than read in part.',
      'file-unreadable': 'The image file could not be read on this bench.',
    },
    identity: (elfClass: string, endian: string, width: number, machine: string) =>
      `The ELF declares ${elfClass}, ${endian}, ${width}-byte pointers, machine ${machine}. Declare the snapshot layout yourself below.`,
    symbolsTable: 'FreeRTOS kernel symbols',
    col: { name: 'Symbol', status: 'Status', address: 'Address', size: 'Size', binding: 'Binding' },
    status: {
      resolved: 'resolved',
      ambiguous: 'ambiguous',
      absent: 'absent',
      'not-examined': 'not examined',
      'undefined-only': 'undefined only',
      unavailable: 'unavailable',
    },
    smp: 'SMP variant',
    delayedNotFilled:
      'xDelayedTaskList1 and xDelayedTaskList2 are listed but never filled: which one is current, and which the overflow list, is read from the pointers in the RAM snapshot.',
    notCarried: 'Not carried into the form',
    readyManual:
      'No per-priority ready list is pre-filled. When pxReadyTasksLists resolves, only the array address and its st_size are; configMAX_PRIORITIES and sizeof(List_t) are yours to declare, never inferred from a symbol size.',
  },

  ramCapture: {
    heading: 'RAM snapshot from Renode emulation (optional)',
    intro:
      'Run the firmware under Renode for a bounded duration, pause emulation, and capture the peripheral SRAM to analyze task structures. The capture is a lead: it proves what the emulated SoC wrote, not that the scheduler ran or that tasks exist.',
    capture: 'Emulate & capture RAM',
    recapture: 'Capture RAM again',
    capturing: 'Emulating and capturing RAM…',
    loadIntoForm: 'Load into form',
    loadedIntoForm: 'Captured RAM loaded into snapshot form.',
    notRun: 'No Renode RAM snapshot has been captured for this image.',
    failed: 'RAM capture failed.',
    capturedHeading: 'Renode RAM captured',
    capturedSummary: (name: string, base: string, bytes: number, sec: number) =>
      `Captured ${bytes.toLocaleString()} bytes from peripheral '${name}' (${base}) after ${sec}s of emulation.`,
    platform: (name: string) => `Platform: ${name}`,
    refused: 'RAM capture refused:',
    remoteRefused: (count: number) => `${count} remote resource request(s) refused (offline containment).`,
    notAvailable: 'Renode is not available on this bench.',
    secondsLabel: 'Emulation seconds',
  },
};
