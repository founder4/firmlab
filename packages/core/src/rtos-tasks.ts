/**
 * Bounded, byte-only enumeration of FreeRTOS task records from a memory snapshot — no signature guessing.
 *
 * This is deliberately narrow: it walks ONE evidenced layout (FreeRTOS's `List_t` / `ListItem_t`, as declared in
 * `kernel/include/list.h` with the default `configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES == 0` build), and only when
 * the caller supplies the address of a real list (a `pxReadyTasksLists[priority]` entry, a delayed, suspended,
 * pending-ready or waiting-termination list — all the same `List_t` — or `pxCurrentTCB`) —
 * never by scanning a buffer for pointer-shaped bytes and guessing they form a task list. A pointer earns a task
 * record by sitting on a structurally valid, in-region doubly-linked chain that a real list can produce; nothing
 * here infers "this looks like a TCB" from content alone.
 *
 * The traversal reports what it did, not just what it found: `attempted` is every node it visited, `completed` is
 * every node that corroborated as an owned task item (a non-null `pvOwner`), and `coverage` says how the walk
 * ended. Per the project's proof-state discipline, an empty `tasks` list is conclusive ("this ready list has zero
 * tasks") only when `coverage === 'complete'` — the chain was followed structurally back to its own sentinel.
 * Every other coverage value (a missing symbol, a pointer outside the supplied memory region, a record truncated
 * by the buffer's edge, or a cycle that never returned to the sentinel) means the question was asked and the
 * traversal could not answer it, which is not the same as "no tasks".
 *
 * Pure: no I/O, no tool dependency, no address translation — the caller resolves symbol addresses and hands in a
 * `buf`/`regionBase` pair (a contiguous memory dump and the address its first byte corresponds to). Wiring this to
 * a live Renode/QEMU memory read, and to symbol resolution from an ELF, is deliberately out of scope here.
 */

/** Pointer width and byte order of the target the memory snapshot was taken from. */
export interface FreeRtosLayout {
  /** sizeof(void*) on the target. Bare-metal Cortex-M/RISC-V32 firmware — this module's evidenced domain — is 4. */
  pointerWidth: 4 | 8;
  endian: 'little' | 'big';
}

/** The common default: 32-bit pointers, little-endian (Cortex-M, RISC-V32 in their native mode). */
export const DEFAULT_FREERTOS_LAYOUT: FreeRtosLayout = { pointerWidth: 4, endian: 'little' };

/**
 * sizeof(TickType_t), the `xItemValue` field width. FreeRTOS defaults `configTICK_TYPE_WIDTH_IN_BITS` to 32 even
 * on 64-bit ports, so this is not derived from `pointerWidth` — conflating the two would silently misalign every
 * field after it on a 64-bit target.
 */
const TICK_WIDTH = 4;

/**
 * Defensive cap on nodes visited per list. Any one FreeRTOS task list — ready, delayed, suspended, pending or
 * terminated — holds at most every task the firmware created (tens on a microcontroller, never thousands), so this
 * only ever bounds a corrupted or adversarial chain that does not return to its own sentinel — it is not expected
 * to fire on real firmware.
 */
const MAX_LIST_ITEMS = 256;

export type FreeRtosCoverage =
  /** The chain was followed structurally back to the list's own sentinel — `tasks` is the complete set. */
  | 'complete'
  /** The traversal cap fired, or a node was revisited, before the chain returned to its sentinel. */
  | 'cycle_capped'
  /** A node's address is in the supplied region but its record runs past the end of the buffer. */
  | 'truncated'
  /** A node's address (or the list sentinel itself) falls outside the supplied memory region. */
  | 'out_of_range'
  /** The caller did not supply a resolvable list/symbol address. */
  | 'missing_symbol';

export interface FreeRtosTaskRecord {
  /** Address of this task's `ListItem_t` (e.g. `xStateListItem`) as found on the list. */
  listItemAddress: number;
  /**
   * The item's `xItemValue`. Its meaning depends on the list (see `FreeRtosItemValueMeaning`): a delayed list's wake
   * tick, but on a ready list — filled by `listINSERT_END`, which never sets it — whatever value was last written.
   */
  itemValue: number;
  /** `pvOwner` — the address of the owning `TCB_t`. This is the field that corroborates the node as a task. */
  tcbAddress: number;
}

export interface FreeRtosTaskListResult {
  coverage: FreeRtosCoverage;
  /** Every node the traversal visited and attempted to read, including ones that failed to corroborate or bound the walk. */
  attempted: number;
  /** Nodes that corroborated as owned task records — `tasks.length`. */
  completed: number;
  tasks: FreeRtosTaskRecord[];
  /** Human-readable audit trail: why the walk ended where it did. */
  evidence: string[];
}

function u32(buf: Uint8Array, o: number, le: boolean): number {
  const a = buf[o] ?? 0;
  const b = buf[o + 1] ?? 0;
  const c = buf[o + 2] ?? 0;
  const d = buf[o + 3] ?? 0;
  return le ? (a | (b << 8) | (c << 16) | (d << 24)) >>> 0 : ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

function readUint(buf: Uint8Array, offset: number, width: 4 | 8, le: boolean): number {
  if (width === 4) return u32(buf, offset, le);
  const first = u32(buf, offset, le);
  const second = u32(buf, offset + 4, le);
  return le ? second * 0x1_0000_0000 + first : first * 0x1_0000_0000 + second;
}

/** `xItemValue` + `pxNext` + `pxPrevious` + `pvOwner` + `pxContainer`, the full `ListItem_t` record. */
function listItemRecordSize(layout: FreeRtosLayout): number {
  return TICK_WIDTH + 4 * layout.pointerWidth;
}

/** What one walk saw beyond the base result: the header count, container back-pointers, and the item values in order. */
interface ListWalk extends FreeRtosTaskListResult {
  /** `uxNumberOfItems` from the `List_t` header, or null when the header lies outside the buffer. */
  declaredItems: number | null;
  /** Visited, in-bounds nodes whose `pxContainer` does not point back at this list. */
  containerMismatches: number[];
  /** `itemValue` of every corroborated task, in chain order. */
  values: number[];
}

/**
 * The one traversal every list kind shares. `parseFreeRtosReadyList` exposes only its base fields (and exactly its
 * original evidence lines); `parseFreeRtosNamedList` exposes the annotations too.
 */
function walkList(
  buf: Uint8Array,
  regionBase: number,
  listAddress: number | null,
  layout: FreeRtosLayout,
  missingEvidence: string,
): ListWalk {
  const empty = (coverage: FreeRtosCoverage, line: string): ListWalk => ({
    coverage,
    attempted: 0,
    completed: 0,
    tasks: [],
    evidence: [line],
    declaredItems: null,
    containerMismatches: [],
    values: [],
  });
  if (listAddress === null) return empty('missing_symbol', missingEvidence);

  const ptr = layout.pointerWidth;
  const le = layout.endian === 'little';
  const recordSize = listItemRecordSize(layout);
  const nextOffset = TICK_WIDTH;
  const ownerOffset = TICK_WIDTH + 2 * ptr;
  const containerOffset = TICK_WIDTH + 3 * ptr;
  // List_t header (no integrity-check bytes): uxNumberOfItems (ptr-width) + pxIndex (ptr-width) precede xListEnd.
  const sentinelAddress = listAddress + 2 * ptr;
  const regionEnd = regionBase + buf.length;

  const inRegion = (addr: number) => addr >= regionBase && addr < regionEnd;
  const readField = (addr: number, fieldOffset: number) => readUint(buf, addr - regionBase + fieldOffset, ptr, le);

  // xListEnd is a MiniListItem_t (itemValue + pxNext + pxPrevious, no owner) — its pxNext is the chain head.
  if (!inRegion(sentinelAddress)) {
    return empty('out_of_range', `list sentinel at 0x${sentinelAddress.toString(16)} falls outside the mapped region`);
  }
  if (sentinelAddress - regionBase + TICK_WIDTH + ptr > buf.length) {
    return empty(
      'truncated',
      `list sentinel at 0x${sentinelAddress.toString(16)} runs past the end of the supplied buffer`,
    );
  }
  // uxNumberOfItems is UBaseType_t, pointer-width on every port this layout models. Read only when it is in the
  // buffer: the header is an annotation, and its absence never changes how the chain itself is walked.
  const declaredItems = inRegion(listAddress) ? readField(listAddress, 0) : null;

  let cur = readField(sentinelAddress, nextOffset);
  const visited = new Set<number>();
  const tasks: FreeRtosTaskRecord[] = [];
  const evidence: string[] = [];
  const containerMismatches: number[] = [];
  let attempted = 0;
  let coverage: FreeRtosCoverage = 'complete';

  while (cur !== sentinelAddress) {
    if (attempted >= MAX_LIST_ITEMS) {
      coverage = 'cycle_capped';
      evidence.push(`traversal cap of ${MAX_LIST_ITEMS} items reached without returning to the list sentinel`);
      break;
    }
    if (visited.has(cur)) {
      coverage = 'cycle_capped';
      evidence.push(`list item at 0x${cur.toString(16)} was revisited without the chain returning to its sentinel`);
      break;
    }
    attempted++;
    if (!inRegion(cur)) {
      coverage = 'out_of_range';
      evidence.push(`list item pointer 0x${cur.toString(16)} falls outside the mapped region`);
      break;
    }
    if (cur - regionBase + recordSize > buf.length) {
      coverage = 'truncated';
      evidence.push(`list item at 0x${cur.toString(16)} runs past the end of the supplied buffer`);
      break;
    }
    visited.add(cur);
    const itemValue = readUint(buf, cur - regionBase, TICK_WIDTH, le);
    const ownerAddr = readField(cur, ownerOffset);
    if (readField(cur, containerOffset) !== listAddress) containerMismatches.push(cur);
    if (ownerAddr === 0) {
      evidence.push(`list item at 0x${cur.toString(16)} has a null owner — not corroborated as a task`);
    } else {
      tasks.push({ listItemAddress: cur, itemValue, tcbAddress: ownerAddr });
    }
    cur = readField(cur, nextOffset);
  }

  return {
    coverage,
    attempted,
    completed: tasks.length,
    tasks,
    evidence,
    declaredItems,
    containerMismatches,
    values: tasks.map((t) => t.itemValue),
  };
}

/**
 * Walk one FreeRTOS `List_t`'s circular chain of `ListItem_t` nodes (e.g. a `pxReadyTasksLists[priority]` entry),
 * starting from its embedded `xListEnd` sentinel, and return every node that corroborates as an owned task.
 *
 * `buf`/`regionBase` describe a contiguous memory snapshot: `buf[0]` is the byte at address `regionBase`.
 * `listAddress` is the address of the `List_t` structure itself (not the sentinel or a list item) — pass `null`
 * when the symbol could not be resolved, which reports `missing_symbol` rather than silently returning no tasks.
 */
export function parseFreeRtosReadyList(
  buf: Uint8Array,
  regionBase: number,
  listAddress: number | null,
  layout: FreeRtosLayout = DEFAULT_FREERTOS_LAYOUT,
): FreeRtosTaskListResult {
  const { coverage, attempted, completed, tasks, evidence } = walkList(
    buf,
    regionBase,
    listAddress,
    layout,
    'no ready-list address supplied',
  );
  return { coverage, attempted, completed, tasks, evidence };
}

/**
 * Which `tasks.c` list a walk read. Every one is the same `List_t`, so the walk is identical; what differs is what a
 * task on it means, and what its items' `xItemValue` holds:
 *
 * - `ready` — `pxReadyTasksLists[priority]`. Filled by `listINSERT_END`, which does not set `xItemValue`.
 * - `delayed` / `delayed_overflow` — `xDelayedTaskList1` / `xDelayedTaskList2`, reached through `pxDelayedTaskList`
 *   and `pxOverflowDelayedTaskList`. The two SWAP roles each time the tick count wraps, so which one is the overflow
 *   list is a fact about those two pointers at snapshot time, never about the list's own name — the caller states
 *   it. Filled by `vListInsert` with `xItemValue = xTimeToWake`, kept in ascending order.
 * - `suspended` — `xSuspendedTaskList`: explicitly suspended tasks, and tasks blocked with `portMAX_DELAY` when
 *   `INCLUDE_vTaskSuspend` is on. `listINSERT_END`; `xItemValue` is not set.
 * - `pending` — `xPendingReadyList`: tasks readied while the scheduler was suspended. It holds each task's
 *   `xEventListItem`, not its `xStateListItem` (whose list is still the one the task is leaving), and that item's
 *   value is `configMAX_PRIORITIES - priority` unless an event group borrowed it.
 * - `terminated` — `xTasksWaitingTermination`: deleted tasks the idle task has not yet freed. `xItemValue` not set.
 */
export type FreeRtosListKind = 'ready' | 'delayed' | 'delayed_overflow' | 'suspended' | 'pending' | 'terminated';

/** What `xItemValue` carries on a given list kind — so a value is only ever read as what the kernel put there. */
export type FreeRtosItemValueMeaning =
  /** `xTimeToWake`, the tick at which the task leaves the delayed list. */
  | 'wake_tick'
  /** `configMAX_PRIORITIES - uxPriority` on an event list item (unless `taskEVENT_LIST_ITEM_VALUE_IN_USE`). */
  | 'event_order'
  /** The list is filled with `listINSERT_END`, which leaves `xItemValue` as whatever was last written. */
  | 'not_maintained';

export const FREERTOS_ITEM_VALUE_MEANING: Readonly<Record<FreeRtosListKind, FreeRtosItemValueMeaning>> = {
  ready: 'not_maintained',
  delayed: 'wake_tick',
  delayed_overflow: 'wake_tick',
  suspended: 'not_maintained',
  pending: 'event_order',
  terminated: 'not_maintained',
};

/** The `tasks.c` symbol name a kind is read from when the caller names nothing more specific. */
export const FREERTOS_LIST_DEFAULT_NAME: Readonly<Record<FreeRtosListKind, string>> = {
  ready: 'pxReadyTasksLists',
  delayed: 'pxDelayedTaskList',
  delayed_overflow: 'pxOverflowDelayedTaskList',
  suspended: 'xSuspendedTaskList',
  pending: 'xPendingReadyList',
  terminated: 'xTasksWaitingTermination',
};

export interface FreeRtosNamedList {
  kind: FreeRtosListKind;
  /** A label for the audit trail (e.g. `xDelayedTaskList1`); defaults to the kind's `tasks.c` symbol. */
  name?: string;
  /** Address of the `List_t` itself, or null when the symbol could not be resolved (→ `missing_symbol`). */
  address: number | null;
  /** For `ready` only: the `pxReadyTasksLists` index, carried through untouched. */
  priority?: number;
}

export interface FreeRtosNamedListResult extends FreeRtosTaskListResult {
  kind: FreeRtosListKind;
  name: string;
  listAddress: number | null;
  priority?: number;
  /** What each task's `itemValue` means on this kind of list. Only `wake_tick` is ever shown as a wake tick. */
  itemValueMeaning: FreeRtosItemValueMeaning;
  /**
   * `uxNumberOfItems` as read from the header, or null when the header was not in the buffer. A `complete` walk
   * whose node count differs from it is reported in `evidence` — a torn snapshot, not a different coverage.
   */
  declaredItems: number | null;
  /**
   * Visited nodes whose `pxContainer` does not point back to this list. A real item on this list always points
   * back, so a non-zero count says the chain wandered into memory that is not this list's. The nodes still count
   * as walked: this is an annotation, never a reason to drop a task the chain itself reached.
   */
  containerMismatches: number;
  /**
   * For `wake_tick` lists: adjacent corroborated items whose wake ticks DEcrease along the chain. `vListInsert`
   * keeps a delayed list sorted, so any count above zero is either a torn snapshot or a list that is not delayed.
   * Always 0 for the other kinds, whose values carry no order.
   */
  orderViolations: number;
}

/**
 * Walk any `tasks.c` task list. Coverage follows exactly the rules of `parseFreeRtosReadyList` — `complete` only
 * when the chain returns to its own sentinel — and the result adds what the walk can corroborate beyond the chain:
 * the header's own item count, every node's container back-pointer, and (on delayed lists) the wake-tick order.
 * None of those annotations upgrades or downgrades `coverage`; they are reported so that a structurally complete
 * walk over an inconsistent snapshot is visible as such.
 */
export function parseFreeRtosNamedList(
  buf: Uint8Array,
  regionBase: number,
  list: FreeRtosNamedList,
  layout: FreeRtosLayout = DEFAULT_FREERTOS_LAYOUT,
): FreeRtosNamedListResult {
  const name = list.name ?? FREERTOS_LIST_DEFAULT_NAME[list.kind];
  const meaning = FREERTOS_ITEM_VALUE_MEANING[list.kind];
  const w = walkList(buf, regionBase, list.address, layout, `no address supplied for ${name} (${list.kind})`);
  const evidence = [...w.evidence];

  if (w.declaredItems !== null && w.coverage === 'complete' && w.declaredItems !== w.attempted) {
    evidence.push(
      `uxNumberOfItems reads ${w.declaredItems} but the chain holds ${w.attempted} item(s) — the snapshot may be torn`,
    );
  }
  for (const at of w.containerMismatches) {
    evidence.push(`list item at 0x${at.toString(16)} has a pxContainer that does not point back to ${name}`);
  }
  let orderViolations = 0;
  if (meaning === 'wake_tick') {
    for (let i = 1; i < w.values.length; i++) if ((w.values[i] ?? 0) < (w.values[i - 1] ?? 0)) orderViolations++;
    const why = 'vListInsert keeps a delayed list sorted, so the snapshot may be torn or this is not a delayed list';
    if (orderViolations > 0) evidence.push(`${orderViolations} wake tick(s) out of ascending order — ${why}`);
  }

  return {
    kind: list.kind,
    name,
    listAddress: list.address,
    ...(list.priority !== undefined ? { priority: list.priority } : {}),
    coverage: w.coverage,
    attempted: w.attempted,
    completed: w.completed,
    tasks: w.tasks,
    evidence,
    itemValueMeaning: meaning,
    declaredItems: w.declaredItems,
    containerMismatches: w.containerMismatches.length,
    orderViolations,
  };
}

/**
 * Walk several named lists over one snapshot, in the order given. A convenience over `parseFreeRtosNamedList`
 * that adds nothing to it — each list's coverage is its own, and one list's failure never stops another's walk.
 */
export function parseFreeRtosList(
  buf: Uint8Array,
  regionBase: number,
  lists: readonly FreeRtosNamedList[],
  layout: FreeRtosLayout = DEFAULT_FREERTOS_LAYOUT,
): FreeRtosNamedListResult[] {
  return lists.map((l) => parseFreeRtosNamedList(buf, regionBase, l, layout));
}

export interface FreeRtosCurrentTaskResult {
  coverage: 'complete' | 'out_of_range' | 'truncated' | 'missing_symbol';
  tcbAddress: number | null;
  evidence: string[];
}

/**
 * Read the single `TCB_t *pxCurrentTCB` global, given its resolved address. The cheapest possible corroborated
 * task fact (one pointer, no traversal) — useful when a symbol table gives `pxCurrentTCB` but not a ready list.
 */
export function parseFreeRtosCurrentTask(
  buf: Uint8Array,
  regionBase: number,
  pxCurrentTcbAddress: number | null,
  layout: FreeRtosLayout = DEFAULT_FREERTOS_LAYOUT,
): FreeRtosCurrentTaskResult {
  if (pxCurrentTcbAddress === null) {
    return { coverage: 'missing_symbol', tcbAddress: null, evidence: ['pxCurrentTCB address not supplied'] };
  }
  const regionEnd = regionBase + buf.length;
  if (pxCurrentTcbAddress < regionBase || pxCurrentTcbAddress >= regionEnd) {
    return {
      coverage: 'out_of_range',
      tcbAddress: null,
      evidence: [`pxCurrentTCB address 0x${pxCurrentTcbAddress.toString(16)} falls outside the mapped region`],
    };
  }
  const offset = pxCurrentTcbAddress - regionBase;
  if (offset + layout.pointerWidth > buf.length) {
    return {
      coverage: 'truncated',
      tcbAddress: null,
      evidence: [`pxCurrentTCB read at 0x${pxCurrentTcbAddress.toString(16)} runs past the end of the supplied buffer`],
    };
  }
  const tcbAddress = readUint(buf, offset, layout.pointerWidth, layout.endian === 'little');
  return {
    coverage: 'complete',
    tcbAddress,
    evidence: [`pxCurrentTCB @ 0x${pxCurrentTcbAddress.toString(16)} -> TCB 0x${tcbAddress.toString(16)}`],
  };
}
