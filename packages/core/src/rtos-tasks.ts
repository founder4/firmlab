/**
 * Bounded, byte-only enumeration of FreeRTOS task records from a memory snapshot — no signature guessing.
 *
 * This is deliberately narrow: it walks FreeRTOS's four evidenced `List_t` / `ListItem_t` combinations for
 * `configUSE_MINI_LIST_ITEM` and `configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES`, with an explicitly declared 16-, 32-
 * or 64-bit `TickType_t`, and only when
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
 * When the integrity-byte option is declared, its width-matched `0x5a...` words are read with separate attempted/
 * completed/mismatch counters. They diagnose the declared layout or snapshot consistency; they never alter walk
 * coverage.
 *
 * Pure: no I/O, no tool dependency, no address translation — the caller resolves symbol addresses and hands in a
 * `buf`/`regionBase` pair (a contiguous memory dump and the address its first byte corresponds to). Wiring this to
 * a live Renode/QEMU memory read, and to symbol resolution from an ELF, is deliberately out of scope here.
 */

/** Pointer, tick width and byte order of the target the memory snapshot was taken from. */
export interface FreeRtosLayout {
  /** sizeof(void*) on the target. Bare-metal Cortex-M/RISC-V32 firmware — this module's evidenced domain — is 4. */
  pointerWidth: 4 | 8;
  endian: 'little' | 'big';
  /** sizeof(TickType_t). Optional so requests stored before 16/64-bit support retain the historical 4-byte layout. */
  tickWidth?: 2 | 4 | 8;
  /** FreeRTOS defaults this to 1. Optional so stored requests from older builds retain their historical layout. */
  useMiniListItem?: boolean;
  /** FreeRTOS defaults this to 0. These bytes change offsets; they are not inferred from a snapshot. */
  useListDataIntegrityCheckBytes?: boolean;
}

/** The common default: 32-bit pointers, little-endian (Cortex-M, RISC-V32 in their native mode). */
export const DEFAULT_FREERTOS_LAYOUT: FreeRtosLayout = { pointerWidth: 4, endian: 'little' };

const DEFAULT_TICK_WIDTH = 4;

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
   * Values through `Number.MAX_SAFE_INTEGER` are numbers; larger 64-bit ticks are exact unsigned decimal strings.
   */
  itemValue: number | string;
  /** `pvOwner` — the address of the owning `TCB_t`. This is the field that corroborates the node as a task. */
  tcbAddress: number;
  /** Decoded only for an explicitly declared EventGroup wait list; absent on every other list kind. */
  eventGroupWait?: FreeRtosEventGroupWait;
}

export interface FreeRtosEventGroupWait {
  /** User event bits requested by the task, with FreeRTOS's top control byte removed. */
  bits: number | string;
  waitForAll: boolean;
  clearOnExit: boolean;
  /** Normally false while the item is still linked; retained as a torn/racing-snapshot diagnostic. */
  unblockedDueToBitSet: boolean;
  /** `taskEVENT_LIST_ITEM_VALUE_IN_USE`, the MSB set while Event Groups own xItemValue. */
  itemValueInUse: boolean;
}

/** Diagnostic reads of FreeRTOS's optional `0x5a` list-integrity words. */
export interface FreeRtosIntegrityChecks {
  /** Whether the caller declared `configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES=1`. */
  enabled: boolean;
  /** Declared marker fields reached by the walk, including fields outside or cut by the supplied region. */
  attempted: number;
  /** Attempted marker fields whose complete declared TickType_t bytes were available and read. */
  completed: number;
  /** Completed reads whose value was not the width-matched repeated `0x5a` word. Never changes coverage or proof. */
  mismatches: number;
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
  /** Optional forever because API job results embedding this type may have been persisted by an older build. */
  integrityChecks?: FreeRtosIntegrityChecks;
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

function readTick(buf: Uint8Array, offset: number, width: 2 | 4 | 8, le: boolean): bigint {
  let value = 0n;
  for (let i = 0; i < width; i++) {
    const byte = BigInt(buf[offset + (le ? width - 1 - i : i)] ?? 0);
    value = (value << 8n) | byte;
  }
  return value;
}

const publicTick = (value: bigint): number | string =>
  value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString(10);

/** Decode Event Groups' width-relative top control byte without interpreting the unordered list as a priority list. */
export function decodeFreeRtosEventGroupValue(value: bigint, tickWidth: 2 | 4 | 8): FreeRtosEventGroupWait {
  const width = BigInt(tickWidth * 8);
  const controlShift = width - 8n;
  const controlMask = 0xffn << controlShift;
  return {
    bits: publicTick(value & ~controlMask),
    clearOnExit: (value & (1n << controlShift)) !== 0n,
    unblockedDueToBitSet: (value & (1n << (controlShift + 1n))) !== 0n,
    waitForAll: (value & (1n << (controlShift + 2n))) !== 0n,
    itemValueInUse: (value & (1n << (width - 1n))) !== 0n,
  };
}

const tickMarker = (width: 2 | 4 | 8): bigint => BigInt(`0x${'5a'.repeat(width)}`);

/**
 * Natural padding before a pointer that follows `TickType_t`. Tick width is independently declared: a 64-bit tick
 * followed by a 32-bit pointer needs no padding, while a 16-bit tick followed by either pointer width does.
 */
export function pointerAlignmentPadding(layout: FreeRtosLayout): number {
  const tick = resolveTickWidth(layout);
  return align(tick, layout.pointerWidth) - tick;
}

export interface DerivedFreeRtosListLayout {
  tickWidth: 2 | 4 | 8;
  useMiniListItem: boolean;
  useListDataIntegrityCheckBytes: boolean;
  listItem: {
    itemValueOffset: number;
    nextOffset: number;
    previousOffset: number;
    ownerOffset: number;
    containerOffset: number;
    size: number;
  };
  sentinel: { itemValueOffset: number; nextOffset: number; previousOffset: number; size: number };
  list: { numberOfItemsOffset: number; indexOffset: number; sentinelOffset: number; size: number };
}

const align = (offset: number, width: number): number => Math.ceil(offset / width) * width;

function resolveTickWidth(layout: FreeRtosLayout): 2 | 4 | 8 {
  const width = layout.tickWidth ?? DEFAULT_TICK_WIDTH;
  if (width !== 2 && width !== 4 && width !== 8) {
    throw new RangeError(`tickWidth must be 2, 4 or 8 bytes; received ${String(width)}`);
  }
  return width;
}

/** Pure natural-ABI layout for the supported FreeRTOS list configurations and declared TickType_t width. */
export function deriveFreeRtosListLayout(layout: FreeRtosLayout): DerivedFreeRtosListLayout {
  const ptr = layout.pointerWidth;
  const tick = resolveTickWidth(layout);
  const structAlignment = Math.max(ptr, tick);
  const integrity = layout.useListDataIntegrityCheckBytes ?? false;
  const mini = layout.useMiniListItem ?? true;

  const itemValueOffset = integrity ? tick : 0;
  const nextOffset = align(itemValueOffset + tick, ptr);
  const itemPreviousOffset = nextOffset + ptr;
  const ownerOffset = itemPreviousOffset + ptr;
  const containerOffset = ownerOffset + ptr;
  const itemDataEnd = containerOffset + ptr;
  const itemTrailingIntegrityOffset = align(itemDataEnd, tick);
  const itemEnd = integrity ? itemTrailingIntegrityOffset + tick : itemDataEnd;
  const itemSize = align(itemEnd, structAlignment);

  const sentinelItemValueOffset = integrity ? tick : 0;
  const sentinelNextOffset = align(sentinelItemValueOffset + tick, ptr);
  const sentinelPreviousOffset = sentinelNextOffset + ptr;
  const miniSentinelSize = align(sentinelPreviousOffset + ptr, structAlignment);
  const sentinelSize = mini ? miniSentinelSize : itemSize;

  const numberOfItemsOffset = align(integrity ? tick : 0, ptr);
  const indexOffset = numberOfItemsOffset + ptr;
  const sentinelOffset = align(indexOffset + ptr, structAlignment);
  const sentinelEnd = sentinelOffset + sentinelSize;
  const listTrailingIntegrityOffset = align(sentinelEnd, tick);
  const listEnd = integrity ? listTrailingIntegrityOffset + tick : sentinelEnd;

  return {
    tickWidth: tick,
    useMiniListItem: mini,
    useListDataIntegrityCheckBytes: integrity,
    listItem: {
      itemValueOffset,
      nextOffset,
      previousOffset: itemPreviousOffset,
      ownerOffset,
      containerOffset,
      size: itemSize,
    },
    sentinel: {
      itemValueOffset: sentinelItemValueOffset,
      nextOffset: sentinelNextOffset,
      previousOffset: sentinelPreviousOffset,
      size: sentinelSize,
    },
    list: { numberOfItemsOffset, indexOffset, sentinelOffset, size: align(listEnd, structAlignment) },
  };
}

/** `xItemValue` + pointers and optional integrity words, the full `ListItem_t` record. */
export function listItemRecordSize(layout: FreeRtosLayout): number {
  return deriveFreeRtosListLayout(layout).listItem.size;
}

/** Bytes of the sentinel head the walk reads, through `pxNext`. */
export function listSentinelHeadSize(layout: FreeRtosLayout): number {
  const d = deriveFreeRtosListLayout(layout).sentinel;
  return d.nextOffset + layout.pointerWidth;
}

/**
 * sizeof(`List_t`) under the declared layout. It is the stride between `pxReadyTasksLists[priority]` entries only
 * for a build with those config options and the declared `TickType_t`; it says nothing about how
 * many priorities a build has.
 */
export function listRecordSize(layout: FreeRtosLayout): number {
  return deriveFreeRtosListLayout(layout).list.size;
}

/** What one walk saw beyond the base result: the header count, container back-pointers, and the item values in order. */
interface ListWalk extends FreeRtosTaskListResult {
  integrityChecks: FreeRtosIntegrityChecks;
  /** `uxNumberOfItems` from the `List_t` header, or null when the header lies outside the buffer. */
  declaredItems: number | null;
  /** Visited, in-bounds nodes whose `pxContainer` does not point back at this list. */
  containerMismatches: number[];
  /** Exact `itemValue` of every corroborated task, in chain order. */
  values: bigint[];
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
  const integrityChecks: FreeRtosIntegrityChecks = {
    enabled: layout.useListDataIntegrityCheckBytes ?? false,
    attempted: 0,
    completed: 0,
    mismatches: 0,
  };
  const evidence: string[] = [];
  const empty = (coverage: FreeRtosCoverage, line: string): ListWalk => ({
    coverage,
    attempted: 0,
    completed: 0,
    tasks: [],
    evidence: [...evidence, line],
    integrityChecks,
    declaredItems: null,
    containerMismatches: [],
    values: [],
  });
  if (listAddress === null) return empty('missing_symbol', missingEvidence);

  const ptr = layout.pointerWidth;
  const le = layout.endian === 'little';
  const derived = deriveFreeRtosListLayout(layout);
  const tick = derived.tickWidth;
  const recordSize = derived.listItem.size;
  const sentinelHeadSize = derived.sentinel.nextOffset + ptr;
  const sentinelAddress = listAddress + derived.list.sentinelOffset;
  const regionEnd = regionBase + buf.length;

  const inRegion = (addr: number) => addr >= regionBase && addr < regionEnd;
  const readField = (addr: number, fieldOffset: number) => readUint(buf, addr - regionBase + fieldOffset, ptr, le);
  const checkIntegrity = (address: number, field: string) => {
    if (!integrityChecks.enabled) return;
    integrityChecks.attempted++;
    const offset = address - regionBase;
    if (offset < 0 || offset + tick > buf.length) return;
    integrityChecks.completed++;
    const actual = readTick(buf, offset, tick, le);
    const expected = tickMarker(tick);
    if (actual === expected) return;
    integrityChecks.mismatches++;
    const hexWidth = tick * 2;
    evidence.push(
      `${field} integrity marker at 0x${address.toString(16)} reads 0x${actual.toString(16).padStart(hexWidth, '0')}, ` +
        `not 0x${expected.toString(16).padStart(hexWidth, '0')} — the declared layout may be wrong or the snapshot may be torn/corrupt`,
    );
  };

  checkIntegrity(listAddress, 'List_t leading');
  checkIntegrity(listAddress + align(derived.list.sentinelOffset + derived.sentinel.size, tick), 'List_t trailing');
  checkIntegrity(sentinelAddress, 'list sentinel leading');
  if (!derived.useMiniListItem)
    checkIntegrity(
      sentinelAddress + align(derived.listItem.containerOffset + ptr, tick),
      'full ListItem_t sentinel trailing',
    );

  // xListEnd is a MiniListItem_t (itemValue + pxNext + pxPrevious, no owner) — its pxNext is the chain head.
  if (!inRegion(sentinelAddress)) {
    return empty('out_of_range', `list sentinel at 0x${sentinelAddress.toString(16)} falls outside the mapped region`);
  }
  if (sentinelAddress - regionBase + sentinelHeadSize > buf.length) {
    return empty(
      'truncated',
      `list sentinel at 0x${sentinelAddress.toString(16)} runs past the end of the supplied buffer`,
    );
  }
  // uxNumberOfItems is UBaseType_t, pointer-width on every port this layout models. Read only when it is in the
  // buffer: the header is an annotation, and its absence never changes how the chain itself is walked.
  const declaredItems = inRegion(listAddress) ? readField(listAddress, derived.list.numberOfItemsOffset) : null;

  let cur = readField(sentinelAddress, derived.sentinel.nextOffset);
  const visited = new Set<number>();
  const tasks: FreeRtosTaskRecord[] = [];
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
    checkIntegrity(cur, 'ListItem_t leading');
    checkIntegrity(cur + align(derived.listItem.containerOffset + ptr, tick), 'ListItem_t trailing');
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
    const exactItemValue = readTick(buf, cur - regionBase + derived.listItem.itemValueOffset, tick, le);
    const ownerAddr = readField(cur, derived.listItem.ownerOffset);
    if (readField(cur, derived.listItem.containerOffset) !== listAddress) containerMismatches.push(cur);
    if (ownerAddr === 0) {
      evidence.push(`list item at 0x${cur.toString(16)} has a null owner — not corroborated as a task`);
    } else {
      tasks.push({ listItemAddress: cur, itemValue: publicTick(exactItemValue), tcbAddress: ownerAddr });
    }
    cur = readField(cur, derived.listItem.nextOffset);
  }

  return {
    coverage,
    attempted,
    completed: tasks.length,
    tasks,
    evidence,
    integrityChecks,
    declaredItems,
    containerMismatches,
    values: tasks.map((t) => BigInt(t.itemValue)),
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
  const { coverage, attempted, completed, tasks, evidence, integrityChecks } = walkList(
    buf,
    regionBase,
    listAddress,
    layout,
    'no ready-list address supplied',
  );
  return { coverage, attempted, completed, tasks, evidence, integrityChecks };
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
 * - `event` — an ordered queue/semaphore wait list (for example `xTasksWaitingToReceive`). It also holds
 *   `xEventListItem`; the caller names the owning object and exact `List_t` address because there is no global
 *   registry of every queue in a FreeRTOS build.
 * - `event_group` — an explicitly named EventGroup `xTasksWaitingForBits`. It uses `vListInsertEnd` (unordered)
 *   and the item value carries requested event bits plus FreeRTOS's top-byte control flags.
 * - `terminated` — `xTasksWaitingTermination`: deleted tasks the idle task has not yet freed. `xItemValue` not set.
 */
export type FreeRtosListKind =
  | 'ready'
  | 'delayed'
  | 'delayed_overflow'
  | 'suspended'
  | 'pending'
  | 'event'
  | 'event_group'
  | 'terminated';

/** What `xItemValue` carries on a given list kind — so a value is only ever read as what the kernel put there. */
export type FreeRtosItemValueMeaning =
  /** `xTimeToWake`, the tick at which the task leaves the delayed list. */
  | 'wake_tick'
  /** `configMAX_PRIORITIES - uxPriority` on an event list item (unless `taskEVENT_LIST_ITEM_VALUE_IN_USE`). */
  | 'event_order'
  /** EventGroup requested bits and top-byte control flags; the list itself is unordered. */
  | 'event_bits'
  /** The list is filled with `listINSERT_END`, which leaves `xItemValue` as whatever was last written. */
  | 'not_maintained';

export const FREERTOS_ITEM_VALUE_MEANING: Readonly<Record<FreeRtosListKind, FreeRtosItemValueMeaning>> = {
  ready: 'not_maintained',
  delayed: 'wake_tick',
  delayed_overflow: 'wake_tick',
  suspended: 'not_maintained',
  pending: 'event_order',
  event: 'event_order',
  event_group: 'event_bits',
  terminated: 'not_maintained',
};

/** The `tasks.c` symbol name a kind is read from when the caller names nothing more specific. */
export const FREERTOS_LIST_DEFAULT_NAME: Readonly<Record<FreeRtosListKind, string>> = {
  ready: 'pxReadyTasksLists',
  delayed: 'pxDelayedTaskList',
  delayed_overflow: 'pxOverflowDelayedTaskList',
  suspended: 'xSuspendedTaskList',
  pending: 'xPendingReadyList',
  event: 'eventList',
  event_group: 'eventGroup.xTasksWaitingForBits',
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
  /** For ordered queue/semaphore waits only; keeps receive/send semantics out of the audit label. */
  waitKind?: 'queue_receive' | 'queue_send' | 'event_group';
}

export interface FreeRtosNamedListResult extends FreeRtosTaskListResult {
  kind: FreeRtosListKind;
  name: string;
  listAddress: number | null;
  priority?: number;
  waitKind?: 'queue_receive' | 'queue_send' | 'event_group';
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
   * For delayed and ordered queue/semaphore lists: adjacent corroborated items whose values decrease. `vListInsert`
   * keeps both ascending, so any count above zero is either a torn snapshot or the wrong declared list semantics.
   */
  orderViolations: number;
  /** Ordered queue/semaphore values that are zero or carry the EventGroup-reserved high bit. */
  valueViolations?: number;
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
  let valueViolations = 0;
  if (meaning === 'wake_tick' || list.kind === 'event') {
    for (let i = 1; i < w.values.length; i++) if ((w.values[i] ?? 0n) < (w.values[i - 1] ?? 0n)) orderViolations++;
    if (orderViolations > 0) {
      const why =
        list.kind === 'event'
          ? 'vListInsert keeps an ordered queue/semaphore wait list in ascending event-order value, so the snapshot may be torn or this is an unsupported unordered EventGroup list'
          : 'vListInsert keeps a delayed list sorted, so the snapshot may be torn or this is not a delayed list';
      evidence.push(
        `${orderViolations} ${list.kind === 'event' ? 'event-order value(s)' : 'wake tick(s)'} out of ascending order — ${why}`,
      );
    }
  }
  if (list.kind === 'event') {
    const highBit = 1n << BigInt((layout.tickWidth ?? 4) * 8 - 1);
    valueViolations = w.values.filter((value) => value === 0n || (value & highBit) !== 0n).length;
    if (valueViolations > 0)
      evidence.push(
        `${valueViolations} queue/semaphore priority key(s) are zero or carry the EventGroup-reserved high bit — the declared ordered-wait semantics may be wrong`,
      );
  }
  if (list.kind === 'event_group') {
    const decoded = w.values.map((value) => decodeFreeRtosEventGroupValue(value, layout.tickWidth ?? 4));
    valueViolations = decoded.filter((value) => value.bits === 0 || !value.itemValueInUse).length;
    if (valueViolations > 0)
      evidence.push(
        `${valueViolations} EventGroup wait value(s) request zero user bits or lack taskEVENT_LIST_ITEM_VALUE_IN_USE — the declared semantics may be wrong or the snapshot may be racing`,
      );
  }
  const tasks =
    list.kind === 'event_group'
      ? w.tasks.map((task, index) => ({
          ...task,
          eventGroupWait: decodeFreeRtosEventGroupValue(w.values[index] ?? 0n, layout.tickWidth ?? 4),
        }))
      : w.tasks;

  return {
    kind: list.kind,
    name,
    listAddress: list.address,
    ...(list.priority !== undefined ? { priority: list.priority } : {}),
    ...(list.waitKind !== undefined ? { waitKind: list.waitKind } : {}),
    coverage: w.coverage,
    attempted: w.attempted,
    completed: w.completed,
    tasks,
    evidence,
    integrityChecks: w.integrityChecks,
    itemValueMeaning: meaning,
    declaredItems: w.declaredItems,
    containerMismatches: w.containerMismatches.length,
    orderViolations,
    ...(list.kind === 'event' || list.kind === 'event_group' ? { valueViolations } : {}),
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

/**
 * The `pxReadyTasksLists[configMAX_PRIORITIES]` array as the operator DECLARES it. Neither number is inferred: a
 * priority count read off `st_size` would assume the stride, and a stride read off `st_size` would assume the count.
 */
export interface FreeRtosReadyListArraySpec {
  /** Address of `pxReadyTasksLists[0]` (the array symbol), or null when it was not resolved. */
  base: number | null;
  /** `configMAX_PRIORITIES` as declared for the build — never derived from the symbol's size. */
  maxPriorities: number;
  /** `sizeof(List_t)` as declared for the build. Cross-checked against the layout the walk reads, never used blind. */
  listSize: number;
  /**
   * The array symbol's `st_size` when an ELF supplied it; null or omitted means not cross-checked, and so does 0,
   * which the ELF specification defines as "no size or unknown size", not as an empty array.
   */
  symbolSize?: number | null;
}

export type FreeRtosReadyListArrayDerivation =
  | {
      status: 'derived';
      /** Bytes between adjacent `pxReadyTasksLists[]` entries — equal to `listRecordSize(layout)` by construction. */
      stride: number;
      /** Whether `st_size` corroborated `maxPriorities × listSize`, or was not available to check. */
      sizeCrossCheck: 'agrees' | 'not_available';
      /** One `ready` list per priority `0..maxPriorities-1`, or a single unresolved list when `base` is null. */
      lists: FreeRtosNamedList[];
      evidence: string[];
    }
  | {
      status: 'refused';
      code: 'layout_mismatch' | 'size_mismatch' | 'invalid_count' | 'invalid_size' | 'address_overflow';
      reason: string;
    };

/**
 * What an unchecked priority count risks, in one sentence. Exported so the API summary states the same limit the
 * derivation's evidence does, word for word.
 */
export const FREERTOS_OVER_DECLARED_COUNT =
  'an over-declared count reads whatever List_t follows the array (e.g. a delayed list) as a ready list, ' +
  'and its items point back to that list, so the walk cannot flag it';

/**
 * Turn a declared ready-list array into per-priority list addresses — or refuse, saying why.
 *
 * The declared `sizeof(List_t)` is evidence, not a stride to walk at: the walk derives one of the four supported
 * mini/integrity/tick-width layout, so a size that differs from `listRecordSize(layout)` means
 * every field past the header would be read at the wrong offset, and the derivation refuses rather than walking at
 * the declared stride. An `st_size` that disagrees with `maxPriorities × listSize` means one of three facts is
 * wrong, and nothing here can say which, so that refuses too.
 *
 * Size equality is necessary, not sufficient: different ABI options can produce the same record size. Tick width
 * therefore remains an explicit declaration rather than something inferred from `sizeof(List_t)`.
 *
 * What a later walk can and cannot catch. The stride is forced equal to the layout, so it cannot be wrong; a base
 * that is NOT a whole number of `List_t` records off shows up as items whose `pxContainer` does not point back. A
 * base off by whole records, or a priority count declared too high, does not: every derived address is then the
 * start of a real `List_t` (tasks.c declares the delayed lists right after the array), its items point back to it,
 * and the walk corroborates them perfectly. Only `st_size` checks the count, so without it the evidence says the
 * count was not cross-checked and what an over-declared count reads.
 */
export function deriveFreeRtosReadyLists(
  spec: FreeRtosReadyListArraySpec,
  layout: FreeRtosLayout,
  maxLists = 64,
): FreeRtosReadyListArrayDerivation {
  const { base, maxPriorities: n, listSize } = spec;
  const symbolSize = spec.symbolSize ?? null;
  if (!Number.isSafeInteger(n) || n < 1 || n > maxLists) {
    return {
      status: 'refused',
      code: 'invalid_count',
      reason: `configMAX_PRIORITIES must be a whole number from 1 to ${maxLists}; ${n} was declared`,
    };
  }
  if (!Number.isSafeInteger(listSize) || listSize < 1) {
    return {
      status: 'refused',
      code: 'invalid_size',
      reason: `sizeof(List_t) must be a positive whole number of bytes; ${listSize} was declared`,
    };
  }
  if (symbolSize !== null && (!Number.isSafeInteger(symbolSize) || symbolSize < 0)) {
    return {
      status: 'refused',
      code: 'invalid_size',
      reason: `pxReadyTasksLists st_size ${symbolSize} is not a byte count; an ELF st_size is a non-negative integer`,
    };
  }
  const stride = listRecordSize(layout);
  if (listSize !== stride) {
    const d = deriveFreeRtosListLayout(layout);
    return {
      status: 'refused',
      code: 'layout_mismatch',
      reason: `the build's List_t is declared as ${listSize} bytes but the declared FreeRTOS options produce a ${stride}-byte layout (configUSE_MINI_LIST_ITEM=${d.useMiniListItem ? 1 : 0}, configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES=${d.useListDataIntegrityCheckBytes ? 1 : 0}, TickType_t=${d.tickWidth} bytes); walking at a ${listSize}-byte stride would read fields at the wrong offsets`,
    };
  }
  const arrayBytes = n * listSize;
  // ELF: "a symbol has no size or an unknown size" when st_size is 0 — an absent fact, not a contradicting one.
  const checkedSize = symbolSize === 0 ? null : symbolSize;
  if (checkedSize !== null && checkedSize !== arrayBytes) {
    return {
      status: 'refused',
      code: 'size_mismatch',
      reason:
        `pxReadyTasksLists st_size is ${symbolSize} bytes but ${n} priorities × ${listSize} bytes is ` +
        `${arrayBytes}; one of the three facts is wrong and none is preferred over the others`,
    };
  }
  const evidence = [
    `sizeof(List_t) declared as ${listSize} bytes agrees with the ${stride}-byte layout the walk reads`,
  ];
  if (symbolSize === 0) evidence.push('pxReadyTasksLists st_size is 0, which ELF defines as no or unknown size');
  evidence.push(
    checkedSize === null
      ? `pxReadyTasksLists st_size not available; the priority count rests on the declaration of ${n} alone ` +
          `(not cross-checked) — ${FREERTOS_OVER_DECLARED_COUNT}`
      : `pxReadyTasksLists st_size ${checkedSize} agrees with ${n} priorities × ${listSize} bytes`,
  );
  const sizeCrossCheck = checkedSize === null ? 'not_available' : 'agrees';

  if (base === null) {
    evidence.push('pxReadyTasksLists was not resolved, so no per-priority address can be derived');
    return {
      status: 'derived',
      stride,
      sizeCrossCheck,
      lists: [{ kind: 'ready', name: 'pxReadyTasksLists', address: null }],
      evidence,
    };
  }
  const limit = layout.pointerWidth === 4 ? 2 ** 32 : Number.MAX_SAFE_INTEGER;
  if (!Number.isSafeInteger(base) || base < 0 || base + arrayBytes > limit) {
    const at = Number.isSafeInteger(base) && base >= 0 ? `0x${base.toString(16)}` : String(base);
    return {
      status: 'refused',
      code: 'address_overflow',
      reason: `pxReadyTasksLists at ${at} plus ${arrayBytes} bytes does not fit the ${layout.pointerWidth * 8}-bit address space`,
    };
  }
  const lists = Array.from(
    { length: n },
    (_, p): FreeRtosNamedList => ({
      kind: 'ready',
      name: `pxReadyTasksLists[${p}]`,
      address: base + p * stride,
      priority: p,
    }),
  );
  return { status: 'derived', stride, sizeCrossCheck, lists, evidence };
}

export interface FreeRtosCurrentTaskResult {
  coverage: 'complete' | 'out_of_range' | 'truncated' | 'missing_symbol';
  tcbAddress: number | null;
  evidence: string[];
}

export type FreeRtosTopReadyRepresentation = 'priority' | 'bitmap';

export interface FreeRtosReadyLaneObservation {
  priority: number | null;
  coverage: FreeRtosCoverage;
  /** Chain nodes, including a node whose owner was null. This decides whether the ready list itself was empty. */
  attempted: number;
}

export interface FreeRtosTopReadyPriorityResult {
  coverage: 'complete' | 'out_of_range' | 'truncated' | 'missing_symbol';
  address: number | null;
  representation: FreeRtosTopReadyRepresentation;
  value: number | null;
  /** Derived only from a complete, fully declared ready-list array; null means no comparison was licensed. */
  expected: number | null;
  agrees: boolean | null;
  evidence: string[];
}

/**
 * Read and reconcile FreeRTOS's `uxTopReadyPriority` scalar. In generic task selection it is a priority; ports
 * using optimized selection commonly turn the same storage into a ready-priority bitmap. The caller declares
 * which representation its build uses — this function never guesses it from the value.
 */
export function parseFreeRtosTopReadyPriority(
  buf: Uint8Array,
  regionBase: number,
  address: number | null,
  layout: FreeRtosLayout,
  representation: FreeRtosTopReadyRepresentation,
  readyLists: readonly FreeRtosReadyLaneObservation[],
  allPrioritiesDeclared: boolean,
): FreeRtosTopReadyPriorityResult {
  const base = { address, representation, value: null, expected: null, agrees: null } as const;
  if (address === null)
    return { ...base, coverage: 'missing_symbol', evidence: ['uxTopReadyPriority address not supplied'] };
  const offset = address - regionBase;
  if (offset < 0 || offset >= buf.length)
    return {
      ...base,
      coverage: 'out_of_range',
      evidence: [`uxTopReadyPriority address 0x${address.toString(16)} falls outside the mapped region`],
    };
  if (offset + layout.pointerWidth > buf.length)
    return {
      ...base,
      coverage: 'truncated',
      evidence: [`uxTopReadyPriority read at 0x${address.toString(16)} runs past the supplied buffer`],
    };

  const value = readUint(buf, offset, layout.pointerWidth, layout.endian === 'little');
  const observed = { ...base, coverage: 'complete' as const, value };
  if (!allPrioritiesDeclared || readyLists.some((l) => l.priority === null || l.coverage !== 'complete')) {
    return {
      ...observed,
      evidence: [
        'uxTopReadyPriority was read but not compared: every priority in a fully resolved ready-list array must complete',
      ],
    };
  }

  const nonEmpty = readyLists.filter((l) => l.attempted > 0).map((l) => l.priority as number);
  if (nonEmpty.length === 0) {
    return {
      ...observed,
      evidence: [
        'uxTopReadyPriority was read but no declared ready list was non-empty, so no expected value was claimed',
      ],
    };
  }
  const expected =
    representation === 'priority'
      ? Math.max(...nonEmpty)
      : nonEmpty.reduce((bits, priority) => bits + 2 ** priority, 0);
  const agrees = value === expected;
  const meaning = representation === 'priority' ? 'highest non-empty ready priority' : 'ready-priority bitmap';
  return {
    ...observed,
    expected,
    agrees,
    evidence: [
      agrees
        ? `uxTopReadyPriority ${representation} value ${value} agrees with the ${meaning} derived from the complete array`
        : `uxTopReadyPriority ${representation} value ${value} does not equal ${expected}, the ${meaning} derived from the complete array — the declared mode may be wrong or the snapshot may be torn`,
    ],
  };
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
