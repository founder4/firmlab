/**
 * Bounded, byte-only enumeration of FreeRTOS task records from a memory snapshot — no signature guessing.
 *
 * This is deliberately narrow: it walks ONE evidenced layout (FreeRTOS's `List_t` / `ListItem_t`, as declared in
 * `kernel/include/list.h` with the default `configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES == 0` build), and only when
 * the caller supplies the address of a real list (a `pxReadyTasksLists[priority]` entry, or `pxCurrentTCB`) —
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
 * Defensive cap on nodes visited per list. A real FreeRTOS ready list holds at most `configMAX_PRIORITIES` tasks
 * (tens, never thousands), so this only ever bounds a corrupted or adversarial chain that does not return to its
 * own sentinel — it is not expected to fire on real firmware.
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
  /** The item's `xItemValue` — for a ready list, its priority-ordering key. */
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
  if (listAddress === null) {
    return {
      coverage: 'missing_symbol',
      attempted: 0,
      completed: 0,
      tasks: [],
      evidence: ['no ready-list address supplied'],
    };
  }

  const ptr = layout.pointerWidth;
  const le = layout.endian === 'little';
  const recordSize = listItemRecordSize(layout);
  const nextOffset = TICK_WIDTH;
  const ownerOffset = TICK_WIDTH + 2 * ptr;
  // List_t header (no integrity-check bytes): uxNumberOfItems (ptr-width) + pxIndex (ptr-width) precede xListEnd.
  const sentinelAddress = listAddress + 2 * ptr;
  const regionEnd = regionBase + buf.length;

  const inRegion = (addr: number) => addr >= regionBase && addr < regionEnd;
  const readField = (addr: number, fieldOffset: number) => readUint(buf, addr - regionBase + fieldOffset, ptr, le);

  // xListEnd is a MiniListItem_t (itemValue + pxNext + pxPrevious, no owner) — its pxNext is the chain head.
  if (!inRegion(sentinelAddress)) {
    return {
      coverage: 'out_of_range',
      attempted: 0,
      completed: 0,
      tasks: [],
      evidence: [`list sentinel at 0x${sentinelAddress.toString(16)} falls outside the mapped region`],
    };
  }
  if (sentinelAddress - regionBase + TICK_WIDTH + ptr > buf.length) {
    return {
      coverage: 'truncated',
      attempted: 0,
      completed: 0,
      tasks: [],
      evidence: [`list sentinel at 0x${sentinelAddress.toString(16)} runs past the end of the supplied buffer`],
    };
  }

  let cur = readField(sentinelAddress, nextOffset);
  const visited = new Set<number>();
  const tasks: FreeRtosTaskRecord[] = [];
  const evidence: string[] = [];
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
    if (ownerAddr === 0) {
      evidence.push(`list item at 0x${cur.toString(16)} has a null owner — not corroborated as a task`);
    } else {
      tasks.push({ listItemAddress: cur, itemValue, tcbAddress: ownerAddr });
    }
    cur = readField(cur, nextOffset);
  }

  return { coverage, attempted, completed: tasks.length, tasks, evidence };
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
