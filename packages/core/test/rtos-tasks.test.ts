import { describe, expect, it } from 'vitest';
import {
  FREERTOS_ITEM_VALUE_MEANING,
  type FreeRtosListKind,
  listItemRecordSize,
  listRecordSize,
  listSentinelHeadSize,
  parseFreeRtosCurrentTask,
  parseFreeRtosList,
  parseFreeRtosNamedList,
  parseFreeRtosReadyList,
  pointerAlignmentPadding,
} from '../src/rtos-tasks.js';

/**
 * Byte-level fixture builder for a FreeRTOS `List_t` + `ListItem_t` chain (default, no integrity-check bytes):
 * `List_t` = uxNumberOfItems(4) + pxIndex(4) + xListEnd{itemValue(4) + pxNext(4) + pxPrevious(4)}.
 * `ListItem_t` = itemValue(4) + pxNext(4) + pxPrevious(4) + pvOwner(4) + pxContainer(4) = 20 bytes.
 */
function memory(regionBase: number, size: number, le: boolean) {
  const buf = new Uint8Array(size);
  const dv = new DataView(buf.buffer);
  const w32 = (addr: number, val: number) => dv.setUint32(addr - regionBase, val >>> 0, le);
  const writeListHeader = (listAddr: number, headNext: number, count = 0) => {
    w32(listAddr, count); // uxNumberOfItems (read only by the named-list walk, as an annotation)
    w32(listAddr + 4, 0); // pxIndex (unused by the parser)
    w32(listAddr + 8, 0); // xListEnd.itemValue
    w32(listAddr + 12, headNext); // xListEnd.pxNext
    w32(listAddr + 16, 0); // xListEnd.pxPrevious
  };
  const writeItem = (addr: number, itemValue: number, next: number, owner: number, container = 0) => {
    w32(addr, itemValue);
    w32(addr + 4, next);
    w32(addr + 8, 0); // pxPrevious (unused by the parser)
    w32(addr + 12, owner);
    w32(addr + 16, container); // pxContainer (checked only by the named-list walk)
  };
  return { buf, writeListHeader, writeItem };
}

const REGION_BASE = 0x2000_0000;
const LIST_ADDR = REGION_BASE; // sentinel lives at LIST_ADDR + 8
const SENTINEL = LIST_ADDR + 8;
const ITEM_A = REGION_BASE + 0x20;
const ITEM_B = REGION_BASE + 0x40;
const ITEM_C = REGION_BASE + 0x60;

describe('parseFreeRtosReadyList', () => {
  it('walks a valid circular list back to its sentinel (little-endian)', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A);
    writeItem(ITEM_A, 5, ITEM_B, 0x3000_0001);
    writeItem(ITEM_B, 10, ITEM_C, 0x3000_0002);
    writeItem(ITEM_C, 15, SENTINEL, 0x3000_0003);

    const result = parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR);
    expect(result.coverage).toBe('complete');
    expect(result.attempted).toBe(3);
    expect(result.completed).toBe(3);
    expect(result.tasks).toEqual([
      { listItemAddress: ITEM_A, itemValue: 5, tcbAddress: 0x3000_0001 },
      { listItemAddress: ITEM_B, itemValue: 10, tcbAddress: 0x3000_0002 },
      { listItemAddress: ITEM_C, itemValue: 15, tcbAddress: 0x3000_0003 },
    ]);
  });

  it('walks the same layout big-endian', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, false);
    writeListHeader(LIST_ADDR, ITEM_A);
    writeItem(ITEM_A, 1, ITEM_B, 0x3000_0011);
    writeItem(ITEM_B, 2, SENTINEL, 0x3000_0012);

    const result = parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR, { pointerWidth: 4, endian: 'big' });
    expect(result.coverage).toBe('complete');
    expect(result.attempted).toBe(2);
    expect(result.completed).toBe(2);
    expect(result.tasks.map((t) => t.tcbAddress)).toEqual([0x3000_0011, 0x3000_0012]);
  });

  it('caps a cycle that revisits a node instead of returning to the sentinel', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A);
    writeItem(ITEM_A, 1, ITEM_B, 0x3000_0001);
    writeItem(ITEM_B, 2, ITEM_C, 0x3000_0002);
    writeItem(ITEM_C, 3, ITEM_B, 0x3000_0003); // points back into the chain, not the sentinel

    const result = parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR);
    expect(result.coverage).toBe('cycle_capped');
    expect(result.attempted).toBe(3);
    expect(result.completed).toBe(3); // the 3 distinct nodes still corroborated before the cycle was detected
    expect(result.evidence.some((e) => e.includes('revisited'))).toBe(true);
  });

  it('reports out_of_range when a chain pointer leaves the mapped region', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A);
    writeItem(ITEM_A, 1, 0xffff_ff00, 0x3000_0001); // next leaves the region entirely

    const result = parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR);
    expect(result.coverage).toBe('out_of_range');
    expect(result.attempted).toBe(2);
    expect(result.completed).toBe(1);
    expect(result.tasks).toEqual([{ listItemAddress: ITEM_A, itemValue: 1, tcbAddress: 0x3000_0001 }]);
  });

  it('reports truncated when a record runs past the end of the supplied buffer', () => {
    const size = 0x200;
    const { buf, writeListHeader } = memory(REGION_BASE, size, true);
    const nearEnd = REGION_BASE + size - 10; // only 10 bytes left, a ListItem_t needs 20
    writeListHeader(LIST_ADDR, nearEnd);

    const result = parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR);
    expect(result.coverage).toBe('truncated');
    expect(result.attempted).toBe(1);
    expect(result.completed).toBe(0);
    expect(result.tasks).toEqual([]);
  });

  it('reports missing_symbol without claiming an empty list when no address was resolved', () => {
    const { buf } = memory(REGION_BASE, 0x200, true);
    const result = parseFreeRtosReadyList(buf, REGION_BASE, null);
    expect(result.coverage).toBe('missing_symbol');
    expect(result.tasks).toEqual([]);
  });

  it('treats a structurally-empty list (sentinel points to itself) as conclusively zero tasks', () => {
    const { buf, writeListHeader } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, SENTINEL); // head == sentinel: no items

    const result = parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR);
    expect(result.coverage).toBe('complete');
    expect(result.attempted).toBe(0);
    expect(result.completed).toBe(0);
    expect(result.tasks).toEqual([]);
    // Contrast: the SAME empty tasks/attempted shape from missing_symbol or out_of_range is NOT conclusive —
    // only 'complete' licenses reading zero tasks as "this list has no tasks".
  });

  it('does not corroborate a node with a null owner, but keeps traversing', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A);
    writeItem(ITEM_A, 1, ITEM_B, 0); // null pvOwner — structurally present, not a corroborated task
    writeItem(ITEM_B, 2, SENTINEL, 0x3000_0002);

    const result = parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR);
    expect(result.coverage).toBe('complete');
    expect(result.attempted).toBe(2);
    expect(result.completed).toBe(1);
    expect(result.tasks).toEqual([{ listItemAddress: ITEM_B, itemValue: 2, tcbAddress: 0x3000_0002 }]);
  });
});

describe('parseFreeRtosCurrentTask', () => {
  it('reads the pxCurrentTCB pointer', () => {
    const { buf } = memory(REGION_BASE, 0x200, true);
    const dv = new DataView(buf.buffer);
    const pxCurrentTcb = REGION_BASE + 0x100;
    dv.setUint32(0x100, 0x3000_0099, true);

    const result = parseFreeRtosCurrentTask(buf, REGION_BASE, pxCurrentTcb);
    expect(result.coverage).toBe('complete');
    expect(result.tcbAddress).toBe(0x3000_0099);
  });

  it('reports missing_symbol when no address is supplied', () => {
    const { buf } = memory(REGION_BASE, 0x200, true);
    const result = parseFreeRtosCurrentTask(buf, REGION_BASE, null);
    expect(result.coverage).toBe('missing_symbol');
    expect(result.tcbAddress).toBeNull();
  });

  it('reports out_of_range for an address outside the mapped region', () => {
    const { buf } = memory(REGION_BASE, 0x200, true);
    const result = parseFreeRtosCurrentTask(buf, REGION_BASE, 0x9000_0000);
    expect(result.coverage).toBe('out_of_range');
    expect(result.tcbAddress).toBeNull();
  });
});

describe('parseFreeRtosReadyList (unchanged by the named-list walk)', () => {
  it('returns exactly its original five fields, even over a header and containers the named walk reads', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A, 7); // a header count that disagrees with the chain
    writeItem(ITEM_A, 9, SENTINEL, 0x3000_0001, 0xdead_beef); // a container that does not point back

    const result = parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR);
    expect(result).toEqual({
      coverage: 'complete',
      attempted: 1,
      completed: 1,
      tasks: [{ listItemAddress: ITEM_A, itemValue: 9, tcbAddress: 0x3000_0001 }],
      evidence: [],
    });
    expect(parseFreeRtosReadyList(buf, REGION_BASE, null).evidence).toEqual(['no ready-list address supplied']);
  });
});

describe('parseFreeRtosNamedList', () => {
  const DELAYED = REGION_BASE + 0x100; // a second List_t, sentinel at +8
  const DELAYED_SENTINEL = DELAYED + 8;

  it('walks a delayed list and reads its item values as wake ticks, in ascending order', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(DELAYED, ITEM_A, 3);
    writeItem(ITEM_A, 100, ITEM_B, 0x3000_0001, DELAYED);
    writeItem(ITEM_B, 250, ITEM_C, 0x3000_0002, DELAYED);
    writeItem(ITEM_C, 250, DELAYED_SENTINEL, 0x3000_0003, DELAYED); // equal wake ticks are still in order

    const r = parseFreeRtosNamedList(buf, REGION_BASE, {
      kind: 'delayed',
      name: 'xDelayedTaskList1',
      address: DELAYED,
    });
    expect(r).toMatchObject({
      kind: 'delayed',
      name: 'xDelayedTaskList1',
      listAddress: DELAYED,
      coverage: 'complete',
      attempted: 3,
      completed: 3,
      itemValueMeaning: 'wake_tick',
      declaredItems: 3,
      containerMismatches: 0,
      orderViolations: 0,
      evidence: [],
    });
    expect(r.tasks.map((t) => t.itemValue)).toEqual([100, 250, 250]);
  });

  it('flags wake ticks that decrease along a delayed chain without changing its coverage', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(DELAYED, ITEM_A, 2);
    writeItem(ITEM_A, 500, ITEM_B, 0x3000_0001, DELAYED);
    writeItem(ITEM_B, 20, DELAYED_SENTINEL, 0x3000_0002, DELAYED);

    const r = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'delayed_overflow', address: DELAYED });
    expect(r.name).toBe('pxOverflowDelayedTaskList');
    expect(r.coverage).toBe('complete');
    expect(r.orderViolations).toBe(1);
    expect(r.evidence.some((e) => e.includes('out of ascending order'))).toBe(true);
  });

  it('never reads order into a list whose item values the kernel does not maintain', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A, 2);
    writeItem(ITEM_A, 500, ITEM_B, 0x3000_0001, LIST_ADDR);
    writeItem(ITEM_B, 20, SENTINEL, 0x3000_0002, LIST_ADDR);

    const r = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'suspended', address: LIST_ADDR });
    expect(r).toMatchObject({ name: 'xSuspendedTaskList', itemValueMeaning: 'not_maintained', orderViolations: 0 });
    expect(r.evidence).toEqual([]);
  });

  it('reports a header count that disagrees with a complete chain as a possibly torn snapshot', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A, 4);
    writeItem(ITEM_A, 0, SENTINEL, 0x3000_0001, LIST_ADDR);

    const r = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'terminated', address: LIST_ADDR });
    expect(r.coverage).toBe('complete');
    expect(r.declaredItems).toBe(4);
    expect(r.evidence).toEqual([expect.stringContaining('uxNumberOfItems reads 4 but the chain holds 1')]);
  });

  it('counts nodes whose pxContainer does not point back, but keeps them as walked tasks', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A, 2);
    writeItem(ITEM_A, 0, ITEM_B, 0x3000_0001, LIST_ADDR);
    writeItem(ITEM_B, 0, SENTINEL, 0x3000_0002, DELAYED); // claims to belong to another list

    const r = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'pending', address: LIST_ADDR });
    expect(r).toMatchObject({ coverage: 'complete', completed: 2, containerMismatches: 1 });
    expect(r.itemValueMeaning).toBe('event_order');
    expect(r.evidence).toEqual([expect.stringContaining(`0x${ITEM_B.toString(16)} has a pxContainer`)]);
  });

  it('reports missing_symbol per kind, naming the list, without claiming it is empty', () => {
    const { buf } = memory(REGION_BASE, 0x200, true);
    const r = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'suspended', address: null });
    expect(r).toMatchObject({ coverage: 'missing_symbol', attempted: 0, completed: 0, declaredItems: null });
    expect(r.evidence).toEqual(['no address supplied for xSuspendedTaskList (suspended)']);
  });

  it('reports out_of_range and truncated for a sentinel the buffer does not hold', () => {
    const size = 0x200;
    const { buf } = memory(REGION_BASE, size, true);
    const outside = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'delayed', address: 0x1000_0000 });
    expect(outside).toMatchObject({ coverage: 'out_of_range', attempted: 0, declaredItems: null });
    // The sentinel starts 4 bytes from the end: in the region, but its pxNext is cut off.
    const edge = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'delayed', address: REGION_BASE + size - 12 });
    expect(edge).toMatchObject({ coverage: 'truncated', attempted: 0 });
  });

  it('reports a chain that leaves the region mid-walk as out_of_range, keeping what it corroborated first', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(DELAYED, ITEM_A, 2);
    writeItem(ITEM_A, 10, 0x9000_0000, 0x3000_0001, DELAYED);

    const r = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'delayed', address: DELAYED });
    expect(r).toMatchObject({ coverage: 'out_of_range', attempted: 2, completed: 1 });
    // A count mismatch is only meaningful against a complete chain; a partial walk does not report one.
    expect(r.evidence.some((e) => e.includes('uxNumberOfItems'))).toBe(false);
  });

  it('caps a chain that never returns to its sentinel at the traversal bound', () => {
    // 300 distinct nodes in a straight line: the cap fires before any revisit could.
    const nodes = 300;
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x20 + nodes * 0x14 + 0x20, true);
    const at = (i: number) => REGION_BASE + 0x20 + i * 0x14;
    writeListHeader(LIST_ADDR, at(0));
    for (let i = 0; i < nodes; i++) writeItem(at(i), i, at(i + 1), 0x3000_0000 + i, LIST_ADDR);

    const r = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'suspended', address: LIST_ADDR });
    expect(r.coverage).toBe('cycle_capped');
    expect(r.attempted).toBe(256);
    expect(r.evidence.some((e) => e.includes('traversal cap of 256'))).toBe(true);
  });

  it('walks the same layout with 8-byte pointers, big-endian', () => {
    const buf = new Uint8Array(0x200);
    const dv = new DataView(buf.buffer);
    const w64 = (addr: number, v: number) => dv.setBigUint64(addr - REGION_BASE, BigInt(v), false);
    // List_t: uxNumberOfItems(8) + pxIndex(8) + xListEnd{itemValue(4) + pad(4) + pxNext(8) + pxPrevious(8)}
    w64(LIST_ADDR, 1);
    w64(LIST_ADDR + 8, LIST_ADDR + 16);
    dv.setUint32(LIST_ADDR + 16 - REGION_BASE, 0, false);
    w64(LIST_ADDR + 24, ITEM_C); // sentinel pxNext (after 4-byte pad)
    w64(LIST_ADDR + 32, ITEM_C); // sentinel pxPrevious
    // ListItem_t: itemValue(4) + pad(4) + pxNext(8) + pxPrevious(8) + pvOwner(8) + pxContainer(8)
    dv.setUint32(ITEM_C - REGION_BASE, 77, false);
    w64(ITEM_C + 8, LIST_ADDR + 16); // pxNext (after 4-byte pad)
    w64(ITEM_C + 16, LIST_ADDR + 16);
    w64(ITEM_C + 24, 0x3000_00aa); // pvOwner
    w64(ITEM_C + 32, LIST_ADDR); // pxContainer

    const r = parseFreeRtosNamedList(
      buf,
      REGION_BASE,
      { kind: 'delayed', address: LIST_ADDR },
      { pointerWidth: 8, endian: 'big' },
    );
    expect(r).toMatchObject({ coverage: 'complete', completed: 1, declaredItems: 1, containerMismatches: 0 });
    expect(r.tasks).toEqual([{ listItemAddress: ITEM_C, itemValue: 77, tcbAddress: 0x3000_00aa }]);
  });

  it('computes record and sentinel sizes with standard natural alignment on 32-bit and 64-bit', () => {
    expect(pointerAlignmentPadding({ pointerWidth: 4, endian: 'little' })).toBe(0);
    expect(pointerAlignmentPadding({ pointerWidth: 8, endian: 'little' })).toBe(4);
    expect(listItemRecordSize({ pointerWidth: 4, endian: 'little' })).toBe(20);
    expect(listItemRecordSize({ pointerWidth: 8, endian: 'little' })).toBe(40);
    expect(listSentinelHeadSize({ pointerWidth: 4, endian: 'little' })).toBe(8);
    expect(listSentinelHeadSize({ pointerWidth: 8, endian: 'little' })).toBe(16);
  });

  it('strides adjacent List_t records by listRecordSize, the way pxReadyTasksLists[] lays them out', () => {
    expect(listRecordSize({ pointerWidth: 4, endian: 'little' })).toBe(20);
    expect(listRecordSize({ pointerWidth: 8, endian: 'little' })).toBe(40);
    // Priority 1's list sits one record after priority 0's; walking it at that address must reach its own sentinel.
    const stride = listRecordSize({ pointerWidth: 4, endian: 'little' });
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, LIST_ADDR + 8);
    writeListHeader(LIST_ADDR + stride, ITEM_B, 1);
    writeItem(ITEM_B, 0, LIST_ADDR + stride + 8, 0x3000_0042);
    expect(parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR)).toMatchObject({ coverage: 'complete', completed: 0 });
    const second = parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR + stride);
    expect(second).toMatchObject({ coverage: 'complete', completed: 1 });
    expect(second.tasks.map((t) => t.tcbAddress)).toEqual([0x3000_0042]);
  });

  it('carries a ready list priority through, and a ready walk agrees with parseFreeRtosReadyList', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A, 1);
    writeItem(ITEM_A, 3, SENTINEL, 0x3000_0001, LIST_ADDR);

    const named = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'ready', address: LIST_ADDR, priority: 3 });
    const ready = parseFreeRtosReadyList(buf, REGION_BASE, LIST_ADDR);
    expect(named).toMatchObject({ ...ready, kind: 'ready', priority: 3, itemValueMeaning: 'not_maintained' });
  });
});

describe('parseFreeRtosList', () => {
  it('walks every kind independently: one failed list never stops or colours another', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A, 1);
    writeItem(ITEM_A, 42, SENTINEL, 0x3000_0001, LIST_ADDR);

    const kinds: FreeRtosListKind[] = ['ready', 'delayed', 'delayed_overflow', 'suspended', 'pending', 'terminated'];
    const results = parseFreeRtosList(buf, REGION_BASE, [
      { kind: 'delayed', address: LIST_ADDR },
      { kind: 'suspended', address: null },
      { kind: 'terminated', address: 0x9000_0000 },
    ]);
    expect(results.map((r) => [r.kind, r.coverage, r.completed])).toEqual([
      ['delayed', 'complete', 1],
      ['suspended', 'missing_symbol', 0],
      ['terminated', 'out_of_range', 0],
    ]);
    expect(Object.keys(FREERTOS_ITEM_VALUE_MEANING).sort()).toEqual([...kinds].sort());
  });
});
