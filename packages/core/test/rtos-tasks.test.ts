import { describe, expect, it } from 'vitest';
import {
  DEFAULT_FREERTOS_LAYOUT,
  FREERTOS_ITEM_VALUE_MEANING,
  FREERTOS_OVER_DECLARED_COUNT,
  type FreeRtosListKind,
  decodeFreeRtosEventGroupValue,
  deriveFreeRtosListLayout,
  deriveFreeRtosReadyLists,
  listItemRecordSize,
  listRecordSize,
  listSentinelHeadSize,
  parseFreeRtosCurrentTask,
  parseFreeRtosList,
  parseFreeRtosNamedList,
  parseFreeRtosReadyList,
  parseFreeRtosTopReadyPriority,
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

describe('parseFreeRtosTopReadyPriority', () => {
  const address = REGION_BASE + 0x180;
  const lanes = [
    { priority: 0, coverage: 'complete' as const, attempted: 1 },
    { priority: 1, coverage: 'complete' as const, attempted: 2 },
    { priority: 2, coverage: 'complete' as const, attempted: 0 },
    { priority: 3, coverage: 'complete' as const, attempted: 1 },
  ];

  it('compares the declared generic-priority representation with the highest non-empty ready list', () => {
    const { buf } = memory(REGION_BASE, 0x200, true);
    new DataView(buf.buffer).setUint32(address - REGION_BASE, 3, true);
    expect(
      parseFreeRtosTopReadyPriority(buf, REGION_BASE, address, DEFAULT_FREERTOS_LAYOUT, 'priority', lanes, true),
    ).toMatchObject({ coverage: 'complete', value: 3, expected: 3, agrees: true });
  });

  it('compares the explicitly declared optimized representation as a bitmap', () => {
    const { buf } = memory(REGION_BASE, 0x200, true);
    new DataView(buf.buffer).setUint32(address - REGION_BASE, 0b1011, true);
    expect(
      parseFreeRtosTopReadyPriority(buf, REGION_BASE, address, DEFAULT_FREERTOS_LAYOUT, 'bitmap', lanes, true),
    ).toMatchObject({ coverage: 'complete', value: 0b1011, expected: 0b1011, agrees: true });
  });

  it('records a disagreement without changing scalar-read coverage', () => {
    const { buf } = memory(REGION_BASE, 0x200, true);
    new DataView(buf.buffer).setUint32(address - REGION_BASE, 1, true);
    const r = parseFreeRtosTopReadyPriority(
      buf,
      REGION_BASE,
      address,
      DEFAULT_FREERTOS_LAYOUT,
      'priority',
      lanes,
      true,
    );
    expect(r).toMatchObject({ coverage: 'complete', value: 1, expected: 3, agrees: false });
    expect(r.evidence.join('\n')).toMatch(/declared mode may be wrong or the snapshot may be torn/);
  });

  it('reads but refuses to compare incomplete or manually selected ready-list coverage', () => {
    const { buf } = memory(REGION_BASE, 0x200, true);
    new DataView(buf.buffer).setUint32(address - REGION_BASE, 3, true);
    const manual = parseFreeRtosTopReadyPriority(
      buf,
      REGION_BASE,
      address,
      DEFAULT_FREERTOS_LAYOUT,
      'priority',
      lanes,
      false,
    );
    expect(manual).toMatchObject({ coverage: 'complete', value: 3, expected: null, agrees: null });
    const partial = parseFreeRtosTopReadyPriority(
      buf,
      REGION_BASE,
      address,
      DEFAULT_FREERTOS_LAYOUT,
      'priority',
      [{ ...lanes[0], coverage: 'truncated' }],
      true,
    );
    expect(partial).toMatchObject({ coverage: 'complete', expected: null, agrees: null });
  });

  it('reports missing, out-of-range and truncated scalar reads explicitly', () => {
    const { buf } = memory(REGION_BASE, 0x20, true);
    expect(
      parseFreeRtosTopReadyPriority(buf, REGION_BASE, null, DEFAULT_FREERTOS_LAYOUT, 'priority', [], false).coverage,
    ).toBe('missing_symbol');
    expect(
      parseFreeRtosTopReadyPriority(buf, REGION_BASE, REGION_BASE - 4, DEFAULT_FREERTOS_LAYOUT, 'priority', [], false)
        .coverage,
    ).toBe('out_of_range');
    expect(
      parseFreeRtosTopReadyPriority(
        buf,
        REGION_BASE,
        REGION_BASE + buf.length - 2,
        DEFAULT_FREERTOS_LAYOUT,
        'priority',
        [],
        false,
      ).coverage,
    ).toBe('truncated');
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
      integrityChecks: { enabled: false, attempted: 0, completed: 0, mismatches: 0 },
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

  it('walks a caller-named ordered queue wait list as xEventListItem ordering evidence', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A, 1);
    writeItem(ITEM_A, 4, SENTINEL, 0x3000_0042, LIST_ADDR);

    expect(
      parseFreeRtosNamedList(buf, REGION_BASE, {
        kind: 'event',
        name: 'fixtureQueue.xTasksWaitingToReceive',
        address: LIST_ADDR,
      }),
    ).toMatchObject({
      kind: 'event',
      name: 'fixtureQueue.xTasksWaitingToReceive',
      coverage: 'complete',
      itemValueMeaning: 'event_order',
      tasks: [{ tcbAddress: 0x3000_0042, itemValue: 4 }],
    });
  });

  it('records a descending value in an ordered queue wait list as structural evidence', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A, 2);
    writeItem(ITEM_A, 4, ITEM_B, 0x3000_0042, LIST_ADDR);
    writeItem(ITEM_B, 2, SENTINEL, 0x3000_0043, LIST_ADDR);

    const r = parseFreeRtosNamedList(buf, REGION_BASE, {
      kind: 'event',
      name: 'fixtureQueue.xTasksWaitingToReceive',
      address: LIST_ADDR,
    });
    expect(r.orderViolations).toBe(1);
    expect(r.evidence).toEqual([expect.stringContaining('unsupported unordered EventGroup list')]);
  });

  it('walks an unordered EventGroup wait list and decodes bits/control flags without priority ordering', () => {
    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A, 2);
    writeItem(ITEM_A, 0x8500_0005, ITEM_B, 0x3000_0042, LIST_ADDR);
    writeItem(ITEM_B, 0x8100_0002, SENTINEL, 0x3000_0043, LIST_ADDR);

    const r = parseFreeRtosNamedList(buf, REGION_BASE, {
      kind: 'event_group',
      name: 'fixtureEventGroup.xTasksWaitingForBits',
      address: LIST_ADDR,
      waitKind: 'event_group',
    });
    expect(r).toMatchObject({
      kind: 'event_group',
      itemValueMeaning: 'event_bits',
      orderViolations: 0,
      valueViolations: 0,
      tasks: [
        {
          itemValue: 0x8500_0005,
          eventGroupWait: {
            bits: 5,
            waitForAll: true,
            clearOnExit: true,
            unblockedDueToBitSet: false,
            itemValueInUse: true,
          },
        },
        { itemValue: 0x8100_0002, eventGroupWait: { bits: 2, waitForAll: false, clearOnExit: true } },
      ],
    });
    expect(r.evidence).toEqual([]);
  });

  it('decodes EventGroup control bits at 16/32/64-bit widths and flags invalid wait values', () => {
    expect(decodeFreeRtosEventGroupValue(0x8505n, 2)).toMatchObject({ bits: 5, waitForAll: true });
    expect(decodeFreeRtosEventGroupValue(0x8500_0005n, 4)).toMatchObject({ bits: 5, waitForAll: true });
    expect(decodeFreeRtosEventGroupValue(0x8500_0000_0000_0005n, 8)).toMatchObject({
      bits: 5,
      waitForAll: true,
    });

    const { buf, writeListHeader, writeItem } = memory(REGION_BASE, 0x200, true);
    writeListHeader(LIST_ADDR, ITEM_A, 1);
    writeItem(ITEM_A, 0, SENTINEL, 0x3000_0042, LIST_ADDR);
    const invalid = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'event_group', address: LIST_ADDR });
    expect(invalid.valueViolations).toBe(1);
    expect(invalid.evidence.join('\n')).toContain('request zero user bits');
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
    expect(pointerAlignmentPadding({ pointerWidth: 4, endian: 'little', tickWidth: 2 })).toBe(2);
    expect(pointerAlignmentPadding({ pointerWidth: 4, endian: 'little', tickWidth: 8 })).toBe(0);
    expect(listItemRecordSize({ pointerWidth: 4, endian: 'little' })).toBe(20);
    expect(listItemRecordSize({ pointerWidth: 8, endian: 'little' })).toBe(40);
    expect(listSentinelHeadSize({ pointerWidth: 4, endian: 'little' })).toBe(8);
    expect(listSentinelHeadSize({ pointerWidth: 8, endian: 'little' })).toBe(16);
  });

  it('derives the mini/integrity layouts for 16-, 32- and 64-bit ticks with natural alignment', () => {
    const expected = [
      {
        pointerWidth: 4 as const,
        tickWidth: 2 as const,
        mini: true,
        integrity: false,
        item: 20,
        sentinel: 12,
        list: 20,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 2 as const,
        mini: false,
        integrity: false,
        item: 20,
        sentinel: 20,
        list: 28,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 2 as const,
        mini: true,
        integrity: true,
        item: 24,
        sentinel: 12,
        list: 28,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 2 as const,
        mini: false,
        integrity: true,
        item: 24,
        sentinel: 24,
        list: 40,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 4 as const,
        mini: true,
        integrity: false,
        item: 20,
        sentinel: 12,
        list: 20,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 4 as const,
        mini: false,
        integrity: false,
        item: 20,
        sentinel: 20,
        list: 28,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 4 as const,
        mini: true,
        integrity: true,
        item: 28,
        sentinel: 16,
        list: 32,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 4 as const,
        mini: false,
        integrity: true,
        item: 28,
        sentinel: 28,
        list: 44,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 8 as const,
        mini: true,
        integrity: false,
        item: 24,
        sentinel: 16,
        list: 24,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 8 as const,
        mini: false,
        integrity: false,
        item: 24,
        sentinel: 24,
        list: 32,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 8 as const,
        mini: true,
        integrity: true,
        item: 40,
        sentinel: 24,
        list: 48,
      },
      {
        pointerWidth: 4 as const,
        tickWidth: 8 as const,
        mini: false,
        integrity: true,
        item: 40,
        sentinel: 40,
        list: 64,
      },
      {
        pointerWidth: 8 as const,
        tickWidth: 2 as const,
        mini: true,
        integrity: false,
        item: 40,
        sentinel: 24,
        list: 40,
      },
      {
        pointerWidth: 8 as const,
        tickWidth: 2 as const,
        mini: true,
        integrity: true,
        item: 48,
        sentinel: 24,
        list: 56,
      },
      {
        pointerWidth: 8 as const,
        tickWidth: 4 as const,
        mini: false,
        integrity: true,
        item: 48,
        sentinel: 48,
        list: 80,
      },
      {
        pointerWidth: 8 as const,
        tickWidth: 8 as const,
        mini: true,
        integrity: false,
        item: 40,
        sentinel: 24,
        list: 40,
      },
      {
        pointerWidth: 8 as const,
        tickWidth: 8 as const,
        mini: true,
        integrity: true,
        item: 56,
        sentinel: 32,
        list: 64,
      },
      {
        pointerWidth: 8 as const,
        tickWidth: 8 as const,
        mini: false,
        integrity: true,
        item: 56,
        sentinel: 56,
        list: 88,
      },
    ];
    for (const e of expected) {
      const d = deriveFreeRtosListLayout({
        pointerWidth: e.pointerWidth,
        endian: 'little',
        tickWidth: e.tickWidth,
        useMiniListItem: e.mini,
        useListDataIntegrityCheckBytes: e.integrity,
      });
      expect(d.tickWidth).toBe(e.tickWidth);
      expect([d.listItem.size, d.sentinel.size, d.list.size]).toEqual([e.item, e.sentinel, e.list]);
    }
  });

  it('walks 16-, 32- and 64-bit tick values exactly in both byte orders', () => {
    const values = new Map<2 | 4 | 8, bigint>([
      [2, 0x1234n],
      [4, 0x1234_5678n],
      [8, 0xfedc_ba98_7654_3210n],
    ]);
    const align = (offset: number, width: number) => Math.ceil(offset / width) * width;
    for (const tickWidth of [2, 4, 8] as const) {
      for (const endian of ['little', 'big'] as const) {
        const little = endian === 'little';
        const layout = {
          pointerWidth: 4 as const,
          tickWidth,
          endian,
          useMiniListItem: true,
          useListDataIntegrityCheckBytes: true,
        };
        const d = deriveFreeRtosListLayout(layout);
        const buf = new Uint8Array(0x200);
        const dv = new DataView(buf.buffer);
        const item = REGION_BASE + 0x100;
        const sentinel = LIST_ADDR + d.list.sentinelOffset;
        const marker = BigInt(`0x${'5a'.repeat(tickWidth)}`);
        const tick = (address: number, value: bigint) => {
          const offset = address - REGION_BASE;
          if (tickWidth === 2) dv.setUint16(offset, Number(value), little);
          else if (tickWidth === 4) dv.setUint32(offset, Number(value), little);
          else dv.setBigUint64(offset, value, little);
        };
        const ptr = (address: number, value: number) => dv.setUint32(address - REGION_BASE, value, little);

        for (const address of [
          LIST_ADDR,
          LIST_ADDR + align(d.list.sentinelOffset + d.sentinel.size, tickWidth),
          sentinel,
          item,
          item + align(d.listItem.containerOffset + layout.pointerWidth, tickWidth),
        ])
          tick(address, marker);
        ptr(LIST_ADDR + d.list.numberOfItemsOffset, 1);
        ptr(sentinel + d.sentinel.nextOffset, item);
        tick(item + d.listItem.itemValueOffset, values.get(tickWidth) ?? 0n);
        ptr(item + d.listItem.nextOffset, sentinel);
        ptr(item + d.listItem.ownerOffset, 0x3000_0042);
        ptr(item + d.listItem.containerOffset, LIST_ADDR);

        const result = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'delayed', address: LIST_ADDR }, layout);
        expect(result).toMatchObject({
          coverage: 'complete',
          declaredItems: 1,
          integrityChecks: { enabled: true, attempted: 5, completed: 5, mismatches: 0 },
        });
        expect(result.tasks[0]?.itemValue).toBe(
          tickWidth === 8 ? '18364758544493064720' : Number(values.get(tickWidth)),
        );

        const itemTrailing = item + align(d.listItem.containerOffset + layout.pointerWidth, tickWidth);
        tick(itemTrailing, 1n);
        const mismatch = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'delayed', address: LIST_ADDR }, layout);
        expect(mismatch).toMatchObject({
          coverage: 'complete',
          integrityChecks: { enabled: true, attempted: 5, completed: 5, mismatches: 1 },
        });
        expect(mismatch.evidence.join('\n')).toContain(
          `reads 0x${'1'.padStart(tickWidth * 2, '0')}, not 0x${'5a'.repeat(tickWidth)}`,
        );
      }
    }
  });

  it('walks one byte-exact 32-bit list under every mini/integrity combination', () => {
    for (const useMiniListItem of [true, false]) {
      for (const useListDataIntegrityCheckBytes of [false, true]) {
        const layout = {
          pointerWidth: 4 as const,
          endian: 'little' as const,
          useMiniListItem,
          useListDataIntegrityCheckBytes,
        };
        const d = deriveFreeRtosListLayout(layout);
        const buf = new Uint8Array(0x200);
        const dv = new DataView(buf.buffer);
        const item = REGION_BASE + 0x100;
        const sentinel = LIST_ADDR + d.list.sentinelOffset;
        const write = (address: number, value: number) => dv.setUint32(address - REGION_BASE, value, true);
        if (useListDataIntegrityCheckBytes) {
          write(LIST_ADDR, 0x5a5a_5a5a);
          write(LIST_ADDR + d.list.sentinelOffset + d.sentinel.size, 0x5a5a_5a5a);
          write(sentinel, 0x5a5a_5a5a);
          if (!useMiniListItem) write(sentinel + d.listItem.containerOffset + layout.pointerWidth, 0x5a5a_5a5a);
          write(item, 0x5a5a_5a5a);
          write(item + d.listItem.containerOffset + layout.pointerWidth, 0x5a5a_5a5a);
        }
        write(LIST_ADDR + d.list.numberOfItemsOffset, 1);
        write(sentinel + d.sentinel.nextOffset, item);
        write(item + d.listItem.itemValueOffset, 0x1234);
        write(item + d.listItem.nextOffset, sentinel);
        write(item + d.listItem.ownerOffset, 0x3000_0042);
        write(item + d.listItem.containerOffset, LIST_ADDR);
        expect(parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'delayed', address: LIST_ADDR }, layout)).toMatchObject(
          {
            coverage: 'complete',
            declaredItems: 1,
            containerMismatches: 0,
            tasks: [{ listItemAddress: item, itemValue: 0x1234, tcbAddress: 0x3000_0042 }],
            integrityChecks: {
              enabled: useListDataIntegrityCheckBytes,
              attempted: useListDataIntegrityCheckBytes ? (useMiniListItem ? 5 : 6) : 0,
              completed: useListDataIntegrityCheckBytes ? (useMiniListItem ? 5 : 6) : 0,
              mismatches: 0,
            },
          },
        );
      }
    }
  });

  it('reports a bad integrity word as a bounded layout/snapshot diagnostic without changing coverage', () => {
    const layout = {
      pointerWidth: 4 as const,
      endian: 'little' as const,
      useMiniListItem: true,
      useListDataIntegrityCheckBytes: true,
    };
    const d = deriveFreeRtosListLayout(layout);
    const buf = new Uint8Array(0x200);
    const dv = new DataView(buf.buffer);
    const item = REGION_BASE + 0x100;
    const sentinel = LIST_ADDR + d.list.sentinelOffset;
    const write = (address: number, value: number) => dv.setUint32(address - REGION_BASE, value, true);
    for (const address of [
      LIST_ADDR,
      LIST_ADDR + d.list.sentinelOffset + d.sentinel.size,
      sentinel,
      item,
      item + d.listItem.containerOffset + layout.pointerWidth,
    ])
      write(address, 0x5a5a_5a5a);
    write(LIST_ADDR + d.list.numberOfItemsOffset, 1);
    write(sentinel + d.sentinel.nextOffset, item);
    write(item + d.listItem.itemValueOffset, 1);
    write(item + d.listItem.nextOffset, sentinel);
    write(item + d.listItem.ownerOffset, 0x3000_0042);
    write(item + d.listItem.containerOffset, LIST_ADDR);
    write(item + d.listItem.containerOffset + layout.pointerWidth, 0x1111_1111);

    const r = parseFreeRtosNamedList(buf, REGION_BASE, { kind: 'ready', address: LIST_ADDR }, layout);
    expect(r).toMatchObject({
      coverage: 'complete',
      completed: 1,
      integrityChecks: { enabled: true, attempted: 5, completed: 5, mismatches: 1 },
    });
    expect(r.evidence.join('\n')).toMatch(/ListItem_t trailing integrity marker.*11111111.*layout may be wrong/);

    const cut = parseFreeRtosNamedList(
      buf.slice(0, item - REGION_BASE + 26),
      REGION_BASE,
      { kind: 'ready', address: LIST_ADDR },
      layout,
    );
    expect(cut).toMatchObject({
      coverage: 'truncated',
      integrityChecks: { enabled: true, attempted: 5, completed: 4, mismatches: 0 },
    });
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

    const kinds: FreeRtosListKind[] = [
      'ready',
      'delayed',
      'delayed_overflow',
      'suspended',
      'pending',
      'event',
      'event_group',
      'terminated',
    ];
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

describe('deriveFreeRtosReadyLists', () => {
  const LE4 = { pointerWidth: 4, endian: 'little' } as const;
  const BE8 = { pointerWidth: 8, endian: 'big' } as const;
  const B = 0x2000_0000;

  it('derives one ready list per declared priority at the walked layout stride', () => {
    const d = deriveFreeRtosReadyLists({ base: B, maxPriorities: 3, listSize: 20 }, LE4);
    expect(d.status).toBe('derived');
    if (d.status !== 'derived') return;
    expect(d.stride).toBe(20);
    expect(d.lists).toEqual([
      { kind: 'ready', name: 'pxReadyTasksLists[0]', address: B, priority: 0 },
      { kind: 'ready', name: 'pxReadyTasksLists[1]', address: B + 20, priority: 1 },
      { kind: 'ready', name: 'pxReadyTasksLists[2]', address: B + 40, priority: 2 },
    ]);
  });

  it('strides 40 bytes on a 64-bit target', () => {
    const d = deriveFreeRtosReadyLists({ base: 0x1000, maxPriorities: 2, listSize: 40 }, BE8);
    expect(d.status === 'derived' && d.lists.map((l) => l.address)).toEqual([0x1000, 0x1028]);
  });

  it('refuses a declared sizeof(List_t) the walker cannot honour, naming both sizes', () => {
    for (const listSize of [28, 24]) {
      const d = deriveFreeRtosReadyLists({ base: B, maxPriorities: 3, listSize }, LE4);
      expect(d).toMatchObject({ status: 'refused', code: 'layout_mismatch' });
      if (d.status === 'refused') expect(d.reason).toMatch(new RegExp(`${listSize} bytes.*20-byte`));
    }
  });

  it('cross-checks st_size against count × size and refuses a disagreement', () => {
    const agrees = deriveFreeRtosReadyLists({ base: B, maxPriorities: 3, listSize: 20, symbolSize: 60 }, LE4);
    expect(agrees).toMatchObject({ status: 'derived', sizeCrossCheck: 'agrees' });
    expect(agrees.status === 'derived' && agrees.evidence.join('\n')).toMatch(/st_size 60 agrees/);
    expect(deriveFreeRtosReadyLists({ base: B, maxPriorities: 3, listSize: 20, symbolSize: 64 }, LE4)).toMatchObject({
      status: 'refused',
      code: 'size_mismatch',
    });
    const unchecked = deriveFreeRtosReadyLists({ base: B, maxPriorities: 3, listSize: 20 }, LE4);
    expect(unchecked).toMatchObject({ status: 'derived', sizeCrossCheck: 'not_available' });
    expect(unchecked.status === 'derived' && unchecked.evidence.join('\n')).toMatch(/not cross-checked/);
    expect(unchecked.status === 'derived' && unchecked.evidence.join('\n')).toContain(FREERTOS_OVER_DECLARED_COUNT);
  });

  it('treats an st_size of 0 as unknown (ELF), never as a size that disagrees', () => {
    const d = deriveFreeRtosReadyLists({ base: B, maxPriorities: 5, listSize: 20, symbolSize: 0 }, LE4);
    expect(d).toMatchObject({ status: 'derived', sizeCrossCheck: 'not_available' });
    if (d.status !== 'derived') return;
    expect(d.lists).toHaveLength(5);
    expect(d.evidence.join('\n')).toMatch(/st_size is 0, which ELF defines as no or unknown size/);
    expect(d.evidence.join('\n')).toMatch(/not cross-checked/);
  });

  it('refuses a negative or fractional st_size as not a byte count, not as a three-way disagreement', () => {
    for (const symbolSize of [-60, 59.5]) {
      const d = deriveFreeRtosReadyLists({ base: B, maxPriorities: 3, listSize: 20, symbolSize }, LE4);
      expect(d).toMatchObject({ status: 'refused', code: 'invalid_size' });
      if (d.status === 'refused') {
        expect(d.reason).toMatch(/not a byte count/);
        expect(d.reason).not.toMatch(/one of the three facts/);
      }
    }
  });

  it('refuses counts outside 1..64, a non-positive list size, and an array that overflows the address space', () => {
    for (const maxPriorities of [0, 65, 1.5]) {
      expect(deriveFreeRtosReadyLists({ base: B, maxPriorities, listSize: 20 }, LE4)).toMatchObject({
        code: 'invalid_count',
      });
    }
    for (const listSize of [0, -20, 20.5]) {
      expect(deriveFreeRtosReadyLists({ base: B, maxPriorities: 3, listSize }, LE4)).toMatchObject({
        code: 'invalid_size',
      });
    }
    const overflow = deriveFreeRtosReadyLists({ base: 0xffff_fff0, maxPriorities: 2, listSize: 20 }, LE4);
    expect(overflow).toMatchObject({ code: 'address_overflow' });
    expect(overflow.status === 'refused' && overflow.reason).toMatch(/^pxReadyTasksLists at 0xfffffff0 plus 40 bytes/);
  });

  it('keeps an unresolved base as one unresolved list, which a walk reports as missing_symbol', () => {
    const d = deriveFreeRtosReadyLists({ base: null, maxPriorities: 3, listSize: 20 }, LE4);
    expect(d.status === 'derived' && d.lists).toEqual([{ kind: 'ready', name: 'pxReadyTasksLists', address: null }]);
    if (d.status !== 'derived' || !d.lists[0]) return;
    expect(parseFreeRtosNamedList(new Uint8Array(4), B, d.lists[0]).coverage).toBe('missing_symbol');
  });
});
