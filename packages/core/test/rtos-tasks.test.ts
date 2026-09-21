import { describe, expect, it } from 'vitest';
import { parseFreeRtosCurrentTask, parseFreeRtosReadyList } from '../src/rtos-tasks.js';

/**
 * Byte-level fixture builder for a FreeRTOS `List_t` + `ListItem_t` chain (default, no integrity-check bytes):
 * `List_t` = uxNumberOfItems(4) + pxIndex(4) + xListEnd{itemValue(4) + pxNext(4) + pxPrevious(4)}.
 * `ListItem_t` = itemValue(4) + pxNext(4) + pxPrevious(4) + pvOwner(4) + pxContainer(4) = 20 bytes.
 */
function memory(regionBase: number, size: number, le: boolean) {
  const buf = new Uint8Array(size);
  const dv = new DataView(buf.buffer);
  const w32 = (addr: number, val: number) => dv.setUint32(addr - regionBase, val >>> 0, le);
  const writeListHeader = (listAddr: number, headNext: number) => {
    w32(listAddr, 0); // uxNumberOfItems (unused by the parser)
    w32(listAddr + 4, 0); // pxIndex (unused by the parser)
    w32(listAddr + 8, 0); // xListEnd.itemValue
    w32(listAddr + 12, headNext); // xListEnd.pxNext
    w32(listAddr + 16, 0); // xListEnd.pxPrevious
  };
  const writeItem = (addr: number, itemValue: number, next: number, owner: number) => {
    w32(addr, itemValue);
    w32(addr + 4, next);
    w32(addr + 8, 0); // pxPrevious (unused by the parser)
    w32(addr + 12, owner);
    w32(addr + 16, 0); // pxContainer (unused by the parser)
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
