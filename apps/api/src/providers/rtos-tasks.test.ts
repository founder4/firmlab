import { describe, expect, it } from 'vitest';
import { type RtosTaskSnapshotInput, runRtosTaskSnapshot, validateRtosTaskSnapshot } from './rtos-tasks.js';

const BASE = 0x2000_0000;
const LIST = BASE; // List_t: uxNumberOfItems, pxIndex, then the xListEnd sentinel at +8
const SENTINEL = LIST + 8;
const ITEM_A = BASE + 0x20;
const ITEM_B = BASE + 0x40;
const CUR = BASE + 0x80;

/** A little-endian 32-bit FreeRTOS ready list with two owned items, plus pxCurrentTCB. */
function snapshot(opts: { bNext?: number; length?: number } = {}): Uint8Array {
  const dv = new DataView(new ArrayBuffer(0x100));
  dv.setUint32(LIST - BASE, 2, true);
  dv.setUint32(SENTINEL - BASE, 0xffff_ffff, true);
  dv.setUint32(SENTINEL - BASE + 4, ITEM_A, true);
  const item = (at: number, value: number, next: number, owner: number) => {
    dv.setUint32(at - BASE, value, true);
    dv.setUint32(at - BASE + 4, next, true);
    dv.setUint32(at - BASE + 12, owner, true);
  };
  item(ITEM_A, 3, ITEM_B, 0x2000_1000);
  item(ITEM_B, 3, opts.bNext ?? SENTINEL, 0x2000_2000);
  dv.setUint32(CUR - BASE, 0x2000_1000, true);
  return new Uint8Array(dv.buffer).slice(0, opts.length ?? 0x100);
}

function body(bytes: Uint8Array, symbols: RtosTaskSnapshotInput['symbols']): RtosTaskSnapshotInput {
  return {
    memory: { base: BASE, endian: 'little', pointerWidth: 4, bytesBase64: Buffer.from(bytes).toString('base64') },
    symbols,
  };
}

function run(input: unknown) {
  const v = validateRtosTaskSnapshot(input);
  if (!v.ok) throw new Error(v.errors.join('; '));
  return runRtosTaskSnapshot(v.snapshot);
}

const SYMBOLS = { pxCurrentTCB: CUR, readyLists: [{ priority: 3, address: LIST }] };

describe('validateRtosTaskSnapshot', () => {
  it('refuses a snapshot that does not declare base, endian and width instead of defaulting them', () => {
    const v = validateRtosTaskSnapshot({ memory: { bytesBase64: 'AAAAAA==' }, symbols: {} });
    expect(v.ok).toBe(false);
    if (v.ok) return;
    expect(v.errors.join('\n')).toMatch(/endian/);
    expect(v.errors.join('\n')).toMatch(/pointerWidth/);
    expect(v.errors.join('\n')).toMatch(/base/);
  });

  it('refuses non-base64, empty snapshots, out-of-space addresses and repeated priorities', () => {
    const mem = { base: BASE, endian: 'little', pointerWidth: 4 };
    expect(validateRtosTaskSnapshot({ memory: { ...mem, bytesBase64: 'not base64!' }, symbols: {} }).ok).toBe(false);
    expect(validateRtosTaskSnapshot({ memory: { ...mem, bytesBase64: '' }, symbols: {} }).ok).toBe(false);
    expect(
      validateRtosTaskSnapshot({ memory: { ...mem, base: 0xffff_fffe, bytesBase64: 'AAAAAA==' }, symbols: {} }).ok,
    ).toBe(false);
    expect(
      validateRtosTaskSnapshot({
        memory: { ...mem, bytesBase64: 'AAAAAA==' },
        symbols: {
          readyLists: [
            { priority: 1, address: BASE },
            { priority: 1, address: BASE },
          ],
        },
      }).ok,
    ).toBe(false);
    expect(
      validateRtosTaskSnapshot({ memory: { ...mem, bytesBase64: 'AAAAAA==' }, symbols: { pxCurrentTCB: -4 } }).ok,
    ).toBe(false);
  });
});

describe('runRtosTaskSnapshot', () => {
  it('walks a valid list to its sentinel and reads pxCurrentTCB, still only as a lead', () => {
    const r = run(body(snapshot(), SYMBOLS));
    expect(r.coverage).toBe('complete');
    expect(r.proofState).toBe('needs_runtime_reproduction');
    expect(r.currentTask).toMatchObject({ coverage: 'complete', tcbAddress: 0x2000_1000 });
    expect(r.readyLists).toHaveLength(1);
    expect(r.readyLists[0]).toMatchObject({ priority: 3, coverage: 'complete', attempted: 2, completed: 2 });
    expect(r.readyLists[0]?.tasks.map((t) => t.tcbAddress)).toEqual([0x2000_1000, 0x2000_2000]);
    // sentinel (4 + 4) + two 20-byte records + one pointer for pxCurrentTCB
    expect(r.totals).toEqual({ nodesAttempted: 2, nodesCompleted: 2, bytesAttempted: 52, bytesCompleted: 52 });
    expect(r.limits.maxListItems).toBe(256);
    expect(r.summary).toMatch(/not read here/);
  });

  it('reports missing_symbol on both lanes when no symbols are supplied — coverage none, not an empty task set', () => {
    const r = run(body(snapshot(), {}));
    expect(r.coverage).toBe('none');
    expect(r.currentTask.coverage).toBe('missing_symbol');
    expect(r.readyLists).toEqual([expect.objectContaining({ priority: null, coverage: 'missing_symbol' })]);
    expect(r.totals).toEqual({ nodesAttempted: 0, nodesCompleted: 0, bytesAttempted: 0, bytesCompleted: 0 });
    expect(r.summary).toMatch(/not a complete task set/);
    expect(r.summary).toMatch(/not "no tasks"/);
  });

  it('reports a record cut by the snapshot edge as truncated with bytes attempted beyond those completed', () => {
    const r = run(body(snapshot({ length: 0x4a }), { readyLists: [{ priority: 3, address: LIST }] }));
    // One task was corroborated before the cut and pxCurrentTCB was not supplied: partial, never none.
    expect(r.coverage).toBe('partial');
    expect(r.summary).toMatch(/1 walked node\(s\) did not yield a corroborated task record/);
    expect(r.readyLists[0]).toMatchObject({ coverage: 'truncated', attempted: 2, completed: 1 });
    expect(r.readyLists[0]).toMatchObject({ bytesAttempted: 48, bytesCompleted: 28 });
  });

  it('reports a pointer outside the snapshot as out_of_range and keeps the task read before it', () => {
    const r = run(body(snapshot({ bNext: 0x3000_0000 }), SYMBOLS));
    expect(r.coverage).toBe('partial');
    expect(r.readyLists[0]).toMatchObject({ coverage: 'out_of_range', attempted: 3, completed: 2 });
    expect(r.readyLists[0]).toMatchObject({ bytesAttempted: 68, bytesCompleted: 48 });
    expect(r.summary).toMatch(/ready list 3: out_of_range/);
  });

  it('reports an out-of-range pxCurrentTCB symbol without reading it', () => {
    const r = run(body(snapshot(), { pxCurrentTCB: 0x9000_0000 }));
    expect(r.currentTask).toMatchObject({ coverage: 'out_of_range', tcbAddress: null, bytesCompleted: 0 });
  });
});
