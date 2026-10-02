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

/**
 * A wider snapshot: the ready list above, plus a delayed list (two items, ascending wake ticks), a suspended list
 * (one item) and an empty pending-ready list — every List_t in the same layout, each item pointing back to its
 * container as a real kernel's does.
 */
const DELAYED = BASE + 0x100;
const SUSPENDED = BASE + 0x160;
const PENDING = BASE + 0x1a0;
const D1 = BASE + 0x120;
const D2 = BASE + 0x140;
const S1 = BASE + 0x180;

function wideSnapshot(opts: { d2Wake?: number; s1Owner?: number } = {}): Uint8Array {
  const dv = new DataView(new ArrayBuffer(0x200));
  new Uint8Array(dv.buffer).set(snapshot());
  const list = (at: number, count: number, head: number) => {
    dv.setUint32(at - BASE, count, true);
    dv.setUint32(at + 8 - BASE, 0xffff_ffff, true);
    dv.setUint32(at + 12 - BASE, head, true);
  };
  const item = (at: number, value: number, next: number, owner: number, container: number) => {
    dv.setUint32(at - BASE, value, true);
    dv.setUint32(at - BASE + 4, next, true);
    dv.setUint32(at - BASE + 12, owner, true);
    dv.setUint32(at - BASE + 16, container, true);
  };
  list(DELAYED, 2, D1);
  item(D1, 50, D2, 0x2000_3000, DELAYED);
  item(D2, opts.d2Wake ?? 90, DELAYED + 8, 0x2000_4000, DELAYED);
  list(SUSPENDED, 1, S1);
  item(S1, 0, SUSPENDED + 8, opts.s1Owner ?? 0x2000_5000, SUSPENDED);
  list(PENDING, 0, PENDING + 8);
  return new Uint8Array(dv.buffer);
}

describe('named state lists', () => {
  it('walks delayed, suspended and pending lists as typed lanes and aggregates every lane into the totals', () => {
    const r = run(
      body(wideSnapshot(), {
        ...SYMBOLS,
        delayedLists: [{ name: 'xDelayedTaskList1', address: DELAYED }],
        suspendedList: SUSPENDED,
        pendingReadyList: PENDING,
      }),
    );
    expect(r.coverage).toBe('complete');
    expect(r.proofState).toBe('needs_runtime_reproduction');
    expect(r.delayedLists).toEqual([
      expect.objectContaining({
        kind: 'delayed',
        name: 'xDelayedTaskList1',
        coverage: 'complete',
        attempted: 2,
        completed: 2,
        itemValueMeaning: 'wake_tick',
        orderViolations: 0,
        containerMismatches: 0,
        bytesAttempted: 48,
        bytesCompleted: 48,
      }),
    ]);
    expect(r.delayedLists?.[0]?.tasks.map((t) => t.itemValue)).toEqual([50, 90]);
    expect(r.suspendedList).toMatchObject({ kind: 'suspended', name: 'xSuspendedTaskList', completed: 1 });
    expect(r.pendingReadyList).toMatchObject({ kind: 'pending', coverage: 'complete', attempted: 0, completed: 0 });
    expect(r.terminatedList).toBeUndefined();
    // ready 2 + delayed 2 + suspended 1 nodes; bytes: ready 48 + delayed 48 + suspended 28 + pending 8 + pxCurrentTCB 4
    expect(r.totals).toEqual({ nodesAttempted: 5, nodesCompleted: 5, bytesAttempted: 136, bytesCompleted: 136 });
    expect(r.unwalkedKinds).toEqual(['delayed', 'terminated']);
    expect(r.summary).toMatch(/^2 ready task record\(s\) \(plus 2 delayed, 1 suspended, 0 pending-ready\) across 4/);
    expect(r.summary).toMatch(/delayed \(second list\), waiting-termination tasks live on lists not read here/);
    expect(r.limits.maxDelayedLists).toBe(2);
  });

  it('types a delayed list the operator names as the overflow list, and says nothing is left unread when all are', () => {
    const r = run(
      body(wideSnapshot(), {
        readyLists: [{ priority: 3, address: LIST }],
        pxCurrentTCB: CUR,
        delayedLists: [{ address: DELAYED }, { name: 'pxOverflowDelayedTaskList', address: PENDING }],
        suspendedList: SUSPENDED,
        pendingReadyList: null,
        terminatedList: null,
      }),
    );
    expect(r.delayedLists?.map((l) => [l.kind, l.name])).toEqual([
      ['delayed', 'xDelayedTaskList1'],
      ['delayed_overflow', 'pxOverflowDelayedTaskList'],
    ]);
    expect(r.unwalkedKinds).toEqual([]);
    expect(r.summary).not.toMatch(/live on lists not read here/);
    // Asked and unresolved is a missing_symbol lane that keeps the whole walk partial — never an empty list.
    expect(r.pendingReadyList).toMatchObject({ coverage: 'missing_symbol', bytesAttempted: 0 });
    expect(r.coverage).toBe('partial');
    expect(r.summary).toMatch(/xPendingReadyList: missing_symbol; xTasksWaitingTermination: missing_symbol/);
  });

  it('keeps a ready-only request exactly as complete as it always was', () => {
    const r = run(body(wideSnapshot(), SYMBOLS));
    expect(r.coverage).toBe('complete');
    expect(r.delayedLists).toBeUndefined();
    expect(r.suspendedList).toBeUndefined();
    expect(r.unwalkedKinds).toEqual(['delayed', 'suspended', 'pending', 'terminated']);
  });

  it('reports a delayed lane cut short as partial and records the bytes it could not read', () => {
    const r = run(body(wideSnapshot().slice(0, 0x14a), { delayedLists: [{ address: DELAYED }], pxCurrentTCB: CUR }));
    expect(r.coverage).toBe('partial');
    expect(r.delayedLists?.[0]).toMatchObject({
      coverage: 'truncated',
      attempted: 2,
      completed: 1,
      bytesAttempted: 48,
      bytesCompleted: 28,
    });
    expect(r.summary).toMatch(/xDelayedTaskList1: truncated/);
  });

  it('surfaces wake ticks out of order and a TCB on two state lists as an inconsistent snapshot', () => {
    // D2 wakes before D1, and the suspended item is owned by a TCB already on the ready list.
    const r = run(
      body(wideSnapshot({ d2Wake: 10, s1Owner: 0x2000_1000 }), {
        ...SYMBOLS,
        delayedLists: [{ address: DELAYED }],
        suspendedList: SUSPENDED,
      }),
    );
    expect(r.delayedLists?.[0]?.orderViolations).toBe(1);
    expect(r.tcbsOnSeveralLists).toEqual([0x2000_1000]);
    expect(r.summary).toMatch(/1 TCB\(s\) appear on more than one state list/);
    expect(r.summary).toMatch(/1 list\(s\) carry structural inconsistencies/);
  });
});

describe('validateRtosTaskSnapshot — named lists', () => {
  const mem = { base: BASE, endian: 'little', pointerWidth: 4, bytesBase64: 'AAAAAA==' };
  const errors = (symbols: unknown) => {
    const v = validateRtosTaskSnapshot({ memory: mem, symbols });
    return v.ok ? [] : v.errors;
  };

  it('refuses more delayed lists than tasks.c declares, bad names and bad addresses', () => {
    expect(errors({ delayedLists: [{ address: 1 }, { address: 2 }, { address: 3 }] }).join()).toMatch(/declares 2/);
    expect(errors({ delayedLists: [{ name: 'x; rm -rf', address: 1 }] }).join()).toMatch(/C identifier/);
    expect(errors({ delayedLists: [{ address: -1 }] }).join()).toMatch(/delayedLists\[0\]\.address/);
    expect(errors({ delayedLists: 'nope' }).join()).toMatch(/must be an array/);
    expect(errors({ suspendedList: 'x' }).join()).toMatch(/suspendedList must be an address or null/);
    expect(errors({ terminatedList: 2 ** 32 }).join()).toMatch(/terminatedList/);
  });

  it('refuses a list address walked twice, so no task is counted twice', () => {
    expect(errors({ readyLists: [{ priority: 1, address: LIST }], suspendedList: LIST }).join()).toMatch(
      /symbols\.suspendedList repeats list address/,
    );
    expect(errors({ delayedLists: [{ address: DELAYED }], pendingReadyList: DELAYED }).join()).toMatch(
      /pendingReadyList repeats/,
    );
    expect(
      errors({
        delayedLists: [
          { name: 'a', address: 1 },
          { name: 'a', address: 2 },
        ],
      }).join(),
    ).toMatch(/repeats name a/);
  });

  it('keeps an omitted list distinct from a null one', () => {
    const v = validateRtosTaskSnapshot({ memory: mem, symbols: { suspendedList: null } });
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    expect(v.snapshot.suspendedList).toBeNull();
    expect('pendingReadyList' in v.snapshot).toBe(false);
  });
});
