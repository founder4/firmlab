import { describe, expect, it } from 'vitest';
import { type JobSlot, createJobScheduler, resolveConcurrencyCap } from './job-scheduler.js';

/** Enqueue a starter that records the order it was granted a slot and hands the token back to the caller. */
function recorder(order: string[], name: string): { start: (slot: JobSlot) => void; slot: () => JobSlot } {
  let granted: JobSlot | null = null;
  return {
    start: (slot: JobSlot) => {
      order.push(name);
      granted = slot;
    },
    slot: () => {
      if (!granted) throw new Error(`${name} was never started`);
      return granted;
    },
  };
}

describe('createJobScheduler', () => {
  it('admits without contention — the path a single job takes and nobody tests', () => {
    const s = createJobScheduler(2);
    expect(s.activeCount).toBe(0);
    expect(s.waitingCount).toBe(0);

    const slot = s.tryAdmit();
    expect(slot).not.toBeNull();
    expect(s.activeCount).toBe(1);
    expect(s.waitingCount).toBe(0);

    slot?.release();
    expect(s.activeCount).toBe(0);
    expect(s.waitingCount).toBe(0);
    // And the scheduler is reusable afterwards, at full capacity.
    expect(s.tryAdmit()).not.toBeNull();
    expect(s.tryAdmit()).not.toBeNull();
  });

  it('admits up to the cap and refuses beyond it', () => {
    const s = createJobScheduler(2);
    expect(s.tryAdmit()).not.toBeNull();
    expect(s.tryAdmit()).not.toBeNull();
    expect(s.tryAdmit()).toBeNull();
    expect(s.activeCount).toBe(2);
    // A refusal is not a queue entry: tryAdmit never enqueues on the caller's behalf.
    expect(s.waitingCount).toBe(0);
  });

  it('releasing a slot starts exactly one waiting starter, in FIFO order', () => {
    const s = createJobScheduler(2);
    const a = s.tryAdmit();
    s.tryAdmit();

    const order: string[] = [];
    const first = recorder(order, 'first');
    const second = recorder(order, 'second');
    const third = recorder(order, 'third');
    s.enqueue(first.start);
    s.enqueue(second.start);
    s.enqueue(third.start);
    expect(s.waitingCount).toBe(3);
    expect(order).toEqual([]);

    a?.release();
    expect(order).toEqual(['first']);
    expect(s.waitingCount).toBe(2);
    // The slot was handed on, not freed: still at capacity.
    expect(s.activeCount).toBe(2);
    expect(s.tryAdmit()).toBeNull();

    first.slot().release();
    expect(order).toEqual(['first', 'second']);
    second.slot().release();
    expect(order).toEqual(['first', 'second', 'third']);
    expect(s.waitingCount).toBe(0);
  });

  it('drains to zero once every started job releases', () => {
    const s = createJobScheduler(1);
    const held = s.tryAdmit();
    const order: string[] = [];
    const queued = recorder(order, 'queued');
    s.enqueue(queued.start);

    held?.release();
    expect(s.activeCount).toBe(1);
    queued.slot().release();
    expect(s.activeCount).toBe(0);
    expect(s.waitingCount).toBe(0);
  });

  it('releasing with an empty queue neither throws nor goes negative', () => {
    const s = createJobScheduler(2);
    const slot = s.tryAdmit();
    expect(() => slot?.release()).not.toThrow();
    expect(s.activeCount).toBe(0);
  });

  it('releasing a token more than once is a no-op, so capacity cannot be invented', () => {
    const s = createJobScheduler(1);
    const slot = s.tryAdmit();
    expect(slot?.held).toBe(true);
    slot?.release();
    expect(slot?.held).toBe(false);
    slot?.release();
    slot?.release();
    expect(s.activeCount).toBe(0);
    // One slot, one job: a double release must not let two through.
    expect(s.tryAdmit()).not.toBeNull();
    expect(s.tryAdmit()).toBeNull();
  });

  it('does not start a waiter twice when its token is released repeatedly', () => {
    const s = createJobScheduler(1);
    const held = s.tryAdmit();
    const order: string[] = [];
    s.enqueue(recorder(order, 'queued').start);

    held?.release();
    held?.release();
    held?.release();
    expect(order).toEqual(['queued']);
    expect(s.activeCount).toBe(1);
  });

  it('frees the slot when the work throws and release runs in a finally', () => {
    const s = createJobScheduler(1);
    const slot = s.tryAdmit();
    expect(() => {
      try {
        throw new Error('provider blew up');
      } finally {
        slot?.release();
      }
    }).toThrow('provider blew up');
    expect(s.activeCount).toBe(0);
    expect(s.tryAdmit()).not.toBeNull();
  });

  it('frees the slot when a queued starter throws synchronously, and still propagates the error', () => {
    const s = createJobScheduler(1);
    const held = s.tryAdmit();
    s.enqueue(() => {
      throw new Error('could not mark the row running');
    });

    expect(() => held?.release()).toThrow('could not mark the row running');
    // The slot handed to the failing starter went back, rather than being stranded.
    expect(s.activeCount).toBe(0);
    expect(s.waitingCount).toBe(0);
    expect(s.tryAdmit()).not.toBeNull();
  });

  it('serialises strictly at a cap of 1', () => {
    const s = createJobScheduler(1);
    const order: string[] = [];
    const slot = s.tryAdmit();
    expect(s.tryAdmit()).toBeNull();

    const a = recorder(order, 'a');
    const b = recorder(order, 'b');
    s.enqueue(a.start);
    s.enqueue(b.start);
    expect(order).toEqual([]);

    slot?.release();
    expect(order).toEqual(['a']);
    a.slot().release();
    expect(order).toEqual(['a', 'b']);
    b.slot().release();
    expect(s.activeCount).toBe(0);
  });

  it('clamps a zero, negative or fractional capacity to at least one whole slot', () => {
    expect(createJobScheduler(0).capacity).toBe(1);
    expect(createJobScheduler(-4).capacity).toBe(1);
    expect(createJobScheduler(Number.NaN).capacity).toBe(1);
    expect(createJobScheduler(2.9).capacity).toBe(2);

    const zero = createJobScheduler(0);
    expect(zero.tryAdmit()).not.toBeNull();
    expect(zero.tryAdmit()).toBeNull();
  });
});

describe('resolveConcurrencyCap', () => {
  it('takes a valid configured value', () => {
    expect(resolveConcurrencyCap('4')).toBe(4);
    expect(resolveConcurrencyCap(3)).toBe(3);
  });

  it('falls back when unset', () => {
    expect(resolveConcurrencyCap(undefined)).toBe(2);
    expect(resolveConcurrencyCap(null)).toBe(2);
    expect(resolveConcurrencyCap('')).toBe(2);
    expect(resolveConcurrencyCap(undefined, 5)).toBe(5);
  });

  it('falls back on an unparseable value instead of stalling every job', () => {
    // `Math.max(1, Number('x'))` is NaN, and `active < NaN` is false forever — nothing would ever start.
    expect(resolveConcurrencyCap('two')).toBe(2);
    expect(resolveConcurrencyCap('x', 3)).toBe(3);
    expect(resolveConcurrencyCap(Number.POSITIVE_INFINITY)).toBe(2);
  });

  it('clamps zero and negatives to one, and floors fractions', () => {
    expect(resolveConcurrencyCap('0')).toBe(1);
    expect(resolveConcurrencyCap('-3')).toBe(1);
    expect(resolveConcurrencyCap('1.9')).toBe(1);
    expect(resolveConcurrencyCap('0.5')).toBe(1);
  });
});
