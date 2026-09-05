/**
 * The bounded-concurrency decision behind the job runner — extracted so it can be tested at all.
 *
 * jobs.ts imports store.js, and a module that imports store.js cannot be reached by vitest (`node:sqlite` does not
 * resolve there, so the test file never even loads). The consequence was structural, not cosmetic: the admission
 * rule, the FIFO waiting queue and the slot accounting — the concurrency primitive that every heavy provider runs
 * under — had no test file and could not acquire one. CLAUDE.md already records what that costs: `dynprobe-run.ts`
 * pinned a single gdb port on the reasoning "one probe runs at a time per job", true per job and false the moment
 * W9 scheduled probes inside two concurrent scans. Scheduling behaviour is exactly the thing nobody could exercise.
 *
 * So this module owns only what can be decided without touching a row: how many slots exist, how many are taken,
 * who is waiting, and what happens on admit and release. It deliberately does NOT own job ids, SQLite writes, log
 * streaming or the work closures — a queued starter is an opaque callback this module invokes and never inspects,
 * which is what keeps it free of the store. jobs.ts binds those halves together, the same way findings.ts binds
 * findings-normalize.ts and opacidad.ts binds opacidad-plan.ts.
 *
 * Two design choices worth stating, because both are guard-shaped and guards here fail on the path where nothing
 * is wrong:
 *
 *  • **A slot is a token, not a counter decrement.** `tryAdmit()` hands back an object whose `release()` is
 *    idempotent, so a double release (a `finally` that runs twice, a caller that releases and then rethrows into
 *    another `finally`) cannot invent capacity that does not exist. Releasing with nothing queued simply frees the
 *    slot; the active count has no path to a negative value.
 *  • **Releasing is what pumps the queue.** There is no separate "start the next one" step a caller could forget:
 *    a release with a waiter present hands that same slot straight to the head of the FIFO. If the starter throws
 *    synchronously, its token is released before the error propagates, so a failed start frees the slot instead of
 *    leaking it.
 *
 * Instances are created per call site rather than living as module-level mutable state, so tests can build
 * independent schedulers instead of fighting over one global counter.
 */

/** A taken concurrency slot. `release()` is idempotent; the second and later calls are no-ops. */
export interface JobSlot {
  /** Give the slot back. Hands it to the head of the waiting queue if there is one, otherwise frees it. */
  release: () => void;
  /** False once this token has been released — exposed for assertions, not for control flow. */
  readonly held: boolean;
}

/** Invoked with a slot already taken on its behalf; must eventually call `slot.release()`. */
export type QueuedStarter = (slot: JobSlot) => void;

export interface JobScheduler {
  /** Maximum slots that can be held at once. */
  readonly capacity: number;
  /** Slots currently held (never negative, never above `capacity`). */
  readonly activeCount: number;
  /** Starters waiting for a slot. */
  readonly waitingCount: number;
  /** Take a slot if one is free, otherwise null. Never queues — the caller decides what "at capacity" means. */
  tryAdmit: () => JobSlot | null;
  /** Wait for a slot in FIFO order. `start` is called with a slot the moment one frees. */
  enqueue: (start: QueuedStarter) => void;
}

/**
 * Read a concurrency cap from configuration.
 *
 * `Math.max(1, Number(raw))` — the shape this replaces — clamps zero and negatives but propagates NaN, and a NaN
 * cap makes `active < capacity` false forever: every job queues and none ever starts. An unparseable value is a
 * misconfiguration, not an instruction to stop working, so it falls back to `fallback`. Fractional values floor
 * (2.9 slots is 2 slots), and any value below 1 clamps to 1 — a cap of zero would disable the workbench.
 */
export function resolveConcurrencyCap(raw: string | number | undefined | null, fallback = 2): number {
  const parsed = raw === undefined || raw === null || raw === '' ? fallback : Number(raw);
  if (!Number.isFinite(parsed)) return Math.max(1, Math.floor(fallback));
  return Math.max(1, Math.floor(parsed));
}

/** Create an independent bounded-concurrency scheduler. `capacity` is clamped to at least 1. */
export function createJobScheduler(capacity: number): JobScheduler {
  const cap = Math.max(1, Math.floor(Number.isFinite(capacity) ? capacity : 1));
  let active = 0;
  const waiting: QueuedStarter[] = [];

  /** Mint a token for a slot that has already been counted as active. */
  const mint = (): JobSlot => {
    let held = true;
    return {
      get held() {
        return held;
      },
      release: () => {
        if (!held) return;
        held = false;
        const next = waiting.shift();
        if (!next) {
          active--;
          return;
        }
        // The slot is handed straight on: `active` stays where it is, no window in which it is free.
        const passed = mint();
        try {
          next(passed);
        } catch (err) {
          // A starter that fails synchronously must not strand the slot it was given.
          passed.release();
          throw err;
        }
      },
    };
  };

  return {
    capacity: cap,
    get activeCount() {
      return active;
    },
    get waitingCount() {
      return waiting.length;
    },
    tryAdmit: () => {
      if (active >= cap) return null;
      active++;
      return mint();
    },
    enqueue: (start: QueuedStarter) => {
      waiting.push(start);
    },
  };
}
