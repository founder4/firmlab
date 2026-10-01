/** Exercises the store binding with an in-memory ledger without opening live SQLite data. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { JobRow } from '../store.js';

const ledger = vi.hoisted(() => new Map<string, JobRow>());
vi.mock('../store.js', () => ({
  insertJob: (row: JobRow) => ledger.set(row.id, { ...row }),
  getJob: (id: string) => ledger.get(id),
  appendJobLog: (id: string, line: string) => {
    const row = ledger.get(id);
    if (row) row.log += `${line}\n`;
  },
  updateJobStatus: (id: string, status: JobRow['status'], resultJson: string | null, error: string | null) => {
    const row = ledger.get(id);
    if (row) Object.assign(row, { status, resultJson, error });
  },
}));

const deferred = () => {
  let resolve!: (value: unknown) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { resolve, reject, promise };
};

beforeEach(() => {
  vi.resetModules();
  ledger.clear();
  process.env.FIRMLAB_MAX_CONCURRENT_JOBS = '1';
});

describe('job cancellation', () => {
  it('removes queued work, repeated cancellation is safe, and only releases running capacity after work cleanup', async () => {
    const { startJob, cancelJob } = await import('./jobs.js');
    const cleanup = deferred();
    const first = startJob('img', 'extract', {}, () => cleanup.promise);
    const never = vi.fn(async () => 'never');
    const queued = startJob('img', 'extract', {}, never);
    cancelJob(queued);
    cancelJob(queued);
    expect(ledger.get(queued)?.status).toBe('cancelled');
    cancelJob(first);
    expect(ledger.get(first)?.status).toBe('cancelling');
    const next = vi.fn(async () => 'next');
    const following = startJob('img', 'extract', {}, next);
    expect(ledger.get(following)?.status).toBe('queued');
    expect(next).not.toHaveBeenCalled();
    cleanup.resolve('late success');
    await vi.waitFor(() => expect(ledger.get(first)?.status).toBe('cancelled'));
    await vi.waitFor(() => expect(ledger.get(following)?.status).toBe('done'));
    expect(never).not.toHaveBeenCalled();
    expect(ledger.get(first)?.resultJson).toBeNull();
  });

  it('preserves already-completed results and errors, but cancellation wins pending success/error races', async () => {
    const { startJob, cancelJob } = await import('./jobs.js');
    const done = startJob('img', 'extract', {}, async () => ({ evidence: 'preserve' }));
    await vi.waitFor(() => expect(ledger.get(done)?.status).toBe('done'));
    cancelJob(done);
    expect(ledger.get(done)?.resultJson).toBe('{"evidence":"preserve"}');
    const failed = startJob('img', 'extract', {}, async () => {
      throw new Error('original');
    });
    await vi.waitFor(() => expect(ledger.get(failed)?.status).toBe('error'));
    cancelJob(failed);
    expect(ledger.get(failed)?.error).toBe('original');
    const pending = deferred();
    const cancelled = startJob('img', 'extract', {}, () => pending.promise);
    cancelJob(cancelled);
    pending.reject(new Error('late failure'));
    await vi.waitFor(() => expect(ledger.get(cancelled)?.status).toBe('cancelled'));
    expect(ledger.get(cancelled)?.error).toBeNull();
  });
});

it('quarantines capacity and logs cleanup failure without an unhandled rejection', async () => {
  const { JobCancellation } = await import('../job-cancellation.js');
  const cleanup = vi.spyOn(JobCancellation.prototype, 'cleanup').mockRejectedValueOnce(new Error('cleanup denied'));
  const { startJob } = await import('./jobs.js');
  const first = startJob('img', 'extract', {}, async () => 'evidence');
  await vi.waitFor(() => expect(ledger.get(first)?.log).toContain('slot retained'));
  expect(ledger.get(first)?.status).toBe('done');
  expect(ledger.get(first)?.resultJson).toBe('"evidence"');
  const next = vi.fn(async () => 'next');
  const queued = startJob('img', 'extract', {}, next);
  expect(ledger.get(queued)?.status).toBe('queued');
  expect(next).not.toHaveBeenCalled();
  cleanup.mockRestore();
});
