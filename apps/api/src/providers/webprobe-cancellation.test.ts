/**
 * Job-owned HTTP cancellation for the active web probe. A probe runs inside a job's cancellation context; when the
 * operator cancels, an in-flight (and stalled) request must abort promptly and no further request may be issued —
 * without changing behaviour for a probe that runs outside any job, and without one job's cancellation reaching a
 * request owned by another job. The injected fetch keeps these deterministic and off the network.
 */
import { describe, expect, it } from 'vitest';
import { JobCancellation, JobCancelledError, jobCancellation } from '../job-cancellation.js';
import { type FetchLike, runWebProbe } from './webprobe.js';

/** A fetch that never resolves on its own; it only ever rejects when its abort signal fires. Records every URL. */
function stallingFetch(calls: string[]): FetchLike {
  return (url, init) =>
    new Promise((_resolve, reject) => {
      calls.push(url);
      if (init?.signal?.aborted) {
        reject(new Error('aborted'));
        return;
      }
      init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
    });
}

describe('runWebProbe — job-owned cancellation', () => {
  it('aborts a stalled in-flight request promptly and issues no further request', async () => {
    const calls: string[] = [];
    const cancellation = new JobCancellation();
    const started = Date.now();
    const probe = jobCancellation.run(cancellation, () =>
      runWebProbe('http://127.0.0.1:1', { fetch: stallingFetch(calls), maxRequests: 50, timeoutMs: 30_000 }),
    );
    setTimeout(() => cancellation.cancel(), 20);
    await expect(probe).rejects.toBeInstanceOf(JobCancelledError);
    // Prompt: far under the 30s per-request timeout the stalled request would otherwise wait out.
    expect(Date.now() - started).toBeLessThan(2000);
    // Only the home request was ever issued; cancellation stopped the loop before any probe request followed it.
    expect(calls).toEqual(['http://127.0.0.1:1/']);
  });

  it('still honours the per-request timeout outside a job (non-job behaviour unchanged)', async () => {
    const calls: string[] = [];
    const started = Date.now();
    // No jobCancellation.run wrapper: the only bound is the caller's timeout, exactly as before.
    const result = await runWebProbe('http://127.0.0.1:1', {
      fetch: stallingFetch(calls),
      maxRequests: 1,
      timeoutMs: 100,
    });
    expect(result.available).toBe(false);
    expect(result.reason).toMatch(/not reachable/);
    expect(calls).toEqual(['http://127.0.0.1:1/']);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('does not abort a probe owned by a different job', async () => {
    const other = new JobCancellation();
    const mine = new JobCancellation();
    // A page with no injection points and a fetch that answers immediately: the probe must complete normally even
    // though an unrelated job is cancelled while it runs.
    const okFetch: FetchLike = () =>
      Promise.resolve({ ok: true, status: 200, text: async () => '<html>no forms here</html>' });
    const probe = jobCancellation.run(mine, () =>
      runWebProbe('http://127.0.0.1:1', { fetch: okFetch, maxRequests: 200, timeoutMs: 30_000 }),
    );
    other.cancel();
    const result = await probe;
    expect(result.available).toBe(true);
    expect(mine.cancelled).toBe(false);
  });
});
