/**
 * Job-owned HTTP cancellation for the external-intelligence track. `allowlistedFetch` is the one choke point every
 * outbound research request passes; when the owning job is cancelled, the request AND its body read must abort
 * promptly instead of waiting out `timeoutMs`. The allowlist, the per-request timeout and the error shape are
 * unchanged — an abort surfaces as the same `AbortError` a timeout already produced. A request made outside any job
 * (shared capability discovery), or owned by a different job, must be untouched by another job's cancellation.
 *
 * Driven against a real loopback server so the body-read abort is exercised over an actual socket, not a stub.
 */
import http from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { JobCancellation, jobCancellation } from '../job-cancellation.js';
import { type ResearchConfig, allowlistedFetch } from './config.js';

const servers: http.Server[] = [];
async function serve(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No listening address');
  return `http://127.0.0.1:${address.port}/`;
}
afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

const cfg = (timeoutMs = 30_000): ResearchConfig => ({ allowlist: ['127.0.0.1'], timeoutMs, hashLookup: false });

describe('allowlistedFetch — job-owned cancellation', () => {
  it('aborts a stalled job-owned request promptly instead of waiting out timeoutMs', async () => {
    let requests = 0;
    let received!: () => void;
    const requestReceived = new Promise<void>((resolve) => {
      received = resolve;
    });
    const url = await serve(() => {
      requests++;
      received();
      /* never responds */
    });
    const cancellation = new JobCancellation();
    await jobCancellation.run(cancellation, async () => {
      // Observe rejection immediately, including when setup fails before cancellation.
      const settled = allowlistedFetch(url, cfg(30_000)).then(
        () => ({ status: 'fulfilled' as const }),
        (error: unknown) => ({ status: 'rejected' as const, error }),
      );
      let setupTimer: ReturnType<typeof setTimeout> | undefined;
      let abortTimer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          requestReceived,
          settled.then((result) => {
            throw new Error('Request settled before cancellation', {
              cause: result.status === 'rejected' ? result.error : undefined,
            });
          }),
          new Promise<never>((_resolve, reject) => {
            setupTimer = setTimeout(() => reject(new Error('Server did not receive the request within 3s')), 3000);
          }),
        ]);
        clearTimeout(setupTimer);

        // Connection setup under load must not consume the cancellation latency budget.
        const started = performance.now();
        cancellation.cancel();
        const result = await Promise.race([
          settled,
          new Promise<never>((_resolve, reject) => {
            abortTimer = setTimeout(() => reject(new Error('Cancellation did not abort the request within 2s')), 2000);
          }),
        ]);
        expect(performance.now() - started).toBeLessThan(2000);
        expect(result.status).toBe('rejected');
        if (result.status === 'rejected') expect(result.error).toMatchObject({ name: 'AbortError' });
        expect(requests).toBe(1);
      } finally {
        clearTimeout(setupTimer);
        clearTimeout(abortTimer);
        cancellation.cancel();
        // afterEach closes the real sockets even if cancellation itself regresses.
      }
    });
  }, 10_000);

  it('aborts a job-owned body read that stalls after the headers arrive', async () => {
    const url = await serve((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.write('partial');
      /* flushes headers + a chunk, then never ends the body */
    });
    const cancellation = new JobCancellation();
    const started = Date.now();
    await jobCancellation.run(cancellation, async () => {
      const res = await allowlistedFetch(url, cfg(30_000));
      expect(res.status).toBe(200);
      const body = res.text();
      setTimeout(() => cancellation.cancel(), 20);
      await expect(body).rejects.toThrow();
    });
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('still enforces the caller timeout inside a job that is not cancelled', async () => {
    const url = await serve(() => {
      /* never responds */
    });
    const cancellation = new JobCancellation();
    const started = Date.now();
    await jobCancellation.run(cancellation, async () => {
      await expect(allowlistedFetch(url, cfg(150))).rejects.toThrow();
    });
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(120);
    expect(elapsed).toBeLessThan(2000);
    expect(cancellation.cancelled).toBe(false);
  });

  it('leaves a non-job request (shared discovery) untouched when an unrelated job is cancelled', async () => {
    const url = await serve((_req, res) => res.end('shared'));
    const unrelated = new JobCancellation();
    // No jobCancellation.run wrapper: this is shared, job-independent discovery.
    const pending = allowlistedFetch(url, cfg(30_000));
    unrelated.cancel();
    const res = await pending;
    expect(await res.text()).toBe('shared');
  });

  it('does not abort a request owned by a different job', async () => {
    const url = await serve((_req, res) => res.end('mine'));
    const other = new JobCancellation();
    const mine = new JobCancellation();
    const res = await jobCancellation.run(mine, async () => {
      const pending = allowlistedFetch(url, cfg(30_000));
      other.cancel();
      return pending;
    });
    expect(await res.text()).toBe('mine');
    expect(mine.cancelled).toBe(false);
  });

  it('still blocks a non-allowlisted host before any socket, even inside a cancellable job', async () => {
    const cancellation = new JobCancellation();
    await jobCancellation.run(cancellation, async () => {
      await expect(allowlistedFetch('https://evil.example.com/x', cfg(30_000))).rejects.toThrow(
        /not on the research allowlist/,
      );
    });
  });
});
