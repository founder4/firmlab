import http from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { PROBE_RESPONSE_CAP, fetchLocalTarget, isLocalTarget, localProbeUrl } from './webprobe-transport.js';

const servers: http.Server[] = [];
async function serve(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No listening address');
  return `http://127.0.0.1:${address.port}`;
}
afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

describe('local probe target validation', () => {
  it('accepts only HTTP(S) literal loopback addresses and pins localhost', () => {
    for (const host of ['127.0.0.1', '127.0.0.2', '[::1]']) {
      expect(isLocalTarget(`http://${host}:8080`)).toBe(true);
    }
    expect(localProbeUrl('https://localhost:8443/').hostname).toBe('127.0.0.1');
  });

  it('rejects hostname prefix bypasses, public targets, credentials, and non-HTTP protocols', () => {
    for (const url of [
      'http://10.example.com',
      'http://192.168.example.com',
      'http://172.16.example.com',
      'http://127.0.0.1.example.com',
      'http://localhost.example.com',
      'http://example.com',
      'http://10.1.2.3',
      'http://192.168.1.1',
      'http://172.16.0.1',
      'http://172.15.0.1',
      'http://172.32.0.1',
      'http://0.0.0.0',
      'http://8.8.8.8',
      'http://[::ffff:8.8.8.8]',
      'http://user:password@127.0.0.1',
      'ftp://127.0.0.1',
      'file:///tmp/a',
    ])
      expect(isLocalTarget(url), url).toBe(false);
  });
});

describe('bounded local transport', () => {
  it('reads a real loopback response through pinned localhost', async () => {
    const target = await serve((_req, res) => res.end('local response'));
    const response = await fetchLocalTarget(target.replace('127.0.0.1', 'localhost'));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('local response');
  });

  it('does not follow even a local redirect or contact its destination', async () => {
    let destinationRequests = 0;
    const destination = await serve((_req, res) => {
      destinationRequests++;
      res.end('must not be fetched');
    });
    const source = await serve((_req, res) => {
      res.writeHead(302, { location: destination });
      res.end();
    });
    await expect(fetchLocalTarget(source)).rejects.toThrow(/redirects are not followed/);
    expect(destinationRequests).toBe(0);
  });

  it('rejects an oversized body instead of reporting a partial read as complete', async () => {
    const target = await serve((_req, res) => res.end('x'.repeat(PROBE_RESPONSE_CAP + 1)));
    await expect(fetchLocalTarget(target)).rejects.toThrow(/not fully examined/);
  });

  it('honours cancellation before opening a socket', async () => {
    let requests = 0;
    const target = await serve((_req, res) => {
      requests++;
      res.end();
    });
    await expect(fetchLocalTarget(target, { signal: AbortSignal.abort() })).rejects.toThrow(/aborted/);
    expect(requests).toBe(0);
  });
});
