/** Local probe transport: literal loopback addresses, pinned localhost, no redirects, bounded response bodies. */
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import type { FetchLike } from './webprobe.js';

export const PROBE_RESPONSE_CAP = 200_000;

export function localProbeUrl(raw: string): URL {
  const url = new URL(raw);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('Probe targets must use HTTP(S) without URL credentials.');
  }
  // Pin the only accepted hostname; no DNS lookup can turn an allowed name into a public destination.
  if (url.hostname === 'localhost') url.hostname = '127.0.0.1';
  const host = url.hostname;
  if (host === '[::1]') return url;
  if (isIP(host) === 4) {
    const [first] = host.split('.').map(Number);
    if (first === 127) {
      return url;
    }
  }
  throw new Error('Probe targets must be localhost or a literal loopback IP address.');
}

export function isLocalTarget(raw: string): boolean {
  try {
    localProbeUrl(raw);
    return true;
  } catch {
    return false;
  }
}

/** TLS verification stays enabled here. Only the emulator's separate loopback transport permits legacy TLS. */
export const fetchLocalTarget: FetchLike = async (raw, init = {}) => {
  const url = localProbeUrl(raw);
  if (init.signal?.aborted) throw new Error('Firmware probe aborted.');
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request(url, { method: init.method ?? 'GET' }, (response) => {
      const status = response.statusCode ?? 0;
      if (status >= 300 && status < 400) {
        request.destroy(new Error(`Probe target returned HTTP ${status}; redirects are not followed.`));
        return;
      }
      const chunks: Buffer[] = [];
      let bytes = 0;
      response.on('data', (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > PROBE_RESPONSE_CAP) {
          request.destroy(new Error(`Probe response exceeded ${PROBE_RESPONSE_CAP} bytes; it was not fully examined.`));
          return;
        }
        chunks.push(chunk);
      });
      response.once('error', reject);
      response.once('end', () => {
        resolve({
          ok: status >= 200 && status < 300,
          status,
          text: async () => Buffer.concat(chunks).toString('utf8'),
        });
      });
    });
    const abort = (): void => {
      request.destroy(new Error('Firmware probe aborted.'));
    };
    // Also bound callers that omit an AbortSignal. This is a total deadline, not an idle-socket timeout.
    const timer = setTimeout(() => request.destroy(new Error('Firmware probe transport timed out.')), 6000);
    init.signal?.addEventListener('abort', abort, { once: true });
    request.once('error', reject);
    request.once('close', () => {
      clearTimeout(timer);
      init.signal?.removeEventListener('abort', abort);
    });
    if (init.signal?.aborted) abort();
    if (init.body) request.write(init.body);
    request.end();
  });
};
