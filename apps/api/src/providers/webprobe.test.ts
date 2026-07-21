import { describe, expect, it } from 'vitest';
import {
  buildProbeUrl,
  cmdInjectionPayloads,
  detectCmdInjection,
  detectPasswdLeak,
  parseInjectionPoints,
  runWebProbe,
  traversalPayloads,
} from './webprobe.js';

describe('payload builders + detectors (pure)', () => {
  it('command-injection payloads carry the nonce across separators/subshells', () => {
    const ps = cmdInjectionPayloads('NONCE1');
    expect(ps.every((p) => p.includes('NONCE1'))).toBe(true);
    expect(ps.some((p) => p.startsWith(';'))).toBe(true);
    expect(ps.some((p) => p.includes('$('))).toBe(true);
  });

  it('detectCmdInjection only fires when the exact nonce is echoed', () => {
    expect(detectCmdInjection('NONCE1', 'ping output ... NONCE1 ... done')).toBe(true);
    expect(detectCmdInjection('NONCE1', 'ping output, no marker')).toBe(false);
  });

  it('detectPasswdLeak requires a real root:…:0:0: line', () => {
    expect(detectPasswdLeak('root:x:0:0:root:/root:/bin/sh\n')).toBe(true);
    expect(detectPasswdLeak('<html>not passwd</html>')).toBe(false);
  });

  it('traversal payloads target /etc/passwd through common encodings', () => {
    expect(traversalPayloads().some((p) => p.includes('%2f'))).toBe(true);
    expect(traversalPayloads().some((p) => p.includes('etc/passwd'))).toBe(true);
  });
});

describe('parseInjectionPoints', () => {
  it('extracts form actions + input names and links with query params', () => {
    const html = `
      <form action="/ping.cgi" method="get"><input name="ip"><input name="count"></form>
      <form action="/login" method="POST"><input name="user"></form>
      <a href="/view?file=readme">docs</a>`;
    const pts = parseInjectionPoints(html);
    expect(pts).toContainEqual({ path: '/ping.cgi', param: 'ip', method: 'GET' });
    expect(pts).toContainEqual({ path: '/login', param: 'user', method: 'POST' });
    expect(pts).toContainEqual({ path: '/view', param: 'file', method: 'GET' });
  });

  it('normalizes relative paths and dedupes', () => {
    const pts = parseInjectionPoints('<a href="cgi?x=1">a</a><a href="cgi?x=2">b</a>');
    expect(pts.filter((p) => p.path === '/cgi')).toHaveLength(1);
  });
});

describe('buildProbeUrl', () => {
  it('url-encodes the payload into the parameter', () => {
    const u = buildProbeUrl('http://127.0.0.1:8080/', { path: '/ping.cgi', param: 'ip', method: 'GET' }, ';echo x;');
    expect(u).toBe('http://127.0.0.1:8080/ping.cgi?ip=%3Becho%20x%3B');
  });
});

/** A stub fetch simulating a router-CGI that (a) serves a form and (b) is command-injectable on /ping.cgi?ip=. */
function vulnerableFetch(): (url: string) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }> {
  return async (url: string) => {
    const u = new URL(url);
    if (u.pathname === '/') {
      return {
        ok: true,
        status: 200,
        text: async () => '<form action="/ping.cgi" method="get"><input name="ip"></form>',
      };
    }
    if (u.pathname === '/ping.cgi') {
      const ip = u.searchParams.get('ip') ?? '';
      // Simulate `system("ping " + ip)`: a shell splits on ; and runs echo, so the nonce lands in the output.
      const m = ip.match(/echo ([A-Za-z0-9]+)/);
      const echoed = m ? m[1] : '';
      return { ok: true, status: 200, text: async () => `PING ${ip}\n${echoed}\n64 bytes` };
    }
    return { ok: false, status: 404, text: async () => 'not found' };
  };
}

describe('runWebProbe', () => {
  it('reproduces command injection against the emulated service → confirmed_in_emulation', async () => {
    const res = await runWebProbe('http://127.0.0.1:8080', { fetch: vulnerableFetch(), nonce: 'FLZdeadbeef' });
    expect(res.available).toBe(true);
    const ci = res.findings.find((f) => f.kind === 'web-command-injection');
    expect(ci?.severity).toBe('critical');
    expect(ci?.proofState).toBe('confirmed_in_emulation');
    expect(ci?.title).toContain('/ping.cgi');
  });

  it('reports no hit honestly on a non-vulnerable target (no overclaim)', async () => {
    const safeFetch = async (url: string) => {
      const u = new URL(url);
      if (u.pathname === '/') return { ok: true, status: 200, text: async () => '<html>hi</html>' };
      return { ok: true, status: 200, text: async () => 'sanitized' };
    };
    const res = await runWebProbe('http://127.0.0.1:8080', { fetch: safeFetch });
    expect(res.available).toBe(true);
    expect(res.findings).toHaveLength(0);
    expect(res.reason).toMatch(/not proof of safety/i);
  });

  it('degrades honestly when the target is unreachable', async () => {
    const deadFetch = async () => {
      throw new Error('ECONNREFUSED');
    };
    const res = await runWebProbe('http://127.0.0.1:9', { fetch: deadFetch });
    expect(res.available).toBe(false);
    expect(res.findings).toHaveLength(0);
    expect(res.reason).toMatch(/not reachable/i);
  });

  it('respects the request budget', async () => {
    let calls = 0;
    const countingFetch = async (url: string) => {
      calls++;
      const u = new URL(url);
      if (u.pathname === '/')
        return { ok: true, status: 200, text: async () => '<form action="/a"><input name="x"></form>' };
      return { ok: true, status: 200, text: async () => 'nothing' };
    };
    const res = await runWebProbe('http://127.0.0.1:8080', { fetch: countingFetch, maxRequests: 5 });
    expect(res.requests).toBeLessThanOrEqual(5);
    expect(calls).toBeLessThanOrEqual(5);
  });
});
