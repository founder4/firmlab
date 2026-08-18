import https from 'node:https';
import { describe, expect, it } from 'vitest';
import {
  buildProbeUrl,
  cmdInjectionPayloads,
  detectCmdInjection,
  detectPasswdLeak,
  fetchFirmwareLoopback,
  parseInjectionPoints,
  runWebProbe,
  traversalPayloads,
} from './webprobe.js';

// Static, self-signed certificate used only by the loopback TLS integration test.
const TLS_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCv3rhezLyuQDT1
/aCr+CWeSzhx+UXt0CjOux5NaGGcsu3Sn7YhKt2fSHrJfCnxMCLOyY1l87wZv9SI
GaJZ915+e/mp4gNDfAQ204MmZiTWjabqLFU8Jb0nEPxELXnX57C88zltQHt+45kf
4ppNpx9dj4MVz9iNFHzmf9CIrDqlGZOyo3e75HFjgx3XQgvxd/u6j8Ud1LGeVZDE
U9tU8zEE++Iu8mx+yI+YC/o5NBPLahJeu3W0z215Q+cnvhB1czIijvDadPSpccdY
2xJYVMTKa4tTN3qtr1LRzbdoTQhR7Q/x+smniuOhetk5eRge04UhDQ7AZPLepNLQ
sRMg/uR1AgMBAAECggEAA3a4vV89aRYpJN4jq7dlsEYtfKsq6injH902FdK0N3Sb
s/4CxYj1V/WCu5SnM9GdoeJ81zDzd7NcQXj1xl1VnlqdOnAR3eKjp5vHVbqFx7b+
/lY0sIxSuyH9we7+Wxb8V2BX9XOjawabBbJ+FQDxYHOa4pNXIcIxSo3iYsq3lfhQ
XcXymusdW98Xt413K1KpitOX8Y+hjdJ/Qvn77kxjc+gcD/+LKeb+tp6URHR6inbe
CE3OH4ZMYeCn1XdvVL+nAzgViZL0TZHSc62aLlu3d7B/7JZtMBLsiBP2CqYSSVw2
NPg+wstFKSVUVacZXco41JRV7Ucin9VKZldpTm1EuQKBgQDg/y3UR6E3tcfWSiGu
/j1nAliPsb3g+rruA/59IIPROuet2Sc1FoVJdR5bORpRMNSxSaKBOVHDbCEc/5Rr
EtXJQXzOIXEpBF47VAifgl9pSghVAbC631dPJf7OKsn9TiF67ZNSbOD9COTXKMWQ
Sn7ZG8kHqVmAmS+KN8GcaMUh2QKBgQDIGpSnAErnxPJACQyVtzdvL+IrOhgU02R5
Tf6dd4619OgheNQPTg0bE0BZVCVDrmK0mMYqNxTDjU1KWxTPviZCFKsM0zJUStvo
8Dvw1eEpcNMmPG7xr+CYnquIx0g/7x6FqO6Vtxy+zA5Ai0j4wNOuY+/7dwa0q4Sb
uQ2uL6hZ/QKBgBEWL/PMEMk7S9bRQGeatS0Kd5FKDUJ1qBaFRSFZg8ky8P8524lj
kXG3rDt/RalezPg9wFKR+MyffJBINIxBHO0wxPqefYqA42scAZ+jdf13+tQB0dsP
NQE0wHoFs9tBwLcmLab3z8pHj6FrXj2L+sAgJQ8o5Dwo5fxYKaLoLfhZAoGBAKXB
3wG3rFTxP/rrhBFBBBqGf8NvDCO0OLaDdTbbosv3Y5LWlFNZRGH5QIS+v1+hRQJ0
yzKNDhYvJqdBa6vqx6ZVmJu3FyncGO6MkhqeETZSz5YM2Zo7JsFGLrHO4nqTiaUO
mxRJ6vXh8qxktL3afX8oKdMUdemTavXUBREVSU/BAoGAJJxkno9XOr2dm1TTipky
mYcnu5MnRsJEc/NLikR2SONwO8d96tXat2rFchHK35nXiG8oGemcWmm4pN9GjgV1
P8l6nEvLI3XEOjdNfY6usuMZwG20gvO6oOQi+SSPXmupC3rUv5y+dR9aGKYdv//6
ZbzNAjwqOZey7rxS9AOovUE=
-----END PRIVATE KEY-----`;

const TLS_CERT = `-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUOP2ld336X74Q2cH0tDJl7kALUEgwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVZmlybWxhYi1sb29wYmFjay10ZXN0MB4XDTI2MDgxODIz
MTA0N1oXDTM2MDgxNTIzMTA0N1owIDEeMBwGA1UEAwwVZmlybWxhYi1sb29wYmFj
ay10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr964Xsy8rkA0
9f2gq/glnks4cflF7dAozrseTWhhnLLt0p+2ISrdn0h6yXwp8TAizsmNZfO8Gb/U
iBmiWfdefnv5qeIDQ3wENtODJmYk1o2m6ixVPCW9JxD8RC151+ewvPM5bUB7fuOZ
H+KaTacfXY+DFc/YjRR85n/QiKw6pRmTsqN3u+RxY4Md10IL8Xf7uo/FHdSxnlWQ
xFPbVPMxBPviLvJsfsiPmAv6OTQTy2oSXrt1tM9teUPnJ74QdXMyIo7w2nT0qXHH
WNsSWFTEymuLUzd6ra9S0c23aE0IUe0P8frJp4rjoXrZOXkYHtOFIQ0OwGTy3qTS
0LETIP7kdQIDAQABo1MwUTAdBgNVHQ4EFgQU72mTuni2ELxgmAFitr2aRKNpVjQw
HwYDVR0jBBgwFoAU72mTuni2ELxgmAFitr2aRKNpVjQwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAn9ZDf20JqYJjlzttR6Hr9g0KtgXhFu6LwGu/
IBBBvD0kCQXf+RcP5C6jQmAMKfAtsCFRUncdSOPbZ+CbyHRM1kDzqqR7PF8+fGt4
9eNmx+WxPLcO/4sAOD6pfXHg4ZoXCiQj7t43BmYa/Gd9Jchwb+CLKiYgoTe0Pl+n
Fo6KLnKcTaHNrOxyA5G3XobyvkAkuyDl/gX5ALZ0NNVMO4mnFZ16XFGBHIO9v60F
lobKLgDLcO0kFtDIyb/qeaU/4BBjwpe3JUfotNshQMetQjf3Mi/V76479g6mCdM2
Fe76F5IYQ/aQQxDxNliNqB0jay37o1OHhjXQnz8ooyPzKHdUWA==
-----END CERTIFICATE-----`;

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

describe('fetchFirmwareLoopback — scoped legacy/self-signed TLS', () => {
  it('drives a self-signed HTTPS service without changing global TLS verification', async () => {
    const server = https.createServer({ key: TLS_KEY, cert: TLS_CERT }, (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<form action="/ping.cgi" method="get"><input name="ip"></form>');
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    try {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('test HTTPS server has no TCP port');
      const target = `https://127.0.0.1:${address.port}`;
      const globalTlsSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;

      // The normal client still rejects the test certificate: only the guarded transport gets the exception.
      await expect(globalThis.fetch(`${target}/`)).rejects.toThrow();
      const result = await runWebProbe(target, {
        fetch: fetchFirmwareLoopback,
        maxRequests: 3,
        timeoutMs: 1000,
      });
      expect(result.available).toBe(true);
      expect(result.requests).toBe(3);
      expect(process.env.NODE_TLS_REJECT_UNAUTHORIZED).toBe(globalTlsSetting);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    }
  });

  it('refuses to apply relaxed TLS to any non-loopback host', async () => {
    await expect(fetchFirmwareLoopback('https://example.com/')).rejects.toThrow(/restricted to loopback/i);
  });
});
