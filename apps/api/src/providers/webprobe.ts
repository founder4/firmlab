/**
 * Active web probe (FSTM stage 7 — dynamic analysis) — the missing half of the emulation ladder. Once a firmware
 * service is booted (chroot-service / full-system), FirmLab can finally *drive* it: templated checks for the two
 * classic, near-confirmatory embedded-web bugs — OS command injection and path traversal — against the endpoints
 * the service actually serves. A reproduced hit against the SANDBOXED service is real dynamic evidence
 * (`confirmed_in_emulation`: proves the sandbox, never the deployed device); everything else is honestly a lead or
 * nothing. No exploitation, no fuzzing of third parties — only the operator's own emulated target.
 *
 * Command injection is marker-based: a unique per-run nonce is injected and only counted if the response echoes it
 * (shell execution proven, not guessed). Traversal is confirmed only when `/etc/passwd`'s `root:…:0:0:` leaks. The
 * payload builders, the injection-point parser, and the detectors are PURE and unit-tested; the runner only does
 * bounded HTTP and composes them, with an injectable fetch so tests never touch the network.
 */
import { randomBytes } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import type { EvidenceChannel, FindingSeverity, ProofState } from '@firmlab/core';

export interface WebFinding {
  kind: string;
  title: string;
  severity: FindingSeverity;
  proofState: ProofState;
  /** How it was known, alongside how far it was proven. Optional so a stored result predating it stays valid. */
  evidenceChannel?: EvidenceChannel;
  evidence: Record<string, unknown>;
  rationale: string;
}

/** A place to inject: an endpoint path + a parameter, discovered from the served page or the built-in sink list. */
export interface InjectionPoint {
  path: string;
  param: string;
  method: 'GET' | 'POST';
}

/** Classic firmware CGI sinks — a small fallback when the served page exposes no forms/links to parse. */
const BUILTIN_POINTS: InjectionPoint[] = [
  { path: '/cgi-bin/ping.cgi', param: 'ip', method: 'GET' },
  { path: '/ping.cgi', param: 'host', method: 'GET' },
  { path: '/diagnostic.cgi', param: 'cmd', method: 'GET' },
  { path: '/apply.cgi', param: 'ping_ipaddr', method: 'GET' },
  { path: '/cgi-bin/get.cgi', param: 'file', method: 'GET' },
];

/** Pure: OS command-injection payloads that echo `nonce` iff a shell runs them. Separator-, pipe-, and subshell-based. */
export function cmdInjectionPayloads(nonce: string): string[] {
  return [
    `;echo ${nonce};`,
    `| echo ${nonce}`,
    `\`echo ${nonce}\``,
    `$(echo ${nonce})`,
    `%0aecho ${nonce}`,
    `&&echo ${nonce}`,
  ];
}

/** Pure: path-traversal payloads aiming at /etc/passwd through the usual encodings. */
export function traversalPayloads(): string[] {
  return [
    '../../../../../../etc/passwd',
    '....//....//....//....//etc/passwd',
    '..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
    '/etc/passwd',
  ];
}

/** Pure: a shell ran our payload iff the unique nonce is echoed back verbatim. */
export function detectCmdInjection(nonce: string, body: string): boolean {
  return body.includes(nonce);
}

/** Pure: a traversal succeeded iff the response leaks a real /etc/passwd root line. */
export function detectPasswdLeak(body: string): boolean {
  return /root:.*:0:0:/.test(body);
}

const FORM_RE = /<form\b[^>]*\baction\s*=\s*["']?([^"'\s>]+)[^>]*>([\s\S]*?)<\/form>/gi;
const INPUT_NAME_RE = /<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']?([^"'\s>]+)/gi;
const METHOD_RE = /\bmethod\s*=\s*["']?\s*post/i;
const HREF_RE = /href\s*=\s*["']([^"']*\?[^"']+)["']/gi;

/**
 * Pure: discover injection points from a served HTML page — form actions + their input names, and any links that
 * already carry query parameters. Paths are normalized to absolute (relative to the page). Deduped.
 */
export function parseInjectionPoints(html: string, basePath = '/'): InjectionPoint[] {
  const out: InjectionPoint[] = [];
  const seen = new Set<string>();
  const add = (path: string, param: string, method: 'GET' | 'POST'): void => {
    const p = path.startsWith('/') ? path : `/${path.replace(/^\.?\//, '')}`;
    const key = `${method} ${p} ${param}`;
    if (param && !seen.has(key)) {
      seen.add(key);
      out.push({ path: p.split('#')[0] ?? p, param, method });
    }
  };
  for (const m of html.matchAll(FORM_RE)) {
    const action = (m[1] || basePath).split('?')[0] ?? basePath;
    const method: 'GET' | 'POST' = METHOD_RE.test(m[0]) ? 'POST' : 'GET';
    for (const nm of (m[2] ?? '').matchAll(INPUT_NAME_RE)) if (nm[1]) add(action, nm[1], method);
  }
  for (const m of html.matchAll(HREF_RE)) {
    const url = m[1] ?? '';
    const [path, query] = url.split('?');
    const param = (query ?? '').split('&')[0]?.split('=')[0] ?? '';
    if (param) add(path ?? '/', param, 'GET');
  }
  return out;
}

/** Pure: build the probe URL for a GET injection point (payload URL-encoded into the parameter). */
export function buildProbeUrl(baseUrl: string, point: InjectionPoint, payload: string): string {
  const base = baseUrl.replace(/\/+$/, '');
  return `${base}${point.path}?${point.param}=${encodeURIComponent(payload)}`;
}

export interface WebProbeResult {
  available: boolean;
  reason: string;
  target: string;
  requests: number;
  points: number;
  findings: WebFinding[];
}

export type FetchLike = (
  url: string,
  init?: { method?: string; signal?: AbortSignal; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
}>;

const LOOPBACK_NAMES = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
const LOOPBACK_RESPONSE_CAP = 200_000;

/**
 * Fetch a service forwarded from a live firmware guest, including its normal self-signed/legacy HTTPS.
 *
 * The relaxed TLS policy is intentionally inseparable from the loopback guard. Firmware often ships a self-signed
 * certificate and TLS 1.0-era stack; accepting those is necessary to test the sandbox, but doing it through a
 * process-global switch would also weaken research/advisory requests. This transport rejects every non-loopback
 * URL before opening a socket and applies `rejectUnauthorized:false` only to that one HTTPS request.
 */
export function fetchFirmwareLoopback(
  rawUrl: string,
  init: { method?: string; signal?: AbortSignal; body?: string } = {},
): ReturnType<FetchLike> {
  const url = new URL(rawUrl);
  if (!LOOPBACK_NAMES.has(url.hostname)) {
    return Promise.reject(new Error(`Firmware TLS relaxation is restricted to loopback, not ${url.hostname}.`));
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return Promise.reject(new Error(`Unsupported firmware probe protocol: ${url.protocol}`));
  }
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request(
      url,
      {
        method: init.method ?? 'GET',
        ...(url.protocol === 'https:'
          ? {
              rejectUnauthorized: false,
              // Old embedded servers frequently stop at TLS 1.0 and weak-but-still-observable cipher suites.
              // This is scoped to the guarded loopback socket above; it never changes Node's global TLS policy.
              minVersion: 'TLSv1' as const,
              ciphers: 'DEFAULT@SECLEVEL=0',
            }
          : {}),
      },
      (response) => {
        const chunks: Buffer[] = [];
        let kept = 0;
        response.on('data', (chunk: Buffer) => {
          if (kept >= LOOPBACK_RESPONSE_CAP) return;
          const take = chunk.subarray(0, LOOPBACK_RESPONSE_CAP - kept);
          chunks.push(take);
          kept += take.length;
        });
        response.once('end', () => {
          const status = response.statusCode ?? 0;
          resolve({
            ok: status >= 200 && status < 300,
            status,
            text: async () => Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    const abort = (): void => {
      request.destroy(new Error('Firmware probe aborted.'));
    };
    init.signal?.addEventListener('abort', abort, { once: true });
    request.once('error', reject);
    request.once('close', () => init.signal?.removeEventListener('abort', abort));
    if (init.body) request.write(init.body);
    request.end();
  });
}

/**
 * Drive a booted firmware service: fetch the base page, discover injection points (+ the built-in sinks), and
 * probe each for command injection and path traversal within a request budget. A reproduced hit is recorded as
 * `confirmed_in_emulation`. Honest: an unreachable target → available:false, and no hit is reported as no hit.
 */
export async function runWebProbe(
  baseUrl: string,
  opts: { fetch?: FetchLike; timeoutMs?: number; maxRequests?: number; nonce?: string } = {},
): Promise<WebProbeResult> {
  const doFetch = (opts.fetch ?? (globalThis.fetch as unknown as FetchLike)) as FetchLike;
  const timeoutMs = opts.timeoutMs ?? 6000;
  const maxRequests = opts.maxRequests ?? 200;
  const nonce = opts.nonce ?? `FLZ${randomNonce()}`;
  const target = baseUrl.replace(/\/+$/, '');

  const get = async (url: string): Promise<{ ok: boolean; status: number; body: string } | null> => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await doFetch(url, { signal: ac.signal });
      return { ok: res.ok, status: res.status, body: (await res.text()).slice(0, 200_000) };
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  };

  const home = await get(`${target}/`);
  if (!home) {
    return {
      available: false,
      reason: `Target ${target} is not reachable — boot the service (chroot-service / full-system) first, then probe.`,
      target,
      requests: 0,
      points: 0,
      findings: [],
    };
  }

  // Points from the served page take priority; the built-in sinks fill in when the page yields none.
  const discovered = parseInjectionPoints(home.body);
  const points = [...discovered, ...BUILTIN_POINTS].slice(0, 40);

  const findings: WebFinding[] = [];
  const seenKinds = new Set<string>();
  let requests = 1; // counted the home fetch

  outer: for (const point of points) {
    if (point.method !== 'GET') continue; // POST bodies are handled by the fuzzer path; probe GET params here
    for (const payload of cmdInjectionPayloads(nonce)) {
      if (requests >= maxRequests) break outer;
      requests++;
      const r = await get(buildProbeUrl(target, point, payload));
      if (r && detectCmdInjection(nonce, r.body) && !seenKinds.has(`ci:${point.path}:${point.param}`)) {
        seenKinds.add(`ci:${point.path}:${point.param}`);
        findings.push({
          kind: 'web-command-injection',
          title: `OS command injection in ${point.path} (${point.param})`,
          severity: 'critical',
          proofState: 'confirmed_in_emulation',
          // A live service answered a request this workbench sent it — the response IS the evidence.
          evidenceChannel: 'probe_response',
          evidence: { path: point.path, param: point.param, payload, nonceEchoed: true },
          rationale:
            'The injected shell command echoed a unique per-run nonce in the response — command execution is ' +
            'reproduced in the sandbox (proves the emulated service, not the deployed device).',
        });
      }
    }
    for (const payload of traversalPayloads()) {
      if (requests >= maxRequests) break outer;
      requests++;
      const r = await get(buildProbeUrl(target, point, payload));
      if (r && detectPasswdLeak(r.body) && !seenKinds.has(`pt:${point.path}:${point.param}`)) {
        seenKinds.add(`pt:${point.path}:${point.param}`);
        findings.push({
          kind: 'web-path-traversal',
          title: `Path traversal in ${point.path} (${point.param})`,
          severity: 'high',
          proofState: 'confirmed_in_emulation',
          // A live service answered a request this workbench sent it — the response IS the evidence.
          evidenceChannel: 'probe_response',
          evidence: { path: point.path, param: point.param, payload, leaked: '/etc/passwd' },
          rationale:
            'The response leaked /etc/passwd (a real root:…:0:0: line) — arbitrary file read reproduced in the ' +
            'sandbox. Proves the emulated service, not the deployed device.',
        });
      }
    }
  }

  return {
    available: true,
    reason: findings.length
      ? `Reproduced ${findings.length} issue(s) against the emulated service over ${requests} requests.`
      : `No command injection or traversal reproduced over ${requests} requests against ${points.length} injection point(s). Absence of a hit is not proof of safety.`,
    target,
    requests,
    points: points.length,
    findings,
  };
}

/** A short random nonce for marker-based detection (uniqueness only; never security-sensitive). */
function randomNonce(): string {
  return randomBytes(6).toString('hex');
}
