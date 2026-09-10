/**
 * Active web probe (FSTM stage 7 — dynamic analysis) — the missing half of the emulation ladder. Once a firmware
 * service is booted (chroot-service / full-system), FirmLab can finally *drive* it: templated checks for the two
 * classic, near-confirmatory embedded-web bugs — OS command injection and path traversal — against the endpoints
 * the service actually serves. A reproduced hit against the SANDBOXED service is real dynamic evidence
 * (`confirmed_in_emulation`: proves the sandbox, never the deployed device); everything else is honestly a lead or
 * nothing. No exploitation, no fuzzing of third parties — only the operator's own emulated target.
 *
 * Command injection requires generated output absent from the input, a clean baseline, and a second challenge.
 * Traversal requires a passwd root line absent from baseline and missing-file controls. The
 * payload builders, the injection-point parser, and the detectors are PURE and unit-tested; the runner only does
 * bounded HTTP and composes them, with an injectable fetch so tests never touch the network.
 */
import { constants as cryptoConstants, randomBytes } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import type { EvidenceChannel, FindingSeverity, ProofState } from '@firmlab/core';
import { fetchLocalTarget, isLocalTarget } from './webprobe-transport.js';

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
  if (!/^[A-Za-z0-9]{2,128}$/.test(nonce))
    throw new Error('Probe nonce must contain 2–128 ASCII alphanumeric characters.');
  const middle = Math.ceil(nonce.length / 2);
  const command = `printf '%s%s' '${nonce.slice(0, middle)}' '${nonce.slice(middle)}'`;
  return [`;${command};`, `| ${command}`, `\`${command}\``, `$(${command})`, `\n${command}`, `&&${command}`];
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

/** Candidate detector only: the runner also requires baseline and independent challenge controls. */
export function detectCmdInjection(nonce: string, body: string): boolean {
  return body.includes(nonce);
}

/** Pure: a traversal succeeded iff the response leaks a real /etc/passwd root line. */
export function detectPasswdLeak(body: string): boolean {
  return /(?:^|\r?\n)root:[^:\r\n]*:0:0:[^:\r\n]*:[^:\r\n]*:[^:\r\n]+(?:\r?\n|$)/.test(body);
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
  return `${base}${point.path}?${encodeURIComponent(point.param)}=${encodeURIComponent(payload)}`;
}

export interface WebProbeResult {
  probeVersion?: number;
  available: boolean;
  reason: string;
  target: string;
  requests: number;
  points: number;
  findings: WebFinding[];
  /** Absent on historical results, whose coverage cannot be reconstructed reliably. */
  coverage?: {
    discoveredPoints: number;
    eligiblePoints: number;
    plannedPoints: number;
    attemptedPoints: number;
    completedPoints: number;
    skippedUnsupportedMethod: number;
    skippedPointLimit: number;
    skippedBudget: number;
    requestBudget: number;
    budgetExhausted: boolean;
    failedRequests: number;
  };
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
  if (!isLocalTarget(rawUrl)) return Promise.reject(new Error('Invalid firmware probe URL or credentials.'));
  if (init.signal?.aborted) return Promise.reject(new Error('Firmware probe aborted.'));
  if (url.hostname === 'localhost') url.hostname = '127.0.0.1';
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
              // Some vendor stacks (the WR940N included) predate RFC 5746. OpenSSL 3 refuses their initial
              // handshake as "unsafe legacy renegotiation" unless this per-socket compatibility bit is present.
              secureOptions: cryptoConstants.SSL_OP_LEGACY_SERVER_CONNECT,
            }
          : {}),
      },
      (response) => {
        response.once('error', reject);
        response.once('aborted', () => reject(new Error('Firmware probe response aborted.')));
        if ((response.statusCode ?? 0) >= 300 && (response.statusCode ?? 0) < 400) {
          response.destroy();
          reject(new Error('Firmware probe redirects are not permitted.'));
          return;
        }
        const chunks: Buffer[] = [];
        let kept = 0;
        response.on('data', (chunk: Buffer) => {
          if (kept + chunk.length > LOOPBACK_RESPONSE_CAP) {
            response.destroy(new Error('Firmware probe response exceeded its byte limit.'));
            return;
          }
          chunks.push(chunk);
          kept += chunk.length;
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
  opts: {
    fetch?: FetchLike;
    timeoutMs?: number;
    maxRequests?: number;
    nonce?: string;
    targetContext?: 'emulation';
  } = {},
): Promise<WebProbeResult> {
  const doFetch = opts.fetch ?? fetchLocalTarget;
  const timeoutMs = opts.timeoutMs ?? 6000;
  const maxRequests = opts.maxRequests ?? 200;
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 0)
    throw new Error('Request budget must be a nonnegative integer.');
  const nonce = opts.nonce ?? `FLZ${randomNonce()}`;
  cmdInjectionPayloads(nonce); // Validate before any network request.
  const target = baseUrl.replace(/\/+$/, '');
  let lastTransportError = '';
  let requests = 0;
  let failedRequests = 0;

  const get = async (url: string): Promise<{ ok: boolean; status: number; body: string } | null> => {
    if (requests >= maxRequests) return null;
    requests++;
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      const res = await doFetch(url, { signal: ac.signal });
      return { ok: res.ok, status: res.status, body: (await res.text()).slice(0, 200_000) };
    } catch (error) {
      failedRequests++;
      lastTransportError = error instanceof Error ? error.message : String(error);
      return null;
    } finally {
      clearTimeout(timer);
    }
  };

  const home = await get(`${target}/`);
  if (!home) {
    return {
      probeVersion: 2,
      available: false,
      reason:
        maxRequests === 0
          ? 'Request budget is zero; target was not contacted.'
          : `Target ${target} is not reachable — boot the service (chroot-service / full-system) first, then probe.${
              lastTransportError ? ` Transport error: ${lastTransportError}` : ''
            }`,
      target,
      requests,
      points: 0,
      findings: [],
    };
  }

  const discovered = parseInjectionPoints(home.body);
  // Interleave sources before the cap, so a large discovery page cannot exclude the fallback sinks.
  const discoveredGet = discovered.filter((point) => point.method === 'GET');
  const candidates: InjectionPoint[] = [];
  const pointKeys = new Set<string>();
  for (let i = 0; i < Math.max(discoveredGet.length, BUILTIN_POINTS.length); i++) {
    for (const point of [discoveredGet[i], BUILTIN_POINTS[i]]) {
      if (!point) continue;
      const key = `${point.path}:${point.param}`;
      if (pointKeys.has(key)) continue;
      pointKeys.add(key);
      candidates.push(point);
    }
  }
  const points = candidates.slice(0, 40);
  const states = points.map((point) => ({
    point,
    baseline: null as { body: string } | null,
    baselineAttempted: false,
    attempted: false,
    steps: 0,
  }));
  const findings: WebFinding[] = [];
  const seenKinds = new Set<string>();
  const proofState: ProofState =
    opts.targetContext === 'emulation' ? 'confirmed_in_emulation' : 'needs_runtime_reproduction';
  const context =
    opts.targetContext === 'emulation'
      ? 'Reproduced in the associated emulation session; this does not prove the deployed device.'
      : 'Observed on the supplied service; association with a firmware emulation session is unverified.';
  // Each round reaches all points before progressing to another payload; techniques alternate.
  const rounds = [
    { kind: 'ci', index: 0 },
    { kind: 'pt', index: 0 },
    { kind: 'ci', index: 1 },
    { kind: 'pt', index: 1 },
    { kind: 'ci', index: 2 },
    { kind: 'pt', index: 2 },
    { kind: 'ci', index: 3 },
    { kind: 'pt', index: 3 },
    { kind: 'ci', index: 4 },
    { kind: 'ci', index: 5 },
  ];
  let budgetExhausted = false;
  outer: for (const round of rounds) {
    for (const state of states) {
      if (requests >= maxRequests) {
        budgetExhausted = true;
        break outer;
      }
      if (round.kind === 'ci' && round.index === 0) {
        if (maxRequests - requests < 2) {
          budgetExhausted = true;
          break outer;
        }
        state.baselineAttempted = true;
        state.baseline = await get(buildProbeUrl(target, state.point, `FLCONTROL${randomNonce()}`));
      }
      if (!state.baseline) continue; // A failed control cannot establish a negative baseline.
      const { point, baseline } = state;
      const key = `${round.kind}:${point.path}:${point.param}`;
      if (seenKinds.has(key)) {
        state.steps++;
        continue;
      }
      const challenge = `${nonce.slice(0, 100)}${randomNonce()}`;
      const payload =
        round.kind === 'ci' ? cmdInjectionPayloads(challenge)[round.index] : traversalPayloads()[round.index];
      if (payload === undefined) continue;
      state.attempted = true;
      const r = await get(buildProbeUrl(target, point, payload));
      if (!r) continue;
      state.steps++;
      if (
        round.kind === 'ci' &&
        detectCmdInjection(challenge, r.body) &&
        !detectCmdInjection(challenge, baseline.body)
      ) {
        const secondChallenge = `${nonce.slice(0, 100)}${randomNonce()}`;
        const secondPayload = cmdInjectionPayloads(secondChallenge)[round.index];
        if (secondPayload === undefined) continue;
        const confirmation = await get(buildProbeUrl(target, point, secondPayload));
        if (!confirmation) {
          state.steps--;
          continue;
        }
        if (
          !detectCmdInjection(secondChallenge, confirmation.body) ||
          detectCmdInjection(secondChallenge, baseline.body) ||
          detectCmdInjection(secondChallenge, r.body) ||
          detectCmdInjection(challenge, confirmation.body)
        )
          continue;
        seenKinds.add(key);
        findings.push({
          kind: 'web-command-injection',
          title: `OS command injection in ${point.path} (${point.param})`,
          severity: 'critical',
          proofState,
          // A live service answered a request this workbench sent it — the response IS the evidence.
          evidenceChannel: 'probe_response',
          evidence: {
            probeVersion: 2,
            path: point.path,
            param: point.param,
            payload,
            expectedOutput: challenge,
            confirmationPayload: secondPayload,
            confirmationOutput: secondChallenge,
            baselineMarkerAbsent: true,
            independentChallengeConfirmed: true,
            targetContext: opts.targetContext ?? 'unverified',
          },
          rationale: `Two independent shell challenges produced their expected outputs, absent verbatim from the inputs and baseline. ${context}`,
        });
      }
      if (round.kind === 'pt' && detectPasswdLeak(r.body) && !detectPasswdLeak(baseline.body)) {
        const controlPayload = payload.replace(/passwd$/, `firmlab-missing-${randomNonce()}`);
        const control = await get(buildProbeUrl(target, point, controlPayload));
        if (!control) {
          state.steps--;
          continue;
        }
        if (detectPasswdLeak(control.body)) continue;
        seenKinds.add(key);
        findings.push({
          kind: 'web-path-traversal',
          title: `Path traversal in ${point.path} (${point.param})`,
          severity: 'high',
          proofState,
          // A live service answered a request this workbench sent it — the response IS the evidence.
          evidenceChannel: 'probe_response',
          evidence: {
            probeVersion: 2,
            path: point.path,
            param: point.param,
            payload,
            leaked: '/etc/passwd',
            baselineLeakAbsent: true,
            missingFileControl: controlPayload,
            missingFileLeakAbsent: true,
            targetContext: opts.targetContext ?? 'unverified',
          },
          rationale: `The requested path returned passwd-format root data absent from baseline and missing-file controls. ${context}`,
        });
      }
    }
  }

  const attemptedPoints = states.filter((state) => state.attempted).length;
  const completedPoints = states.filter((state) => state.steps === rounds.length).length;
  return {
    probeVersion: 2,
    available: true,
    reason: findings.length
      ? `Observed ${findings.length} issue(s) over ${requests} requests; attempted ${attemptedPoints}/${points.length} planned points, completed ${completedPoints}. ${context}`
      : `No command injection or traversal reproduced over ${requests} requests; attempted ${attemptedPoints}/${points.length} planned injection point(s), completed ${completedPoints}. Absence of a hit is not proof of safety.`,
    target,
    requests,
    points: attemptedPoints,
    findings,
    coverage: {
      discoveredPoints: discovered.length,
      eligiblePoints: candidates.length,
      plannedPoints: points.length,
      attemptedPoints,
      completedPoints,
      skippedUnsupportedMethod: discovered.length - discoveredGet.length,
      skippedPointLimit: candidates.length - points.length,
      skippedBudget: states.filter((state) => !state.baselineAttempted).length,
      requestBudget: maxRequests,
      budgetExhausted: (budgetExhausted || requests >= maxRequests) && completedPoints < points.length,
      failedRequests,
    },
  };
}

/** A short random nonce for marker-based detection (uniqueness only; never security-sensitive). */
function randomNonce(): string {
  return randomBytes(6).toString('hex');
}
