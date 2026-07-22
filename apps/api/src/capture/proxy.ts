/**
 * Network-capture interception (Phase 6.1, design §7/§9). Runs mitmproxy (mitmdump) as an on-path proxy so an OTA
 * download can be watched, scored for "is this firmware?", and carved. Positioning (getting the target's traffic to
 * the proxy) is the operator's job via the on-path-gateway/-spoof backends; this module owns the interception half.
 *
 * The proxy loads a small bundled addon (embedded below, written to the session dir at spawn — no build-time file
 * copy) that appends response metadata to `<capdir>/flows.jsonl` and saves plausibly-firmware bodies under
 * `<capdir>/bodies/`. FirmLab does the AUTHORITATIVE firmware scoring (`scoreFirmwareFlow`) and carving. The pure
 * `parseFlowManifest` + the disk-reading `refreshCaptureFlows` are unit/integration-tested; the mitmdump spawn
 * degrades honestly when the tool is absent (the session records why), and teardown is guaranteed on every exit.
 *
 * Live capture (a real device's OTA over a positioned proxy) is validated on the deploy — the same discipline as
 * the emulation ladder. Here the deterministic core (manifest → score → carve → ingest) is fully exercised.
 */
import { type ChildProcess, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { CAPTURE_DIR } from '../paths.js';
import { type FlowMeta, scoreFirmwareFlow } from '../providers/flowscore.js';
import {
  type CaptureFlowRow,
  type CaptureSessionRow,
  getCaptureFlow,
  getCaptureSession,
  getDevice,
  insertCaptureSession,
  listCaptureFlows,
  updateCaptureSession,
  upsertCaptureFlow,
} from '../store.js';
import { parseFlowManifest } from './flow-manifest.js';
import { ingestCapturedBlob } from './ingest.js';
import { armPositioning, stopPositioning } from './spoof.js';

const PROXY_PORT = Math.max(1, Number(process.env.FIRMLAB_CAPTURE_PROXY_PORT ?? 8788));
const WINDOW_MS = Math.max(30, Number(process.env.FIRMLAB_CAPTURE_WINDOW_SECONDS ?? 300)) * 1000;
/** Cap the body we read back for scoring so a pathological multi-GB response can't blow up memory. */
const MAX_BODY_BYTES = 64 * 1024 * 1024;

/** The mitmproxy addon, embedded so it ships with the code (tsc doesn't copy .py). Written to the session dir. */
const MITM_ADDON = `# FirmLab capture addon (Phase 6.1) — appends response metadata to flows.jsonl and saves plausibly-firmware
# bodies to bodies/<flowid>.bin. FirmLab does the authoritative scoring; this only pre-filters what to save.
import json, os, re
from mitmproxy import ctx, http

FW_URL = re.compile(r"/ota\\b|/firmware\\b|/upgrade\\b|/fw\\b|/update\\b|\\.bin\\b|\\.pkg\\b|\\.img\\b|\\.trx\\b|\\.chk\\b", re.I)

def _capdir():
    return getattr(ctx.options, "capdir", None)

def _fwmin():
    try:
        return int(getattr(ctx.options, "fwmin", 262144))
    except Exception:
        return 262144

def load(loader):
    loader.add_option("capdir", str, "", "FirmLab capture dir")
    loader.add_option("fwmin", int, 262144, "min body bytes to save")

def response(flow: http.HTTPFlow):
    capdir = _capdir()
    if not capdir:
        return
    os.makedirs(os.path.join(capdir, "bodies"), exist_ok=True)
    resp = flow.response
    body = resp.content if resp else b""
    ct = (resp.headers.get("content-type", "") if resp else "") or ""
    url = flow.request.pretty_url
    scheme = flow.request.scheme
    tls = "tls-unpinned" if scheme == "https" else ("plaintext" if scheme == "http" else None)
    saved = None
    if body and (bool(FW_URL.search(url)) or len(body) >= _fwmin() or "octet-stream" in ct.lower()):
        saved = os.path.join("bodies", flow.id + ".bin")
        with open(os.path.join(capdir, saved), "wb") as f:
            f.write(body)
    rec = {"id": flow.id, "host": flow.request.host, "url": url, "method": flow.request.method,
           "status": resp.status_code if resp else None, "contentType": ct or None,
           "contentLength": len(body), "tls": tls, "body": saved}
    with open(os.path.join(capdir, "flows.jsonl"), "a") as f:
        f.write(json.dumps(rec) + "\\n")
`;

const proxies = new Map<string, { proc: ChildProcess; timer: NodeJS.Timeout }>();

function mitmdumpOnPath(): boolean {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    try {
      fs.accessSync(path.join(dir, 'mitmdump'), fs.constants.X_OK);
      return true;
    } catch {}
  }
  return false;
}

function newId(): string {
  return `${Date.now().toString(36)}${Math.trunc(performance.now()).toString(36)}`.slice(0, 12);
}

function capdirFor(sessionId: string): string {
  return path.join(CAPTURE_DIR, sessionId);
}

export interface StartResult {
  sessionId: string;
  watching: boolean;
  reason: string;
  port: number;
}

/**
 * Arm a capture session for a target device: write the addon, spawn mitmdump on-path if present, and time-box it
 * with a guaranteed teardown. Always records an auditable capture_session; when mitmdump is absent the session is
 * created in `error` with the honest reason (never a watching session that silently does nothing).
 */
export function startCaptureSession(deviceId: string | null): StartResult {
  const sessionId = newId();
  const capdir = capdirFor(sessionId);
  fs.mkdirSync(path.join(capdir, 'bodies'), { recursive: true });
  fs.writeFileSync(path.join(capdir, 'firmlab_addon.py'), MITM_ADDON);
  fs.writeFileSync(path.join(capdir, 'flows.jsonl'), '');

  const now = Date.now();

  // Positioning (6.2): get the target's traffic to the proxy — operator gateway, active ARP spoof, or manual.
  const targetIp = deviceId ? (getDevice(deviceId)?.ip ?? null) : null;
  const positioning = armPositioning(sessionId, targetIp);

  const available = mitmdumpOnPath();
  let watching = false;
  let reason: string;
  let status: CaptureSessionRow['status'];
  let error: string | null = null;

  if (available) {
    try {
      const proc = spawn(
        'mitmdump',
        [
          '-q',
          '--mode',
          'transparent',
          '--listen-port',
          String(PROXY_PORT),
          '--set',
          `capdir=${capdir}`,
          '-s',
          path.join(capdir, 'firmlab_addon.py'),
        ],
        { stdio: 'ignore', detached: false },
      );
      proc.on('error', () => undefined); // spawn failure surfaces via the missing manifest, not a crash
      const timer = setTimeout(() => teardownCaptureSession(sessionId, 'timed_out'), WINDOW_MS);
      timer.unref?.();
      proxies.set(sessionId, { proc, timer });
      watching = true;
      status = 'watching';
      reason = `Proxy watching on :${PROXY_PORT} (transparent), positioning: ${positioning.strategy}. Trigger the OTA now. Auto-teardown in ${Math.round(WINDOW_MS / 1000)}s.`;
    } catch (e) {
      status = 'error';
      error = e instanceof Error ? e.message : String(e);
      reason = `Could not start mitmdump: ${error}`;
    }
  } else {
    status = 'error';
    error = 'mitmproxy (mitmdump) not installed';
    reason = 'Capture proxy unavailable — install mitmproxy to intercept OTA flows (the network-proxy backend).';
  }

  insertCaptureSession({
    id: sessionId,
    status,
    subnet: null,
    targetDeviceId: deviceId,
    strategyJson: JSON.stringify({
      proxy: { port: PROXY_PORT, transport: 'network-proxy', available },
      positioning: { strategy: positioning.strategy, active: positioning.active },
    }),
    transcript: `[positioning] ${positioning.reason}\n[armed] capture session for ${deviceId ?? 'a target'} — ${reason}\n`,
    deviceCount: 0,
    error,
    createdAt: now,
    updatedAt: now,
  });

  // If the proxy never came up, don't leave a spoof running with nothing to intercept.
  if (status === 'error') stopPositioning(sessionId);

  return { sessionId, watching, reason, port: PROXY_PORT };
}

/**
 * Re-read the proxy manifest and (re)score any new flows, persisting each as a capture_flows row and staging the
 * firmware candidates as carved. Idempotent + cheap on re-poll (a flow already scored at the same size is skipped).
 */
export function refreshCaptureFlows(sessionId: string): CaptureFlowRow[] {
  const capdir = capdirFor(sessionId);
  let manifest = '';
  try {
    manifest = fs.readFileSync(path.join(capdir, 'flows.jsonl'), 'utf8');
  } catch {
    return listCaptureFlows(sessionId);
  }
  const now = Date.now();
  for (const raw of parseFlowManifest(manifest)) {
    const existing = getCaptureFlow(raw.id);
    if (existing && existing.size === raw.contentLength) continue; // already scored at this size
    const bodyRel = raw.body;
    const bodyAbs = bodyRel ? path.join(capdir, bodyRel) : null;
    let body = new Uint8Array(0);
    let bodyPath: string | null = null;
    if (bodyAbs) {
      try {
        const stat = fs.statSync(bodyAbs);
        if (stat.size <= MAX_BODY_BYTES) {
          body = fs.readFileSync(bodyAbs);
          bodyPath = bodyAbs;
        }
      } catch {}
    }
    const meta: FlowMeta = {
      url: raw.url,
      method: raw.method,
      contentType: raw.contentType,
      contentLength: raw.contentLength,
      tls: raw.tls,
    };
    const score = scoreFirmwareFlow(meta, body);
    const carved = score.isFirmwareCandidate && bodyPath ? 1 : 0;
    upsertCaptureFlow({
      id: raw.id,
      sessionId,
      host: raw.host,
      url: raw.url,
      method: raw.method,
      contentType: raw.contentType,
      size: raw.contentLength,
      tlsPosture: raw.tls,
      firmwareScore: score.score,
      carved,
      bodyPath: carved ? bodyPath : null,
      createdAt: now,
    });
  }

  const flows = listCaptureFlows(sessionId);
  const session = getCaptureSession(sessionId);
  if (session && session.status === 'watching' && flows.some((f) => f.carved)) {
    updateCaptureSession(
      sessionId,
      'carving',
      `${session.transcript}[carving] firmware-looking flow(s) detected — ${flows.filter((f) => f.carved).length} candidate(s) ready to ingest.\n`,
      session.deviceCount,
      session.error,
    );
  }
  return flows;
}

/** Ingest a carved flow's body as a workbench image + provenance. Marks the session `ingested`. */
export function ingestFlow(sessionId: string, flowId: string): { imageId: string; filename: string } {
  const flow = getCaptureFlow(flowId);
  if (!flow || flow.sessionId !== sessionId) throw new Error('Flow not found in this session');
  if (!flow.carved || !flow.bodyPath) throw new Error('Flow is not a carved firmware candidate');
  const buf = fs.readFileSync(flow.bodyPath);
  const base = (() => {
    try {
      const p = new URL(flow.url ?? '').pathname;
      const name = path.basename(p);
      return name && name !== '/' ? name : `capture-${flowId}.bin`;
    } catch {
      return `capture-${flowId}.bin`;
    }
  })();
  const session = getCaptureSession(sessionId);
  const result = ingestCapturedBlob(buf, base, {
    sessionId,
    deviceId: session?.targetDeviceId ?? null,
    endpoint: flow.url,
    transport: flow.tlsPosture?.startsWith('tls') ? 'https' : 'http',
    tlsPosture: flow.tlsPosture,
  });
  if (session) {
    updateCaptureSession(
      sessionId,
      'ingested',
      `${session.transcript}[ingested] carved ${base} (${result.size} bytes) → workbench image ${result.imageId}.\n`,
      session.deviceCount,
      session.error,
    );
  }
  return { imageId: result.imageId, filename: result.filename };
}

/** Guaranteed teardown: stop the proxy, clear the timer, and mark the session torn down (idempotent). */
export function teardownCaptureSession(sessionId: string, finalStatus: 'torn_down' | 'timed_out' = 'torn_down'): void {
  const p = proxies.get(sessionId);
  if (p) {
    clearTimeout(p.timer);
    try {
      p.proc.kill('SIGTERM');
    } catch {}
    proxies.delete(sessionId);
  }
  stopPositioning(sessionId); // restore ARP — guaranteed on every teardown path
  const session = getCaptureSession(sessionId);
  if (session && session.status !== 'ingested' && session.status !== 'torn_down') {
    updateCaptureSession(
      sessionId,
      finalStatus,
      `${session.transcript}[${finalStatus}] proxy stopped; positioning restored.\n`,
      session.deviceCount,
      session.error,
    );
  }
}
