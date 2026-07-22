/**
 * FirmLab LAN capture agent (Phase 6.2, design §5c) — the robust answer to Docker. Runs standalone on a small
 * Linux box that sits ON the LAN with the privileges a NAT-bridged container can't have: it positions the target
 * (bettercap ARP spoof), intercepts (mitmproxy), and streams the carved firmware candidates it sees back to the
 * workbench over the token-authenticated `/api/capture/agent/*` channel. The workbench does the authoritative
 * firmware scoring + carving + ingest, so the heavy privileged surface stays off the main app and keeps working
 * when the workbench runs on a different machine.
 *
 * Requires: node, mitmproxy (mitmdump), bettercap — all on the agent box. Nothing here decides a verdict; it just
 * saves plausibly-firmware response bodies and forwards them.
 *
 * Usage (on the LAN box):
 *   FIRMLAB_CAPTURE_AGENT_TOKEN=<same token as the workbench> \
 *   WORKBENCH_URL=http://<workbench-host>:8799 \
 *   TARGET_IP=192.168.1.42 [IFACE=eth0] [AGENT_ID=pi-lab] \
 *   node capture-agent.mjs
 * Then trigger the device's OTA. Ctrl-C tears everything down (bettercap restores ARP).
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const WORKBENCH = process.env.WORKBENCH_URL ?? 'http://127.0.0.1:8799';
const TOKEN = process.env.FIRMLAB_CAPTURE_AGENT_TOKEN;
const TARGET_IP = process.env.TARGET_IP;
const IFACE = process.env.IFACE || null;
const AGENT_ID = process.env.AGENT_ID || os.hostname();
const PROXY_PORT = Number(process.env.PROXY_PORT ?? 8788);

if (!TOKEN) {
  console.error('Set FIRMLAB_CAPTURE_AGENT_TOKEN (must match the workbench).');
  process.exit(1);
}

// The same pre-filter addon the workbench embeds: save plausibly-firmware bodies + a metadata manifest.
const ADDON = `import json, os, re
from mitmproxy import ctx, http
FW_URL = re.compile(r"/ota\\b|/firmware\\b|/upgrade\\b|/fw\\b|/update\\b|\\.bin\\b|\\.pkg\\b|\\.img\\b|\\.trx\\b|\\.chk\\b", re.I)
def load(loader):
    loader.add_option("capdir", str, "", "capture dir")
def response(flow: http.HTTPFlow):
    capdir = getattr(ctx.options, "capdir", None)
    if not capdir: return
    os.makedirs(os.path.join(capdir, "bodies"), exist_ok=True)
    resp = flow.response; body = resp.content if resp else b""
    ct = (resp.headers.get("content-type","") if resp else "") or ""
    url = flow.request.pretty_url; scheme = flow.request.scheme
    tls = "tls-unpinned" if scheme=="https" else ("plaintext" if scheme=="http" else None)
    saved = None
    if body and (bool(FW_URL.search(url)) or len(body) >= 262144 or "octet-stream" in ct.lower()):
        saved = os.path.join("bodies", flow.id + ".bin")
        open(os.path.join(capdir, saved), "wb").write(body)
    rec = {"id":flow.id,"host":flow.request.host,"url":url,"method":flow.request.method,
           "contentType":ct or None,"contentLength":len(body),"tls":tls,"body":saved}
    open(os.path.join(capdir,"flows.jsonl"),"a").write(json.dumps(rec)+"\\n")
`;

async function api(pathname, body) {
  const res = await fetch(`${WORKBENCH}/api/capture/agent/${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-capture-token': TOKEN },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${pathname}: ${res.status} ${await res.text()}`);
  return res.json();
}

const capdir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-agent-'));
fs.mkdirSync(path.join(capdir, 'bodies'), { recursive: true });
fs.writeFileSync(path.join(capdir, 'addon.py'), ADDON);
fs.writeFileSync(path.join(capdir, 'flows.jsonl'), '');

const { sessionId } = await api('session', { agentId: AGENT_ID });
console.log(`Agent session ${sessionId} on the workbench. Positioning + interception starting…`);

const procs = [];
if (TARGET_IP) {
  procs.push(
    spawn(
      'bettercap',
      ['-no-colors', '-eval', `set arp.spoof.targets ${TARGET_IP}; arp.spoof on`, ...(IFACE ? ['-iface', IFACE] : [])],
      { stdio: 'ignore' },
    ),
  );
}
procs.push(
  spawn(
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
      path.join(capdir, 'addon.py'),
    ],
    { stdio: 'ignore' },
  ),
);

const forwarded = new Set();
const timer = setInterval(() => {
  let manifest;
  try {
    manifest = fs.readFileSync(path.join(capdir, 'flows.jsonl'), 'utf8');
  } catch {
    return;
  }
  for (const line of manifest.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let flow;
    try {
      flow = JSON.parse(t);
    } catch {
      continue;
    }
    if (!flow.id || forwarded.has(flow.id) || !flow.body) continue;
    forwarded.add(flow.id);
    try {
      const buf = fs.readFileSync(path.join(capdir, flow.body));
      api('flow', {
        sessionId,
        flow: {
          id: flow.id,
          host: flow.host,
          url: flow.url,
          method: flow.method,
          contentType: flow.contentType,
          contentLength: flow.contentLength,
          tls: flow.tls,
        },
        bodyBase64: buf.toString('base64'),
      })
        .then((r) => console.log(`→ ${flow.url}  score=${r.firmwareScore}${r.carved ? ' [carved]' : ''}`))
        .catch((e) => console.error('forward failed:', e.message));
    } catch (e) {
      console.error('read body failed:', e.message);
    }
  }
}, 1000);

function teardown() {
  clearInterval(timer);
  for (const p of procs) {
    try {
      p.kill('SIGTERM');
    } catch {}
  }
  fs.rmSync(capdir, { recursive: true, force: true });
  console.log('\nTorn down (ARP restored by bettercap).');
  process.exit(0);
}
process.on('SIGINT', teardown);
process.on('SIGTERM', teardown);
