/**
 * Discovery-scan orchestration (Phase 6.0). A capture scan is NOT an image-scoped job (there is no image yet — a
 * capture precedes one), so it can't ride the `startJob`/`jobs` machinery. Instead it anchors a `capture_session`
 * row (the design-§9 lifecycle: armed → discovering → done | error) and upserts what it finds into the persistent
 * `devices` inventory. Fire-and-forget with a durable transcript, exactly like a job the UI polls.
 */
import { randomUUID } from 'node:crypto';
import { type DiscoveryResult, runDiscovery } from '../providers/discover.js';
import { type CaptureSessionRow, insertCaptureSession, updateCaptureSession, upsertDevice } from '../store.js';
import { loadCaptureConfig } from './config.js';

function newId(): string {
  return randomUUID().slice(0, 12);
}

/**
 * Arm a discovery session for the given subnet (or auto-detect when null) and run it in the background. Returns
 * the session id immediately; the caller polls `getCaptureSession(id)` + `listDevices()` for progress and results.
 * Assumes the capture lane is enabled (the route gates on `loadCaptureConfig()`); reads it only for the timeout.
 */
export function startDiscoveryScan(subnet: string | null): string {
  const cfg = loadCaptureConfig();
  const id = newId();
  const now = Date.now();
  const opened = `[armed] capture lane armed — discovery starting on ${subnet ?? 'the auto-detected primary subnet'}\n`;
  const session: CaptureSessionRow = {
    id,
    status: 'discovering',
    subnet,
    targetDeviceId: null,
    strategyJson: null,
    transcript: opened,
    deviceCount: 0,
    error: null,
    createdAt: now,
    updatedAt: now,
  };
  insertCaptureSession(session);
  void runScan(id, subnet, cfg?.discoverTimeoutMs ?? 60_000, opened);
  return id;
}

async function runScan(id: string, subnet: string | null, timeoutMs: number, transcript: string): Promise<void> {
  try {
    const result: DiscoveryResult = await runDiscovery({ subnet, timeoutMs });
    let t = `${transcript}[discovering] ${result.reason}\n`;
    if (!result.available) {
      updateCaptureSession(id, 'error', t, 0, result.reason);
      return;
    }
    const now = Date.now();
    for (const d of result.devices) {
      upsertDevice({
        id: newId(),
        mac: d.mac,
        ouiVendor: d.ouiVendor,
        ip: d.ip,
        mdnsIdentity: d.mdnsIdentity,
        openPorts: d.openPorts.length ? d.openPorts.join(',') : null,
        typeGuess: d.typeGuess,
        typeConfidence: d.typeConfidence,
        firstSeen: now,
        lastSeen: now,
      });
    }
    t += `[done] inventory updated with ${result.devices.length} device(s) from ${result.subnet}.\n`;
    updateCaptureSession(id, 'done', t, result.devices.length, null);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    updateCaptureSession(id, 'error', `${transcript}[error] ${msg}\n`, 0, msg);
  }
}
