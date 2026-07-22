/**
 * BLE backend — DFU reassembly (Phase 6.4, design §8). A Bluetooth OTA (Nordic DFU & vendor variants) sends the
 * firmware as a stream of writes to a DFU DATA characteristic; a BLE sniffer (nRF52840: nRF Sniffer / Sniffle)
 * captures those writes, and the FirmLab value-add is REASSEMBLING them back into the image, which then ingests
 * through the exact same path as any other capture (a `ble-gatt` carved flow → a workbench image + provenance).
 *
 * The reassembly is PURE (concatenate the DATA-characteristic payloads in order) and unit-tested. It operates on
 * a NORMALIZED write stream — the sniffer/agent turns its PCAP into the ordered DATA-char payloads first; that
 * radio-specific decode is where a live sniffer plugs in. Reassembling a *provided* capture needs no dongle (so it
 * validates anywhere); the live over-the-air sniff needs the nRF hardware and is deploy-validated. A DFU transfer
 * is firmware by construction, so a reassembled image is always carved (never a silent "not firmware").
 */
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { CAPTURE_DIR } from '../paths.js';
import { type FlowMeta, scoreFirmwareFlow } from '../providers/flowscore.js';
import { getCaptureSession, insertCaptureSession, upsertCaptureFlow } from '../store.js';
import { reassembleDfu } from './dfu.js';

/** Create a capture session for a BLE OTA. NOT dongle-gated — reassembling a provided capture needs no radio. */
export function createBleSession(deviceId: string | null): string {
  const id = randomUUID().slice(0, 12);
  const now = Date.now();
  fs.mkdirSync(path.join(CAPTURE_DIR, id, 'bodies'), { recursive: true });
  insertCaptureSession({
    id,
    status: 'watching',
    subnet: null,
    targetDeviceId: deviceId,
    strategyJson: JSON.stringify({ transport: 'ble-gatt' }),
    transcript: `[armed] BLE DFU capture session for ${deviceId ?? 'a target'}\n`,
    deviceCount: 0,
    error: null,
    createdAt: now,
    updatedAt: now,
  });
  return id;
}

/**
 * Reassemble a captured DFU write stream into an image and stage it as a carved `ble-gatt` flow (ingestable by the
 * normal path). A DFU transfer is firmware by construction → always carved. Returns the flow id + score (info only).
 */
export function stageBleDfu(
  sessionId: string,
  name: string,
  chunks: Uint8Array[],
): { flowId: string; size: number; firmwareScore: number; carved: boolean } {
  if (!getCaptureSession(sessionId)) throw new Error('Unknown capture session');
  const blob = reassembleDfu(chunks);
  if (blob.length === 0) throw new Error('Empty DFU stream — nothing to reassemble');
  const flowId = randomUUID().slice(0, 12);
  const meta: FlowMeta = {
    url: `ble-dfu://${name}`,
    method: 'DFU',
    contentType: 'application/octet-stream',
    contentLength: blob.length,
    tls: null,
  };
  const score = scoreFirmwareFlow(meta, blob);
  const bodyPath = path.join(CAPTURE_DIR, sessionId, 'bodies', `${flowId}.bin`);
  fs.mkdirSync(path.dirname(bodyPath), { recursive: true });
  fs.writeFileSync(bodyPath, blob);
  upsertCaptureFlow({
    id: flowId,
    sessionId,
    host: null,
    url: meta.url,
    method: 'DFU',
    contentType: meta.contentType,
    size: blob.length,
    tlsPosture: null,
    firmwareScore: score.score,
    carved: 1, // a DFU image IS firmware — always ingestable
    bodyPath,
    createdAt: Date.now(),
  });
  return { flowId, size: blob.length, firmwareScore: score.score, carved: true };
}
