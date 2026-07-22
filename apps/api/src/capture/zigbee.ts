/**
 * Zigbee backend — OTA Upgrade cluster capture (Phase 6.5, design §8). A Zigbee OTA (cluster 0x0019) is sniffed
 * (CC2531 / ConBee) as a series of Image-Block-Response payloads; the FirmLab value-add is REASSEMBLING those into
 * the standardized OTA file and UNWRAPPING it to the firmware image the device flashes, which then ingests through
 * the exact same path as any other capture (a carved `zigbee-ota` flow → a workbench image + provenance).
 *
 * The parse/reassembly is PURE (see `zigbee-ota.ts`) and unit-tested; it operates on a NORMALIZED block stream —
 * the sniffer/agent turns its radio capture into the ordered Image-Block payloads first (the radio-specific decode
 * where a live sniffer plugs in). Reassembling a *provided* capture needs no dongle (so it validates anywhere); the
 * live over-the-air sniff needs the Zigbee radio and is deploy-validated. A valid OTA transfer is firmware by
 * construction, so a successfully-unwrapped image is always carved; a stream that isn't a Zigbee OTA file is
 * rejected honestly (never a fabricated image).
 */
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { CAPTURE_DIR } from '../paths.js';
import { type FlowMeta, scoreFirmwareFlow } from '../providers/flowscore.js';
import { getCaptureSession, insertCaptureSession, upsertCaptureFlow } from '../store.js';
import { extractOtaImage, parseZigbeeOtaHeader, reassembleOtaBlocks } from './zigbee-ota.js';

/** Create a capture session for a Zigbee OTA. NOT dongle-gated — reassembling a provided capture needs no radio. */
export function createZigbeeSession(deviceId: string | null): string {
  const id = randomUUID().slice(0, 12);
  const now = Date.now();
  fs.mkdirSync(path.join(CAPTURE_DIR, id, 'bodies'), { recursive: true });
  insertCaptureSession({
    id,
    status: 'watching',
    subnet: null,
    targetDeviceId: deviceId,
    strategyJson: JSON.stringify({ transport: 'zigbee-ota' }),
    transcript: `[armed] Zigbee OTA capture session for ${deviceId ?? 'a target'}\n`,
    deviceCount: 0,
    error: null,
    createdAt: now,
    updatedAt: now,
  });
  return id;
}

export interface ZigbeeStageResult {
  flowId: string;
  size: number;
  manufacturerCode: number;
  imageType: number;
  fileVersion: number;
  firmwareScore: number;
  carved: boolean;
}

/**
 * Reassemble captured OTA Image-Block payloads, unwrap the standard container to the firmware image, and stage it
 * as a carved `zigbee-ota` flow (ingestable by the normal path). Throws honestly when the stream isn't a valid
 * Zigbee OTA file (no 0x0BEEF11E header / no upgrade-image sub-element) — never a fabricated blob.
 */
export function stageZigbeeOta(sessionId: string, name: string, blocks: Uint8Array[]): ZigbeeStageResult {
  if (!getCaptureSession(sessionId)) throw new Error('Unknown capture session');
  const file = reassembleOtaBlocks(blocks);
  const header = parseZigbeeOtaHeader(file);
  if (!header) throw new Error('Not a Zigbee OTA file — missing the 0x0BEEF11E OTA header');
  const image = extractOtaImage(file);
  if (!image || image.length === 0) throw new Error('OTA file carries no upgrade-image (tag 0x0000) sub-element');

  const flowId = randomUUID().slice(0, 12);
  const label = header.headerString || name;
  const meta: FlowMeta = {
    url: `zigbee-ota://${label}?fileVersion=${header.fileVersion}`,
    method: 'OTA',
    contentType: 'application/octet-stream',
    contentLength: image.length,
    tls: null,
  };
  const score = scoreFirmwareFlow(meta, image);
  const bodyPath = path.join(CAPTURE_DIR, sessionId, 'bodies', `${flowId}.bin`);
  fs.mkdirSync(path.dirname(bodyPath), { recursive: true });
  fs.writeFileSync(bodyPath, image);
  upsertCaptureFlow({
    id: flowId,
    sessionId,
    host: null,
    url: meta.url,
    method: 'OTA',
    contentType: meta.contentType,
    size: image.length,
    tlsPosture: null,
    firmwareScore: score.score,
    carved: 1, // a valid unwrapped OTA image IS firmware — always ingestable
    bodyPath,
    createdAt: Date.now(),
  });
  return {
    flowId,
    size: image.length,
    manufacturerCode: header.manufacturerCode,
    imageType: header.imageType,
    fileVersion: header.fileVersion,
    firmwareScore: score.score,
    carved: true,
  };
}
