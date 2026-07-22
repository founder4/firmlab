/**
 * Capture auto-ingest (Phase 6.1, design §10). A captured firmware blob is fed through the EXACT same intake the
 * Dashboard upload uses — `analyzeImageBuffer` → an `images` row → structure/secrets/corpus — so a carved blob
 * becomes a normal FirmLab image and the rest of the workbench already knows what to do with it. The one addition
 * is a `capture_provenance` record linking that image back to how it was acquired (device / session / endpoint /
 * transport / TLS posture). Capturing and analyzing become one continuous motion.
 */
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { analyzeImageBuffer } from '../analysis.js';
import { flagKnownCredentials, recordCredentials } from '../corpus.js';
import { normalizeSecrets, syncFindings } from '../findings.js';
import { IMAGES_DIR } from '../paths.js';
import { insertCaptureProvenance, insertImage, updateImageAnalysis } from '../store.js';

export interface CaptureProvenanceInput {
  deviceId?: string | null;
  sessionId?: string | null;
  /** The endpoint/URL (or host) the blob was carved from. */
  endpoint?: string | null;
  version?: string | null;
  /** 'http' | 'https' | 'ble-gatt' | … */
  transport?: string | null;
  /** 'plaintext' | 'tls-unpinned' | 'tls-pinned' | null. */
  tlsPosture?: string | null;
}

export interface IngestResult {
  imageId: string;
  filename: string;
  size: number;
  sha256: string;
}

/**
 * Ingest a captured blob as a workbench image + its provenance. Mirrors the POST /images upload path verbatim
 * (id → disk → hash → insert → analyze → seed findings/corpus), then records where it came from. Synchronous, like
 * the upload handler. Analysis failure is non-fatal (the image lands in `error` state), exactly as on upload.
 */
export function ingestCapturedBlob(buf: Buffer, filename: string, prov: CaptureProvenanceInput): IngestResult {
  const safeName = path.basename(filename || 'capture.bin').replace(/[^a-zA-Z0-9._-]+/g, '_') || 'capture.bin';
  const id = randomUUID().slice(0, 8); // images use 8-char ids (the upload convention)
  const dir = path.join(IMAGES_DIR, id);
  fs.mkdirSync(dir, { recursive: true });
  const dest = path.join(dir, safeName);
  fs.writeFileSync(dest, buf);

  const sha256 = createHash('sha256').update(buf).digest('hex');
  const now = Date.now();
  insertImage({
    id,
    filename: safeName,
    path: dest,
    size: buf.length,
    sha256,
    uploadedAt: now,
    status: 'analyzing',
    identityJson: null,
    analysisJson: null,
    tags: null,
  });

  try {
    const analysis = analyzeImageBuffer(buf);
    updateImageAnalysis(id, 'ready', JSON.stringify(analysis.identity), JSON.stringify(analysis));
    syncFindings(id, 'secrets', normalizeSecrets(analysis.secrets));
    recordCredentials(
      id,
      analysis.secrets
        .filter((s) => s.secretKind)
        .map((s) => ({ value: s.value, kind: s.secretKind ?? null, severity: s.severity ?? null })),
    );
    flagKnownCredentials(id);
  } catch {
    updateImageAnalysis(id, 'error', null, null);
  }

  insertCaptureProvenance({
    id: randomUUID().slice(0, 12),
    imageId: id,
    deviceId: prov.deviceId ?? null,
    sessionId: prov.sessionId ?? null,
    endpoint: prov.endpoint ?? null,
    version: prov.version ?? null,
    transport: prov.transport ?? null,
    tlsPosture: prov.tlsPosture ?? null,
    capturedAt: now,
  });

  return { imageId: id, filename: safeName, size: buf.length, sha256 };
}
