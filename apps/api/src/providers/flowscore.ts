/**
 * Firmware-flow scoring (Phase 6.1, design §7). The FirmLab value-add over a generic proxy: it RECOGNIZES firmware
 * in an intercepted HTTP(S) stream. Each response is scored 0..100 for "is this an OTA blob?" from signals FirmLab
 * already computes elsewhere — `@firmlab/core` magic signatures on the body (squashfs/uImage/DTB/UBI/…), Shannon
 * entropy (encrypted/compressed OTA runs hot), the Content-Type, the Content-Length, and URL heuristics
 * (/ota, /firmware, /upgrade, .bin/.pkg/.img). Pure + unit-tested; the proxy runner calls this on each saved body.
 *
 * Honest: the score is a *lead*, not a verdict — a high score means "worth carving + ingesting", and the ingested
 * blob then flows through the normal analysis proof-states. A low score is never proof it isn't firmware.
 */
import { computeEntropyProfile, scanSignatures, windowEntropy } from '@firmlab/core';

export type TlsPosture = 'plaintext' | 'tls-unpinned' | 'tls-pinned' | null;

export interface FlowMeta {
  url: string;
  method: string;
  contentType: string | null;
  contentLength: number;
  tls: TlsPosture;
}

export interface FlowScore {
  score: number;
  isFirmwareCandidate: boolean;
  reasons: string[];
  signatureIds: string[];
  entropy: number;
}

/** Categories whose magic at the head of a body is a strong firmware signal, with per-category weight. */
const CATEGORY_WEIGHT: Record<string, number> = {
  filesystem: 40,
  bootloader: 40,
  kernel: 38,
  container: 30,
  compression: 25,
  executable: 15,
  image: 12,
};

/** A path/filename that looks like a firmware download. */
const FIRMWARE_URL =
  /(?:\/ota\b|\/firmware\b|\/upgrade\b|\/fw\b|\/update\b|\.bin\b|\.pkg\b|\.img\b|\.trx\b|\.chk\b|\.dav\b|\.hex\b|\.dlf\b)/i;

/** Content types that are clearly NOT a firmware blob — a strong negative. */
const NON_FIRMWARE_CT =
  /^(?:text\/|application\/json|application\/javascript|application\/xml|image\/|video\/|audio\/|font\/)/i;

/** The score at or above which a flow is worth carving + offering for ingest. */
export const FIRMWARE_THRESHOLD = 50;

/** Pure: does the URL path/filename look like a firmware download? */
export function urlLooksFirmware(url: string): boolean {
  return FIRMWARE_URL.test(url);
}

/**
 * Pure: score a flow 0..100 for carrying an OTA firmware blob. Combines a magic-signature hit near the head of the
 * body, entropy classification, the Content-Type, the size, and URL heuristics. Never throws on odd input.
 */
export function scoreFirmwareFlow(meta: FlowMeta, body: Uint8Array): FlowScore {
  const reasons: string[] = [];
  let score = 0;

  // 1. Magic signatures near the head of the body — the strongest positive.
  const hits = scanSignatures(body, { maxHits: 64 });
  const headHits = hits.filter((h) => h.offset < 4096 && h.confidence !== 'low');
  const signatureIds = [...new Set(headHits.map((h) => h.id))];
  let best = 0;
  for (const h of headHits) {
    const w = (CATEGORY_WEIGHT[h.category] ?? 0) * (h.offset === 0 ? 1 : 0.7);
    if (w > best) best = w;
  }
  if (best > 0) {
    score += best;
    reasons.push(`firmware magic near offset 0 (${signatureIds.join(', ')})`);
  }

  // 2. Entropy — encrypted/compressed OTA images run hot; a plausible size gate avoids scoring tiny hot blobs.
  const entropy = body.length > 0 ? windowEntropy(body, 0, body.length) : 0;
  if (body.length >= 4096) {
    const profile = computeEntropyProfile(body);
    if (profile.likelyEncrypted) {
      score += 25;
      reasons.push(`high entropy ${entropy.toFixed(2)} — likely encrypted (an at-rest-encrypted OTA still ingests)`);
    } else if (profile.likelyCompressed) {
      score += 15;
      reasons.push(`high entropy ${entropy.toFixed(2)} — likely compressed`);
    }
  }

  // 3. Content-Type. Octet-stream / generic binary is a mild positive; text/json/media is a strong negative.
  const ct = (meta.contentType ?? '').toLowerCase();
  if (NON_FIRMWARE_CT.test(ct)) {
    score -= 40;
    reasons.push(`content-type ${ct} is not a firmware blob`);
  } else if (/octet-stream|application\/(?:x-|binary|mac|zip|gzip|x-tar)|^$/.test(ct) || ct === '') {
    score += 15;
    reasons.push(`binary content-type ${ct || '(none)'}`);
  }

  // 4. Size. Most OTA images are hundreds of KB to tens of MB.
  const size = meta.contentLength || body.length;
  if (size >= 1024 * 1024) {
    score += 20;
    reasons.push(`${(size / (1024 * 1024)).toFixed(1)} MB body`);
  } else if (size >= 256 * 1024) {
    score += 10;
    reasons.push(`${Math.round(size / 1024)} KB body`);
  } else if (size > 0 && size < 8 * 1024) {
    score -= 20;
    reasons.push('body too small to be a typical firmware image');
  }

  // 5. URL heuristics.
  if (urlLooksFirmware(meta.url)) {
    score += 20;
    reasons.push('URL path looks like a firmware download');
  }

  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  return {
    score: clamped,
    isFirmwareCandidate: clamped >= FIRMWARE_THRESHOLD,
    reasons,
    signatureIds,
    entropy,
  };
}
