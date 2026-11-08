/**
 * Locally recomputed integrity for LISTED MediaTek generic BootROM hits, through an internal code capability.
 * Core supplies no crypto implementation. Actual bytes are reparsed before trusting bounds, even if a caller
 * supplies persisted tiers or metadata. A matching unkeyed digest covers GFH/payload only: the first 0x600
 * device/BRLYT bytes, the digest field itself and trailing bytes are outside it. No authenticity or boot proof.
 */
import { parseMediaTekBromHeader } from './mediatek-image.js';
import { TIER_SCORE } from './signatures.js';
import type { SignatureHit } from './types.js';

export const SIGNATURE_DIGEST_MAX_EXECUTIONS = 8;
export const SIGNATURE_DIGEST_MAX_BYTES = 64 * 1024 * 1024;

export interface SignatureDigestOptions {
  /** INTERNAL trusted code only, never HTTP/Settings/model data. Synchronous SHA-256; must not mutate input. */
  sha256?: (bytes: Uint8Array) => Uint8Array;
  /** Internal tests may lower these limits; no option can widen the hard ceilings. */
  maxExecutions?: number;
  maxBytes?: number;
}

/** New analyses record this; absence on an older persisted StaticAnalysis means not recorded, not complete. */
export interface SignatureDigestCoverage {
  scope: 'listed_mediatek_brom_hits';
  /** Presence of a code capability, not proof it completed successfully or returned a valid digest. */
  capability: 'provided' | 'unavailable';
  /** Supported rule ids in the supplied bounded listing, not all scanner matches or a corpus denominator. */
  listed: number;
  /** Listed candidates whose actual bytes and rule/media agreement passed revalidation. */
  planned: number;
  invalidCandidates: number;
  attempted: number;
  /** Only a valid 32-byte result counts as completed; a throw/malformed return does not. */
  completed: number;
  matched: number;
  mismatched: number;
  unavailable: number;
  skipped: number;
  skippedExecutionBudget: number;
  skippedByteBudget: number;
  bytesPlanned: number;
  /** Bytes passed to the primitive, including calls that threw; not a claim of actual hash work. */
  bytesSubmitted: number;
  bytesCompleted: number;
  maxExecutions: number;
  maxBytes: number;
  note: string;
}

export type MediaTekDigestCandidate =
  | { supported: false }
  | { supported: true; valid: false; reason: string }
  | {
      supported: true;
      valid: true;
      coveredStart: number;
      coveredEnd: number;
      digestStart: number;
      digestEnd: number;
      meta: Record<string, string | number>;
    };

function mediaForRule(id: string): 'nor' | 'emmc' | 'sdmmc' | undefined {
  switch (id) {
    case 'mediatek-brom-nor':
      return 'nor';
    case 'mediatek-brom-emmc':
      return 'emmc';
    case 'mediatek-brom-sdmmc':
      return 'sdmmc';
    default:
      return undefined;
  }
}

/** Pure decision: raw meta, previous tiers and provider flags never choose eligibility or byte ranges. */
export function planMediaTekDigest(buf: Uint8Array, hit: SignatureHit): MediaTekDigestCandidate {
  const media = mediaForRule(hit.id);
  if (!media) return { supported: false };
  const parsed = parseMediaTekBromHeader(buf, hit.offset);
  if (!parsed.valid) return { supported: true, valid: false, reason: parsed.reason };
  if (media !== parsed.declaredMedia) {
    return { supported: true, valid: false, reason: 'rule id does not agree with the actual declared media' };
  }
  return {
    supported: true,
    valid: true,
    coveredStart: hit.offset + parsed.digest.coveredStart,
    coveredEnd: hit.offset + parsed.digest.coveredEnd,
    digestStart: hit.offset + parsed.digest.offset,
    digestEnd: hit.offset + parsed.totalSize,
    // Reconstruct only known fields; do not forward arbitrary/raw hash metadata from a caller or old JSON.
    meta: {
      size: parsed.totalSize,
      payloadSize: parsed.payloadSize,
      declaredMedia: parsed.declaredMedia,
      loadAddr: parsed.loadAddress,
      digestOffset: parsed.digest.offset,
      digestCoveredStart: hit.offset + parsed.digest.coveredStart,
      digestCoveredEnd: hit.offset + parsed.digest.coveredEnd,
      digestUnhashedHeaderStart: hit.offset,
      digestUnhashedHeaderEnd: hit.offset + 0x600,
    },
  };
}

function lowerLimit(value: number | undefined, ceiling: number): number {
  if (value === undefined || value === Number.POSITIVE_INFINITY) return ceiling;
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(ceiling, Math.floor(value)));
}

const LIMITS =
  'Only GFH/payload are hash-covered; first 0x600 device/BRLYT bytes, digest field and trailing bytes are unhashed. ' +
  'No authenticity, device, boot, execution or whole-image clean proof.';

/**
 * Keep rows/counts/order/confidence intact; return updated copies of supported hits and separate coverage.
 * Deterministic scheduling is offset then rule id in code-unit order, independent of input listing order.
 * A byte-budget skip does not prevent a later small candidate. Nothing here performs I/O or selects algorithms.
 */
export function verifySignatureDigests(
  buf: Uint8Array,
  hits: SignatureHit[],
  options: SignatureDigestOptions = {},
): { hits: SignatureHit[]; coverage: SignatureDigestCoverage } {
  const coverage: SignatureDigestCoverage = {
    scope: 'listed_mediatek_brom_hits',
    capability: typeof options.sha256 === 'function' ? 'provided' : 'unavailable',
    listed: 0,
    planned: 0,
    invalidCandidates: 0,
    attempted: 0,
    completed: 0,
    matched: 0,
    mismatched: 0,
    unavailable: 0,
    skipped: 0,
    skippedExecutionBudget: 0,
    skippedByteBudget: 0,
    bytesPlanned: 0,
    bytesSubmitted: 0,
    bytesCompleted: 0,
    maxExecutions: lowerLimit(options.maxExecutions, SIGNATURE_DIGEST_MAX_EXECUTIONS),
    maxBytes: lowerLimit(options.maxBytes, SIGNATURE_DIGEST_MAX_BYTES),
    note: `Only listed supported hits are considered; scanner listing caps may omit matches. Zero candidates or zero mismatches is not whole-image clean. ${LIMITS}`,
  };
  const out = [...hits];
  const scheduled = hits
    .map((hit, index) => ({ hit, index }))
    .filter(({ hit }) => mediaForRule(hit.id) !== undefined)
    .sort((a, b) => a.hit.offset - b.hit.offset || (a.hit.id < b.hit.id ? -1 : a.hit.id > b.hit.id ? 1 : 0));

  for (const { hit, index } of scheduled) {
    coverage.listed++;
    const candidate = planMediaTekDigest(buf, hit);
    if (!candidate.supported) continue;
    if (!candidate.valid) {
      coverage.invalidCandidates++;
      out[index] = {
        ...hit,
        tier: 'magic',
        score: TIER_SCORE.magic,
        meta: { digest: 'invalid_candidate' },
        rationale: `Digest not verified: actual-byte revalidation failed (${candidate.reason}). ${LIMITS}`,
      };
      continue;
    }
    coverage.planned++;
    const size = candidate.coveredEnd - candidate.coveredStart;
    coverage.bytesPlanned += size;
    let status: 'verified' | 'mismatch' | 'unavailable' | 'skipped_budget';
    let reason: string;
    if (typeof options.sha256 !== 'function') {
      coverage.unavailable++;
      status = 'unavailable';
      reason = 'sha256_capability_missing';
    } else if (coverage.attempted >= coverage.maxExecutions) {
      coverage.skipped++;
      coverage.skippedExecutionBudget++;
      status = 'skipped_budget';
      reason = 'execution_budget';
    } else if (size > coverage.maxBytes - coverage.bytesSubmitted) {
      coverage.skipped++;
      coverage.skippedByteBudget++;
      status = 'skipped_budget';
      reason = 'byte_budget';
    } else {
      // Protect the source even from an accidentally mutating internal capability. Buffer.slice is a view,
      // so use Uint8Array.from explicitly. The trusted capability contract still forbids mutation.
      const submitted = Uint8Array.from(buf.subarray(candidate.coveredStart, candidate.coveredEnd));
      coverage.attempted++;
      coverage.bytesSubmitted += size;
      try {
        const digest = options.sha256(submitted);
        if (
          !(digest instanceof Uint8Array) ||
          !ArrayBuffer.isView(digest) ||
          digest.byteLength !== 32 ||
          digest.length !== 32
        ) {
          coverage.unavailable++;
          status = 'unavailable';
          reason = 'sha256_result_malformed';
        } else {
          let matches = true;
          for (let i = 0; i < 32; i++) {
            if (digest[i] !== buf[candidate.digestStart + i]) matches = false;
          }
          coverage.completed++;
          coverage.bytesCompleted += size;
          if (matches) coverage.matched++;
          else coverage.mismatched++;
          status = matches ? 'verified' : 'mismatch';
          reason = matches ? 'covered_bytes_match' : 'covered_bytes_mismatch';
        }
      } catch {
        coverage.unavailable++;
        status = 'unavailable';
        reason = 'sha256_capability_threw';
      }
    }
    const tier = status === 'verified' ? 'verified' : 'consistent';
    out[index] = {
      ...hit,
      tier,
      score: TIER_SCORE[tier],
      meta: { ...candidate.meta, digest: status, digestReason: reason },
      rationale:
        `Structurally consistent envelope; SHA-256 ${status} (${reason}) over ` +
        `[${candidate.coveredStart}, ${candidate.coveredEnd}). ${LIMITS}`,
    };
  }
  return { hits: out, coverage };
}
