/**
 * Pure wireless capture reassembly coverage and completeness verification (Phase 6.4/6.5).
 * Store-free: calculates whether a reassembled stream is complete, incomplete (with missing bytes/blocks),
 * or unknown based strictly on received payloads and structural headers.
 */
import { parseDfuInitSize } from './dfu.js';
import type { ZigbeeOtaHeader } from './zigbee-ota.js';

export type CompletenessStatus = 'complete' | 'incomplete' | 'unknown';

export interface MissingGaps {
  sequences?: number[];
  bytes?: number;
}

export interface ReassemblyCompleteness {
  status: CompletenessStatus;
  receivedBytes: number;
  expectedBytes?: number;
  missingBytes?: number;
  missingSequences?: number[];
  missing?: MissingGaps;
  reason: string;
}

/**
 * Pure: find missing sequence numbers in an ordered or unordered list of block/chunk indices.
 * Assumes a 0-indexed sequence. Bounded to at most 100 missing items to avoid unbounded memory/payloads.
 */
/** The most missing sequence numbers listed; a longer gap list is cut here and the reason says so. */
export const MISSING_SEQUENCE_CAP = 100;

export function findMissingSequences(sequences: number[]): number[] {
  if (!sequences || sequences.length === 0) return [];
  const set = new Set(sequences);
  // A loop, not Math.max(...sequences): spreading a large operator-supplied array overflows the call stack.
  let max = -1;
  for (const n of sequences) if (n > max) max = n;
  const missing: number[] = [];
  for (let i = 0; i <= max; i++) {
    if (!set.has(i)) {
      missing.push(i);
      if (missing.length >= MISSING_SEQUENCE_CAP) break;
    }
  }
  return missing;
}

/**
 * Pure: assess reassembly completeness for a Nordic BLE DFU DATA stream.
 *
 * Only a gap in the chunk sequence is evidence that bytes are missing, so only it yields `incomplete`. The init
 * packet's size is read by `parseDfuInitSize`, which is a best-effort trailer read (its own contract: "never a hard
 * requirement") — it cannot tell a legacy init packet from a newer one. So it may CORROBORATE a stream (an exact
 * byte match is `complete`), but a mismatch is `unknown` with both numbers stated, never `incomplete`: a heuristic
 * that disagrees must not block ingestion of a stream that may be whole.
 */
export function assessBleCompleteness(
  receivedBytes: number,
  initPacket?: Uint8Array | null,
  chunkSeqs?: number[],
): ReassemblyCompleteness {
  const missingSeqs = chunkSeqs && chunkSeqs.length > 0 ? findMissingSequences(chunkSeqs) : [];
  const hint = initPacket && initPacket.length >= 4 ? parseDfuInitSize(initPacket) : null;
  const hintNote =
    hint === null ? '' : ` The init packet's best-effort size read gives ${hint} bytes; received ${receivedBytes}.`;

  if (missingSeqs.length > 0) {
    const capped = missingSeqs.length >= MISSING_SEQUENCE_CAP ? ` (listing capped at ${MISSING_SEQUENCE_CAP})` : '';
    return {
      status: 'incomplete',
      receivedBytes,
      ...(hint === null ? {} : { expectedBytes: hint }),
      missingSequences: missingSeqs,
      missing: { sequences: missingSeqs },
      reason: `DFU stream is missing ${missingSeqs.length} chunk sequence(s)${capped}.${hintNote}`,
    };
  }
  if (hint !== null && hint === receivedBytes) {
    return {
      status: 'complete',
      receivedBytes,
      expectedBytes: hint,
      reason: `No chunk sequence is missing and the ${receivedBytes} bytes received match the size the init packet declares.`,
    };
  }
  return {
    status: 'unknown',
    receivedBytes,
    ...(hint === null ? {} : { expectedBytes: hint }),
    reason:
      (chunkSeqs && chunkSeqs.length > 0
        ? 'No chunk sequence is missing, but'
        : 'No chunk sequence numbers were supplied, and') +
      (hint === null
        ? ' no readable init packet declares the expected size, so completeness cannot be established.'
        : ` the init packet's size is a best-effort read that does not match, so completeness cannot be established.${hintNote}`),
  };
}

/**
 * Pure: assess reassembly completeness for a Zigbee OTA stream (cluster 0x0019).
 * Checks truncation against totalImageSize in the standardized 0x0BEEF11E header,
 * presence of the tag-0x0000 upgrade-image sub-element, and any gaps in block sequence numbers.
 */
export function assessZigbeeCompleteness(
  receivedBytes: number,
  header: ZigbeeOtaHeader | null,
  hasCompleteUpgradeImage: boolean,
  blockSeqs?: number[],
): ReassemblyCompleteness {
  const missingSeqs = blockSeqs && blockSeqs.length > 0 ? findMissingSequences(blockSeqs) : [];
  const hasMissingSeqs = missingSeqs.length > 0;

  if (!header) {
    if (receivedBytes < 56) {
      return {
        status: 'incomplete',
        receivedBytes,
        reason: 'Truncated stream: shorter than minimum 56-byte Zigbee OTA header',
      };
    }
    return {
      status: 'unknown',
      receivedBytes,
      reason: 'Missing Zigbee OTA header (0x0BEEF11E) — cannot determine declared image size',
    };
  }

  const expectedBytes = header.totalImageSize;

  if (receivedBytes < expectedBytes) {
    const missingBytes = expectedBytes - receivedBytes;
    const reason = hasMissingSeqs
      ? `Truncated OTA file: received ${receivedBytes} of declared ${expectedBytes} bytes (missing ${missingBytes} bytes), missing ${missingSeqs.length} block sequence(s)`
      : `Truncated OTA file: received ${receivedBytes} of declared ${expectedBytes} bytes (missing ${missingBytes} bytes)`;

    const res: ReassemblyCompleteness = {
      status: 'incomplete',
      receivedBytes,
      expectedBytes,
      missingBytes,
      reason,
    };
    const missing: MissingGaps = { bytes: missingBytes };
    if (hasMissingSeqs) {
      res.missingSequences = missingSeqs;
      missing.sequences = missingSeqs;
    }
    res.missing = missing;
    return res;
  }

  if (hasMissingSeqs) {
    return {
      status: 'incomplete',
      receivedBytes,
      expectedBytes,
      missingSequences: missingSeqs,
      missing: { sequences: missingSeqs },
      reason: `Missing ${missingSeqs.length} block sequence(s)`,
    };
  }

  if (!hasCompleteUpgradeImage) {
    return {
      status: 'incomplete',
      receivedBytes,
      expectedBytes,
      reason: 'OTA file carries no complete upgrade-image (tag 0x0000) sub-element',
    };
  }

  return {
    status: 'complete',
    receivedBytes,
    expectedBytes,
    reason: 'Zigbee OTA stream is complete and verified against header totalImageSize',
  };
}
