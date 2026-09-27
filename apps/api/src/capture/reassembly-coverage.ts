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
export function findMissingSequences(sequences: number[]): number[] {
  if (!sequences || sequences.length === 0) return [];
  const set = new Set(sequences);
  const max = Math.max(...sequences);
  const missing: number[] = [];
  for (let i = 0; i <= max; i++) {
    if (!set.has(i)) {
      missing.push(i);
      if (missing.length >= 100) break;
    }
  }
  return missing;
}

/**
 * Pure: assess reassembly completeness for a Nordic BLE DFU DATA stream.
 * Size is compared against the declared length in the init packet ONLY if the init packet
 * can be structurally parsed (e.g. legacy init packet uint32 trailer).
 * If the init packet is missing or unparseable, expected size is unknown — NEVER guessed.
 */
export function assessBleCompleteness(
  receivedBytes: number,
  initPacket?: Uint8Array | null,
  chunkSeqs?: number[],
): ReassemblyCompleteness {
  const missingSeqs = chunkSeqs && chunkSeqs.length > 0 ? findMissingSequences(chunkSeqs) : [];
  const hasMissingSeqs = missingSeqs.length > 0;

  const expectedBytes = initPacket && initPacket.length >= 4 ? parseDfuInitSize(initPacket) : null;

  if (expectedBytes !== null && expectedBytes !== undefined) {
    if (receivedBytes < expectedBytes) {
      const missingBytes = expectedBytes - receivedBytes;
      const reason = hasMissingSeqs
        ? `Incomplete DFU stream: received ${receivedBytes} of declared ${expectedBytes} bytes (missing ${missingBytes} bytes), missing ${missingSeqs.length} chunk sequence(s)`
        : `Incomplete DFU stream: received ${receivedBytes} of declared ${expectedBytes} bytes (missing ${missingBytes} bytes)`;

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

    if (receivedBytes > expectedBytes) {
      const res: ReassemblyCompleteness = {
        status: 'incomplete',
        receivedBytes,
        expectedBytes,
        reason: `DFU stream length (${receivedBytes} bytes) exceeds declared size in init packet (${expectedBytes} bytes)`,
      };
      if (hasMissingSeqs) {
        res.missingSequences = missingSeqs;
        res.missing = { sequences: missingSeqs };
      }
      return res;
    }

    if (hasMissingSeqs) {
      return {
        status: 'incomplete',
        receivedBytes,
        expectedBytes,
        missingSequences: missingSeqs,
        missing: { sequences: missingSeqs },
        reason: `DFU stream has ${missingSeqs.length} missing chunk sequence(s)`,
      };
    }

    return {
      status: 'complete',
      receivedBytes,
      expectedBytes,
      reason: `BLE DFU reassembly complete: received ${receivedBytes} bytes matching declared size in init packet`,
    };
  }

  // Init packet not provided or could not be parsed structurally
  if (hasMissingSeqs) {
    return {
      status: 'incomplete',
      receivedBytes,
      missingSequences: missingSeqs,
      missing: { sequences: missingSeqs },
      reason: `Incomplete DFU stream: missing ${missingSeqs.length} chunk sequence(s) (expected size unknown without valid init packet)`,
    };
  }

  return {
    status: 'unknown',
    receivedBytes,
    reason: 'Expected size unknown — no init packet provided or format cannot be parsed structurally',
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
