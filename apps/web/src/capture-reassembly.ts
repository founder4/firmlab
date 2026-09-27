/**
 * Pure wireless capture reassembly and validation utilities.
 * Handles Nordic BLE DFU DATA characteristic chunks and Zigbee OTA (cluster 0x0019) Image-Blocks.
 */

export const ZIGBEE_OTA_MAGIC = 0x0beef11e;

export interface ZigbeeOtaHeader {
  manufacturerCode: number;
  imageType: number;
  fileVersion: number;
  headerString: string;
  totalImageSize: number;
  headerLength: number;
}

export function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  const CHUNK_SIZE = 0x8000;
  for (let i = 0; i < len; i += CHUNK_SIZE) {
    const sub = bytes.subarray(i, Math.min(i + CHUNK_SIZE, len));
    binary += String.fromCharCode(...sub);
  }
  return btoa(binary);
}

export function base64ToUint8(b64: string): Uint8Array {
  const binary = atob(b64.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function hexToUint8(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error('Invalid hex string length');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = Number.parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Pure: best-effort read of a Nordic Legacy DFU init packet's declared image size.
 * The last 4 bytes before the CRC of the classic init packet are the firmware length (uint32 little-endian).
 */
export function parseDfuInitSize(initPacket: Uint8Array): number | null {
  if (initPacket.length < 4) return null;
  const o = initPacket.length - 4;
  const size =
    ((initPacket[o] ?? 0) |
      ((initPacket[o + 1] ?? 0) << 8) |
      ((initPacket[o + 2] ?? 0) << 16) |
      ((initPacket[o + 3] ?? 0) << 24)) >>>
    0;
  return size > 0 && size < 0x4000000 ? size : null; // < 64 MB sanity
}

function u16(b: Uint8Array, o: number): number {
  return (b[o] ?? 0) | ((b[o + 1] ?? 0) << 8);
}

function u32(b: Uint8Array, o: number): number {
  return ((b[o] ?? 0) | ((b[o + 1] ?? 0) << 8) | ((b[o + 2] ?? 0) << 16) | ((b[o + 3] ?? 0) << 24)) >>> 0;
}

function decodeAscii(b: Uint8Array, off: number, max: number): string {
  let s = '';
  for (let i = 0; i < max; i++) {
    const c = b[off + i] ?? 0;
    if (c === 0) break;
    if (c >= 0x20 && c <= 0x7e) s += String.fromCharCode(c);
  }
  return s;
}

/**
 * Pure: parse standardized Zigbee OTA header (magic 0x0BEEF11E).
 */
export function parseZigbeeOtaHeader(buf: Uint8Array): ZigbeeOtaHeader | null {
  if (buf.length < 56 || u32(buf, 0) !== ZIGBEE_OTA_MAGIC) return null;
  const headerLength = u16(buf, 6);
  if (headerLength < 56 || headerLength > buf.length) return null;
  return {
    manufacturerCode: u16(buf, 10),
    imageType: u16(buf, 12),
    fileVersion: u32(buf, 14),
    headerString: decodeAscii(buf, 20, 32),
    totalImageSize: u32(buf, 52),
    headerLength,
  };
}

/**
 * Pure: unwrap the OTA container to the tag-0x0000 upgrade image.
 */
export function extractOtaImage(buf: Uint8Array): Uint8Array | null {
  const h = parseZigbeeOtaHeader(buf);
  if (!h) return null;
  let o = h.headerLength;
  while (o + 6 <= buf.length) {
    const tag = u16(buf, o);
    const len = u32(buf, o + 2);
    const dataStart = o + 6;
    if (dataStart + len > buf.length) break;
    if (tag === 0x0000) return buf.subarray(dataStart, dataStart + len);
    o = dataStart + len;
  }
  return null;
}

export function detectMissingSequences(seqs: number[]): number[] {
  if (seqs.length <= 1) return [];
  const sorted = Array.from(new Set(seqs)).sort((a, b) => a - b);
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  if (min === undefined || max === undefined) return [];
  const missing: number[] = [];
  const set = new Set(sorted);
  for (let i = min; i <= max; i++) {
    if (!set.has(i)) {
      missing.push(i);
    }
  }
  return missing;
}

export interface BleReassemblyInspection {
  reconstructedBytes: number;
  chunkCount: number;
  expectedSize: number | null;
  missingBytes: number;
  missingSeqs: number[];
  isComplete: boolean;
  integrityChecked: boolean;
  integrityValid: boolean;
  details: string[];
}

export function inspectBleReassembly(
  chunks: Uint8Array[],
  initPacket?: Uint8Array | null,
  declaredExpectedSize?: number | null,
  missingSeqs: number[] = [],
): BleReassemblyInspection {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const initSize = initPacket ? parseDfuInitSize(initPacket) : null;
  const expectedSize = declaredExpectedSize ?? initSize;

  let missingBytes = 0;
  if (expectedSize !== null && total < expectedSize) {
    missingBytes = expectedSize - total;
  }

  const details: string[] = [];
  const integrityChecked = initPacket !== null && initPacket !== undefined;
  const integrityValid = integrityChecked && initSize !== null && total === initSize;

  if (missingSeqs.length > 0) {
    details.push(`Missing chunk sequence(s): #${missingSeqs.join(', #')}`);
  }
  if (expectedSize !== null && missingBytes > 0) {
    details.push(`Missing ${missingBytes} bytes (${total} received of ${expectedSize} expected)`);
  }

  const isComplete = chunks.length > 0 && missingSeqs.length === 0 && (expectedSize === null || total >= expectedSize);

  return {
    reconstructedBytes: total,
    chunkCount: chunks.length,
    expectedSize,
    missingBytes,
    missingSeqs,
    isComplete,
    integrityChecked,
    integrityValid,
    details,
  };
}

export interface ZigbeeReassemblyInspection {
  reconstructedBytes: number;
  blockCount: number;
  header: ZigbeeOtaHeader | null;
  expectedTotalBytes: number | null;
  missingBytes: number;
  missingSeqs: number[];
  isComplete: boolean;
  integrityChecked: boolean;
  integrityValid: boolean;
  upgradeImageFound: boolean;
  upgradeImageBytes: number;
  details: string[];
}

export function inspectZigbeeReassembly(blocks: Uint8Array[], missingSeqs: number[] = []): ZigbeeReassemblyInspection {
  const total = blocks.reduce((n, b) => n + b.length, 0);
  const file = new Uint8Array(total);
  let o = 0;
  for (const b of blocks) {
    file.set(b, o);
    o += b.length;
  }

  const header = parseZigbeeOtaHeader(file);
  const details: string[] = [];

  if (missingSeqs.length > 0) {
    details.push(`Missing block sequence(s): #${missingSeqs.join(', #')}`);
  }

  let expectedTotalBytes: number | null = null;
  let missingBytes = 0;
  let upgradeImageFound = false;
  let upgradeImageBytes = 0;

  if (!header) {
    details.push('Missing or invalid 0x0BEEF11E Zigbee OTA header');
  } else {
    expectedTotalBytes = header.totalImageSize;
    if (total < header.totalImageSize) {
      missingBytes = header.totalImageSize - total;
      details.push(
        `Truncated file: received ${total} bytes of ${header.totalImageSize} declared OTA container bytes (${missingBytes} bytes missing)`,
      );
    }
    const img = extractOtaImage(file);
    if (img && img.length > 0) {
      upgradeImageFound = true;
      upgradeImageBytes = img.length;
    } else {
      details.push('No valid upgrade-image (tag 0x0000) sub-element found in OTA stream');
    }
  }

  const integrityChecked = header !== null;
  const integrityValid = header !== null && missingBytes === 0 && upgradeImageFound;
  const isComplete =
    blocks.length > 0 && header !== null && missingBytes === 0 && missingSeqs.length === 0 && upgradeImageFound;

  return {
    reconstructedBytes: total,
    blockCount: blocks.length,
    header,
    expectedTotalBytes,
    missingBytes,
    missingSeqs,
    isComplete,
    integrityChecked,
    integrityValid,
    upgradeImageFound,
    upgradeImageBytes,
    details,
  };
}

export interface ParsedCaptureInput {
  name?: string | undefined;
  chunksOrBlocks: Uint8Array[];
  base64Items: string[];
  initPacket?: Uint8Array | undefined;
  expectedSize?: number | undefined;
  missingSeqs: number[];
  error?: string | undefined;
}

/**
 * Pure: parse uploaded content (JSON, text lines of base64/hex, or binary) into standardized chunks/blocks.
 */
export function parseCapturePayload(content: string | Uint8Array, filename: string): ParsedCaptureInput {
  if (content instanceof Uint8Array) {
    const b64 = uint8ToBase64(content);
    return {
      name: filename,
      chunksOrBlocks: [content],
      base64Items: [b64],
      missingSeqs: [],
    };
  }

  const text = content.trim();
  if (!text) {
    return {
      chunksOrBlocks: [],
      base64Items: [],
      missingSeqs: [],
      error: 'Empty capture file',
    };
  }

  // Case 1: JSON
  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      const parsed = JSON.parse(text);
      const name =
        typeof parsed === 'object' && parsed !== null && 'name' in parsed && typeof parsed.name === 'string'
          ? parsed.name
          : filename.replace(/\.json$/i, '.bin');

      let rawItems: unknown[] = [];
      if (Array.isArray(parsed)) {
        rawItems = parsed;
      } else if (parsed && typeof parsed === 'object') {
        if (Array.isArray(parsed.chunks)) rawItems = parsed.chunks;
        else if (Array.isArray(parsed.blocks)) rawItems = parsed.blocks;
        else if (Array.isArray(parsed.data)) rawItems = parsed.data;
      }

      const seqs: number[] = [];
      const base64Items: string[] = [];
      const chunksOrBlocks: Uint8Array[] = [];

      for (let i = 0; i < rawItems.length; i++) {
        const item = rawItems[i];
        if (typeof item === 'string') {
          base64Items.push(item);
          chunksOrBlocks.push(base64ToUint8(item));
        } else if (item && typeof item === 'object') {
          const obj = item as Record<string, unknown>;
          if (typeof obj.seq === 'number') seqs.push(obj.seq);
          else if (typeof obj.index === 'number') seqs.push(obj.index);

          const payload = typeof obj.data === 'string' ? obj.data : typeof obj.chunk === 'string' ? obj.chunk : null;
          if (payload) {
            base64Items.push(payload);
            chunksOrBlocks.push(base64ToUint8(payload));
          }
        }
      }

      const missingSeqs = detectMissingSequences(seqs);
      let initPacket: Uint8Array | undefined;
      if (parsed && typeof parsed === 'object' && 'initPacket' in parsed && typeof parsed.initPacket === 'string') {
        initPacket = base64ToUint8(parsed.initPacket);
      }
      const expectedSize =
        parsed && typeof parsed === 'object' && 'expectedSize' in parsed && typeof parsed.expectedSize === 'number'
          ? parsed.expectedSize
          : undefined;

      return {
        name,
        chunksOrBlocks,
        base64Items,
        initPacket,
        expectedSize,
        missingSeqs,
      };
    } catch (e) {
      return {
        chunksOrBlocks: [],
        base64Items: [],
        missingSeqs: [],
        error: `Invalid JSON capture: ${e instanceof Error ? e.message : String(e)}`,
      };
    }
  }

  // Case 2: Line-delimited base64 or hex
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));
  const base64Items: string[] = [];
  const chunksOrBlocks: Uint8Array[] = [];

  for (const line of lines) {
    if (/^[0-9a-fA-F]+$/.test(line) && line.length % 2 === 0) {
      const u8 = hexToUint8(line);
      chunksOrBlocks.push(u8);
      base64Items.push(uint8ToBase64(u8));
    } else {
      try {
        const u8 = base64ToUint8(line);
        chunksOrBlocks.push(u8);
        base64Items.push(line);
      } catch {
        return {
          chunksOrBlocks: [],
          base64Items: [],
          missingSeqs: [],
          error: `Unrecognized line format: ${line.slice(0, 32)}…`,
        };
      }
    }
  }

  return {
    name: filename.replace(/\.(txt|log|hex)$/i, '.bin'),
    chunksOrBlocks,
    base64Items,
    missingSeqs: [],
  };
}
