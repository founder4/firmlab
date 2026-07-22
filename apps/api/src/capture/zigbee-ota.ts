/**
 * Pure Zigbee OTA parsing (Phase 6.5) — kept store-free so it can be unit-tested. A Zigbee OTA Upgrade (cluster
 * 0x0019) transfers a file with a STANDARDIZED header (magic 0x0BEEF11E) wrapping the firmware as a tag-0x0000
 * sub-element. The FirmLab value-add over a raw sniff: reassemble the Image-Block payloads into the OTA file, then
 * UNWRAP the standard container to the actual firmware image the device flashes. The standardized header is what
 * makes this reliable (design §8). Everything here is pure + honest — a stream that isn't a valid OTA file → null.
 */

/** The Zigbee OTA file identifier (little-endian uint32 at offset 0). */
export const ZIGBEE_OTA_MAGIC = 0x0beef11e;

export interface ZigbeeOtaHeader {
  manufacturerCode: number;
  imageType: number;
  fileVersion: number;
  /** The 32-byte OTA header string (human label), NUL-trimmed. */
  headerString: string;
  /** Declared total file size (header + all sub-elements). */
  totalImageSize: number;
  /** Where the sub-elements begin (== the header length field). */
  headerLength: number;
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

/** Pure: reassemble the OTA file from the ordered Image-Block-Response data payloads (concatenate). */
export function reassembleOtaBlocks(blocks: Uint8Array[]): Uint8Array {
  const total = blocks.reduce((n, b) => n + b.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const b of blocks) {
    out.set(b, o);
    o += b.length;
  }
  return out;
}

/**
 * Pure: parse the standardized Zigbee OTA header. The base header is 56 bytes (0x0BEEF11E magic, version, header
 * length, field control, manufacturer, image type, file version, stack version, 32-byte string, total size).
 * Returns null when the bytes aren't a valid OTA file (honest — not a Zigbee OTA transfer).
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
 * Pure: unwrap the OTA container to the actual firmware image — the tag-0x0000 "upgrade image" sub-element. Walks
 * the sub-element list (tag u16 + length u32 + data) starting at the header length. Returns null when the file
 * isn't a valid OTA file or carries no upgrade-image sub-element.
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
