/**
 * Conservative MediaTek LK legacy header subset, derived from U-Boot's public host image generator at
 * 5508406582f6f7120dce0c4b3059819a41788db2. This is a container boundary, never device attribution or bootability.
 * The 512-byte header has no checksum: complete declared bytes establish consistency only, not integrity or
 * authenticity. Other LK layouts and the separate BootROM/NAND/MT7621 formats are deliberately unsupported.
 */
export type MediaTekLkHeaderResult =
  | { valid: false; reason: string }
  | {
      valid: true;
      name: string;
      payloadSize: number;
      totalSize: number;
      loadAddress: number;
      mode: number;
    };

/**
 * Parse one header at a buffer-relative offset without modifying or reading outside the Uint8Array view.
 * Accept the generator's NUL-padded names (including empty/non-ASCII), erased reserved area, and nonzero
 * mode required by its source comment. Payload size excludes the header; zero is emitted by mkimage -s.
 * Extra bytes after the declared payload may belong to another embedded image and are not constrained.
 */
export function parseMediaTekLkHeader(buf: Uint8Array, offset = 0): MediaTekLkHeaderResult {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > buf.length) {
    return { valid: false, reason: 'LK header offset is outside this buffer' };
  }
  const remaining = buf.length - offset;
  if (remaining < 512) return { valid: false, reason: 'the complete 512-byte LK header is unavailable' };
  const view = new DataView(buf.buffer, buf.byteOffset + offset, 512);
  if (view.getUint32(0, true) !== 0x58881688) {
    return { valid: false, reason: 'little-endian LK_PART_MAGIC is absent' };
  }
  const payloadSize = view.getUint32(4, true);
  // Subtraction preserves the full unsigned size: do not wrap 512 + size through a 32-bit bitwise operation.
  if (payloadSize > remaining - 512) {
    return { valid: false, reason: `declared ${payloadSize}-byte LK payload exceeds the remaining bytes` };
  }
  const loadAddress = view.getUint32(40, true);
  if (loadAddress === 0) return { valid: false, reason: 'supported LK generator requires a nonzero load address' };
  const mode = view.getUint32(44, true);
  if (mode === 0) return { valid: false, reason: 'LK mode must be nonzero in the supported legacy subset' };
  let nameEnd = 8;
  while (nameEnd < 40 && view.getUint8(nameEnd) !== 0) nameEnd++;
  // snprintf into the generator's 32-byte lk_name actually permits 31 bytes, despite README's "32".
  if (nameEnd === 40) return { valid: false, reason: 'supported LK name requires a NUL within its 32 bytes' };
  for (let at = nameEnd; at < 40; at++) {
    if (view.getUint8(at) !== 0) return { valid: false, reason: 'LK name has nonzero bytes after its NUL' };
  }
  for (let at = 48; at < 512; at++) {
    if (view.getUint8(at) !== 0xff) {
      return { valid: false, reason: `LK reserved byte ${at} is not erased (unsupported header variant)` };
    }
  }
  return {
    valid: true,
    name: new TextDecoder('utf-8', { ignoreBOM: true }).decode(buf.subarray(offset + 8, offset + nameEnd)),
    payloadSize,
    totalSize: 512 + payloadSize,
    loadAddress,
    mode,
  };
}
