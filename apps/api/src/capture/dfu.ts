/**
 * Pure BLE DFU reassembly (Phase 6.4) — kept in its own store-free module so the reassembly can be unit-tested
 * without pulling in the SQLite layer. A Nordic-style DFU sends the firmware as ordered writes to a DATA
 * characteristic; reassembly concatenates those payloads back into the image.
 */

/** Pure: reassemble a DFU image from the ordered DATA-characteristic write payloads. */
export function reassembleDfu(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

/**
 * Pure: best-effort read of a Nordic Legacy DFU init packet's declared image size (the last 4 bytes before the CRC
 * of the classic init packet are the firmware length, little-endian). Returns null when the input isn't a plausible
 * init packet — a sanity cross-check for the reassembled length, never a hard requirement.
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
