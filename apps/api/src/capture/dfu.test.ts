import { describe, expect, it } from 'vitest';
import { parseDfuInitSize, reassembleDfu } from './dfu.js';

describe('reassembleDfu', () => {
  it('concatenates the DATA-characteristic writes back into the image, in order', () => {
    const chunks = [Uint8Array.from([0x68, 0x73, 0x71, 0x73]), Uint8Array.from([1, 2, 3]), Uint8Array.from([4, 5])];
    const out = reassembleDfu(chunks);
    expect(Array.from(out)).toEqual([0x68, 0x73, 0x71, 0x73, 1, 2, 3, 4, 5]);
  });
  it('reassembles a chunked blob byte-for-byte (20-byte MTU writes)', () => {
    const src = Uint8Array.from({ length: 250 }, (_, i) => i & 0xff);
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < src.length; i += 20) chunks.push(src.subarray(i, i + 20));
    expect(Array.from(reassembleDfu(chunks))).toEqual(Array.from(src));
  });
  it('returns an empty image for no writes', () => {
    expect(reassembleDfu([]).length).toBe(0);
  });
});

describe('parseDfuInitSize', () => {
  it('reads the little-endian image-size trailer as a sanity cross-check', () => {
    // Trailer 0x0000C000 (49152) little-endian.
    const init = Uint8Array.from([0xde, 0xad, 0x00, 0xc0, 0x00, 0x00]);
    expect(parseDfuInitSize(init)).toBe(0xc000);
  });
  it('returns null for an implausible / too-short packet', () => {
    expect(parseDfuInitSize(Uint8Array.from([1, 2]))).toBeNull();
    expect(parseDfuInitSize(Uint8Array.from([0, 0, 0, 0]))).toBeNull(); // zero size
  });
});
