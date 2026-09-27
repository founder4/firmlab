import { describe, expect, it } from 'vitest';
import { diagnoseSquashfs, parseLzmaHeader, parseSquashfsSuperblock } from '../src/extract-diagnose.js';

/** Build a SquashFS 4.0 little-endian superblock with chosen fields, padded to `size`. */
function squashfs(opts: {
  inodes: number;
  comp: number;
  bytesUsed: number;
  idTable: number;
  size: number;
}): Uint8Array {
  const bytes = new Uint8Array(opts.size);
  bytes.set([0x68, 0x73, 0x71, 0x73]);
  const view = new DataView(bytes.buffer);
  view.setUint32(0x04, opts.inodes, true);
  view.setUint16(0x14, opts.comp, true);
  view.setBigUint64(0x28, BigInt(opts.bytesUsed), true);
  view.setBigUint64(0x30, BigInt(opts.idTable), true);
  return bytes;
}

describe('parseSquashfsSuperblock', () => {
  it('reads the fields that explain why an extractor refused', () => {
    const sb = parseSquashfsSuperblock(
      squashfs({ inodes: 581, comp: 2, bytesUsed: 2536106, idTable: 2536098, size: 4096 }),
    );
    expect(sb?.inodes).toBe(581);
    expect(sb?.compression).toBe('lzma');
    expect(sb?.bytesUsed).toBe(2536106);
    expect(sb?.idTableStart).toBe(2536098);
  });

  it('names an unknown compression id instead of pretending it knows', () => {
    expect(
      parseSquashfsSuperblock(squashfs({ inodes: 1, comp: 99, bytesUsed: 10, idTable: 1, size: 4096 }))?.compression,
    ).toBe('unknown(99)');
  });

  it('returns null for bytes that are not a SquashFS', () => {
    expect(parseSquashfsSuperblock(new Uint8Array(4096).fill(0x41))).toBeNull();
    expect(parseSquashfsSuperblock(new Uint8Array(8))).toBeNull();
  });
});

describe('diagnoseSquashfs — a truncated image and a missing tool look identical from the error message', () => {
  /**
   * The real Asus-Router blob, in miniature. Its superblock is coherent — 581 inodes, LZMA, bytes_used exactly
   * the carved size — and the id table it points at lands in a run of trailing zeros. unsquashfs AND sasquatch
   * both answer "File system corruption detected", which sends you hunting for a better extractor when the actual
   * problem is that the bytes are not in the file.
   */
  it('calls out an id table that lands in trailing zero padding as a truncated image', () => {
    const size = 4096;
    const blob = squashfs({ inodes: 581, comp: 2, bytesUsed: size, idTable: size - 8, size });
    const d = diagnoseSquashfs(blob);
    expect(d?.idTableInZeroFill).toBe(true);
    expect(d?.verdict).toContain('truncated');
    expect(d?.verdict).toContain('not one'); // ...reads like a tool problem and is not one
    expect(d?.verdict).toContain('Re-acquire');
  });

  it('calls out a volume that declares more bytes than were carved', () => {
    const blob = squashfs({ inodes: 10, comp: 4, bytesUsed: 999_999, idTable: 128, size: 4096 });
    const d = diagnoseSquashfs(blob);
    expect(d?.short).toBe(true);
    expect(d?.verdict).toContain('cut short');
    expect(d?.verdict).toContain('not a missing extractor');
  });

  it('points at sasquatch when the volume is complete and merely LZMA', () => {
    const size = 4096;
    const blob = squashfs({ inodes: 42, comp: 2, bytesUsed: size, idTable: 128, size });
    blob[128] = 0x01; // id table region carries data, so the tail-zero test must not fire
    blob[size - 1] = 0x7f;
    const d = diagnoseSquashfs(blob);
    expect(d?.idTableInZeroFill).toBe(false);
    expect(d?.verdict).toContain('sasquatch');
  });

  it('is null for a blob that is not a SquashFS at all', () => {
    expect(diagnoseSquashfs(new Uint8Array(4096).fill(0x41))).toBeNull();
  });
});

describe('parseLzmaHeader — a carved blob nobody opened is not an empty result', () => {
  /** Raw LZMA "alone" header, verbatim shape from AliExpress-Repeater's carved kernel blob. */
  const lzma = (uncompressed: number, size = 64): Uint8Array => {
    const bytes = new Uint8Array(size);
    bytes[0] = 0x5d; // lc=3 lp=0 pb=2
    const view = new DataView(bytes.buffer);
    view.setUint32(1, 33554432, true); // 32 MB dictionary
    view.setBigUint64(5, BigInt(uncompressed), true);
    return bytes;
  };

  it('reads the declared uncompressed size, which is what makes the blob worth reporting', () => {
    expect(parseLzmaHeader(lzma(7660784))).toEqual({ dictSize: 33554432, uncompressedSize: 7660784 });
  });

  it('rejects bytes that are not a plausible stream rather than inventing a payload size', () => {
    expect(parseLzmaHeader(new Uint8Array(64).fill(0xff))).toBeNull(); // props byte out of range
    const badDict = lzma(1000);
    new DataView(badDict.buffer).setUint32(1, 12345, true); // not a power of two
    expect(parseLzmaHeader(badDict)).toBeNull();
    expect(parseLzmaHeader(new Uint8Array(4))).toBeNull();
  });
});
