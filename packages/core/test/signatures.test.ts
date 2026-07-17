import { describe, expect, it } from 'vitest';
import { computeEntropyProfile } from '../src/entropy.js';
import { scanSignatures } from '../src/signatures.js';
import { buildStructureSegments, inferIdentity } from '../src/structure.js';

/** Place `bytes` into a zero-filled buffer of `size` at `offset`. */
function planted(size: number, offset: number, bytes: number[]): Uint8Array {
  const buf = new Uint8Array(size);
  buf.set(bytes, offset);
  return buf;
}
function ascii(s: string): number[] {
  return [...s].map((c) => c.charCodeAt(0));
}

describe('scanSignatures', () => {
  it('finds a SquashFS magic at its offset', () => {
    const buf = planted(8192, 4096, ascii('hsqs'));
    const hits = scanSignatures(buf);
    const sqfs = hits.find((h) => h.id === 'squashfs-le');
    expect(sqfs).toBeDefined();
    expect(sqfs?.offset).toBe(4096);
    expect(sqfs?.category).toBe('filesystem');
  });

  it('decodes a uImage header and finds it at offset 0', () => {
    const buf = planted(1024, 0, [0x27, 0x05, 0x19, 0x56]);
    const hits = scanSignatures(buf);
    const uimage = hits.find((h) => h.id === 'uimage');
    expect(uimage).toBeDefined();
    expect(uimage?.category).toBe('bootloader');
    expect(uimage?.meta).toHaveProperty('loadAddr');
  });

  it('decodes ELF arch metadata', () => {
    const buf = new Uint8Array(64);
    // ELF, 32-bit, little-endian, e_machine=8 (MIPS) at offset 18.
    buf.set([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01], 0);
    buf[18] = 8;
    const hits = scanSignatures(buf);
    const elf = hits.find((h) => h.id === 'elf');
    expect(elf?.meta?.bits).toBe(32);
    expect(elf?.meta?.machine).toBe(8);
    expect(elf?.meta?.endian).toBe('little');
  });

  it('finds a PEM private-key block', () => {
    const buf = new TextEncoder().encode('junk\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...');
    const hits = scanSignatures(buf);
    expect(hits.some((h) => h.id === 'pem-cert')).toBe(true);
  });

  it('respects highConfidenceOnly', () => {
    const buf = planted(64, 0, ascii('MZ')); // low-confidence rule
    expect(scanSignatures(buf).some((h) => h.id === 'pe-mz')).toBe(true);
    expect(scanSignatures(buf, { highConfidenceOnly: true }).some((h) => h.id === 'pe-mz')).toBe(false);
  });

  it('caps the number of hits', () => {
    // A buffer of all 0xff — the yaffs2 low-confidence rule could match repeatedly; ensure the cap holds.
    const buf = new Uint8Array(10000).fill(0x1f);
    for (let i = 0; i < buf.length; i += 3) buf[i + 1] = 0x8b; // sprinkle gzip-ish
    const hits = scanSignatures(buf, { maxHits: 100 });
    expect(hits.length).toBeLessThanOrEqual(100);
  });
});

describe('extended signature pack', () => {
  it('finds an ext superblock only at its 0x438 offset', () => {
    const buf = planted(4096, 0x438, [0x53, 0xef]);
    const hits = scanSignatures(buf);
    const ext = hits.find((h) => h.id === 'ext');
    expect(ext?.offset).toBe(0x438);
    expect(ext?.category).toBe('filesystem');
    // The same magic elsewhere must NOT fire (offset-anchored).
    expect(scanSignatures(planted(4096, 0x100, [0x53, 0xef])).some((h) => h.id === 'ext')).toBe(false);
  });

  it('finds F2FS and EROFS superblocks at 0x400', () => {
    expect(scanSignatures(planted(4096, 0x400, [0x10, 0x20, 0xf5, 0xf2])).some((h) => h.id === 'f2fs')).toBe(true);
    expect(scanSignatures(planted(4096, 0x400, [0xe2, 0xe1, 0xf5, 0xe0])).some((h) => h.id === 'erofs')).toBe(true);
  });

  it('finds a big-endian CramFS', () => {
    const hits = scanSignatures(planted(512, 0, [0x28, 0xcd, 0x3d, 0x45]));
    expect(hits.find((h) => h.id === 'cramfs-be')?.category).toBe('filesystem');
  });

  it('finds kernel markers: IKCFG, bzImage, arm64 Image', () => {
    expect(scanSignatures(new TextEncoder().encode('..IKCFG_ST..')).some((h) => h.id === 'linux-ikcfg')).toBe(true);
    expect(scanSignatures(planted(1024, 0x202, ascii('HdrS'))).some((h) => h.id === 'bzimage')).toBe(true);
    expect(scanSignatures(planted(128, 0x38, ascii('ARMd'))).some((h) => h.id === 'arm64-linux')).toBe(true);
  });

  it('finds archives and lzop: 7-Zip, RAR, android-sparse, lzop, cpio-odc', () => {
    expect(scanSignatures(planted(64, 0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])).some((h) => h.id === '7zip')).toBe(
      true,
    );
    expect(scanSignatures(planted(64, 0, [...ascii('Rar!'), 0x1a, 0x07])).some((h) => h.id === 'rar')).toBe(true);
    expect(scanSignatures(planted(64, 0, [0x3a, 0xff, 0x26, 0xed])).some((h) => h.id === 'android-sparse')).toBe(true);
    expect(
      scanSignatures(planted(64, 0, [0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a])).some(
        (h) => h.id === 'lzop',
      ),
    ).toBe(true);
    expect(scanSignatures(planted(64, 0, ascii('070707'))).some((h) => h.id === 'cpio-odc')).toBe(true);
  });
});

describe('structure + identity', () => {
  it('classifies an image with a SquashFS as embedded-linux', () => {
    const buf = planted(16384, 8192, ascii('hsqs'));
    const hits = scanSignatures(buf);
    const identity = inferIdentity(buf, hits);
    expect(identity.firmwareClass).toBe('embedded-linux');
    expect(identity.filesystems).toContain('squashfs');
  });

  it('builds gap-filled segments covering the whole image', () => {
    const buf = planted(16384, 8192, ascii('hsqs'));
    const hits = scanSignatures(buf);
    const entropy = computeEntropyProfile(buf, { windowSize: 1024 });
    const segments = buildStructureSegments(buf.length, hits, entropy);
    expect(segments.length).toBeGreaterThan(0);
    // Segments should be contiguous and cover [0, size].
    expect(segments[0]?.start).toBe(0);
    expect(segments[segments.length - 1]?.end).toBe(buf.length);
    for (let i = 1; i < segments.length; i++) {
      expect(segments[i]?.start).toBe(segments[i - 1]?.end);
    }
  });

  it('infers little-endian MIPS from an embedded ELF', () => {
    const buf = new Uint8Array(128);
    buf.set([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01], 0);
    buf[18] = 8;
    const identity = inferIdentity(buf, scanSignatures(buf));
    expect(identity.arch).toBe('mipsel');
    expect(identity.endianness).toBe('little');
  });
});
