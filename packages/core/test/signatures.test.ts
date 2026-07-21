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

describe('W0 device-class identity (entropy-gated, non-Linux classes)', () => {
  it('finds the ESP partition-table magic anchored at 0x8000', () => {
    const buf = new Uint8Array(0x9000);
    buf.set([0xaa, 0x50], 0x8000);
    expect(scanSignatures(buf).some((h) => h.id === 'esp-parttable')).toBe(true);
    // The same magic elsewhere must NOT fire (offset-anchored).
    expect(scanSignatures(planted(0x9000, 0x100, [0xaa, 0x50])).some((h) => h.id === 'esp-parttable')).toBe(false);
  });

  it('finds the RP2350 PICOBIN start marker', () => {
    expect(scanSignatures(planted(0x100, 0x14, [0xd3, 0xde, 0xff, 0xff])).some((h) => h.id === 'picobin')).toBe(true);
  });

  it('classifies an ESP32 flash dump as esp-soc (xtensa), NOT jffs2 — even with coincidental jffs2 magics', () => {
    const buf = new Uint8Array(0x9000);
    buf.set([0xaa, 0x50], 0x8000); // partition table entry @ 0x8000
    buf[0x1000] = 0xe9; // ESP bootloader image header magic; chip_id @ 0x100c is 0x0000 (ESP32) → xtensa
    buf.set([0x85, 0x19], 0x200); // coincidental JFFS2 magics (the historical false-positive)
    buf.set([0x85, 0x19], 0x300);
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).toBe('esp-soc');
    expect(id.arch).toBe('xtensa');
    expect(id.filesystems).toEqual([]);
    expect(id.classRationale).toMatch(/ESP SoC/);
  });

  it('reads the ESP arch from the image header chip_id (ESP32-C3 → RISC-V), not from strings', () => {
    const buf = new Uint8Array(0x9000);
    buf.set([0xaa, 0x50], 0x8000);
    buf[0x1000] = 0xe9; // image header magic
    buf[0x100c] = 0x05; // chip_id = 0x0005 (ESP32-C3) → RISC-V
    expect(inferIdentity(buf, scanSignatures(buf)).arch).toBe('riscv');
  });

  it('classifies an RP2350 PICOBIN image as baremetal with the ISA read from IMAGE_TYPE (RISC-V)', () => {
    const buf = new Uint8Array(0x1000);
    buf.set([0xd3, 0xde, 0xff, 0xff], 0x14); // start marker
    buf.set([0x42, 0x01, 0x01, 0x11], 0x18); // IMAGE_TYPE: EXE | CPU_RISCV | CHIP_RP2350 (flags 0x1101 LE)
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).toBe('baremetal');
    expect(id.arch).toBe('riscv'); // must NOT be Arm-by-name
    expect(id.classRationale).toMatch(/RISC-V/);
  });

  it('classifies a FIT container wrapping a UBI image as openwrt-fit-ubi (beats a SquashFS inside it)', () => {
    const buf = new Uint8Array(0x2000);
    buf.set([0xd0, 0x0d, 0xfe, 0xed], 0); // FIT (device-tree) header at offset 0
    buf.set([0x00, 0x10, 0x00, 0x00], 4); // totalsize
    buf.set(ascii('UBI#'), 420); // UBI sub-image
    buf.set(ascii('hsqs'), 1000); // a SquashFS inside — must not win over the container class
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).toBe('openwrt-fit-ubi');
    expect(id.classRationale).toMatch(/FIT/);
  });

  it('classifies a whole-image high-entropy blob with no header as encrypted (not jffs2)', () => {
    const buf = new Uint8Array(256 * 1024);
    for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff; // uniform histogram → H≈8, no container magic
    const entropy = computeEntropyProfile(buf);
    expect(entropy.likelyEncrypted).toBe(true);
    const id = inferIdentity(buf, scanSignatures(buf), entropy);
    expect(id.firmwareClass).toBe('encrypted');
    expect(id.filesystems).toEqual([]);
    expect(id.classRationale).toMatch(/encrypted/i);
  });

  it('a lone coincidental JFFS2 magic (invalid node type) does NOT become embedded-linux', () => {
    const buf = planted(4096, 100, [0x85, 0x19, 0x00, 0x00]); // magic, but 0x0000 is not a real JFFS2 node type
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).not.toBe('embedded-linux');
    expect(id.filesystems).toEqual([]);
  });

  it('a real JFFS2 node stream (valid node types) IS embedded-linux', () => {
    const buf = new Uint8Array(8192);
    for (const off of [100, 300, 600, 900]) buf.set([0x85, 0x19, 0x02, 0xe0], off); // magic + node type 0xe002 (INODE)
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).toBe('embedded-linux');
    expect(id.filesystems).toContain('jffs2');
  });
});
