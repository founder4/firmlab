import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { computeEntropyProfile } from '../src/entropy.js';
import {
  SIGNATURE_RULES,
  md5,
  parseSercommPrefixHeader,
  scanSignatures,
  scanSignaturesDetailed,
} from '../src/signatures.js';
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

/**
 * Minimal U-Boot mtk_image default (hdroffset=0) generic envelope, laid out as mtk_image_set_gen_header at the
 * pinned commit writes it. The digest field is left zero: the scanner does not verify it, and these tests pin that.
 */
function bromEnvelope(name: string, type: number, payloadSize = 1): Uint8Array {
  const total = 0x900 + payloadSize + 32;
  const out = new Uint8Array(total).fill(0xff);
  const dv = new DataView(out.buffer);
  out.set([...ascii(name), 0], 0);
  dv.setUint32(12, 1, true);
  dv.setUint32(16, 0x200, true);
  out.set([...ascii('BRLYT'), 0, 0, 0], 0x200);
  for (const [at, v] of [
    [0x208, 1],
    [0x20c, 0x600],
    [0x210, total],
    [0x214, 0x42424242],
    [0x218, type],
    [0x21c, 0x600],
    [0x220, total],
  ] as const)
    dv.setUint32(at, v, true);
  const g = 0x600;
  out.fill(0, g, total);
  const common = (at: number, size: number, gfhType: number, version: number) => {
    dv.setUint32(g + at, (0x4d4d4d | (version << 24)) >>> 0, true);
    dv.setUint16(g + at + 4, size, true);
    dv.setUint16(g + at + 6, gfhType, true);
  };
  common(0, 56, 0, 1);
  out.set(ascii('FILE_INFO'), g + 8);
  dv.setUint32(g + 20, 1, true);
  dv.setUint16(g + 24, 1, true);
  out[g + 26] = 5;
  out[g + 27] = 1;
  for (const [at, v] of [
    [28, 0x100],
    [32, total - 0x600],
    [36, total],
    [40, 0x300],
    [44, 32],
    [48, 0x300],
    [52, 1],
  ] as const)
    dv.setUint32(g + at, v, true);
  common(56, 12, 1, 1);
  dv.setUint32(g + 64, 1, true);
  common(68, 100, 7, 3);
  dv.setUint32(g + 76, 0x190, true);
  dv.setUint32(g + 156, 5000, true);
  common(168, 0x214, 3, 1);
  common(700, 20, 2, 1);
  dv.setUint32(g + 712, 0x10, true);
  dv.setUint32(g + 716, 0x80, true);
  common(720, 48, 8, 1);
  dv.setUint32(g + 728, 3, true);
  return out;
}
const BROM_RULES = [
  ['mediatek-brom-nor', 'SF_BOOT', 0x10007],
  ['mediatek-brom-emmc', 'EMMC_BOOT', 0x10005],
  ['mediatek-brom-sdmmc', 'SDMMC_BOOT', 0x10008],
] as const;

/**
 * Realtek cvimg linux/linux-ro image assembled from the documented field facts (big-endian words, len = payload +
 * 2-byte checksum rounded to even). Not a generator output; the checksum bytes are arbitrary and must stay unverified.
 */
function cvimgImage(signature: string, payloadLength: number, startAddr = 0x80500000, burnAddr = 0x30000): Uint8Array {
  const len = payloadLength + 2 + (payloadLength % 2);
  const out = new Uint8Array(16 + len);
  const dv = new DataView(out.buffer);
  out.set(ascii(signature));
  dv.setUint32(4, startAddr, false);
  dv.setUint32(8, burnAddr, false);
  dv.setUint32(12, len, false);
  for (let i = 0; i < payloadLength; i++) out[16 + i] = 0x41 + i;
  out[16 + len - 2] = 0x12;
  out[16 + len - 1] = 0x34;
  return out;
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
    // ELF, 32-bit, little-endian, EV_CURRENT, e_machine=8 (MIPS) at offset 18. The EI_VERSION byte is part of
    // the fixture because the rule now checks it: a `\x7fELF` with a zero e_ident is not an ELF, and the
    // fixture that omitted it was asserting a shape no real binary has.
    buf.set([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01], 0);
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
    buf.set([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01], 0); // …0x01 = EI_VERSION, checked by the rule
    buf[18] = 8;
    const identity = inferIdentity(buf, scanSignatures(buf));
    expect(identity.arch).toBe('mipsel');
    expect(identity.endianness).toBe('little');
  });

  it('keeps a top-level ELF out of the Linux rootfs lane when its contents resemble SquashFS', () => {
    const buf = new Uint8Array(512);
    buf.set([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01], 0); // ELF32, LE, EV_CURRENT
    buf[18] = 40; // EM_ARM
    buf.set(ascii('hsqs'), 0x100); // incidental bytes inside the executable
    const identity = inferIdentity(buf, scanSignatures(buf));
    expect(identity.firmwareClass).toBe('rtos');
    expect(identity.arch).toBe('arm');
    expect(identity.filesystems).toEqual([]);
    expect(identity.classRationale).toMatch(/Top-level ELF/);
  });
});

describe('W0 device-class identity (entropy-gated, non-Linux classes)', () => {
  it('classifies the official Framework QMK raw RP2040 image as ARM RTOS without filename hints', () => {
    // Hash-locked release evidence: complete boot2 + vectors, plus QMK strings from the same binary. Keeping only
    // the decisive bytes demonstrates that classification is independent of the release filename.
    const prefix = Uint8Array.from(
      Buffer.from(
        'ALUySyEgWGCYaAIhiEOYYNhgGGFYYS5LACGZYAQhWWEBIfAimVArSRlgASGZYDUgAPBE+AIikEIU0AYhGWYA8DT4GW4BIRlmACAYZhpmAPAs+BluGW4ZbgUgAPAv+AEhCEL50QAhmWAbSRlgACFZYBpJG0gBYAEhmWDrIRlmoCEZZgDwEvgAIZlgFkkUSAFgASGZYAG8ACgA0ABHEkgTSQhgA8iA8wiICEcDtZlqBCABQvvQASABQvjRA70CtRhmGGb/9/L/GG4YbgK9AAACQAAAABgAAAcAAANfACEiAAD0AAAYIiAAoAABABAI7QDgAAAAAAAAAAAAAAAABwuP1QAEBCDFAgAQ',
        'base64',
      ),
    );
    const markers = new TextEncoder().encode(
      '\0eeconfig_update_rgb_matrix_default\0rgb_matrix_config EEPROM\0xkeyboard_report: \0suspending keyboard\0',
    );
    const buf = new Uint8Array(prefix.length + markers.length);
    buf.set(prefix);
    buf.set(markers, prefix.length);
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).toBe('rtos');
    expect(id.arch).toBe('arm');
    expect(id.endianness).toBe('little');
    expect(id.filesystems).toEqual([]);
    expect(id.classRationale).toMatch(/QMK keyboard.*RP2040.*boot2 CRC32/i);
  });

  it('keeps a structurally valid RP2040 image without RTOS markers as bare-metal', () => {
    const buf = Uint8Array.from(
      Buffer.from(
        'ALUySyEgWGCYaAIhiEOYYNhgGGFYYS5LACGZYAQhWWEBIfAimVArSRlgASGZYDUgAPBE+AIikEIU0AYhGWYA8DT4GW4BIRlmACAYZhpmAPAs+BluGW4ZbgUgAPAv+AEhCEL50QAhmWAbSRlgACFZYBpJG0gBYAEhmWDrIRlmoCEZZgDwEvgAIZlgFkkUSAFgASGZYAG8ACgA0ABHEkgTSQhgA8iA8wiICEcDtZlqBCABQvvQASABQvjRA70CtRhmGGb/9/L/GG4YbgK9AAACQAAAABgAAAcAAANfACEiAAD0AAAYIiAAoAABABAI7QDgAAAAAAAAAAAAAAAABwuP1QAEBCDFAgAQ',
        'base64',
      ),
    );
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).toBe('baremetal');
    expect(id.arch).toBe('arm');
    expect(id.classRationale).toMatch(/no RTOS family marker/i);
  });

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
    const dv = new DataView(buf.buffer);
    dv.setUint32(0x14, 0xffff_ded3, true); // start marker
    dv.setUint32(0x18, 0x1101_0142, true); // IMAGE_TYPE: EXE | CPU_RISCV | CHIP_RP2350
    dv.setUint32(0x1c, 0x0000_01ff, true); // LAST: one preceding item word
    dv.setUint32(0x20, 0, true); // singleton block loop
    dv.setUint32(0x24, 0xab12_3579, true); // end marker
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

  it('classifies an eCos monolith (uImage says Linux, payload is eCos) as rtos, NOT embedded-linux', () => {
    const buf = new Uint8Array(0x4000);
    // U-Boot uImage header whose ih_os byte @28 says Linux (5), ih_arch @29 says MIPS (5) — the OS byte lies.
    buf.set([0x27, 0x05, 0x19, 0x56], 0);
    buf[28] = 5; // ih_os = IH_OS_LINUX
    buf[29] = 5; // ih_arch = IH_ARCH_MIPS
    // eCos payload markers — the truth.
    buf.set(ascii('RedBoot> '), 0x800);
    buf.set(ascii('cyg_scheduler_start'), 0x900);
    buf.set(ascii('zxrouter'), 0xa00);
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).toBe('rtos');
    expect(id.arch).toBe('mipsel'); // refined from the uImage's endian-less mips
    expect(id.endianness).toBe('little');
    expect(id.filesystems).toEqual([]);
    expect(id.classRationale).toMatch(/eCos/i);
  });

  it('does NOT call a real Linux image eCos just because its bootloader mentions RedBoot', () => {
    // A genuine SquashFS rootfs present → embedded-linux wins; the RedBoot string must not divert it to rtos.
    const buf = new Uint8Array(0x4000);
    buf.set(ascii('hsqs'), 0x100); // SquashFS LE magic
    buf.set(ascii('RedBoot bootloader'), 0x800);
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).toBe('embedded-linux');
  });
});

/**
 * The listing bound, and the one thing it may not cost.
 *
 * `maxHits` used to `return hits` from inside the scan loop, which ended the walk mid-buffer and truncated by file
 * offset — arrival order. That was not just a short list: `inferIdentity` reads `new Set(hits.map(h => h.id))`, so
 * losing a rule TYPE changes a persisted identity. Measured on the corpus before the fix, the 61.7 MB Obsbot image
 * kept 5 000 of 32 372 matches, lost `cramfs`, `lzop`, `lz4` and `trx` outright, and stored `[squashfs, ubifs, ubi]`
 * where the complete scan says `[squashfs, cramfs, ubifs, ubi]`.
 */
describe('scanSignaturesDetailed — the bound shortens the list, never the id set', () => {
  /**
   * A buffer whose first stretch is dense in ONE magic and which carries a different magic only near the end —
   * the shape that made the old bound lose a type: past the cap, the late rule was never reached.
   */
  function crowdedThenRare(): Uint8Array {
    const buf = new Uint8Array(200_000);
    // gzip members, one every 4 bytes, far more than any small cap will list.
    for (let off = 0; off + 3 < 150_000; off += 4) buf.set([0x1f, 0x8b, 0x08, 0x00], off);
    // A single SquashFS magic near the end, well past where a small cap would have stopped.
    buf.set(ascii('hsqs'), 190_000);
    return buf;
  }

  it('still lists a rule first seen past the cap', () => {
    const buf = crowdedThenRare();
    const scan = scanSignaturesDetailed(buf, { maxHits: 10 });
    expect(scan.hits.length).toBeGreaterThan(10);
    const late = scan.hits.find((h) => h.id === 'squashfs-le');
    expect(late).toBeDefined();
    expect(late?.offset).toBe(190_000);
  });

  it('produces the same id set — and so the same identity — as an unbounded scan', () => {
    const buf = crowdedThenRare();
    const bounded = scanSignaturesDetailed(buf, { maxHits: 10 });
    const full = scanSignaturesDetailed(buf, { maxHits: Number.MAX_SAFE_INTEGER });
    const ids = (s: typeof bounded): string[] => [...new Set(s.hits.map((h) => h.id))].sort();
    expect(ids(bounded)).toEqual(ids(full));
    expect(bounded.distinctIds).toBe(full.distinctIds);
    const entropy = computeEntropyProfile(buf);
    expect(inferIdentity(buf, bounded.hits, entropy)).toEqual(inferIdentity(buf, full.hits, entropy));
    // And the list really is still bounded — the point is that it costs at most one entry per unseen rule.
    expect(bounded.hits.length).toBeLessThan(full.hits.length);
  });

  it('counts every match even though it lists only some', () => {
    const scan = scanSignaturesDetailed(crowdedThenRare(), { maxHits: 10 });
    expect(scan.matched).toBeGreaterThan(scan.hits.length);
    // `matched` is what makes "5 000 listed" readable as a bound rather than as the answer.
    expect(scan.matched).toBeGreaterThan(30_000);
  });

  it('keeps hits ascending by offset, which the structure map depends on', () => {
    const scan = scanSignaturesDetailed(crowdedThenRare(), { maxHits: 10 });
    const offsets = scan.hits.map((h) => h.offset);
    expect([...offsets].sort((a, b) => a - b)).toEqual(offsets);
  });

  it('changes nothing at all below the bound — the branch where the guard finds nothing wrong', () => {
    const buf = planted(8192, 4096, ascii('hsqs'));
    const scan = scanSignaturesDetailed(buf);
    expect(scan.hits.length).toBeLessThan(5000);
    expect(scan.matched).toBe(scan.hits.length);
    expect(scan.distinctIds).toBe(new Set(scan.hits.map((h) => h.id)).size);
    // The plain entry point returns exactly the detailed one's list, as every existing caller relies on.
    expect(scanSignatures(buf)).toEqual(scan.hits);
  });
});

/**
 * The confidence rubric, and the fixture table that is its denominator.
 *
 * Every rule that can REJECT gets both fixtures here: one that the structural check must accept, and one whose
 * magic is byte-identical but whose structure is broken. The negative is the part that matters — a scanner
 * without a rejection path is what produced hundreds of hits per corpus image, and a rule whose rejection branch
 * is never exercised is a guard whose success path nobody runs (the `deploy.sh` lsof lesson, in a scanner).
 *
 * The table is also checked AGAINST the registry: if a rule gains a `verify` and no fixtures, the coverage test
 * below fails by name. That is deliberate — a fixture list whose denominator is invisible proves nothing.
 */
describe('signature confidence rubric', () => {
  /** Build a buffer of `size` with `[offset, bytes]` patches applied. */
  function img(size: number, ...patches: [number, number[]][]): Uint8Array {
    const buf = new Uint8Array(size);
    for (const [off, bytes] of patches) buf.set(bytes, off);
    return buf;
  }
  function u32beBytes(v: number): number[] {
    return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
  }
  function u32leBytes(v: number): number[] {
    return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
  }
  /** A well-formed UEFI firmware volume header whose `_FVH` signature sits 40 bytes into it, per the spec. */
  function uefiVolume(zeroVectorByte = 0): Uint8Array {
    const base = 0x100;
    return img(
      0x400,
      [base, new Array(16).fill(zeroVectorByte)], // ZeroVector — all zero by definition
      [base + 16, new Array(16).fill(0xaa)], // FileSystemGuid
      [base + 32, [...u32leBytes(0x1000), ...u32leBytes(0)]], // FvLength u64 LE
      [base + 40, [...'_FVH'].map((c) => c.charCodeAt(0))],
      [base + 48, [0x48, 0x00]], // HeaderLength
    );
  }

  /** Independent synthetic image matching OpenWrt firmware-utils' mksercommfw 512-byte prefix layout. */
  function sercommPrefix(opts: { badSecondaryMagic?: boolean; badChecksum?: boolean } = {}): Uint8Array {
    const buf = img(
      0x300,
      [0, ascii('sErCoMm')],
      [7, [0, 1, 0, 0]],
      [11, ascii('TEST-HW')],
      [45, ascii('A1')],
      [55, u32beBytes(0x01020304)],
      [63, ascii(opts.badSecondaryMagic ? 'sErCoMX' : 'sErCoMm')],
    );
    let sum = 0;
    for (const byte of buf) sum = (sum + byte) & 0xff;
    buf[511] = -sum & 0xff;
    if (opts.badChecksum) buf[0x280] = 1;
    return buf;
  }

  interface RubricCase {
    id: string;
    /** A fixture the rule must accept. */
    pos: Uint8Array;
    /** Same magic, broken structure — the rule must reject it and count the rejection. */
    neg?: Uint8Array;
    /** Tier the positive fixture must reach. */
    tier: 'magic' | 'structural' | 'consistent' | 'verified';
  }

  const CASES: RubricCase[] = [
    {
      id: 'mediatek-lk',
      tier: 'consistent',
      pos: img(
        513,
        [0, new Array(512).fill(0xff)],
        [0, [0x88, 0x16, 0x88, 0x58]],
        [4, u32leBytes(1)],
        [8, new Array(32).fill(0)],
        [40, u32leBytes(1)],
      ),
      neg: img(
        513,
        [0, new Array(512).fill(0xff)],
        [0, [0x88, 0x16, 0x88, 0x58]],
        [4, u32leBytes(2)],
        [8, new Array(32).fill(0)],
        [40, u32leBytes(1)],
      ),
    },
    {
      id: 'realtek-cvimg-cs6c',
      tier: 'consistent',
      pos: cvimgImage('cs6c', 5),
      // Same signature; the declared region runs one byte past the buffer.
      neg: cvimgImage('cs6c', 5).subarray(0, 23),
    },
    {
      id: 'realtek-cvimg-cr6c',
      tier: 'consistent',
      pos: cvimgImage('cr6c', 4),
      // Same signature; an odd declared length the producer never writes.
      neg: (() => {
        const bad = cvimgImage('cr6c', 4);
        bad[15] = 5;
        return bad;
      })(),
    },
    {
      id: 'mediatek-brom-nor',
      tier: 'consistent',
      pos: bromEnvelope('SF_BOOT', 0x10007),
      // Same device name; BRLYT declares another media type, which the generator never pairs with this name.
      neg: bromEnvelope('SF_BOOT', 0x10005),
    },
    {
      id: 'mediatek-brom-emmc',
      tier: 'consistent',
      pos: bromEnvelope('EMMC_BOOT', 0x10005),
      // Same device name; BRLYT declares another media type, which the generator never pairs with this name.
      neg: bromEnvelope('EMMC_BOOT', 0x10008),
    },
    {
      id: 'mediatek-brom-sdmmc',
      tier: 'consistent',
      pos: bromEnvelope('SDMMC_BOOT', 0x10008),
      // Same device name; BRLYT declares another media type, which the generator never pairs with this name.
      neg: bromEnvelope('SDMMC_BOOT', 0x10007),
    },
    // --- existing rules that gained a structural check ---
    {
      id: 'elf',
      tier: 'consistent',
      pos: img(64, [0, [0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01]]),
      neg: img(64, [0, [0x7f, 0x45, 0x4c, 0x46, 0x09, 0x01, 0x01]]),
    },
    {
      id: 'gzip',
      tier: 'consistent',
      pos: img(64, [0, [0x1f, 0x8b, 0x08, 0x00]]),
      neg: img(64, [0, [0x1f, 0x8b, 0x08, 0xe0]]),
    },
    {
      id: 'jffs2-le',
      tier: 'consistent',
      pos: img(64, [0, [0x85, 0x19, 0x02, 0xe0]]),
      neg: img(64, [0, [0x85, 0x19, 0x34, 0x12]]),
    },
    {
      id: 'jffs2-be',
      tier: 'consistent',
      pos: img(64, [0, [0x19, 0x85, 0xe0, 0x02]]),
      neg: img(64, [0, [0x19, 0x85, 0x12, 0x34]]),
    },
    // dict size 0x00800000 (power of two) + the all-ones "unknown length" marker.
    {
      id: 'lzma',
      tier: 'consistent',
      pos: img(64, [0, [0x5d, 0x00, 0x00, 0x80, 0x00, ...new Array(8).fill(0xff)]]),
      neg: img(64, [0, [0x5d, 0x00, 0x00, 0x33, 0x00, ...new Array(8).fill(0xff)]]),
    },
    {
      id: 'pem-cert',
      tier: 'consistent',
      pos: new TextEncoder().encode('-----BEGIN RSA PRIVATE KEY-----\nMIIE'),
      neg: new TextEncoder().encode('-----BEGIN the meeting at nine, everyone'),
    },
    { id: 'uefi-fv', tier: 'consistent', pos: uefiVolume(0), neg: uefiVolume(0x41) },
    {
      // The CRC field is left zero, so the image fits but its checksum does not: penalized, not rejected.
      id: 'trx',
      tier: 'structural',
      pos: img(0x2000, [0, [...[...'HDR0'].map((c) => c.charCodeAt(0)), ...u32leBytes(0x1000)]], [16, u32leBytes(28)]),
      neg: img(0x2000, [0, [...[...'HDR0'].map((c) => c.charCodeAt(0)), ...u32leBytes(4)]]),
    },

    // --- vendor / platform containers, each with a rejecting structural check ---
    {
      id: 'sercomm-prefix',
      tier: 'verified',
      pos: sercommPrefix(),
      neg: sercommPrefix({ badSecondaryMagic: true }),
    },
    {
      id: 'trx-v2',
      tier: 'consistent',
      pos: img(0x2000, [0, [...[...'HDR1'].map((c) => c.charCodeAt(0)), ...u32leBytes(0x1000)]], [16, u32leBytes(28)]),
      neg: img(0x2000, [0, [...[...'HDR1'].map((c) => c.charCodeAt(0)), ...u32leBytes(4)]]),
    },
    {
      id: 'seama',
      tier: 'consistent',
      pos: img(0x400, [0, [0x5e, 0xa3, 0xa4, 0x17, 0, 0, 0x00, 0x40, ...u32beBytes(0x100)]]),
      neg: img(0x400, [0, [0x5e, 0xa3, 0xa4, 0x17, 0, 0, 0x99, 0x99, ...u32beBytes(0x100)]]),
    },
    {
      id: 'wrgg',
      tier: 'consistent',
      pos: img(0x100, [0, ascii('wrgg03_dlob.hans_dir825b')]),
      neg: img(0x100, [0, ascii('wrgg0'.padEnd(40, 'A'))]),
    },
    {
      id: 'netgear-chk',
      tier: 'consistent',
      // header_len = 0x28 + strlen(board_id) + 1; board_id is NUL-terminated ASCII filling the header out.
      pos: img(
        0x200,
        [0, [0x2a, 0x23, 0x24, 0x5e, ...u32beBytes(0x3b)]],
        [0x18, u32beBytes(0x1000)],
        [0x28, ascii('U12H072T00_NETGEAR')],
      ),
      neg: img(0x200, [0, [0x2a, 0x23, 0x24, 0x5e, ...u32beBytes(0x10)]], [0x18, u32beBytes(0x1000)]),
    },
    {
      id: 'netgear-dni',
      tier: 'consistent',
      pos: new TextEncoder().encode('device:WNDR3700v2\nversion:1.0.0.0\nregion:WW\n'),
      neg: new TextEncoder().encode('device:eth0 is down and the log says nothing useful about it'),
    },
    {
      id: 'ubnt-fw-ubnt',
      tier: 'consistent',
      pos: img(0x200, [0, ascii('UBNT')], [0x100, ascii('PART')]),
      neg: img(0x200, [0, ascii('UBNT')]),
    },
    {
      id: 'ubnt-fw-open',
      tier: 'consistent',
      pos: img(0x200, [0, ascii('OPEN')], [0x100, ascii('PART')]),
      neg: img(0x200, [0, ascii('OPEN')]),
    },
    {
      id: 'ubnt-fw-geos',
      tier: 'consistent',
      pos: img(0x200, [0, ascii('GEOS')], [0x100, ascii('PART')]),
      neg: img(0x200, [0, ascii('GEOS')]),
    },
    {
      // A fitting layout with a zero MD5 field: penalized to structural, not rejected. The rejection is a kernel
      // that runs past the declared length.
      id: 'tplink-v1',
      tier: 'structural',
      pos: img(0x400, [0, [1, 0, 0, 0, ...ascii('TP-LINK Technologies')]], [0x7c, u32beBytes(0x400)]),
      neg: img(
        0x400,
        [0, [1, 0, 0, 0, ...ascii('TP-LINK Technologies')]],
        [0x7c, u32beBytes(0x400)],
        [0x80, [...u32beBytes(0x200), ...u32beBytes(0x300)]],
      ),
    },
    {
      id: 'tplink-safeloader',
      tier: 'consistent',
      pos: new TextEncoder().encode('fwup-ptn 512 1024\r\n'),
      neg: new TextEncoder().encode('fwup-ptn_table_entry_name'),
    },
    {
      id: 'rkfw',
      tier: 'consistent',
      pos: img(0x400, [0, ascii('RKFW')], [0x100, ascii('RKAF')]),
      neg: img(0x400, [0, ascii('RKFW')]),
    },
    {
      id: 'rkaf',
      tier: 'consistent',
      pos: img(0x400, [0, ascii('RKAF')], [8, ascii('RK3288')]),
      neg: img(0x400, [0, ascii('RKAF')]),
    },
    {
      id: 'imx-ivt',
      tier: 'consistent',
      pos: img(0x100, [0, [0xd1, 0x00, 0x20, 0x41, ...u32leBytes(0x87800000)]], [0x14, u32leBytes(0x877ff400)]),
      // reserved1 (@8) must be zero — a real IVT never sets it.
      neg: img(
        0x100,
        [0, [0xd1, 0x00, 0x20, 0x41, ...u32leBytes(0x87800000), ...u32leBytes(1)]],
        [0x14, u32leBytes(0x877ff400)],
      ),
    },
    {
      id: 'bflt',
      tier: 'consistent',
      pos: img(0x40, [0, [...ascii('bFLT'), ...u32beBytes(4)]]),
      neg: img(0x40, [0, [...ascii('bFLT'), ...u32beBytes(7)]]),
    },
    {
      id: 'avb-vbmeta',
      tier: 'consistent',
      pos: img(0x40, [0, [...ascii('AVB0'), ...u32beBytes(1), ...u32beBytes(0)]]),
      neg: img(0x40, [0, [...ascii('AVB0'), ...u32beBytes(9), ...u32beBytes(0)]]),
    },
    {
      id: 'android-dt-table',
      tier: 'consistent',
      pos: img(0x40, [0, [0xd7, 0xb7, 0xab, 0x1e, ...u32beBytes(0x1000), ...u32beBytes(32)]]),
      neg: img(0x40, [0, [0xd7, 0xb7, 0xab, 0x1e, ...u32beBytes(0x1000), ...u32beBytes(64)]]),
    },
    {
      id: 'fmap',
      tier: 'consistent',
      pos: img(0x40, [0, [...ascii('__FMAP__'), 0x01]]),
      neg: img(0x40, [0, [...ascii('__FMAP__'), 0x03]]),
    },
    {
      id: 'intel-fpt',
      tier: 'consistent',
      pos: img(0x40, [0, [...ascii('$FPT'), ...u32leBytes(8)]]),
      neg: img(0x40, [0, [...ascii('$FPT'), ...u32leBytes(0)]]),
    },

    // --- vendor magics long enough to stand alone: `structural` by the base ladder, no verify to reject ---
    { id: 'cfe', tier: 'structural', pos: img(0x40, [0, ascii('CFE1CFE1')]) },
    { id: 'imagewty', tier: 'structural', pos: img(0x40, [0, ascii('IMAGEWTY')]) },
    { id: 'android-vendor-boot', tier: 'structural', pos: img(0x40, [0, ascii('VNDRBOOT')]) },
    { id: 'cbfs', tier: 'structural', pos: img(0x40, [0, ascii('LARCHIVE')]) },
    // Anchored at 0x10: the offset IS the constraint, which is what lifts it a rung to `consistent`.
    { id: 'intel-flash-descriptor', tier: 'consistent', pos: img(0x100, [0x10, [0x5a, 0xa5, 0xf0, 0x0f]]) },
  ];

  it.each(CASES)('accepts the $id positive fixture at tier $tier', ({ id, pos, tier }) => {
    const scan = scanSignaturesDetailed(pos);
    const hit = scan.hits.find((h) => h.id === id);
    expect(hit, `${id} did not fire on its positive fixture`).toBeDefined();
    expect(hit?.tier).toBe(tier);
    expect(hit?.score).toBe({ magic: 25, structural: 60, consistent: 85, verified: 99 }[tier]);
  });

  it('decodes the exact mksercommfw fields and downgrades a broken 8-bit sum without losing the container', () => {
    const parsed = parseSercommPrefixHeader(sercommPrefix());
    expect(parsed).toEqual({
      valid: true,
      hardwareId: 'TEST-HW',
      hardwareRevision: 'A1',
      softwareVersion: 0x01020304,
      checksumValid: true,
    });
    const hit = scanSignatures(sercommPrefix({ badChecksum: true })).find(
      (candidate) => candidate.id === 'sercomm-prefix',
    );
    expect(hit?.tier).toBe('consistent');
    expect(hit?.rationale).toMatch(/complete-image 8-bit sum is nonzero/);
    expect(hit?.meta).toMatchObject({
      hardwareId: 'TEST-HW',
      hardwareRevision: 'A1',
      softwareVersion: 0x01020304,
    });
  });

  it('rejects malformed Sercomm fields and never finds the anchored prefix when shifted', () => {
    expect(parseSercommPrefixHeader(sercommPrefix().subarray(0, 511))).toMatchObject({ valid: false });
    const badVersion = sercommPrefix();
    badVersion[8] = 2;
    expect(parseSercommPrefixHeader(badVersion)).toMatchObject({
      valid: false,
      reason: expect.stringMatching(/version/),
    });
    const nonPrintable = sercommPrefix();
    nonPrintable[11] = 1;
    expect(parseSercommPrefixHeader(nonPrintable)).toMatchObject({
      valid: false,
      reason: expect.stringMatching(/hardware id/),
    });
    const textAfterNul = sercommPrefix();
    textAfterNul[30] = 0x41;
    expect(parseSercommPrefixHeader(textAfterNul)).toMatchObject({ valid: false });
    const badPadding = sercommPrefix();
    badPadding[100] = 1;
    expect(parseSercommPrefixHeader(badPadding)).toMatchObject({
      valid: false,
      reason: expect.stringMatching(/padding/),
    });
    const shifted = new Uint8Array(sercommPrefix().length + 1);
    shifted.set(sercommPrefix(), 1);
    expect(scanSignatures(shifted).some((hit) => hit.id === 'sercomm-prefix')).toBe(false);
  });

  it.each(CASES.filter((c) => c.neg))('rejects the $id negative fixture and counts the rejection', ({ id, neg }) => {
    const scan = scanSignaturesDetailed(neg as Uint8Array);
    expect(
      scan.hits.some((h) => h.id === id),
      `${id} accepted a structurally broken fixture`,
    ).toBe(false);
    // The rejection is recorded, not silently dropped: that count is what tells "no such format here" apart
    // from "its magic is all over this image and every instance failed its check".
    expect(scan.rejectedByRule?.[id] ?? 0).toBeGreaterThan(0);
    expect(scan.rejected ?? 0).toBeGreaterThan(0);
  });

  it('covers every rejecting rule — this table is the denominator, not a sample', () => {
    // `uimage` checks and never rejects — its CRC mismatches penalize (see the checksum-verified tier suite), so it
    // is named here rather than given a negative case it could not honestly have.
    const softOnly = new Set(['uimage']);
    const rejecting = SIGNATURE_RULES.filter((r) => r.verify && !softOnly.has(r.id)).map((r) => r.id);
    const covered = new Set(CASES.filter((c) => c.neg).map((c) => c.id));
    expect([...rejecting].sort()).toEqual([...covered].sort());
  });

  it('gives a rationale saying what was read, exactly when a check ran', () => {
    const elf = scanSignatures(img(64, [0, [0x7f, 0x45, 0x4c, 0x46, 0x02, 0x02, 0x01]])).find((h) => h.id === 'elf');
    expect(elf?.rationale).toMatch(/64-bit big-endian, EV_CURRENT/);
    // A rule with no structural check makes no claim about one — silence, not a manufactured sentence.
    const sqfs = scanSignatures(planted(512, 0, ascii('hsqs'))).find((h) => h.id === 'squashfs-le');
    expect(sqfs?.rationale).toBeUndefined();
    expect(sqfs?.tier).toBe('structural');
  });

  it('derives the base tier from the rule prior, and an offset anchor lifts it one rung', () => {
    const esp = new Uint8Array(0x9000);
    esp.set([0xaa, 0x50], 0x8000);
    // Two bytes — pure noise anywhere but 0x8000, which is exactly why the anchor is worth a rung.
    expect(scanSignatures(esp).find((h) => h.id === 'esp-parttable')?.tier).toBe('consistent');
    // A `low` prior with no check and no anchor stays at the bottom of the ladder.
    expect(scanSignatures(planted(64, 0, ascii('MZ'))).find((h) => h.id === 'pe-mz')?.tier).toBe('magic');
  });

  it('never lets a magic under 4 bytes claim high confidence without an anchor or a check', () => {
    const overclaiming = SIGNATURE_RULES.filter(
      (r) => r.magic.length < 4 && r.atOffset === undefined && !r.verify && r.confidence === 'high',
    ).map((r) => r.id);
    expect(overclaiming).toEqual([]);
  });

  it('counts rejections against the matches that produced them', () => {
    // Twelve `\x7fELF` runs whose e_ident is zeroed — the shape a compressed blob produces constantly.
    const buf = new Uint8Array(0x1000);
    for (let i = 0; i < 12; i++) buf.set([0x7f, 0x45, 0x4c, 0x46], i * 0x80);
    const scan = scanSignaturesDetailed(buf);
    expect(scan.hits.some((h) => h.id === 'elf')).toBe(false);
    expect(scan.rejectedByRule?.elf).toBe(12);
    // `matched` stays the raw denominator: 12 magics matched, 12 were rejected, 0 survived.
    expect(scan.matched).toBeGreaterThanOrEqual(12);
    expect(scan.matched - (scan.rejected ?? 0)).toBe(scan.hits.length);
  });

  it('rejects nothing on a clean image — the branch where the guard finds nothing wrong', () => {
    const scan = scanSignaturesDetailed(planted(8192, 4096, ascii('hsqs')));
    expect(scan.rejected).toBe(0);
    expect(scan.rejectedByRule).toEqual({});
    expect(scan.hits.length).toBe(scan.matched);
  });

  it('keeps ids unique across the registry', () => {
    const ids = SIGNATURE_RULES.map((r) => r.id);
    expect(ids.length).toBe(new Set(ids).size);
  });
});

/**
 * `classEvidence` — HOW the class was decided, kept apart from what it is.
 *
 * The distinction the workbench kept losing: a format header that a structural check confirmed and a threshold
 * over marker strings both produce a `firmwareClass`, and until now they rendered identically. A uImage header
 * is an exact signature for a uImage and an inference about its payload, which is why the eCos monolith repacked
 * in one is `heuristic` here and not `exact-signature`.
 */
/**
 * The `verified` rung. The expected CRCs come from `node:zlib`, not from core's own table, so these tests would
 * catch a wrong polynomial or the wrong one of the two conventions (U-Boot inverts the register, TRX does not).
 */
describe('checksum-verified tier — uImage, TRX and TP-Link v1 recompute their own checksums', () => {
  const crc = (b: Uint8Array): number => zlib.crc32(b) >>> 0;

  function uimage(payload: Uint8Array, opts: { badHeader?: boolean; badData?: boolean; truncate?: number } = {}) {
    const h = Buffer.alloc(64);
    h.writeUInt32BE(0x27051956, 0);
    h.writeUInt32BE(payload.length, 12);
    h.writeUInt32BE(opts.badData ? 0xdeadbeef : crc(payload), 24);
    h.writeUInt32BE(opts.badHeader ? 0x12345678 : crc(h), 4);
    const whole = Buffer.concat([h, payload]);
    return whole.subarray(0, whole.length - (opts.truncate ?? 0));
  }
  const payload = new TextEncoder().encode('Linux kernel payload bytes, repeated. '.repeat(40));
  const tierOf = (buf: Uint8Array, id: string) => scanSignatures(buf).find((h) => h.id === id)?.tier;

  it('reaches verified only when both uImage CRCs recompute', () => {
    expect(tierOf(uimage(payload), 'uimage')).toBe('verified');
  });

  it('keeps a self-checking header whose payload differs, as consistent — the measured corpus case', () => {
    const hit = scanSignatures(uimage(payload, { badData: true })).find((h) => h.id === 'uimage');
    expect(hit?.tier).toBe('consistent');
    expect(hit?.rationale).toMatch(/modified or re-packed/);
    expect(tierOf(uimage(payload, { truncate: 10 }), 'uimage')).toBe('consistent');
  });

  it('penalizes a header CRC mismatch to magic without rejecting the hit', () => {
    const scan = scanSignaturesDetailed(uimage(payload, { badHeader: true }));
    expect(scan.hits.find((h) => h.id === 'uimage')?.tier).toBe('magic');
    expect(scan.rejectedByRule.uimage).toBeUndefined();
  });

  function trx(opts: { badCrc?: boolean } = {}) {
    const buf = Buffer.alloc(0x400, 0x5a);
    buf.write('HDR0', 0, 'latin1');
    buf.writeUInt32LE(0x400, 4);
    buf.writeUInt32LE(0, 12);
    buf.writeUInt32LE(28, 16);
    // TRX stores the raw register: zlib's value with its final inversion undone.
    buf.writeUInt32LE(opts.badCrc ? 1 : ~crc(buf.subarray(12, 0x400)) >>> 0, 8);
    return buf;
  }

  it('computes MD5 exactly as node:crypto does, across the padding boundaries', () => {
    for (const n of [0, 1, 55, 56, 63, 64, 65, 1000]) {
      const data = Uint8Array.from({ length: n }, (_, i) => (i * 31 + 7) & 0xff);
      expect(Buffer.from(md5(data)).toString('hex')).toBe(crypto.createHash('md5').update(data).digest('hex'));
    }
  });

  function tplink(salt: 'normal' | 'boot' | 'none') {
    const buf = Buffer.alloc(0x800, 0x33);
    buf.fill(0, 0, 0x200);
    Buffer.from([1, 0, 0, 0]).copy(buf, 0);
    buf.write('TP-LINK Technologies', 4, 'latin1');
    buf.writeUInt32BE(0x800, 0x7c);
    buf.writeUInt32BE(0x200, 0x80);
    buf.writeUInt32BE(0x400, 0x84);
    const salts = {
      normal: 'dcd73aa5c39598fbddf9e7f40eae4738',
      boot: '8cef335bd5c5cefaa79c28dab2e90f42',
      none: '00000000000000000000000000000000',
    };
    Buffer.from(salts[salt], 'hex').copy(buf, 0x4c);
    crypto.createHash('md5').update(buf).digest().copy(buf, 0x4c);
    return buf;
  }

  it('reaches verified on a TP-Link v1 header signed under either measured salt, structural under neither', () => {
    expect(tierOf(tplink('normal'), 'tplink-v1')).toBe('verified');
    expect(tierOf(tplink('boot'), 'tplink-v1')).toBe('verified');
    expect(tierOf(tplink('none'), 'tplink-v1')).toBe('structural');
  });

  it('reaches verified on a TRX whose stored register recomputes, and only structural when it does not', () => {
    expect(tierOf(trx(), 'trx')).toBe('verified');
    expect(tierOf(trx({ badCrc: true }), 'trx')).toBe('structural');
  });
});

describe('inferIdentity — exact signature vs heuristic vs unknown', () => {
  it('calls a filesystem superblock an exact signature', () => {
    const buf = planted(16384, 8192, ascii('hsqs'));
    expect(inferIdentity(buf, scanSignatures(buf)).classEvidence).toBe('exact-signature');
  });

  it('calls a verified UEFI volume header an exact signature', () => {
    const base = 0x100;
    const buf = new Uint8Array(0x400);
    buf.set(new Array(16).fill(0xaa), base + 16);
    buf.set([0x00, 0x10, 0x00, 0x00], base + 32); // FvLength
    buf.set(ascii('_FVH'), base + 40);
    buf.set([0x48, 0x00], base + 48); // HeaderLength
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).toBe('uefi-bios');
    expect(id.classEvidence).toBe('exact-signature');
  });

  it('does NOT reach uefi-bios on a bare `_FVH` string with no volume header behind it', () => {
    const buf = new TextEncoder().encode('a log line mentioning _FVH and nothing else at all');
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).not.toBe('uefi-bios');
  });

  it('calls a uImage container heuristic — the header is exact, what it wraps is not', () => {
    const buf = planted(0x4000, 0, [0x27, 0x05, 0x19, 0x56]);
    const id = inferIdentity(buf, scanSignatures(buf));
    expect(id.firmwareClass).toBe('embedded-linux');
    expect(id.classEvidence).toBe('heuristic');
  });

  it('calls the eCos marker scan heuristic', () => {
    const buf = new TextEncoder().encode('redboot cyg_scheduler cyg_thread padding');
    expect(inferIdentity(buf, []).classEvidence).toBe('heuristic');
  });

  it('calls a whole-image entropy verdict heuristic, not a signature', () => {
    const buf = new Uint8Array(256 * 1024);
    for (let i = 0; i < buf.length; i++) buf[i] = i & 0xff;
    const id = inferIdentity(buf, scanSignatures(buf), computeEntropyProfile(buf));
    expect(id.firmwareClass).toBe('encrypted');
    expect(id.classEvidence).toBe('heuristic');
  });

  it('says unknown when nothing identified the image — a fallback is not a finding', () => {
    const id = inferIdentity(new Uint8Array(64 * 1024), []);
    expect(id.firmwareClass).toBe('unknown');
    expect(id.classEvidence).toBe('unknown');
  });
});

/**
 * What the rubric does and does not buy, measured rather than asserted.
 *
 * Run over 16 MB of random bytes, the registry matches ~760 magics. JFFS2 node-type corroboration now rejects
 * roughly two thirds of them: the ~510 `jffs2-le` / `jffs2-be` coincidences whose following word is not a valid
 * node type. The remaining ~258 `pe-mz` hits honestly survive because that two-byte rule has no structural check
 * to run, but they remain on the bottom rung rather than looking equivalent to corroborated format evidence.
 *
 * On a real ELF (`/usr/lib/.../ld-linux-x86-64.so.2`) the same scan keeps the genuine header at offset 0 at
 * `consistent` and drops a coincidental `\x7fELF` inside the file — the shape this is supposed to have.
 *
 * The classifier consumes the same pure JFFS2 predicate as the scanner and rechecks even persisted legacy hits,
 * so a future scanner refactor cannot silently loosen the identity decision.
 */
describe('rubric behaviour on unstructured bytes', () => {
  /** Deterministic xorshift32 so the measurement is a regression test and not a dice roll. */
  function pseudoRandom(size: number, seed = 0x1a2b3c4d): Uint8Array {
    const buf = new Uint8Array(size);
    let x = seed;
    for (let i = 0; i < size; i++) {
      x ^= x << 13;
      x ^= x >>> 17;
      x ^= x << 5;
      buf[i] = x & 0xff;
    }
    return buf;
  }

  it('lets noise match, but never lets it above the bottom rung', () => {
    const scan = scanSignaturesDetailed(pseudoRandom(4 * 1024 * 1024), { maxHits: Number.MAX_SAFE_INTEGER });
    // Not a vacuous pass: random bytes really do trip the short magics, which is the whole problem.
    expect(scan.hits.length).toBeGreaterThan(50);
    const promoted = scan.hits.filter((h) => h.tier !== 'magic');
    expect(promoted.map((h) => `${h.id}@${h.offset}`)).toEqual([]);
    // And every surviving rule is a short, uncheckable magic — if a new rule starts surviving here, it needs one.
    for (const h of scan.hits) expect(h.rationale).toBeUndefined();
  });
});

describe('MediaTek LK scanner bounds', () => {
  function lk(): Uint8Array {
    const bytes = new Uint8Array(513).fill(0xff);
    bytes.set([0x88, 0x16, 0x88, 0x58, 1, 0, 0, 0]);
    bytes.fill(0, 8, 44);
    bytes[40] = 1;
    return bytes;
  }

  it('keeps embedded LK hits past the listing cap and counts malformed candidates', () => {
    const bytes = new Uint8Array(1200);
    bytes.set(lk(), 13);
    bytes.set([0x88, 0x16, 0x88, 0x58], 1000);
    const scan = scanSignaturesDetailed(bytes, { maxHits: 0 });
    expect(scan.hits.find((hit) => hit.id === 'mediatek-lk')).toMatchObject({
      offset: 13,
      tier: 'consistent',
      category: 'container',
      meta: { size: 513, payloadSize: 1, loadAddr: 1, mode: 0xffffffff, name: '' },
    });
    expect(scan.matched).toBe(2);
    expect(scan.rejected).toBe(1);
    expect(scan.rejectedByRule?.['mediatek-lk']).toBe(1);
    expect(scan.distinctIds).toBe(1);
    expect(scan.hits[0]?.rationale).toMatch(/no checksum.*no authenticity/i);
  });

  it('counts every incomplete LK candidate before the cap, without inventing a checksum tier', () => {
    const complete = lk();
    for (let length = 4; length < complete.length; length++) {
      const scan = scanSignaturesDetailed(complete.subarray(0, length), { maxHits: 0 });
      expect(
        scan.hits.some((hit) => hit.id === 'mediatek-lk'),
        `length ${length}`,
      ).toBe(false);
      expect(scan.matched).toBe(1);
      expect(scan.rejectedByRule?.['mediatek-lk']).toBe(1);
    }
    complete[512] = 0;
    expect(scanSignatures(complete).find((hit) => hit.id === 'mediatek-lk')?.tier).toBe('consistent');
  });

  it('does not treat incidental vendor strings, generic uImage or BootROM names as LK headers', () => {
    const bytes = new Uint8Array(600);
    bytes.set(Buffer.from('MediaTek MTK LK_PART_MAGIC SF_BOOT EMMC_BOOT SDMMC_BOOT BRLYT FILE_INFO'));
    bytes.set([0x27, 0x05, 0x19, 0x56], 200);
    expect(scanSignatures(bytes).some((hit) => hit.id === 'mediatek-lk')).toBe(false);
  });
});

describe('MediaTek BootROM envelope scanner bounds', () => {
  it.each(BROM_RULES)(
    'keeps an embedded %s hit past the listing cap and counts malformed candidates',
    (id, name, type) => {
      const envelope = bromEnvelope(name, type);
      const bytes = new Uint8Array(envelope.length + 600);
      bytes.set(envelope, 13);
      bytes.set([...ascii(name), 0], envelope.length + 100);
      const scan = scanSignaturesDetailed(bytes, { maxHits: 0 });
      expect(scan.hits.filter((hit) => hit.id.startsWith('mediatek-'))).toEqual([
        expect.objectContaining({
          id,
          offset: 13,
          tier: 'consistent',
          category: 'container',
          meta: expect.objectContaining({
            size: envelope.length,
            payloadSize: 1,
            loadAddr: 0x400,
            digest: 'not_verified',
          }),
          rationale: expect.stringMatching(/SHA-256 field.*not verified.*no integrity, authenticity/i),
        }),
      ]);
      expect(scan.rejectedByRule?.[id]).toBe(1);
      expect(scan.matched - (scan.rejected ?? 0)).toBe(scan.hits.length);
    },
  );

  it('counts every incomplete envelope candidate before the cap, without inventing a verified tier', () => {
    const complete = bromEnvelope('SF_BOOT', 0x10007);
    for (let length = 8; length < complete.length; length++) {
      const scan = scanSignaturesDetailed(complete.subarray(0, length), { maxHits: 0 });
      expect(
        scan.hits.some((hit) => hit.id === 'mediatek-brom-nor'),
        `length ${length}`,
      ).toBe(false);
      expect(scan.rejectedByRule?.['mediatek-brom-nor']).toBe(1);
    }
    expect(scanSignatures(complete).find((hit) => hit.id === 'mediatek-brom-nor')?.tier).toBe('consistent');
  });

  it('identifies nothing else in a complete envelope, and LK and BootROM never stand in for each other', () => {
    const envelope = bromEnvelope('EMMC_BOOT', 0x10005);
    expect(scanSignatures(envelope).map((hit) => hit.id)).toEqual(['mediatek-brom-emmc']);
    const lk = new Uint8Array(513).fill(0xff);
    lk.set([0x88, 0x16, 0x88, 0x58, 1, 0, 0, 0]);
    lk.fill(0, 8, 44);
    lk[40] = 1;
    expect(scanSignatures(lk).some((hit) => hit.id.startsWith('mediatek-brom-'))).toBe(false);
  });

  it('does not treat incidental vendor strings, generic uImage or bare names as a BootROM envelope', () => {
    const bytes = new Uint8Array(0x1200);
    bytes.set(ascii('MediaTek MTK SF_BOOT EMMC_BOOT SDMMC_BOOT BRLYT FILE_INFO MMM'));
    bytes.set([...ascii('SF_BOOT'), 0, ...ascii('EMMC_BOOT'), 0, ...ascii('SDMMC_BOOT'), 0], 100);
    bytes.set([0x27, 0x05, 0x19, 0x56], 200);
    bytes.set([...ascii('BRLYT'), 0, 0, 0, 1, 0, 0, 0], 0x400);
    const scan = scanSignaturesDetailed(bytes);
    expect(scan.hits.some((hit) => hit.id.startsWith('mediatek-'))).toBe(false);
    expect(scan.rejectedByRule?.['mediatek-brom-nor']).toBe(1);
    expect(scan.rejectedByRule?.['mediatek-brom-emmc']).toBe(1);
    expect(scan.rejectedByRule?.['mediatek-brom-sdmmc']).toBe(1);
  });
});

describe('Realtek cvimg scanner bounds', () => {
  it('keeps embedded cs6c/cr6c hits past the listing cap, counts malformed candidates, never verifies', () => {
    const first = cvimgImage('cs6c', 7);
    const second = cvimgImage('cr6c', 0, 0, 0);
    const bytes = new Uint8Array(400).fill(0xee);
    bytes.set(first, 13);
    bytes.set(second, 200);
    bytes.set(ascii('cs6c'), 300); // trailing incidental signature: zeroed fields are rejected
    bytes.fill(0, 304, 316);
    const scan = scanSignaturesDetailed(bytes, { maxHits: 0 });
    expect(scan.hits.filter((hit) => hit.id.startsWith('realtek-'))).toEqual([
      expect.objectContaining({
        id: 'realtek-cvimg-cs6c',
        offset: 13,
        tier: 'consistent',
        score: 85,
        category: 'container',
        meta: {
          size: 26,
          declaredLength: 10,
          producerOption: 'linux',
          startAddr: 0x80500000,
          burnAddr: 0x30000,
          checksumOffset: 24,
          checksum: 'not_verified',
        },
        rationale: expect.stringMatching(/checksum.*not verified.*no integrity, authenticity or device\/runtime/i),
      }),
      expect.objectContaining({ id: 'realtek-cvimg-cr6c', offset: 200, tier: 'consistent' }),
    ]);
    expect(scan.rejectedByRule?.['realtek-cvimg-cs6c']).toBe(1);
    expect(scan.matched - (scan.rejected ?? 0)).toBe(scan.hits.length);
  });

  it('counts every truncation of a candidate before the cap, and a wrong checksum keeps the same tier', () => {
    const complete = cvimgImage('cs6c', 6);
    for (let length = 4; length < complete.length; length++) {
      const scan = scanSignaturesDetailed(complete.subarray(0, length), { maxHits: 0 });
      expect(
        scan.hits.some((hit) => hit.id === 'realtek-cvimg-cs6c'),
        `length ${length}`,
      ).toBe(false);
      expect(scan.rejectedByRule?.['realtek-cvimg-cs6c']).toBe(1);
    }
    const wrongSum = cvimgImage('cs6c', 6);
    wrongSum[wrongSum.length - 1] ^= 0xff;
    expect(scanSignatures(wrongSum).find((hit) => hit.id === 'realtek-cvimg-cs6c')?.tier).toBe('consistent');
  });

  it('does not match csys/csro/CSYS, other cvimg signatures, or incidental Realtek strings', () => {
    const bytes = new Uint8Array(600);
    bytes.set(ascii('Realtek RTL8196C cvimg cs6 cr6 CS6C CR6C Cs6c'));
    let at = 100;
    for (const sig of ['csys', 'csro', 'CSYS', 'cs6b', 'cr6b', 'r6cr', 'boot', 'allp']) {
      bytes.set(cvimgImage(sig, 4), at);
      at += 40;
    }
    const scan = scanSignaturesDetailed(bytes);
    expect(scan.hits.some((hit) => hit.id.startsWith('realtek-'))).toBe(false);
    expect(scan.rejectedByRule?.['realtek-cvimg-cs6c']).toBeUndefined();
  });
});

/**
 * A uImage match the scanner will not list must not pay for a CRC over its whole payload.
 *
 * The listing cap stops the scan ADDING rows, never looking, so every match still runs its rule's check — and the
 * uImage check's last step is a CRC over the declared payload. N header-CRC-valid uImage headers that each declare
 * "the rest of the buffer" therefore cost O(N × length) even when only one row is listed: the payload CRC only ever
 * chooses between `consistent` and `verified`, a tier an unlisted match never shows. These tests count the bytes
 * the scan actually indexes (a transparent proxy over the caller's buffer, no production hook), compare every
 * capped result against an uncapped control, and never assert on time.
 */
describe('unlisted uImage matches skip the payload CRC, nothing else', () => {
  const crc = (b: Uint8Array): number => zlib.crc32(b) >>> 0;
  const uimageRule = SIGNATURE_RULES.find((r) => r.id === 'uimage');

  /** Write a uImage header at `off` declaring `size` payload bytes; the payload must already be final. */
  function writeUimage(buf: Buffer, off: number, size: number, opts: { badHeader?: boolean; badData?: boolean } = {}) {
    buf.fill(0, off, Math.min(buf.length, off + 64));
    buf.writeUInt32BE(0x27051956, off);
    buf.writeUInt32BE(size, off + 12);
    buf.writeUInt32BE(0x80008000, off + 16);
    const end = Math.min(buf.length, off + 64 + size);
    buf.writeUInt32BE(opts.badData ? 0xdeadbeef : crc(buf.subarray(off + 64, end)), off + 24);
    buf.writeUInt32BE(opts.badHeader ? 0x12345678 : crc(buf.subarray(off, off + 64)), off + 4);
  }

  /**
   * Synthetic, inert bytes: `count` headers, `stride` apart, each declaring the REST of the buffer as its payload.
   * Written last-to-first so each header's payload (which contains every later header) is final when its CRC is
   * taken — every header and payload CRC is legitimate unless `opts` breaks the first one.
   */
  function stacked(
    length: number,
    count: number,
    stride: number,
    first: { badHeader?: boolean; badData?: boolean } = {},
  ) {
    const buf = Buffer.alloc(length);
    for (let i = 0; i < length; i++) buf[i] = (i * 131 + 17) & 0x7f;
    for (let i = count - 1; i >= 0; i--) {
      const off = i * stride;
      writeUimage(buf, off, length - off - 64, i === 0 ? first : {});
    }
    return buf;
  }

  /** Counts indexed reads through the scanner; typed-array methods are bound to the real buffer. */
  function counted(target: Uint8Array): { view: Uint8Array; reads: () => number } {
    let reads = 0;
    const view = new Proxy(target, {
      get(t, prop) {
        if (typeof prop === 'string') {
          const c = prop.charCodeAt(0);
          if (c >= 48 && c <= 57) {
            reads++;
            return t[Number(prop)];
          }
        }
        const v = Reflect.get(t, prop, t);
        return typeof v === 'function' ? v.bind(t) : v;
      },
    });
    return { view, reads: () => reads };
  }

  function scanCounted(buf: Uint8Array, maxHits: number) {
    const { view, reads } = counted(buf);
    const scan = scanSignaturesDetailed(view, { maxHits });
    return { scan, reads: reads() };
  }

  const ALL = Number.MAX_SAFE_INTEGER;
  /** Everything but the list must equal the uncapped scan, and every listed row must equal its uncapped twin. */
  function expectSameAsUncapped(buf: Uint8Array, maxHits: number) {
    const capped = scanSignaturesDetailed(buf, { maxHits });
    const full = scanSignaturesDetailed(buf, { maxHits: ALL });
    expect(capped.matched).toBe(full.matched);
    expect(capped.rejected).toBe(full.rejected);
    expect(capped.rejectedByRule).toEqual(full.rejectedByRule);
    expect(capped.distinctIds).toBe(full.distinctIds);
    expect(new Set(capped.hits.map((h) => h.id))).toEqual(new Set(full.hits.map((h) => h.id)));
    for (const hit of capped.hits) {
      expect(hit).toEqual(full.hits.find((h) => h.offset === hit.offset && h.id === hit.id));
    }
    return { capped, full };
  }

  it.each([
    [16, 64 * 1024, 4096],
    [64, 64 * 1024, 1024],
    [128, 64 * 1024, 512],
  ])('reads each byte a bounded number of times under maxHits 0 with %i stacked headers', (count, length, stride) => {
    const buf = stacked(length, count, stride);
    const capped = scanCounted(buf, 0);
    const control = scanCounted(buf, ALL);
    // The control lists every header, so it pays every payload CRC: about count × length / 2 reads.
    expect(control.reads).toBeGreaterThan((count * length) / 4);
    // Capped: one pass, the listed first header's payload, and header-sized work per unlisted match. Generous.
    expect(capped.reads).toBeLessThan(6 * length);
    expect(capped.scan.hits.filter((h) => h.id === 'uimage')).toEqual([
      expect.objectContaining({ offset: 0, tier: 'verified', score: 99 }),
    ]);
    expect(control.scan.hits.filter((h) => h.id === 'uimage' && h.tier === 'verified')).toHaveLength(count);
    expect(control.scan.rejectedByRule?.uimage).toBeUndefined();
    expectSameAsUncapped(buf, 0);
  });

  it('leaves every listed row, counter and the id set unchanged at caps 0, 1, 16 and the default', () => {
    const buf = stacked(32 * 1024, 64, 512);
    for (const cap of [0, 1, 16, 5000]) expectSameAsUncapped(buf, cap);
    // The default lists all 64, so it is the old behaviour by construction: every header is fully verified.
    const listed = scanSignaturesDetailed(buf).hits.filter((h) => h.id === 'uimage');
    expect(listed).toHaveLength(64);
    expect(listed.every((h) => h.tier === 'verified' && /payload CRC both recompute/.test(h.rationale ?? ''))).toBe(
      true,
    );
    expect(listed[0]?.meta).toEqual({ dataSize: 32 * 1024 - 64, loadAddr: '80008000', osCode: 0, archCode: 0 });
  });

  it('shows a payload mismatch or a header mismatch on the listed hit exactly as before', () => {
    const badData = stacked(16 * 1024, 32, 512, { badData: true });
    const { capped } = expectSameAsUncapped(badData, 0);
    const first = capped.hits.find((h) => h.id === 'uimage');
    expect(first).toMatchObject({ offset: 0, tier: 'consistent' });
    expect(first?.rationale).toMatch(/modified or re-packed/);

    const badHeader = stacked(16 * 1024, 32, 512, { badHeader: true });
    expect(expectSameAsUncapped(badHeader, 0).capped.hits.find((h) => h.id === 'uimage')).toMatchObject({
      offset: 0,
      tier: 'magic',
    });
  });

  it('counts a truncated header and an out-of-bounds payload without rejecting either, capped or not', () => {
    const buf = stacked(8 * 1024, 8, 512);
    const tail = Buffer.alloc(8 * 1024 + 100);
    buf.copy(tail);
    writeUimage(tail, 8 * 1024, 0x7fffffff); // declared payload runs far past the buffer
    tail.writeUInt32BE(0x27051956, tail.length - 20); // header itself runs past the end
    const { capped, full } = expectSameAsUncapped(tail, 0);
    expect(full.hits.find((h) => h.offset === 8 * 1024)?.rationale).toMatch(/runs past this buffer/);
    expect(full.hits.find((h) => h.offset === tail.length - 20)?.tier).toBe('magic');
    expect(capped.rejectedByRule?.uimage).toBeUndefined();
  });

  it('fully verifies the first hit of a rule that appears only after the list is full', () => {
    // Listed uImage first, then 40 unlisted ones, then a TRX nobody has seen: it is listed and checks its CRC.
    const head = stacked(32 * 1024, 40, 512);
    const trx = Buffer.alloc(0x400, 0x5a);
    trx.write('HDR0', 0, 'latin1');
    trx.writeUInt32LE(0x400, 4);
    trx.writeUInt32LE(28, 16);
    trx.writeUInt32LE(~crc(trx.subarray(12, 0x400)) >>> 0, 8);
    const buf = Buffer.concat([head, trx]);
    const { capped } = expectSameAsUncapped(buf, 0);
    expect(capped.hits.find((h) => h.id === 'trx')).toMatchObject({ offset: 32 * 1024, tier: 'verified' });

    // The reverse: other ids fill the list first, and the first uImage still pays for its whole payload.
    const late = Buffer.alloc(64 * 1024);
    for (let i = 0; i < 8; i++) late.write('hsqs', i * 64, 'latin1');
    for (let i = 4096; i < late.length; i++) late[i] = (i * 7) & 0x7f;
    writeUimage(late, 4096, late.length - 4096 - 64);
    const { scan, reads } = scanCounted(late, 1);
    expect(scan.hits.find((h) => h.id === 'uimage')).toMatchObject({ offset: 4096, tier: 'verified' });
    expect(reads).toBeGreaterThan(late.length - 4096); // the scan pass plus the full payload CRC
    expectSameAsUncapped(late, 1);
  });

  it('keeps the direct registry check whole, and the unlisted one agrees with it on every reject-or-survive', () => {
    const verify = uimageRule?.verify;
    const unlisted = uimageRule?.verifyUnlisted;
    if (!verify || !unlisted) throw new Error('uimage rule lost its checks');
    const good = stacked(4096, 1, 0);
    expect(verify(good, 0)).toEqual({
      tier: 'verified',
      why: `header CRC and the ${4096 - 64}-byte payload CRC both recompute to the declared values`,
    });
    expect(unlisted(good, 0).tier).toBe('consistent');
    expect(unlisted(good, 0).why).toMatch(/not computed for an unlisted match/);
    const variants = [
      good,
      stacked(4096, 1, 0, { badData: true }),
      stacked(4096, 1, 0, { badHeader: true }),
      good.subarray(0, 4000),
      good.subarray(0, 40),
    ];
    for (const buf of variants) {
      const full = verify(buf, 0);
      const cheap = unlisted(buf, 0);
      expect(cheap.tier === 'rejected').toBe(full.tier === 'rejected');
      // Header-level verdicts are identical; only the payload rung (consistent vs verified) is withheld.
      if (/not computed/.test(cheap.why)) expect(['consistent', 'verified']).toContain(full.tier);
      else expect(cheap).toEqual(full);
    }
    // Each rule with the hook needs its own agreement test like this one (TRX and TP-Link v1 have theirs below).
    expect(SIGNATURE_RULES.filter((r) => r.verifyUnlisted).map((r) => r.id)).toEqual(['uimage', 'trx', 'tplink-v1']);
  });

  it('never mutates the caller buffer', () => {
    const buf = stacked(16 * 1024, 32, 512);
    const before = Buffer.from(buf);
    scanSignaturesDetailed(buf, { maxHits: 0 });
    scanSignaturesDetailed(buf);
    expect(buf.equals(before)).toBe(true);
  });
});

/**
 * TRX (HDR0) and TP-Link v1 matches the scanner will not list must not pay for their checksum either.
 *
 * Same omitted-row gap as the uImage unit above: the TRX CRC and the TP-Link salted MD5 only ever choose between a
 * shown tier and a better one, so after the listing cap N headers that each declare the rest of the buffer cost
 * O(N × length) for nothing anyone sees. The oracle here is the scan WITHOUT the two hooks (removed for one call,
 * test-only), so "unchanged" is checked against the old behaviour itself, not against a fixture's expectation.
 * Work is counted, never timed: indexed reads for the TRX CRC (a JS loop over the buffer), and requested
 * `subarray` spans for TP-Link, whose copy and MD5 run over a native copy the read proxy cannot see.
 */
describe('unlisted TRX and TP-Link v1 matches skip the checksum, nothing else', () => {
  const crc = (b: Uint8Array): number => zlib.crc32(b) >>> 0;
  const HOOKED = ['trx', 'tplink-v1'] as const;
  const ruleOf = (id: string) => {
    const rule = SIGNATURE_RULES.find((r) => r.id === id);
    if (!rule?.verify || !rule.verifyUnlisted) throw new Error(`${id} lost its checks`);
    return { verify: rule.verify, unlisted: rule.verifyUnlisted };
  };
  const SALTS = { normal: 'dcd73aa5c39598fbddf9e7f40eae4738', boot: '8cef335bd5c5cefaa79c28dab2e90f42' } as const;

  /** The scan as it was before this unit: the two hooks removed for one call, then put back. */
  function withoutHooks<T>(fn: () => T): T {
    const saved = HOOKED.map((id) => {
      const rule = SIGNATURE_RULES.find((r) => r.id === id) as { verifyUnlisted?: unknown };
      const hook = rule.verifyUnlisted;
      rule.verifyUnlisted = undefined;
      return [rule, hook] as const;
    });
    try {
      return fn();
    } finally {
      for (const [rule, hook] of saved) rule.verifyUnlisted = hook;
    }
  }

  const pattern = (length: number) => {
    const buf = Buffer.alloc(length);
    for (let i = 0; i < length; i++) buf[i] = (i * 131 + 17) & 0x7f;
    return buf;
  };

  /** `count` TRX headers `stride` apart, each declaring the rest of the buffer; written last-to-first. */
  function stackedTrx(
    length: number,
    count: number,
    stride: number,
    o: { badFirst?: boolean; rejectEvery?: number } = {},
  ) {
    const buf = pattern(length);
    for (let i = count - 1; i >= 0; i--) {
      const off = i * stride;
      buf.fill(0, off, off + 28);
      buf.write('HDR0', off, 'latin1');
      const reject = o.rejectEvery !== undefined && i > 0 && i % o.rejectEvery === 0;
      buf.writeUInt32LE(reject ? 4 : length - off, off + 4);
      buf.writeUInt32LE(28, off + 16);
      buf.writeUInt32LE(i === 0 && o.badFirst ? 1 : ~crc(buf.subarray(off + 12, length)) >>> 0, off + 8);
    }
    return buf;
  }

  /** `count` TP-Link v1 headers, each signing the rest of the buffer under alternating salts; last-to-first. */
  function stackedTplink(
    length: number,
    count: number,
    stride: number,
    o: { first?: 'normal' | 'boot' | 'none'; rejectEvery?: number } = {},
  ) {
    const buf = pattern(length);
    for (let i = count - 1; i >= 0; i--) {
      const off = i * stride;
      const len = length - off;
      buf.fill(0, off, off + 0x200);
      Buffer.from([1, 0, 0, 0]).copy(buf, off);
      buf.write('TP-LINK Technologies', off + 4, 'latin1');
      const reject = o.rejectEvery !== undefined && i > 0 && i % o.rejectEvery === 0;
      buf.writeUInt32BE(len, off + 0x7c);
      buf.writeUInt32BE(0x200, off + 0x80);
      buf.writeUInt32BE(reject ? len : 0x100, off + 0x84); // a rejected one's kernel runs past its declared length
      const salt = i === 0 ? (o.first ?? 'normal') : i % 2 ? 'boot' : 'normal';
      Buffer.from(salt === 'none' ? '00'.repeat(16) : SALTS[salt], 'hex').copy(buf, off + 0x4c);
      crypto
        .createHash('md5')
        .update(buf.subarray(off, length))
        .digest()
        .copy(buf, off + 0x4c);
    }
    return buf;
  }

  /** Test-only instrumentation: indexed reads, and the byte span of every `subarray` the scan requests. */
  function counted(target: Uint8Array) {
    let reads = 0;
    let spans = 0;
    const view = new Proxy(target, {
      get(t, prop) {
        if (typeof prop === 'string') {
          const c = prop.charCodeAt(0);
          if (c >= 48 && c <= 57) {
            reads++;
            return t[Number(prop)];
          }
        }
        if (prop === 'subarray') {
          return (a?: number, b?: number) => {
            const sub = t.subarray(a, b);
            spans += sub.length;
            return sub;
          };
        }
        const v = Reflect.get(t, prop, t);
        return typeof v === 'function' ? v.bind(t) : v;
      },
    });
    return { view, work: () => ({ reads, spans }) };
  }
  const work = (buf: Uint8Array, maxHits: number) => {
    const { view, work: w } = counted(buf);
    const scan = scanSignaturesDetailed(view, { maxHits });
    return { scan, ...w() };
  };

  it('reads each byte a bounded number of times for 32 stacked TRX headers under maxHits 0', () => {
    const length = 128 * 1024;
    const buf = stackedTrx(length, 32, 4096);
    const capped = work(buf, 0);
    const before = withoutHooks(() => work(buf, 0));
    // RED baseline: before the hook the capped scan paid every CRC, about 32 × length / 2 reads.
    expect(before.reads).toBeGreaterThan((32 * length) / 4);
    expect(capped.reads).toBeLessThan(6 * length);
    expect(capped.scan).toEqual(before.scan);
    expect(capped.scan.hits.filter((h) => h.id === 'trx')).toEqual([
      expect.objectContaining({ offset: 0, tier: 'verified' }),
    ]);
  });

  it('requests a bounded copy span for 32 stacked TP-Link v1 headers under maxHits 0', () => {
    const length = 128 * 1024;
    const buf = stackedTplink(length, 32, 4096);
    const capped = work(buf, 0);
    const before = withoutHooks(() => work(buf, 0));
    // RED baseline: before the hook every unlisted header copied its whole declared length for the salted MD5.
    expect(before.spans).toBeGreaterThan((32 * length) / 4);
    // Capped: the listed first header's full copy, plus 16-byte stored-digest views and small header views.
    expect(capped.spans).toBeLessThan(3 * length);
    expect(capped.scan).toEqual(before.scan);
    expect(capped.scan.hits.filter((h) => h.id === 'tplink-v1')).toEqual([
      expect.objectContaining({ offset: 0, tier: 'verified' }),
    ]);
  });

  const fixtures: Array<[string, () => Uint8Array]> = [
    ['valid TRX stack', () => stackedTrx(32 * 1024, 24, 1024)],
    [
      'TRX stack, bad first CRC, some rejected',
      () => stackedTrx(32 * 1024, 24, 1024, { badFirst: true, rejectEvery: 3 }),
    ],
    ['valid TP-Link stack', () => stackedTplink(32 * 1024, 24, 1024)],
    [
      'TP-Link stack, unsalted first, some rejected',
      () => stackedTplink(32 * 1024, 24, 1024, { first: 'none', rejectEvery: 3 }),
    ],
    ['TP-Link boot-salted first', () => stackedTplink(16 * 1024, 8, 1024, { first: 'boot' })],
    [
      'mixed TRX, TP-Link and uImage-free filler, truncated tails',
      () => {
        const head = Buffer.concat([
          stackedTrx(16 * 1024, 12, 1024, { rejectEvery: 4 }),
          stackedTplink(16 * 1024, 12, 1024, { rejectEvery: 5 }),
        ]);
        const tail = Buffer.alloc(0x300, 0x11);
        tail.write('HDR0', 0x10, 'latin1'); // huge declared length: rejected by the base rule both ways
        tail.writeUInt32LE(0x7fffffff, 0x14);
        Buffer.from([1, 0, 0, 0, ...Buffer.from('TP-LINK Technologies', 'latin1')]).copy(tail, 0x200); // header past end
        return Buffer.concat([head, tail]);
      },
    ],
  ];
  const CAPS: Array<number | undefined> = [undefined, 0, 1, 0.5, -1, Number.POSITIVE_INFINITY, Number.NaN, 5000];

  it.each(fixtures)('equals the pre-hook scan as whole JSON at every cap and confidence filter: %s', (_name, make) => {
    const buf = make();
    const before = Buffer.from(buf);
    for (const maxHits of CAPS) {
      for (const highConfidenceOnly of [undefined, false, true]) {
        const options = {
          ...(maxHits === undefined ? {} : { maxHits }),
          ...(highConfidenceOnly === undefined ? {} : { highConfidenceOnly }),
        };
        const now = scanSignaturesDetailed(buf, options);
        const old = withoutHooks(() => scanSignaturesDetailed(buf, options));
        expect(now).toEqual(old);
        expect(JSON.stringify(now)).toBe(JSON.stringify(old));
        expect(inferIdentity(buf, now.hits)).toEqual(inferIdentity(buf, old.hits));
        const full = scanSignaturesDetailed(buf, { ...options, maxHits: Number.POSITIVE_INFINITY });
        expect(now.matched).toBe(full.matched);
        expect(now.rejected).toBe(full.rejected);
        expect(now.rejectedByRule).toEqual(full.rejectedByRule);
        expect(now.distinctIds).toBe(full.distinctIds);
        expect(new Set(now.hits.map((h) => h.id))).toEqual(new Set(full.hits.map((h) => h.id)));
        expect(now.hits.every((h) => !/not computed for an unlisted match/.test(h.rationale ?? ''))).toBe(true);
      }
    }
    expect(Buffer.from(buf).equals(before)).toBe(true);
  });

  it('shows the checksum positive and mismatch on the listed row exactly as before', () => {
    const trxBad = scanSignaturesDetailed(stackedTrx(16 * 1024, 16, 1024, { badFirst: true }), { maxHits: 0 });
    expect(trxBad.hits.find((h) => h.id === 'trx')).toMatchObject({ offset: 0, tier: 'structural' });
    expect(trxBad.hits.find((h) => h.id === 'trx')?.rationale).toMatch(/does not match — suspicious, not rejected/);
    const tpNone = scanSignaturesDetailed(stackedTplink(16 * 1024, 16, 1024, { first: 'none' }), { maxHits: 0 });
    expect(tpNone.hits.find((h) => h.id === 'tplink-v1')).toMatchObject({ offset: 0, tier: 'structural' });
    expect(tpNone.hits.find((h) => h.id === 'tplink-v1')?.rationale).toMatch(/matches neither salt/);
    const tpBoot = scanSignaturesDetailed(stackedTplink(16 * 1024, 16, 1024, { first: 'boot' }), { maxHits: 0 });
    expect(tpBoot.hits.find((h) => h.id === 'tplink-v1')?.rationale).toMatch(/recomputes \(boot salt\)/);
    // No unlisted-only rationale ever reaches a row, at any cap.
    for (const scan of [trxBad, tpNone, tpBoot]) {
      expect(scan.hits.some((h) => /not computed for an unlisted match/.test(h.rationale ?? ''))).toBe(false);
    }
  });

  it('fully verifies the first hit of each rule when it appears only after the list is full', () => {
    // 20 unlisted TRX headers fill the list's only slot, then the first TP-Link header: listed, MD5 computed.
    const buf = Buffer.concat([stackedTrx(24 * 1024, 20, 1024), stackedTplink(8 * 1024, 4, 1024)]);
    const { scan, spans } = work(buf, 1);
    expect(scan.hits.find((h) => h.id === 'tplink-v1')).toMatchObject({ offset: 24 * 1024, tier: 'verified' });
    expect(spans).toBeGreaterThanOrEqual(8 * 1024); // its full declared length was copied for the MD5
    expect(scan).toEqual(withoutHooks(() => scanSignaturesDetailed(buf, { maxHits: 1 })));
    // The reverse: TP-Link fills the list, and the first TRX still pays for its whole CRC.
    const rev = Buffer.concat([stackedTplink(24 * 1024, 20, 1024), stackedTrx(32 * 1024, 4, 1024)]);
    const r = work(rev, 1);
    expect(r.scan.hits.find((h) => h.id === 'trx')).toMatchObject({ offset: 24 * 1024, tier: 'verified' });
    expect(r.reads).toBeGreaterThan(rev.length + 32 * 1024 - 64); // the scan pass plus the full CRC
    expect(r.scan).toEqual(withoutHooks(() => scanSignaturesDetailed(rev, { maxHits: 1 })));
  });

  it('keeps the direct registry checks whole, ignoring extra arguments, and agrees on every reject-or-survive', () => {
    const trx = ruleOf('trx');
    const tp = ruleOf('tplink-v1');
    const goodTrx = stackedTrx(4096, 1, 0);
    const goodTp = stackedTplink(4096, 1, 0);
    expect(trx.verify(goodTrx, 0).tier).toBe('verified');
    expect(tp.verify(goodTp, 0)).toEqual({
      tier: 'verified',
      why: 'layout fits and the salted MD5 over 4096 bytes recomputes (normal salt)',
    });
    // An accidental third argument must never select the cheap form.
    const loose = (f: unknown) => f as (...args: unknown[]) => { tier: string };
    expect(loose(trx.verify)(goodTrx, 0, false).tier).toBe('verified');
    expect(loose(tp.verify)(goodTp, 0, false).tier).toBe('verified');
    expect(loose(tp.unlisted)(goodTp, 0, true).tier).toBe('structural');
    expect(tp.unlisted(goodTp, 0).why).toMatch(/not computed for an unlisted match/);

    const trxVariant = (edit: (b: Buffer) => void, src = goodTrx) => {
      const b = Buffer.from(src);
      edit(b);
      return b;
    };
    const trxCases = [
      goodTrx,
      stackedTrx(4096, 1, 0, { badFirst: true }),
      goodTrx.subarray(0, 4000), // payload past the buffer
      goodTrx.subarray(0, 20), // header itself truncated
      trxVariant((b) => b.writeUInt32LE(0, 4)), // length 0
      trxVariant((b) => b.writeUInt32LE(27, 4)),
      trxVariant((b) => b.writeUInt32LE(0x7fffffff, 4)), // huge
      trxVariant((b) => b.writeUInt32LE(256 * 1024 * 1024, 4)), // maximum plausible, unavailable bytes
      trxVariant((b) => b.writeUInt32LE(256 * 1024 * 1024 + 1, 4)),
      trxVariant((b) => b.writeUInt32LE(5000, 16)), // first partition outside the image
      trxVariant((b) => b.writeUInt32LE(12, 16)),
    ];
    const tpVariant = (edit: (b: Buffer) => void) => {
      const b = Buffer.from(goodTp);
      edit(b);
      return b;
    };
    const tpCases = [
      goodTp,
      stackedTplink(4096, 1, 0, { first: 'boot' }),
      stackedTplink(4096, 1, 0, { first: 'none' }),
      goodTp.subarray(0, 4000), // declared length past the buffer
      goodTp.subarray(0, 0x1ff), // header itself truncated
      tpVariant((b) => b.writeUInt32BE(0, 0x7c)), // length 0
      tpVariant((b) => b.writeUInt32BE(0x1ff, 0x7c)),
      tpVariant((b) => b.writeUInt32BE(0x7fffffff, 0x7c)), // huge
      tpVariant((b) => b.writeUInt32BE(256 * 1024 * 1024, 0x7c)), // maximum plausible, unavailable bytes
      tpVariant((b) => b.writeUInt32BE(256 * 1024 * 1024 + 1, 0x7c)),
      tpVariant((b) => b.writeUInt32BE(4096, 0x84)), // kernel past the declared length
      tpVariant((b) => {
        b.writeUInt32BE(0xfff, 0x88);
        b.writeUInt32BE(2, 0x8c);
      }), // rootfs past the declared length
    ];
    for (const [rule, cases] of [
      [trx, trxCases],
      [tp, tpCases],
    ] as const) {
      for (const buf of cases) {
        const full = rule.verify(buf, 0);
        const cheap = rule.unlisted(buf, 0);
        expect(cheap.tier === 'rejected').toBe(full.tier === 'rejected');
        // Every pre-checksum verdict is identical; only the checksum rung is withheld.
        if (/not computed/.test(cheap.why) || (rule === trx && cheap.tier === 'consistent')) {
          expect(['structural', 'verified']).toContain(full.tier);
        } else expect(cheap).toEqual(full);
      }
    }
  });

  it('still runs the full fallback verifier on every omitted match of a rule without a hook', () => {
    const rule = SIGNATURE_RULES.find((r) => r.id === 'trx-v2');
    if (!rule?.verify) throw new Error('trx-v2 lost its verifier');
    expect(rule.verifyUnlisted).toBeUndefined();
    const saved = rule.verify;
    let calls = 0;
    rule.verify = (buf, off) => {
      calls++;
      return saved(buf, off);
    };
    try {
      const buf = Buffer.alloc(2048);
      for (let i = 0; i < 16; i++) {
        buf.write('HDR1', i * 64, 'latin1');
        buf.writeUInt32LE(i % 2 ? 0 : 28, i * 64 + 4);
      }
      const scan = scanSignaturesDetailed(buf, { maxHits: 0 });
      expect(calls).toBe(16);
      expect(scan.rejectedByRule['trx-v2']).toBe(8);
      expect(scan.hits.filter((h) => h.id === 'trx-v2')).toHaveLength(1);
    } finally {
      rule.verify = saved;
    }
  });

  it('never mutates the caller buffer', () => {
    for (const buf of [stackedTrx(16 * 1024, 16, 1024), stackedTplink(16 * 1024, 16, 1024)]) {
      const before = Buffer.from(buf);
      scanSignaturesDetailed(buf, { maxHits: 0 });
      scanSignaturesDetailed(buf);
      expect(buf.equals(before)).toBe(true);
    }
  });
});

describe('listing option compatibility', () => {
  it('preserves the legacy NaN listing behavior instead of treating it as a reached cap', () => {
    const bytes = new Uint8Array(192);
    for (const offset of [0, 64, 128]) bytes.set([0x27, 0x05, 0x19, 0x56], offset);
    const full = scanSignaturesDetailed(bytes, { maxHits: 5000 });
    expect(full.hits.filter((hit) => hit.id === 'uimage')).toHaveLength(3);
    expect(scanSignaturesDetailed(bytes, { maxHits: Number.NaN })).toEqual(full);
  });
});

/**
 * The remaining integrity walks, after uImage/TRX/TP-Link gained `verifyUnlisted`: Sercomm's complete-image 8-bit
 * sum, and every other rule's check. Instrumentation is test-only — indexed reads, iterator-yielded bytes (the
 * Sercomm sum is a `for…of`, which a read-counting proxy cannot see), requested `subarray` spans, and the byte length
 * of every `DataView` window (the MediaTek and Realtek parsers read natively through one). Nothing asserts on time.
 */
describe('remaining integrity walks: no unlisted match pays payload-sized work', () => {
  const CAPS = [undefined, 0, 1, 0.5, -1, Number.POSITIVE_INFINITY, Number.NaN, 5000] as const;
  const ALL = Number.MAX_SAFE_INTEGER;

  function filler(length: number): Uint8Array {
    const b = new Uint8Array(length);
    for (let i = 0; i < length; i++) b[i] = (i * 131 + 17) & 0x7f;
    return b;
  }

  function work(target: Uint8Array, maxHits?: number) {
    const w = { reads: 0, iter: 0, spans: 0, windows: 0 };
    const view = new Proxy(target, {
      get(t, prop) {
        if (typeof prop === 'string') {
          const c = prop.charCodeAt(0);
          if (c >= 48 && c <= 57) {
            w.reads++;
            return t[Number(prop)];
          }
        }
        if (prop === Symbol.iterator) {
          return function* () {
            for (const b of t) {
              w.iter++;
              yield b;
            }
          };
        }
        if (prop === 'subarray') {
          return (a?: number, b?: number) => {
            const sub = t.subarray(a, b);
            w.spans += sub.length;
            return sub;
          };
        }
        const v = Reflect.get(t, prop, t);
        return typeof v === 'function' ? v.bind(t) : v;
      },
    });
    const RealDataView = globalThis.DataView;
    globalThis.DataView = class extends RealDataView {
      constructor(buffer: ArrayBufferLike, byteOffset?: number, byteLength?: number) {
        super(buffer, byteOffset, byteLength);
        w.windows += this.byteLength;
      }
    } as DataViewConstructor;
    try {
      const scan = scanSignaturesDetailed(view, maxHits === undefined ? {} : { maxHits });
      return { scan, ...w, total: w.reads + w.iter + w.spans + w.windows };
    } finally {
      globalThis.DataView = RealDataView;
    }
  }

  /** Everything but the list equals the uncapped scan, and every listed row equals its uncapped twin. */
  function expectSameAsUncapped(buf: Uint8Array, maxHits: number | undefined) {
    const capped = scanSignaturesDetailed(buf, maxHits === undefined ? {} : { maxHits });
    const full = scanSignaturesDetailed(buf, { maxHits: ALL });
    expect(capped.matched).toBe(full.matched);
    expect(capped.rejected).toBe(full.rejected);
    expect(capped.rejectedByRule).toEqual(full.rejectedByRule);
    expect(capped.distinctIds).toBe(full.distinctIds);
    expect(new Set(capped.hits.map((h) => h.id))).toEqual(new Set(full.hits.map((h) => h.id)));
    for (const hit of capped.hits) {
      expect(full.hits.find((h) => h.offset === hit.offset && h.id === hit.id)).toEqual(hit);
    }
    return capped;
  }

  /**
   * A mksercommfw-shaped 512-byte prefix at offset 0 (independent of the parser), followed by `others` raw uImage
   * magics so that every cap is reached long before the scan ends. Byte 511 zeroes the complete-image sum last.
   */
  function sercommImage(length: number, others: number, o: { badSum?: boolean; badHeader?: boolean } = {}) {
    const b = filler(length);
    b.fill(0, 0, 512);
    b.set(ascii('sErCoMm'), 0);
    b.set([0, 1, 0, 0], 7);
    b.set(ascii('TEST-HW'), 11);
    b.set(ascii('A1'), 45);
    b.set([1, 2, 3, 4], 55);
    b.set(ascii(o.badHeader ? 'sErCoMX' : 'sErCoMm'), 63);
    for (let i = 0; i < others; i++) b.set([0x27, 0x05, 0x19, 0x56], 1024 + i * 64);
    let sum = 0;
    for (const x of b) sum = (sum + x) & 0xff;
    b[511] = -sum & 0xff;
    if (o.badSum) b[length - 1] = (b[length - 1] as number) ^ 1;
    return b;
  }

  it('anchors Sercomm at offset 0, so its single match is always its first and always listed', () => {
    expect(SIGNATURE_RULES.find((r) => r.id === 'sercomm-prefix')?.atOffset).toBe(0);
    for (const length of [16 * 1024, 64 * 1024]) {
      for (const others of [0, 64]) {
        const buf = sercommImage(length, others);
        const reference = work(buf, ALL);
        for (const cap of CAPS) {
          const measured = work(buf, cap);
          const sercomm = measured.scan.hits.filter((h) => h.id === 'sercomm-prefix');
          expect(sercomm, `cap ${cap}`).toEqual([
            expect.objectContaining({
              offset: 0,
              tier: 'verified',
              meta: expect.objectContaining({ hardwareId: 'TEST-HW' }),
            }),
          ]);
          expect(measured.scan.matched).toBe(1 + others);
          expectSameAsUncapped(buf, cap);
          // The sum is a fixed walk per scan — the same whatever the cap and however many other matches follow.
          expect(measured.iter).toBe(reference.iter);
          expect(measured.iter).toBeLessThanOrEqual(2 * length);
        }
      }
    }
  });

  it('keeps a nonzero Sercomm sum listed as consistent, and a broken header rejected, under every cap', () => {
    const length = 16 * 1024;
    const badSum = sercommImage(length, 32, { badSum: true });
    const badHeader = sercommImage(length, 32, { badHeader: true });
    for (const cap of CAPS) {
      const listed = expectSameAsUncapped(badSum, cap).hits.find((h) => h.id === 'sercomm-prefix');
      expect(listed, `cap ${cap}`).toMatchObject({ offset: 0, tier: 'consistent' });
      expect(listed?.rationale).toMatch(/8-bit sum is nonzero/);
      const rejected = work(badHeader, cap);
      expect(rejected.scan.hits.some((h) => h.id === 'sercomm-prefix')).toBe(false);
      expect(rejected.scan.rejectedByRule?.['sercomm-prefix']).toBe(1);
      expectSameAsUncapped(badHeader, cap);
      // A header that fails its structure never reaches the complete-image sum.
      expect(rejected.iter).toBe(0);
    }
  });

  it('preserves the legacy maxHits NaN listing on a Sercomm image', () => {
    const buf = sercommImage(16 * 1024, 16);
    const full = scanSignaturesDetailed(buf, { maxHits: 5000 });
    expect(full.hits.filter((h) => h.id === 'uimage')).toHaveLength(16);
    expect(scanSignaturesDetailed(buf, { maxHits: Number.NaN })).toEqual(full);
  });

  it('spends the same work per raw-magic match on every rule whatever the buffer length', () => {
    // Up to four copies inside the first 64 KiB; each check's window (RKFW's 16 KiB is the widest) fits in both
    // lengths, so a check whose work followed the declared payload or the buffer end would differ between them.
    const lengths = [80 * 1024, 160 * 1024];
    const baselines = lengths.map((l) => work(filler(l), 0).total);
    for (const rule of SIGNATURE_RULES) {
      const positions = rule.atOffset !== undefined ? [rule.atOffset] : [0, 1, 2, 3].map((i) => i * 16 * 1024);
      const perMatch = lengths.map((length, i) => {
        const buf = filler(length);
        for (const p of positions) buf.set(rule.magic, p);
        return (work(buf, 0).total - (baselines[i] as number)) / positions.length;
      });
      expect(perMatch[1], rule.id).toBe(perMatch[0]);
      expect(perMatch[0], rule.id).toBeLessThanOrEqual(0x4000 + 0x1000);
    }
  }, 60_000);

  /** Valid headers `stride` apart, each declaring the rest of the buffer, for the parsers that accept them. */
  const STACKS: ReadonlyArray<[string, number, (buf: Uint8Array, off: number) => void]> = [
    [
      'mediatek-lk',
      512,
      (buf, off) => {
        const header = new Uint8Array(512).fill(0xff);
        const dv = new DataView(header.buffer);
        dv.setUint32(0, 0x58881688, true);
        dv.setUint32(4, buf.length - off - 512, true);
        header.fill(0, 8, 44);
        header[40] = 1;
        buf.set(header, off);
      },
    ],
    [
      'mediatek-brom-nor',
      0x900,
      (buf, off) => buf.set(bromEnvelope('SF_BOOT', 0x10007, buf.length - off - 0x900 - 32).subarray(0, 0x900), off),
    ],
    [
      'realtek-cvimg-cs6c',
      16,
      (buf, off) => {
        const dv = new DataView(buf.buffer, buf.byteOffset + off, 16);
        buf.set(ascii('cs6c'), off);
        dv.setUint32(4, 0x80500000, false);
        dv.setUint32(8, 0x30000, false);
        dv.setUint32(12, (buf.length - off - 16) & ~1, false);
      },
    ],
  ];

  it.each(STACKS)(
    'reads a constant header, never the declared payload, for stacked valid %s headers',
    (id, header, write) => {
      const lengths = [64 * 1024, 256 * 1024];
      const count = 8;
      const totals = lengths.map((length) => {
        const buf = filler(length);
        for (let i = count - 1; i >= 0; i--) write(buf, i * 0x1000);
        const capped = work(buf, 0);
        const uncapped = work(buf, ALL);
        expect(capped.scan.hits.filter((h) => h.id === id)).toEqual([
          expect.objectContaining({ offset: 0, tier: 'consistent' }),
        ]);
        expect(uncapped.scan.hits.filter((h) => h.id === id)).toHaveLength(count);
        expect(capped.scan.rejectedByRule?.[id]).toBeUndefined();
        expectSameAsUncapped(buf, 0);
        return {
          capped: capped.total - work(filler(length), 0).total,
          uncapped: uncapped.total - work(filler(length), ALL).total,
        };
      });
      // Neither the omitted rows nor the listed ones grow with the payload every header declares. Not exact equality:
      // the declared-length field itself differs between the two buffers, and its bytes are scanned as candidate magic
      // starts like any other. A walk over the declared payload would differ by ~192 KiB per header, not by 64 bytes.
      for (const key of ['capped', 'uncapped'] as const) {
        expect(Math.abs((totals[1]?.[key] as number) - (totals[0]?.[key] as number)), key).toBeLessThanOrEqual(
          64 * count,
        );
      }
      // Per header: its parse window, a decode for the one listed row, and the scanner's own candidate checks on the
      // header bytes — all proportional to the fixed header, none to the declared payload.
      expect((totals[1]?.capped as number) / count).toBeLessThanOrEqual(4 * header + 0x100);
    },
  );
});
