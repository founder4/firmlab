import { describe, expect, it } from 'vitest';
import { computeEntropyProfile } from '../src/entropy.js';
import { SIGNATURE_RULES, scanSignatures, scanSignaturesDetailed } from '../src/signatures.js';
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
      id: 'trx',
      tier: 'consistent',
      pos: img(0x2000, [0, [...[...'HDR0'].map((c) => c.charCodeAt(0)), ...u32leBytes(0x1000)]], [16, u32leBytes(28)]),
      neg: img(0x2000, [0, [...[...'HDR0'].map((c) => c.charCodeAt(0)), ...u32leBytes(4)]]),
    },

    // --- vendor / platform containers, each with a rejecting structural check ---
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
    const rejecting = SIGNATURE_RULES.filter((r) => r.verify).map((r) => r.id);
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
 * Run over 16 MB of random bytes, the registry matches ~760 magics. The rubric rejects only a handful of them —
 * and that is the honest result, because every surviving match comes from a rule whose magic is TWO BYTES
 * (`pe-mz`, `jffs2-le`, `jffs2-be`: ~258/257/253 apiece) and which has no structural check to run. The rubric's
 * claim was never "fewer rows"; it is that a row you cannot corroborate must not look like one you can. So the
 * invariant worth locking is the one below: noise may survive the scan, but it may never leave the bottom rung.
 *
 * On a real ELF (`/usr/lib/.../ld-linux-x86-64.so.2`) the same scan keeps the genuine header at offset 0 at
 * `consistent` and drops a coincidental `\x7fELF` inside the file — the shape this is supposed to have.
 *
 * The remaining 2-byte noise is a separate, named piece of work: `structure.ts` already corroborates JFFS2 by
 * node type when it DECIDES a class, and pushing that check into the scanner is tracked in docs/BACKLOG.md
 * rather than done halfway here.
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
