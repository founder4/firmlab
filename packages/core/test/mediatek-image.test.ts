import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseMediaTekBromHeader, parseMediaTekLkHeader } from '../src/mediatek-image.js';

// Complete inert fixture produced by upstream mkimage 2026.10-rc5, whose mtk_image.c is byte-identical to
// pinned v2026.10. Payload is bytes 0..255 followed by 0xa5; provenance/commands are in the accompanying doc.
const GENERATED_BASE64 =
  'iBaIWAEBAABzeW50aGV0aWMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIH/////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '//////////////////////////////////////////////////////////////////////////////////8AAQIDBAUGBwgJCgsM' +
  'DQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZX' +
  'WFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGi' +
  'o6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt' +
  '7u/w8fLz9PX29/j5+vv8/f7/pQ==';
function generated(): Uint8Array {
  return Uint8Array.from(Buffer.from(GENERATED_BASE64, 'base64'));
}
function set32(bytes: Uint8Array, at: number, value: number): void {
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(at, value, true);
}

describe('MediaTek LK legacy header subset', () => {
  it('parses an independent upstream generated fixture without changing bytes', () => {
    const bytes = generated();
    const before = Uint8Array.from(bytes);
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(
      '3829f6203fa47e0a9a71bebcf67311cb47e19211246c9baef3c35771f6a1b689',
    );
    expect(parseMediaTekLkHeader(bytes)).toEqual({
      valid: true,
      name: 'synthetic',
      payloadSize: 257,
      totalSize: 769,
      loadAddress: 0x81000000,
      mode: 0xffffffff,
    });
    expect(bytes).toEqual(before);
  });

  it('rejects every incomplete header and every missing declared payload byte', () => {
    const bytes = generated();
    for (let length = 0; length < bytes.length; length++) {
      expect(parseMediaTekLkHeader(bytes.subarray(0, length)).valid, `length ${length}`).toBe(false);
    }
  });

  it('rejects wrong endian/magic, zero mode, impossible sizes and unsupported reserved bytes', () => {
    for (const [at, value] of [
      [0, 0x88168858],
      [0, 0],
      [4, 258],
      [4, 0xffffffff],
      [4, 0xfffffe01],
      [44, 0],
      [40, 0],
    ] as const) {
      const bytes = generated();
      set32(bytes, at, value);
      expect(parseMediaTekLkHeader(bytes).valid, `field ${at} value ${value}`).toBe(false);
    }
    for (let at = 48; at < 512; at++) {
      const bytes = generated();
      bytes[at] = 0;
      expect(parseMediaTekLkHeader(bytes).valid, `reserved byte ${at}`).toBe(false);
    }
  });

  it('accepts unsigned nonzero addresses and modes without claiming memory or runtime validity', () => {
    const bytes = generated();
    set32(bytes, 40, 1);
    set32(bytes, 44, 1);
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, loadAddress: 1, mode: 1 });
    set32(bytes, 40, 0xffffffff);
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, loadAddress: 0xffffffff });
  });

  it('accepts zero payloads emitted by mkimage -s and empty names', () => {
    const bytes = generated().slice(0, 512);
    set32(bytes, 4, 0);
    bytes.fill(0, 8, 40);
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, payloadSize: 0, totalSize: 512, name: '' });
  });

  it('accepts the actual 31-byte maximum and UTF-8 names, rejecting missing NUL or nonzero NUL padding', () => {
    const bytes = generated();
    bytes.fill(0, 8, 40);
    bytes.set(Buffer.from('1234567890123456789012345678901'), 8);
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, name: '1234567890123456789012345678901' });
    bytes[39] = 65;
    expect(parseMediaTekLkHeader(bytes).valid).toBe(false);
    bytes.fill(0, 8, 40);
    bytes.set(Buffer.from('écho'), 8);
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, name: 'écho' });
    // Generator accepts non-ASCII and control bytes; printable ASCII is not a source-established invariant.
    bytes[8] = 1;
    expect(parseMediaTekLkHeader(bytes).valid).toBe(true);
    bytes[20] = 65;
    expect(parseMediaTekLkHeader(bytes).valid).toBe(false);
  });

  it('uses remaining bytes from a nonzero embedded offset and respects Uint8Array view offsets', () => {
    const backing = new Uint8Array(900).fill(0x55);
    const view = backing.subarray(11, 811);
    view.set(generated(), 7);
    expect(parseMediaTekLkHeader(view, 7)).toMatchObject({ valid: true, totalSize: 769 });
    expect(parseMediaTekLkHeader(view.subarray(0, 775), 7).valid).toBe(false);
    expect(parseMediaTekLkHeader(view, 0).valid).toBe(false);
    expect(parseMediaTekLkHeader(view.subarray(7))).toMatchObject({ valid: true });
  });

  it('bounds offsets before any read and accepts arbitrary trailing bytes outside the declared image', () => {
    for (const offset of [-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER, 770]) {
      expect(parseMediaTekLkHeader(generated(), offset).valid).toBe(false);
    }
    const bytes = new Uint8Array(800).fill(0xa5);
    bytes.set(generated());
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, totalSize: 769 });
  });

  it('does not invent integrity verification for a format without an integrity field', () => {
    const bytes = generated();
    bytes[768] ^= 0xff;
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true });
  });
});

// Complete inert BootROM fixture from the same packaged upstream mkimage: `-T mtk_image -a 0x201000 -n media=nor`
// over the 257-byte payload above (0..255, 0xa5). Provenance/commands are in docs/MEDIATEK-BOOTROM-20261108.md.
const BROM_NOR_BASE64 =
  'U0ZfQk9PVAD/////AQAAAAACAAD/////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '//////////////////////////////////////////////////////////////////////////////////9CUkxZVAAAAAEAAAAA' +
  'BgAAIQoAAEJCQkIHAAEAAAYAACEKAAD/////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////TU1NATgAAABGSUxFX0lORk8AAAABAAAAAQAFAQANIAAhBAAAIQoA' +
  'AAADAAAgAAAAAAMAAAEAAABNTU0BDAABAAEAAABNTU0DZAAHAJABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiBMAAAAAAAAAAAAATU1NARQCAwAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE1NTQEUAAIAAAAAABAA' +
  'AACAAAAATU1NATAACAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAwQFBgcICQoLDA0ODxAREhMU' +
  'FRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f' +
  'YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmq' +
  'q6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T1' +
  '9vf4+fr7/P3+/6VLLq1qkzlkvEucrCqMfLJX0ImhBSdIuZd/s2MRyA02Tw==';

type BromMedia = 'nor' | 'emmc' | 'sdmmc';
const BROM_DEVICE: Record<BromMedia, [string, number]> = {
  nor: ['SF_BOOT', 0x10007],
  emmc: ['EMMC_BOOT', 0x10005],
  sdmmc: ['SDMMC_BOOT', 0x10008],
};
function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}
/** Payloads the generator script wrote: 0..n-1 mod 256, except the shared 257-byte payload (0..255, 0xa5). */
function inertPayload(size: number): Uint8Array {
  const bytes = Uint8Array.from({ length: size }, (_, i) => i & 0xff);
  if (size === 257) bytes[256] = 0xa5;
  return bytes;
}
/**
 * Test-only re-statement of mtk_image_set_gen_header at the pinned commit (0xff device/BRLYT fill, zeroed GFH,
 * SHA-256 over [0x600, total - 32) written at total - 32). Its outputs are pinned below to the SHA-256 of the real
 * mkimage files, so it is evidence only where it reproduces the tool byte-for-byte.
 */
function buildBrom(opts: {
  media: BromMedia;
  payload: Uint8Array;
  address: number;
  arm64?: boolean;
  hdrOffset?: number;
  skip?: boolean;
}): Uint8Array {
  const total = 0x900 + (opts.skip ? 0 : opts.payload.length + 32);
  const out = new Uint8Array(total).fill(0xff);
  const dv = new DataView(out.buffer);
  const [name, type] = BROM_DEVICE[opts.media];
  out.set(Buffer.from(name), 0);
  out[name.length] = 0;
  dv.setUint32(12, 1, true);
  dv.setUint32(16, 0x200, true);
  const hdrOffset = opts.hdrOffset ?? 0;
  out.set([0x42, 0x52, 0x4c, 0x59, 0x54, 0, 0, 0], 0x200);
  dv.setUint32(0x208, 1, true);
  dv.setUint32(0x20c, (hdrOffset + 0x600) >>> 0, true);
  dv.setUint32(0x210, (hdrOffset + total) >>> 0, true);
  dv.setUint32(0x214, 0x42424242, true);
  dv.setUint32(0x218, type, true);
  dv.setUint32(0x21c, (hdrOffset + 0x600) >>> 0, true);
  dv.setUint32(0x220, (hdrOffset + total) >>> 0, true);
  const g = 0x600;
  out.fill(0, g, g + 0x300);
  const common = (at: number, size: number, gfhType: number, version: number) => {
    dv.setUint32(g + at, (0x4d4d4d | (version << 24)) >>> 0, true);
    dv.setUint16(g + at + 4, size, true);
    dv.setUint16(g + at + 6, gfhType, true);
  };
  common(0, 56, 0, 1);
  out.set(Buffer.from('FILE_INFO'), g + 8);
  dv.setUint32(g + 20, 1, true);
  dv.setUint16(g + 24, 1, true);
  out[g + 26] = 5;
  out[g + 27] = 1;
  dv.setUint32(g + 28, (opts.address - 0x300) >>> 0, true);
  dv.setUint32(g + 32, total - 0x600, true);
  dv.setUint32(g + 36, total, true);
  dv.setUint32(g + 40, 0x300, true);
  dv.setUint32(g + 44, 32, true);
  dv.setUint32(g + 48, 0x300, true);
  dv.setUint32(g + 52, 1, true);
  common(56, 12, 1, 1);
  dv.setUint32(g + 64, 1, true);
  common(68, 100, 7, 3);
  dv.setUint32(g + 76, opts.arm64 ? 0x1190 : 0x190, true);
  if (opts.arm64) out[g + 153] = 0x64;
  dv.setUint32(g + 156, 5000, true);
  common(168, 0x214, 3, 1);
  common(700, 20, 2, 1);
  dv.setUint32(g + 712, 0x10, true);
  dv.setUint32(g + 716, 0x80, true);
  common(720, 48, 8, 1);
  dv.setUint32(g + 728, 3, true);
  if (!opts.skip) out.set(opts.payload, 0x900);
  out.set(
    createHash('sha256')
      .update(out.subarray(0x600, total - 32))
      .digest(),
    total - 32,
  );
  return out;
}
function bromNor(): Uint8Array {
  return Uint8Array.from(Buffer.from(BROM_NOR_BASE64, 'base64'));
}

/** Every exit-0 output of the real generator run, by file SHA-256 (docs/MEDIATEK-BOOTROM-20261108.md). */
const ACCEPTED_GENERATOR_OUTPUTS: {
  file: string;
  media: BromMedia;
  size: number;
  address: number;
  arm64?: boolean;
  sha: string;
}[] = [
  {
    file: 'nor',
    media: 'nor',
    size: 257,
    address: 0x201000,
    sha: 'e90664dda0beec0b9af8e8dfc17a693407e711128caef3e75f0059815464c9e9',
  },
  {
    file: 'emmc',
    media: 'emmc',
    size: 257,
    address: 0x201000,
    sha: 'dc2fe0ff673a02d03365829a863d664d4b3af088a9af3b8d4fe7ad33e6e28177',
  },
  {
    file: 'sdmmc',
    media: 'sdmmc',
    size: 257,
    address: 0x201000,
    sha: 'b7af46bee98c099de4b2c882b1da57f562d366fa56ae8dfb8dd94055c55b3000',
  },
  {
    file: 'nor-arm64',
    media: 'nor',
    size: 257,
    address: 0x201000,
    arm64: true,
    sha: 'a0d00542fe4eca0bd5ecae60c2db618d7752ec43b8d78da041209e6f034f02be',
  },
  {
    file: 'nor-p1',
    media: 'nor',
    size: 1,
    address: 0x201000,
    sha: '776fb8de4d560306e2bf53dbf5d7222d1e6002216671a89a88031918bcbdab65',
  },
  {
    file: 'nor-p2',
    media: 'nor',
    size: 2,
    address: 0x201000,
    sha: '925457a5d9bebf71206f4769b0053d080e85a7f4e8809bb5d6fcfbadf29ddeb4',
  },
  {
    file: 'nor-p3',
    media: 'nor',
    size: 3,
    address: 0x201000,
    sha: '981ab61c03742398f392869945047830f3bd34fde3376296722119e070222db6',
  },
  {
    file: 'nor-p4',
    media: 'nor',
    size: 4,
    address: 0x201000,
    sha: '6c9f675c2afd921dd779d9301f571f34a8b0d6f3b05cc7f8c86c06bbca3aba82',
  },
  {
    file: 'nor-p31',
    media: 'nor',
    size: 31,
    address: 0x201000,
    sha: '2a2cedef9e822659bf3721b64cc7da2f1de279e6fcf43237fca5b19a72f924d0',
  },
  {
    file: 'nor-p32',
    media: 'nor',
    size: 32,
    address: 0x201000,
    sha: '27db738ebb61906c81fc4ae39b23002591f96a476b5540e7d080520a48ed230f',
  },
  {
    file: 'nor-p33',
    media: 'nor',
    size: 33,
    address: 0x201000,
    sha: '4a0ac93aa259856cbdcd97b7754f5d7ce64c4a3787c958af09d1f33fb380f13b',
  },
  {
    file: 'emmc-p4099',
    media: 'emmc',
    size: 4099,
    address: 0x201000,
    sha: '806ab0ac7a126f03423cbf26ab25739eeba43e97cafce066bb66d7cb7c224bf5',
  },
  {
    file: 'nor-a1',
    media: 'nor',
    size: 257,
    address: 1,
    sha: '51c59bc8a3e84cc4bb37b9d1443695bdb71a3f0409c3c75f55c6740ef66a9e47',
  },
  {
    file: 'nor-a2ff',
    media: 'nor',
    size: 257,
    address: 0x2ff,
    sha: '630ed583a64b1f4abfe67833bb03307749821d0c845722556f22e188a97eb74b',
  },
  {
    file: 'nor-a300',
    media: 'nor',
    size: 257,
    address: 0x300,
    sha: '3809e5441cd748e4f14b5b1e17ffd4f4ca583b3635d7a80b707521998442a63f',
  },
  {
    file: 'nor-a301',
    media: 'nor',
    size: 257,
    address: 0x301,
    sha: 'ff71b9cbdef98db5b1e3c2b3c02291f15766d682c70519c8941f345d60a9e253',
  },
  {
    file: 'nor-affffffff',
    media: 'nor',
    size: 257,
    address: 0xffffffff,
    sha: '7656f49bd1a9c4c72a7b1319e47f2c86f39da330a857956bdab80cde21c14a3b',
  },
];

describe('MediaTek BootROM generic NOR/SD/eMMC envelope subset', () => {
  it('parses the embedded real mkimage output, reporting the digest field without verifying it', () => {
    const bytes = bromNor();
    const before = Uint8Array.from(bytes);
    expect(sha256(bytes)).toBe(ACCEPTED_GENERATOR_OUTPUTS[0]?.sha);
    expect(sha256(bytes.subarray(0x900, 0x900 + 257))).toBe(
      'b23f2086c41b555319b29654f82c18db7793c8a9628688e71c91cb20c5138a9c',
    );
    expect(parseMediaTekBromHeader(bytes)).toEqual({
      valid: true,
      declaredMedia: 'nor',
      deviceName: 'SF_BOOT',
      brlytType: 0x10007,
      headerSize: 0x900,
      payloadSize: 257,
      totalSize: 2593,
      loadAddress: 0x201000,
      gfhLoadAddress: 0x200d00,
      arm64JumpFlag: false,
      digest: {
        algorithm: 'sha256',
        offset: 2561,
        length: 32,
        coveredStart: 0x600,
        coveredEnd: 2561,
        hex: Buffer.from(bytes.subarray(2561)).toString('hex'),
        verified: false,
      },
    });
    expect(bytes).toEqual(before);
  });

  it.each(ACCEPTED_GENERATOR_OUTPUTS)('reproduces and accepts generator output $file', (c) => {
    const bytes = buildBrom({
      media: c.media,
      payload: inertPayload(c.size),
      address: c.address,
      arm64: c.arm64 ?? false,
    });
    expect(sha256(bytes)).toBe(c.sha);
    expect(parseMediaTekBromHeader(bytes)).toMatchObject({
      valid: true,
      declaredMedia: c.media,
      payloadSize: c.size,
      totalSize: 0x900 + c.size + 32,
      loadAddress: c.address,
      gfhLoadAddress: (c.address - 0x300) >>> 0,
      arm64JumpFlag: c.arm64 ?? false,
      digest: { offset: 0x900 + c.size, coveredStart: 0x600, coveredEnd: 0x900 + c.size, verified: false },
    });
  });

  it('refuses the real generator outputs outside the supported default variant, naming why', () => {
    const payload = inertPayload(257);
    const cases: [Uint8Array, string, RegExp][] = [
      [
        buildBrom({ media: 'nor', payload, address: 0x201000, hdrOffset: 0x1000 }),
        '2327a762b27938224a2fcafe4aabe46d709a76cacf539f0fcb766da0afc5375a',
        /header_size 0x1600.*hdroffset/,
      ],
      [
        buildBrom({ media: 'emmc', payload, address: 0x201000, hdrOffset: 4 }),
        '76722b649064812898ad4294e3820deb79393a1872f904a7eecef5413e99cc66',
        /header_size 0x604.*hdroffset/,
      ],
      [
        buildBrom({ media: 'nor', payload, address: 0x201000, skip: true }),
        'a12b7faa3a50d3747bb89d39eaee57bcc198175dbadfee79fa09f73f0330c4af',
        /header-only.*-s/,
      ],
    ];
    for (const [bytes, sha, reason] of cases) {
      expect(sha256(bytes)).toBe(sha);
      expect(parseMediaTekBromHeader(bytes)).toEqual({ valid: false, reason: expect.stringMatching(reason) });
    }
  });

  it('rejects every incomplete header and every missing declared byte', () => {
    for (const bytes of [bromNor(), buildBrom({ media: 'sdmmc', payload: inertPayload(1), address: 1 })]) {
      for (let length = 0; length < bytes.length; length++) {
        const parsed = parseMediaTekBromHeader(bytes.subarray(0, length));
        expect(parsed.valid, `length ${length}`).toBe(false);
      }
    }
  });

  it('rejects a one-bit change anywhere in the 0x900-byte header except the free load-address word', () => {
    const base = bromNor();
    for (let at = 0; at < 0x900; at++) {
      const bytes = Uint8Array.from(base);
      bytes[at] = (bytes[at] ?? 0) ^ 1;
      const parsed = parseMediaTekBromHeader(bytes);
      if (at >= 0x61c && at < 0x620) expect(parsed.valid, `load address byte ${at}`).toBe(true);
      else expect(parsed.valid, `header byte 0x${at.toString(16)}`).toBe(false);
    }
  });

  it('rejects wrong endian, magic, version, sizes, copies, cross-header media and out-of-scope variants', () => {
    const cases: [number, number, RegExp][] = [
      [12, 0x01000000, /device header version/],
      [16, 0x00020000, /device header size/],
      [0x208, 2, /BRLYT version/],
      [0x214, 0x42424243, /BRLYT magic/],
      [0x218, 0x07000100, /BRLYT type/],
      [0x218, 0x10002, /NAND/],
      [0x218, 0x10009, /NAND/],
      [0x218, 0x10005, /does not match/],
      [0x20c, 0, /header_size 0x0/],
      [0x21c, 0x601, /header_size copy/],
      [0x220, 0xa20, /total_size copy/],
      [0x224, 0, /BRLYT unused/],
      [0x600, 0x4d4d4d01, /GFH FILE_INFO magic/],
      [0x600, 0x024d4d4d, /GFH FILE_INFO.*version/],
      [0x61c, 0xfffffd00, /load address of zero/],
      [0x624, 0xa22, /max_size/],
      [0x620, 0x422, /GFH total_size/],
      [0x64c, 0x191, /BROM_CFG/],
    ];
    for (const [at, value, reason] of cases) {
      const bytes = bromNor();
      new DataView(bytes.buffer).setUint32(at, value, true);
      expect(parseMediaTekBromHeader(bytes), `field 0x${at.toString(16)}`).toEqual({
        valid: false,
        reason: expect.stringMatching(reason),
      });
    }
    const nand = bromNor();
    nand[0x61a] = 2;
    expect(parseMediaTekBromHeader(nand)).toMatchObject({ valid: false, reason: expect.stringMatching(/NAND/) });
    const unsigned = bromNor();
    unsigned[0x61b] = 0;
    expect(parseMediaTekBromHeader(unsigned)).toMatchObject({
      valid: false,
      reason: expect.stringMatching(/GFH_SIG_TYPE_NONE/),
    });
    const arm64Mismatch = bromNor();
    arm64Mismatch[0x600 + 153] = 0x64;
    expect(parseMediaTekBromHeader(arm64Mismatch).valid).toBe(false);
  });

  it('refuses oversized, signed-negative and wrapping declared sizes without 32-bit arithmetic', () => {
    for (const total of [0xffffffff, 0x80000000, 0xa21, 0xa22, 0x920, 0x901, 0x8ff, 0x5ff, 0]) {
      const bytes = bromNor();
      const dv = new DataView(bytes.buffer);
      for (const at of [0x210, 0x220, 0x624]) dv.setUint32(at, total, true);
      dv.setUint32(0x620, (total - 0x600) >>> 0, true);
      const parsed = parseMediaTekBromHeader(bytes);
      if (total === 0xa21) expect(parsed.valid).toBe(true);
      else expect(parsed.valid, `total 0x${total.toString(16)}`).toBe(false);
    }
  });

  it('keeps the SHA-256 field honest: a changed payload or digest is not detected, and is never called verified', () => {
    const payloadChanged = bromNor();
    payloadChanged[0x900] ^= 0xff;
    const digestZeroed = bromNor();
    digestZeroed.fill(0, 2561);
    for (const bytes of [payloadChanged, digestZeroed]) {
      expect(parseMediaTekBromHeader(bytes)).toMatchObject({ valid: true, digest: { verified: false } });
    }
    expect(parseMediaTekBromHeader(digestZeroed)).toMatchObject({ digest: { hex: '0'.repeat(64) } });
  });

  it('uses remaining bytes from a nonzero embedded offset and respects Uint8Array view offsets', () => {
    const backing = new Uint8Array(4000).fill(0x55);
    const view = backing.subarray(13, 3013);
    view.set(bromNor(), 7);
    expect(parseMediaTekBromHeader(view, 7)).toMatchObject({ valid: true, totalSize: 2593, payloadSize: 257 });
    expect(parseMediaTekBromHeader(view.subarray(0, 7 + 2592), 7).valid).toBe(false);
    expect(parseMediaTekBromHeader(view, 0).valid).toBe(false);
    expect(parseMediaTekBromHeader(view.subarray(7))).toMatchObject({ valid: true });
    expect(parseMediaTekBromHeader(view, 7)).toEqual(parseMediaTekBromHeader(bromNor()));
  });

  it('bounds offsets before any read, never throws, and leaves trailing bytes unconstrained', () => {
    for (const offset of [-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER, 2594]) {
      expect(parseMediaTekBromHeader(bromNor(), offset).valid).toBe(false);
    }
    const trailing = new Uint8Array(3000).fill(0xa5);
    trailing.set(bromNor());
    expect(parseMediaTekBromHeader(trailing)).toMatchObject({ valid: true, totalSize: 2593 });
    let state = 0x1234567;
    for (let round = 0; round < 300; round++) {
      const bytes = bromNor();
      for (let n = 0; n < 4; n++) {
        state = (Math.imul(state, 1103515245) + 12345) >>> 0;
        bytes[state % 0x900] = state >>> 24;
      }
      expect(() => parseMediaTekBromHeader(bytes.subarray(0, state % bytes.length))).not.toThrow();
      expect(() => parseMediaTekBromHeader(bytes)).not.toThrow();
    }
  });

  it('keeps LK and BootROM parsers disjoint on each other’s real generator output', () => {
    expect(parseMediaTekBromHeader(generated()).valid).toBe(false);
    expect(parseMediaTekLkHeader(bromNor()).valid).toBe(false);
    const names = new Uint8Array(0x1000);
    names.set(Buffer.from('SF_BOOT\0EMMC_BOOT\0SDMMC_BOOT\0BRLYT\0FILE_INFO\0MMM'));
    for (let off = 0; off < 64; off++) expect(parseMediaTekBromHeader(names, off).valid).toBe(false);
  });
});
