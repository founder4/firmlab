import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { identifyBlob, surveyUnopenedPayloads } from './extract-recover.js';

/** A raw LZMA "alone" header: properties byte, 4-byte dictionary size, 8-byte uncompressed size. */
function lzmaAlone(props = 0x5d, dictSize = 33554432): Buffer {
  const b = Buffer.alloc(32);
  b[0] = props;
  b.writeUInt32LE(dictSize, 1);
  b.writeBigUInt64LE(BigInt(7660784), 5);
  return b;
}

describe('identifyBlob — the extension lies, the magic does not', () => {
  /**
   * The reason this reads magic instead of the filename: binwalk names a raw LZMA stream `.7z`, and 7-Zip is a
   * different format with a different header. Dispatching on the extension would hand a `.7z` to a 7-Zip reader
   * that cannot open it, and the blob would be reported unopenable when it is merely misnamed.
   */
  it('reads a raw LZMA stream, which binwalk will have called .7z', () => {
    expect(identifyBlob(lzmaAlone())).toBe('lzma-alone');
  });

  it('reads the lzop container header verbatim from the BeanView blob', () => {
    const b = Buffer.alloc(32);
    Buffer.from([0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b);
    expect(identifyBlob(b)).toBe('lzop');
  });

  it('reads gzip and xz', () => {
    const gz = Buffer.alloc(32);
    gz[0] = 0x1f;
    gz[1] = 0x8b;
    expect(identifyBlob(gz)).toBe('gzip');
    const xz = Buffer.alloc(32);
    Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]).copy(xz);
    expect(identifyBlob(xz)).toBe('xz');
  });

  it('declines a blob whose bytes match nothing, rather than feeding it to a decompressor', () => {
    // High-entropy noise: an LZMA properties byte would be <= 224 and the dictionary a power of two.
    const noise = Buffer.alloc(32, 0xff);
    expect(identifyBlob(noise)).toBeNull();
    // A plausible props byte but a dictionary size that is not a power of two is not a stream either.
    expect(identifyBlob(lzmaAlone(0x5d, 12345))).toBeNull();
    expect(identifyBlob(Buffer.alloc(4))).toBeNull();
  });

  it('does not mistake a short buffer for an LZMA stream on the properties byte alone', () => {
    const short = Buffer.alloc(8);
    short[0] = 0x5d;
    short.writeUInt32LE(33554432, 1);
    expect(identifyBlob(short)).toBeNull();
  });
});

describe('surveyUnopenedPayloads', () => {
  const mk = (): string => fs.mkdtempSync(path.join(os.tmpdir(), 'survey-'));

  it('reports payloads carved beside a rootfs, largest first, without opening them', () => {
    const out = mk();
    fs.mkdirSync(path.join(out, 'squashfs-root', 'etc'), { recursive: true });
    // Two carved siblings: an xz and a gzip, both above the minimum blob size.
    fs.writeFileSync(
      path.join(out, 'big.xz'),
      Buffer.concat([Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]), Buffer.alloc(40000)]),
    );
    fs.writeFileSync(path.join(out, 'small.gz'), Buffer.concat([Buffer.from([0x1f, 0x8b, 0x08]), Buffer.alloc(9000)]));

    const s = surveyUnopenedPayloads(out, path.join(out, 'squashfs-root'));
    expect(s.payloads.map((p) => p.path)).toEqual(['big.xz', 'small.gz']);
    expect(s.payloads[0]?.format).toBe('xz');
    expect(s.totalBytes).toBeGreaterThan(49000);
    // The sentence must not let a recovered rootfs read as a fully-opened image.
    expect(s.note).toMatch(/not the whole image/);
    expect(s.note).toMatch(/only that nobody looked/);
  });

  it('excludes payloads INSIDE the rootfs — those are shipped files, already browsable', () => {
    const out = mk();
    const root = path.join(out, 'squashfs-root', 'usr', 'share');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(
      path.join(root, 'locale.gz'),
      Buffer.concat([Buffer.from([0x1f, 0x8b, 0x08]), Buffer.alloc(9000)]),
    );

    const s = surveyUnopenedPayloads(out, path.join(out, 'squashfs-root'));
    expect(s.payloads).toEqual([]);
    expect(s.note).toMatch(/No compressed payload was left unopened/);
  });

  it('says so plainly when nothing was left over, rather than returning a bare empty list', () => {
    const out = mk();
    fs.mkdirSync(path.join(out, 'squashfs-root'), { recursive: true });
    const s = surveyUnopenedPayloads(out, path.join(out, 'squashfs-root'));
    expect(s.totalBytes).toBe(0);
    expect(s.note).toMatch(/No compressed payload/);
  });
});
