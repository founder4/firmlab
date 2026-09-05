import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { diagnoseNoRootfs, diagnoseSquashfs, parseLzmaHeader, parseSquashfsSuperblock } from './extract-diagnose.js';

/** Build a SquashFS 4.0 little-endian superblock with chosen fields, padded to `size`. */
function squashfs(opts: { inodes: number; comp: number; bytesUsed: number; idTable: number; size: number }): Buffer {
  const buf = Buffer.alloc(opts.size);
  buf.write('hsqs', 0, 'latin1');
  buf.writeUInt32LE(opts.inodes, 0x04);
  buf.writeUInt16LE(opts.comp, 0x14);
  buf.writeBigUInt64LE(BigInt(opts.bytesUsed), 0x28);
  buf.writeBigUInt64LE(BigInt(opts.idTable), 0x30);
  return buf;
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
    expect(parseSquashfsSuperblock(Buffer.alloc(4096, 0x41))).toBeNull();
    expect(parseSquashfsSuperblock(Buffer.alloc(8))).toBeNull();
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
    expect(diagnoseSquashfs(Buffer.alloc(4096, 0x41))).toBeNull();
  });
});

describe('diagnoseNoRootfs — three empties that need three different next moves', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'diagnose-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  /**
   * BeanView-Camera's real shape: 27 JFFS2 volumes, 772 files, not one of them a rootfs — they are the camera's
   * data partitions, and one of them holds a private key. Reporting "no rootfs" and stopping throws that away.
   */
  it('reports extracted data partitions instead of calling the result empty', () => {
    const root = path.join(tmp, 'volumes');
    for (const [i, names] of [
      ['jffs2-root', ['devinfo', 'home', 'private_key.pem']],
      ['jffs2-root-0', ['voice', 'ipc_db_backup']],
    ].entries()) {
      void i;
      const [dir, files] = names as [string, string[]];
      fs.mkdirSync(path.join(root, dir), { recursive: true });
      for (const f of files) fs.writeFileSync(path.join(root, dir, f), 'x');
    }
    const d = diagnoseNoRootfs(root);
    expect(d.volumes).toHaveLength(2);
    expect(d.totalFiles).toBe(5);
    expect(d.verdict).toContain('none is a Linux rootfs');
    expect(d.verdict).toContain('private_key.pem');
    expect(d.verdict).toContain('worth reading');
  });

  it('explains a carved filesystem blob that produced nothing', () => {
    const root = path.join(tmp, 'blob');
    fs.mkdirSync(root, { recursive: true });
    const size = 8192;
    fs.writeFileSync(
      path.join(root, '120000.squashfs'),
      squashfs({ inodes: 581, comp: 2, bytesUsed: size, idTable: size - 8, size }),
    );
    const d = diagnoseNoRootfs(root);
    expect(d.blobs).toHaveLength(1);
    expect(d.verdict).toContain('120000.squashfs');
    expect(d.verdict).toContain('truncated');
  });

  it('says an empty output is an unanswered question, not a clean result', () => {
    const root = path.join(tmp, 'nothing');
    fs.mkdirSync(root, { recursive: true });
    const d = diagnoseNoRootfs(root);
    expect(d.verdict).toContain('Nothing was extracted');
    expect(d.verdict).toContain('not a clean result');
  });
});

describe('parseLzmaHeader — a carved blob nobody opened is not an empty result', () => {
  /** Raw LZMA "alone" header, verbatim shape from AliExpress-Repeater's carved kernel blob. */
  const lzma = (uncompressed: number, size = 64): Buffer => {
    const b = Buffer.alloc(size);
    b[0] = 0x5d; // lc=3 lp=0 pb=2
    b.writeUInt32LE(33554432, 1); // 32 MB dictionary
    b.writeBigUInt64LE(BigInt(uncompressed), 5);
    return b;
  };

  it('reads the declared uncompressed size, which is what makes the blob worth reporting', () => {
    expect(parseLzmaHeader(lzma(7660784))).toEqual({ dictSize: 33554432, uncompressedSize: 7660784 });
  });

  it('rejects bytes that are not a plausible stream rather than inventing a payload size', () => {
    expect(parseLzmaHeader(Buffer.alloc(64, 0xff))).toBeNull(); // props byte out of range
    const badDict = lzma(1000);
    badDict.writeUInt32LE(12345, 1); // not a power of two
    expect(parseLzmaHeader(badDict)).toBeNull();
    expect(parseLzmaHeader(Buffer.alloc(4))).toBeNull();
  });

  it('reports a carved LZMA blob as unexamined instead of calling the output empty', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'diagnose-lzma-'));
    fs.writeFileSync(path.join(root, '50040.7z'), lzma(7660784, 4096));
    const d = diagnoseNoRootfs(root);
    expect(d.verdict).toContain('50040.7z');
    expect(d.verdict).toContain('7660784');
    expect(d.verdict).toContain('UNEXAMINED');
    expect(d.verdict).not.toContain('Nothing was extracted');
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('replaces unexamined wording after the recovery pass opened and rescanned the payload', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'diagnose-recovered-lzma-'));
    const blob = path.join(root, '50040.7z');
    fs.writeFileSync(blob, lzma(7660784, 4096));
    const d = diagnoseNoRootfs(root, [
      {
        blob,
        format: 'lzma-alone',
        bytes: 511555,
        outcome: 'partial',
        note: 'compressed data is corrupt',
      },
    ]);
    expect(d.verdict).toContain('recovered 511555 bytes');
    expect(d.verdict).toContain('rescanned');
    expect(d.verdict).toContain('compressed data is corrupt');
    expect(d.verdict).not.toContain('UNEXAMINED');
    fs.rmSync(root, { recursive: true, force: true });
  });
});

describe('the verdict stays readable, and does not accuse an extractor that succeeded', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'diagnose-noise-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  /**
   * BeanView again, and the mistake the first version made on it: 29 `.jffs2` blobs were listed as "no extractor
   * opened it" while their volumes were sitting right there holding the 666 files those blobs produced. False, and
   * it buried the one sentence that mattered under a wall of repetition.
   */
  it('does not report filesystem blobs whose volumes did come out', () => {
    const root = path.join(tmp, 'opened');
    fs.mkdirSync(path.join(root, 'jffs2-root'), { recursive: true });
    fs.writeFileSync(path.join(root, 'jffs2-root', 'private_key.pem'), 'x');
    for (const n of ['520000.jffs2', '71442C.jffs2', '722A14.jffs2']) {
      fs.writeFileSync(path.join(root, n), Buffer.alloc(64, 0x11));
    }
    const d = diagnoseNoRootfs(root);
    expect(d.blobs).toHaveLength(0);
    expect(d.verdict).toContain('private_key.pem');
    expect(d.verdict).not.toContain('.jffs2');
  });

  it('still reports a compressed payload, which never becomes a volume directory', () => {
    const root = path.join(tmp, 'compressed');
    fs.mkdirSync(path.join(root, 'jffs2-root'), { recursive: true });
    fs.writeFileSync(path.join(root, 'jffs2-root', 'voice'), 'x');
    const b = Buffer.alloc(4096);
    b[0] = 0x5d;
    b.writeUInt32LE(33554432, 1);
    b.writeBigUInt64LE(BigInt(1305600), 5);
    fs.writeFileSync(path.join(root, 'persondet.lzma'), b);
    const d = diagnoseNoRootfs(root);
    expect(d.blobs).toHaveLength(1);
    expect(d.verdict).toContain('persondet.lzma');
  });

  it('counts a blob once when binwalk re-ran and carved it twice', () => {
    const root = path.join(tmp, 'twice');
    const blob = Buffer.alloc(4096);
    blob[0] = 0x5d;
    blob.writeUInt32LE(33554432, 1);
    blob.writeBigUInt64LE(BigInt(999), 5);
    for (const dir of ['_img.extracted', '_img-0.extracted']) {
      fs.mkdirSync(path.join(root, dir), { recursive: true });
      fs.writeFileSync(path.join(root, dir, '50040.7z'), blob);
    }
    expect(diagnoseNoRootfs(root).blobs).toHaveLength(1);
  });

  it('folds a long blob list instead of printing every line', () => {
    const root = path.join(tmp, 'many');
    fs.mkdirSync(root, { recursive: true });
    for (let i = 0; i < 9; i++) fs.writeFileSync(path.join(root, `b${i}.squashfs`), Buffer.alloc(128 + i, 0x22));
    const d = diagnoseNoRootfs(root);
    expect(d.blobs).toHaveLength(9);
    expect(d.verdict).toContain('5 further carved blob(s) are unexamined');
  });
});
