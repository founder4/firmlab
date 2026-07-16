import { describe, expect, it } from 'vitest';
import { mergeSignatureSources, parseBinwalkOutput } from '../src/binwalk.js';
import { type FsEntry, buildFsTree, summarizeFs } from '../src/filesystem.js';
import { scanSignatures } from '../src/signatures.js';

const entries: FsEntry[] = [
  { path: 'bin', type: 'dir', size: 0, mode: 0o755 },
  { path: 'bin/busybox', type: 'file', size: 500000, mode: 0o755 },
  { path: 'bin/su', type: 'file', size: 30000, mode: 0o4755 }, // setuid root
  { path: 'etc/passwd', type: 'file', size: 400, mode: 0o644 },
  { path: 'etc/shadow', type: 'file', size: 200, mode: 0o600 },
  { path: 'etc/server.pem', type: 'file', size: 1800, mode: 0o644 },
  { path: 'tmp/writable', type: 'file', size: 10, mode: 0o666 }, // world-writable
  { path: 'lib/libc.so', type: 'symlink', size: 0, symlinkTarget: 'libc.so.0' },
];

describe('buildFsTree', () => {
  it('nests files under synthesized directories', () => {
    const tree = buildFsTree(entries);
    expect(tree.type).toBe('dir');
    const bin = tree.children?.find((c) => c.name === 'bin');
    expect(bin?.type).toBe('dir');
    expect(bin?.children?.some((c) => c.name === 'busybox')).toBe(true);
  });

  it('marks setuid binaries', () => {
    const tree = buildFsTree(entries);
    const bin = tree.children?.find((c) => c.name === 'bin');
    const su = bin?.children?.find((c) => c.name === 'su');
    expect(su?.setuid).toBe(true);
  });

  it('preserves symlink targets', () => {
    const tree = buildFsTree(entries);
    const lib = tree.children?.find((c) => c.name === 'lib');
    const libc = lib?.children?.find((c) => c.name === 'libc.so');
    expect(libc?.type).toBe('symlink');
    expect(libc?.symlinkTarget).toBe('libc.so.0');
  });
});

describe('summarizeFs', () => {
  it('counts and flags the audit surface', () => {
    const s = summarizeFs(entries);
    expect(s.totalDirs).toBe(1);
    expect(s.totalSymlinks).toBe(1);
    expect(s.setuidBinaries.map((n) => n.name)).toContain('su');
    expect(s.worldWritable.map((n) => n.name)).toContain('writable');
    const notablePaths = s.notable.map((n) => n.path);
    expect(notablePaths).toContain('etc/passwd');
    expect(notablePaths).toContain('etc/shadow');
    expect(notablePaths).toContain('etc/server.pem');
  });
});

describe('parseBinwalkOutput + merge', () => {
  const sample = `DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes
64            0x40            LZMA compressed data, properties: 0x5D
1114112       0x110000        Squashfs filesystem, little endian, version 4.0, size: 5242880
`;

  it('parses offsets, descriptions, and categories', () => {
    const hits = parseBinwalkOutput(sample);
    expect(hits).toHaveLength(3);
    expect(hits[0]?.offset).toBe(0);
    expect(hits[0]?.id).toBe('uimage');
    expect(hits[2]?.offset).toBe(1114112);
    expect(hits[2]?.category).toBe('filesystem');
  });

  it('ignores header and separator lines', () => {
    expect(parseBinwalkOutput('DECIMAL x y\n----\n').length).toBe(0);
  });

  it('merges binwalk over built-in at overlapping offsets', () => {
    const buf = new Uint8Array(2048);
    buf.set([0x27, 0x05, 0x19, 0x56], 0); // uImage at 0
    const builtin = scanSignatures(buf);
    const binwalk = parseBinwalkOutput('0  0x0  uImage header, header size: 64 bytes\n');
    const merged = mergeSignatureSources(builtin, binwalk);
    const atZero = merged.filter((h) => h.offset === 0);
    // The binwalk hit at offset 0 should win; no duplicate built-in uImage at 0.
    expect(atZero.some((h) => h.meta?.source === 'binwalk')).toBe(true);
  });
});
