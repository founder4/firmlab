/**
 * Tests for the extraction browser.
 *
 * The path guard is tested against REAL trees with REAL symlinks, in a temp dir, rather than against a string
 * model of one. That is deliberate: `resolveInsideRootfs`'s lexical test passes `link/etc/passwd` when `link`
 * points out of the tree, and a fixture built from the same assumption as the code would never have shown it —
 * which is the trap CLAUDE.md records twice over (`dynprobe-run.ts`).
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  DEFAULT_READ_BYTES,
  MAX_READ_BYTES,
  classifyBytes,
  describeExtraction,
  hexdump,
  listDirectory,
  modeString,
  parseReadRange,
  readFileSlice,
  resolvePath,
} from './fsbrowse.js';

const NUL = String.fromCharCode(0);

/** A tree that mirrors the shapes the corpus actually contains, symlinks included. */
function makeTree(): { root: string; outside: string } {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'fsbrowse-'));
  const root = path.join(base, 'extract');
  const outside = path.join(base, 'outside');
  fs.mkdirSync(path.join(root, 'squashfs-root', 'etc'), { recursive: true });
  fs.mkdirSync(path.join(root, 'squashfs-root', 'bin'), { recursive: true });
  fs.mkdirSync(outside, { recursive: true });

  fs.writeFileSync(path.join(outside, 'secret'), 'host bytes the firmware never held');
  fs.writeFileSync(path.join(root, 'squashfs-root', 'etc', 'shadow'), 'root:!:19000:0:99999:7:::\n');
  fs.writeFileSync(path.join(root, 'squashfs-root', 'bin', 'busybox'), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0]));
  fs.writeFileSync(path.join(root, 'squashfs-root', 'empty'), '');

  // DVRF ships exactly this: the account database is a symlink out of the tree.
  fs.symlinkSync('/dev/null', path.join(root, 'squashfs-root', 'etc', 'passwd'));
  // The ordinary, contained case: /bin/sh -> busybox.
  fs.symlinkSync('busybox', path.join(root, 'squashfs-root', 'bin', 'sh'));
  // A symlinked DIRECTORY pointing out of the tree — the ancestor case a lexical guard alone waves through.
  fs.symlinkSync(outside, path.join(root, 'escape-dir'));

  return { root, outside };
}

const { root, outside } = makeTree();
afterAll(() => fs.rmSync(path.dirname(root), { recursive: true, force: true }));

describe('resolvePath — every refusal names its rule', () => {
  it('accepts a contained relative path', () => {
    const r = resolvePath(root, 'squashfs-root/etc/shadow');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.rel).toBe('squashfs-root/etc/shadow');
  });

  it('accepts the root itself as the empty path', () => {
    const r = resolvePath(root, '');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.rel).toBe('');
  });

  it('refuses .. traversal by the containment rule', () => {
    const r = resolvePath(root, '../outside/secret');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rule).toBe('escapes-root');
      expect(r.reason).toMatch(/containment rule/);
    }
  });

  it('refuses .. traversal buried mid-path', () => {
    const r = resolvePath(root, 'squashfs-root/etc/../../../outside/secret');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rule).toBe('escapes-root');
  });

  it('refuses an absolute path by its own rule, not the containment one', () => {
    const r = resolvePath(root, '/etc/passwd');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rule).toBe('absolute-path');
      expect(r.reason).toMatch(/absolute-path rule/);
    }
  });

  it('refuses a NUL in the path before touching the filesystem', () => {
    const r = resolvePath(root, `squashfs-root/etc/shadow${NUL}.png`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rule).toBe('nul-in-path');
  });

  it('refuses a symlink that escapes the root, and names where it pointed', () => {
    const r = resolvePath(root, 'squashfs-root/etc/passwd');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.rule).toBe('symlink-escapes-root');
      expect(r.reason).toMatch(/symlink rule/);
      expect(r.symlinkTarget).toBe('/dev/null');
    }
  });

  it('refuses a path THROUGH a symlinked ancestor that escapes — the lexical guard alone lets this pass', () => {
    // Lexically `escape-dir/secret` is inside the root; only realpath shows it is not.
    expect(path.resolve(root, 'escape-dir/secret').startsWith(root + path.sep)).toBe(true);
    const r = resolvePath(root, 'escape-dir/secret');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rule).toBe('symlink-escapes-root');
  });

  it('follows a symlink that stays inside the root', () => {
    const r = resolvePath(root, 'squashfs-root/bin/sh');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.viaSymlink).toBe(true);
  });

  it('reports a missing entry as not-found rather than as an empty result', () => {
    const r = resolvePath(root, 'squashfs-root/etc/nope');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rule).toBe('not-found');
  });

  it('refuses a dangling symlink whose target lies outside', () => {
    const dangling = path.join(root, 'squashfs-root', 'dangling');
    fs.symlinkSync('/no/such/host/path', dangling);
    const r = resolvePath(root, 'squashfs-root/dangling');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rule).toBe('symlink-escapes-root');
    fs.unlinkSync(dangling);
  });
});

describe('listDirectory', () => {
  it('lists type, size, mode and the symlink target', () => {
    const listing = listDirectory(root, 'squashfs-root/bin');
    expect('entries' in listing).toBe(true);
    if (!('entries' in listing)) return;
    const sh = listing.entries.find((e) => e.name === 'sh');
    expect(sh?.type).toBe('symlink');
    expect(sh?.symlinkTarget).toBe('busybox');
    expect(sh?.symlinkResolved).toBe('squashfs-root/bin/busybox');
    expect(sh?.symlinkEscapes).toBeUndefined();
    const busybox = listing.entries.find((e) => e.name === 'busybox');
    expect(busybox?.type).toBe('file');
    expect(busybox?.size).toBe(7);
  });

  it('reports a symlink that escapes rather than hiding the entry', () => {
    const listing = listDirectory(root, 'squashfs-root/etc');
    if (!('entries' in listing)) throw new Error('expected a listing');
    const passwd = listing.entries.find((e) => e.name === 'passwd');
    expect(passwd?.symlinkEscapes).toBe(true);
    expect(passwd?.symlinkTarget).toBe('/dev/null');
  });

  it('refuses to list a file, naming the rule', () => {
    const r = listDirectory(root, 'squashfs-root/etc/shadow');
    expect('rule' in r && r.rule).toBe('not-a-directory');
  });

  it('sorts directories first then by name BEFORE the cap, and states what it dropped', () => {
    const many = path.join(root, 'many');
    fs.mkdirSync(many, { recursive: true });
    for (let i = 0; i < 10; i++) fs.writeFileSync(path.join(many, `f${String(i).padStart(2, '0')}`), 'x');
    fs.mkdirSync(path.join(many, 'zdir'), { recursive: true });

    const listing = listDirectory(root, 'many', 3);
    if (!('entries' in listing)) throw new Error('expected a listing');
    expect(listing.totalEntries).toBe(11);
    expect(listing.entries.length).toBe(3);
    // The directory sorts first even though its name is last alphabetically — the rule, not readdir order.
    expect(listing.entries[0]?.name).toBe('zdir');
    expect(listing.entries[1]?.name).toBe('f00');
    expect(listing.truncated).toBe(true);
    expect(listing.truncationRule).toMatch(/11 entries are present and 3 are shown/);
    expect(listing.truncationRule).toMatch(/not by the order the extractor happened to write/);
    fs.rmSync(many, { recursive: true, force: true });
  });

  it('says an empty directory is empty instead of rendering as nothing', () => {
    const empty = path.join(root, 'emptydir');
    fs.mkdirSync(empty, { recursive: true });
    const listing = listDirectory(root, 'emptydir');
    if (!('entries' in listing)) throw new Error('expected a listing');
    expect(listing.entries).toHaveLength(0);
    expect(listing.note).toMatch(/is not evidence that the firmware has nothing at this path/);
    fs.rmSync(empty, { recursive: true, force: true });
  });
});

describe('modeString', () => {
  it('renders the ls -l bits', () => {
    expect(modeString(0o755, 'file')).toBe('-rwxr-xr-x');
    expect(modeString(0o755, 'dir')).toBe('drwxr-xr-x');
    expect(modeString(0o777, 'symlink')).toBe('lrwxrwxrwx');
    expect(modeString(0o644, 'file')).toBe('-rw-r--r--');
  });

  it('shows setuid and sticky, which is the whole reason the string exists', () => {
    expect(modeString(0o4755, 'file')).toBe('-rwsr-xr-x');
    expect(modeString(0o4644, 'file')).toBe('-rwSr--r--');
    expect(modeString(0o1777, 'dir')).toBe('drwxrwxrwt');
  });
});

describe('classifyBytes — from the bytes, never the extension', () => {
  it('calls a PEM file text', () => {
    const c = classifyBytes(new TextEncoder().encode('-----BEGIN PUBLIC KEY-----\nMIIBIjANBg\n'));
    expect(c.kind).toBe('text');
    expect(c.reason).toMatch(/name played no part/);
  });

  it('calls an ELF header binary on the strength of one NUL', () => {
    const c = classifyBytes(Uint8Array.from([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x02, 0x01, 0x00]));
    expect(c.kind).toBe('binary');
    expect(c.nulBytes).toBe(1);
    expect(c.reason).toMatch(/NUL byte/);
  });

  it('does not rely on the name: a .pem holding an ELF is binary, a .bin holding a script is text', () => {
    expect(classifyBytes(Uint8Array.from([0x7f, 0x45, 0x4c, 0x46, 0x00])).kind).toBe('binary');
    expect(classifyBytes(new TextEncoder().encode('#!/bin/sh\nexit 0\n')).kind).toBe('text');
  });

  it('calls NUL-free high-entropy bytes binary by the non-printable ratio', () => {
    const noisy = Uint8Array.from({ length: 256 }, (_, i) => (i % 255) + 1);
    const c = classifyBytes(noisy);
    expect(c.kind).toBe('binary');
    expect(c.reason).toMatch(/non-printable/);
  });

  it('keeps a UTF-8 config file as text despite its high bytes', () => {
    const c = classifyBytes(new TextEncoder().encode('nombre = "cámara de vigilancia — ñ"\n'));
    expect(c.kind).toBe('text');
    expect(c.utf8).toBe(true);
  });

  it('reports an empty file as empty, not as text', () => {
    const c = classifyBytes(new Uint8Array(0));
    expect(c.kind).toBe('empty');
    expect(c.reason).toMatch(/nothing to classify/);
  });
});

describe('hexdump', () => {
  it('renders offset, two hex groups and an ASCII gutter', () => {
    const bytes = new TextEncoder().encode('FirmLab hexdump!');
    expect(hexdump(bytes)).toBe('00000000  46 69 72 6d 4c 61 62 20  68 65 78 64 75 6d 70 21  |FirmLab hexdump!|');
  });

  it('seeds the offset column from the read offset, so a window never claims to be the file start', () => {
    const out = hexdump(Uint8Array.from([0x41]), 0x1000);
    expect(out.startsWith('00001000  41')).toBe(true);
  });

  it('pads a short final line and dots the non-printable bytes', () => {
    const out = hexdump(Uint8Array.from([0x7f, 0x45, 0x4c, 0x46]));
    expect(out).toBe('00000000  7f 45 4c 46                                       |.ELF|');
  });

  it('returns an empty string for no bytes', () => {
    expect(hexdump(new Uint8Array(0))).toBe('');
  });
});

describe('parseReadRange — a clamp is stated, never silent', () => {
  it('defaults offset 0 and the default limit', () => {
    const r = parseReadRange(undefined, undefined, 1000);
    expect(r).toEqual({ offset: 0, limit: DEFAULT_READ_BYTES, adjustments: [] });
  });

  it('clamps a limit over the ceiling and says so', () => {
    const r = parseReadRange(0, MAX_READ_BYTES * 4, 10_000_000);
    expect(r.limit).toBe(MAX_READ_BYTES);
    expect(r.adjustments[0]).toMatch(/exceeds this deployment's/);
  });

  it('clamps a negative offset and says so', () => {
    const r = parseReadRange(-5, 100, 1000);
    expect(r.offset).toBe(0);
    expect(r.adjustments[0]).toMatch(/negative/);
  });

  it('says when the offset is past the end instead of returning a silent empty read', () => {
    const r = parseReadRange(5000, 100, 1000);
    expect(r.offset).toBe(1000);
    expect(r.adjustments[0]).toMatch(/past the end of the file/);
  });

  it('rejects a non-numeric limit by naming it', () => {
    const r = parseReadRange(0, 'lots', 1000);
    expect(r.limit).toBe(DEFAULT_READ_BYTES);
    expect(r.adjustments[0]).toMatch(/is not a number/);
  });
});

describe('readFileSlice', () => {
  it('reads a text file whole and says it was not truncated', () => {
    const r = readFileSlice(root, 'squashfs-root/etc/shadow', 0, 4096);
    if (!('size' in r)) throw new Error('expected a read');
    expect(r.view).toBe('text');
    expect(r.text).toMatch(/^root:!:/);
    expect(r.truncated).toBe(false);
    expect(r.truncationRule).toBeUndefined();
    expect(r.claim).toMatch(/not evidence about the running device/);
  });

  it('states the bound when it truncates: where it stopped and what remains', () => {
    const big = path.join(root, 'big.txt');
    fs.writeFileSync(big, 'a'.repeat(5000));
    const r = readFileSlice(root, 'big.txt', 0, 100);
    if (!('size' in r)) throw new Error('expected a read');
    expect(r.size).toBe(5000);
    expect(r.bytesRead).toBe(100);
    expect(r.truncated).toBe(true);
    expect(r.unreadBefore).toBe(0);
    expect(r.unreadAfter).toBe(4900);
    expect(r.truncationRule).toMatch(/bytes 0–100/);
    expect(r.truncationRule).toMatch(/4900 byte\(s\) AFTER it were not read/);
    fs.rmSync(big, { force: true });
  });

  it('renders a binary file as a hexdump even when text was asked for, and says which rule chose', () => {
    const r = readFileSlice(root, 'squashfs-root/bin/busybox', 0, 4096, 'text');
    if (!('size' in r)) throw new Error('expected a read');
    expect(r.view).toBe('hex');
    expect(r.hexdump).toMatch(/^00000000 {2}7f 45 4c 46/);
    expect(r.viewReason).toMatch(/despite the request for text/);
    expect(r.text).toBeUndefined();
  });

  it('honours a hex view for a text file, since that is a preference and not a claim', () => {
    const r = readFileSlice(root, 'squashfs-root/etc/shadow', 0, 32, 'hex');
    if (!('size' in r)) throw new Error('expected a read');
    expect(r.view).toBe('hex');
    expect(r.viewReason).toMatch(/because it was asked for/);
  });

  it('reads through a contained symlink', () => {
    const r = readFileSlice(root, 'squashfs-root/bin/sh', 0, 16);
    if (!('size' in r)) throw new Error('expected a read');
    expect(r.bytesRead).toBe(7);
  });

  it('refuses to read through a symlink that escapes the root', () => {
    const r = readFileSlice(root, 'squashfs-root/etc/passwd', 0, 16);
    expect('rule' in r && r.rule).toBe('symlink-escapes-root');
  });

  it('refuses a directory with the not-a-file rule instead of an empty read', () => {
    const r = readFileSlice(root, 'squashfs-root/etc', 0, 16);
    expect('rule' in r && r.rule).toBe('not-a-file');
  });

  it('reports an empty file as empty rather than as an unremarkable text file', () => {
    const r = readFileSlice(root, 'squashfs-root/empty', 0, 16);
    if (!('size' in r)) throw new Error('expected a read');
    expect(r.size).toBe(0);
    expect(r.classification.kind).toBe('empty');
    expect(r.truncated).toBe(false);
  });

  it('reads a window from the middle and keeps absolute offsets in the dump', () => {
    const big = path.join(root, 'window.bin');
    fs.writeFileSync(big, Buffer.alloc(4096, 0x41));
    const r = readFileSlice(root, 'window.bin', 4000, 16, 'hex');
    if (!('size' in r)) throw new Error('expected a read');
    expect(r.offset).toBe(4000);
    expect(r.bytesRead).toBe(16);
    expect(r.hexdump?.startsWith('00000fa0  41')).toBe(true);
    // A window that runs to EOF is still not the file: the 4000 skipped bytes must be named, not implied away.
    expect(r.truncated).toBe(true);
    expect(r.unreadBefore).toBe(4000);
    expect(r.unreadAfter).toBe(80);
    expect(r.truncationRule).toMatch(/4000 byte\(s\) BEFORE it were skipped by the offset/);
    fs.rmSync(big, { force: true });
  });
});

describe('describeExtraction — an empty tree has five causes and they are not the same answer', () => {
  it('separates "never extracted" from "extracted and empty"', () => {
    const never = describeExtraction({ jobStatus: null });
    expect(never.state).toBe('never-run');
    expect(never.browsable).toBe(false);
    expect(never.verdict).toMatch(/unasked question, not an empty filesystem/);

    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fsbrowse-empty-'));
    const ran = describeExtraction({ jobStatus: 'done', outputDir: emptyDir, rootfsPath: null });
    expect(ran.state).toBe('no-output');
    expect(ran.browsable).toBe(false);
    expect(ran.verdict).toMatch(/unanswered question, not a clean result/);
    fs.rmSync(emptyDir, { recursive: true, force: true });
  });

  it('quotes the extract diagnosis rather than paraphrasing it', () => {
    const v = describeExtraction({
      jobStatus: 'done',
      outputDir: root,
      rootfsPath: null,
      noRootfsVerdict: '27 volume(s) were extracted holding 666 file(s), and none is a Linux rootfs.',
    });
    expect(v.state).toBe('volumes-only');
    expect(v.browsable).toBe(true);
    expect(v.verdict).toContain('27 volume(s) were extracted holding 666 file(s)');
  });

  it('names the rootfs but insists the browse root is the whole carve', () => {
    const v = describeExtraction({
      jobStatus: 'done',
      outputDir: root,
      rootfsPath: path.join(root, 'squashfs-root'),
      extractor: 'binwalk',
    });
    expect(v.state).toBe('rootfs');
    expect(v.rootfsRel).toBe('squashfs-root');
    expect(v.verdict).toMatch(/WHOLE carve/);
    expect(v.verdict).toMatch(/not a guarantee that the image held nothing more/);
  });

  it('says the diagnosis is MISSING when a stored result predates it, rather than implying there was nothing to report', () => {
    // Asus-Router's real extract row in the corpus carries no `noRootfsDiagnosis` — it was written before
    // extract-diagnose.ts existed. An absent field and an answered question must not read the same.
    const v = describeExtraction({ jobStatus: 'done', outputDir: root, rootfsPath: null });
    expect(v.state).toBe('volumes-only');
    expect(v.verdict).toMatch(/No diagnosis of the missing rootfs was recorded/);
    expect(v.verdict).toMatch(/unknown rather than answered/);
  });

  it('marks a running extraction as mid-write rather than as a result', () => {
    expect(describeExtraction({ jobStatus: 'running', outputDir: root }).state).toBe('in-progress');
    expect(describeExtraction({ jobStatus: 'running', outputDir: root }).browsable).toBe(false);
  });

  it('keeps a failed extraction browsable but labelled a partial carve', () => {
    const v = describeExtraction({ jobStatus: 'error', jobError: 'binwalk exited 1', outputDir: root });
    expect(v.state).toBe('failed');
    expect(v.browsable).toBe(true);
    expect(v.verdict).toMatch(/partial carve, not the image's filesystem/);
  });
});
