import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  type RootfsLink,
  buildGraph,
  indexFileNames,
  indexSymlinks,
  isElf,
  looksLikeSoname,
  orphanBinaries,
  parseNeeded,
  resolveLinkPath,
  runComponentMap,
  selectElfScan,
  walkRootfs,
} from './compmap.js';

// A faithful `rabin2 -l <bin>` listing: a header, the linked sonames, a blank line, and a count footer.
const LIBS_OUTPUT = `[Linked libraries]
libc.so.0
libcrypto.so.1.1

2 libraries
`;

describe('parseNeeded', () => {
  it('extracts exactly the shared-object names, ignoring header/footer noise', () => {
    expect(parseNeeded(LIBS_OUTPUT)).toEqual(['libc.so.0', 'libcrypto.so.1.1']);
  });

  it('returns nothing for a statically-linked binary (no libraries)', () => {
    expect(parseNeeded('[Linked libraries]\n\n0 libraries\n')).toEqual([]);
  });

  it('is tolerant of brackets / paths and dedupes, and rejects .so lookalikes', () => {
    const noisy = '  [libc.so.0]  libc.so.0\n  /usr/lib/libssl.so\n  config.socket  not.a.solib\n';
    expect(parseNeeded(noisy)).toEqual(['libc.so.0', 'libssl.so']);
  });
});

describe('looksLikeSoname', () => {
  it('accepts a versioned shared object and rejects a runtime path or a lookalike', () => {
    expect(looksLikeSoname('libc.so.0')).toBe(true);
    expect(looksLikeSoname('libcrypto.so.1.1')).toBe(true);
    expect(looksLikeSoname('libssl.so')).toBe(true);
    expect(looksLikeSoname('resolv.conf')).toBe(false);
    expect(looksLikeSoname('config.socket')).toBe(false);
  });
});

describe('isElf', () => {
  it('is true for the ELF magic (0x7F E L F)', () => {
    expect(isElf(new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]))).toBe(true);
  });

  it('is false for non-ELF bytes and for a too-short buffer', () => {
    expect(isElf(new Uint8Array([0x4d, 0x5a, 0x90, 0x00]))).toBe(false); // MZ (PE)
    expect(isElf(new Uint8Array([0x7f, 0x45]))).toBe(false); // truncated
    expect(isElf(new Uint8Array([]))).toBe(false);
  });
});

describe('resolveLinkPath — lexical, and the whole containment argument', () => {
  it('resolves a sibling target against the link’s own directory', () => {
    expect(resolveLinkPath('lib', 'libuClibc-0.9.33.so')).toBe('lib/libuClibc-0.9.33.so');
    expect(resolveLinkPath('', 'bin/busybox')).toBe('bin/busybox');
  });

  it('walks `.` and `..` inside the rootfs', () => {
    expect(resolveLinkPath('usr/lib', '../../lib/libc.so.0')).toBe('lib/libc.so.0');
    expect(resolveLinkPath('bin', './busybox')).toBe('bin/busybox');
  });

  it('reads an absolute target as ROOTFS-absolute, never as a host path', () => {
    // The carve's own `lib/libc.so.6` — whether or not the host has one at `/lib/libc.so.6` is irrelevant here.
    expect(resolveLinkPath('lib', '/lib/libc.so.6')).toBe('lib/libc.so.6');
    expect(resolveLinkPath('usr/lib', '/bin/busybox')).toBe('bin/busybox');
  });

  it('returns null for a target that climbs above the root — an escape resolves to nothing', () => {
    expect(resolveLinkPath('lib', '../../../etc/passwd')).toBeNull();
    expect(resolveLinkPath('', '../outside/libc.so.6')).toBeNull();
  });
});

/** The uClibc shape every busybox rootfs has: the soname is a link, the file on disk has the versioned name. */
const UCLIBC_LINKS: RootfsLink[] = [{ path: 'lib/libc.so.0', target: 'libuClibc-0.9.33.so' }];
const UCLIBC_FILES = ['lib/libuClibc-0.9.33.so', 'bin/busybox'];

describe('indexSymlinks', () => {
  it('indexes a soname link by NAME and records where its text lands', () => {
    const idx = indexSymlinks(UCLIBC_FILES, ['lib', 'bin'], UCLIBC_LINKS);
    const p = idx.provides.get('libc.so.0');
    expect(p).toMatchObject({
      name: 'libc.so.0',
      link: 'lib/libc.so.0',
      target: 'libuClibc-0.9.33.so',
      resolvesTo: 'lib/libuClibc-0.9.33.so',
      hops: 1,
    });
    expect(idx.broken).toEqual([]);
  });

  it('follows a link chain through the index (link → link → file) and counts the hops', () => {
    const idx = indexSymlinks(
      ['usr/lib/libssl.so.1.1.0k'],
      ['lib', 'usr/lib'],
      [
        { path: 'lib/libssl.so', target: '../usr/lib/libssl.so.1.1' },
        { path: 'usr/lib/libssl.so.1.1', target: 'libssl.so.1.1.0k' },
      ],
    );
    expect(idx.provides.get('libssl.so')).toMatchObject({ resolvesTo: 'usr/lib/libssl.so.1.1.0k', hops: 2 });
    expect(idx.broken).toEqual([]);
  });

  it('reports a dangling link and provides nothing for it', () => {
    const idx = indexSymlinks(['bin/busybox'], ['lib', 'bin'], [{ path: 'lib/libz.so.1', target: 'libz.so.1.2.11' }]);
    expect(idx.provides.has('libz.so.1')).toBe(false);
    expect(idx.broken).toEqual([{ link: 'lib/libz.so.1', target: 'libz.so.1.2.11', reason: 'dangling' }]);
  });

  it('reports an escaping link and provides nothing for it', () => {
    const idx = indexSymlinks(['bin/busybox'], ['lib'], [{ path: 'lib/libc.so.6', target: '../../../lib/libc.so.6' }]);
    expect(idx.provides.has('libc.so.6')).toBe(false);
    expect(idx.broken[0]?.reason).toBe('escapes-rootfs');
  });

  it('reports a link cycle instead of chasing it', () => {
    const idx = indexSymlinks(
      [],
      ['lib'],
      [
        { path: 'lib/a.so', target: 'b.so' },
        { path: 'lib/b.so', target: 'a.so' },
      ],
    );
    expect(idx.provides.size).toBe(0);
    expect(idx.broken.map((b) => b.reason)).toEqual(['cycle', 'cycle']);
  });

  it('treats a link onto a walked directory as neither a provision nor broken', () => {
    // `lib → usr/lib` is ordinary on a rootfs; calling it dangling would cry wolf on every image.
    const idx = indexSymlinks(['usr/lib/libc.so.0'], ['usr', 'usr/lib'], [{ path: 'lib', target: 'usr/lib' }]);
    expect(idx.provides.size).toBe(0);
    expect(idx.broken).toEqual([]);
  });

  it('picks the same provider for a duplicated basename whatever order the walk found them in', () => {
    const files = ['lib/libuClibc-0.9.33.so', 'usr/lib/libuClibc-0.9.33.so'];
    const links: RootfsLink[] = [
      { path: 'usr/lib/libc.so.0', target: 'libuClibc-0.9.33.so' },
      { path: 'lib/libc.so.0', target: 'libuClibc-0.9.33.so' },
    ];
    const forward = indexSymlinks(files, ['lib', 'usr/lib'], links);
    const reversed = indexSymlinks([...files].reverse(), ['usr/lib', 'lib'], [...links].reverse());
    expect(forward.provides.get('libc.so.0')?.link).toBe('lib/libc.so.0');
    expect(reversed.provides.get('libc.so.0')?.link).toBe('lib/libc.so.0');
  });
});

describe('indexFileNames — the cheap half of the answer, over the whole tree', () => {
  it('keys the walked files by basename, which is what a DT_NEEDED entry is', () => {
    const idx = indexFileNames(['lib/libc.so', 'bin/busybox']);
    expect(idx.get('libc.so')).toEqual({ name: 'libc.so', path: 'lib/libc.so', count: 1 });
    expect(idx.get('busybox')?.path).toBe('bin/busybox');
    expect(idx.has('libssl.so')).toBe(false);
  });

  it('picks the same file for a duplicated basename whatever order the walk found them in', () => {
    const files = ['usr/lib/libc.so', 'lib/libc.so', 'opt/lib/libc.so'];
    const forward = indexFileNames(files);
    const reversed = indexFileNames([...files].reverse());
    expect(forward.get('libc.so')).toEqual({ name: 'libc.so', path: 'lib/libc.so', count: 3 });
    expect(reversed.get('libc.so')).toEqual(forward.get('libc.so'));
  });
});

describe('selectElfScan — the one bound left, and it ranks', () => {
  // The GL.iNet shape in miniature: kernel modules outnumber everything and answer nothing, and arrival order
  // puts them first. `lib/modules/…` sorts ahead of `sbin/…` by path, so a cap that took arrival order here would
  // spend its whole budget on files with no DT_NEEDED section to read.
  const elfs = [
    'lib/modules/5.4/ath.ko',
    'lib/modules/5.4/mac80211.ko',
    'lib/libuClibc-1.0.14.so',
    'usr/lib/libz.so.1.2.11',
    'www/cgi-bin/glc',
    'sbin/dropbear',
    'bin/busybox',
  ];
  const linkTargets = new Set(['lib/libuClibc-1.0.14.so']);

  it('ranks programs, then the libraries a symlink names, then other programs, then sonames, then modules', () => {
    const sel = selectElfScan(elfs, linkTargets, 7);
    expect(sel.scan).toEqual([
      'bin/busybox',
      'sbin/dropbear',
      'lib/libuClibc-1.0.14.so',
      'www/cgi-bin/glc',
      'usr/lib/libz.so.1.2.11',
      'lib/modules/5.4/ath.ko',
      'lib/modules/5.4/mac80211.ko',
    ]);
    expect(sel.dropped).toBe(0);
    expect(sel.total).toBe(7);
  });

  it('spends a tight budget on the programs, not on whatever the walk reached first', () => {
    const sel = selectElfScan(elfs, linkTargets, 3);
    expect(sel.scan).toEqual(['bin/busybox', 'sbin/dropbear', 'lib/libuClibc-1.0.14.so']);
    expect(sel.dropped).toBe(4);
    expect(sel.scan.some((f) => f.endsWith('.ko'))).toBe(false);
  });

  it('selects the same set whatever order the walk produced — the set is not a fact about the directory', () => {
    const forward = selectElfScan(elfs, linkTargets, 4);
    const reversed = selectElfScan([...elfs].reverse(), linkTargets, 4);
    expect(reversed.scan).toEqual(forward.scan);
  });

  it('states what it read, what it dropped and by what rule — always, not only on a cut', () => {
    const whole = selectElfScan(elfs, linkTargets, 20);
    expect(whole.rule).toMatch(/Read DT_NEEDED from 7 of 7 ELF files/);
    expect(whole.rule).toMatch(/never by directory order/);
    expect(whole.rule).not.toMatch(/left unopened/); // nothing was dropped: the sentence must not claim otherwise

    const cut = selectElfScan(elfs, linkTargets, 3);
    expect(cut.rule).toMatch(/Read DT_NEEDED from 3 of 7 ELF files/);
    // And what the cap now costs, stated: the names still resolve, the dropped files' own edges do not.
    expect(cut.rule).toMatch(/The 4 left unopened are still indexed by NAME/);
  });

  it('is empty and honest for a rootfs with no ELF at all', () => {
    const sel = selectElfScan([], new Set(), 300);
    expect(sel).toMatchObject({ scan: [], dropped: 0, total: 0 });
    expect(sel.rule).toMatch(/0 of 0 ELF files/);
  });
});

describe('buildGraph', () => {
  const graph = buildGraph([
    { binary: 'bin/httpd', needs: ['libc.so.0', 'libssl.so'] },
    { binary: 'lib/libc.so.0', needs: [] },
  ]);
  const kind = new Map(graph.nodes.map((n) => [n.id, n.kind]));

  it('makes present entries binary nodes and referenced-only sonames lib nodes', () => {
    expect(kind.get('httpd')).toBe('binary');
    expect(kind.get('libc.so.0')).toBe('binary'); // present as an entry → binary
    expect(kind.get('libssl.so')).toBe('lib'); // only referenced → lib
  });

  it('adds a binary→lib edge for every DT_NEEDED reference', () => {
    expect(graph.edges).toContainEqual({ from: 'httpd', to: 'libc.so.0' });
    expect(graph.edges).toContainEqual({ from: 'httpd', to: 'libssl.so' });
  });

  it('reports a referenced-but-absent soname as unresolved', () => {
    expect(graph.unresolved).toContain('libssl.so');
    expect(graph.unresolved).not.toContain('libc.so.0');
  });

  it('flags an entry executable nothing depends on as an orphan', () => {
    const orphans = orphanBinaries(graph);
    expect(orphans).toContain('httpd');
    expect(orphans).not.toContain('libc.so.0'); // something depends on it
  });

  it('carries no link fields at all when no symlink index was passed — absence means "never looked"', () => {
    expect('linkProvided' in graph).toBe(false);
    expect('brokenLinks' in graph).toBe(false);
    expect('brokenLinkRule' in graph).toBe(false);
  });
});

describe('buildGraph — resolving sonames by name, without following anything', () => {
  const entries = [
    { binary: 'bin/httpd', needs: ['libc.so.0', 'libssl.so.1.1', 'libgone.so.2'] },
    { binary: 'lib/libuClibc-0.9.33.so', needs: [] },
    { binary: 'usr/lib/libssl.so.1.1', needs: ['libc.so.0'] },
  ];
  const idx = indexSymlinks(
    ['lib/libuClibc-0.9.33.so', 'usr/lib/libssl.so.1.1', 'bin/httpd'],
    ['lib', 'usr/lib', 'bin', 'etc'],
    [
      { path: 'lib/libc.so.0', target: 'libuClibc-0.9.33.so' },
      { path: 'lib/libgone.so.2', target: 'libgone.so.2.1.0' }, // dangling, and something needs it
      { path: 'etc/resolv.conf', target: '/tmp/resolv.conf' }, // dangling by design on every carve
    ],
  );
  const graph = buildGraph(entries, idx);
  const kind = new Map(graph.nodes.map((n) => [n.id, n.kind]));

  it('keeps the three outcomes apart: a file, a link, and nothing at all', () => {
    expect(kind.get('libssl.so.1.1')).toBe('binary'); // a walked FILE provides it — the strong case
    expect(kind.get('libc.so.0')).toBe('link'); // only a symlink says so — the weaker one
    expect(kind.get('libgone.so.2')).toBe('lib'); // genuinely unresolved
  });

  it('resolves a link-provided soname and labels it with the link and its target', () => {
    expect(graph.unresolved).not.toContain('libc.so.0');
    expect(graph.linkProvided).toEqual([
      {
        name: 'libc.so.0',
        link: 'lib/libc.so.0',
        target: 'libuClibc-0.9.33.so',
        resolvesTo: 'lib/libuClibc-0.9.33.so',
        hops: 1,
      },
    ]);
  });

  it('does not list a soname a real file resolved as link-provided', () => {
    expect(graph.linkProvided?.map((p) => p.name)).not.toContain('libssl.so.1.1');
  });

  it('still reports a genuinely absent library as unresolved', () => {
    expect(graph.unresolved).toEqual(['libgone.so.2']);
  });

  it('reports the dangling link that explains it, and stays quiet about /etc/resolv.conf', () => {
    expect(graph.brokenLinks).toContainEqual({
      link: 'lib/libgone.so.2',
      target: 'libgone.so.2.1.0',
      reason: 'dangling',
      needed: true,
    });
    expect(graph.brokenLinks?.some((b) => b.link === 'etc/resolv.conf')).toBe(false);
    expect(graph.brokenLinkCount).toBe(2); // both were FOUND; the rule decides which are worth listing
    expect(graph.brokenLinkRule).toMatch(/2 broken in total/);
  });

  it('keeps `unresolved` and the lib-node set the same set — the web falls back to the nodes', () => {
    expect(graph.unresolved).toEqual(graph.nodes.filter((n) => n.kind === 'lib').map((n) => n.id));
  });
});

describe('buildGraph — the fourth outcome: in the carve, never opened', () => {
  /**
   * The GL.iNet defect in miniature. `lib/libc.so` is a real 590 KB file that 298 binaries reference, and it was
   * reported unresolved by every one of them because the walk stopped at 4,000 of 6,496 files and the ELF pass at
   * 300. Names now index the whole tree while only the ranked top of the ELF pass is opened, so the reference
   * resolves — as its own kind, because "the carve has this file and nothing here read it" is not the same claim
   * as "we read it", and it is certainly not "it is missing".
   */
  const entries = [
    { binary: 'bin/httpd', needs: ['libc.so', 'libc.so.0', 'libz.so.1', 'libgone.so.2'] },
    { binary: 'sbin/dropbear', needs: ['libz.so.1'] },
  ];
  const files = ['bin/httpd', 'sbin/dropbear', 'lib/libc.so', 'lib/libuClibc-1.0.14.so'];
  const links: RootfsLink[] = [{ path: 'lib/libc.so.0', target: 'libuClibc-1.0.14.so' }];
  const graph = buildGraph(entries, indexSymlinks(files, ['bin', 'sbin', 'lib'], links), indexFileNames(files));
  const kind = new Map(graph.nodes.map((n) => [n.id, n.kind]));

  it('keeps the FOUR outcomes apart, in descending strength', () => {
    expect(kind.get('httpd')).toBe('binary'); // walked AND its DT_NEEDED read by this run
    expect(kind.get('libc.so')).toBe('file'); // in the carve; the ELF pass never opened it
    expect(kind.get('libc.so.0')).toBe('link'); // only a symlink says the name exists
    expect(kind.get('libgone.so.2')).toBe('lib'); // nothing in the carve provides it
  });

  it('resolves the library the ELF pass never reached, and names the file that provides it', () => {
    expect(graph.unresolved).not.toContain('libc.so');
    expect(graph.fileProvided).toEqual([{ name: 'libc.so', path: 'lib/libc.so', count: 1 }]);
  });

  it('still reports a genuinely absent library as unresolved — a wider index is not a blanket amnesty', () => {
    // Neither a file nor a link in the tree carries either name, and both stay unresolved.
    expect([...graph.unresolved].sort()).toEqual(['libgone.so.2', 'libz.so.1']);
    expect(kind.get('libz.so.1')).toBe('lib');
    expect(graph.unresolved).toEqual(graph.nodes.filter((n) => n.kind === 'lib').map((n) => n.id));
  });

  it('prefers the file to the link when both provide the name — the file is the stronger fact', () => {
    const both = buildGraph(
      [{ binary: 'bin/httpd', needs: ['libssl.so.1.1'] }],
      indexSymlinks(
        ['usr/lib/libssl.so.1.1.0k', 'lib/libssl.so.1.1'],
        ['lib', 'usr/lib'],
        [{ path: 'usr/lib/libssl.so.1.1', target: 'libssl.so.1.1.0k' }],
      ),
      indexFileNames(['usr/lib/libssl.so.1.1.0k', 'lib/libssl.so.1.1']),
    );
    expect(both.nodes.find((n) => n.id === 'libssl.so.1.1')?.kind).toBe('file');
    expect(both.fileProvided?.map((p) => p.path)).toEqual(['lib/libssl.so.1.1']);
    expect(both.linkProvided).toEqual([]); // looked, and the stronger answer won — not "never looked"
  });

  it('carries no file fields at all without the index — absence means "this run never looked"', () => {
    const withLinksOnly = buildGraph(entries, indexSymlinks(files, ['bin', 'sbin', 'lib'], links));
    expect('fileProvided' in withLinksOnly).toBe(false);
    expect(withLinksOnly.nodes.some((n) => n.kind === 'file')).toBe(false);
    // …and that build reports exactly the cap artifact this change removes.
    expect(withLinksOnly.unresolved).toContain('libc.so');

    // The two indexes are independent: file names without link texts is a coherent run and says so.
    const filesOnly = buildGraph(entries, undefined, indexFileNames(files));
    expect('linkProvided' in filesOnly).toBe(false);
    expect(filesOnly.fileProvided?.map((p) => p.name)).toEqual(['libc.so']);
    expect([...filesOnly.unresolved].sort()).toEqual(['libc.so.0', 'libgone.so.2', 'libz.so.1']);
  });
});

describe('buildGraph — the uClibc shape that made the unresolved table a fiction', () => {
  // The measured Tenda case: 63 of 67 binaries "need" a missing libc.so.0, which the rootfs has as a symlink.
  const entries = Array.from({ length: 63 }, (_, i) => ({ binary: `bin/app${i}`, needs: ['libc.so.0'] })).concat([
    { binary: 'lib/libuClibc-0.9.33.so', needs: [] },
  ]);
  const files = entries.map((e) => e.binary);

  it('collapses to zero false unresolved once the link is read by name', () => {
    const idx = indexSymlinks(files, ['bin', 'lib'], UCLIBC_LINKS);
    const graph = buildGraph(entries, idx);
    expect(graph.unresolved).toEqual([]);
    expect(graph.nodes.filter((n) => n.kind === 'lib')).toEqual([]);
    expect(graph.linkProvided).toHaveLength(1);
    expect(graph.edges).toHaveLength(63);
  });

  it('stays collapsed with the file index beside it, and stays a LINK — the weaker fact is not upgraded', () => {
    const idx = indexSymlinks(files, ['bin', 'lib'], UCLIBC_LINKS);
    const graph = buildGraph(entries, idx, indexFileNames(files));
    expect(graph.unresolved).toEqual([]);
    // No file is called `libc.so.0`; only the link is. Indexing the tree by name must not blur that into `file`.
    expect(graph.nodes.find((n) => n.id === 'libc.so.0')?.kind).toBe('link');
    expect(graph.fileProvided).toEqual([]); // looked, found none — the carve provides that name only via the link
  });

  it('reports all 63 as unresolved when the rootfs really has no such link — an empty index is not a fix', () => {
    const graph = buildGraph(entries, indexSymlinks(files, ['bin', 'lib'], []));
    expect(graph.unresolved).toEqual(['libc.so.0']);
    expect(graph.linkProvided).toEqual([]); // looked, found none — not the same as never looking
    expect(graph.brokenLinks).toEqual([]);
  });
});

describe('buildGraph — a rootfs with no symlinks behaves exactly as before', () => {
  const entries = [
    { binary: 'bin/httpd', needs: ['libc.so.6', 'libssl.so'] },
    { binary: 'lib/libc.so.6', needs: [] },
  ];

  it('gives the same nodes, edges and unresolved set with an empty index as with none', () => {
    const withoutIndex = buildGraph(entries);
    const withEmptyIndex = buildGraph(entries, indexSymlinks(['bin/httpd', 'lib/libc.so.6'], ['bin', 'lib'], []));
    expect(withEmptyIndex.nodes).toEqual(withoutIndex.nodes);
    expect(withEmptyIndex.edges).toEqual(withoutIndex.edges);
    expect(withEmptyIndex.unresolved).toEqual(withoutIndex.unresolved);
    expect(withoutIndex.nodes.some((n) => n.kind === 'link')).toBe(false);
    expect(withoutIndex.unresolved).toEqual(['libssl.so']);
  });
});

describe('walkRootfs — reads what a link says, follows none of it', () => {
  /**
   * A real directory tree, because the containment claim is about the filesystem and not about a fixture. The
   * decisive links point at files that DO exist on the host: an implementation that called `realpath` would
   * resolve them and report the library as present, and this test would then fail.
   */
  function makeTree(): { dir: string; rootfs: string; outside: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-compmap-'));
    const rootfs = path.join(dir, 'rootfs');
    const outside = path.join(dir, 'outside');
    fs.mkdirSync(path.join(rootfs, 'lib'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'bin'), { recursive: true });
    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(path.join(rootfs, 'lib/libuClibc-0.9.33.so'), 'not really an elf');
    fs.writeFileSync(path.join(rootfs, 'bin/busybox'), 'not really an elf');
    fs.writeFileSync(path.join(outside, 'libhost.so.6'), 'the host copy');
    fs.writeFileSync(path.join(outside, 'secret.txt'), 'must never be walked');
    fs.symlinkSync('libuClibc-0.9.33.so', path.join(rootfs, 'lib/libc.so.0'));
    fs.symlinkSync(path.join(outside, 'libhost.so.6'), path.join(rootfs, 'lib/libabs.so.6')); // absolute → host
    fs.symlinkSync('../../outside/libhost.so.6', path.join(rootfs, 'lib/librel.so.6')); // relative → host
    fs.symlinkSync('libgone.so.1.2.3', path.join(rootfs, 'lib/libgone.so.1')); // dangling
    fs.symlinkSync('../outside', path.join(rootfs, 'escape-dir')); // a directory link out of the image
    return { dir, rootfs, outside };
  }

  it('collects files and link texts, never descending through a link', () => {
    const { dir, rootfs, outside } = makeTree();
    try {
      // Both host targets really are reachable by traversal — that is what makes the assertions below mean something.
      expect(fs.existsSync(path.join(rootfs, 'lib/libabs.so.6'))).toBe(true);
      expect(fs.existsSync(path.join(rootfs, 'lib/librel.so.6'))).toBe(true);

      const scan = walkRootfs(rootfs, 4000);
      expect(scan.files.sort()).toEqual(['bin/busybox', 'lib/libuClibc-0.9.33.so']);
      expect(scan.files.some((f) => f.includes('secret.txt'))).toBe(false); // the directory link was not entered
      expect(scan.truncated).toBe(false);
      expect(scan.links.find((l) => l.path === 'lib/libc.so.0')?.target).toBe('libuClibc-0.9.33.so');
      expect(scan.links.find((l) => l.path === 'lib/libabs.so.6')?.target).toBe(path.join(outside, 'libhost.so.6'));
      expect(scan.links.map((l) => l.path).sort()).toEqual([
        'escape-dir',
        'lib/libabs.so.6',
        'lib/libc.so.0',
        'lib/libgone.so.1',
        'lib/librel.so.6',
      ]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('resolves the in-rootfs soname and refuses both links that leave the image', () => {
    const { dir, rootfs } = makeTree();
    try {
      const scan = walkRootfs(rootfs, 4000);
      const idx = indexSymlinks(scan.files, scan.dirs, scan.links);

      expect(idx.provides.get('libc.so.0')?.resolvesTo).toBe('lib/libuClibc-0.9.33.so');
      // The host's copy exists and is reachable through both links; neither may make the name count as provided.
      expect(idx.provides.has('libabs.so.6')).toBe(false);
      expect(idx.provides.has('librel.so.6')).toBe(false);

      const reasons = new Map(idx.broken.map((b) => [b.link, b.reason]));
      expect(reasons.get('lib/libabs.so.6')).toBe('dangling'); // rootfs-absolute: the carve has no such path
      expect(reasons.get('lib/librel.so.6')).toBe('escapes-rootfs');
      expect(reasons.get('lib/libgone.so.1')).toBe('dangling');
      expect(reasons.get('escape-dir')).toBe('escapes-rootfs');

      // And end to end: a binary needing the host-linked name is still unresolved, the uClibc one is not.
      const graph = buildGraph([{ binary: 'bin/busybox', needs: ['libc.so.0', 'libabs.so.6'] }], idx);
      expect(graph.unresolved).toEqual(['libabs.so.6']);
      expect(graph.linkProvided?.map((p) => p.name)).toEqual(['libc.so.0']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('says so when a CALLER caps it, so "absent" stays a claim about what it saw', () => {
    const { dir, rootfs } = makeTree();
    try {
      const scan = walkRootfs(rootfs, 1);
      expect(scan.files).toHaveLength(1);
      expect(scan.truncated).toBe(true);
      // The provider passes no bound, and that is the branch that runs: a name index of the whole tree.
      expect(walkRootfs(rootfs).truncated).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('walkRootfs — the whole tree, because naming is cheap (the GL.iNet cap artifact)', () => {
  /**
   * A rootfs bigger than the walk's old 4,000-file bound, with the library past it. On the real GL.iNet carve the
   * bound cut the walk at 4,000 of 6,496 files and a genuine 590 KB `lib/libc.so` that 298 binaries reference was
   * never seen — 65 of that image's 65 unresolved sonames were artifacts of the two caps. `readdir` is not what
   * costs, so nothing is capped here any more.
   */
  function makeBigTree(pad: number): { dir: string; rootfs: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-compmap-big-'));
    const rootfs = path.join(dir, 'rootfs');
    fs.mkdirSync(path.join(rootfs, 'usr/share/pad'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'lib'), { recursive: true });
    fs.mkdirSync(path.join(rootfs, 'bin'), { recursive: true });
    for (let i = 0; i < pad; i += 1) fs.writeFileSync(path.join(rootfs, `usr/share/pad/f${i}`), '');
    fs.writeFileSync(path.join(rootfs, 'lib/libc.so'), 'the library every binary names');
    fs.writeFileSync(path.join(rootfs, 'bin/httpd'), 'a program');
    return { dir, rootfs };
  }

  it('indexes every file of a rootfs larger than the old bound, and produces no cap-artifact unresolved row', () => {
    const { dir, rootfs } = makeBigTree(4200);
    try {
      const bounded = walkRootfs(rootfs, 4000);
      expect(bounded.truncated).toBe(true);
      expect(bounded.files).toHaveLength(4000);

      const scan = walkRootfs(rootfs);
      expect(scan.truncated).toBe(false);
      expect(scan.files).toHaveLength(4202);
      expect(scan.files).toContain('lib/libc.so');

      // The ELF pass never opened the library — only the program is an entry — and it resolves all the same.
      const entries = [{ binary: 'bin/httpd', needs: ['libc.so'] }];
      const whole = buildGraph(entries, undefined, indexFileNames(scan.files));
      expect(whole.unresolved).toEqual([]);
      expect(whole.nodes.find((n) => n.id === 'libc.so')?.kind).toBe('file');

      // …and the same graph over a name index cut short is exactly the false row this change removes.
      const cut = indexFileNames(scan.files.filter((f) => f !== 'lib/libc.so'));
      expect(buildGraph(entries, undefined, cut).unresolved).toEqual(['libc.so']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('runComponentMap', () => {
  it('degrades honestly to available:false for a nonexistent rootfs', async () => {
    const res = await runComponentMap('/tmp/firmlab-compmap-does-not-exist-xyz');
    expect(res.available).toBe(false);
    expect(res.binaryCount).toBe(0);
    expect(res.graph).toEqual({ nodes: [], edges: [], unresolved: [] });
    expect(res.findings).toEqual([]);
  });
});
