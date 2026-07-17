import type { FsNode, ImageIdentity } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import { diffCves, diffFiles, diffIdentity, diffPackages, flattenFiles } from './diff.js';
import type { SbomVuln } from './sbom.js';

const identity = (over: Partial<ImageIdentity>): ImageIdentity => ({
  firmwareClass: 'embedded-linux',
  arch: 'mipsel',
  endianness: 'little',
  filesystems: ['squashfs'],
  ...over,
});

describe('diffIdentity', () => {
  it('returns only differing fields', () => {
    const a = identity({ arch: 'mipsel' });
    const b = identity({ arch: 'arm', bootloader: 'U-Boot' });
    const changes = diffIdentity(a, b);
    const fields = changes.map((c) => c.field).sort();
    expect(fields).toEqual(['arch', 'bootloader']);
    expect(changes.find((c) => c.field === 'arch')).toEqual({ field: 'arch', a: 'mipsel', b: 'arm' });
  });

  it('treats filesystems order-independently', () => {
    const a = identity({ filesystems: ['squashfs', 'jffs2'] });
    const b = identity({ filesystems: ['jffs2', 'squashfs'] });
    expect(diffIdentity(a, b)).toEqual([]);
  });

  it('reports a missing side as em-dash', () => {
    const changes = diffIdentity(null, identity({}));
    expect(changes.find((c) => c.field === 'arch')).toEqual({ field: 'arch', a: '—', b: 'mipsel' });
  });
});

describe('diffPackages', () => {
  it('classifies added, removed, and version-changed packages', () => {
    const a = [
      { name: 'openssl', version: '1.1.1' },
      { name: 'busybox', version: '1.30' },
    ];
    const b = [
      { name: 'openssl', version: '1.1.1w' },
      { name: 'dropbear', version: '2022.82' },
    ];
    const d = diffPackages(a, b);
    expect(d.added).toEqual([{ name: 'dropbear', version: '2022.82' }]);
    expect(d.removed).toEqual([{ name: 'busybox', version: '1.30' }]);
    expect(d.changed).toEqual([{ name: 'openssl', a: '1.1.1', b: '1.1.1w' }]);
  });
});

describe('diffCves', () => {
  const vuln = (id: string, severity: SbomVuln['severity']): SbomVuln => ({
    id,
    severity,
    packageName: 'pkg',
    packageVersion: '1',
    fixedIn: null,
  });

  it('tallies newly-introduced CVEs by severity', () => {
    const a = [vuln('CVE-1', 'High')];
    const b = [vuln('CVE-1', 'High'), vuln('CVE-2', 'Critical'), vuln('CVE-3', 'Low')];
    const d = diffCves(a, b);
    expect(d.addedIds).toEqual(['CVE-2', 'CVE-3']);
    expect(d.removedIds).toEqual([]);
    expect(d.addedBySeverity.Critical).toBe(1);
    expect(d.addedBySeverity.Low).toBe(1);
    expect(d.addedBySeverity.High).toBe(0);
  });
});

describe('flattenFiles / diffFiles', () => {
  const node = (path: string, type: FsNode['type'], size: number, children?: FsNode[]): FsNode => ({
    path,
    name: path.split('/').pop() ?? path,
    type,
    size,
    ...(children ? { children } : {}),
  });

  it('flattens only file nodes into a path→size map', () => {
    const tree = node('', 'dir', 0, [
      node('bin', 'dir', 0, [node('bin/ls', 'file', 100)]),
      node('etc', 'dir', 0, [node('etc/passwd', 'file', 42), node('etc/link', 'symlink', 0)]),
    ]);
    const flat = flattenFiles(tree);
    expect([...flat.keys()].sort()).toEqual(['bin/ls', 'etc/passwd']);
    expect(flat.get('etc/passwd')).toBe(42);
  });

  it('classifies added, removed, and size-changed files', () => {
    const a = node('', 'dir', 0, [node('a', 'file', 1), node('common', 'file', 10)]);
    const b = node('', 'dir', 0, [node('b', 'file', 2), node('common', 'file', 20)]);
    const d = diffFiles(a, b);
    expect(d.added).toEqual(['b']);
    expect(d.removed).toEqual(['a']);
    expect(d.changed).toEqual(['common']);
    expect(d.counts).toEqual({ added: 1, removed: 1, changed: 1 });
  });

  it('reports no data gracefully for null trees', () => {
    expect(flattenFiles(null).size).toBe(0);
  });
});
