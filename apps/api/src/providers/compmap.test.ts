import { describe, expect, it } from 'vitest';
import { buildGraph, isElf, orphanBinaries, parseNeeded, runComponentMap } from './compmap.js';

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
