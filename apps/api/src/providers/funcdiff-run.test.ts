import { describe, expect, it } from 'vitest';
import { pathPriority, rankChangedPaths } from './funcdiff-run.js';

describe('pathPriority', () => {
  it('puts service directories ahead of everything else, most privileged first', () => {
    expect(pathPriority('usr/sbin/httpd')).toBeLessThan(pathPriority('usr/bin/curl'));
    expect(pathPriority('sbin/telnetd')).toBeLessThan(pathPriority('bin/ash'));
    expect(pathPriority('usr/lib/libc.so')).toBeGreaterThan(pathPriority('bin/ash'));
  });

  it('reads a leading ./ as the root, so a walk that emits one is not demoted', () => {
    expect(pathPriority('./usr/sbin/httpd')).toBe(pathPriority('usr/sbin/httpd'));
  });

  it('gives an unlisted directory one rank, below every listed one', () => {
    expect(pathPriority('etc/config')).toBe(pathPriority('var/run/x'));
    expect(pathPriority('etc/config')).toBeGreaterThan(pathPriority('bin/ash'));
  });
});

describe('rankChangedPaths', () => {
  // The defect this replaces: `shared` is sorted for determinism, so `.slice(0, 20)` kept the ALPHABETICALLY
  // first twenty. On a security patch that is `/bin/ash` ahead of `/usr/sbin/httpd`, which inverts the only
  // ordering an operator diffing two releases cares about.
  it('keeps the network-facing service ahead of the shell the alphabet would have preferred', () => {
    const ranked = rankChangedPaths(['bin/ash', 'usr/sbin/httpd'], () => 0);
    expect(ranked).toEqual(['usr/sbin/httpd', 'bin/ash']);
  });

  it('breaks a tie within a directory by the larger byte delta', () => {
    const delta: Record<string, number> = { 'usr/sbin/a': 12, 'usr/sbin/b': 4096, 'usr/sbin/c': 200 };
    expect(rankChangedPaths(Object.keys(delta), (p) => delta[p] ?? 0)).toEqual([
      'usr/sbin/b',
      'usr/sbin/c',
      'usr/sbin/a',
    ]);
  });

  // Stability is what makes the cap's cut reproducible rather than an artifact of walk order.
  it('falls back to the path when directory and delta both tie, and never mutates its input', () => {
    const input = ['usr/sbin/z', 'usr/sbin/a'];
    expect(rankChangedPaths(input, () => 7)).toEqual(['usr/sbin/a', 'usr/sbin/z']);
    expect(input).toEqual(['usr/sbin/z', 'usr/sbin/a']);
  });

  it('is a permutation: ranking drops nothing, the cap does that afterwards and says so', () => {
    const paths = ['etc/x', 'bin/ash', 'usr/sbin/httpd', 'usr/lib/libc.so', 'libexec/foo'];
    expect([...rankChangedPaths(paths, () => 0)].sort()).toEqual([...paths].sort());
  });
});
