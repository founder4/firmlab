import { describe, expect, it } from 'vitest';
import { assessDecoy, decoyFinding, zeroFraction } from './decoy.js';

/** A mostly-zeros buffer with `nonZero` non-zero bytes sprinkled in — a hollow image. */
function hollow(size: number, nonZero: number): Uint8Array {
  const b = new Uint8Array(size);
  for (let i = 0; i < nonZero; i++) b[Math.floor((i * size) / nonZero)] = (i % 255) + 1;
  return b;
}

describe('zeroFraction', () => {
  it('is ~1 for an all-zero buffer and ~0 for a dense one', () => {
    expect(zeroFraction(new Uint8Array(1000))).toBe(1);
    const dense = new Uint8Array(1000).map((_, i) => (i % 255) + 1);
    expect(zeroFraction(dense)).toBeLessThan(0.05);
  });
});

describe('assessDecoy', () => {
  it('flags a claimed-filesystem, mostly-zeros image with no rootfs as a decoy', () => {
    const a = assessDecoy(hollow(100_000, 5_000), { fsClaimed: true, rootfsRecovered: false });
    expect(a.isDecoy).toBe(true);
    expect(a.zeroFraction).toBeGreaterThan(0.9);
    expect(a.reason).toMatch(/zeros|unextractable/i);
  });

  it('does NOT flag when a rootfs was recovered', () => {
    expect(assessDecoy(hollow(100_000, 5_000), { fsClaimed: true, rootfsRecovered: true }).isDecoy).toBe(false);
  });

  it('does NOT flag a legitimately headerless blob (no filesystem claimed)', () => {
    // A high-zero image but nothing claimed a filesystem (e.g. a sparse encrypted region) — not a decoy.
    expect(assessDecoy(hollow(100_000, 5_000), { fsClaimed: false, rootfsRecovered: false }).isDecoy).toBe(false);
  });

  it('does NOT flag a dense image that merely failed to extract', () => {
    const dense = new Uint8Array(100_000).map((_, i) => (i % 255) + 1);
    expect(assessDecoy(dense, { fsClaimed: true, rootfsRecovered: false }).isDecoy).toBe(false);
  });
});

describe('decoyFinding', () => {
  it('emits a medium static_confirmed finding for a decoy, nothing otherwise', () => {
    const drafts = decoyFinding(assessDecoy(hollow(100_000, 3_000), { fsClaimed: true, rootfsRecovered: false }));
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('corrupt-decoy');
    expect(drafts[0]?.severity).toBe('medium');
    expect(drafts[0]?.proofState).toBe('static_confirmed');
    expect(decoyFinding({ isDecoy: false, zeroFraction: 0, reason: '' })).toHaveLength(0);
  });
});
