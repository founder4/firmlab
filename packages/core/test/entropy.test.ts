import { describe, expect, it } from 'vitest';
import { computeEntropyProfile, windowEntropy } from '../src/entropy.js';

describe('windowEntropy', () => {
  it('is 0 for a uniform block', () => {
    const buf = new Uint8Array(1024).fill(0x41);
    expect(windowEntropy(buf, 0, buf.length)).toBe(0);
  });

  it('is 8 for a perfectly balanced byte distribution', () => {
    // Every byte value appears exactly once → maximum entropy.
    const buf = new Uint8Array(256);
    for (let i = 0; i < 256; i++) buf[i] = i;
    expect(windowEntropy(buf, 0, 256)).toBeCloseTo(8, 6);
  });

  it('is 1 for a two-symbol equiprobable block', () => {
    const buf = new Uint8Array(1024);
    for (let i = 0; i < 1024; i++) buf[i] = i % 2 === 0 ? 0x00 : 0xff;
    expect(windowEntropy(buf, 0, 1024)).toBeCloseTo(1, 6);
  });

  it('returns 0 for an empty range', () => {
    expect(windowEntropy(new Uint8Array(10), 5, 5)).toBe(0);
  });
});

describe('computeEntropyProfile', () => {
  it('flags a whole-image high-entropy blob as likely encrypted', () => {
    // Pseudo-random bytes across the whole image → uniformly high entropy.
    const buf = new Uint8Array(64 * 1024);
    let seed = 1234567;
    for (let i = 0; i < buf.length; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      buf[i] = (seed >>> 16) & 0xff;
    }
    const profile = computeEntropyProfile(buf, { windowSize: 4096 });
    expect(profile.mean).toBeGreaterThan(7.5);
    expect(profile.likelyEncrypted).toBe(true);
  });

  it('does not flag a low-entropy padded image as encrypted', () => {
    const buf = new Uint8Array(64 * 1024).fill(0x00);
    const profile = computeEntropyProfile(buf, { windowSize: 4096 });
    expect(profile.mean).toBe(0);
    expect(profile.likelyEncrypted).toBe(false);
    expect(profile.highEntropyRegions).toHaveLength(0);
  });

  it('detects an embedded high-entropy region among low-entropy structure', () => {
    const buf = new Uint8Array(64 * 1024).fill(0x00);
    // Fill the middle 16KB with high-entropy bytes.
    let seed = 42;
    for (let i = 24 * 1024; i < 40 * 1024; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      buf[i] = (seed >>> 16) & 0xff;
    }
    const profile = computeEntropyProfile(buf, { windowSize: 4096 });
    expect(profile.likelyEncrypted).toBe(false);
    expect(profile.likelyCompressed).toBe(true);
    expect(profile.highEntropyRegions.length).toBeGreaterThanOrEqual(1);
    const region = profile.highEntropyRegions[0];
    expect(region).toBeDefined();
    expect(region?.start).toBeGreaterThanOrEqual(20 * 1024);
    expect(region?.end).toBeLessThanOrEqual(44 * 1024);
  });

  it('handles an empty buffer', () => {
    const profile = computeEntropyProfile(new Uint8Array(0));
    expect(profile.samples).toHaveLength(0);
    expect(profile.mean).toBe(0);
  });
});
