import { describe, expect, it } from 'vitest';
import { analyzeImageBuffer, chooseEntropyWindow } from './analysis.js';

describe('chooseEntropyWindow', () => {
  it('keeps samples bounded (~2048) for large images', () => {
    const size = 500 * 1024 * 1024;
    const window = chooseEntropyWindow(size);
    expect(size / window).toBeLessThanOrEqual(4096);
    expect(window).toBeGreaterThanOrEqual(256);
  });

  it('never goes below the minimum window for tiny images', () => {
    expect(chooseEntropyWindow(1024)).toBe(256);
  });

  it('returns a power of two', () => {
    const w = chooseEntropyWindow(10 * 1024 * 1024);
    expect((w & (w - 1)) === 0).toBe(true);
  });
});

describe('analyzeImageBuffer', () => {
  it('produces a full analysis bundle for a planted image', () => {
    const buf = new Uint8Array(64 * 1024);
    buf.set([0x27, 0x05, 0x19, 0x56], 0); // uImage
    buf.set([0x68, 0x73, 0x71, 0x73], 0x8000); // squashfs
    const analysis = analyzeImageBuffer(buf);
    expect(analysis.size).toBe(buf.length);
    expect(analysis.identity.firmwareClass).toBe('embedded-linux');
    expect(analysis.structure.length).toBeGreaterThan(0);
    expect(analysis.entropy.samples.length).toBeGreaterThan(0);
  });
});
