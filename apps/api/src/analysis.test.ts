import { createHash } from 'node:crypto';
import { analyzeBuffer, scanSignaturesDetailed } from '@firmlab/core';
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

const BROM_NOR_BASE64 =
  'U0ZfQk9PVAD/////AQAAAAACAAD/////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '//////////////////////////////////////////////////////////////////////////////////9CUkxZVAAAAAEAAAAA' +
  'BgAAIQoAAEJCQkIHAAEAAAYAACEKAAD/////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////TU1NATgAAABGSUxFX0lORk8AAAABAAAAAQAFAQANIAAhBAAAIQoA' +
  'AAADAAAgAAAAAAMAAAEAAABNTU0BDAABAAEAAABNTU0DZAAHAJABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiBMAAAAAAAAAAAAATU1NARQCAwAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE1NTQEUAAIAAAAAABAA' +
  'AACAAAAATU1NATAACAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAwQFBgcICQoLDA0ODxAREhMU' +
  'FRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f' +
  'YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmq' +
  'q6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T1' +
  '9vf4+fr7/P3+/6VLLq1qkzlkvEucrCqMfLJX0ImhBSdIuZd/s2MRyA02Tw==';

// Actual packaged U-Boot mkimage output; its full-file hash pins the independent fixture.
function bromNor(): Uint8Array {
  const bytes = Uint8Array.from(Buffer.from(BROM_NOR_BASE64, 'base64'));
  expect(createHash('sha256').update(bytes).digest('hex')).toBe(
    'e90664dda0beec0b9af8e8dfc17a693407e711128caef3e75f0059815464c9e9',
  );
  return bytes;
}

describe('native MediaTek BootROM digest at intake', () => {
  it('verifies real mkimage bytes only through the API native capability', () => {
    const bytes = bromNor();
    const core = analyzeBuffer(bytes);
    const api = analyzeImageBuffer(bytes);
    expect(core.signatures.find((h) => h.id === 'mediatek-brom-nor')?.tier).toBe('consistent');
    expect(api.signatures.find((h) => h.id === 'mediatek-brom-nor')).toMatchObject({
      tier: 'verified',
      score: 99,
      meta: { digest: 'verified' },
    });
  });
});

describe('native digest intake bounds and coherence', () => {
  it.each([0x900, 2592])('keeps mutation at %i visible as mismatch, retaining counts and classification', (at) => {
    const bytes = bromNor();
    bytes[at] = (bytes[at] ?? 0) ^ 1;
    const raw = scanSignaturesDetailed(bytes);
    const core = analyzeBuffer(bytes);
    const analysis = analyzeImageBuffer(bytes);
    const candidate = analysis.signatures.find((h) => h.id === 'mediatek-brom-nor');
    expect(candidate).toMatchObject({ tier: 'consistent', score: 85, meta: { digest: 'mismatch' } });
    expect(analysis.signatureDigests).toMatchObject({
      listed: 1,
      attempted: 1,
      completed: 1,
      mismatched: 1,
      matched: 0,
    });
    expect(analysis.signatureScan).toEqual({ ...raw, hits: analysis.signatures });
    expect(analysis.identity).toEqual(core.identity);
    expect(analysis.signatures).toBe(analysis.signatureScan?.hits);
    expect(analysis.structure.find((s) => s.start === candidate?.offset)?.meta).toEqual(candidate?.meta);
  });

  it('supports embedded byte views and preserves source bytes while verifying only the declared GFH/payload', () => {
    const backing = new Uint8Array(4000).fill(0xa5);
    const view = backing.subarray(13, 3513);
    view.set(bromNor(), 7);
    const before = backing.slice();
    const analysis = analyzeImageBuffer(view);
    expect(analysis.signatures.find((h) => h.id === 'mediatek-brom-nor')).toMatchObject({
      offset: 7,
      tier: 'verified',
      score: 99,
      meta: { digest: 'verified', digestCoveredStart: 1543, digestCoveredEnd: 2568 },
    });
    expect(analysis.signatureDigests).toMatchObject({ bytesSubmitted: 1025, bytesCompleted: 1025 });
    expect(backing).toEqual(before);
  });

  it('hash-matches another valid unhashed media header without authenticating the device or BRLYT', () => {
    const bytes = bromNor();
    bytes.fill(0xff, 0, 12);
    bytes.set(Buffer.from('SDMMC_BOOT\0'));
    new DataView(bytes.buffer).setUint32(0x218, 0x10008, true);
    const analysis = analyzeImageBuffer(bytes);
    const candidate = analysis.signatures.find((h) => h.id === 'mediatek-brom-sdmmc');
    expect(candidate).toMatchObject({ tier: 'verified', meta: { digest: 'verified', declaredMedia: 'sdmmc' } });
    expect(candidate?.rationale).toContain('first 0x600 device/BRLYT bytes');
    expect(candidate?.rationale).toContain('No authenticity, device, boot, execution or whole-image clean proof');
  });

  it('never verifies invalid/truncated envelopes and records zero listed candidates without a clean claim', () => {
    const invalid = bromNor();
    invalid[12] = 2;
    for (const bytes of [new Uint8Array(0), invalid, bromNor().subarray(0, 2592)]) {
      const analysis = analyzeImageBuffer(bytes);
      expect(analysis.signatures.filter((h) => h.id.startsWith('mediatek-brom-'))).toEqual([]);
      expect(analysis.signatureDigests).toMatchObject({ listed: 0, planned: 0, attempted: 0, completed: 0 });
      expect(analysis.signatureDigests?.note).toContain('not whole-image clean');
      expect(JSON.parse(JSON.stringify(analysis))).toEqual(analysis);
    }
  });

  it('enforces native per-analysis execution limits and persists honest partial coverage without digest values', () => {
    const unit = bromNor();
    const bytes = new Uint8Array(unit.length * 10);
    for (let n = 0; n < 10; n++) bytes.set(unit, unit.length * n);
    const before = bytes.slice();
    const analysis = analyzeImageBuffer(bytes);
    expect(analysis.signatures).toHaveLength(10);
    expect(analysis.signatureDigests).toMatchObject({
      listed: 10,
      planned: 10,
      attempted: 8,
      completed: 8,
      matched: 8,
      skipped: 2,
    });
    expect(analysis.signatures.filter((h) => h.tier === 'verified')).toHaveLength(8);
    expect(analysis.signatures.filter((h) => h.meta?.digest === 'skipped_budget')).toHaveLength(2);
    const json = JSON.stringify(analysis);
    expect(JSON.parse(json)).toEqual(analysis);
    expect(json).not.toContain(Buffer.from(unit.subarray(2561)).toString('hex'));
    expect(bytes).toEqual(before);
    for (const candidate of analysis.signatures) {
      expect(analysis.structure.find((s) => s.start === candidate.offset)?.meta).toEqual(candidate.meta);
    }
  });
});
