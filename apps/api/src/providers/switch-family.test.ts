import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_SWITCH_SCAN_BYTES, detectSwitchFamily } from '@firmlab/core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  DEFAULT_SWITCH_ROOTFS_LIMITS,
  type SwitchFileResult,
  aggregateSwitchFamilies,
  runSwitchFamilyAnalysis,
} from './switch-family.js';

const source = (filePath: string, text: string, lane: SwitchFileResult['lane'] = 'rootfs'): SwitchFileResult => ({
  lane,
  path: filePath,
  fileBytes: Buffer.byteLength(text),
  result: detectSwitchFamily(Buffer.from(text)),
});

describe('pure switch-family aggregation', () => {
  it('makes two families ambiguous across files, independent of order or counts', () => {
    const files = [source('z.ko', 'QCA8337 '.repeat(20)), source('a.ko', 'RTL8366')];
    const result = aggregateSwitchFamilies(files);
    expect(result.verdict).toBe('ambiguous');
    expect(result).toEqual(aggregateSwitchFamilies([...files].reverse()));
    expect(result.candidates.find((candidate) => candidate.family === 'qca8337')).toMatchObject({
      hitCount: 20,
      evidence: expect.arrayContaining([expect.objectContaining({ path: 'z.ko', lane: 'rootfs', offset: 0 })]),
    });
    expect(files[0]?.result.coverage.recordsDropped).toEqual([{ ruleId: 'qca8337-literal', dropped: 4 }]);
  });

  it('merges one family without promoting repeated template evidence', () => {
    const result = aggregateSwitchFamilies([source('b', 'RTL8367'), source('a', 'RTL8366')]);
    expect(result.verdict).toBe('template-only');
    expect(result.candidates[0]).toMatchObject({ hitCount: 2, distinctTokens: ['RTL8366', 'RTL8367'] });
  });

  it('never creates candidates from vendor names', () => {
    const result = aggregateSwitchFamilies([source('a', 'Realtek'), source('b', 'Broadcom Realtek')]);
    expect(result.verdict).toBe('vendor-only');
    expect(result.candidates).toEqual([]);
    expect(result.vendorMentions.find((vendor) => vendor.vendor === 'Realtek')?.count).toBe(2);
  });

  it('keeps cross-lane provenance and does not mutate inputs', () => {
    const files = [source('fw.bin', 'QCA8337', 'raw'), source('lib/a.ko', 'QCA8337')];
    const before = structuredClone(files);
    const result = aggregateSwitchFamilies(files);
    expect(result.verdict).toBe('single-family-lead');
    expect(result.candidates[0]?.evidence.map(({ lane, path }) => ({ lane, path }))).toEqual([
      { lane: 'raw', path: 'fw.bin' },
      { lane: 'rootfs', path: 'lib/a.ko' },
    ]);
    expect(files).toEqual(before);
    expect(result.summary).toMatch(/never identify live hardware/);
    expect(aggregateSwitchFamilies([]).summary).toMatch(/not evidence of no switch/);
  });
});

describe('bounded switch-family filesystem lanes', () => {
  let temporary: string;
  let image: string;
  let rootfs: string;
  beforeEach(async () => {
    temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'firmlab-switch-family-'));
    image = path.join(temporary, 'fw.bin');
    rootfs = path.join(temporary, 'rootfs');
    await fs.mkdir(rootfs);
    await fs.writeFile(image, 'opaque raw bytes');
  });
  afterEach(async () => {
    await fs.rm(temporary, { recursive: true, force: true });
  });

  it('runs raw-only and states no-rootfs as not run, without claiming a negative', async () => {
    await fs.writeFile(image, 'QCA8337');
    const result = await runSwitchFamilyAnalysis(image);
    expect(result.raw.status).toBe('completed');
    expect(result.raw.result?.verdict).toBe('single-family-lead');
    expect(result.rootfs).toMatchObject({ status: 'not-run', reason: 'not run: no extracted rootfs', result: null });
    expect(result.rootfs.coverage.filesExamined).toBe(0);
    expect(result.overall.verdict).toBe('single-family-lead');
    expect(result).not.toHaveProperty('findings');
  });

  it('aggregates uncompressed rootfs bytes across files into an ambiguous lane and overall result', async () => {
    await fs.mkdir(path.join(rootfs, 'lib'));
    await fs.writeFile(path.join(rootfs, 'lib/z.ko'), 'QCA8337');
    await fs.writeFile(path.join(rootfs, 'a'), 'BCM5315');
    const result = await runSwitchFamilyAnalysis(image, rootfs);
    expect(result.raw.result?.verdict).toBe('none-observed');
    expect(result.rootfs.status).toBe('completed');
    expect(result.rootfs.result?.verdict).toBe('ambiguous');
    expect(result.overall.verdict).toBe('ambiguous');
    expect(result.rootfs.files.map((file) => file.path)).toEqual(['a', 'lib/z.ko']);
    expect(
      result.rootfs.result?.candidates
        .flatMap((candidate) => candidate.evidence)
        .map((hit) => hit.path)
        .sort(),
    ).toEqual(['a', 'lib/z.ko']);
  });

  it('also detects ambiguity between the raw lane and a single-family rootfs lane', async () => {
    await fs.writeFile(image, 'RTL8366');
    await fs.writeFile(path.join(rootfs, 'driver'), 'QCA8337');
    const result = await runSwitchFamilyAnalysis(image, rootfs);
    expect(result.raw.result?.verdict).toBe('template-only');
    expect(result.rootfs.result?.verdict).toBe('single-family-lead');
    expect(result.overall.verdict).toBe('ambiguous');
  });

  it('selects by sorted relative path rather than creation order and reports a dropped file', async () => {
    await fs.writeFile(path.join(rootfs, 'z'), 'BCM5315');
    await fs.writeFile(path.join(rootfs, 'a'), 'QCA8337');
    const result = await runSwitchFamilyAnalysis(image, rootfs, { ...DEFAULT_SWITCH_ROOTFS_LIMITS, maxFiles: 1 });
    expect(result.rootfs.coverage).toMatchObject({
      filesDiscovered: 2,
      filesExamined: 1,
      filesSkipped: 1,
      filesTruncated: 0,
    });
    expect(result.rootfs.files.map((file) => file.path)).toEqual(['a']);
    expect(result.rootfs.status).toBe('partial');
    expect(result.rootfs.coverage.selection).toMatch(/ascending relative path/);
  });

  it('enforces per-file and total byte caps and reports all truncated and skipped files', async () => {
    for (const name of ['c', 'b', 'a']) await fs.writeFile(path.join(rootfs, name), 'QCA8337 more bytes');
    const result = await runSwitchFamilyAnalysis(image, rootfs, {
      ...DEFAULT_SWITCH_ROOTFS_LIMITS,
      maxBytesPerFile: 8,
      maxTotalBytes: 12,
    });
    expect(result.rootfs.coverage).toMatchObject({
      filesDiscovered: 3,
      filesExamined: 2,
      filesSkipped: 1,
      filesTruncated: 2,
      bytesScanned: 12,
    });
    expect(result.rootfs.files.map((file) => file.result.coverage.bytesScanned)).toEqual([8, 4]);
    expect(result.rootfs.files.every((file) => file.result.coverage.stoppedBy === 'input-truncated')).toBe(true);
    expect(result.rootfs.files[1]?.result.coverage.edgeUnresolved).toBe(1);
  });

  it('reports unknown inventory beyond its entry cap, without inventing skipped-file counts', async () => {
    await fs.writeFile(path.join(rootfs, 'z'), 'BCM5315');
    await fs.writeFile(path.join(rootfs, 'a'), 'QCA8337');
    const result = await runSwitchFamilyAnalysis(image, rootfs, { ...DEFAULT_SWITCH_ROOTFS_LIMITS, maxEntries: 1 });
    expect(result.rootfs.coverage).toMatchObject({
      inventoryComplete: false,
      entriesExamined: 1,
      filesDiscovered: 1,
      filesExamined: 1,
    });
    expect(result.rootfs.reason).toMatch(/undiscovered counts unknown/);
    expect(result.rootfs.status).toBe('partial');
  });

  it('never follows file or directory symlinks outside the rootfs, or internal symlinks', async () => {
    await fs.mkdir(path.join(temporary, 'outside'));
    await fs.writeFile(path.join(temporary, 'outside/chip'), 'QCA8337');
    await fs.writeFile(path.join(rootfs, 'plain'), 'neutral');
    await fs.symlink(path.join(temporary, 'outside/chip'), path.join(rootfs, 'file-link'));
    await fs.symlink(path.join(temporary, 'outside'), path.join(rootfs, 'dir-link'));
    await fs.symlink('plain', path.join(rootfs, 'internal-link'));
    const result = await runSwitchFamilyAnalysis(image, rootfs);
    expect(result.rootfs.coverage).toMatchObject({ filesExamined: 1, symlinksSkipped: 3 });
    expect(result.rootfs.result?.verdict).toBe('none-observed');
    expect(result.rootfs.files.map((file) => file.path)).toEqual(['plain']);
    // Unfollowed links hide no firmware bytes: an internal target is inventoried on its own path.
    expect(result.rootfs.status).toBe('completed');
  });

  it('reports stale rootfs and raw read failures as errors rather than an empty successful scan', async () => {
    const result = await runSwitchFamilyAnalysis(path.join(temporary, 'missing'), path.join(temporary, 'stale'));
    expect(result.raw).toMatchObject({ status: 'error', file: null, result: null });
    expect(result.rootfs).toMatchObject({ status: 'error', result: null });
    expect(result.rootfs.reason).toMatch(/could not run/);
  });

  it('caps a sparse raw image at the core detector limit and preserves its actual disk size', async () => {
    await fs.writeFile(image, 'QCA8337 ');
    await fs.truncate(image, DEFAULT_SWITCH_SCAN_BYTES + 8);
    const result = await runSwitchFamilyAnalysis(image);
    expect(result.raw.status).toBe('partial');
    expect(result.raw.file?.fileBytes).toBe(DEFAULT_SWITCH_SCAN_BYTES + 8);
    expect(result.raw.file?.result.coverage).toMatchObject({
      bytesScanned: DEFAULT_SWITCH_SCAN_BYTES,
      completed: false,
    });
  });

  it('rejects cancelled work and invalid limits before scanning', async () => {
    const cancellation = new AbortController();
    cancellation.abort();
    await expect(runSwitchFamilyAnalysis(image, rootfs, undefined, cancellation.signal)).rejects.toMatchObject({
      name: 'AbortError',
    });
    await expect(
      runSwitchFamilyAnalysis(image, rootfs, { ...DEFAULT_SWITCH_ROOTFS_LIMITS, maxFiles: 0 }),
    ).rejects.toThrow(/maxFiles/);
  });
});
