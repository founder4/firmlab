import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_SWITCH_SCAN_BYTES, detectSwitchFamily } from '@firmlab/core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  DEFAULT_SWITCH_ROOTFS_LIMITS,
  SWITCH_SKIPPED_PATHS_RECORDED,
  type SwitchFileResult,
  aggregateSwitchFamilies,
  orderSwitchRootfsFiles,
  runSwitchFamilyAnalysis,
  switchPathRank,
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
  });

  it('calls an aggregate over zero scanned bytes not-scanned, never none-observed', () => {
    const none = aggregateSwitchFamilies([], { notScannedBecause: 'raw lane error (gone)' });
    expect(none.verdict).toBe('not-scanned');
    expect(none.summary).toMatch(/^No bytes were scanned: no file was read; raw lane error \(gone\)\./);
    expect(none.summary).toMatch(/not a negative result/);
    expect(none.summary).not.toMatch(/observed/);
    expect(none.inputs).toEqual({ files: 0, bytesScanned: 0, lanes: [] });
    const empty = aggregateSwitchFamilies([source('empty', '')]);
    expect(empty.verdict).toBe('not-scanned');
    expect(empty.summary).toMatch(/the 1 file\(s\) read held no bytes/);
    // One byte read is enough for a negative-shaped verdict, and it still disclaims absence.
    expect(aggregateSwitchFamilies([source('a', 'x')]).verdict).toBe('none-observed');
  });

  it('keeps per-lane counts exact and labels the overall count as a sum that may overlap across lanes', () => {
    const text = 'QCA8337 Realtek RTL8367RB';
    const both = aggregateSwitchFamilies([source('fw.bin', text, 'raw'), source('lib/a.ko', text)]);
    expect(both.candidates[0]).toMatchObject({ hitCount: 2, hitCountByLane: { raw: 1, rootfs: 1 } });
    expect(both.vendorMentions[0]).toMatchObject({ vendor: 'Realtek', count: 2, countByLane: { raw: 1, rootfs: 1 } });
    expect(both.nearMisses?.countByLane).toEqual({ raw: 1, rootfs: 1 });
    expect(both.countBasis).toMatch(/may count one occurrence twice/);
    expect(both.summary).toMatch(/Overall counts are per-lane sums and may count bytes both lanes saw twice/);
    expect(both.inputs).toMatchObject({ files: 2, lanes: ['raw', 'rootfs'] });

    const one = aggregateSwitchFamilies([source('a.ko', text), source('b.ko', text)]);
    expect(one.candidates[0]).toMatchObject({ hitCount: 2, hitCountByLane: { rootfs: 2 } });
    expect(one.countBasis).toMatch(/single lane; no lane overlap is possible/);
    expect(one.summary).not.toMatch(/per-lane sums/);
  });

  it('carries rejected near-misses into a none-observed summary without creating a candidate', () => {
    const result = aggregateSwitchFamilies([
      source('fw.bin', ' RTL8367RB ', 'raw'),
      source('lib/b53.ko', ' BCM53125 '),
    ]);
    expect(result.verdict).toBe('none-observed');
    expect(result.candidates).toEqual([]);
    expect(result.nearMisses).toMatchObject({
      count: 2,
      examples: [
        { lane: 'raw', path: 'fw.bin', token: 'RTL8367RB' },
        { lane: 'rootfs', path: 'lib/b53.ko', token: 'BCM53125' },
      ],
    });
    expect(result.summary).toMatch(
      /2 family-shaped token\(s\) \(e\.g\. RTL8367RB, BCM53125\) were seen and deliberately not/,
    );
    expect(result.summary).toMatch(/not evidence of no switch/);
  });

  it('tolerates per-file results stored before near-misses existed', () => {
    const { nearMisses: _absent, ...stored } = source('a', ' RTL8367 ').result;
    const old: SwitchFileResult = { lane: 'rootfs', path: 'a', fileBytes: 9, result: stored };
    const result = aggregateSwitchFamilies([old]);
    expect(result.verdict).toBe('template-only');
    expect(result.nearMisses?.count).toBe(0);
  });

  it('ranks rootfs paths by where switch literals live, then by path', () => {
    expect(switchPathRank('lib/modules/5.4/net/dsa/x.bin')).toBe(0);
    expect(switchPathRank('usr/lib/modules/rtl8367.ko')).toBe(0);
    expect(switchPathRank('anywhere/qca8k.ko')).toBe(0);
    expect(switchPathRank('boot/vmlinux')).toBe(1);
    expect(switchPathRank('boot/zImage-5.4')).toBe(1);
    expect(switchPathRank('boot/board.dtb')).toBe(2);
    expect(switchPathRank('usr/lib/libshared.so')).toBe(3);
    expect(switchPathRank('opt/x/libfoo.so.1.2')).toBe(3);
    expect(switchPathRank('usr/sbin/swconfig')).toBe(3);
    expect(switchPathRank('lib64/ld.so.conf')).toBe(3);
    expect(switchPathRank('etc/config/network')).toBe(4);
    expect(switchPathRank('www/libjs/app.js')).toBe(3);
    expect(switchPathRank('www/index.html')).toBe(4);
    expect(orderSwitchRootfsFiles(['etc/b', 'bin/a', 'usr/lib/libshared.so', 'lib/z.ko', 'boot/a.dtb'])).toEqual([
      'lib/z.ko',
      'boot/a.dtb',
      'bin/a',
      'usr/lib/libshared.so',
      'etc/b',
    ]);
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
    // A kernel module outranks an unranked file; aggregation still orders evidence by path.
    expect(result.rootfs.files.map((file) => file.path)).toEqual(['lib/z.ko', 'a']);
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

  it('breaks rank ties by sorted relative path rather than creation order and reports a dropped file', async () => {
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
    expect(result.rootfs.coverage.selection).toMatch(/ties go by ascending relative path/);
    expect(result.rootfs.coverage.skippedPaths).toEqual(['z']);
    expect(result.rootfs.reason).toMatch(/First skipped by the cap, in selection order: z\./);
  });

  it('keeps the likeliest files under the file cap instead of the first in the alphabet', async () => {
    for (const [name, text] of [
      ['bin/a', 'neutral'],
      ['etc/b', 'neutral'],
      ['usr/lib/libshared.so', 'BCM5397'],
      ['lib/modules/5.4/rtl8367.ko', 'neutral'],
      ['www/index.html', 'neutral'],
    ] as const) {
      await fs.mkdir(path.dirname(path.join(rootfs, name)), { recursive: true });
      await fs.writeFile(path.join(rootfs, name), text);
    }
    const result = await runSwitchFamilyAnalysis(image, rootfs, { ...DEFAULT_SWITCH_ROOTFS_LIMITS, maxFiles: 3 });
    expect(result.rootfs.files.map((file) => file.path)).toEqual([
      'lib/modules/5.4/rtl8367.ko',
      'bin/a',
      'usr/lib/libshared.so',
    ]);
    expect(result.rootfs.result?.verdict).toBe('template-only');
    expect(result.rootfs.coverage.skippedPaths).toEqual(['etc/b', 'www/index.html']);
    expect(result.rootfs.coverage.selection).toMatch(/ranked by where switch literals live BEFORE any cap applies/);
  });

  it('records at most the stated number of skipped paths and says how many more there were', async () => {
    const total = SWITCH_SKIPPED_PATHS_RECORDED + 3;
    for (let k = 0; k < total; k++) await fs.writeFile(path.join(rootfs, `f${String(k).padStart(2, '0')}`), 'x');
    const result = await runSwitchFamilyAnalysis(image, rootfs, { ...DEFAULT_SWITCH_ROOTFS_LIMITS, maxFiles: 1 });
    expect(result.rootfs.coverage.filesSkipped).toBe(total - 1);
    expect(result.rootfs.coverage.skippedPaths).toHaveLength(SWITCH_SKIPPED_PATHS_RECORDED);
    expect(result.rootfs.coverage.skippedPaths?.[0]).toBe('f01');
    expect(result.rootfs.reason).toMatch(/and 2 more\./);
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
    expect(result.overall.verdict).toBe('not-scanned');
    expect(result.overall.summary).toMatch(/^No bytes were scanned: no file was read; raw lane error \(Raw image not/);
    expect(result.overall.summary).toMatch(/rootfs lane error \(Rootfs lane could not run/);
    expect(result.overall.summary).not.toMatch(/observed/);
  });

  it('calls an unreadable image with no rootfs not-scanned, naming both lanes', async () => {
    const result = await runSwitchFamilyAnalysis(path.join(temporary, 'missing'));
    expect(result.raw.status).toBe('error');
    expect(result.rootfs.status).toBe('not-run');
    expect(result.overall.verdict).toBe('not-scanned');
    expect(result.overall.summary).toMatch(/raw lane error .*; rootfs lane not-run \(not run: no extracted rootfs\)/);
  });

  it('calls an empty rootfs not-scanned in its lane while the raw lane still decides overall', async () => {
    const result = await runSwitchFamilyAnalysis(image, rootfs);
    expect(result.rootfs.status).toBe('completed');
    expect(result.rootfs.result?.verdict).toBe('not-scanned');
    expect(result.rootfs.result?.summary).toMatch(/no file was read; rootfs lane completed \(0 of 0 discovered/);
    expect(result.overall.verdict).toBe('none-observed');
  });

  it.skipIf(process.getuid?.() === 0)(
    'calls a rootfs whose every file failed to read not-scanned, never none-observed',
    async () => {
      await fs.writeFile(path.join(rootfs, 'locked'), 'QCA8337');
      await fs.chmod(path.join(rootfs, 'locked'), 0o000);
      const result = await runSwitchFamilyAnalysis(path.join(temporary, 'missing'), rootfs);
      expect(result.rootfs.status).toBe('partial');
      expect(result.rootfs.coverage).toMatchObject({ filesDiscovered: 1, filesExamined: 0, filesSkipped: 1 });
      expect(result.rootfs.coverage.skippedPaths).toEqual([]);
      expect(result.rootfs.result?.verdict).toBe('not-scanned');
      expect(result.rootfs.result?.summary).toMatch(/0 of 1 discovered regular file\(s\) read/);
      expect(result.overall.verdict).toBe('not-scanned');
    },
  );

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
