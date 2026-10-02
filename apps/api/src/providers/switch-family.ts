/**
 * Static switch-family leads from the raw image and, separately, uncompressed extracted files. Only core's
 * detector supplies mappings; aggregation never upgrades a template or vendor name to exact family evidence.
 * No findings are emitted and nothing here identifies live hardware or chooses an emulation/tagging format.
 * Both reads and rootfs inventory are bounded, with deterministic selection and explicit incomplete coverage.
 *
 * **No bytes, no verdict.** An aggregate over zero scanned bytes — the raw image unreadable and no rootfs file read,
 * or a rootfs whose every file failed — is `not-scanned` and names the lanes' statuses, never `none-observed`.
 *
 * **The file cap keeps the likeliest files, not the first in the alphabet.** Switch literals live in kernel modules,
 * kernel images, device trees and the libraries and binaries that drive the switch, so those are ranked first and the
 * cap drops the rest; a cap that kept `bin/` and `etc/` over `usr/lib/libshared.so` made the set an artifact of
 * directory layout. The ranking is stated in `coverage.selection` and the first dropped paths are recorded.
 *
 * **Counts are per lane; the overall figure is a sum that may overlap.** A rootfs stored uncompressed inside the image
 * shows the same literal to both lanes. Overall `hitCount` / `count` keep their stored meaning (a sum over every file
 * in every lane), each candidate and vendor also carries its per-lane counts, and `countBasis` says which applies.
 */
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import {
  DEFAULT_SWITCH_SCAN_BYTES,
  DEFERRED_SWITCH_MAPPINGS,
  NEAR_MISS_EXAMPLES,
  type SwitchEvidenceHit,
  type SwitchFamilyCandidate,
  type SwitchFamilyResult,
  type SwitchFamilyVerdict,
  type SwitchNearMissExample,
  detectSwitchFamily,
  nearMissSentence,
} from '@firmlab/core';

export interface SwitchFileResult {
  lane: 'raw' | 'rootfs';
  /** Image basename for raw input; rootfs-relative path otherwise. Offsets are relative to this file. */
  path: string;
  fileBytes: number;
  result: SwitchFamilyResult;
}

type SwitchLane = SwitchFileResult['lane'];
/** Per-lane counts. A lane absent from the record contributed nothing. */
export type SwitchLaneCounts = Partial<Record<SwitchLane, number>>;

export interface SwitchFamilyAggregate {
  verdict: SwitchFamilyVerdict;
  candidates: (Omit<SwitchFamilyCandidate, 'evidence'> & {
    evidence: (SwitchEvidenceHit & { lane: SwitchLane; path: string })[];
    /** `hitCount` split by lane; each lane's figure is exact. Absent on results stored by older builds. */
    hitCountByLane?: SwitchLaneCounts;
  })[];
  vendorMentions: {
    vendor: string;
    count: number;
    /** `count` split by lane; each lane's figure is exact. Absent on results stored by older builds. */
    countByLane?: SwitchLaneCounts;
    sources: { lane: SwitchLane; path: string; offsets: number[] }[];
  }[];
  /** Family-shaped tokens the boundary rule rejected, summed per file. Never candidates. Optional: older builds. */
  nearMisses?: {
    count: number;
    countByLane: SwitchLaneCounts;
    /** First file's occurrence of each distinct token, in lane/path order, at most `NEAR_MISS_EXAMPLES`. */
    examples: (SwitchNearMissExample & { lane: SwitchLane; path: string })[];
  };
  /** What was actually scanned. Optional: absent on results stored by older builds. */
  inputs?: { files: number; bytesScanned: number; lanes: SwitchLane[] };
  /** How `hitCount` and vendor `count` were formed, and whether lanes may overlap. Optional: older builds. */
  countBasis?: string;
  deferred: SwitchFamilyResult['deferred'];
  summary: string;
}

const NOT_SCANNED = 'This is not a negative result: nothing is known about switch-family literals in these bytes.';
const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const LANES: readonly SwitchLane[] = ['raw', 'rootfs'];

function bump(counts: SwitchLaneCounts | undefined, lane: SwitchLane, by: number): SwitchLaneCounts {
  const next = { ...counts };
  if (by > 0) next[lane] = (next[lane] ?? 0) + by;
  return next;
}

export interface SwitchAggregateOptions {
  /** Why nothing may have been scanned (the lanes' statuses), quoted if the aggregate turns out `not-scanned`. */
  notScannedBecause?: string;
}

/** Pure: combine detector outputs, preserving all per-file counts, evidence provenance and core verdict rules. */
export function aggregateSwitchFamilies(
  files: readonly SwitchFileResult[],
  options: SwitchAggregateOptions = {},
): SwitchFamilyAggregate {
  const candidates: SwitchFamilyAggregate['candidates'] = [];
  const vendorMentions: SwitchFamilyAggregate['vendorMentions'] = [];
  const nearMisses: NonNullable<SwitchFamilyAggregate['nearMisses']> = { count: 0, countByLane: {}, examples: [] };
  const exampleTokens = new Set<string>();
  const lanes = new Set<SwitchLane>();
  let bytesScanned = 0;
  for (const file of [...files].sort((a, b) => compare(a.lane, b.lane) || compare(a.path, b.path))) {
    lanes.add(file.lane);
    bytesScanned += file.result.coverage.bytesScanned;
    for (const candidate of file.result.candidates) {
      let combined = candidates.find((item) => item.family === candidate.family);
      if (!combined) {
        combined = { ...candidate, hitCount: 0, hitCountByLane: {}, distinctTokens: [], evidence: [] };
        candidates.push(combined);
      }
      if (candidate.standing === 'exact-literal') combined.standing = 'exact-literal';
      combined.hitCount += candidate.hitCount;
      combined.hitCountByLane = bump(combined.hitCountByLane, file.lane, candidate.hitCount);
      combined.distinctTokens = [...new Set([...combined.distinctTokens, ...candidate.distinctTokens])].sort(compare);
      combined.evidence.push(...candidate.evidence.map((hit) => ({ ...hit, lane: file.lane, path: file.path })));
    }
    for (const vendor of file.result.vendorMentions) {
      let combined = vendorMentions.find((item) => item.vendor === vendor.vendor);
      if (!combined) {
        combined = { vendor: vendor.vendor, count: 0, countByLane: {}, sources: [] };
        vendorMentions.push(combined);
      }
      combined.count += vendor.count;
      combined.countByLane = bump(combined.countByLane, file.lane, vendor.count);
      combined.sources.push({ lane: file.lane, path: file.path, offsets: [...vendor.offsets] });
    }
    const misses = file.result.nearMisses;
    if (misses && misses.count > 0) {
      nearMisses.count += misses.count;
      nearMisses.countByLane = bump(nearMisses.countByLane, file.lane, misses.count);
      for (const example of misses.examples) {
        const key = example.token.toUpperCase();
        if (exampleTokens.has(key) || nearMisses.examples.length >= NEAR_MISS_EXAMPLES) continue;
        exampleTokens.add(key);
        nearMisses.examples.push({ ...example, lane: file.lane, path: file.path });
      }
    }
  }
  candidates.sort((a, b) => compare(a.family, b.family));
  vendorMentions.sort((a, b) => compare(a.vendor, b.vendor));
  const verdict: SwitchFamilyVerdict =
    candidates.length >= 2
      ? 'ambiguous'
      : candidates.length === 1
        ? candidates[0]?.standing === 'exact-literal'
          ? 'single-family-lead'
          : 'template-only'
        : vendorMentions.length > 0
          ? 'vendor-only'
          : bytesScanned === 0
            ? 'not-scanned'
            : 'none-observed';
  const inputs = { files: files.length, bytesScanned, lanes: LANES.filter((lane) => lanes.has(lane)) };
  const countBasis =
    inputs.lanes.length > 1
      ? 'hitCount, vendor count and nearMisses.count are sums over every file in every lane. The raw image can ' +
        'contain the same bytes as an extracted file (an uncompressed rootfs), so the overall figure may count one ' +
        'occurrence twice; each per-lane figure (hitCountByLane, countByLane) is exact within that lane.'
      : 'hitCount, vendor count and nearMisses.count are sums over the files of a single lane; no lane overlap is ' +
        'possible.';

  if (verdict === 'not-scanned') {
    const what =
      files.length === 0 ? 'no file was read' : `the ${files.length} file(s) read held no bytes (0 bytes scanned)`;
    return {
      verdict,
      candidates,
      vendorMentions,
      nearMisses,
      inputs,
      countBasis,
      deferred: DEFERRED_SWITCH_MAPPINGS,
      summary: `No bytes were scanned: ${what}${options.notScannedBecause ? `; ${options.notScannedBecause}` : ''}. ${NOT_SCANNED}`,
    };
  }
  const explanation: Record<Exclude<SwitchFamilyVerdict, 'not-scanned'>, string> = {
    ambiguous: 'Literals from multiple families are present; counts and file order cannot choose a family.',
    'single-family-lead': 'Only one family has an exact literal in the scanned bytes.',
    'template-only': 'Only unverified family-template tokens are present; they cannot single out a family.',
    'vendor-only': 'Only vendor names are present; vendor names are never switch-family candidates.',
    'none-observed':
      'No family literal or vendor name was observed in the scanned bytes; this is not evidence of no switch.',
  };
  const rejected =
    (verdict === 'none-observed' || verdict === 'vendor-only') && nearMisses.count > 0
      ? ` ${nearMissSentence(
          nearMisses.count,
          nearMisses.examples.map((example) => example.token),
        )}${inputs.lanes.length > 1 ? ' That count is a per-lane sum and may overlap.' : ''}`
      : '';
  const overlap =
    inputs.lanes.length > 1 && (candidates.length > 0 || vendorMentions.length > 0)
      ? ' Overall counts are per-lane sums and may count bytes both lanes saw twice; per-lane counts are exact.'
      : '';
  return {
    verdict,
    candidates,
    vendorMentions,
    nearMisses,
    inputs,
    countBasis,
    deferred: DEFERRED_SWITCH_MAPPINGS,
    summary: `${explanation[verdict]}${rejected}${overlap} Static leads may belong to dormant drivers for other boards, never identify live hardware, and do not prove networking or emulation works. Compressed, encrypted and unscanned bytes remain unknown; consult each lane and file coverage.`,
  };
}

/** Cap-skipped rootfs paths recorded by name, in selection order. `filesSkipped` keeps the full count. */
export const SWITCH_SKIPPED_PATHS_RECORDED = 8;

const KERNEL_IMAGE = /^(vmlinu[xz]|zimage|uimage|bzimage|kernel)([._-].*)?$/i;
const LIB_OR_BIN_DIR = /^(lib[^/]*|s?bin)$/i;
const SHARED_LIBRARY = /\.so(\.[0-9][0-9.]*)?$/i;

/**
 * Pure: how likely a rootfs-relative path is to hold a switch literal, lower first. 0: kernel modules (`*.ko`,
 * anything under a `lib/modules/` directory). 1: kernel images (`vmlinux`, `vmlinuz`, `zImage`, `uImage`,
 * `bzImage`, `kernel`, with or without a suffix). 2: device trees (`*.dtb`, `*.dtbo`). 3: shared libraries (`*.so`,
 * `*.so.N`) and anything under a `lib*`, `bin` or `sbin` directory. 4: everything else.
 */
export function switchPathRank(relative: string): number {
  const segments = relative.split('/');
  const base = (segments.at(-1) ?? '').toLowerCase();
  const dirs = segments.slice(0, -1);
  if (base.endsWith('.ko') || /(^|\/)lib\/modules\//.test(relative)) return 0;
  if (KERNEL_IMAGE.test(base)) return 1;
  if (base.endsWith('.dtb') || base.endsWith('.dtbo')) return 2;
  if (SHARED_LIBRARY.test(base) || dirs.some((dir) => LIB_OR_BIN_DIR.test(dir))) return 3;
  return 4;
}

/** Pure: order discovered files for the cap — by `switchPathRank`, then ascending relative path (code-unit order). */
export function orderSwitchRootfsFiles(paths: readonly string[]): string[] {
  return [...paths].sort((a, b) => switchPathRank(a) - switchPathRank(b) || compare(a, b));
}

const SWITCH_ROOTFS_SELECTION = [
  'Inventory uses sorted directory names in depth-first order, capped by maxEntries. Discovered regular files are',
  'then ranked by where switch literals live BEFORE any cap applies: kernel modules (*.ko, lib/modules/**), then',
  'kernel images (vmlinux, vmlinuz, zImage, uImage, bzImage, kernel*), then device trees (*.dtb, *.dtbo), then',
  'shared libraries (*.so*) and files under lib*, bin and sbin directories, then everything else; ties go by',
  'ascending relative path (code-unit order). Prefixes are read in that order up to maxFiles, maxBytesPerFile and',
  `maxTotalBytes, and the first ${SWITCH_SKIPPED_PATHS_RECORDED} cap-skipped paths are recorded in skippedPaths.`,
  'All symlinks are skipped. Counts exclude unknown entries beyond incomplete inventory.',
].join(' ');

export interface SwitchRootfsLimits {
  maxFiles: number;
  maxBytesPerFile: number;
  maxTotalBytes: number;
  maxEntries: number;
}

export const DEFAULT_SWITCH_ROOTFS_LIMITS: Readonly<SwitchRootfsLimits> = {
  maxFiles: 1024,
  maxBytesPerFile: 4 * 1024 * 1024,
  maxTotalBytes: 64 * 1024 * 1024,
  maxEntries: 50_000,
};

export interface SwitchRootfsLane {
  status: 'completed' | 'partial' | 'not-run' | 'error';
  reason: string;
  result: SwitchFamilyAggregate | null;
  files: SwitchFileResult[];
  coverage: {
    limits: SwitchRootfsLimits;
    selection: string;
    inventoryComplete: boolean;
    entriesExamined: number;
    /** Counts concern discovered regular files only; an incomplete inventory leaves further counts unknown. */
    filesDiscovered: number;
    filesExamined: number;
    filesSkipped: number;
    filesTruncated: number;
    bytesScanned: number;
    symlinksSkipped: number;
    specialFilesSkipped: number;
    errors: { path: string; reason: string }[];
    /** First cap-skipped paths in selection order, at most `SWITCH_SKIPPED_PATHS_RECORDED`. Optional: older builds. */
    skippedPaths?: string[];
  };
}

export interface SwitchFamilyAnalysis {
  raw: {
    status: 'completed' | 'partial' | 'error';
    reason: string;
    file: SwitchFileResult | null;
    result: SwitchFamilyAggregate | null;
  };
  rootfs: SwitchRootfsLane;
  overall: SwitchFamilyAggregate;
}

const message = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/** Pure: the lanes' statuses in one clause, for an aggregate that may have scanned nothing. */
export function switchLaneStatuses(raw: SwitchFamilyAnalysis['raw'], rootfs: SwitchRootfsLane): string {
  const rawPart =
    raw.status === 'error'
      ? `raw lane error (${raw.reason})`
      : `raw lane ${raw.status} (${raw.file?.result.coverage.bytesScanned ?? 0} byte(s) scanned)`;
  return `${rawPart}; ${rootfsLaneStatus(rootfs)}`;
}

function rootfsLaneStatus(rootfs: SwitchRootfsLane): string {
  if (rootfs.status === 'not-run' || rootfs.status === 'error')
    return `rootfs lane ${rootfs.status} (${rootfs.reason})`;
  const c = rootfs.coverage;
  return (
    `rootfs lane ${rootfs.status} (${c.filesExamined} of ${c.filesDiscovered} discovered regular file(s) read, ` +
    `${c.filesSkipped} skipped by cap or unreadable, ${c.errors.length} error(s) recorded, ${c.bytesScanned} byte(s) scanned)`
  );
}

/** Read only regular files without following a final symlink, including short-read handling. */
async function readPrefix(filePath: string, cap: number): Promise<{ bytes: Buffer; fileBytes: number }> {
  const file = await fs.open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (!stat.isFile()) throw new Error('Not a regular file');
    const buffer = Buffer.alloc(Math.min(stat.size, cap));
    let read = 0;
    while (read < buffer.length) {
      const chunk = await file.read(buffer, read, buffer.length - read, read);
      if (chunk.bytesRead === 0) break;
      read += chunk.bytesRead;
    }
    return { bytes: buffer.subarray(0, read), fileBytes: stat.size };
  } finally {
    await file.close();
  }
}

/** Read bounded byte prefixes; the caller's job signal is checked between filesystem operations and scans. */
export async function runSwitchFamilyAnalysis(
  imagePath: string,
  rootfsPath: string | null = null,
  limits: SwitchRootfsLimits = DEFAULT_SWITCH_ROOTFS_LIMITS,
  signal?: AbortSignal,
): Promise<SwitchFamilyAnalysis> {
  for (const [key, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${key} must be a positive safe integer`);
  }
  signal?.throwIfAborted();
  let raw: SwitchFamilyAnalysis['raw'];
  try {
    const { bytes, fileBytes } = await readPrefix(imagePath, DEFAULT_SWITCH_SCAN_BYTES);
    const result = detectSwitchFamily(bytes, { inputTruncated: bytes.length < fileBytes });
    const file: SwitchFileResult = { lane: 'raw', path: path.basename(imagePath), fileBytes, result };
    raw = {
      status: result.coverage.completed ? 'completed' : 'partial',
      reason: `Raw image: scanned ${result.coverage.bytesScanned} of ${fileBytes} bytes. ${result.coverage.statement}`,
      file,
      result: aggregateSwitchFamilies([file]),
    };
  } catch (error) {
    raw = { status: 'error', reason: `Raw image not scanned: ${message(error)}`, file: null, result: null };
  }
  signal?.throwIfAborted();
  const rootfs: SwitchRootfsLane = {
    status: 'not-run',
    reason: 'not run: no extracted rootfs',
    result: null,
    files: [],
    coverage: {
      limits: { ...limits },
      selection: SWITCH_ROOTFS_SELECTION,
      inventoryComplete: false,
      entriesExamined: 0,
      filesDiscovered: 0,
      filesExamined: 0,
      filesSkipped: 0,
      filesTruncated: 0,
      bytesScanned: 0,
      symlinksSkipped: 0,
      specialFilesSkipped: 0,
      errors: [],
      skippedPaths: [],
    },
  };
  const coverage = rootfs.coverage;
  if (rootfsPath !== null) {
    try {
      const rootStat = await fs.lstat(rootfsPath);
      if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new Error('Rootfs is not a regular directory');
      const root = await fs.realpath(rootfsPath);
      const files: string[] = [];
      coverage.inventoryComplete = true;
      const containedPath = async (relative: string): Promise<string> => {
        const candidate = path.join(root, relative);
        const real = await fs.realpath(candidate);
        if (real !== candidate || (real !== root && !real.startsWith(`${root}${path.sep}`))) {
          throw new Error('Path changed or traverses a symlink; not scanned');
        }
        return candidate;
      };
      const walk = async (relative: string): Promise<void> => {
        signal?.throwIfAborted();
        try {
          const directory = await containedPath(relative);
          const entries = (await fs.readdir(directory, { withFileTypes: true })).sort((a, b) =>
            compare(a.name, b.name),
          );
          for (const entry of entries) {
            if (coverage.entriesExamined >= limits.maxEntries) {
              coverage.inventoryComplete = false;
              return;
            }
            coverage.entriesExamined++;
            const child = relative ? `${relative}/${entry.name}` : entry.name;
            if (entry.isSymbolicLink()) coverage.symlinksSkipped++;
            else if (entry.isDirectory()) await walk(child);
            else if (entry.isFile()) files.push(child);
            else coverage.specialFilesSkipped++;
          }
        } catch (error) {
          coverage.inventoryComplete = false;
          coverage.errors.push({ path: relative || '.', reason: message(error) });
        }
      };
      await walk('');
      coverage.filesDiscovered = files.length;
      const skippedPaths: string[] = [];
      coverage.skippedPaths = skippedPaths;
      let capSkipped = 0;
      for (const relative of orderSwitchRootfsFiles(files)) {
        signal?.throwIfAborted();
        if (coverage.filesExamined >= limits.maxFiles || coverage.bytesScanned >= limits.maxTotalBytes) {
          coverage.filesSkipped++;
          capSkipped++;
          if (skippedPaths.length < SWITCH_SKIPPED_PATHS_RECORDED) skippedPaths.push(relative);
          continue;
        }
        try {
          const filePath = await containedPath(relative);
          const cap = Math.min(
            limits.maxBytesPerFile,
            limits.maxTotalBytes - coverage.bytesScanned,
            DEFAULT_SWITCH_SCAN_BYTES,
          );
          const { bytes, fileBytes } = await readPrefix(filePath, cap);
          const result = detectSwitchFamily(bytes, { inputTruncated: bytes.length < fileBytes });
          rootfs.files.push({ lane: 'rootfs', path: relative, fileBytes, result });
          coverage.filesExamined++;
          coverage.bytesScanned += result.coverage.bytesScanned;
          if (!result.coverage.completed) coverage.filesTruncated++;
        } catch (error) {
          coverage.filesSkipped++;
          coverage.errors.push({ path: relative, reason: message(error) });
        }
      }
      rootfs.status =
        !coverage.inventoryComplete || coverage.filesSkipped > 0 || coverage.filesTruncated > 0
          ? 'partial'
          : 'completed';
      const firstSkipped =
        skippedPaths.length > 0
          ? ` First skipped by the cap, in selection order: ${skippedPaths.join(', ')}${capSkipped > skippedPaths.length ? ` and ${capSkipped - skippedPaths.length} more` : ''}.`
          : '';
      rootfs.reason = `Examined ${coverage.filesExamined} of ${coverage.filesDiscovered} discovered regular files; skipped ${coverage.filesSkipped}, truncated ${coverage.filesTruncated}, scanned ${coverage.bytesScanned} bytes.${firstSkipped} Inventory ${coverage.inventoryComplete ? 'complete' : 'incomplete; undiscovered counts unknown'}. Symlinks not followed: ${coverage.symlinksSkipped} (a firmware link's target is either a regular file inside the rootfs, inventoried on its own path, or not firmware content); special entries (device nodes, FIFOs, sockets: no stored bytes) skipped: ${coverage.specialFilesSkipped}. No decoding of still-compressed files is attempted.`;
      rootfs.result = aggregateSwitchFamilies(rootfs.files, { notScannedBecause: rootfsLaneStatus(rootfs) });
    } catch (error) {
      rootfs.status = 'error';
      rootfs.reason = `Rootfs lane could not run: ${message(error)}`;
    }
  }
  signal?.throwIfAborted();
  const overall = aggregateSwitchFamilies([...(raw.file ? [raw.file] : []), ...rootfs.files], {
    notScannedBecause: switchLaneStatuses(raw, rootfs),
  });
  return { raw, rootfs, overall };
}
