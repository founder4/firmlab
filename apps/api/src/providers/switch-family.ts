/**
 * Static switch-family leads from the raw image and, separately, uncompressed extracted files. Only core's
 * detector supplies mappings; aggregation never upgrades a template or vendor name to exact family evidence.
 * No findings are emitted and nothing here identifies live hardware or chooses an emulation/tagging format.
 * Both reads and rootfs inventory are bounded, with deterministic selection and explicit incomplete coverage.
 */
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import {
  DEFAULT_SWITCH_SCAN_BYTES,
  DEFERRED_SWITCH_MAPPINGS,
  type SwitchEvidenceHit,
  type SwitchFamilyCandidate,
  type SwitchFamilyResult,
  type SwitchFamilyVerdict,
  detectSwitchFamily,
} from '@firmlab/core';

export interface SwitchFileResult {
  lane: 'raw' | 'rootfs';
  /** Image basename for raw input; rootfs-relative path otherwise. Offsets are relative to this file. */
  path: string;
  fileBytes: number;
  result: SwitchFamilyResult;
}

export interface SwitchFamilyAggregate {
  verdict: SwitchFamilyVerdict;
  candidates: (Omit<SwitchFamilyCandidate, 'evidence'> & {
    evidence: (SwitchEvidenceHit & { lane: SwitchFileResult['lane']; path: string })[];
  })[];
  vendorMentions: {
    vendor: string;
    count: number;
    sources: { lane: SwitchFileResult['lane']; path: string; offsets: number[] }[];
  }[];
  deferred: SwitchFamilyResult['deferred'];
  summary: string;
}

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Pure: combine detector outputs, preserving all per-file counts, evidence provenance and core verdict rules. */
export function aggregateSwitchFamilies(files: readonly SwitchFileResult[]): SwitchFamilyAggregate {
  const candidates: SwitchFamilyAggregate['candidates'] = [];
  const vendorMentions: SwitchFamilyAggregate['vendorMentions'] = [];
  for (const file of [...files].sort((a, b) => compare(a.lane, b.lane) || compare(a.path, b.path))) {
    for (const candidate of file.result.candidates) {
      let combined = candidates.find((item) => item.family === candidate.family);
      if (!combined) {
        combined = { ...candidate, hitCount: 0, distinctTokens: [], evidence: [] };
        candidates.push(combined);
      }
      if (candidate.standing === 'exact-literal') combined.standing = 'exact-literal';
      combined.hitCount += candidate.hitCount;
      combined.distinctTokens = [...new Set([...combined.distinctTokens, ...candidate.distinctTokens])].sort(compare);
      combined.evidence.push(...candidate.evidence.map((hit) => ({ ...hit, lane: file.lane, path: file.path })));
    }
    for (const vendor of file.result.vendorMentions) {
      let combined = vendorMentions.find((item) => item.vendor === vendor.vendor);
      if (!combined) {
        combined = { vendor: vendor.vendor, count: 0, sources: [] };
        vendorMentions.push(combined);
      }
      combined.count += vendor.count;
      combined.sources.push({ lane: file.lane, path: file.path, offsets: [...vendor.offsets] });
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
          : 'none-observed';
  const explanation: Record<SwitchFamilyVerdict, string> = {
    ambiguous: 'Literals from multiple families are present; counts and file order cannot choose a family.',
    'single-family-lead': 'Only one family has an exact literal in the scanned bytes.',
    'template-only': 'Only unverified family-template tokens are present; they cannot single out a family.',
    'vendor-only': 'Only vendor names are present; vendor names are never switch-family candidates.',
    'none-observed':
      'No family literal or vendor name was observed in the scanned bytes; this is not evidence of no switch.',
  };
  return {
    verdict,
    candidates,
    vendorMentions,
    deferred: DEFERRED_SWITCH_MAPPINGS,
    summary: `${explanation[verdict]} Static leads may belong to dormant drivers for other boards, never identify live hardware, and do not prove networking or emulation works. Compressed, encrypted and unscanned bytes remain unknown; consult each lane and file coverage.`,
  };
}

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
      selection:
        'Inventory uses sorted directory names in depth-first order, capped by maxEntries; discovered regular files are then selected by ascending relative path (code-unit order). Read prefixes up to maxFiles, maxBytesPerFile and maxTotalBytes; all symlinks are skipped. Counts exclude unknown entries beyond incomplete inventory.',
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
      for (const relative of files.sort(compare)) {
        signal?.throwIfAborted();
        if (coverage.filesExamined >= limits.maxFiles || coverage.bytesScanned >= limits.maxTotalBytes) {
          coverage.filesSkipped++;
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
      rootfs.result = aggregateSwitchFamilies(rootfs.files);
      rootfs.status =
        !coverage.inventoryComplete ||
        coverage.filesSkipped > 0 ||
        coverage.filesTruncated > 0
          ? 'partial'
          : 'completed';
      rootfs.reason = `Examined ${coverage.filesExamined} of ${coverage.filesDiscovered} discovered regular files; skipped ${coverage.filesSkipped}, truncated ${coverage.filesTruncated}, scanned ${coverage.bytesScanned} bytes. Inventory ${coverage.inventoryComplete ? 'complete' : 'incomplete; undiscovered counts unknown'}. Symlinks not followed: ${coverage.symlinksSkipped} (a firmware link's target is either a regular file inside the rootfs, inventoried on its own path, or not firmware content); special entries (device nodes, FIFOs, sockets: no stored bytes) skipped: ${coverage.specialFilesSkipped}. No decoding of still-compressed files is attempted.`;
    } catch (error) {
      rootfs.status = 'error';
      rootfs.reason = `Rootfs lane could not run: ${message(error)}`;
    }
  }
  signal?.throwIfAborted();
  return { raw, rootfs, overall: aggregateSwitchFamilies([...(raw.file ? [raw.file] : []), ...rootfs.files]) };
}
