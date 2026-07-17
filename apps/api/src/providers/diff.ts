/**
 * Firmware diff provider. Compares two already-analyzed images across three axes — inferred identity, SBOM
 * packages + CVEs, and the extracted rootfs file set — and returns a structured delta. It reads each side's
 * data from stored jobs (latest successful `sbom` / `extract`) and the persisted identity; a side that lacks
 * an SBOM or an extract simply reports `hasData:false` for that section rather than failing. All comparison
 * logic lives in small pure functions so it is unit-testable without any I/O.
 */
import type { FsNode, ImageIdentity } from '@firmlab/core';
import type { ExtractResult } from './extract.js';
import type { JobHandle } from './jobs.js';
import type { SbomResult, SbomVuln } from './sbom.js';

type Severity = SbomVuln['severity'];
const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];

const PKG_CAP = 2000;
const CVE_CAP = 500;
const FILE_CAP = 1000;

export interface IdentityChange {
  field: string;
  a: string;
  b: string;
}

export interface PackageChange {
  name: string;
  a: string;
  b: string;
}

export interface FirmwareDiffResult {
  a: { id: string; filename: string };
  b: { id: string; filename: string };
  identity: IdentityChange[];
  packages: {
    hasData: boolean;
    added: { name: string; version: string }[];
    removed: { name: string; version: string }[];
    changed: PackageChange[];
  };
  cves: {
    hasData: boolean;
    addedIds: string[];
    removedIds: string[];
    addedBySeverity: Record<Severity, number>;
  };
  files: {
    hasData: boolean;
    added: string[];
    removed: string[];
    changed: string[];
    counts: { added: number; removed: number; changed: number };
  };
}

// === Pure diff helpers (unit-tested) ===

function severityTally(): Record<Severity, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 };
}

/** Compare the human-facing identity fields; only differing fields are returned. */
export function diffIdentity(a: ImageIdentity | null, b: ImageIdentity | null): IdentityChange[] {
  const fieldOf = (id: ImageIdentity | null): Record<string, string> => ({
    firmwareClass: id?.firmwareClass ?? '—',
    arch: id?.arch ?? '—',
    endianness: id?.endianness ?? '—',
    bootloader: id?.bootloader ?? '—',
    kernel: id?.kernel ?? '—',
    filesystems: id?.filesystems?.slice().sort().join(', ') || '—',
  });
  const fa = fieldOf(a);
  const fb = fieldOf(b);
  const out: IdentityChange[] = [];
  for (const field of Object.keys(fa)) {
    if (fa[field] !== fb[field]) out.push({ field, a: fa[field] as string, b: fb[field] as string });
  }
  return out;
}

/** Diff SBOM package sets by name; a name present on both with a different version is "changed". */
export function diffPackages(
  aPkgs: { name: string; version: string }[],
  bPkgs: { name: string; version: string }[],
): FirmwareDiffResult['packages'] {
  const aMap = new Map(aPkgs.map((p) => [p.name, p.version]));
  const bMap = new Map(bPkgs.map((p) => [p.name, p.version]));
  const added: { name: string; version: string }[] = [];
  const removed: { name: string; version: string }[] = [];
  const changed: PackageChange[] = [];
  for (const [name, version] of bMap) if (!aMap.has(name)) added.push({ name, version });
  for (const [name, version] of aMap) {
    if (!bMap.has(name)) removed.push({ name, version });
    else if (bMap.get(name) !== version) changed.push({ name, a: version, b: bMap.get(name) as string });
  }
  const byName = (x: { name: string }, y: { name: string }): number => x.name.localeCompare(y.name);
  return {
    hasData: true,
    added: added.sort(byName).slice(0, PKG_CAP),
    removed: removed.sort(byName).slice(0, PKG_CAP),
    changed: changed.sort(byName).slice(0, PKG_CAP),
  };
}

/** Diff CVE id sets; newly-introduced CVEs are additionally tallied by severity (from the B side). */
export function diffCves(aVulns: SbomVuln[], bVulns: SbomVuln[]): FirmwareDiffResult['cves'] {
  const aIds = new Set(aVulns.map((v) => v.id));
  const bIds = new Set(bVulns.map((v) => v.id));
  const addedIds = [...bIds].filter((id) => !aIds.has(id)).sort();
  const removedIds = [...aIds].filter((id) => !bIds.has(id)).sort();
  const addedBySeverity = severityTally();
  const addedSet = new Set(addedIds);
  for (const v of bVulns) {
    if (addedSet.has(v.id)) {
      const sev = SEVERITIES.includes(v.severity) ? v.severity : 'Unknown';
      addedBySeverity[sev] += 1;
    }
  }
  return {
    hasData: true,
    addedIds: addedIds.slice(0, CVE_CAP),
    removedIds: removedIds.slice(0, CVE_CAP),
    addedBySeverity,
  };
}

/** Flatten a rootfs tree into a path→size map of files (dirs/symlinks ignored for the file diff). */
interface FileFingerprint {
  size: number;
  sha1?: string;
}

export function flattenFiles(tree: FsNode | null): Map<string, FileFingerprint> {
  const out = new Map<string, FileFingerprint>();
  if (!tree) return out;
  const stack: FsNode[] = [tree];
  while (stack.length > 0) {
    const node = stack.pop() as FsNode;
    if (node.type === 'file') out.set(node.path, { size: node.size, ...(node.sha1 ? { sha1: node.sha1 } : {}) });
    if (node.children) for (const c of node.children) stack.push(c);
  }
  return out;
}

/**
 * Diff two rootfs file maps: added (B-only), removed (A-only), changed. A file is "changed" when both sides
 * carry a content hash and the hashes differ; when a hash is missing (file over the extractor's hash cap) it
 * falls back to a size comparison.
 */
export function diffFiles(aTree: FsNode | null, bTree: FsNode | null): FirmwareDiffResult['files'] {
  const aFiles = flattenFiles(aTree);
  const bFiles = flattenFiles(bTree);
  const added: string[] = [];
  const removed: string[] = [];
  const changed: string[] = [];
  for (const p of bFiles.keys()) if (!aFiles.has(p)) added.push(p);
  for (const [p, a] of aFiles) {
    const b = bFiles.get(p);
    if (!b) {
      removed.push(p);
    } else if (a.sha1 && b.sha1) {
      if (a.sha1 !== b.sha1) changed.push(p);
    } else if (a.size !== b.size) {
      changed.push(p);
    }
  }
  added.sort();
  removed.sort();
  changed.sort();
  return {
    hasData: true,
    added: added.slice(0, FILE_CAP),
    removed: removed.slice(0, FILE_CAP),
    changed: changed.slice(0, FILE_CAP),
    counts: { added: added.length, removed: removed.length, changed: changed.length },
  };
}

// === I/O glue ===
// `store` is imported lazily so the pure helpers above can be unit-tested without loading node:sqlite.

export async function runDiff(aId: string, bId: string, handle: JobHandle): Promise<FirmwareDiffResult> {
  const { getImage, listJobs } = await import('../store.js');

  const identityOf = (id: string): ImageIdentity | null => {
    const row = getImage(id);
    if (!row?.identityJson) return null;
    try {
      return JSON.parse(row.identityJson) as ImageIdentity;
    } catch {
      return null;
    }
  };
  const latestResult = <T>(imageId: string, kind: 'sbom' | 'extract'): T | null => {
    const done = listJobs(imageId).find((j) => j.kind === kind && j.status === 'done' && j.resultJson);
    if (!done?.resultJson) return null;
    try {
      return JSON.parse(done.resultJson) as T;
    } catch {
      return null;
    }
  };

  const aRow = getImage(aId);
  const bRow = getImage(bId);
  const a = { id: aId, filename: aRow?.filename ?? aId };
  const b = { id: bId, filename: bRow?.filename ?? bId };

  handle.log(`Diffing ${a.filename} → ${b.filename}`);

  const identity = diffIdentity(identityOf(aId), identityOf(bId));
  handle.log(`Identity: ${identity.length} field(s) differ.`);

  const aSbom = latestResult<SbomResult>(aId, 'sbom');
  const bSbom = latestResult<SbomResult>(bId, 'sbom');
  let packages: FirmwareDiffResult['packages'];
  let cves: FirmwareDiffResult['cves'];
  if (aSbom?.available && bSbom?.available) {
    packages = diffPackages(aSbom.packages, bSbom.packages);
    cves = diffCves(aSbom.vulnerabilities, bSbom.vulnerabilities);
    handle.log(
      `Packages: +${packages.added.length} / -${packages.removed.length} / ~${packages.changed.length}; ` +
        `CVEs: +${cves.addedIds.length} / -${cves.removedIds.length}.`,
    );
  } else {
    handle.log('SBOM missing on one or both sides — skipping package/CVE diff.');
    packages = { hasData: false, added: [], removed: [], changed: [] };
    cves = { hasData: false, addedIds: [], removedIds: [], addedBySeverity: severityTally() };
  }

  const aExtract = latestResult<ExtractResult>(aId, 'extract');
  const bExtract = latestResult<ExtractResult>(bId, 'extract');
  let files: FirmwareDiffResult['files'];
  if (aExtract?.tree && bExtract?.tree) {
    files = diffFiles(aExtract.tree, bExtract.tree);
    handle.log(`Files: +${files.counts.added} / -${files.counts.removed} / ~${files.counts.changed}.`);
  } else {
    handle.log('Extracted rootfs missing on one or both sides — skipping file diff.');
    files = { hasData: false, added: [], removed: [], changed: [], counts: { added: 0, removed: 0, changed: 0 } };
  }

  return { a, b, identity, packages, cves, files };
}
