/**
 * Vendor VEX documents shipped inside an extracted rootfs — found by a stated rule, read under stated caps, and
 * attached as a verdict ON rows that already exist. Parsing and per-document resolution are core's
 * (`parseVendorVex` / `resolveVendorVex`); this module decides which files are read, how the per-document answers
 * combine, and which product strings count as the component a row is about.
 *
 * What it refuses to claim:
 *
 *  - **A vendor statement is an assertion found in the bytes, not a code fact.** The verdict rides on a row as
 *    metadata, exactly as `curatedCveVerdict` does. It never changes a row's proof state or severity, never removes
 *    or suppresses a row, and never raises one: "the vendor says fixed" is not "the code is fixed", and "the vendor
 *    says affected" is not a reproduction.
 *  - **Silence is not agreement.** A CVE no document mentions, a rootfs with no documents, or a document that was
 *    refused attaches NOTHING — `vendorVexVerdictFor` returns null and the row is byte-for-byte unchanged.
 *  - **No fuzzy product matching.** A statement counts only when it names the row's exact CVE id AND one of the
 *    product strings accepted below. "linux" alone is not the Linux kernel; a substring is never a match.
 *  - **Disagreement is not resolved by order.** Statements (in one document or across several) that assert
 *    different things for the same CVE and product are `conflicting`, with every source listed.
 *
 * Discovery is bounded and deterministic: the tree walk visits at most `maxEntries` entries and never follows a
 * symbolic link (a symlinked candidate is refused by name, because a link inside a vendor rootfs can point at the
 * host); candidates are sorted by path and the file cap drops by that order; a document above the per-document cap
 * is refused without being read, and the total-byte cap drops the rest — every drop is counted.
 */
import fs from 'node:fs';
import path from 'node:path';
import {
  DEFAULT_MAX_VEX_DOCUMENT_BYTES,
  type ProductMatcherPredicate,
  type VendorVexDocument,
  type VendorVexStatus,
  type VendorVexVerdictKind,
  parseVendorVex,
  resolveVendorVex,
} from '@firmlab/core';

// === Candidate selection (pure) =========================================================================

export const VEX_CANDIDATE_RULE =
  'a .json file whose name ends in .openvex.json or .vex.json, or whose name contains "csaf", or that sits under ' +
  'a directory whose name contains "vex" or "csaf" (case-insensitive); symbolic links are never followed';

/** Pure: whether a rootfs-relative path (`/`-separated) is a VEX candidate under `VEX_CANDIDATE_RULE`. */
export function isVexCandidatePath(relPath: string): boolean {
  const segments = relPath.toLowerCase().split('/').filter(Boolean);
  const base = segments.at(-1);
  if (!base?.endsWith('.json')) return false;
  if (base.endsWith('.openvex.json') || base.endsWith('.vex.json') || base.includes('csaf')) return true;
  return segments.slice(0, -1).some((d) => d.includes('vex') || d.includes('csaf'));
}

/** Pure: the candidates in sorted path order, capped, with what the cap dropped. */
export function selectVexCandidates(
  relPaths: readonly string[],
  maxFiles: number,
): { selected: string[]; found: number; dropped: number } {
  const all = relPaths.filter(isVexCandidatePath).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const selected = all.slice(0, maxFiles);
  return { selected, found: all.length, dropped: all.length - selected.length };
}

// === Discovery (thin reader) ============================================================================

export interface VendorVexDiscoveryRefusal {
  /** Rootfs-relative, leading `/`. */
  path: string;
  reason:
    | 'symlink_not_followed'
    | 'not_regular_file'
    | 'oversized_document'
    | 'unreadable'
    | 'malformed_json'
    | 'non_vex_json';
  message: string;
}

export interface VendorVexDiscoveryCoverage {
  rule: string;
  candidatesFound: number;
  /** Candidates opened or refused by name (selected under the file cap). */
  examined: number;
  parsed: number;
  refused: number;
  droppedByFileCap: number;
  droppedByByteCap: number;
  /** Symbolic links the walk met and did not follow, candidate or not. */
  symlinksSkipped: number;
  entriesVisited: number;
  /** True when the walk stopped at `maxEntries`, so candidates beyond it were never seen. */
  walkTruncated: boolean;
  bytesRead: number;
  caps: { maxFiles: number; maxTotalBytes: number; maxDocumentBytes: number; maxEntries: number };
  statement: string;
}

export interface VendorVexDiscovery {
  documents: VendorVexDocument[];
  refusals: VendorVexDiscoveryRefusal[];
  coverage: VendorVexDiscoveryCoverage;
}

export interface VendorVexDiscoveryOptions {
  maxFiles?: number;
  maxTotalBytes?: number;
  maxDocumentBytes?: number;
  maxEntries?: number;
}

export const DEFAULT_VEX_MAX_FILES = 64;
export const DEFAULT_VEX_MAX_TOTAL_BYTES = 16 * 1024 * 1024;
export const DEFAULT_VEX_MAX_ENTRIES = 200_000;

/** Walk `rootfs` without following links; returns rootfs-relative paths of regular files and of symlinks. */
function walk(
  rootfs: string,
  maxEntries: number,
): { files: string[]; symlinks: string[]; visited: number; truncated: boolean } {
  const files: string[] = [];
  const symlinks: string[] = [];
  let visited = 0;
  const stack: string[] = [''];
  while (stack.length > 0) {
    const rel = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(path.join(rootfs, rel), { withFileTypes: true });
    } catch {
      continue;
    }
    // Sorted so a truncated walk stops at the same place on every run, independent of readdir order.
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of entries) {
      if (visited >= maxEntries) return { files, symlinks, visited, truncated: true };
      visited++;
      const child = `${rel}/${e.name}`;
      if (e.isSymbolicLink()) symlinks.push(child);
      else if (e.isDirectory()) stack.push(child);
      else if (e.isFile()) files.push(child);
    }
  }
  return { files, symlinks, visited, truncated: false };
}

/** A discovery that read nothing, with the reason — what a missing rootfs or an unexpected fault degrades to. */
function emptyDiscovery(caps: VendorVexDiscoveryCoverage['caps'], reason: string): VendorVexDiscovery {
  return {
    documents: [],
    refusals: [],
    coverage: {
      rule: VEX_CANDIDATE_RULE,
      candidatesFound: 0,
      examined: 0,
      parsed: 0,
      refused: 0,
      droppedByFileCap: 0,
      droppedByByteCap: 0,
      symlinksSkipped: 0,
      entriesVisited: 0,
      walkTruncated: false,
      bytesRead: 0,
      caps,
      statement: `${reason} No vendor VEX document was examined, so nothing is attached to any row; that is not a clean result.`,
    },
  };
}

/**
 * Thin reader: find, read and parse the VEX documents in `rootfs` under the stated rule and caps. Never throws: a
 * missing rootfs or an unexpected fault degrades to an empty discovery that says why, so a job never fails on it.
 */
export function discoverVendorVex(
  rootfs: string | null | undefined,
  options: VendorVexDiscoveryOptions = {},
): VendorVexDiscovery {
  const caps = {
    maxFiles: options.maxFiles ?? DEFAULT_VEX_MAX_FILES,
    maxTotalBytes: options.maxTotalBytes ?? DEFAULT_VEX_MAX_TOTAL_BYTES,
    maxDocumentBytes: options.maxDocumentBytes ?? DEFAULT_MAX_VEX_DOCUMENT_BYTES,
    maxEntries: options.maxEntries ?? DEFAULT_VEX_MAX_ENTRIES,
  };
  if (!rootfs) return emptyDiscovery(caps, 'No extracted rootfs was available to search.');
  try {
    return discoverIn(rootfs, caps);
  } catch (e) {
    return emptyDiscovery(caps, `VEX discovery failed (${e instanceof Error ? e.message : String(e)}).`);
  }
}

function discoverIn(rootfs: string, caps: VendorVexDiscoveryCoverage['caps']): VendorVexDiscovery {
  const tree = walk(rootfs, caps.maxEntries);
  const linked = new Set(tree.symlinks);
  const { selected, found, dropped } = selectVexCandidates([...tree.files, ...tree.symlinks], caps.maxFiles);

  const documents: VendorVexDocument[] = [];
  const refusals: VendorVexDiscoveryRefusal[] = [];
  let bytesRead = 0;
  let droppedByByteCap = 0;
  for (const rel of selected) {
    const refuse = (reason: VendorVexDiscoveryRefusal['reason'], message: string) =>
      refusals.push({ path: rel, reason, message });
    if (linked.has(rel)) {
      refuse('symlink_not_followed', 'A symbolic link is never followed out of the rootfs.');
      continue;
    }
    const abs = path.join(rootfs, rel);
    let size: number;
    try {
      // lstat again: the walk saw a regular file, and a link swapped in since must still not be followed.
      const st = fs.lstatSync(abs);
      if (st.isSymbolicLink()) {
        refuse('symlink_not_followed', 'A symbolic link is never followed out of the rootfs.');
        continue;
      }
      if (!st.isFile()) {
        refuse('not_regular_file', 'Not a regular file.');
        continue;
      }
      size = st.size;
    } catch (e) {
      refuse('unreadable', e instanceof Error ? e.message : String(e));
      continue;
    }
    if (size > caps.maxDocumentBytes) {
      refuse('oversized_document', `${size} bytes is above the ${caps.maxDocumentBytes}-byte document cap; not read.`);
      continue;
    }
    if (bytesRead + size > caps.maxTotalBytes) {
      droppedByByteCap++;
      continue;
    }
    let text: string;
    try {
      text = fs.readFileSync(abs, 'utf8');
    } catch (e) {
      refuse('unreadable', e instanceof Error ? e.message : String(e));
      continue;
    }
    bytesRead += size;
    const parsed = parseVendorVex(text, rel, { maxDocumentBytes: caps.maxDocumentBytes });
    if (parsed.ok) documents.push(parsed);
    else refuse(parsed.reason, parsed.message);
  }

  const parts = [
    `${found} VEX candidate file(s) under the rule (${VEX_CANDIDATE_RULE}); ${documents.length} parsed, ${refusals.length} refused.`,
  ];
  if (dropped > 0)
    parts.push(`${dropped} candidate(s) beyond the ${caps.maxFiles}-file cap were not read (sorted path order).`);
  if (droppedByByteCap > 0) {
    parts.push(`${droppedByByteCap} candidate(s) were not read: the ${caps.maxTotalBytes}-byte total cap was reached.`);
  }
  if (tree.truncated) {
    parts.push(`The walk stopped at ${caps.maxEntries} entries; candidates beyond it were never seen.`);
  }
  if (found === 0 && !tree.truncated) {
    parts.push('No document is not a clean result: silence from a vendor attaches nothing to any row.');
  }
  parts.push('A vendor statement is an assertion, not a code fact, and never changes a proof state.');

  return {
    documents,
    refusals,
    coverage: {
      rule: VEX_CANDIDATE_RULE,
      candidatesFound: found,
      examined: selected.length,
      parsed: documents.length,
      refused: refusals.length,
      droppedByFileCap: dropped,
      droppedByByteCap,
      symlinksSkipped: tree.symlinks.length,
      entriesVisited: tree.visited,
      walkTruncated: tree.truncated,
      bytesRead,
      caps,
      statement: parts.join(' '),
    },
  };
}

// === Product matching (pure) ============================================================================

type ProductId =
  | { kind: 'purl'; type: string; namespace: string; name: string; version: string | null }
  | { kind: 'cpe'; part: string; vendor: string; product: string; version: string | null }
  | { kind: 'plain'; value: string };

function wildcard(v: string | null | undefined): boolean {
  return v === null || v === undefined || v === '' || v === '*' || v === '-';
}

function parseProductId(raw: string): ProductId {
  const id = raw.trim();
  const purl = /^pkg:([^/]+)\/([^?#]+)/i.exec(id);
  if (purl) {
    const type = (purl[1] as string).toLowerCase();
    let body = purl[2] as string;
    let version: string | null = null;
    const at = body.lastIndexOf('@');
    if (at >= 0) {
      version = decodeURIComponent(body.slice(at + 1));
      body = body.slice(0, at);
    }
    const segs = body.split('/').map((s) => decodeURIComponent(s));
    return { kind: 'purl', type, namespace: segs.slice(0, -1).join('/'), name: segs.at(-1) ?? '', version };
  }
  if (/^cpe:2\.3:/i.test(id)) {
    const f = id.split(':');
    return { kind: 'cpe', part: f[2] ?? '', vendor: f[3] ?? '', product: f[4] ?? '', version: f[5] ?? null };
  }
  if (/^cpe:\//i.test(id)) {
    const f = id.slice(5).split(':');
    return { kind: 'cpe', part: f[0] ?? '', vendor: f[1] ?? '', product: f[2] ?? '', version: f[3] ?? null };
  }
  return { kind: 'plain', value: id };
}

/**
 * The product strings accepted as "the Linux kernel", stated in full, each with the reason it is unambiguous:
 *
 *  - `cpe:2.3:o:linux:linux_kernel:…` / `cpe:/o:linux:linux_kernel:…` — the NVD CPE identity of the kernel, the same
 *    vendor/product pair the research lane's kernel query is scoped to. Part must be `o`; an `a:` CPE is not it.
 *  - `linux_kernel` — that CPE's product token, bare.
 *  - `linux-kernel` — the component name this codebase gives the kernel (`selectKernelCveCandidate`).
 *  - `pkg:generic/linux-kernel` / `pkg:generic/linux_kernel`, no namespace — the two tokens above as a generic purl.
 *
 * Deliberately NOT accepted, as forms whose meaning is not unique: `linux` alone and `pkg:generic/linux` (a distro or
 * an OS as easily as the kernel), distro source packages such as `pkg:deb/debian/linux` (a distro build carrying its
 * own patch set, not the vendor's kernel), free-text names such as "Linux Kernel 5.10", and any substring match.
 */
export const LINUX_KERNEL_VEX_PRODUCTS =
  'a plain identifier exactly "linux-kernel" or "linux_kernel" (case-insensitive); a purl ' +
  'pkg:generic/linux-kernel or pkg:generic/linux_kernel with no namespace; or a CPE (2.2 or 2.3) with part "o", ' +
  'vendor "linux" and product "linux_kernel". A versioned purl or CPE matches only when its version equals the ' +
  "image's detected kernel version or its upstream token; an unversioned or wildcard one matches any version.";

/** Pure: the conservative Linux-kernel matcher for `resolveVendorVex`. */
export function linuxKernelProductMatcher(versions: readonly (string | null | undefined)[]): ProductMatcherPredicate {
  const accepted = new Set(versions.filter((v): v is string => typeof v === 'string' && v.length > 0));
  const versionOk = (v: string | null) => wildcard(v) || accepted.has(v as string);
  return (raw) => {
    const p = parseProductId(raw);
    if (p.kind === 'plain') return ['linux-kernel', 'linux_kernel'].includes(p.value.toLowerCase());
    if (p.kind === 'purl') {
      return (
        p.type === 'generic' &&
        p.namespace === '' &&
        ['linux-kernel', 'linux_kernel'].includes(p.name) &&
        versionOk(p.version)
      );
    }
    return (
      p.part.toLowerCase() === 'o' &&
      p.vendor.toLowerCase() === 'linux' &&
      p.product.toLowerCase() === 'linux_kernel' &&
      versionOk(p.version)
    );
  };
}

export const PACKAGE_VEX_PRODUCTS =
  'the exact package name as a plain identifier; a purl of any type whose final name segment equals the package ' +
  'name exactly; or a CPE whose product field equals the package name (case-insensitive). A versioned purl or CPE ' +
  "matches only when its version equals the row's package version.";

/** Pure: the matcher for a package row (grype). Exact name, never a substring. */
export function packageProductMatcher(name: string, version: string): ProductMatcherPredicate {
  const versionOk = (v: string | null) => wildcard(v) || v === version;
  return (raw) => {
    const p = parseProductId(raw);
    if (p.kind === 'plain') return p.value === name;
    if (p.kind === 'purl') return p.name === name && versionOk(p.version);
    return p.product.toLowerCase() === name.toLowerCase() && versionOk(p.version);
  };
}

// === The verdict on a row (pure) ========================================================================

export type VendorVexRowVerdictKind = Exclude<VendorVexVerdictKind, 'unmentioned'>;

/** One statement a row's verdict rests on. */
export interface VendorVexRowSource {
  sourcePath: string | null;
  statementIndex: number | null;
  status: VendorVexStatus | 'conflicting';
  justification: string | null;
}

/**
 * The verdict attached to a row's evidence as `vendorVex`. OPTIONAL FOREVER on any persisted row: absent means no
 * vendor statement was matched (or VEX was never looked for), never "the vendor agrees".
 */
export interface VendorVexRowVerdict {
  verdict: VendorVexRowVerdictKind;
  /** Always `vendor_assertion`: the verdict is a claim found in the image, not a code fact. */
  basis: 'vendor_assertion';
  sourcePath: string | null;
  statementIndex: number | null;
  justification: string | null;
  /** Every statement the verdict rests on, across all documents, in sorted-path then statement order. */
  sources: VendorVexRowSource[];
  rationale: string;
}

const STATUS_OF: Record<Exclude<VendorVexRowVerdictKind, 'conflicting'>, VendorVexStatus> = {
  vendor_states_fixed: 'fixed',
  vendor_states_not_affected: 'not_affected',
  vendor_states_affected: 'affected',
  vendor_under_investigation: 'under_investigation',
};

const ASSERTION =
  "This is the vendor's assertion, not a code fact; it changes neither the proof state nor the severity.";

/**
 * Pure: the vendor's verdict for one row, combined across every discovered document — or null when no document
 * makes an explicit statement for this CVE and an accepted product. Null attaches nothing.
 */
export function vendorVexVerdictFor(
  discovery: Pick<VendorVexDiscovery, 'documents'> | null | undefined,
  cveId: string,
  matcher: ProductMatcherPredicate,
  componentName: string,
): VendorVexRowVerdict | null {
  if (!discovery || discovery.documents.length === 0) return null;
  const sources: VendorVexRowSource[] = [];
  const kinds = new Set<VendorVexRowVerdictKind>();
  for (const doc of discovery.documents) {
    // The explicit form: component name, then the matcher. A predicate rather than an array, because a versioned
    // purl or CPE must also agree with the row's version, which an exact-string list cannot express.
    const v = resolveVendorVex(doc, cveId, componentName, matcher);
    if (v.verdict === 'unmentioned') continue;
    kinds.add(v.verdict);
    for (const s of v.matchedStatements ?? []) {
      sources.push({
        sourcePath: doc.sourcePath,
        statementIndex: s.statementIndex,
        status: s.status,
        justification: s.justification ?? null,
      });
    }
  }
  if (kinds.size === 0) return null;
  const statuses = new Set(sources.map((s) => s.status));
  const first = sources[0];
  if (kinds.has('conflicting') || statuses.size > 1 || kinds.size > 1) {
    const listed = sources.map((s) => `${s.sourcePath} #${s.statementIndex} says ${s.status}`).join('; ');
    return {
      verdict: 'conflicting',
      basis: 'vendor_assertion',
      sourcePath: null,
      statementIndex: null,
      justification: null,
      sources,
      rationale: `Vendor VEX statements disagree on ${cveId} for ${componentName} (${listed}); not resolved by order. ${ASSERTION}`,
    };
  }
  const verdict = [...kinds][0] as Exclude<VendorVexRowVerdictKind, 'conflicting'>;
  const where = sources.map((s) => `${s.sourcePath} #${s.statementIndex}`).join(', ');
  return {
    verdict,
    basis: 'vendor_assertion',
    sourcePath: first?.sourcePath ?? null,
    statementIndex: first?.statementIndex ?? null,
    justification: first?.justification ?? null,
    sources,
    rationale: `A vendor VEX document states ${STATUS_OF[verdict].replace('_', ' ')} for ${cveId} in ${componentName} (${where}${first?.justification ? `; justification: ${first.justification}` : ''}). ${ASSERTION}`,
  };
}
