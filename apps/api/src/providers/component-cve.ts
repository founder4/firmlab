/**
 * Component-fingerprint CVE provider (W2 depth) — the n-day surface `syft`+`grype` miss.
 *
 * `syft` keys off PACKAGE MANIFESTS (opkg/dpkg/apk databases). A stripped SOHO firmware that ships a bundled
 * binary with NO manifest — the classic TP-Link/MediaTek build — catalogues 0 packages, so `grype` returns 0
 * CVEs even when the image ships a decade-old `pppd` with a pre-auth RCE. The autonomous pass found these by
 * reading the version string out of the binary itself and matching it to a known CVE. This provider does exactly
 * that, deterministically: it locates a curated set of high-value embedded components by binary name, extracts
 * the version from the printable strings IN the binary, and matches it against a small, hand-verified table of
 * well-documented embedded n-days (the ones a manifest-only SBOM structurally cannot see).
 *
 * Honesty is preserved: the CVE table is intentionally SMALL and every entry is a famous, checkable n-day with an
 * explicit affected-version predicate — it never guesses "this era is probably vulnerable". A component found but
 * not matched is reported as an inventory fact, not a vuln.
 *
 * The parse/match is PURE and lives in `@firmlab/core` (`component-cve.ts` there: the rule table, version
 * ordering, extraction, matching, `curatedCveVerdict` and the finding drafts). This module is only the runner: it
 * walks the rootfs under an entry budget and reads bounded binary prefixes.
 *
 * Closes docs/AUTONOMOUS-WORKERS.md §9 gap #1 — pppd 2.4.x → CVE-2020-8597 on WR940N and WDR3600 (app: 0 CVEs).
 */
import fs from 'node:fs';
import path from 'node:path';
import {
  COMPONENT_RULES,
  type ComponentHit,
  type FindingDraft,
  binaryStrings,
  buildComponentFindings,
  extractComponentVersion,
  matchesBinName,
} from '@firmlab/core';

export interface ComponentCveResult {
  available: boolean;
  hits: ComponentHit[];
  findings: FindingDraft[];
  reason: string;
  /**
   * True when the rootfs walk stopped at its entry budget, so `hits` covers only the subtrees it reached.
   *
   * This is the curated-CVE path: its `reason` states how many components were versioned and how many CVEs
   * matched, and a reader takes that for the image's embedded-n-day surface. Over a partial walk it is a floor,
   * and a component the walk never reached is indistinguishable from one that is not there. Optional forever —
   * absent on a result stored by an older build, and absent means NOT RECORDED, never "the walk completed".
   */
  walkTruncated?: boolean;
  /** Directory entries the walk visited. Optional forever, for the same reason. */
  entriesWalked?: number;
}

const WALK_CAP = 8000;

/**
 * Where the components this table curates actually live, most-likely first.
 *
 * The walk is a LIFO stack over an 8 000-entry budget, so on a rootfs bigger than that WHICH subtrees get covered
 * was decided by `readdirSync` order — the set of components found became an artifact of directory layout, which
 * is the one thing a bound here must not do. Visiting the library and service directories first means a truncated
 * walk still reaches where busybox, dropbear, openssl and the rest are, and the truncation costs the tail of
 * `/usr/share` rather than the answer.
 */
const COMPONENT_DIRS = ['usr/lib', 'lib', 'usr/sbin', 'sbin', 'usr/bin', 'bin', 'usr/libexec', 'usr/local'];

/**
 * Rank a rootfs-relative directory path: lower is visited earlier. Pure and exported so a test can pin the order
 * the cap depends on.
 *
 * A directory ranks well if it is a component directory, is INSIDE one, or is on the way TO one. The third case
 * is not a nicety — the walk descends a level at a time, and without it `usr` (a one-segment directory matching no
 * two-segment entry) ranked last while holding `usr/lib`, `usr/sbin` and `usr/bin`, so the ordering meant to help
 * a truncated walk sent it everywhere except where the components are. Measured in-container before the fix: a
 * bounded walk of a Debian root spent all 8 000 entries and found ZERO components, on a filesystem carrying
 * libcrypto.
 */
export function componentDirPriority(rel: string): number {
  const norm = rel.replace(/^\.?\//, '');
  let best = COMPONENT_DIRS.length;
  for (let i = 0; i < COMPONENT_DIRS.length; i++) {
    const d = COMPONENT_DIRS[i] as string;
    const onTheWay = norm === d || norm.startsWith(`${d}/`) || d.startsWith(`${norm}/`);
    if (onTheWay && i < best) best = i;
  }
  return best;
}
const BIN_READ_CAP = 8 * 1024 * 1024;
const ALL_BIN_NAMES = new Set(COMPONENT_RULES.flatMap((r) => r.binNames));

/** Read a bounded prefix of a file as bytes (missing/unreadable → empty). */
function readBounded(abs: string): Uint8Array {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, BIN_READ_CAP);
      const b = Buffer.allocUnsafe(size);
      fs.readSync(fd, b, 0, size, 0);
      return b;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return new Uint8Array(0);
  }
}

/**
 * Fingerprint bundled components in an extracted rootfs against the curated CVE table. Walks the rootfs for the
 * target binary names, reads each one's printable strings, extracts the version and matches CVEs — the n-day
 * surface a manifest-only SBOM cannot reach. Honest: no rootfs → available:false; a component with no known CVE
 * is an inventory fact, never inflated to a vuln.
 */
export function runComponentCve(rootfsPath: string | null): ComponentCveResult {
  if (!rootfsPath) {
    return { available: false, hits: [], findings: [], reason: 'No extracted rootfs — run extraction first.' };
  }
  const root = path.resolve(rootfsPath);
  try {
    if (!fs.statSync(root).isDirectory()) throw new Error('not a dir');
  } catch {
    return { available: false, hits: [], findings: [], reason: 'No extracted rootfs — run extraction first.' };
  }

  const hits: ComponentHit[] = [];
  const seen = new Set<string>();
  let walked = 0;
  let truncated = false;
  const stack: string[] = [root];
  while (stack.length > 0 && walked < WALK_CAP) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    // Subdirectories are collected and pushed together at the end of the loop: the stack is LIFO, so pushing the
    // LOWEST-priority ones first leaves the component directories on top, to be popped next.
    const subdirs: string[] = [];
    for (const e of entries) {
      if (walked >= WALK_CAP) {
        truncated = true;
        break;
      }
      walked++;
      if (e.isSymbolicLink()) continue;
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        subdirs.push(abs);
        continue;
      }
      if (!e.isFile()) continue;
      if (!ALL_BIN_NAMES.has(e.name) && !matchesBinName(e.name)) continue;
      const rule = matchesBinName(e.name);
      if (!rule) continue;
      const rel = path.relative(root, abs);
      const version = extractComponentVersion(binaryStrings(readBounded(abs)), rule);
      if (!version) continue;
      const key = `${rule.component}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ component: rule.component, version, path: rel });
    }
    subdirs.sort((x, y) => componentDirPriority(path.relative(root, y)) - componentDirPriority(path.relative(root, x)));
    stack.push(...subdirs);
  }
  // Entries still on the stack mean tree was left unvisited. Checked separately from the in-loop `break`, because
  // the outer `while` can exit on the budget with directories still queued and never reach that branch.
  if (stack.length > 0) truncated = true;

  const findings = buildComponentFindings(hits);
  const cveCount = findings.filter((f) => f.kind === 'component-cve').length;
  return {
    available: true,
    hits,
    findings,
    walkTruncated: truncated,
    entriesWalked: walked,
    reason: describeComponentScan(hits.length, cveCount, { walked, truncated }),
  };
}

/**
 * The sentence the panel prints. Pure and exported so both branches are reachable from a test: the clean one is
 * reserved for a walk that finished, and a truncated walk says the two counts are a floor rather than the surface.
 */
export function describeComponentScan(
  componentCount: number,
  cveCount: number,
  scan: { walked: number; truncated: boolean },
): string {
  const head = `Component fingerprint: ${componentCount} bundled component(s) versioned, ${cveCount} CVE(s) matched from the curated embedded-n-day table (the surface a manifest-only SBOM misses).`;
  if (!scan.truncated) return head;
  return [
    head,
    `The rootfs walk stopped at its ${WALK_CAP}-entry budget after ${scan.walked} entries, so both counts are a`,
    'FLOOR: library and service directories are visited first, but a component in a subtree the walk never',
    'reached is indistinguishable here from one that is not present.',
  ].join(' ');
}
