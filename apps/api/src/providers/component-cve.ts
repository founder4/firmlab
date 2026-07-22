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
 * not matched is reported as an inventory fact, not a vuln. The parse/match is PURE and unit-tested; the runner
 * only walks the rootfs and reads bounded binary prefixes.
 *
 * Closes docs/AUTONOMOUS-WORKERS.md §9 gap #1 — pppd 2.4.x → CVE-2020-8597 on WR940N and WDR3600 (app: 0 CVEs).
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FindingSeverity } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';

/** A dotted version, optionally with a single trailing letter (OpenSSL-style `1.0.1f`). */
export interface ParsedVersion {
  nums: number[];
  letter: string; // '' when absent
  raw: string;
}

/** Pure: parse `1.0.1f` / `2.4.3` into comparable parts. Returns null when it is not a dotted version. */
export function parseVersion(raw: string): ParsedVersion | null {
  const m = raw.match(/^(\d+(?:\.\d+)*)([a-z])?$/);
  if (!m) return null;
  const nums = (m[1] as string).split('.').map((n) => Number.parseInt(n, 10));
  return { nums, letter: m[2] ?? '', raw };
}

/** Pure: compare two parsed versions (numeric fields first, then the trailing letter). -1 / 0 / 1. */
export function compareVersion(a: ParsedVersion, b: ParsedVersion): number {
  const len = Math.max(a.nums.length, b.nums.length);
  for (let i = 0; i < len; i++) {
    const d = (a.nums[i] ?? 0) - (b.nums[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  if (a.letter === b.letter) return 0;
  return a.letter < b.letter ? -1 : 1;
}

/** Inclusive `low <= v <= high` on parsed versions. */
export function versionInRange(v: string, low: string, high: string): boolean {
  const pv = parseVersion(v);
  const pl = parseVersion(low);
  const ph = parseVersion(high);
  if (!pv || !pl || !ph) return false;
  return compareVersion(pv, pl) >= 0 && compareVersion(pv, ph) <= 0;
}

export interface CveRule {
  id: string;
  title: string;
  severity: FindingSeverity;
  /** Inclusive affected range [low, high] — deliberately explicit, never an open-ended "old-ish" guess. */
  low: string;
  high: string;
}

export interface ComponentRule {
  component: string;
  /** Binary basenames that carry this component. */
  binNames: string[];
  /** Ordered version-extraction patterns (first match wins); capture group 1 is the version. */
  versionRes: RegExp[];
  cves: CveRule[];
}

/**
 * Curated component table. SMALL BY DESIGN — each CVE is a famous, individually-verified embedded n-day that a
 * manifest-only SBOM cannot see because the component is a bundled binary with no package database entry.
 */
export const COMPONENT_RULES: readonly ComponentRule[] = [
  {
    component: 'pppd',
    binNames: ['pppd'],
    versionRes: [/pppd version (\d+\.\d+\.\d+)/i, /\bppp[- ]?(\d+\.\d+\.\d+)/i],
    cves: [
      {
        id: 'CVE-2020-8597',
        title: 'pppd EAP dispatch stack buffer overflow — pre-auth remote RCE',
        severity: 'critical',
        low: '2.4.2',
        high: '2.4.8',
      },
    ],
  },
  {
    component: 'openssl',
    binNames: ['openssl', 'libssl.so', 'libcrypto.so'],
    versionRes: [/OpenSSL (\d+\.\d+\.\d+[a-z]?)/],
    cves: [
      {
        id: 'CVE-2014-0160',
        title: 'OpenSSL TLS heartbeat out-of-bounds read (Heartbleed) — memory disclosure',
        severity: 'high',
        low: '1.0.1',
        high: '1.0.1f',
      },
    ],
  },
];

export interface ComponentHit {
  component: string;
  version: string;
  path: string;
}

/** Pure: extract a component version from a blob's printable strings using the rule's patterns (first match). */
export function extractComponentVersion(strings: string, rule: ComponentRule): string | null {
  for (const re of rule.versionRes) {
    const m = strings.match(re);
    if (m?.[1]) return m[1];
  }
  return null;
}

/** Pure: the CVEs from a rule whose affected range covers `version`. */
export function matchCves(rule: ComponentRule, version: string): CveRule[] {
  return rule.cves.filter((c) => versionInRange(version, c.low, c.high));
}

/**
 * Pure: turn located component versions into findings. A matched CVE is `static_confirmed` (the version string is
 * literally in the binary; the CVE's affected range is public fact) — the reachability of the flaw is a separate
 * concern noted in the rationale, so this is a fingerprint fact, not a device verdict. A component with no CVE
 * match is emitted as an `info` inventory fact so the operator sees it was checked, not skipped.
 */
export function buildComponentFindings(hits: ComponentHit[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  for (const hit of hits) {
    const rule = COMPONENT_RULES.find((r) => r.component === hit.component);
    const cves = rule ? matchCves(rule, hit.version) : [];
    if (cves.length === 0) {
      drafts.push({
        kind: 'component-version',
        title: `${hit.component} ${hit.version} (bundled binary, no manifest)`,
        severity: 'info',
        proofState: 'static_confirmed',
        evidence: { component: hit.component, version: hit.version, path: hit.path },
        rationale:
          'Component version fingerprinted from the binary strings (no package manifest, so a manifest-only SBOM ' +
          'misses it). No known CVE matched this version in the curated table.',
      });
      continue;
    }
    for (const cve of cves) {
      drafts.push({
        kind: 'component-cve',
        title: `${cve.id} — ${hit.component} ${hit.version}: ${cve.title}`,
        severity: cve.severity,
        proofState: 'static_confirmed',
        evidence: {
          cve: cve.id,
          component: hit.component,
          version: hit.version,
          affected: `${cve.low}–${cve.high}`,
          path: hit.path,
        },
        rationale: `The bundled ${hit.component} binary reports version ${hit.version}, inside the published affected range ${cve.low}–${cve.high} for ${cve.id}. Version + CVE range are both static facts; runtime reachability of the flaw is a separate confirmation step. Found by binary fingerprinting — a manifest-only SBOM returns 0 CVEs here.`,
      });
    }
  }
  return drafts;
}

export interface ComponentCveResult {
  available: boolean;
  hits: ComponentHit[];
  findings: FindingDraft[];
  reason: string;
}

const WALK_CAP = 8000;
const BIN_READ_CAP = 8 * 1024 * 1024;
const ALL_BIN_NAMES = new Set(COMPONENT_RULES.flatMap((r) => r.binNames));

/** Extract printable ASCII runs (>= 4 chars) from a binary buffer as one newline-joined string, bounded. */
function binaryStrings(buf: Uint8Array): string {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i] as number;
    if (b >= 0x20 && b <= 0x7e) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= 4) out.push(cur);
      cur = '';
    }
  }
  if (cur.length >= 4) out.push(cur);
  return out.join('\n');
}

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

/** Does a basename match a rule binary (exact, or a versioned `.so.N` shared-object variant)? */
function matchesBinName(base: string): ComponentRule | undefined {
  return COMPONENT_RULES.find((r) => r.binNames.some((n) => base === n || (n.endsWith('.so') && base.startsWith(n))));
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
  const stack: string[] = [root];
  while (stack.length > 0 && walked < WALK_CAP) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (walked >= WALK_CAP) break;
      walked++;
      if (e.isSymbolicLink()) continue;
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(abs);
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
  }

  const findings = buildComponentFindings(hits);
  const cveCount = findings.filter((f) => f.kind === 'component-cve').length;
  return {
    available: true,
    hits,
    findings,
    reason: `Component fingerprint: ${hits.length} bundled component(s) versioned, ${cveCount} CVE(s) matched from the curated embedded-n-day table (the surface a manifest-only SBOM misses).`,
  };
}
