/**
 * SBOM + N-day CVE provider. Runs `syft` over an extracted rootfs to enumerate the software bill of materials,
 * then `grype` over the same tree to match known vulnerabilities. Both are optional: with syft absent the job
 * returns a clear `available:false` result rather than throwing, and with grype absent it still returns the
 * package inventory (grypeAvailable:false). Nothing here fails the static workbench — it only enriches it.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isToolAvailable } from '../tools.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Negligible' | 'Unknown';

const SEVERITY_ORDER: readonly Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];

export interface SbomVuln {
  id: string;
  severity: Severity;
  packageName: string;
  packageVersion: string;
  fixedIn: string | null;
}

export interface SbomResult {
  available: boolean;
  reason?: string;
  target: string;
  packageCount: number;
  packages: { name: string; version: string; type: string }[];
  grypeAvailable: boolean;
  vulnerabilities: SbomVuln[];
  counts: Record<Severity, number>;
}

const PKG_CAP = 500;
const VULN_CAP = 1000;

export function emptyCounts(): Record<Severity, number> {
  return { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 };
}

/** Coerce an arbitrary grype severity string into our fixed union. */
export function normalizeSeverity(raw: unknown): Severity {
  const s = String(raw ?? '').toLowerCase();
  if (s === 'critical') return 'Critical';
  if (s === 'high') return 'High';
  if (s === 'medium') return 'Medium';
  if (s === 'low') return 'Low';
  if (s === 'negligible') return 'Negligible';
  return 'Unknown';
}

/** Sort Critical→Unknown and tally per-severity counts. Pure — unit-tested. */
export function rankVulnerabilities(vulns: SbomVuln[]): { sorted: SbomVuln[]; counts: Record<Severity, number> } {
  const counts = emptyCounts();
  for (const v of vulns) counts[v.severity] += 1;
  const sorted = [...vulns].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.id.localeCompare(b.id),
  );
  return { sorted, counts };
}

function unavailable(target: string, reason: string): SbomResult {
  return {
    available: false,
    reason,
    target,
    packageCount: 0,
    packages: [],
    grypeAvailable: false,
    vulnerabilities: [],
    counts: emptyCounts(),
  };
}

interface SyftArtifact {
  name?: string;
  version?: string;
  type?: string;
}
interface GrypeMatch {
  vulnerability?: { id?: string; severity?: string; fix?: { versions?: string[] } };
  artifact?: { name?: string; version?: string };
}

export async function runSbom(_imageId: string, rootfsPath: string, handle: JobHandle): Promise<SbomResult> {
  if (!(await isToolAvailable('syft'))) {
    handle.log('syft not available on PATH — build the firmware Docker image to enable SBOM/CVE scanning.');
    return unavailable(rootfsPath, 'syft not installed');
  }

  // === syft: software bill of materials ===
  handle.log(`Running: syft scan dir:${rootfsPath} -o json`);
  let packages: { name: string; version: string; type: string }[] = [];
  try {
    const { stdout } = await execFileAsync('syft', ['scan', `dir:${rootfsPath}`, '-o', 'json'], {
      timeout: 10 * 60 * 1000,
      maxBuffer: 64 * 1024 * 1024,
    });
    const parsed = JSON.parse(stdout) as { artifacts?: SyftArtifact[] };
    const artifacts = Array.isArray(parsed.artifacts) ? parsed.artifacts : [];
    packages = artifacts.slice(0, PKG_CAP).map((a) => ({
      name: String(a.name ?? '?'),
      version: String(a.version ?? ''),
      type: String(a.type ?? ''),
    }));
    handle.log(`syft catalogued ${artifacts.length} package(s).`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    handle.log(`syft failed: ${message}`);
    return unavailable(rootfsPath, `syft failed: ${message}`);
  }

  // === grype: N-day CVE matching (optional) ===
  const grypeAvailable = await isToolAvailable('grype');
  let vulnerabilities: SbomVuln[] = [];
  let counts = emptyCounts();
  if (!grypeAvailable) {
    handle.log('grype not available — returning SBOM without CVE matching.');
  } else {
    handle.log(`Running: grype dir:${rootfsPath} -o json`);
    try {
      const { stdout } = await execFileAsync('grype', [`dir:${rootfsPath}`, '-o', 'json'], {
        timeout: 10 * 60 * 1000,
        maxBuffer: 64 * 1024 * 1024,
      });
      const parsed = JSON.parse(stdout) as { matches?: GrypeMatch[] };
      const matches = Array.isArray(parsed.matches) ? parsed.matches : [];
      const mapped: SbomVuln[] = matches.slice(0, VULN_CAP).map((m) => {
        const fixVersions = m.vulnerability?.fix?.versions;
        return {
          id: String(m.vulnerability?.id ?? '?'),
          severity: normalizeSeverity(m.vulnerability?.severity),
          packageName: String(m.artifact?.name ?? '?'),
          packageVersion: String(m.artifact?.version ?? ''),
          fixedIn: Array.isArray(fixVersions) && fixVersions.length > 0 ? fixVersions.join(', ') : null,
        };
      });
      const ranked = rankVulnerabilities(mapped);
      vulnerabilities = ranked.sorted;
      counts = ranked.counts;
      handle.log(`grype found ${matches.length} vulnerabilit(ies): ${counts.Critical} critical, ${counts.High} high.`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      handle.log(`grype failed (SBOM still returned): ${message}`);
    }
  }

  return {
    available: true,
    target: rootfsPath,
    packageCount: packages.length,
    packages,
    grypeAvailable,
    vulnerabilities,
    counts,
  };
}
