/**
 * SBOM + N-day CVE provider. Runs `syft` over an extracted rootfs to enumerate the software bill of materials,
 * then `grype` over the same tree to match known vulnerabilities. Both are optional: with syft absent the job
 * returns a clear `available:false` result rather than throwing, and with grype absent it still returns the
 * package inventory (grypeAvailable:false). Nothing here fails the static workbench — it only enriches it.
 *
 * **This lane makes no network request.** It used to: grype's own defaults downloaded a multi-gigabyte
 * vulnerability database on first run with every FirmLab flag off. Both tools now run under `anchoreEnv()`, and
 * grype runs only against a database that is already on disk unless the research lane is explicitly on —
 * `providers/sbom-db.ts` holds the policy, the measurement that produced it and the refusal text.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isToolAvailable } from '../tools.js';
import type { JobHandle } from './jobs.js';
import { anchoreEnv, dbAgeDays, dbUpdateAllowed, decideGrype, grypeDbDir, readGrypeDbStatus } from './sbom-db.js';

const execFileAsync = promisify(execFile);

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Negligible' | 'Unknown';

const SEVERITY_ORDER: readonly Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];

export interface SbomVuln {
  id: string;
  severity: Severity;
  packageName: string;
  packageVersion: string;
  fixedIn: string | null;
  /**
   * The CVSS vector grype carried for this match, when it carried one — the METRICS, not the score, because
   * `providers/cve-device-triage.ts` needs to know whether the flaw is local, remote, or availability-only and
   * the number cannot answer that. Preferred v3.1 → v3.0 → v4.0, see `preferredCvssVector`.
   *
   * OPTIONAL FOREVER: an `SbomResult` is persisted as JSON on the job row and re-read for as long as the image
   * exists, so a result stored by an older build has no vector and never will. Absent means "not recorded",
   * never "this CVE has no vector" — and triage reads absence as `unknown`, which produces no verdict.
   */
  cvssVector?: string;
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
  /**
   * What syft and grype actually found, against what this result LISTS.
   *
   * Both OPTIONAL FOREVER: an `SbomResult` is persisted as JSON on the job row and re-read for as long as the
   * image exists, so a stored result is data written by an older build and cannot carry a field it never had.
   * Absent means the totals were not recorded — never that nothing was dropped.
   *
   * These exist because `packageCount` and `counts` were both read off the CAPPED list and presented as totals.
   * Measured on the deployed GL.iNet image: syft catalogued 2 019 packages and the stored result said
   * `packageCount: 500`, which is `PKG_CAP` — a bound wearing the name of a count.
   */
  packageTotal?: number;
  vulnerabilityTotal?: number;
  /**
   * Why CVE matching did not happen, when it did not. Also OPTIONAL FOREVER, and it is the field that keeps
   * `grypeAvailable:false` from being read as "grype is not installed": since the lane stopped downloading a
   * database behind the operator's back, the commonest reason is that grype IS installed and has none.
   */
  grypeReason?: string;
  /**
   * The same thing `grypeReason` says, as a value a caller can switch on.
   *
   * `grypeAvailable: false` covers three situations that need three different responses — grype is not installed,
   * grype is installed and has no vulnerability database, grype ran and threw — and only the third is worth asking
   * again. W9 sent all three to `remedy: 'install-tool'`, so a coverage campaign never retried a broken execution
   * and reported it as a deployment to go and fix. The sentence in `grypeReason` already distinguished them, but
   * `opacidad-remedy.ts` refuses to derive a remedy by parsing English prose — reword the sentence and the campaign
   * inherits the defect — so the discriminant has to be a field.
   *
   * OPTIONAL FOREVER, like every other field added here: a result stored by an older build carries no outcome, and
   * absent means "not recorded", never "grype ran". Absent on the `available: false` paths too, where syft decided
   * the job before grype was ever reached.
   */
  grypeOutcome?: GrypeOutcome;
  /**
   * What the CVE list was matched against. A vulnerability count is only as current as the database behind it,
   * and an empty list from an old one is not a clean bill of health — same discipline as `coverage.ts`. Optional
   * forever: a result stored before this field existed recorded no database identity, which is not the same as
   * having matched against none.
   */
  grypeDb?: { schemaVersion: string | null; built: string | null; from: string | null; ageDays: number | null };
  /**
   * What became of syft — the SBOM half — as a value a caller can switch on, the twin of `grypeOutcome`.
   *
   * `available: false` covers a syft that is not installed AND a syft that ran and threw, and W9 sent both to
   * `remedy: 'install-tool'` with the hand-written note `'syft/grype not installed'` — false when syft IS installed
   * and the invocation failed, which the same scan may settle by asking again. `reason` already distinguished the
   * two (`'syft not installed'` vs `` `syft failed: ${message}` ``), but `opacidad-remedy.ts` refuses to derive a
   * remedy by parsing prose, so the discriminant is a field.
   *
   * OPTIONAL FOREVER: a result stored by an older build carries none, and absent means "not recorded" — W9 then
   * keeps the conservative `install-tool` it always used, never inferring a retryable failure it has no record of.
   */
  syftOutcome?: SyftOutcome;
}

/** What became of the SBOM half of this lane. See `SbomResult.syftOutcome`. */
export type SyftOutcome =
  /** syft ran to completion; `packages` is its catalogue of this rootfs. */
  | 'ran'
  /** syft is not on PATH in this deployment. */
  | 'tool_absent'
  /** syft was invoked and the invocation failed. The same question against the same bytes may settle it. */
  | 'run_failed';

/** What became of the CVE half of this lane. See `SbomResult.grypeOutcome`. */
export type GrypeOutcome =
  /** grype ran to completion against a database on disk; `vulnerabilities` is its answer about this firmware. */
  | 'matched'
  /** grype is not on PATH in this deployment. */
  | 'tool_absent'
  /** grype is installed and has no vulnerability database, and this lane never downloads one on its own. */
  | 'db_absent'
  /** grype was invoked and the invocation failed. The same question against the same bytes may settle it. */
  | 'run_failed';

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

function unavailable(target: string, reason: string, syftOutcome: SyftOutcome): SbomResult {
  return {
    available: false,
    reason,
    target,
    packageCount: 0,
    packages: [],
    grypeAvailable: false,
    vulnerabilities: [],
    counts: emptyCounts(),
    syftOutcome,
  };
}

interface SyftArtifact {
  name?: string;
  version?: string;
  type?: string;
}
interface GrypeMatch {
  vulnerability?: {
    id?: string;
    severity?: string;
    fix?: { versions?: string[] };
    cvss?: { version?: string; vector?: string }[];
  };
  artifact?: { name?: string; version?: string };
}

/**
 * Pure: pick one CVSS vector out of the several grype may attach to a match.
 *
 * grype carries an entry per scoring source, so the same CVE routinely arrives with a v2, a v3.1 and a v4.0
 * vector at once. Taking the first would make the choice an artifact of feed order, and v2 has no metric that
 * distinguishes a local escalation from a remote one in the shape triage reads. The preference is explicit —
 * 3.1, then 3.0, then 4.0 — and anything else is skipped rather than passed along to be mis-parsed. Undefined
 * when there is nothing usable, which triage reads as `unknown` and leaves the row alone.
 *
 * 4.0 ranks last only because it is the least represented in the databases in hand today; `cvssMetrics` reads
 * it fully, so a match carrying only a 4.0 vector is still triaged.
 */
export function preferredCvssVector(entries: { version?: string; vector?: string }[] | undefined): string | undefined {
  if (!Array.isArray(entries)) return undefined;
  for (const want of ['3.1', '3.0', '4.0']) {
    const hit = entries.find((e) => typeof e.vector === 'string' && e.vector && e.version?.startsWith(want));
    if (hit?.vector) return hit.vector;
  }
  return undefined;
}

export async function runSbom(_imageId: string, rootfsPath: string, handle: JobHandle): Promise<SbomResult> {
  const env = anchoreEnv();
  if (!(await isToolAvailable('syft'))) {
    handle.log('syft not available on PATH — build the firmware Docker image to enable SBOM/CVE scanning.');
    return unavailable(rootfsPath, 'syft not installed', 'tool_absent');
  }

  // === syft: software bill of materials ===
  handle.log(`Running: syft scan dir:${rootfsPath} -o json`);
  let packages: { name: string; version: string; type: string }[] = [];
  let packageTotal = 0;
  let vulnerabilityTotal = 0;
  try {
    const { stdout } = await execFileAsync('syft', ['scan', `dir:${rootfsPath}`, '-o', 'json'], {
      timeout: 10 * 60 * 1000,
      maxBuffer: 64 * 1024 * 1024,
      env,
    });
    const parsed = JSON.parse(stdout) as { artifacts?: SyftArtifact[] };
    const artifacts = Array.isArray(parsed.artifacts) ? parsed.artifacts : [];
    packageTotal = artifacts.length;
    // Sorted before the cut, so which 500 survive is a stated rule and not syft's catalogue order.
    packages = [...artifacts]
      .map((a) => ({ name: String(a.name ?? '?'), version: String(a.version ?? ''), type: String(a.type ?? '') }))
      .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version))
      .slice(0, PKG_CAP);
    handle.log(`syft catalogued ${artifacts.length} package(s); listing ${packages.length}.`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    handle.log(`syft failed: ${message}`);
    return unavailable(rootfsPath, `syft failed: ${message}`, 'run_failed');
  }

  // === grype: N-day CVE matching (optional, and offline) ===
  //
  // Three outcomes, and the result has to distinguish them, because "no CVEs listed" is the rendering of all
  // three: grype is absent, grype is present with no database, or grype ran. Only the third says anything about
  // this firmware. The database is never fetched here unless the operator turned the research lane on — see
  // `sbom-db.ts` for the measurement that made that rule necessary.
  const toolPresent = await isToolAvailable('grype');
  let grypeAvailable = false;
  let grypeOutcome: GrypeOutcome = 'matched';
  let grypeReason: string | undefined;
  let grypeDb: SbomResult['grypeDb'];
  let vulnerabilities: SbomVuln[] = [];
  let counts = emptyCounts();
  if (!toolPresent) {
    grypeOutcome = 'tool_absent';
    grypeReason = 'CVE matching was not attempted: grype is not installed on this deployment.';
    handle.log('grype not available — returning SBOM without CVE matching.');
  } else {
    const dbDir = grypeDbDir();
    const status = await readGrypeDbStatus(env);
    const decision = decideGrype(status, { updateAllowed: dbUpdateAllowed(), dbDir });
    if (!decision.run) {
      grypeOutcome = 'db_absent';
      grypeReason = decision.reason;
      handle.log(decision.reason);
    } else {
      handle.log(decision.note);
      grypeAvailable = true;
      handle.log(`Running: grype dir:${rootfsPath} -o json`);
      try {
        const { stdout } = await execFileAsync('grype', [`dir:${rootfsPath}`, '-o', 'json'], {
          timeout: 10 * 60 * 1000,
          maxBuffer: 64 * 1024 * 1024,
          env,
        });
        const parsed = JSON.parse(stdout) as { matches?: GrypeMatch[] };
        const matches = Array.isArray(parsed.matches) ? parsed.matches : [];
        vulnerabilityTotal = matches.length;
        const mapped: SbomVuln[] = matches.map((m) => {
          const fixVersions = m.vulnerability?.fix?.versions;
          const vector = preferredCvssVector(m.vulnerability?.cvss);
          return {
            id: String(m.vulnerability?.id ?? '?'),
            severity: normalizeSeverity(m.vulnerability?.severity),
            packageName: String(m.artifact?.name ?? '?'),
            packageVersion: String(m.artifact?.version ?? ''),
            fixedIn: Array.isArray(fixVersions) && fixVersions.length > 0 ? fixVersions.join(', ') : null,
            ...(vector ? { cvssVector: vector } : {}),
          };
        });
        // Rank and count over EVERY match, then cut. The cap used to be applied to grype's raw array first, so it
        // truncated by grype's own emission order — arrival order — and `counts` was a tally of the survivors
        // presented as a total. Severity now decides who survives, and the counts are the real ones either way.
        const ranked = rankVulnerabilities(mapped);
        vulnerabilities = ranked.sorted.slice(0, VULN_CAP);
        counts = ranked.counts;
        // Read the database identity AFTER the run, not before: on the one path that is permitted to fetch one,
        // the pre-run status is the absence that authorised the fetch, and recording that would attribute the
        // matches to a database that did not exist when they were made.
        const used = status.present ? status : await readGrypeDbStatus(env);
        grypeDb = {
          schemaVersion: used.schemaVersion,
          built: used.built,
          from: used.from,
          ageDays: dbAgeDays(used.built),
        };
        handle.log(
          `grype found ${matches.length} vulnerabilit(ies): ${counts.Critical} critical, ${counts.High} high; ` +
            `listing ${vulnerabilities.length} highest-severity first.`,
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        grypeAvailable = false;
        grypeOutcome = 'run_failed';
        grypeReason = `CVE matching was attempted and failed (the SBOM below is unaffected): ${message}`;
        handle.log(`grype failed (SBOM still returned): ${message}`);
      }
    }
  }

  return {
    available: true,
    target: rootfsPath,
    packageCount: packages.length,
    packageTotal,
    vulnerabilityTotal,
    packages,
    syftOutcome: 'ran',
    grypeAvailable,
    grypeOutcome,
    ...(grypeReason ? { grypeReason } : {}),
    ...(grypeDb ? { grypeDb } : {}),
    vulnerabilities,
    counts,
  };
}
