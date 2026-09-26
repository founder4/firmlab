import { describe, expect, it } from 'vitest';
import {
  GRYPE_NO_KEV_PROVIDER_REASON,
  type SbomVuln,
  type Severity,
  emptyCounts,
  grypeKevAnnotation,
  normalizeSeverity,
  preferredCvssVector,
  rankVulnerabilities,
} from './sbom.js';

describe('normalizeSeverity', () => {
  it('maps known grype severities case-insensitively', () => {
    expect(normalizeSeverity('Critical')).toBe('Critical');
    expect(normalizeSeverity('high')).toBe('High');
    expect(normalizeSeverity('MEDIUM')).toBe('Medium');
    expect(normalizeSeverity('negligible')).toBe('Negligible');
  });
  it('falls back to Unknown for unrecognized or missing input', () => {
    expect(normalizeSeverity('bogus')).toBe('Unknown');
    expect(normalizeSeverity(undefined)).toBe('Unknown');
    expect(normalizeSeverity(null)).toBe('Unknown');
  });
});

describe('rankVulnerabilities', () => {
  const mk = (id: string, severity: SbomVuln['severity']): SbomVuln => ({
    id,
    severity,
    packageName: 'pkg',
    packageVersion: '1.0',
    fixedIn: null,
  });

  it('sorts Critical→Unknown and tallies counts', () => {
    const { sorted, counts } = rankVulnerabilities([
      mk('CVE-3', 'Low'),
      mk('CVE-1', 'Critical'),
      mk('CVE-2', 'High'),
      mk('CVE-4', 'Unknown'),
    ]);
    expect(sorted.map((v) => v.severity)).toEqual(['Critical', 'High', 'Low', 'Unknown']);
    expect(counts.Critical).toBe(1);
    expect(counts.High).toBe(1);
    expect(counts.Low).toBe(1);
    expect(counts.Unknown).toBe(1);
    expect(counts.Medium).toBe(0);
  });

  it('breaks ties within a severity by id', () => {
    const { sorted } = rankVulnerabilities([mk('CVE-9', 'High'), mk('CVE-1', 'High')]);
    expect(sorted.map((v) => v.id)).toEqual(['CVE-1', 'CVE-9']);
  });

  it('emptyCounts starts at zero for every severity', () => {
    expect(emptyCounts()).toEqual({ Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 });
  });
});

/**
 * The caps, and the totals they used to eat.
 *
 * `matches.slice(0, VULN_CAP)` ran BEFORE `rankVulnerabilities`, so the cut was by grype's own emission order —
 * arrival order — and `counts` was a tally of the survivors presented as a total. Packages were worse in practice:
 * measured on the deployed GL.iNet image, syft catalogued 2 019 and the stored result said `packageCount: 500`,
 * which is `PKG_CAP` exactly. A bound wearing the name of a count.
 */
describe('sbom — the cut is by severity, and the counts are of everything', () => {
  const vuln = (id: string, severity: Severity): SbomVuln => ({
    id,
    severity,
    packageName: 'busybox',
    packageVersion: '1.7.2',
    fixedIn: null,
  });

  it('counts every match, not the ones that survived the listing', () => {
    // Two criticals arriving LAST, the shape the old order lost: they were sliced off before being counted.
    const all = [...Array.from({ length: 8 }, (_, i) => vuln(`CVE-LOW-${i}`, 'Low')), vuln('CVE-C1', 'Critical')];
    const ranked = rankVulnerabilities(all);
    expect(ranked.counts.Critical).toBe(1);
    expect(ranked.counts.Low).toBe(8);
    // Ranking puts the critical first, so a cut of ANY size keeps it.
    expect(ranked.sorted.slice(0, 1)[0]?.id).toBe('CVE-C1');
  });

  it('ranks before any cut, so severity and not arrival order decides who is listed', () => {
    const arrivalOrder = [vuln('CVE-M1', 'Medium'), vuln('CVE-L1', 'Low'), vuln('CVE-C1', 'Critical')];
    const kept = rankVulnerabilities(arrivalOrder)
      .sorted.slice(0, 2)
      .map((v) => v.id);
    expect(kept).toEqual(['CVE-C1', 'CVE-M1']);
    expect(kept).not.toContain('CVE-L1');
  });

  it('is a stable order, so the same SBOM lists the same set twice', () => {
    const set = [vuln('CVE-B', 'High'), vuln('CVE-A', 'High'), vuln('CVE-C', 'High')];
    const once = rankVulnerabilities(set).sorted.map((v) => v.id);
    const twice = rankVulnerabilities([...set].reverse()).sorted.map((v) => v.id);
    expect(once).toEqual(twice);
    expect(once).toEqual(['CVE-A', 'CVE-B', 'CVE-C']);
  });
});

/**
 * grype attaches one CVSS entry per scoring source, so the same CVE routinely arrives with several vectors at
 * once. Taking the first would make the choice an artifact of feed order — and on a v2-first row it would hand
 * triage a vector with no metric that separates a local escalation from a remote one.
 */
describe('preferredCvssVector', () => {
  const V2 = 'AV:N/AC:L/Au:N/C:P/I:P/A:P';
  const V30 = 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  const V31 = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H';
  const V40 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H';

  it('prefers 3.1 over everything else, whatever order they arrive in', () => {
    const entries = [
      { version: '2.0', vector: V2 },
      { version: '4.0', vector: V40 },
      { version: '3.1', vector: V31 },
      { version: '3.0', vector: V30 },
    ];
    expect(preferredCvssVector(entries)).toBe(V31);
    expect(preferredCvssVector([...entries].reverse())).toBe(V31);
  });

  it('falls to 3.0, then 4.0, rather than dropping a usable vector', () => {
    expect(
      preferredCvssVector([
        { version: '2.0', vector: V2 },
        { version: '3.0', vector: V30 },
      ]),
    ).toBe(V30);
    expect(
      preferredCvssVector([
        { version: '2.0', vector: V2 },
        { version: '4.0', vector: V40 },
      ]),
    ).toBe(V40);
  });

  it('skips a v2-only row rather than passing a vector triage cannot read', () => {
    expect(preferredCvssVector([{ version: '2.0', vector: V2 }])).toBeUndefined();
  });

  it('is undefined for the shapes grype actually omits', () => {
    expect(preferredCvssVector(undefined)).toBeUndefined();
    expect(preferredCvssVector([])).toBeUndefined();
    expect(preferredCvssVector([{ version: '3.1' }])).toBeUndefined();
    expect(preferredCvssVector([{ vector: V31 }])).toBeUndefined();
  });
});

describe('grypeKevAnnotation', () => {
  // Shape measured on grype 0.119.0 / schema v6.1.9 (2026-09-26): KEV rides on a GHSA row, keyed by its own `cve`.
  const LOG4J = {
    cve: 'CVE-2021-44228',
    dateAdded: '2021-12-10',
    knownRansomwareCampaignUse: 'known',
  };
  const descriptor = { db: { providers: { kev: { captured: '2026-09-26T00:33:03Z' }, nvd: { captured: 'x' } } } };
  const match = (id: string, name: string, knownExploited?: (typeof LOG4J)[]) => ({
    vulnerability: { id, ...(knownExploited ? { knownExploited } : {}) },
    artifact: { name, version: '2.14.1' },
  });

  it('reports the KEV CVE carried on a GHSA row, keyed by the cve and deduped across rows', () => {
    const r = grypeKevAnnotation({
      descriptor,
      matches: [
        match('GHSA-jfh8-c2jp-5v3q', 'log4j-core', [LOG4J]),
        match('CVE-2021-44228', 'log4j-core', [LOG4J]),
        match('GHSA-p6xc-xr62-6r2g', 'log4j-core'),
      ],
    });
    expect(r).toEqual({
      state: 'annotated',
      captured: '2026-09-26T00:33:03Z',
      matches: [
        {
          cve: 'CVE-2021-44228',
          vulnerabilityIds: ['GHSA-jfh8-c2jp-5v3q', 'CVE-2021-44228'],
          packages: ['log4j-core@2.14.1'],
          dateAdded: '2021-12-10',
          knownRansomware: 'known',
        },
      ],
    });
  });

  it('is a measured zero, dated, when the database carried KEV and no match was in it', () => {
    expect(grypeKevAnnotation({ descriptor, matches: [match('GHSA-p6xc-xr62-6r2g', 'log4j-core')] })).toEqual({
      state: 'annotated',
      captured: '2026-09-26T00:33:03Z',
      matches: [],
    });
  });

  it('is unknown, never zero, when the database names no kev provider — even if a row claims KEV', () => {
    const noKev = { db: { providers: { nvd: { captured: 'x' } } } };
    for (const out of [{ matches: [] }, { descriptor: noKev, matches: [match('X', 'p', [LOG4J])] }, null, 'junk']) {
      expect(grypeKevAnnotation(out)).toEqual({ state: 'no-kev-provider', reason: GRYPE_NO_KEV_PROVIDER_REASON });
    }
  });

  it('drops an annotation whose cve is not a CVE id', () => {
    const r = grypeKevAnnotation({ descriptor, matches: [match('GHSA-x', 'p', [{ ...LOG4J, cve: 'n/a' }])] });
    expect(r).toEqual({ state: 'annotated', captured: '2026-09-26T00:33:03Z', matches: [] });
  });
});
