import { describe, expect, it } from 'vitest';
import { type SbomVuln, emptyCounts, normalizeSeverity, rankVulnerabilities } from './sbom.js';

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
