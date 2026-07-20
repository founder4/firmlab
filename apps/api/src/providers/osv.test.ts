import { describe, expect, it } from 'vitest';
import { buildOsvQuery, osvEcosystem, parseOsvResponse } from './osv.js';

describe('osvEcosystem', () => {
  it('maps syft package types to OSV ecosystems', () => {
    expect(osvEcosystem('deb')).toBe('Debian');
    expect(osvEcosystem('apk')).toBe('Alpine');
    expect(osvEcosystem('python')).toBe('PyPI');
    expect(osvEcosystem('npm')).toBe('npm');
  });
  it('returns null for unmapped types (honest: not queryable)', () => {
    expect(osvEcosystem('binary')).toBeNull();
    expect(osvEcosystem('unknown')).toBeNull();
  });
});

describe('buildOsvQuery', () => {
  it('builds the /v1/query package+version body', () => {
    expect(buildOsvQuery('busybox', '1.35.0', 'Debian')).toEqual({
      package: { name: 'busybox', ecosystem: 'Debian' },
      version: '1.35.0',
    });
  });
});

describe('parseOsvResponse', () => {
  it('extracts id, aliases, summary, severity and references', () => {
    const adv = parseOsvResponse({
      vulns: [
        {
          id: 'DSA-1234',
          aliases: ['CVE-2023-1111'],
          summary: 'heap overflow in busybox',
          database_specific: { severity: 'HIGH' },
          references: [{ url: 'https://example.org/adv' }, { type: 'WEB' }],
        },
      ],
    });
    expect(adv).toHaveLength(1);
    expect(adv[0]?.id).toBe('DSA-1234');
    expect(adv[0]?.aliases).toEqual(['CVE-2023-1111']);
    expect(adv[0]?.severity).toBe('HIGH');
    expect(adv[0]?.references).toEqual(['https://example.org/adv']);
  });

  it('falls back to CVSS score for severity and details for summary', () => {
    const adv = parseOsvResponse({
      vulns: [{ id: 'X', details: 'long details', severity: [{ type: 'CVSS_V3', score: '9.8' }] }],
    });
    expect(adv[0]?.severity).toBe('9.8');
    expect(adv[0]?.summary).toBe('long details');
  });

  it('an empty/absent vulns list is no advisories, never an error', () => {
    expect(parseOsvResponse({})).toEqual([]);
    expect(parseOsvResponse({ vulns: [] })).toEqual([]);
  });
});
