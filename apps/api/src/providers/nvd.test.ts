import { describe, expect, it } from 'vitest';
import { NVD_ENDPOINT, buildNvdQuery, parseNvdResponse } from './nvd.js';

describe('buildNvdQuery', () => {
  it('builds a keyword search of name + version, capped', () => {
    const url = new URL(buildNvdQuery('dropbear', '2019.78'));
    expect(`${url.origin}${url.pathname}`).toBe(NVD_ENDPOINT);
    expect(url.searchParams.get('keywordSearch')).toBe('dropbear 2019.78');
    expect(url.searchParams.get('resultsPerPage')).toBe('20');
  });

  it('falls back to a name-only keyword when the version is unknown', () => {
    const url = new URL(buildNvdQuery('busybox', ''));
    expect(url.searchParams.get('keywordSearch')).toBe('busybox');
  });

  it('URL-encodes the keyword safely', () => {
    const url = new URL(buildNvdQuery('lib c++', '1.0'));
    expect(url.searchParams.get('keywordSearch')).toBe('lib c++ 1.0');
  });
});

describe('parseNvdResponse', () => {
  const json = {
    vulnerabilities: [
      {
        cve: {
          id: 'CVE-2018-15599',
          descriptions: [
            { lang: 'es', value: 'desbordamiento' },
            { lang: 'en', value: 'Recursion in dropbear leads to stack exhaustion.' },
          ],
          metrics: {
            cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: 'HIGH' } }],
            cvssMetricV2: [{ baseSeverity: 'MEDIUM', cvssData: { baseScore: 5.0 } }],
          },
          references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2018-15599' }, {}],
        },
      },
    ],
  };

  it('extracts id, english summary, severity/score (preferring CVSS v3.1) and references', () => {
    const adv = parseNvdResponse(json);
    expect(adv).toHaveLength(1);
    expect(adv[0]?.id).toBe('CVE-2018-15599');
    expect(adv[0]?.summary).toContain('stack exhaustion');
    expect(adv[0]?.severity).toBe('HIGH');
    expect(adv[0]?.score).toBe(7.5);
    expect(adv[0]?.references).toEqual(['https://nvd.nist.gov/vuln/detail/CVE-2018-15599']);
  });

  it('falls back to CVSS v2 severity when v3 is absent', () => {
    const adv = parseNvdResponse({
      vulnerabilities: [{ cve: { id: 'CVE-2000-1', metrics: { cvssMetricV2: [{ baseSeverity: 'LOW' }] } } }],
    });
    expect(adv[0]?.severity).toBe('LOW');
    expect(adv[0]?.score).toBeNull();
  });

  it('tolerates missing metrics/descriptions and a non-array payload', () => {
    const adv = parseNvdResponse({ vulnerabilities: [{ cve: { id: 'CVE-2001-2' } }] });
    expect(adv[0]?.severity).toBeNull();
    expect(adv[0]?.summary).toBe('');
    expect(parseNvdResponse({})).toEqual([]);
    expect(parseNvdResponse('nope')).toEqual([]);
  });
});
