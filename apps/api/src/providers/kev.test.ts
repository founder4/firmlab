import { describe, expect, it } from 'vitest';
import { collectCveIds, crossReferenceKev, parseKevCatalog } from './kev.js';

const CATALOG = {
  title: 'CISA Catalog of Known Exploited Vulnerabilities',
  count: 2,
  vulnerabilities: [
    {
      cveID: 'CVE-2021-44228',
      vendorProject: 'Apache',
      product: 'Log4j2',
      vulnerabilityName: 'Apache Log4j2 RCE',
      dateAdded: '2021-12-10',
      shortDescription: 'Log4j2 JNDI features do not protect against attacker-controlled LDAP.',
      knownRansomwareCampaignUse: 'Known',
    },
    {
      cveID: 'cve-2018-15599',
      vendorProject: 'Dropbear',
      product: 'SSH',
      vulnerabilityName: 'Dropbear recursion',
      dateAdded: '2022-01-01',
      shortDescription: 'Stack exhaustion.',
      knownRansomwareCampaignUse: 'Unknown',
    },
    { notACve: true },
  ],
};

describe('parseKevCatalog', () => {
  it('normalizes entries and upper-cases the CVE id, dropping non-CVE rows', () => {
    const entries = parseKevCatalog(CATALOG);
    expect(entries).toHaveLength(2);
    expect(entries[0]?.cveID).toBe('CVE-2021-44228');
    expect(entries[1]?.cveID).toBe('CVE-2018-15599'); // was lower-case in the feed
    expect(entries[0]?.knownRansomware).toBe('Known');
  });

  it('tolerates a malformed payload', () => {
    expect(parseKevCatalog({})).toEqual([]);
    expect(parseKevCatalog(null)).toEqual([]);
  });
});

describe('crossReferenceKev', () => {
  const catalog = parseKevCatalog(CATALOG);

  it('returns only the discovered CVEs that are in KEV (case-insensitive)', () => {
    const matches = crossReferenceKev(['cve-2021-44228', 'CVE-2099-0000'], catalog);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.cveID).toBe('CVE-2021-44228');
    expect(matches[0]?.product).toBe('Log4j2');
  });

  it('returns nothing when no discovered CVE is exploited', () => {
    expect(crossReferenceKev(['CVE-2000-1234'], catalog)).toHaveLength(0);
  });
});

describe('collectCveIds', () => {
  it('gathers CVE ids from OSV aliases + ids and NVD ids, deduped and upper-cased', () => {
    const osv = [
      { advisories: [{ id: 'DSA-1', aliases: ['CVE-2021-44228', 'GHSA-xxxx'] }] },
      { advisories: [{ id: 'CVE-2020-0001', aliases: [] }] },
    ];
    const nvd = [{ advisories: [{ id: 'cve-2021-44228' }, { id: 'CVE-2019-9999' }] }];
    const ids = collectCveIds(osv, nvd).sort();
    expect(ids).toEqual(['CVE-2019-9999', 'CVE-2020-0001', 'CVE-2021-44228']);
  });

  it('ignores non-CVE identifiers (OSV database ids, GHSAs)', () => {
    const ids = collectCveIds([{ advisories: [{ id: 'RUSTSEC-2021-1', aliases: ['GHSA-abc'] }] }], []);
    expect(ids).toEqual([]);
  });
});
