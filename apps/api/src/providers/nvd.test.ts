import { describe, expect, it } from 'vitest';
import {
  COMPONENT_CPE,
  NVD_ENDPOINT,
  buildNvdQuery,
  describeNvdDrop,
  nvdCacheKey,
  nvdCandidateTier,
  nvdCpeAlternates,
  nvdCpeFor,
  nvdVersion,
  parseNvdResponse,
  rankNvdCandidates,
  shouldPauseForRateLimit,
} from './nvd.js';

describe('buildNvdQuery', () => {
  it('asks a mapped component by CPE version match, not by keyword', () => {
    const q = buildNvdQuery('dropbear', '2019.78');
    const url = new URL(q.url);
    expect(`${url.origin}${url.pathname}`).toBe(NVD_ENDPOINT);
    expect(q.strategy).toBe('cpe');
    expect(url.searchParams.get('virtualMatchString')).toBe('cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2019.78');
    expect(url.searchParams.get('resultsPerPage')).toBe('20');
    // The whole defect: the keyword form matched CVE DESCRIPTIONS, which name the fixed release and never the
    // vulnerable one someone shipped, so asking for the installed version could not be answered.
    expect(url.searchParams.get('keywordSearch')).toBeNull();
  });

  it('drops only the version constraint when the version is unknown — still scoped to the product', () => {
    const q = buildNvdQuery('busybox', '');
    expect(q.strategy).toBe('cpe');
    expect(new URL(q.url).searchParams.get('virtualMatchString')).toBe('cpe:2.3:a:busybox:busybox');
  });

  it('falls back to a keyword for an unmapped component rather than guessing a CPE vendor', () => {
    const q = buildNvdQuery('vendor-httpd', '1.2');
    expect(q.strategy).toBe('keyword');
    const url = new URL(q.url);
    expect(url.searchParams.get('keywordSearch')).toBe('vendor-httpd 1.2');
    expect(url.searchParams.get('virtualMatchString')).toBeNull();
  });

  it('falls back to a name-only keyword when an unmapped component has no version', () => {
    expect(new URL(buildNvdQuery('vendor-httpd', '').url).searchParams.get('keywordSearch')).toBe('vendor-httpd');
  });

  it('URL-encodes the keyword safely', () => {
    expect(new URL(buildNvdQuery('lib c++', '1.0').url).searchParams.get('keywordSearch')).toBe('lib c++ 1.0');
  });
});

describe('nvdCpeFor', () => {
  it('queries the first identity of every mapped component, and every entry has one', () => {
    for (const name of ['busybox', 'dropbear', 'dnsmasq', 'pppd', 'openssl', 'curl', 'ffmpeg']) {
      expect(nvdCpeFor(name)).toBe(COMPONENT_CPE[name]?.[0]);
      expect(nvdCpeFor(name)).toBeTruthy();
    }
  });

  it('pins curl, where the obvious guess is the wrong one', () => {
    // Measured against the live API: `curl:curl` at 8.6.0 returns 0, `haxx:curl` returns 35. A guessed vendor
    // string does not fail loudly — it queries a product that does not exist and returns nothing, which reads
    // exactly like "no CVEs".
    expect(nvdCpeFor('curl')).toBe('haxx:curl');
  });

  it('carries the alternate identities without querying them', () => {
    expect(nvdCpeAlternates('dropbear')).toEqual(['matt_johnston:dropbear_ssh_server', 'dropbear_project:dropbear']);
    expect(nvdCpeAlternates('curl')).toEqual(['haxx:libcurl']);
    // A component with a single known identity has nothing unchecked to declare.
    expect(nvdCpeAlternates('busybox')).toEqual([]);
    expect(nvdCpeAlternates('vendor-httpd')).toEqual([]);
  });

  it('pins pppd, which is the one that cannot be derived from the name', () => {
    // `pppd` returns ZERO entries from NVD's CPE dictionary; this identity was read off the CPEs attached to
    // CVE-2020-8597 — the pppd CVE the curated table already claims. A plausible-looking guess would query a
    // product that does not exist and return nothing, indistinguishably from "no CVEs".
    expect(nvdCpeFor('pppd')).toBe('point-to-point_protocol_project:point-to-point_protocol');
  });

  it('matches on the normalized name, and refuses anything unverified', () => {
    expect(nvdCpeFor('  BusyBox ')).toBe('busybox:busybox');
    expect(nvdCpeFor('busybox-w32')).toBeNull();
    expect(nvdCpeFor('')).toBeNull();
  });
});

describe('nvdVersion', () => {
  it("treats syft's UNKNOWN placeholder as the absence of a version, not as one", () => {
    // 66 of the GL.iNet's kernel modules come back versioned `UNKNOWN`, and passing it through built
    // `keywordSearch=act_connmark UNKNOWN` — a rate-limit slot spent asking NVD about a word.
    expect(nvdVersion('UNKNOWN')).toBe('');
    expect(nvdVersion('unknown')).toBe('');
    expect(nvdVersion('  ')).toBe('');
    expect(nvdVersion('N/A')).toBe('');
    expect(nvdVersion(' 1.01 ')).toBe('1.01');
  });

  it('keeps a real version that merely looks odd', () => {
    expect(nvdVersion('2012.55')).toBe('2012.55');
    expect(nvdVersion('0.107.73-2')).toBe('0.107.73-2');
  });
});

describe('rankNvdCandidates', () => {
  // The real GL.iNet BE3600 shape: syft lists kernel modules alphabetically first, so arrival order handed the
  // whole 6-slot anonymous budget to unversioned names and never asked the three answerable ones anything.
  const glinet = [
    { name: 'act_connmark', version: 'UNKNOWN' },
    { name: 'act_csum', version: 'UNKNOWN' },
    { name: 'act_gact', version: 'UNKNOWN' },
    { name: 'dnsmasq', version: '2.92' },
    { name: 'pppd', version: '2.4.9' },
    { name: 'openssl', version: '3.0.13' },
  ];

  it('puts the answerable questions ahead of the cap, not behind it', () => {
    const top3 = rankNvdCandidates(glinet)
      .slice(0, 3)
      .map((c) => c.name);
    expect(top3.sort()).toEqual(['dnsmasq', 'openssl', 'pppd']);
  });

  it('orders by tier: cpe+version, cpe, keyword+version, keyword alone', () => {
    const ranked = rankNvdCandidates([
      { name: 'act_connmark', version: 'UNKNOWN' },
      { name: 'vendor-httpd', version: '1.2' },
      { name: 'busybox', version: '' },
      { name: 'busybox', version: '1.01' },
    ]);
    expect(ranked.map((c) => nvdCandidateTier(c))).toEqual([
      'cpe-versioned',
      'cpe-unversioned',
      'keyword-versioned',
      'keyword-unversioned',
    ]);
  });

  it('is stable within a tier, so the order is never an artifact of the sort', () => {
    const same = [
      { name: 'openssl', version: '3.0.13' },
      { name: 'dnsmasq', version: '2.92' },
      { name: 'pppd', version: '2.4.9' },
    ];
    expect(rankNvdCandidates(same).map((c) => c.name)).toEqual(['openssl', 'dnsmasq', 'pppd']);
  });
});

describe('describeNvdDrop', () => {
  it('says nothing when the cap dropped nothing', () => {
    expect(describeNvdDrop([], 6)).toBe('');
  });

  it('distinguishes a bound working as intended from a budget that is too small', () => {
    // Same count, opposite meanings — which is the whole reason the rule is stated rather than just the number.
    const junk = describeNvdDrop([{ name: 'act_csum', version: 'UNKNOWN' }], 6);
    expect(junk).toContain('keyword-only questions');
    const real = describeNvdDrop([{ name: 'busybox', version: '1.01' }], 6);
    expect(real).toContain('the cap is genuinely too small');
    expect(real).toContain('1 cpe-versioned');
  });
});

describe('nvdCacheKey', () => {
  it('is the exact request, so a different component or version is a different entry', () => {
    expect(nvdCacheKey('dropbear', '2019.78')).toBe(buildNvdQuery('dropbear', '2019.78').url);
    expect(nvdCacheKey('dropbear', '2019.78')).not.toBe(nvdCacheKey('dropbear', '2020.81'));
    expect(nvdCacheKey('dropbear', '')).not.toBe(nvdCacheKey('dropbear', '2019.78'));
  });

  it('changed with the query form, so keyword-era answers are not served to CPE-era questions', () => {
    // The cache is keyed on the URL precisely so a changed question invalidates rather than reuses. Without this
    // the first run after the fix would replay the empty keyword answers it was meant to replace.
    expect(nvdCacheKey('dropbear', '2012.55')).toContain('virtualMatchString');
    expect(nvdCacheKey('dropbear', '2012.55')).not.toContain('keywordSearch');
  });

  it('carries no API key — the key travels in a header and must never land in a cache filename', () => {
    expect(nvdCacheKey('busybox', '1.01')).not.toMatch(/apikey/i);
  });
});

describe('shouldPauseForRateLimit', () => {
  it('waits between real requests, which is what NVD asks for', () => {
    expect(shouldPauseForRateLimit(1, true, 6500)).toBe(true);
    expect(shouldPauseForRateLimit(3, true, 6500)).toBe(true);
  });

  it('never waits before a cache hit — nothing goes out, so no rate-limit toll is owed', () => {
    expect(shouldPauseForRateLimit(1, false, 6500)).toBe(false);
    expect(shouldPauseForRateLimit(5, false, 6500)).toBe(false);
  });

  it('never waits before the first request, or when an API key removed the delay', () => {
    expect(shouldPauseForRateLimit(0, true, 6500)).toBe(false);
    expect(shouldPauseForRateLimit(2, true, 0)).toBe(false);
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
