import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  COMPONENT_CPE,
  LINUX_KERNEL_CNA_SOURCE,
  NVD_ENDPOINT,
  NVD_MAX_ADVISORIES,
  NVD_MAX_PAGES,
  NVD_PAGE_SIZE,
  buildNvdQuery,
  describeNvdDrop,
  nextNvdPage,
  nvdCacheKey,
  nvdCandidateTier,
  nvdCpeAlternates,
  nvdCpeFor,
  nvdVersion,
  parseNvdResponse,
  parseNvdTotal,
  queryNvdBatch,
  rankNvdCandidates,
  resolveNvdPaginationBounds,
  shouldPauseForRateLimit,
} from './nvd.js';

const tempDirs: string[] = [];

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('buildNvdQuery', () => {
  it('asks a mapped component by CPE version match, not by keyword', () => {
    const q = buildNvdQuery('dropbear', '2019.78');
    const url = new URL(q.url);
    expect(`${url.origin}${url.pathname}`).toBe(NVD_ENDPOINT);
    expect(q.strategy).toBe('cpe');
    expect(url.searchParams.get('virtualMatchString')).toBe('cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2019.78');
    // Bound to the constant, not to a literal: the request page size and the parser's slice were two different
    // silent limits on the same list until they were made one number.
    expect(url.searchParams.get('resultsPerPage')).toBe(String(NVD_PAGE_SIZE));
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

  it('puts later pages at the requested NVD startIndex without changing the first-page cache key', () => {
    expect(new URL(buildNvdQuery('linux-kernel', '6.1').url).searchParams.get('startIndex')).toBeNull();
    const page = new URL(buildNvdQuery('linux-kernel', '6.1', 25, 50).url);
    expect(page.searchParams.get('startIndex')).toBe('50');
    expect(page.searchParams.get('resultsPerPage')).toBe('25');
    expect(nvdCacheKey('linux-kernel', '6.1', 50, 25)).toBe(page.toString());
  });
});

describe('nvdCpeFor', () => {
  it('queries the first identity of every mapped component, and every entry has one', () => {
    for (const name of ['busybox', 'dropbear', 'dnsmasq', 'pppd', 'openssl', 'curl', 'ffmpeg', 'linux-kernel']) {
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

  it('uses the OS/kernel CPE part and restricts Linux results to the kernel CNA', () => {
    const url = new URL(buildNvdQuery('linux-kernel', '2.6.31').url);
    expect(url.searchParams.get('virtualMatchString')).toBe('cpe:2.3:o:linux:linux_kernel:2.6.31');
    expect(url.searchParams.get('sourceIdentifier')).toBe(LINUX_KERNEL_CNA_SOURCE);
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

  it('keeps the kernel inside the anonymous budget when CPE-versioned questions tie', () => {
    const ranked = rankNvdCandidates([
      { name: 'busybox', version: '1.36' },
      { name: 'linux-kernel', version: '2.6.31' },
      { name: 'dnsmasq', version: '2.92' },
    ]);
    expect(ranked[0]?.name).toBe('linux-kernel');
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

describe('nextNvdPage', () => {
  it('starts at zero and advances by the advisory coverage already completed', () => {
    const bounds = { pageSize: 50, maxPages: 4, maxAdvisories: 200 };
    expect(
      nextNvdPage(
        { pagesCompleted: 0, advisoriesCollected: 0, lastPageCount: 0, lastPageRequested: 0, totalMatching: null },
        bounds,
      ),
    ).toEqual({ fetch: true, startIndex: 0, resultsPerPage: 50 });
    expect(
      nextNvdPage(
        { pagesCompleted: 1, advisoriesCollected: 50, lastPageCount: 50, lastPageRequested: 50, totalMatching: 70 },
        bounds,
      ),
    ).toEqual({ fetch: true, startIndex: 50, resultsPerPage: 20 });
    expect(
      nextNvdPage(
        { pagesCompleted: 2, advisoriesCollected: 70, lastPageCount: 20, lastPageRequested: 20, totalMatching: 70 },
        bounds,
      ),
    ).toEqual({ fetch: false, complete: true, reason: 'complete' });
  });

  it('enforces both hard production ceilings even when callers request more', () => {
    expect(resolveNvdPaginationBounds({ maxPages: 999, maxAdvisories: 999_999 })).toEqual({
      pageSize: NVD_PAGE_SIZE,
      maxPages: NVD_MAX_PAGES,
      maxAdvisories: NVD_MAX_ADVISORIES,
    });
  });

  it('never calls page/advisory-bounded or unknowable coverage complete', () => {
    expect(
      nextNvdPage(
        { pagesCompleted: 2, advisoriesCollected: 100, lastPageCount: 50, lastPageRequested: 50, totalMatching: 120 },
        { pageSize: 50, maxPages: 2, maxAdvisories: 200 },
      ),
    ).toEqual({ fetch: false, complete: false, reason: 'page-cap' });
    expect(
      nextNvdPage(
        { pagesCompleted: 2, advisoriesCollected: 60, lastPageCount: 30, lastPageRequested: 30, totalMatching: 120 },
        { pageSize: 30, maxPages: 4, maxAdvisories: 60 },
      ),
    ).toEqual({ fetch: false, complete: false, reason: 'advisory-cap' });
    expect(
      nextNvdPage(
        { pagesCompleted: 1, advisoriesCollected: 50, lastPageCount: 50, lastPageRequested: 50, totalMatching: null },
        { pageSize: 50, maxPages: 4, maxAdvisories: 200 },
      ),
    ).toEqual({ fetch: false, complete: false, reason: 'missing-total' });
    expect(
      nextNvdPage(
        { pagesCompleted: 1, advisoriesCollected: 49, lastPageCount: 49, lastPageRequested: 50, totalMatching: 60 },
        { pageSize: 50, maxPages: 4, maxAdvisories: 200 },
      ),
    ).toEqual({ fetch: false, complete: false, reason: 'short-page' });
  });
});

describe('parseNvdTotal', () => {
  it("reads NVD's own match count, which is the denominator a page-limited list needs", () => {
    // Measured: curl 8.6.0 matches 35 CVEs and openssl 3.0.13 matches 26, while a page returned 20 of each. The
    // list was presented as the set, so 21 advisories vanished without anything saying so.
    expect(parseNvdTotal({ totalResults: 35, vulnerabilities: [] })).toBe(35);
    expect(parseNvdTotal({ totalResults: 0 })).toBe(0);
  });

  it('is null rather than 0 when the field is absent — "we did not read it" is not "there are none"', () => {
    expect(parseNvdTotal({})).toBeNull();
    expect(parseNvdTotal(null)).toBeNull();
    expect(parseNvdTotal({ totalResults: 'many' })).toBeNull();
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

  it('extracts id, english summary, severity/score (preferring CVSS v3.1 over v2) and references', () => {
    const adv = parseNvdResponse(json);
    expect(adv).toHaveLength(1);
    expect(adv[0]?.id).toBe('CVE-2018-15599');
    expect(adv[0]?.summary).toContain('stack exhaustion');
    expect(adv[0]?.severity).toBe('HIGH');
    expect(adv[0]?.score).toBe(7.5);
    expect(adv[0]?.references).toEqual(['https://nvd.nist.gov/vuln/detail/CVE-2018-15599']);
  });

  /**
   * NVD attaches v4.0 to a small and growing minority of records, so the fixture above — v3.1 and v2, no v4 — is
   * the shape the overwhelming majority of responses still have, and it has to keep scoring 7.5. These two cover
   * the other side: a record that DOES carry v4.0 is read from it, newest first, as NVD itself presents it.
   */
  it('prefers CVSS v4.0 when NVD published one', () => {
    const adv = parseNvdResponse({
      vulnerabilities: [
        {
          cve: {
            id: 'CVE-2024-1',
            metrics: {
              cvssMetricV40: [{ cvssData: { baseScore: 9.3, baseSeverity: 'CRITICAL' } }],
              cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: 'HIGH' } }],
              cvssMetricV2: [{ baseSeverity: 'MEDIUM', cvssData: { baseScore: 5.0 } }],
            },
          },
        },
      ],
    });
    expect(adv[0]?.severity).toBe('CRITICAL');
    expect(adv[0]?.score).toBe(9.3);
  });

  it('falls through a v4.0 entry that carries no cvssData, rather than reporting the CVE as ungraded', () => {
    const adv = parseNvdResponse({
      vulnerabilities: [
        {
          cve: {
            id: 'CVE-2024-2',
            metrics: {
              cvssMetricV40: [{}],
              cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: 'HIGH' } }],
            },
          },
        },
      ],
    });
    expect(adv[0]?.severity).toBe('HIGH');
    expect(adv[0]?.score).toBe(7.5);
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

describe('queryNvdBatch pagination', () => {
  const cfg = {
    allowlist: ['services.nvd.nist.gov'],
    timeoutMs: 1_000,
    hashLookup: false,
  };

  function cacheOptions() {
    const dir = mkdtempSync(join(tmpdir(), 'firmlab-nvd-pages-'));
    tempDirs.push(dir);
    return { dir, now: 1_000, ttlMs: 60_000 };
  }

  function payload(start: number, count: number, totalResults: number) {
    return {
      totalResults,
      vulnerabilities: Array.from({ length: count }, (_, i) => ({
        cve: { id: `CVE-2026-${String(start + i).padStart(4, '0')}` },
      })),
    };
  }

  it('retrieves successive offsets, rate-limits network pages, and reuses every page from cache', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000);
    const requestTimes: number[] = [];
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      requestTimes.push(Date.now());
      const start = Number(new URL(String(input)).searchParams.get('startIndex') ?? 0);
      const count = start === 0 ? 50 : 5;
      return new Response(JSON.stringify(payload(start, count, 55)), { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const cache = cacheOptions();

    const firstPromise = queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 100,
      cache,
    });
    await vi.runAllTimersAsync();
    const first = await firstPromise;
    expect(requestTimes).toEqual([1_000, 1_100]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(first.components[0]?.advisories).toHaveLength(55);
    expect(first.components[0]?.pageCoverage).toMatchObject({
      attemptedOffsets: [0, 50],
      completedOffsets: [0, 50],
      totalMatching: 55,
      complete: true,
      truncated: false,
      stopReason: 'complete',
    });
    expect(first.cache).toMatchObject({ hits: 0, misses: 2 });

    const cached = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 100,
      cache,
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(cached.cache).toMatchObject({ hits: 2, misses: 0 });
    expect(cached.completed).toBe(1);
    expect(cached.incomplete).toBe(0);
  });

  it('stops at the advisory bound and reports the retained prefix rather than calling it complete', async () => {
    const urls: URL[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        const url = new URL(String(input));
        urls.push(url);
        const start = Number(url.searchParams.get('startIndex') ?? 0);
        const count = Number(url.searchParams.get('resultsPerPage'));
        return new Response(JSON.stringify(payload(start, count, 120)), { status: 200 });
      }),
    );

    const result = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
      maxPages: 4,
      maxAdvisories: 70,
    });
    expect(urls.map((url) => url.searchParams.get('startIndex'))).toEqual([null, '50']);
    expect(urls.map((url) => url.searchParams.get('resultsPerPage'))).toEqual(['50', '20']);
    expect(result.totalAdvisories).toBe(70);
    expect(result.pageCoverage?.[0]).toMatchObject({
      attemptedOffsets: [0, 50],
      completedOffsets: [0, 50],
      totalMatching: 120,
      complete: false,
      truncated: true,
      stopReason: 'advisory-cap',
    });
    expect(result.truncated).toEqual([{ name: 'linux-kernel', version: '6.1', shown: 70, total: 120 }]);
    expect(result.completed).toBe(0);
    expect(result.incomplete).toBe(1);
  });

  it('enforces the production page ceiling even when the batch requests more pages and advisories', async () => {
    const starts: (string | null)[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        const url = new URL(String(input));
        const start = Number(url.searchParams.get('startIndex') ?? 0);
        starts.push(url.searchParams.get('startIndex'));
        return new Response(JSON.stringify(payload(start, 50, 300)), { status: 200 });
      }),
    );

    const result = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
      maxPages: 999,
      maxAdvisories: 999_999,
    });

    expect(starts).toEqual([null, '50', '100', '150']);
    expect(result.components[0]?.advisories).toHaveLength(NVD_MAX_ADVISORIES);
    expect(result.pageCoverage?.[0]).toMatchObject({
      maxPages: NVD_MAX_PAGES,
      maxAdvisories: NVD_MAX_ADVISORIES,
      complete: false,
      truncated: true,
      stopReason: 'page-cap',
    });
    expect(result.incomplete).toBe(1);
  });

  it('keeps completed pages but marks a later-page failure as partial', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        calls += 1;
        return calls === 1
          ? new Response(JSON.stringify(payload(0, 50, 60)), { status: 200 })
          : new Response(null, { status: 503 });
      }),
    );

    const result = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
    });
    expect(result.components[0]?.advisories).toHaveLength(50);
    expect(result.pageCoverage?.[0]).toMatchObject({
      attemptedOffsets: [0, 50],
      completedOffsets: [0],
      totalMatching: 60,
      complete: false,
      truncated: true,
      stopReason: 'request-failed',
    });
    expect(result.truncated).toEqual([{ name: 'linux-kernel', version: '6.1', shown: 50, total: 60 }]);
  });

  it('does not call pages with changing NVD totals a complete set', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        const start = Number(new URL(String(input)).searchParams.get('startIndex') ?? 0);
        calls += 1;
        return new Response(JSON.stringify(payload(start, start === 0 ? 50 : 5, calls === 1 ? 55 : 56)), {
          status: 200,
        });
      }),
    );

    const result = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
    });

    expect(result.components[0]?.advisories).toHaveLength(55);
    expect(result.pageCoverage?.[0]).toMatchObject({
      attemptedOffsets: [0, 50],
      completedOffsets: [0, 50],
      totalMatching: 55,
      complete: false,
      truncated: null,
      stopReason: 'total-changed',
    });
    expect(result.completed).toBe(0);
    expect(result.incomplete).toBe(1);
  });

  it('reports a first-page failure as unknown, not as an empty CPE answer', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(null, { status: 503 })),
    );
    const result = await queryNvdBatch([{ name: 'dropbear', version: '2012.55' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
    });
    expect(result.components).toEqual([]);
    expect(result.uncheckedIdentities).toEqual([]);
    expect(result.truncated).toEqual([]);
    expect(result.pageCoverage?.[0]).toMatchObject({
      attemptedOffsets: [0],
      completedOffsets: [],
      totalMatching: null,
      complete: false,
      truncated: null,
      stopReason: 'request-failed',
    });
    expect(result.completed).toBe(0);
    expect(result.incomplete).toBe(1);
  });
});
