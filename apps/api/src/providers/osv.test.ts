import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import type { ResearchConfig } from '../research/config.js';
import {
  OSV_ADVISORY_CAP,
  buildOsvQuery,
  cvssV3BaseScore,
  describeOsvDrop,
  osvCacheKey,
  osvEcosystem,
  osvQueryEcosystem,
  osvSeverityScore,
  parseOsvAnswer,
  queryOsv,
  queryOsvBatch,
} from './osv.js';

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

describe('osvCacheKey', () => {
  it('is the question, so the same component asked twice is asked of OSV once', () => {
    expect(osvCacheKey('busybox', '1.01', 'Debian')).toBe(osvCacheKey('busybox', '1.01', 'Debian'));
    expect(osvCacheKey('busybox', '1.01', 'Debian')).toContain('busybox');
  });

  it('separates a different version, name or ecosystem — never reuses the answer to another question', () => {
    const key = osvCacheKey('busybox', '1.01', 'Debian');
    expect(osvCacheKey('busybox', '1.02', 'Debian')).not.toBe(key);
    expect(osvCacheKey('busybox', '1.01', 'Alpine')).not.toBe(key);
    expect(osvCacheKey('dropbear', '1.01', 'Debian')).not.toBe(key);
  });
});

describe('osvQueryEcosystem', () => {
  it('names the ecosystem a question would be asked under', () => {
    expect(osvQueryEcosystem({ version: '1.35.0', type: 'deb' })).toBe('Debian');
  });

  it('refuses a component with no version — /v1/query asks whether THIS version is affected', () => {
    expect(osvQueryEcosystem({ version: '', type: 'deb' })).toBeNull();
  });

  it('refuses a type with no ecosystem mapping', () => {
    expect(osvQueryEcosystem({ version: '1.0', type: 'binary' })).toBeNull();
  });
});

/**
 * The vectors are the ones OSV actually serves. Every published score asserted here is the value NVD prints for
 * the same string, so this checks the implementation against the specification rather than against itself.
 */
describe('cvssV3BaseScore', () => {
  it('scores a scope-changed vector — Log4Shell, published as 10.0', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
  });

  it('scores a network confidentiality-only vector — Heartbleed, published as 7.5', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')).toBe(7.5);
  });

  it('scores a high-complexity local availability vector at 2.5, rounding UP as CVSS 3.1 requires', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L')).toBe(2.5);
  });

  it('scores a 3.0 vector by the same equations', () => {
    expect(cvssV3BaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')).toBe(7.5);
  });

  it('is null for what it cannot read — a v4.0 vector, a v2 vector, a missing or unknown metric', () => {
    // v4.0 is scored, but not here: it is a different procedure (`cvssV4Score`), not a different set of weights.
    expect(cvssV3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
    expect(cvssV3BaseScore('AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeNull();
    expect(cvssV3BaseScore('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull();
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H')).toBeNull();
    expect(cvssV3BaseScore('9.8')).toBeNull();
  });

  it('is 0 for a vector with no impact, which is a score rather than a refusal to score', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')).toBe(0);
  });
});

describe('osvSeverityScore', () => {
  it('prefers the vector, which is what Debian and Alpine actually publish', () => {
    expect(osvSeverityScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
  });

  it('takes a bare numeric base score as given', () => {
    expect(osvSeverityScore('9.8')).toBe(9.8);
  });

  it('places a named level at the floor of its band, so it cannot outrank a measured score in that band', () => {
    expect(osvSeverityScore('HIGH')).toBe(7);
    expect(osvSeverityScore('moderate')).toBe(osvSeverityScore('MEDIUM'));
    expect(osvSeverityScore('CRITICAL') as number).toBeGreaterThan(osvSeverityScore('HIGH') as number);
    expect(osvSeverityScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N') as number).toBeGreaterThan(
      osvSeverityScore('HIGH') as number,
    );
  });

  it('grades a CVSS v4.0 vector, which OSV publishes for the newer advisories', () => {
    expect(osvSeverityScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBe(9.3);
    expect(osvSeverityScore(' CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N ')).toBe(8.5);
  });

  it('refuses to grade what it cannot read, rather than calling it zero', () => {
    expect(osvSeverityScore(null)).toBeNull();
    expect(osvSeverityScore('')).toBeNull();
    expect(osvSeverityScore('   ')).toBeNull();
    // A v4.0 vector truncated to its base impacts is not a v4.0 vector, and guessing the missing SC/SI/SA would
    // be inventing the part of the answer that was not published.
    expect(osvSeverityScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H')).toBeNull();
    // A v2 vector, and a version newer than anything implemented here.
    expect(osvSeverityScore('AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBeNull();
    expect(osvSeverityScore('CVSS:5.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
    expect(osvSeverityScore('11')).toBeNull();
  });
});

describe('parseOsvAnswer', () => {
  it('extracts id, aliases, summary, severity and references', () => {
    const { advisories } = parseOsvAnswer({
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
    expect(advisories).toHaveLength(1);
    expect(advisories[0]?.id).toBe('DSA-1234');
    expect(advisories[0]?.aliases).toEqual(['CVE-2023-1111']);
    expect(advisories[0]?.severity).toBe('HIGH');
    expect(advisories[0]?.references).toEqual(['https://example.org/adv']);
  });

  it('falls back to CVSS score for severity and details for summary', () => {
    const { advisories } = parseOsvAnswer({
      vulns: [{ id: 'X', details: 'long details', severity: [{ type: 'CVSS_V3', score: '9.8' }] }],
    });
    expect(advisories[0]?.severity).toBe('9.8');
    expect(advisories[0]?.summary).toBe('long details');
  });

  it('an empty/absent vulns list is no advisories, never an error', () => {
    expect(parseOsvAnswer({})).toEqual({ advisories: [], totalMatching: 0, cveIds: [] });
    expect(parseOsvAnswer({ vulns: [] })).toEqual({ advisories: [], totalMatching: 0, cveIds: [] });
  });

  it("ranks by severity BEFORE the cap, so the listing is not OSV's response order", () => {
    const vulns = [
      ...Array.from({ length: OSV_ADVISORY_CAP }, (_, i) => ({
        id: `OSV-LOW-${i}`,
        database_specific: { severity: 'LOW' },
      })),
      { id: 'CVE-2021-44228', database_specific: { severity: 'CRITICAL' } },
    ];
    const { advisories } = parseOsvAnswer({ vulns });
    expect(advisories).toHaveLength(OSV_ADVISORY_CAP);
    expect(advisories[0]?.id).toBe('CVE-2021-44228');
  });

  it('keeps OSV order inside a tier, so re-asking the same question does not reshuffle the table', () => {
    const { advisories } = parseOsvAnswer({
      vulns: [
        { id: 'A', database_specific: { severity: 'HIGH' } },
        { id: 'B', database_specific: { severity: 'HIGH' } },
        { id: 'C', database_specific: { severity: 'HIGH' } },
      ],
    });
    expect(advisories.map((a) => a.id)).toEqual(['A', 'B', 'C']);
  });

  it('counts every advisory the answer held, so a capped listing carries its own denominator', () => {
    const vulns = Array.from({ length: OSV_ADVISORY_CAP + 7 }, (_, i) => ({ id: `OSV-${i}` }));
    const answer = parseOsvAnswer({ vulns });
    expect(answer.advisories).toHaveLength(OSV_ADVISORY_CAP);
    expect(answer.totalMatching).toBe(OSV_ADVISORY_CAP + 7);
  });

  /**
   * The defect this file's cap used to carry: `kev.ts` builds the known-exploited cross-reference out of these
   * identifiers, so cutting them with the LISTING would have decided, silently, that a CVE CISA lists as actively
   * exploited is not in the firmware. The listing may be a prefix; this set may not.
   */
  it('keeps every CVE in the answer, including the advisories the listing cut', () => {
    const vulns = [
      ...Array.from({ length: OSV_ADVISORY_CAP }, (_, i) => ({
        id: `OSV-${i}`,
        database_specific: { severity: 'CRITICAL' },
      })),
      { id: 'GHSA-cut', aliases: ['CVE-2014-0160'], database_specific: { severity: 'LOW' } },
    ];
    const answer = parseOsvAnswer({ vulns });
    expect(answer.advisories.map((a) => a.id)).not.toContain('GHSA-cut');
    expect(answer.cveIds).toContain('CVE-2014-0160');
  });

  /**
   * The rule the real corpus forced. Measured over the answers this deployment has cached: 117 of 121 graded
   * advisories state severity ONLY as a CVSS v3 vector and 4 only as a v4.0 one. The v4.0 four are now scored and
   * compete on their number like any other; what the rule protects is whatever the NEXT unreadable shape turns
   * out to be, because cutting it in favour of a graded LOW would be the bound deciding a question it could not
   * read.
   */
  it('never cuts an advisory it could not grade in favour of one it graded low', () => {
    const vulns = [
      ...Array.from({ length: OSV_ADVISORY_CAP }, (_, i) => ({
        id: `OSV-LOW-${i}`,
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L' }],
      })),
      { id: 'OSV-V2', severity: [{ type: 'CVSS_V2', score: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' }] },
      { id: 'OSV-UNGRADED' },
    ];
    const { advisories } = parseOsvAnswer({ vulns });
    expect(advisories).toHaveLength(OSV_ADVISORY_CAP);
    const ids = advisories.map((a) => a.id);
    // Kept — and shown last, so the reader's first badges stay the severities that are known.
    expect(ids.slice(-2)).toEqual(['OSV-V2', 'OSV-UNGRADED']);
  });

  /**
   * A v4.0 advisory used to be unrankable, so it sat with the ungraded ones at the end of the listing no matter
   * how severe it was — a 9.3 shown below a 5.4. It now ranks on its score, against v3-graded neighbours.
   */
  it('ranks a v4.0-graded advisory against v3-graded ones by the score each states', () => {
    const { advisories } = parseOsvAnswer({
      vulns: [
        { id: 'v3-medium', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N' }] },
        {
          id: 'v4-critical',
          severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }],
        },
        { id: 'v3-high', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }] },
        { id: 'ungraded' },
      ],
    });
    expect(advisories.map((a) => a.id)).toEqual(['v4-critical', 'v3-high', 'v3-medium', 'ungraded']);
  });

  it('orders a real mix of vectors by the score they state', () => {
    const { advisories } = parseOsvAnswer({
      vulns: [
        { id: 'medium', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N' }] },
        { id: 'critical', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' }] },
        { id: 'high', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }] },
      ],
    });
    expect(advisories.map((a) => a.id)).toEqual(['critical', 'high', 'medium']);
  });

  it('collects CVEs from the id as well as the aliases, deduped and upper-cased', () => {
    const answer = parseOsvAnswer({
      vulns: [
        { id: 'CVE-2023-1111', aliases: ['GHSA-xxxx', 'cve-2023-1111'] },
        { id: 'RUSTSEC-2021-1', aliases: ['CVE-2021-2222'] },
      ],
    });
    expect(answer.cveIds.sort()).toEqual(['CVE-2021-2222', 'CVE-2023-1111']);
  });

  /**
   * The shape OSV actually serves for a firmware rootfs, and the reason this reads `upstream`: of the 133
   * advisories this deployment has cached, NOT ONE carries an alias and NOT ONE has a bare CVE as its id — so a
   * collector reading only ids and aliases returned zero CVEs, and the KEV cross-reference built from them had
   * never seen an OSV-discovered CVE at all.
   */
  it('reads the CVE a distro record names upstream, which is the only place it appears', () => {
    const answer = parseOsvAnswer({
      vulns: [{ id: 'DEBIAN-CVE-2016-2781', upstream: ['CVE-2016-2781'], details: 'chroot escape' }],
    });
    expect(answer.cveIds).toEqual(['CVE-2016-2781']);
    expect(answer.advisories[0]?.upstream).toEqual(['CVE-2016-2781']);
    expect(answer.advisories[0]?.aliases).toEqual([]);
  });

  it('tolerates a non-array aliases/upstream rather than throwing on a malformed record', () => {
    const answer = parseOsvAnswer({ vulns: [{ id: 'X', aliases: 'CVE-2020-1', upstream: 7 }] });
    expect(answer.advisories[0]?.aliases).toEqual([]);
    expect(answer.advisories[0]?.upstream).toEqual([]);
    expect(answer.cveIds).toEqual([]);
  });
});

describe('describeOsvDrop', () => {
  it('says nothing when the cap dropped nothing', () => {
    expect(describeOsvDrop(0, 80)).toBe('');
  });

  it('names the count, the cap and the rule — arrival order, stated rather than hidden', () => {
    const rule = describeOsvDrop(12, 80);
    expect(rule).toContain('12');
    expect(rule).toContain('80');
    expect(rule).toMatch(/order the SBOM lists them/);
  });
});

/**
 * The wiring, exercised end to end with a stubbed global fetch — no socket is ever opened, and a second call that
 * reached the stub would fail the test. This is the part unit-testing the pure pieces cannot cover: that the
 * provider actually READS the cache before asking, WRITES what it got, and refuses to store a failure.
 */
describe('queryOsv reads through the cache', () => {
  const HOUR = 60 * 60 * 1000;
  const T0 = 1_700_000_000_000;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-osv-cache-'));
  const cfg: ResearchConfig = { allowlist: ['api.osv.dev'], timeoutMs: 1000, hashLookup: false };
  afterAll(() => {
    vi.unstubAllGlobals();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('asks OSV once, then answers the same question from disk with the age of the answer', async () => {
    let calls = 0;
    vi.stubGlobal('fetch', async () => {
      calls += 1;
      return new Response(
        JSON.stringify({ vulns: [{ id: 'CVE-2021-44228', database_specific: { severity: 'HIGH' } }] }),
      );
    });
    const component = { name: 'log4j-core', version: '2.14.1', type: 'java-archive' };

    const first = await queryOsv(component, cfg, { dir, ttlMs: 24 * HOUR, now: T0 });
    expect(calls).toBe(1);
    expect(first.advisories[0]?.id).toBe('CVE-2021-44228');
    expect(first.freshness).toEqual({ origin: 'network', fetchedAt: new Date(T0).toISOString(), ageMs: 0 });

    const second = await queryOsv(component, cfg, { dir, ttlMs: 24 * HOUR, now: T0 + 2 * HOUR });
    expect(calls).toBe(1);
    expect(second.advisories[0]?.severity).toBe('HIGH');
    expect(second.freshness).toEqual({ origin: 'cache', fetchedAt: new Date(T0).toISOString(), ageMs: 2 * HOUR });
  });

  it('re-asks past the TTL instead of serving an advisory list that may have moved on', async () => {
    let calls = 0;
    vi.stubGlobal('fetch', async () => {
      calls += 1;
      return new Response(JSON.stringify({ vulns: [{ id: `OSV-${calls}` }] }));
    });
    const component = { name: 'busybox', version: '1.01', type: 'deb' };
    await queryOsv(component, cfg, { dir, ttlMs: HOUR, now: T0 });
    const later = await queryOsv(component, cfg, { dir, ttlMs: HOUR, now: T0 + 50 * HOUR });
    expect(calls).toBe(2);
    expect(later.advisories[0]?.id).toBe('OSV-2');
    expect(later.freshness?.origin).toBe('network');
  });

  it('does not cache an HTTP error — a bad afternoon at OSV must not become a durable "no advisories"', async () => {
    let calls = 0;
    vi.stubGlobal('fetch', async () => {
      calls += 1;
      return new Response('nope', { status: 503 });
    });
    const component = { name: 'dropbear', version: '2012.55', type: 'deb' };
    const failed = await queryOsv(component, cfg, { dir, now: T0 });
    expect(failed.queryable).toBe(true);
    expect(failed.advisories).toEqual([]);
    expect(failed.freshness).toBeNull();
    await queryOsv(component, cfg, { dir, now: T0 });
    expect(calls).toBe(2);
  });

  it('never touches the network or the cache for a component OSV cannot map', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new Error('an unmapped component must not reach the network');
    });
    const r = await queryOsv({ name: 'vendor-httpd', version: '1.0', type: 'binary' }, cfg, { dir, now: T0 });
    expect(r.queryable).toBe(false);
    expect(r.freshness).toBeNull();
  });
});

/**
 * The batch's budget, exercised over a shape a real rootfs produces: an SBOM whose alphabetically-early entries
 * are unmappable (syft catalogues ~2,000 of them on an OpenWRT image) and whose answerable components sit behind
 * them. The cap used to be taken over the whole list, so those slots were spent on components that never reached
 * the network and the answerable ones were never asked.
 */
describe('queryOsvBatch spends its budget on questions OSV can answer', () => {
  const T0 = 1_700_000_000_000;
  const cfg: ResearchConfig = { allowlist: ['api.osv.dev'], timeoutMs: 1000, hashLookup: false };
  const dirs: string[] = [];
  const freshDir = (): string => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-osv-batch-'));
    dirs.push(d);
    return d;
  };
  afterAll(() => {
    vi.unstubAllGlobals();
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  });

  const kernelModules = Array.from({ length: 5 }, (_, i) => ({ name: `act_${i}`, version: '', type: 'binary' }));
  const answerable = [
    { name: 'busybox', version: '1.01', type: 'deb' },
    { name: 'dnsmasq', version: '2.78', type: 'deb' },
  ];

  it('does not let unmappable components consume the query cap, and counts every one of them as skipped', async () => {
    const asked: string[] = [];
    vi.stubGlobal('fetch', async (_url: string, init: { body: string }) => {
      asked.push(JSON.parse(init.body).package.name);
      return new Response(JSON.stringify({ vulns: [] }));
    });
    const batch = await queryOsvBatch([...kernelModules, ...answerable], cfg, 2, { dir: freshDir(), now: T0 });
    expect(asked.sort()).toEqual(['busybox', 'dnsmasq']);
    expect(batch.queried).toBe(2);
    expect(batch.skipped).toBe(kernelModules.length);
    expect(batch.notQueried).toBe(0);
    expect(batch.notQueriedRule).toBe('');
  });

  it('reports the answerable components the cap DID drop, and by what rule', async () => {
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ vulns: [] })));
    const batch = await queryOsvBatch([...answerable, ...kernelModules], cfg, 1, { dir: freshDir(), now: T0 });
    expect(batch.queried).toBe(1);
    expect(batch.notQueried).toBe(1);
    expect(batch.notQueriedRule).toContain('1 ecosystem-mapped component(s) went unqueried');
    expect(batch.skipped).toBe(kernelModules.length);
  });

  it('states where a component listing is a prefix of OSV’s answer, with both numbers', async () => {
    const vulns = Array.from({ length: OSV_ADVISORY_CAP + 3 }, (_, i) => ({ id: `OSV-${i}` }));
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ vulns })));
    const batch = await queryOsvBatch([answerable[0] as (typeof answerable)[number]], cfg, 80, {
      dir: freshDir(),
      now: T0,
    });
    expect(batch.totalAdvisories).toBe(OSV_ADVISORY_CAP);
    expect(batch.truncated).toEqual([
      { name: 'busybox', version: '1.01', shown: OSV_ADVISORY_CAP, total: OSV_ADVISORY_CAP + 3 },
    ]);
  });

  it('reports no truncation when the whole answer fits, and nothing at all when the request failed', async () => {
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ vulns: [{ id: 'CVE-2023-1111' }] })));
    const ok = await queryOsvBatch(answerable, cfg, 80, { dir: freshDir(), now: T0 });
    expect(ok.truncated).toEqual([]);
    expect(ok.components[0]?.totalMatching).toBe(1);

    vi.stubGlobal('fetch', async () => new Response('nope', { status: 503 }));
    const failed = await queryOsvBatch(answerable, cfg, 80, { dir: freshDir(), now: T0 });
    expect(failed.queried).toBe(2);
    expect(failed.withAdvisories).toBe(0);
    expect(failed.truncated).toEqual([]);
  });
});
