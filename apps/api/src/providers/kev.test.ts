import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ResearchConfig } from '../research/config.js';
import {
  KEV_NO_INPUT_REASON,
  type KevResult,
  collectCveIds,
  crossReferenceKev,
  fetchAndMatchKev,
  kevLogLine,
  parseKevCatalog,
} from './kev.js';

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

describe('fetchAndMatchKev with nothing to check', () => {
  const cfg: ResearchConfig = { allowlist: ['www.cisa.gov'], timeoutMs: 1000, hashLookup: false };

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('is not-checked with no freshness — there is no catalog behind the verdict', async () => {
    const r = await fetchAndMatchKev([], cfg);
    expect(r.checked).toBe(false);
    expect(r.matches).toEqual([]);
    expect(r.freshness).toBeNull();
    expect(r.reason).toBe(KEV_NO_INPUT_REASON);
  });

  /**
   * The distinction the whole result shape exists for: nothing to cross-reference is an UNASKED question, not a
   * count of zero. `notCheckedCode` carries it machine-readably so no caller has to pattern-match the prose, and
   * `inputCveCount: 0` is the denominator that makes the sentence checkable.
   */
  it('records the unasked question as `no-input`, distinct from a download that failed', async () => {
    const r = await fetchAndMatchKev([], cfg);
    expect(r.notCheckedCode).toBe('no-input');
    expect(r.inputCveCount).toBe(0);
    expect(r.catalogSize).toBe(0);
    expect(r.reason).toContain('not zero');
  });

  // Downloading a multi-megabyte catalogue to search it for nothing is a request nobody needed to make — and it
  // would also be the only way a `no-input` run could ever report a freshness, i.e. a verdict it does not have.
  it('does not request the catalogue at all', async () => {
    const fetchSpy = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    await fetchAndMatchKev([], cfg);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // A failed download is the OTHER not-checked outcome: the question WAS put (one CVE went in) and came back
  // unanswered. Same `checked: false`, opposite meaning — so the code, not the phrasing, separates them.
  it('a real input whose download fails is `fetch-failed`, and counts the input it had', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-kev-'));
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('nope', { status: 503 })),
    );
    const r = await fetchAndMatchKev(['CVE-2021-44228'], cfg, { dir });
    expect(r.checked).toBe(false);
    expect(r.notCheckedCode).toBe('fetch-failed');
    expect(r.inputCveCount).toBe(1);
    expect(r.reason).toContain('503');
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

describe('fetchAndMatchKev with CVEs to check', () => {
  const cfg: ResearchConfig = { allowlist: ['www.cisa.gov'], timeoutMs: 1000, hashLookup: false };

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // Unchanged behaviour, pinned: a non-empty input still downloads the catalogue and still reports the count.
  it('downloads the catalogue once and reports the matches against it', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-kev-'));
    const fetchSpy = vi.fn(async () => new Response(JSON.stringify(CATALOG), { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    const r = await fetchAndMatchKev(['CVE-2021-44228', 'CVE-2000-1234'], cfg, { dir });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(r.checked).toBe(true);
    expect(r.notCheckedCode).toBeUndefined();
    expect(r.inputCveCount).toBe(2);
    expect(r.catalogSize).toBe(2);
    expect(r.matches.map((m) => m.cveID)).toEqual(['CVE-2021-44228']);
    expect(r.freshness?.origin).toBe('network');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  // A searched catalogue that matched nothing IS a zero, and stays one — this is the case the `no-input` branch
  // must never be confused with.
  it('reports a genuine zero when the catalogue was searched and matched nothing', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-kev-'));
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify(CATALOG), { status: 200 })),
    );
    const r = await fetchAndMatchKev(['CVE-2000-1234'], cfg, { dir });
    expect(r.checked).toBe(true);
    expect(r.matches).toEqual([]);
    expect(r.inputCveCount).toBe(1);
    fs.rmSync(dir, { recursive: true, force: true });
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

  /**
   * The OSV listing is capped; its `cveIds` is not. Reading only the listing meant a component with more
   * advisories than the cap could drop a CVE that CISA lists as actively exploited, and the KEV verdict would
   * have read as "not known-exploited" on a question nobody asked.
   */
  it('reads the OSV answer’s complete CVE set, not just the advisories the listing kept', () => {
    const ids = collectCveIds(
      [{ advisories: [{ id: 'CVE-2021-44228', aliases: [] }], cveIds: ['CVE-2021-44228', 'CVE-2014-0160'] }],
      [],
    );
    expect(ids.sort()).toEqual(['CVE-2014-0160', 'CVE-2021-44228']);
  });

  it('falls back to the listing for a result stored before that set existed', () => {
    const ids = collectCveIds([{ advisories: [{ id: 'DSA-1', aliases: ['CVE-2020-1234'] }] }], []);
    expect(ids).toEqual(['CVE-2020-1234']);
  });

  it('reads the CVE a distro record names upstream — where OSV puts it, and where nothing looked before', () => {
    const ids = collectCveIds(
      [{ advisories: [{ id: 'DEBIAN-CVE-2016-2781', aliases: [], upstream: ['CVE-2016-2781'] }] }],
      [],
    );
    expect(ids).toEqual(['CVE-2016-2781']);
  });
});

/**
 * The run log is where the distinction reaches an operator. "not checked" for an input set that was empty reads
 * as a broken lookup; a count read off it would be worse still. Three outcomes, three sentences.
 */
describe('kevLogLine', () => {
  const base: KevResult = { checked: false, catalogSize: 0, matches: [], freshness: null };

  it('reports the count when the cross-reference actually ran', () => {
    const line = kevLogLine({ ...base, checked: true, catalogSize: 1300 }, 7);
    expect(line).toBe('KEV: 7 discovered CVEs cross-referenced → 0 known-exploited (catalog: 1300).');
  });

  it('says the question was not asked — and never prints a zero — when there was no input', () => {
    const line = kevLogLine({ ...base, reason: KEV_NO_INPUT_REASON, notCheckedCode: 'no-input', inputCveCount: 0 }, 0);
    expect(line).toContain('not asked');
    expect(line).toContain('not zero');
    expect(line).not.toContain('known-exploited (catalog');
  });

  it('keeps a failed download reading as a failure, with its reason', () => {
    const line = kevLogLine({ ...base, reason: 'KEV feed HTTP 503', notCheckedCode: 'fetch-failed' }, 4);
    expect(line).toBe('KEV: not checked (KEV feed HTTP 503).');
  });

  // A result persisted by an older build has no discriminator; the line it produced then is the line it produces
  // now, rather than a new claim read off a field that build never wrote.
  it('falls back to the old sentence for a result stored before the discriminator existed', () => {
    expect(kevLogLine({ ...base, reason: 'KEV feed returned no catalog' }, 2)).toBe(
      'KEV: not checked (KEV feed returned no catalog).',
    );
  });
});
