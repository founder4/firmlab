import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  CACHE_SCHEMA_VERSION,
  type CacheEntryStat,
  type Freshness,
  buildEnvelope,
  cacheEntryPath,
  cachedFetch,
  cachedFreshness,
  classifyAge,
  liveFreshness,
  parseEnvelope,
  planCacheEviction,
  readCache,
  resolveCacheLimits,
  resolveTtlMs,
  scanCacheEntries,
  serializeEnvelope,
  summarizeFreshness,
  sweepResearchCache,
  writeCache,
} from './cache.js';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

describe('resolveTtlMs', () => {
  it('defaults to 24 hours', () => {
    expect(resolveTtlMs({})).toBe(24 * HOUR);
    expect(resolveTtlMs({ FIRMLAB_RESEARCH_CACHE_TTL_HOURS: '  ' })).toBe(24 * HOUR);
  });

  it('honours the configured hours, including fractions', () => {
    expect(resolveTtlMs({ FIRMLAB_RESEARCH_CACHE_TTL_HOURS: '1' })).toBe(HOUR);
    expect(resolveTtlMs({ FIRMLAB_RESEARCH_CACHE_TTL_HOURS: '0.5' })).toBe(HOUR / 2);
  });

  it('reads 0 as "never serve from cache" — the documented way to force live lookups', () => {
    expect(resolveTtlMs({ FIRMLAB_RESEARCH_CACHE_TTL_HOURS: '0' })).toBe(0);
    expect(classifyAge(1000, 0, 1000).fresh).toBe(false);
  });

  it('falls back to the default for anything unusable, rather than to "fresh forever"', () => {
    expect(resolveTtlMs({ FIRMLAB_RESEARCH_CACHE_TTL_HOURS: 'soon' })).toBe(24 * HOUR);
    expect(resolveTtlMs({ FIRMLAB_RESEARCH_CACHE_TTL_HOURS: '-3' })).toBe(24 * HOUR);
  });
});

describe('cacheEntryPath', () => {
  it('is deterministic per source+key and namespaces by source', () => {
    const a = cacheEntryPath('/c', 'osv', 'busybox@1.01');
    expect(cacheEntryPath('/c', 'osv', 'busybox@1.01')).toBe(a);
    expect(path.dirname(a)).toBe(path.join('/c', 'osv'));
    expect(cacheEntryPath('/c', 'nvd', 'busybox@1.01')).not.toBe(a);
    expect(cacheEntryPath('/c', 'osv', 'busybox@1.02')).not.toBe(a);
  });

  it('never lets a key become a path — a URL or a traversal hashes like anything else', () => {
    const p = cacheEntryPath('/c', 'nvd', 'https://services.nvd.nist.gov/x?keywordSearch=../../etc/passwd');
    expect(path.resolve(p).startsWith(path.resolve('/c'))).toBe(true);
    expect(p).not.toContain('..');
    expect(path.basename(p)).toMatch(/^[0-9a-f]{32}\.json$/);
  });
});

describe('the envelope round-trips, and refuses what it cannot trust', () => {
  it('carries the raw payload plus when it came off the wire', () => {
    const entry = buildEnvelope('osv', 'busybox@1.01', { vulns: [{ id: 'X' }] }, 1_700_000_000_000);
    const read = parseEnvelope(serializeEnvelope(entry));
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    expect(read.entry.fetchedAt).toBe(1_700_000_000_000);
    expect(read.entry.key).toBe('busybox@1.01');
    expect(read.entry.payload).toEqual({ vulns: [{ id: 'X' }] });
  });

  it('rejects a corrupt, wrong-schema or timestampless entry, each with its own reason', () => {
    expect(parseEnvelope('{oops')).toEqual({ ok: false, reason: 'cache entry is not JSON' });
    expect(parseEnvelope('null').ok).toBe(false);
    const wrongSchema = parseEnvelope(JSON.stringify({ version: 99, fetchedAt: 1, payload: {} }));
    expect(wrongSchema.ok).toBe(false);
    if (!wrongSchema.ok) expect(wrongSchema.reason).toContain(`v${CACHE_SCHEMA_VERSION}`);
    const noStamp = parseEnvelope(JSON.stringify({ version: CACHE_SCHEMA_VERSION, payload: {} }));
    expect(noStamp.ok).toBe(false);
    if (!noStamp.ok) expect(noStamp.reason).toContain('fetchedAt');
  });
});

describe('classifyAge — the staleness decision', () => {
  it('is fresh inside the TTL and stale outside it', () => {
    expect(classifyAge(1000, 500, 1200)).toEqual({ fresh: true, ageMs: 200 });
    expect(classifyAge(1000, 500, 1500)).toEqual({ fresh: false, ageMs: 500 });
    expect(classifyAge(1000, 500, 90_000)).toEqual({ fresh: false, ageMs: 89_000 });
  });

  it('refuses an entry stamped in the future — an age we cannot state is not one we may serve', () => {
    expect(classifyAge(5000, 24 * HOUR, 1000)).toEqual({ fresh: false, ageMs: 0 });
  });
});

describe('summarizeFreshness', () => {
  it('counts what left the machine and how old the oldest served answer was', () => {
    const items: (Freshness | null)[] = [
      cachedFreshness(0, 30_000),
      cachedFreshness(0, 90_000),
      liveFreshness(1000),
      null,
    ];
    expect(summarizeFreshness(items)).toEqual({ hits: 2, misses: 1, oldestAgeMs: 90_000 });
  });

  it('reports no age when nothing came from the cache', () => {
    expect(summarizeFreshness([liveFreshness(1000)])).toEqual({ hits: 0, misses: 1, oldestAgeMs: 0 });
    expect(summarizeFreshness([])).toEqual({ hits: 0, misses: 0, oldestAgeMs: 0 });
  });
});

describe('read/write against a real directory', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-cache-'));
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('serves what it stored, with the ORIGINAL fetch time and the age at serving', () => {
    const t0 = 1_700_000_000_000;
    expect(writeCache('osv', 'k1', { vulns: [] }, { dir, now: t0 }).written).toBe(true);
    const hit = readCache('osv', 'k1', { dir, ttlMs: 24 * HOUR, now: t0 + 3 * HOUR });
    expect(hit.status).toBe('fresh');
    if (hit.status === 'miss') return;
    expect(hit.entry.fetchedAt).toBe(t0);
    expect(hit.ageMs).toBe(3 * HOUR);
  });

  it('reports an expired entry as stale — and still hands it over, so its age can be stated', () => {
    const t0 = 1_700_000_000_000;
    writeCache('osv', 'k2', { vulns: [{ id: 'OLD' }] }, { dir, now: t0 });
    const lookup = readCache('osv', 'k2', { dir, ttlMs: HOUR, now: t0 + 40 * HOUR });
    expect(lookup.status).toBe('stale');
    if (lookup.status === 'miss') return;
    expect(lookup.ageMs).toBe(40 * HOUR);
    expect(lookup.entry.payload).toEqual({ vulns: [{ id: 'OLD' }] });
  });

  it('an absent or corrupt entry is a miss that says why, never a throw', () => {
    expect(readCache('osv', 'never-asked', { dir })).toEqual({ status: 'miss', reason: 'not cached' });
    const file = cacheEntryPath(dir, 'osv', 'k3');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, '{"version":1,"fetch');
    expect(readCache('osv', 'k3', { dir })).toEqual({ status: 'miss', reason: 'cache entry is not JSON' });
  });

  it('leaves no temp file behind', () => {
    expect(fs.readdirSync(path.join(dir, 'osv')).filter((f) => f.endsWith('.tmp'))).toEqual([]);
  });
});

describe('honest degradation when the cache directory is unwritable', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-cache-ro-'));
  // A FILE where the cache root should be: mkdir fails, exactly as it would on a read-only data root.
  const dir = path.join(base, 'not-a-dir');
  fs.writeFileSync(dir, 'x');
  afterAll(() => fs.rmSync(base, { recursive: true, force: true }));

  it('reports the failure instead of pretending it cached', () => {
    const w = writeCache('osv', 'k', { vulns: [] }, { dir });
    expect(w.written).toBe(false);
    if (w.written) return;
    expect(w.reason.length).toBeGreaterThan(0);
  });

  it('still returns the answer — a broken cache slows a lookup down, it does not break it', async () => {
    const answer = await cachedFetch('osv', 'k', async () => ({ vulns: [] }), { dir });
    expect(answer.payload).toEqual({ vulns: [] });
    expect(answer.freshness?.origin).toBe('network');
    expect(answer.stored).toBe(false);
  });
});

describe('cachedFetch', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-cachedfetch-'));
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));
  const t0 = 1_700_000_000_000;

  it('asks the service once, then serves from disk with the age of the answer', async () => {
    let calls = 0;
    const fetcher = async (): Promise<unknown> => {
      calls += 1;
      return { vulns: [{ id: 'CVE-2021-44228' }] };
    };
    const first = await cachedFetch('osv', 'log4j@2.14', fetcher, { dir, ttlMs: 24 * HOUR, now: t0 });
    expect(calls).toBe(1);
    expect(first.freshness).toEqual({ origin: 'network', fetchedAt: new Date(t0).toISOString(), ageMs: 0 });
    expect(first.stored).toBe(true);

    const second = await cachedFetch('osv', 'log4j@2.14', fetcher, { dir, ttlMs: 24 * HOUR, now: t0 + 2 * HOUR });
    expect(calls).toBe(1);
    expect(second.payload).toEqual({ vulns: [{ id: 'CVE-2021-44228' }] });
    expect(second.freshness).toEqual({
      origin: 'cache',
      fetchedAt: new Date(t0).toISOString(),
      ageMs: 2 * HOUR,
    });
  });

  it('re-queries past the TTL instead of serving the stale answer', async () => {
    let calls = 0;
    const fetcher = async (): Promise<unknown> => {
      calls += 1;
      return { vulns: [{ id: `call-${calls}` }] };
    };
    await cachedFetch('nvd', 'busybox@1.01', fetcher, { dir, ttlMs: HOUR, now: t0 });
    const later = await cachedFetch('nvd', 'busybox@1.01', fetcher, { dir, ttlMs: HOUR, now: t0 + 50 * HOUR });
    expect(calls).toBe(2);
    expect(later.payload).toEqual({ vulns: [{ id: 'call-2' }] });
    expect(later.freshness?.origin).toBe('network');
    expect(later.freshness?.fetchedAt).toBe(new Date(t0 + 50 * HOUR).toISOString());
  });

  it('never stores a failure as if the service had answered it', async () => {
    let calls = 0;
    const failing = async (): Promise<unknown> => {
      calls += 1;
      return null;
    };
    const first = await cachedFetch('kev', 'catalog', failing, { dir, now: t0 });
    expect(first).toEqual({ payload: null, freshness: null, stored: false });
    await cachedFetch('kev', 'catalog', failing, { dir, now: t0 });
    expect(calls).toBe(2);
    expect(readCache('kev', 'catalog', { dir, now: t0 }).status).toBe('miss');
  });
});

describe('resolveCacheLimits — off unless asked for', () => {
  it('is off by default, so the reproducibility record survives an unconfigured deployment', () => {
    expect(resolveCacheLimits({})).toEqual({ maxBytes: 0, maxAgeDays: 0 });
    expect(resolveCacheLimits({ FIRMLAB_MAX_RESEARCH_CACHE_BYTES: '  ' })).toEqual({ maxBytes: 0, maxAgeDays: 0 });
  });

  it('reads each cap independently', () => {
    expect(resolveCacheLimits({ FIRMLAB_MAX_RESEARCH_CACHE_BYTES: '1048576' })).toEqual({
      maxBytes: 1_048_576,
      maxAgeDays: 0,
    });
    expect(resolveCacheLimits({ FIRMLAB_MAX_RESEARCH_CACHE_AGE_DAYS: '30' })).toEqual({
      maxBytes: 0,
      maxAgeDays: 30,
    });
  });

  it('turns a malformed cap OFF rather than guessing one — a wrong threshold here deletes the record', () => {
    expect(resolveCacheLimits({ FIRMLAB_MAX_RESEARCH_CACHE_BYTES: 'lots' }).maxBytes).toBe(0);
    expect(resolveCacheLimits({ FIRMLAB_MAX_RESEARCH_CACHE_AGE_DAYS: '-7' }).maxAgeDays).toBe(0);
    expect(resolveCacheLimits({ FIRMLAB_MAX_RESEARCH_CACHE_BYTES: 'Infinity' }).maxBytes).toBe(0);
  });
});

describe('planCacheEviction — the eviction decision', () => {
  const NOW = 1_700_000_000_000;
  /** Four entries of 100B each, one day apart; `a` is the oldest. */
  const four: CacheEntryStat[] = [
    { path: '/c/osv/a.json', bytes: 100, writtenAt: NOW - 4 * DAY },
    { path: '/c/osv/b.json', bytes: 100, writtenAt: NOW - 3 * DAY },
    { path: '/c/nvd/c.json', bytes: 100, writtenAt: NOW - 2 * DAY },
    { path: '/c/kev/d.json', bytes: 100, writtenAt: NOW - 1 * DAY },
  ];

  it('evicts nothing with both caps off — the default, and the documented one', () => {
    const plan = planCacheEviction(four, { maxBytes: 0, maxAgeDays: 0 }, NOW);
    expect(plan.evictions).toEqual([]);
    expect(plan.evictedBytes).toBe(0);
    expect(plan.totalBytes).toBe(400);
    expect(plan.remainingBytes).toBe(400);
    expect(plan.report).toContain('no eviction configured');
    expect(plan.report).toContain('FIRMLAB_MAX_RESEARCH_CACHE_BYTES');
  });

  it('evicts nothing when the cache is under the size cap', () => {
    const plan = planCacheEviction(four, { maxBytes: 400, maxAgeDays: 0 }, NOW);
    expect(plan.evictions).toEqual([]);
    expect(plan.report).toContain('within the 400B cap');
    expect(plan.report).toContain('nothing evicted');
  });

  it('evicts oldest-first down to the cap, and no further', () => {
    const plan = planCacheEviction(four, { maxBytes: 250, maxAgeDays: 0 }, NOW);
    expect(plan.evictions.map((e) => e.path)).toEqual(['/c/osv/a.json', '/c/osv/b.json']);
    expect(plan.evictions.every((e) => e.rule === 'size')).toBe(true);
    expect(plan.evictedBytes).toBe(200);
    expect(plan.remainingBytes).toBe(200);
    expect(plan.remainingCount).toBe(2);
  });

  it('orders by write time then path, so the set is never an artifact of directory order', () => {
    const shuffled = [four[2], four[0], four[3], four[1]] as CacheEntryStat[];
    const plan = planCacheEviction(shuffled, { maxBytes: 150, maxAgeDays: 0 }, NOW);
    expect(plan.evictions.map((e) => e.path)).toEqual(['/c/osv/a.json', '/c/osv/b.json', '/c/nvd/c.json']);

    const sameInstant: CacheEntryStat[] = [
      { path: '/c/osv/z.json', bytes: 100, writtenAt: NOW },
      { path: '/c/osv/y.json', bytes: 100, writtenAt: NOW },
    ];
    const tie = planCacheEviction(sameInstant, { maxBytes: 100, maxAgeDays: 0 }, NOW);
    expect(tie.evictions.map((e) => e.path)).toEqual(['/c/osv/y.json']);
    expect(planCacheEviction([...sameInstant].reverse(), { maxBytes: 100, maxAgeDays: 0 }, NOW).evictions).toEqual(
      tie.evictions,
    );
  });

  it('removes only what is older than the age cap, and touches nothing else', () => {
    const plan = planCacheEviction(four, { maxBytes: 0, maxAgeDays: 3 }, NOW);
    expect(plan.evictions.map((e) => e.path)).toEqual(['/c/osv/a.json']);
    expect(plan.evictions[0]?.rule).toBe('age');
    expect(plan.evictions[0]?.ageMs).toBe(4 * DAY);
    expect(plan.remainingCount).toBe(3);
  });

  it('never age-evicts an entry stamped in the future — an age we cannot state is not a decision', () => {
    const future: CacheEntryStat[] = [{ path: '/c/osv/f.json', bytes: 100, writtenAt: NOW + 5 * DAY }];
    expect(planCacheEviction(future, { maxBytes: 0, maxAgeDays: 1 }, NOW).evictions).toEqual([]);
    // ...but it is still size-evictable: that rule asks how big it is, not how old.
    const sized = planCacheEviction(future, { maxBytes: 10, maxAgeDays: 1 }, NOW);
    expect(sized.evictions.map((e) => e.rule)).toEqual(['size']);
    expect(sized.evictions[0]?.ageMs).toBe(0);
  });

  it('names what it dropped and under which rule, counting each separately', () => {
    const plan = planCacheEviction(four, { maxBytes: 150, maxAgeDays: 3 }, NOW);
    expect(plan.evictions.map((e) => [e.path, e.rule])).toEqual([
      ['/c/osv/a.json', 'age'],
      ['/c/osv/b.json', 'size'],
      ['/c/nvd/c.json', 'size'],
    ]);
    expect(plan.report).toBe(
      'research cache: evicted 3 of 4 entries (300B) — 1 older than 3d, 2 oldest-first over the 150B cap; ' +
        '1 entry (100B) kept',
    );
  });

  it('handles an empty cache without inventing a total', () => {
    const plan = planCacheEviction([], { maxBytes: 10, maxAgeDays: 1 }, NOW);
    expect(plan).toMatchObject({ entryCount: 0, totalBytes: 0, evictedBytes: 0, remainingBytes: 0 });
    expect(plan.report).toContain('0 entries, 0B');
  });
});

describe('sweepResearchCache against a real directory', () => {
  const roots: string[] = [];
  const makeCache = (): string => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-cache-sweep-'));
    roots.push(dir);
    return dir;
  };
  afterAll(() => {
    for (const r of roots) fs.rmSync(r, { recursive: true, force: true });
  });

  const NOW = 1_700_000_000_000;
  /** Write one real entry and back-date it, so the sweep sees the ages we mean it to see. */
  const seed = (dir: string, source: string, key: string, ageDays: number): string => {
    const w = writeCache(source, key, { vulns: [{ id: key }] }, { dir, now: NOW - ageDays * DAY });
    if (!w.written) throw new Error(w.reason);
    const when = new Date(NOW - ageDays * DAY);
    fs.utimesSync(w.path, when, when);
    return w.path;
  };

  it('is a no-op on a missing cache directory — the sweep runs on every upload', () => {
    const missing = path.join(makeCache(), 'never-created');
    const result = sweepResearchCache({ dir: missing, limits: { maxBytes: 1, maxAgeDays: 1 }, now: NOW });
    expect(result.entryCount).toBe(0);
    expect(result.removed).toEqual([]);
    expect(result.failed).toEqual([]);
    expect(result.truncated).toBe(false);
  });

  it('deletes nothing, and logs nothing, with both caps unset', () => {
    const dir = makeCache();
    const kept = seed(dir, 'osv', 'k-old', 400);
    const lines: string[] = [];
    const result = sweepResearchCache({
      dir,
      limits: { maxBytes: 0, maxAgeDays: 0 },
      now: NOW,
      log: (l) => lines.push(l),
    });
    expect(result.removed).toEqual([]);
    expect(result.entryCount).toBe(1);
    expect(result.totalBytes).toBeGreaterThan(0);
    expect(lines).toEqual([]);
    expect(fs.existsSync(kept)).toBe(true);
  });

  it('really removes the files the plan selected, oldest-first, and says so', () => {
    const dir = makeCache();
    const oldest = seed(dir, 'osv', 'a', 4);
    const middle = seed(dir, 'nvd', 'b', 3);
    const newest = seed(dir, 'kev', 'c', 1);
    const each = fs.statSync(newest).size;
    const lines: string[] = [];
    const result = sweepResearchCache({
      dir,
      limits: { maxBytes: 2 * each, maxAgeDays: 0 },
      now: NOW,
      log: (l) => lines.push(l),
    });
    expect(result.removed).toEqual([oldest]);
    expect(fs.existsSync(oldest)).toBe(false);
    expect(fs.existsSync(middle)).toBe(true);
    expect(fs.existsSync(newest)).toBe(true);
    expect(lines).toEqual([result.report]);
    expect(result.report).toContain('1 oldest-first over the');
  });

  it('applies the age cap to what is on disk, and a second sweep then finds nothing left to do', () => {
    const dir = makeCache();
    const old = seed(dir, 'osv', 'ancient', 90);
    const recent = seed(dir, 'osv', 'recent', 2);
    const limits = { maxBytes: 0, maxAgeDays: 30 };
    const first = sweepResearchCache({ dir, limits, now: NOW });
    expect(first.removed).toEqual([old]);
    expect(first.report).toContain('1 older than 30d');
    expect(fs.existsSync(recent)).toBe(true);

    const second = sweepResearchCache({ dir, limits, now: NOW });
    expect(second.removed).toEqual([]);
    expect(second.entryCount).toBe(1);
    expect(second.report).toContain('nothing evicted');
  });

  it('scans only entries, leaving an in-flight temp file to the write that owns it', () => {
    const dir = makeCache();
    seed(dir, 'osv', 'real', 1);
    fs.writeFileSync(path.join(dir, 'osv', 'inflight.json.1234.tmp'), 'half-writ');
    const scan = scanCacheEntries(dir);
    expect(scan.entries.map((e) => path.basename(e.path)).filter((n) => n.endsWith('.tmp'))).toEqual([]);
    expect(scan.entries).toHaveLength(1);
    expect(scan.truncated).toBe(false);
  });

  it('says when its walk was truncated rather than passing a partial total off as the whole', () => {
    const dir = makeCache();
    seed(dir, 'osv', 'a', 1);
    seed(dir, 'nvd', 'b', 1);
    seed(dir, 'kev', 'c', 1);
    expect(scanCacheEntries(dir, 2).truncated).toBe(true);
    expect(scanCacheEntries(dir).truncated).toBe(false);
  });
});
