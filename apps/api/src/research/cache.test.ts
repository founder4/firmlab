import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  CACHE_SCHEMA_VERSION,
  type Freshness,
  buildEnvelope,
  cacheEntryPath,
  cachedFetch,
  cachedFreshness,
  classifyAge,
  liveFreshness,
  parseEnvelope,
  readCache,
  resolveTtlMs,
  serializeEnvelope,
  summarizeFreshness,
  writeCache,
} from './cache.js';

const HOUR = 60 * 60 * 1000;

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
