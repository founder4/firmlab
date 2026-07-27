/**
 * On-disk cache for the external-intelligence lookups (Phase 5). Two reasons to have one, and the second is the
 * one that shapes the design.
 *
 * Not re-querying is the easy half. NVD rate-limits anonymous callers to 5 requests / 30 s, so `queryNvdBatch`
 * already sleeps 6.5 s between calls and a corpus-wide re-run costs minutes of waiting on services that answer for
 * free. The cache is keyed by the QUESTION — the exact request that produced the answer — never by the image, so
 * sixteen firmwares that all ship busybox 1.01 ask OSV about it once between them.
 *
 * Reproducibility is the half that constrains everything else. A cached answer served as if it were live is
 * indistinguishable from a fresh one: the finding it produces looks identical, carries the same proof state, and
 * says nothing about when the advisory list behind it was true. A workbench whose premise is that a claim is
 * checkable cannot quietly hand back a year-old CVE list. So:
 *
 * - every entry records `fetchedAt` — the moment the payload came off the wire, not the moment it was served;
 * - every answer, cached or live, comes back with a `Freshness` stating which of the two it was and how old it is,
 *   so the age is reachable by the caller and can be surfaced without changing this layer again;
 * - past the TTL an entry is NOT served. It is reported `stale` and the provider re-queries. We deliberately do
 *   not fall back to a stale entry when that re-query fails: nothing downstream renders the age yet, so a stale
 *   answer standing in for a live one would be invisible — precisely the silent staleness this cache exists to
 *   prevent. A failed lookup fails exactly as it did before the cache existed.
 *
 * What is stored is the RAW payload the service returned, not our parse of it. The cache file is then the evidence
 * — readable by hand, re-parsed on every read — so a later fix to a parser applies to cached answers too instead
 * of freezing yesterday's bug on disk. An HTTP error is never stored: a failure is not the service's answer.
 *
 * TTL: `FIRMLAB_RESEARCH_CACHE_TTL_HOURS`, default 24, fractional values allowed. 24 h is chosen so that a scan
 * re-run within the working session that produced it is free, identical and offline, while a run the next day goes
 * back to the sources — published advisories, and KEV in particular, move on a scale of days, and pretending
 * otherwise for longer would buy speed with honesty. `0` disables serving from the cache entirely (every lookup
 * goes to the network) while still recording what came back, because that record is the reproducibility half.
 *
 * Honest degradation, as everywhere else here: an unwritable data root makes lookups slower, never broken. Every
 * filesystem operation is wrapped; a write that fails reports `written: false` with the reason instead of
 * pretending it cached, and a corrupt or wrong-schema entry is a miss with a stated reason.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DATA_DIR } from '../paths.js';

/**
 * Envelope schema version. Bump it when the envelope's MEANING changes; a mismatch is treated as a miss, so an old
 * entry is re-fetched rather than reinterpreted under new rules.
 */
export const CACHE_SCHEMA_VERSION = 1;

/** Cache root, under the single data root so one bind-mount carries it with the rest of the workbench state. */
export const RESEARCH_CACHE_DIR = path.join(DATA_DIR, 'research-cache');

/** Default time-to-live, in hours. See the module header for why a day. */
export const DEFAULT_TTL_HOURS = 24;

const HOUR_MS = 60 * 60 * 1000;

/** What a cache file holds: the service's raw answer plus everything needed to judge whether it is still usable. */
export interface CacheEnvelope {
  version: number;
  /** Which external source produced the payload (`osv` / `nvd` / `kev`); also the on-disk namespace. */
  source: string;
  /** The request this answer belongs to, in clear text, so a cache file is auditable without the code. */
  key: string;
  /** Epoch ms at which the payload was received FROM the service — not when it was written or served. */
  fetchedAt: number;
  /** Exactly what the service returned, unparsed. */
  payload: unknown;
}

/** How an answer was obtained and how old it is. Every answer carries one, cached or not. */
export interface Freshness {
  origin: 'network' | 'cache';
  /** ISO 8601 instant the payload came off the wire. For a live answer, now. */
  fetchedAt: string;
  /** Age of the served payload in ms. 0 for a live answer. */
  ageMs: number;
}

/** Aggregate freshness for a batch of lookups — how much of it never left the machine, and how old the oldest is. */
export interface CacheSummary {
  /** Answers served from disk. These sent nothing. */
  hits: number;
  /** Answers fetched live (a miss, or a stale entry that was refreshed). */
  misses: number;
  /** Age of the OLDEST cached answer served, in ms. 0 when nothing came from the cache. */
  oldestAgeMs: number;
}

/** The result of looking in the cache. A stale entry is returned too — the caller may want to say how old it was. */
export type CacheLookup =
  | { status: 'miss'; reason: string }
  | { status: 'stale'; entry: CacheEnvelope; ageMs: number }
  | { status: 'fresh'; entry: CacheEnvelope; ageMs: number };

/** Outcome of a write. Never throws, and never claims a write that did not happen. */
export type CacheWrite = { written: true; path: string } | { written: false; reason: string };

/** Overrides for the cache's two environmental inputs (directory, TTL) plus the clock — what makes it testable. */
export interface CacheOptions {
  dir?: string;
  ttlMs?: number;
  now?: number;
}

/**
 * Pure: the configured TTL in ms. Anything unusable (non-numeric, negative) falls back to the default rather than
 * failing a lookup — a malformed env var must not decide that an advisory list is fresh forever.
 */
export function resolveTtlMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.FIRMLAB_RESEARCH_CACHE_TTL_HOURS;
  if (raw === undefined || raw.trim() === '') return DEFAULT_TTL_HOURS * HOUR_MS;
  const hours = Number(raw);
  if (!Number.isFinite(hours) || hours < 0) return DEFAULT_TTL_HOURS * HOUR_MS;
  return Math.round(hours * HOUR_MS);
}

/**
 * Pure: the on-disk path for one cached answer. The filename is a digest of source + key, so a key may be any
 * string — a URL, a JSON body — without ever becoming a path: no traversal, no length limit, no case-folding
 * surprise on a mounted volume. The clear-text key lives INSIDE the file, which is where auditability belongs.
 */
export function cacheEntryPath(dir: string, source: string, key: string): string {
  const digest = createHash('sha256').update(`${source} ${key}`).digest('hex').slice(0, 32);
  return path.join(dir, source.replace(/[^a-z0-9-]/gi, '_'), `${digest}.json`);
}

/** Pure: the envelope to write for one answer. */
export function buildEnvelope(source: string, key: string, payload: unknown, now: number): CacheEnvelope {
  return { version: CACHE_SCHEMA_VERSION, source, key, fetchedAt: now, payload };
}

/** Pure: serialize an envelope. Compact on purpose — the KEV catalog is megabytes, and `jq` reads it either way. */
export function serializeEnvelope(entry: CacheEnvelope): string {
  return JSON.stringify(entry);
}

export type EnvelopeRead = { ok: true; entry: CacheEnvelope } | { ok: false; reason: string };

/**
 * Pure: read a cache file back. Every rejection states its reason, because "the cache did not answer" and "the
 * cache answered something we could not trust" are different events and only one of them means the file is broken.
 */
export function parseEnvelope(text: string): EnvelopeRead {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { ok: false, reason: 'cache entry is not JSON' };
  }
  if (!raw || typeof raw !== 'object') return { ok: false, reason: 'cache entry is not an object' };
  const e = raw as Partial<CacheEnvelope>;
  if (e.version !== CACHE_SCHEMA_VERSION) {
    return { ok: false, reason: `cache entry schema v${String(e.version)} != v${CACHE_SCHEMA_VERSION}` };
  }
  if (typeof e.fetchedAt !== 'number' || !Number.isFinite(e.fetchedAt)) {
    return { ok: false, reason: 'cache entry has no usable fetchedAt' };
  }
  if (!('payload' in e)) return { ok: false, reason: 'cache entry has no payload' };
  return {
    ok: true,
    entry: {
      version: CACHE_SCHEMA_VERSION,
      source: String(e.source ?? ''),
      key: String(e.key ?? ''),
      fetchedAt: e.fetchedAt,
      payload: e.payload,
    },
  };
}

/**
 * Pure: the staleness decision, the one rule this whole module exists to make explicit. Fresh means "younger than
 * the TTL and therefore servable as the current answer"; everything else is re-queried.
 *
 * Two edge cases are deliberate. A TTL of 0 makes nothing fresh — the documented way to force live lookups. And a
 * NEGATIVE age (an entry stamped in the future: a clock that moved, or a cache directory carried over from another
 * machine) is not fresh either, because we cannot say how old it is, and an age we cannot state is not one we may
 * serve.
 */
export function classifyAge(fetchedAt: number, ttlMs: number, now: number): { fresh: boolean; ageMs: number } {
  const ageMs = now - fetchedAt;
  if (ageMs < 0) return { fresh: false, ageMs: 0 };
  return { fresh: ttlMs > 0 && ageMs < ttlMs, ageMs };
}

/** Pure: the freshness a cached answer carries — when it was really fetched, and how long ago that was. */
export function cachedFreshness(fetchedAt: number, ageMs: number): Freshness {
  return { origin: 'cache', fetchedAt: new Date(fetchedAt).toISOString(), ageMs };
}

/** Pure: the freshness a live answer carries. Age 0, and the timestamp is the fetch itself. */
export function liveFreshness(now: number): Freshness {
  return { origin: 'network', fetchedAt: new Date(now).toISOString(), ageMs: 0 };
}

/** Pure: fold a batch's per-answer freshness into the summary a caller can report. */
export function summarizeFreshness(items: readonly (Freshness | null | undefined)[]): CacheSummary {
  let hits = 0;
  let misses = 0;
  let oldestAgeMs = 0;
  for (const f of items) {
    if (!f) continue;
    if (f.origin === 'cache') {
      hits += 1;
      oldestAgeMs = Math.max(oldestAgeMs, f.ageMs);
    } else {
      misses += 1;
    }
  }
  return { hits, misses, oldestAgeMs };
}

/** Look one answer up. A missing, unreadable, corrupt or wrong-schema file is a miss with a reason, never a throw. */
export function readCache(source: string, key: string, opts: CacheOptions = {}): CacheLookup {
  const dir = opts.dir ?? RESEARCH_CACHE_DIR;
  const ttlMs = opts.ttlMs ?? resolveTtlMs();
  const now = opts.now ?? Date.now();
  let text: string;
  try {
    text = fs.readFileSync(cacheEntryPath(dir, source, key), 'utf8');
  } catch {
    return { status: 'miss', reason: 'not cached' };
  }
  const read = parseEnvelope(text);
  if (!read.ok) return { status: 'miss', reason: read.reason };
  const { fresh, ageMs } = classifyAge(read.entry.fetchedAt, ttlMs, now);
  return fresh ? { status: 'fresh', entry: read.entry, ageMs } : { status: 'stale', entry: read.entry, ageMs };
}

/**
 * Store one answer. Written to a temp file and renamed, so a process that dies mid-write leaves no half-JSON that
 * would read back as a corrupt hit. An unwritable data root is reported, never thrown and never silently taken for
 * a successful cache.
 */
export function writeCache(source: string, key: string, payload: unknown, opts: CacheOptions = {}): CacheWrite {
  const dir = opts.dir ?? RESEARCH_CACHE_DIR;
  const now = opts.now ?? Date.now();
  const file = cacheEntryPath(dir, source, key);
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(tmp, serializeEnvelope(buildEnvelope(source, key, payload, now)));
    fs.renameSync(tmp, file);
    return { written: true, path: file };
  } catch (err) {
    try {
      fs.rmSync(tmp, { force: true });
    } catch {
      // the temp file is already gone, or the directory was never writable — nothing to clean up
    }
    return { written: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

/** An answer plus its provenance. `freshness: null` means the request failed and there is no answer at all. */
export interface CachedAnswer {
  payload: unknown;
  freshness: Freshness | null;
  /** Whether this answer was persisted. False on a live answer means the next lookup will query again. */
  stored: boolean;
}

/**
 * Read-through cache around one external request — the single place the three providers get their answers, so the
 * "fresh → serve, stale → re-query, never store a failure" rule is written once.
 *
 * `fetchPayload` returns the raw payload to cache, or `null` to say "this is not an answer" (an HTTP error, a body
 * that would not parse). A failure is never frozen on disk as though the service had said it.
 */
export async function cachedFetch(
  source: string,
  key: string,
  fetchPayload: () => Promise<unknown>,
  opts: CacheOptions = {},
): Promise<CachedAnswer> {
  const now = opts.now ?? Date.now();
  const lookup = readCache(source, key, { ...opts, now });
  if (lookup.status === 'fresh') {
    return {
      payload: lookup.entry.payload,
      freshness: cachedFreshness(lookup.entry.fetchedAt, lookup.ageMs),
      stored: true,
    };
  }
  const payload = await fetchPayload();
  if (payload === null) return { payload: null, freshness: null, stored: false };
  const write = writeCache(source, key, payload, { ...opts, now });
  return { payload, freshness: liveFreshness(now), stored: write.written };
}
