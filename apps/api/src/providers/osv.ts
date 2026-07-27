/**
 * OSV.dev provider (Phase 5) — correlate the firmware's SBOM against PUBLISHED vulnerability advisories. OSV is a
 * free, no-auth, authoritative aggregator; it's the cleanest first external source. Egress is minimal: only a
 * component's name, version and ecosystem leave the machine — never firmware bytes. Every request goes through the
 * allowlisted fetch, so only api.osv.dev is ever contacted.
 *
 * Honesty: a published advisory for a component that is PRESENT is a lead, not a confirmed vulnerability of THIS
 * image — reachability is decided per-image (the corpus / emulation), never by a version-string match. The request
 * builder and response parser are pure and unit-tested; only queryOsv touches the network.
 *
 * Answers go through the on-disk cache (research/cache.ts), keyed by the QUESTION rather than by the image: a
 * corpus where sixteen firmwares ship the same busybox asks OSV about it once. Every result therefore carries a
 * `freshness` saying whether it came off the wire or off the disk and how old it is — a cached advisory list that
 * could not state its age would produce a finding indistinguishable from a fresh one, which is the one thing this
 * lane may not do.
 */
import {
  type CacheOptions,
  type CacheSummary,
  type Freshness,
  cachedFetch,
  summarizeFreshness,
} from '../research/cache.js';
import { type ResearchConfig, allowlistedFetch } from '../research/config.js';

export const OSV_ENDPOINT = 'https://api.osv.dev/v1/query';

/** Cache namespace for OSV answers — also the subdirectory they live in under the data root. */
export const OSV_CACHE_SOURCE = 'osv';

/** syft package type → OSV ecosystem. Components with no mapping can't be queried precisely and are skipped. */
const ECOSYSTEM: Record<string, string> = {
  deb: 'Debian',
  apk: 'Alpine',
  npm: 'npm',
  python: 'PyPI',
  wheel: 'PyPI',
  egg: 'PyPI',
  'go-module': 'Go',
  gomod: 'Go',
  'rust-crate': 'crates.io',
  gem: 'RubyGems',
  'java-archive': 'Maven',
  jar: 'Maven',
};

export function osvEcosystem(syftType: string): string | null {
  return ECOSYSTEM[syftType.toLowerCase()] ?? null;
}

export function buildOsvQuery(
  name: string,
  version: string,
  ecosystem: string,
): { package: { name: string; ecosystem: string }; version: string } {
  return { package: { name, ecosystem }, version };
}

/**
 * Pure: the cache key for one OSV question. It IS the request body — the same package, ecosystem and version that
 * leave the machine — so two callers asking the same question share an answer, and a change to what we ask
 * invalidates the entry instead of silently reusing an answer to a different question.
 */
export function osvCacheKey(name: string, version: string, ecosystem: string): string {
  return JSON.stringify(buildOsvQuery(name, version, ecosystem));
}

export interface OsvAdvisory {
  id: string;
  aliases: string[];
  summary: string;
  severity: string | null;
  references: string[];
}

/** Pure: parse an OSV /v1/query response into a compact advisory list. Tolerates missing fields. */
export function parseOsvResponse(json: unknown): OsvAdvisory[] {
  const vulns = (json as { vulns?: unknown[] })?.vulns;
  if (!Array.isArray(vulns)) return [];
  return vulns.slice(0, 50).map((raw) => {
    const v = raw as {
      id?: string;
      aliases?: string[];
      summary?: string;
      details?: string;
      severity?: { type?: string; score?: string }[];
      database_specific?: { severity?: string };
      references?: { url?: string }[];
    };
    const cvss = v.severity?.find((s) => s.score)?.score ?? null;
    const sev = v.database_specific?.severity ?? cvss ?? null;
    return {
      id: String(v.id ?? '?'),
      aliases: Array.isArray(v.aliases) ? v.aliases.filter((a): a is string => typeof a === 'string') : [],
      summary: String(v.summary ?? v.details ?? '').slice(0, 240),
      severity: sev,
      references: (v.references ?? [])
        .map((r) => String(r.url ?? ''))
        .filter(Boolean)
        .slice(0, 5),
    };
  });
}

export interface OsvComponentResult {
  name: string;
  version: string;
  ecosystem: string | null;
  queryable: boolean;
  advisories: OsvAdvisory[];
  /** Where this answer came from and when OSV actually produced it. Null when nothing was asked or nothing came back. */
  freshness: Freshness | null;
}

/**
 * Query OSV for one component. Components with no OSV ecosystem mapping are reported as not-queryable (honest).
 * Read-through the cache: a fresh entry is served without contacting OSV, a stale one is re-queried, and an HTTP
 * error is never stored — so a bad afternoon at api.osv.dev cannot become a cached "no advisories".
 */
export async function queryOsv(
  component: { name: string; version: string; type: string },
  cfg: ResearchConfig,
  cache: CacheOptions = {},
): Promise<OsvComponentResult> {
  const ecosystem = osvEcosystem(component.type);
  const base = { name: component.name, version: component.version, ecosystem };
  if (!ecosystem || !component.version) {
    return { ...base, queryable: false, advisories: [], freshness: null };
  }
  const answer = await cachedFetch(
    OSV_CACHE_SOURCE,
    osvCacheKey(component.name, component.version, ecosystem),
    async () => {
      const res = await allowlistedFetch(OSV_ENDPOINT, cfg, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(buildOsvQuery(component.name, component.version, ecosystem)),
      });
      return res.ok ? await res.json() : null;
    },
    cache,
  );
  return {
    ...base,
    queryable: true,
    advisories: answer.freshness ? parseOsvResponse(answer.payload) : [],
    freshness: answer.freshness,
  };
}

export interface OsvBatchResult {
  queried: number;
  skipped: number;
  withAdvisories: number;
  totalAdvisories: number;
  components: OsvComponentResult[];
  /** How many of the `queried` answers came off the disk (those sent nothing) and how old the oldest one was. */
  cache: CacheSummary;
}

/** Correlate a whole SBOM against OSV. Dedupes, caps the number of queries, and reports what it could/couldn't do. */
export async function queryOsvBatch(
  packages: { name: string; version: string; type: string }[],
  cfg: ResearchConfig,
  cap = 80,
  cache: CacheOptions = {},
): Promise<OsvBatchResult> {
  const seen = new Set<string>();
  const unique = packages.filter((p) => {
    const k = `${p.name}@${p.version}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const results: OsvComponentResult[] = [];
  // Freshness is collected for EVERY queried component, not only the ones that turned out to have advisories —
  // `components` keeps only the latter, so the summary is the sole place the age of a clean answer survives.
  const freshness: (Freshness | null)[] = [];
  let queried = 0;
  let skipped = 0;
  for (const p of unique.slice(0, cap)) {
    const r = await queryOsv(p, cfg, cache);
    if (r.queryable) queried += 1;
    else skipped += 1;
    freshness.push(r.freshness);
    if (r.advisories.length > 0) results.push(r);
  }
  return {
    queried,
    skipped,
    withAdvisories: results.length,
    totalAdvisories: results.reduce((n, r) => n + r.advisories.length, 0),
    components: results,
    cache: summarizeFreshness(freshness),
  };
}
