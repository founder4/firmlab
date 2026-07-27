/**
 * NVD provider (Phase 5, external-intelligence source #2) — correlate firmware components against the NIST National
 * Vulnerability Database. NVD is the canonical, free, no-auth CVE catalog; it COMPLEMENTS OSV, which only covers
 * components it can map to a package ecosystem. Firmware is full of components OSV can't map (busybox, dropbear,
 * the kernel, vendor daemons); NVD's keyword search reaches those by matching the CVE corpus itself.
 *
 * Same non-negotiables as OSV: egress is minimal (only a component name + version leave, as a keyword — never
 * firmware bytes), every request goes through the allowlisted fetch (only services.nvd.nist.gov is contacted), and
 * a keyword hit is a LEAD, not a confirmed vulnerability of THIS image — reachability is decided per-image. NVD
 * rate-limits hard without an API key (5 req / 30 s), so the batch caps the query count and reports honestly what
 * it did NOT query rather than silently truncating. The query builder and response parser are pure + unit-tested.
 *
 * That rate limit is also why the on-disk cache (research/cache.ts) matters most here: six components at 6.5 s
 * apart is over half a minute of waiting for answers we may already have, and the delay exists to be polite to
 * NVD, so it is skipped for an answer that never leaves the machine (`shouldPauseForRateLimit`, pure). Cached
 * answers carry their `freshness` — origin and age — because a CVE list that cannot say when it was true is a
 * finding that cannot be checked.
 */
import {
  type CacheOptions,
  type CacheSummary,
  type Freshness,
  cachedFetch,
  readCache,
  summarizeFreshness,
} from '../research/cache.js';
import { type ResearchConfig, allowlistedFetch } from '../research/config.js';

export const NVD_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

/** Cache namespace for NVD answers — also the subdirectory they live in under the data root. */
export const NVD_CACHE_SOURCE = 'nvd';

/**
 * Pure: the NVD CVE-API query string for a component. `keywordSearch` matches CVEs whose description contains ALL
 * the words, so a name + a concrete version narrows to genuinely relevant advisories (a bare name would return
 * thousands of noise hits). `resultsPerPage` caps the response. No version → a name-only (broader) keyword lead.
 */
export function buildNvdQuery(name: string, version: string, resultsPerPage = 20): string {
  const keyword = version ? `${name} ${version}` : name;
  const params = new URLSearchParams({
    keywordSearch: keyword,
    resultsPerPage: String(resultsPerPage),
  });
  return `${NVD_ENDPOINT}?${params.toString()}`;
}

/**
 * Pure: the cache key for one NVD question — the request URL itself, which is exactly what is asked and nothing
 * more (the API key travels in a header, so it never lands in a key or a filename). Keying on the URL means a
 * change to the query, `resultsPerPage` included, invalidates the entry rather than reusing the answer to a
 * different question.
 */
export function nvdCacheKey(name: string, version: string): string {
  return buildNvdQuery(name, version);
}

/**
 * Pure: does the next component in a batch have to wait? The delay exists to respect NVD's 5-req/30-s anonymous
 * limit, so it is owed only when a request is actually going out: pausing before a cache hit would pay a
 * rate-limit toll for a request that never happens, and a fully cached batch of six would sit idle for 32 s. It is
 * also not owed before the FIRST request of a run, which is what `networkCalls` tracks.
 */
export function shouldPauseForRateLimit(networkCalls: number, willFetch: boolean, delayMs: number): boolean {
  return willFetch && networkCalls > 0 && delayMs > 0;
}

export interface NvdAdvisory {
  /** CVE ID, e.g. CVE-2019-1234. */
  id: string;
  summary: string;
  /** CVSS base severity label (CRITICAL/HIGH/…) when NVD published one, else null. */
  severity: string | null;
  /** CVSS base score when present, else null. */
  score: number | null;
  references: string[];
}

/** Pure: pull the highest-priority CVSS severity/score NVD attached (v3.1 → v3.0 → v2), tolerating gaps. */
function extractSeverity(metrics: NvdCveMetrics | undefined): { severity: string | null; score: number | null } {
  const v31 = metrics?.cvssMetricV31?.[0]?.cvssData;
  const v30 = metrics?.cvssMetricV30?.[0]?.cvssData;
  const v2 = metrics?.cvssMetricV2?.[0];
  if (v31) return { severity: v31.baseSeverity ?? null, score: v31.baseScore ?? null };
  if (v30) return { severity: v30.baseSeverity ?? null, score: v30.baseScore ?? null };
  if (v2) return { severity: v2.baseSeverity ?? null, score: v2.cvssData?.baseScore ?? null };
  return { severity: null, score: null };
}

interface NvdCvssData {
  baseScore?: number;
  baseSeverity?: string;
}
interface NvdCveMetrics {
  cvssMetricV31?: { cvssData?: NvdCvssData }[];
  cvssMetricV30?: { cvssData?: NvdCvssData }[];
  cvssMetricV2?: { baseSeverity?: string; cvssData?: NvdCvssData }[];
}

/** Pure: parse an NVD CVE-API 2.0 response into a compact advisory list. Tolerates missing fields. */
export function parseNvdResponse(json: unknown): NvdAdvisory[] {
  const vulns = (json as { vulnerabilities?: unknown[] })?.vulnerabilities;
  if (!Array.isArray(vulns)) return [];
  return vulns.slice(0, 50).map((raw) => {
    const cve = (raw as { cve?: unknown }).cve as
      | {
          id?: string;
          descriptions?: { lang?: string; value?: string }[];
          metrics?: NvdCveMetrics;
          references?: { url?: string }[];
        }
      | undefined;
    const desc = cve?.descriptions?.find((d) => d.lang === 'en')?.value ?? cve?.descriptions?.[0]?.value ?? '';
    const { severity, score } = extractSeverity(cve?.metrics);
    return {
      id: String(cve?.id ?? '?'),
      summary: String(desc).slice(0, 240),
      severity,
      score,
      references: (cve?.references ?? [])
        .map((r) => String(r.url ?? ''))
        .filter(Boolean)
        .slice(0, 5),
    };
  });
}

export interface NvdComponentResult {
  name: string;
  version: string;
  advisories: NvdAdvisory[];
  /** Where this answer came from and when NVD actually produced it. Null when the request failed. */
  freshness: Freshness | null;
}

/**
 * Query NVD for one component by keyword. An NVD API key (env, passed via cfg) lifts the rate limit but is optional.
 * Read-through the cache: a fresh entry answers without touching NVD, a stale one is re-queried, and a rate-limit
 * rejection (HTTP 403/429) is never stored — caching one would turn a throttle into a durable "no CVEs".
 */
export async function queryNvd(
  component: { name: string; version: string },
  cfg: ResearchConfig,
  cache: CacheOptions = {},
): Promise<NvdComponentResult> {
  const answer = await cachedFetch(
    NVD_CACHE_SOURCE,
    nvdCacheKey(component.name, component.version),
    async () => {
      const headers: Record<string, string> = {};
      if (cfg.nvdApiKey) headers.apiKey = cfg.nvdApiKey;
      const res = await allowlistedFetch(buildNvdQuery(component.name, component.version), cfg, { headers });
      return res.ok ? await res.json() : null;
    },
    cache,
  );
  return {
    name: component.name,
    version: component.version,
    advisories: answer.freshness ? parseNvdResponse(answer.payload) : [],
    freshness: answer.freshness,
  };
}

export interface NvdBatchResult {
  /** Components an answer was obtained for. `cache.hits` of them never left the machine. */
  queried: number;
  /** Candidate components not queried because of the rate-limit cap — reported, never silently dropped. */
  notQueried: number;
  withAdvisories: number;
  totalAdvisories: number;
  components: NvdComponentResult[];
  /** How many of the `queried` answers came off the disk, and how old the oldest one was. */
  cache: CacheSummary;
}

/**
 * Correlate a set of components against NVD, capped to respect NVD's no-key rate limit. `delayMs` spaces the
 * requests (NVD asks for ~6 s between anonymous calls); it is 0 when an API key is present. The caller passes the
 * components OSV could not map, so NVD fills exactly OSV's coverage gap without re-querying what OSV already found.
 */
/** A name+version pair headed for NVD's keyword search — all the batch query needs. */
export interface NvdCandidate {
  name: string;
  version: string;
}

/**
 * Pure: merge the two sources of NVD candidates into the exact list that will leave the machine.
 *
 * De-duplication has to happen HERE rather than inside `queryNvdBatch`, which does its own: the egress ledger is a
 * promise shown to the operator about how many names go out, and a promise computed from a list that is quietly
 * shortened afterwards is not a promise. It also reports how many candidates the fingerprint contributed that the
 * SBOM did not already have, because the ledger declares that split — a name out of an opkg database is something
 * the operator installed, a name read from the strings of a bundled binary is something the analysis derived.
 */
export function mergeNvdCandidates(
  manifest: NvdCandidate[],
  fingerprinted: NvdCandidate[],
): { candidates: NvdCandidate[]; fingerprintedOnly: NvdCandidate[] } {
  const seen = new Set(manifest.map((c) => `${c.name}@${c.version}`));
  const fingerprintedOnly = fingerprinted.filter((c) => {
    const key = `${c.name}@${c.version}`;
    if (!c.name || !c.version || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { candidates: [...manifest, ...fingerprintedOnly], fingerprintedOnly };
}

export async function queryNvdBatch(
  components: { name: string; version: string }[],
  cfg: ResearchConfig,
  opts: { cap?: number; delayMs?: number; cache?: CacheOptions } = {},
): Promise<NvdBatchResult> {
  const cap = opts.cap ?? (cfg.nvdApiKey ? 40 : 6);
  const delayMs = opts.delayMs ?? (cfg.nvdApiKey ? 0 : 6500);
  const seen = new Set<string>();
  const unique = components.filter((c) => {
    const k = `${c.name}@${c.version}`;
    if (!c.name || seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  const cache = opts.cache ?? {};
  const results: NvdComponentResult[] = [];
  // Freshness is collected for every component, not only the ones with advisories: `components` keeps only the
  // latter, so this is the sole place the age of a clean answer survives.
  const freshness: (Freshness | null)[] = [];
  let queried = 0;
  let networkCalls = 0;
  const toQuery = unique.slice(0, cap);
  for (const c of toQuery) {
    // Peek before deciding to wait. `queryNvd` reads the cache again a moment later, which costs one small file
    // read and keeps it self-contained; the alternative is a batch that sleeps through requests it never makes.
    const willFetch = readCache(NVD_CACHE_SOURCE, nvdCacheKey(c.name, c.version), cache).status !== 'fresh';
    if (shouldPauseForRateLimit(networkCalls, willFetch, delayMs)) await sleep(delayMs);
    const r = await queryNvd(c, cfg, cache);
    if (r.freshness?.origin === 'network') networkCalls += 1;
    queried += 1;
    freshness.push(r.freshness);
    if (r.advisories.length > 0) results.push(r);
  }
  return {
    queried,
    notQueried: Math.max(0, unique.length - toQuery.length),
    withAdvisories: results.length,
    totalAdvisories: results.reduce((n, r) => n + r.advisories.length, 0),
    components: results,
    cache: summarizeFreshness(freshness),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
