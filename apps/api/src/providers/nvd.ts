/**
 * NVD provider (Phase 5, external-intelligence source #2) — correlate firmware components against the NIST National
 * Vulnerability Database. NVD is the canonical, free, no-auth CVE catalog; it COMPLEMENTS OSV, which only covers
 * components it can map to a package ecosystem. Firmware is full of components OSV can't map (busybox, dropbear,
 * the kernel, vendor daemons), and reaching those is this module's whole reason to exist.
 *
 * **How it asks, and why it changed.** It asked by `keywordSearch=<name> <version>` until 2026-07-28, and that
 * question is nearly unanswerable: keyword matches the CVE *description*, and a description reads "Dropbear SSH
 * before 2016.74" — it names the fixed release, never the vulnerable one someone actually shipped. Searching for
 * the version in hand therefore matches almost nothing. Measured live against the API: `dropbear 2012.55` → **0
 * results**, while the CPE match for the same component and version → **15**. The first real research run on a
 * WR940N queried all three fingerprinted components and returned zero advisories — a lane that worked end to end
 * and asked a question that could not be answered. So a mapped component is now asked by `virtualMatchString`,
 * against NVD's own CPE product identity, which is the field that actually encodes affected version RANGES.
 *
 * The map is CURATED and MEASURED rather than derived, because a CPE vendor string cannot be guessed from a
 * component name — `pppd` does not appear in the CPE dictionary at all, and `openssl` and `dropbear` each carry
 * several competing identities of which only one answers at the versions this corpus ships. Guessing one would be
 * the fabrication this codebase refuses elsewhere. Anything unmapped keeps the keyword query: a weak question is
 * still better than no question, and `matchedBy` records which of the two produced the answer so a caller can
 * weigh it.
 *
 * Same non-negotiables as OSV: egress is minimal (only a component name + version leave, as a keyword or a CPE
 * match string — never firmware bytes), every request goes through the allowlisted fetch (only
 * services.nvd.nist.gov is contacted), and a hit is a LEAD, not a confirmed vulnerability of THIS image — NVD
 * asserts that a version is affected, never that the code is reachable here. NVD rate-limits hard without an API
 * key (5 req / 30 s), so the batch caps the query count and reports honestly what it did NOT query rather than
 * silently truncating. The query builder and response parser are pure + unit-tested.
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
 * The CPE product identity of each component the fingerprint table (`component-cve.ts`) can name. Every entry was
 * read out of NVD's own CPE dictionary and then MEASURED against the CVE API at a version this corpus actually
 * ships, on 2026-07-28 — counts below are that measurement, not an estimate:
 *
 *   busybox 1.01     → busybox:busybox                                            17 CVEs
 *   dropbear 2012.55 → dropbear_ssh_project:dropbear_ssh                          15
 *   dnsmasq 2.78     → thekelleys:dnsmasq                                         15
 *   pppd 2.4.3       → point-to-point_protocol_project:point-to-point_protocol     5
 *   openssl 1.0.1    → openssl:openssl                                            78
 *
 * Two of these are not guessable, which is why the table is curated. `pppd` returns ZERO entries from the CPE
 * dictionary — the daemon's binary name is not its product identity, and the mapping above came from reading the
 * CPEs attached to CVE-2020-8597, the pppd CVE the curated table already claims. And a component can carry several
 * competing identities: dropbear also exists as `matt_johnston:dropbear_ssh_server` (40 dictionary entries) and
 * `dropbear_project:dropbear` (28), openssl also as `openssl_project:openssl` (89) — and at the versions this
 * corpus ships, each of those alternates returned **0**. They are recorded here as measured-empty rather than
 * omitted, because "we chose one of three" is a decision a later reader must be able to see and re-check; picking
 * the alternate silently is how a lane returns nothing and looks healthy doing it.
 */
export const COMPONENT_CPE: Readonly<Record<string, string>> = {
  busybox: 'busybox:busybox',
  dropbear: 'dropbear_ssh_project:dropbear_ssh',
  dnsmasq: 'thekelleys:dnsmasq',
  pppd: 'point-to-point_protocol_project:point-to-point_protocol',
  openssl: 'openssl:openssl',
};

/** Which question NVD was actually asked. A CPE answer is version-scoped; a keyword answer is a description match. */
export type NvdMatchStrategy = 'cpe' | 'keyword';

/** Pure: the curated CPE identity for a component name, or null when nothing verified covers it. */
export function nvdCpeFor(name: string): string | null {
  return COMPONENT_CPE[name.trim().toLowerCase()] ?? null;
}

/**
 * Pure: the NVD CVE-API query string for a component, and which of the two questions it asks.
 *
 * Mapped → `virtualMatchString=cpe:2.3:a:<vendor>:<product>:<version>`, which NVD resolves against the affected
 * version RANGES attached to each CVE. That is the only form that can answer "is the version I am holding
 * affected"; the keyword form asks whether the description happens to contain the version, which for a vulnerable
 * release it essentially never does. With no version the CPE is sent without one — still correctly scoped to the
 * product, just unconstrained (busybox: 46 CVEs against 17 for 1.01), which beats a name-only keyword.
 *
 * Unmapped → the original `keywordSearch`, which matches CVEs whose description contains ALL the words. It is the
 * weak question, kept deliberately: an unverified vendor guess would be worse than a weak answer, and `strategy`
 * tells the caller which one it got. `resultsPerPage` caps the response.
 */
export function buildNvdQuery(
  name: string,
  version: string,
  resultsPerPage = 20,
): { url: string; strategy: NvdMatchStrategy } {
  const cpe = nvdCpeFor(name);
  const params = cpe
    ? new URLSearchParams({
        virtualMatchString: `cpe:2.3:a:${cpe}${version ? `:${version}` : ''}`,
        resultsPerPage: String(resultsPerPage),
      })
    : new URLSearchParams({
        keywordSearch: version ? `${name} ${version}` : name,
        resultsPerPage: String(resultsPerPage),
      });
  return { url: `${NVD_ENDPOINT}?${params.toString()}`, strategy: cpe ? 'cpe' : 'keyword' };
}

/**
 * Pure: the cache key for one NVD question — the request URL itself, which is exactly what is asked and nothing
 * more (the API key travels in a header, so it never lands in a key or a filename). Keying on the URL means a
 * change to the query, `resultsPerPage` included, invalidates the entry rather than reusing the answer to a
 * different question.
 */
export function nvdCacheKey(name: string, version: string): string {
  return buildNvdQuery(name, version).url;
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
  /**
   * Which question produced this answer. `cpe` is version-scoped against NVD's affected ranges; `keyword` only
   * matched description text and is the weaker of the two — an empty `keyword` result says considerably less than
   * an empty `cpe` one, and the caller must be able to tell them apart.
   */
  matchedBy: NvdMatchStrategy;
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
  const query = buildNvdQuery(component.name, component.version);
  const answer = await cachedFetch(
    NVD_CACHE_SOURCE,
    nvdCacheKey(component.name, component.version),
    async () => {
      const headers: Record<string, string> = {};
      if (cfg.nvdApiKey) headers.apiKey = cfg.nvdApiKey;
      const res = await allowlistedFetch(query.url, cfg, { headers });
      return res.ok ? await res.json() : null;
    },
    cache,
  );
  return {
    name: component.name,
    version: component.version,
    advisories: answer.freshness ? parseNvdResponse(answer.payload) : [],
    freshness: answer.freshness,
    matchedBy: query.strategy,
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
  /**
   * How the batch split between the two questions. Counted over everything QUERIED, not over what came back with
   * advisories, because the interesting case is the silent one: a run that asked entirely by keyword and returned
   * nothing has not established that the components are unaffected, and only this number shows it.
   */
  askedByCpe: number;
  askedByKeyword: number;
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
  let askedByCpe = 0;
  const toQuery = unique.slice(0, cap);
  for (const c of toQuery) {
    // Peek before deciding to wait. `queryNvd` reads the cache again a moment later, which costs one small file
    // read and keeps it self-contained; the alternative is a batch that sleeps through requests it never makes.
    const willFetch = readCache(NVD_CACHE_SOURCE, nvdCacheKey(c.name, c.version), cache).status !== 'fresh';
    if (shouldPauseForRateLimit(networkCalls, willFetch, delayMs)) await sleep(delayMs);
    const r = await queryNvd(c, cfg, cache);
    if (r.freshness?.origin === 'network') networkCalls += 1;
    if (r.matchedBy === 'cpe') askedByCpe += 1;
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
    askedByCpe,
    askedByKeyword: queried - askedByCpe,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
