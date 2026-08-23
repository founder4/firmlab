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
 * NVD's stable source identifier for the Linux kernel CNA. Restricting the kernel query to this source is
 * load-bearing: a bare Linux CPE match also returns vulnerabilities in applications that merely RUN on Linux.
 * Measured on 2026-08-23, Linux 2.6.31 produced 3,848 broad CPE matches, including KDE aRts, versus 2,037
 * records issued by the kernel CNA. The latter is still a large, explicitly truncated candidate set, but it is
 * at least a set of kernel advisories rather than "software seen on Linux".
 */
export const LINUX_KERNEL_CNA_SOURCE = '416baaa9-dc9f-4396-8d5f-8c081fb06d67';

/**
 * The CPE product identities of each component this workbench can name — the fingerprint table's five, plus the
 * ones a real rootfs SBOM surfaces that OSV cannot map. **The first entry is the one queried**; the rest are the
 * other identities NVD carries for the same software, kept as data (see `uncheckedIdentities`).
 *
 * Every entry was read out of NVD's own CPE dictionary and then MEASURED against the CVE API at a version some
 * image in this corpus actually ships, on 2026-07-28. The counts are that measurement, not an estimate:
 *
 *   busybox 1.01     → busybox:busybox                                            17 CVEs
 *   dropbear 2012.55 → dropbear_ssh_project:dropbear_ssh                          15
 *   dnsmasq 2.78     → thekelleys:dnsmasq                                         15
 *   pppd 2.4.3       → point-to-point_protocol_project:point-to-point_protocol     5
 *   openssl 1.0.1    → openssl:openssl                                            78
 *   curl 8.6.0       → haxx:curl                                                  35
 *   ffmpeg 6.1.2     → ffmpeg:ffmpeg                                              18
 *   Linux 2.6.31     → o:linux:linux_kernel + Linux-kernel CNA source filter    2,037 (prefix reported)
 *
 * **Nothing here is guessable, which is the entire reason it is a hand-measured table.** `pppd` returns ZERO
 * entries from the CPE dictionary — the daemon's binary name is not its product identity — so that mapping was
 * read off the CPEs attached to CVE-2020-8597, the pppd CVE the curated table already claims. And `curl` is the
 * clearest case: the obvious `curl:curl` returns **0**, while the real identity `haxx:curl` returns 35. A guessed
 * vendor string does not fail loudly; it queries a product that does not exist and returns nothing, which is
 * indistinguishable from "this component has no CVEs".
 *
 * The alternates were measured too, and at the versions this corpus ships each returned **0** — dropbear also
 * exists as `matt_johnston:dropbear_ssh_server` (40 dictionary entries) and `dropbear_project:dropbear` (28),
 * openssl as `openssl_project:openssl` (89), curl as `haxx:libcurl` (3 CVEs at 8.6.0). That is a statement about
 * these versions, not about the products, so they are carried rather than discarded: a component whose primary
 * identity comes back empty says which identities went unchecked instead of presenting the zero as settled.
 */
export const COMPONENT_CPE: Readonly<Record<string, readonly string[]>> = {
  busybox: ['busybox:busybox'],
  dropbear: ['dropbear_ssh_project:dropbear_ssh', 'matt_johnston:dropbear_ssh_server', 'dropbear_project:dropbear'],
  dnsmasq: ['thekelleys:dnsmasq'],
  pppd: ['point-to-point_protocol_project:point-to-point_protocol'],
  openssl: ['openssl:openssl', 'openssl_project:openssl'],
  curl: ['haxx:curl', 'haxx:libcurl'],
  ffmpeg: ['ffmpeg:ffmpeg'],
  'linux-kernel': ['linux:linux_kernel'],
};

/** CPE part is `a` for applications and `o` for the Linux operating-system/kernel identity. */
function nvdCpePart(name: string): 'a' | 'o' {
  return name.trim().toLowerCase() === 'linux-kernel' ? 'o' : 'a';
}

/** Which question NVD was actually asked. A CPE answer is version-scoped; a keyword answer is a description match. */
export type NvdMatchStrategy = 'cpe' | 'keyword';

/** Pure: the CPE identity actually queried for a component name, or null when nothing verified covers it. */
export function nvdCpeFor(name: string): string | null {
  return COMPONENT_CPE[name.trim().toLowerCase()]?.[0] ?? null;
}

/**
 * Pure: the other CPE identities NVD carries for the same software — measured empty at the versions in this
 * corpus, and NOT queried. They exist so an empty answer can name what it did not look at: `dropbear` under
 * `dropbear_ssh_project` returning nothing is a different claim from `dropbear` having no CVEs anywhere in NVD,
 * and only the second reading is wrong. Querying them too would cost a rate-limit slot per identity against an
 * anonymous budget of six, so it stays a labelling fix rather than an extra request.
 */
export function nvdCpeAlternates(name: string): string[] {
  return [...(COMPONENT_CPE[name.trim().toLowerCase()] ?? [])].slice(1);
}

/**
 * Pure: the version to ask with, or '' when there is nothing usable. syft writes the literal string `UNKNOWN` for
 * a component whose version it could not read — 66 of the GL.iNet's kernel modules come back that way — and
 * passing it through produced `keywordSearch=act_connmark UNKNOWN`, a question that spends a rate-limit slot to
 * ask NVD about a word. A placeholder is the ABSENCE of a version, so it is treated as one.
 */
export function nvdVersion(raw: string): string {
  const v = raw.trim();
  return !v || /^(unknown|none|n\/a|null|undefined)$/i.test(v) ? '' : v;
}

/**
 * How answerable a candidate's question is. The order of this union IS the priority order.
 *
 * `cpe-versioned` resolves a concrete version against each CVE's affected range — the only combination that can
 * actually answer "is what I am holding affected". `cpe-unversioned` is still scoped to the right product.
 * `keyword-versioned` matches description text, which names the FIXED release, so it rarely matches. And
 * `keyword-unversioned` asks NVD whether any CVE description happens to contain a bare word — for a name like
 * `act_connmark` that is not a question at all.
 */
export const NVD_TIERS = ['cpe-versioned', 'cpe-unversioned', 'keyword-versioned', 'keyword-unversioned'] as const;
export type NvdTier = (typeof NVD_TIERS)[number];

/** Pure: which tier a candidate falls in. */
export function nvdCandidateTier(c: NvdCandidate): NvdTier {
  const mapped = nvdCpeFor(c.name) !== null;
  const versioned = nvdVersion(c.version) !== '';
  if (mapped) return versioned ? 'cpe-versioned' : 'cpe-unversioned';
  return versioned ? 'keyword-versioned' : 'keyword-unversioned';
}

/**
 * Pure: order candidates by answerability BEFORE the rate-limit cap truncates.
 *
 * This exists because the cap used to take the first `cap` in arrival order, and arrival order is syft's — which
 * is alphabetical. Measured on the real GL.iNet BE3600: 72 candidates, an anonymous budget of 6, and all six went
 * to `act_connmark`/`act_csum`/`act_gact`/… — kernel modules with no version — while `dnsmasq 2.92`, `pppd 2.4.9`
 * and `openssl 3.0.13`, the three components carrying a curated CPE identity and a real version, were never asked
 * anything. The budget bought nothing and the answerable questions were the ones dropped. That is the same defect
 * `selectFindings` was written for in binvuln.ts: a bound must not make its own result an artifact of scan order.
 *
 * Ranking is stable within a tier except for the one explicitly named priority: the Linux-kernel question goes
 * first among equally answerable CPE+version candidates so the anonymous cap cannot recreate the userland/kernel
 * asymmetry this provider is meant to close. Everything else retains arrival order.
 */
export function rankNvdCandidates(candidates: NvdCandidate[]): NvdCandidate[] {
  const rank = new Map<NvdTier, number>(NVD_TIERS.map((t, i) => [t, i]));
  return candidates
    .map((c, i) => ({
      c,
      i,
      t: rank.get(nvdCandidateTier(c)) ?? NVD_TIERS.length,
      // A kernel answer can contain thousands of CNA advisories and is the one gap this source specifically
      // closes. Keep it inside the anonymous six-request budget when it ties with other CPE-versioned questions.
      kernel: c.name.trim().toLowerCase() === 'linux-kernel' ? 0 : 1,
    }))
    .sort((a, b) => a.t - b.t || a.kernel - b.kernel || a.i - b.i)
    .map((x) => x.c);
}

/**
 * Pure: the NVD CVE-API query string for a component, and which of the two questions it asks.
 *
 * Mapped → `virtualMatchString=cpe:2.3:<part>:<vendor>:<product>:<version>`, which NVD resolves against the affected
 * version RANGES attached to each CVE. That is the only form that can answer "is the version I am holding
 * affected"; the kernel additionally carries the Linux-CNA `sourceIdentifier`, because the broad Linux CPE also
 * denotes the platform under unrelated applications. The keyword form asks whether the description contains the version, which for a vulnerable
 * release it essentially never does. With no version the CPE is sent without one — still correctly scoped to the
 * product, just unconstrained (busybox: 46 CVEs against 17 for 1.01), which beats a name-only keyword.
 *
 * Unmapped → the original `keywordSearch`, which matches CVEs whose description contains ALL the words. It is the
 * weak question, kept deliberately: an unverified vendor guess would be worse than a weak answer, and `strategy`
 * tells the caller which one it got. `resultsPerPage` caps the response.
 */
/**
 * How many advisories one question may return. It was 20 while `parseNvdResponse` independently sliced at 50 —
 * two different silent bounds on the same list, the tighter one invisible. They are one number now, and whatever
 * it still cuts is REPORTED (`totalMatching`) rather than dropped: measured on the GL.iNet, curl 8.6.0 has 35 CVEs
 * and openssl 3.0.13 has 26, so the old page size discarded 21 of them and presented the remainder as the set.
 */
export const NVD_PAGE_SIZE = 50;

export function buildNvdQuery(
  name: string,
  version: string,
  resultsPerPage = NVD_PAGE_SIZE,
): { url: string; strategy: NvdMatchStrategy } {
  const cpe = nvdCpeFor(name);
  const v = nvdVersion(version);
  const normalizedName = name.trim().toLowerCase();
  const params = cpe
    ? new URLSearchParams({
        virtualMatchString: `cpe:2.3:${nvdCpePart(name)}:${cpe}${v ? `:${v}` : ''}`,
        ...(normalizedName === 'linux-kernel' ? { sourceIdentifier: LINUX_KERNEL_CNA_SOURCE } : {}),
        resultsPerPage: String(resultsPerPage),
      })
    : new URLSearchParams({
        keywordSearch: v ? `${name} ${v}` : name,
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

/**
 * Pure: how many CVEs NVD says match the question, independent of how many it returned on this page. This is the
 * denominator — without it a page-limited list looks like the complete answer, which is the reading a bound is
 * never allowed to invite. Null when the response does not carry the field.
 */
export function parseNvdTotal(json: unknown): number | null {
  const t = (json as { totalResults?: unknown })?.totalResults;
  return typeof t === 'number' && Number.isFinite(t) ? t : null;
}

/** Pure: parse an NVD CVE-API 2.0 response into a compact advisory list. Tolerates missing fields. */
export function parseNvdResponse(json: unknown): NvdAdvisory[] {
  const vulns = (json as { vulnerabilities?: unknown[] })?.vulnerabilities;
  if (!Array.isArray(vulns)) return [];
  return vulns.slice(0, NVD_PAGE_SIZE).map((raw) => {
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
  /**
   * Other CPE identities NVD carries for this software that were NOT queried. Populated only when a CPE question
   * came back EMPTY and alternates exist — the one case where the zero could be an artifact of which identity was
   * asked rather than a fact about the version. Empty otherwise, including when advisories were found.
   */
  uncheckedIdentities: string[];
  /**
   * How many CVEs NVD says match, which is not always how many are in `advisories` — one page is returned per
   * question. `advisories.length < totalMatching` means the list here is a prefix, and the difference has to be
   * visible or a truncated list reads as a complete one. Null when the response carried no count.
   */
  totalMatching: number | null;
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
  const advisories = answer.freshness ? parseNvdResponse(answer.payload) : [];
  // Only an EMPTY cpe answer can be an artifact of which identity was asked; a populated one already answered.
  const unchecked = query.strategy === 'cpe' && advisories.length === 0 ? nvdCpeAlternates(component.name) : [];
  return {
    name: component.name,
    version: component.version,
    advisories,
    freshness: answer.freshness,
    matchedBy: query.strategy,
    uncheckedIdentities: unchecked,
    totalMatching: answer.freshness ? parseNvdTotal(answer.payload) : null,
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
  /**
   * What the cap dropped, and by what rule — a bound that truncates has to say so in its own result, or the set it
   * returns reads as the set that existed. Empty when nothing was dropped.
   */
  notQueriedRule: string;
  /** How many candidates sat in each answerability tier, before the cap. */
  tiers: Record<NvdTier, number>;
  /**
   * Components whose CPE question came back EMPTY while NVD carries other identities for the same software that
   * were not asked. This has to live on the batch, not only on the component result: `components` keeps only the
   * entries that found advisories, so an empty answer — the exact case this label describes — would otherwise be
   * dropped before anyone could read it.
   */
  uncheckedIdentities: { name: string; version: string; identities: string[] }[];
  /** Components whose advisory list is a PREFIX of what NVD holds, with both numbers. Empty when nothing was cut. */
  truncated: { name: string; version: string; shown: number; total: number }[];
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
  derived: NvdCandidate[] = [],
): { candidates: NvdCandidate[]; fingerprintedOnly: NvdCandidate[]; derivedOnly: NvdCandidate[] } {
  const seen = new Set(manifest.map((c) => `${c.name}@${c.version}`));
  const fingerprintedOnly = fingerprinted.filter((c) => {
    const key = `${c.name}@${c.version}`;
    if (!c.name || !c.version || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const derivedOnly = derived.filter((c) => {
    const key = `${c.name}@${c.version}`;
    if (!c.name || !c.version || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { candidates: [...manifest, ...fingerprintedOnly, ...derivedOnly], fingerprintedOnly, derivedOnly };
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

  // Rank BEFORE capping. Taking the first `cap` in arrival order spent the whole anonymous budget on whatever syft
  // happened to list first, which on a real OpenWRT rootfs is 66 alphabetically-early kernel modules with no
  // version, while the components that carry a CPE identity and a real version went unasked.
  const ranked = rankNvdCandidates(unique);
  const tiers = Object.fromEntries(NVD_TIERS.map((t) => [t, 0])) as Record<NvdTier, number>;
  for (const c of ranked) tiers[nvdCandidateTier(c)] += 1;

  const cache = opts.cache ?? {};
  const results: NvdComponentResult[] = [];
  const unchecked: { name: string; version: string; identities: string[] }[] = [];
  const truncated: { name: string; version: string; shown: number; total: number }[] = [];
  // Freshness is collected for every component, not only the ones with advisories: `components` keeps only the
  // latter, so this is the sole place the age of a clean answer survives.
  const freshness: (Freshness | null)[] = [];
  let queried = 0;
  let networkCalls = 0;
  let askedByCpe = 0;
  const toQuery = ranked.slice(0, cap);
  const dropped = ranked.slice(cap);
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
    if (r.uncheckedIdentities.length > 0) {
      unchecked.push({ name: r.name, version: r.version, identities: r.uncheckedIdentities });
    }
    if (r.totalMatching !== null && r.totalMatching > r.advisories.length) {
      truncated.push({ name: r.name, version: r.version, shown: r.advisories.length, total: r.totalMatching });
    }
  }
  return {
    queried,
    notQueried: dropped.length,
    withAdvisories: results.length,
    totalAdvisories: results.reduce((n, r) => n + r.advisories.length, 0),
    components: results,
    cache: summarizeFreshness(freshness),
    askedByCpe,
    askedByKeyword: queried - askedByCpe,
    notQueriedRule: describeNvdDrop(dropped, cap),
    tiers,
    uncheckedIdentities: unchecked,
    truncated,
  };
}

/**
 * Pure: state what the cap dropped and by which rule. Naming the tiers matters more than the number: dropping 66
 * unversioned kernel-module names is a bound working as intended, and dropping a `cpe-versioned` component is the
 * budget being genuinely too small for the image — the same count means opposite things.
 */
export function describeNvdDrop(dropped: NvdCandidate[], cap: number): string {
  if (dropped.length === 0) return '';
  const byTier = new Map<NvdTier, number>();
  for (const c of dropped) {
    const t = nvdCandidateTier(c);
    byTier.set(t, (byTier.get(t) ?? 0) + 1);
  }
  const parts = NVD_TIERS.filter((t) => byTier.has(t)).map((t) => `${byTier.get(t)} ${t}`);
  const answerableLost = (byTier.get('cpe-versioned') ?? 0) + (byTier.get('cpe-unversioned') ?? 0);
  const tail =
    answerableLost > 0
      ? ` ${answerableLost} of them carry a CPE identity, so the cap is genuinely too small for this image.`
      : ' All of them were keyword-only questions, which NVD can rarely answer anyway.';
  return `${dropped.length} candidate(s) went unqueried: the rate-limit cap of ${cap} was reached, and candidates are ranked most-answerable first (${parts.join(', ')}).${tail}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
