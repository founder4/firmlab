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
 * silently truncating. The query builder, response parser, ranking and pagination decisions are pure,
 * unit-tested, and live in `@firmlab/core` (`nvd-domain.ts`); this module keeps the fetch, the cache and the batch.
 *
 * That rate limit is also why the on-disk cache (research/cache.ts) matters most here: six components at 6.5 s
 * apart is over half a minute of waiting for answers we may already have, and the delay exists to be polite to
 * NVD, so it is skipped for an answer that never leaves the machine (`shouldPauseForRateLimit`, pure). Cached
 * answers carry their `freshness` — origin and age — because a CVE list that cannot say when it was true is a
 * finding that cannot be checked.
 */
import {
  NVD_TIERS,
  type NvdAdvisory,
  type NvdCandidate,
  type NvdMatchStrategy,
  type NvdPageCoverage,
  type NvdPaginationProgress,
  type NvdPaginationStopReason,
  type NvdTier,
  buildNvdQuery,
  describeNvdDrop,
  nextNvdPage,
  nvdCacheKey,
  nvdCandidateTier,
  nvdCpeAlternates,
  parseNvdResponse,
  parseNvdTotal,
  rankNvdCandidates,
  resolveNvdPaginationBounds,
  shouldPauseForRateLimit,
} from '@firmlab/core';
import {
  type CacheOptions,
  type CacheSummary,
  type Freshness,
  cachedFetch,
  readCache,
  summarizeFreshness,
} from '../research/cache.js';
import { type ResearchConfig, allowlistedFetch } from '../research/config.js';

/** Cache namespace for NVD answers — also the subdirectory they live in under the data root. */
export const NVD_CACHE_SOURCE = 'nvd';

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
  /** Optional forever: older persisted results predate multi-page retrieval. */
  pageCoverage?: NvdPageCoverage;
  /** Optional forever: one freshness entry per attempted page, including null for a failed request. */
  pageFreshness?: (Freshness | null)[];
}

interface NvdQueryControl {
  maxPages?: number;
  maxAdvisories?: number;
  beforePage?: (willFetch: boolean) => Promise<void>;
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
  control: NvdQueryControl = {},
): Promise<NvdComponentResult> {
  const bounds = resolveNvdPaginationBounds(control);
  const advisories: NvdAdvisory[] = [];
  const attemptedOffsets: number[] = [];
  const completedOffsets: number[] = [];
  const pageFreshness: (Freshness | null)[] = [];
  let firstFreshness: Freshness | null = null;
  let totalMatching: number | null = null;
  let progress: NvdPaginationProgress = {
    pagesCompleted: 0,
    advisoriesCollected: 0,
    lastPageCount: 0,
    lastPageRequested: 0,
    totalMatching: null,
  };
  let decision = nextNvdPage(progress, bounds);
  let stopReason: NvdPaginationStopReason = 'request-failed';
  let complete = false;
  let droppedByPageBounds = 0;

  while (decision.fetch) {
    const { startIndex, resultsPerPage } = decision;
    const query = buildNvdQuery(component.name, component.version, resultsPerPage, startIndex);
    const cacheKey = nvdCacheKey(component.name, component.version, startIndex, resultsPerPage);
    const willFetch = readCache(NVD_CACHE_SOURCE, cacheKey, cache).status !== 'fresh';
    await control.beforePage?.(willFetch);
    attemptedOffsets.push(startIndex);

    let answer: Awaited<ReturnType<typeof cachedFetch>>;
    try {
      answer = await cachedFetch(
        NVD_CACHE_SOURCE,
        cacheKey,
        async () => {
          const headers: Record<string, string> = {};
          if (cfg.nvdApiKey) headers.apiKey = cfg.nvdApiKey;
          const res = await allowlistedFetch(query.url, cfg, { headers });
          return res.ok ? await res.json() : null;
        },
        cache,
      );
    } catch {
      pageFreshness.push(null);
      stopReason = 'request-failed';
      break;
    }
    pageFreshness.push(answer.freshness);
    if (!answer.freshness) {
      stopReason = 'request-failed';
      break;
    }

    if (firstFreshness === null) firstFreshness = answer.freshness;
    completedOffsets.push(startIndex);
    const parsedPage = parseNvdResponse(answer.payload);
    const page = parsedPage.slice(0, resultsPerPage);
    const pageDropped = parsedPage.length - page.length;
    droppedByPageBounds += pageDropped;
    advisories.push(...page);
    const pageTotal = parseNvdTotal(answer.payload);
    if (totalMatching === null) totalMatching = pageTotal;
    else if (pageTotal !== totalMatching) {
      stopReason = 'total-changed';
      break;
    }
    if (pageDropped > 0) {
      stopReason = 'oversized-page';
      break;
    }
    progress = {
      pagesCompleted: completedOffsets.length,
      advisoriesCollected: advisories.length,
      lastPageCount: page.length,
      lastPageRequested: resultsPerPage,
      totalMatching,
    };
    decision = nextNvdPage(progress, bounds);
    if (!decision.fetch) {
      stopReason = decision.reason;
      complete = decision.complete;
    }
  }

  const truncated = totalMatching === null || stopReason === 'total-changed' ? null : advisories.length < totalMatching;
  const pageCoverage: NvdPageCoverage = {
    attemptedOffsets,
    completedOffsets,
    pageSize: bounds.pageSize,
    maxPages: bounds.maxPages,
    maxAdvisories: bounds.maxAdvisories,
    totalMatching,
    complete,
    truncated,
    stopReason,
    ...(droppedByPageBounds > 0 ? { droppedByPageBounds } : {}),
  };
  const strategy = buildNvdQuery(component.name, component.version).strategy;
  // Only a COMPLETE empty CPE answer can implicate alternate identities. Failure or unknown coverage is not zero.
  const unchecked = strategy === 'cpe' && complete && advisories.length === 0 ? nvdCpeAlternates(component.name) : [];
  return {
    name: component.name,
    version: component.version,
    advisories,
    freshness: firstFreshness,
    matchedBy: strategy,
    uncheckedIdentities: unchecked,
    totalMatching,
    pageCoverage,
    pageFreshness,
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
  /** Optional forever: coverage includes empty and failed components that `components` intentionally omits. */
  pageCoverage?: ({ name: string; version: string } & NvdPageCoverage)[];
  /** Optional forever: attempts whose full reported match set was retrieved. */
  completed?: number;
  /** Optional forever: bounds, missing totals, or request failures prevented a complete component answer. */
  incomplete?: number;
}

/**
 * Correlate a set of components against NVD, capped to respect NVD's no-key rate limit. `delayMs` spaces the
 * requests (NVD asks for ~6 s between anonymous calls); it is 0 when an API key is present. The caller passes the
 * components OSV could not map, so NVD fills exactly OSV's coverage gap without re-querying what OSV already found.
 */
export async function queryNvdBatch(
  components: { name: string; version: string }[],
  cfg: ResearchConfig,
  opts: {
    cap?: number;
    delayMs?: number;
    cache?: CacheOptions;
    maxPages?: number;
    maxAdvisories?: number;
  } = {},
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
  const pageCoverage: ({ name: string; version: string } & NvdPageCoverage)[] = [];
  // Freshness is collected for every component, not only the ones with advisories: `components` keeps only the
  // latter, so this is the sole place the age of a clean answer survives.
  const freshness: (Freshness | null)[] = [];
  let queried = 0;
  let networkCalls = 0;
  let askedByCpe = 0;
  let completed = 0;
  const toQuery = ranked.slice(0, cap);
  const dropped = ranked.slice(cap);
  for (const c of toQuery) {
    const r = await queryNvd(c, cfg, cache, {
      ...(opts.maxPages === undefined ? {} : { maxPages: opts.maxPages }),
      ...(opts.maxAdvisories === undefined ? {} : { maxAdvisories: opts.maxAdvisories }),
      beforePage: async (willFetch) => {
        if (shouldPauseForRateLimit(networkCalls, willFetch, delayMs)) await sleep(delayMs);
        if (willFetch) networkCalls += 1;
      },
    });
    if (r.matchedBy === 'cpe') askedByCpe += 1;
    queried += 1;
    freshness.push(...(r.pageFreshness ?? [r.freshness]));
    if (r.pageCoverage) {
      pageCoverage.push({ name: r.name, version: r.version, ...r.pageCoverage });
      if (r.pageCoverage.complete) completed += 1;
    }
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
    pageCoverage,
    completed,
    incomplete: queried - completed,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
