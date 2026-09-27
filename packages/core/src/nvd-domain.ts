/**
 * NVD domain — the pure, portable half of the NVD provider: which question a component is asked (curated CPE
 * identity or keyword), how candidates are ranked before the rate-limit cap truncates, how pagination decides
 * its next page and when it may call a set complete, how a CVE-API 2.0 response is read, and how a dropped
 * candidate set is described. Nothing here touches the network, the cache or the clock; `apps/api`'s
 * `providers/nvd.ts` owns the allowlisted fetch, the on-disk cache and the batch loop, and binds these decisions.
 *
 * Why the curated table and every bound look the way they do is documented at each declaration below and in the
 * provider's own header, which travels with the I/O. Moving them here changed their home, not their values.
 */

export const NVD_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

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

/**
 * Hard per-component retrieval bounds. Kernel CPEs can match thousands of CVEs, so pagination must have a ceiling
 * just as the component queue does. Four pages closes the common 20/50-row first-page truncation without turning
 * one component into an unbounded number of NVD requests; the coverage record below makes the remaining prefix
 * explicit.
 */
export const NVD_MAX_PAGES = 4;
export const NVD_MAX_ADVISORIES = 200;

export interface NvdPaginationBounds {
  pageSize: number;
  maxPages: number;
  maxAdvisories: number;
}

export interface NvdPaginationProgress {
  pagesCompleted: number;
  advisoriesCollected: number;
  lastPageCount: number;
  lastPageRequested: number;
  totalMatching: number | null;
}

export type NvdPaginationStopReason =
  | 'complete'
  | 'page-cap'
  | 'advisory-cap'
  | 'oversized-page'
  | 'missing-total'
  | 'short-page'
  | 'empty-page'
  | 'total-changed'
  | 'request-failed';

export type NvdPageDecision =
  | { fetch: true; startIndex: number; resultsPerPage: number }
  | { fetch: false; complete: boolean; reason: Exclude<NvdPaginationStopReason, 'request-failed'> };

/** Pure: normalize caller-supplied test/smaller bounds without ever permitting the production hard caps to grow. */
export function resolveNvdPaginationBounds(
  requested: { maxPages?: number; maxAdvisories?: number } = {},
): NvdPaginationBounds {
  const bounded = (value: number | undefined, hardCap: number): number => {
    if (value === undefined || !Number.isFinite(value)) return hardCap;
    return Math.max(1, Math.min(hardCap, Math.floor(value)));
  };
  return {
    pageSize: NVD_PAGE_SIZE,
    maxPages: bounded(requested.maxPages, NVD_MAX_PAGES),
    maxAdvisories: bounded(requested.maxAdvisories, NVD_MAX_ADVISORIES),
  };
}

/**
 * Pure: decide whether another page may be requested and at which offset. A missing denominator, an empty page
 * before the denominator is reached, or either hard cap stops retrieval as INCOMPLETE; only collecting the stated
 * `totalMatching` count is complete.
 */
export function nextNvdPage(
  progress: NvdPaginationProgress,
  bounds: NvdPaginationBounds = resolveNvdPaginationBounds(),
): NvdPageDecision {
  if (progress.pagesCompleted === 0) {
    return { fetch: true, startIndex: 0, resultsPerPage: Math.min(bounds.pageSize, bounds.maxAdvisories) };
  }
  if (progress.totalMatching === null) return { fetch: false, complete: false, reason: 'missing-total' };
  if (progress.advisoriesCollected >= progress.totalMatching) {
    return { fetch: false, complete: true, reason: 'complete' };
  }
  if (progress.lastPageCount < progress.lastPageRequested) {
    return {
      fetch: false,
      complete: false,
      reason: progress.lastPageCount === 0 ? 'empty-page' : 'short-page',
    };
  }
  if (progress.pagesCompleted >= bounds.maxPages) return { fetch: false, complete: false, reason: 'page-cap' };
  if (progress.advisoriesCollected >= bounds.maxAdvisories) {
    return { fetch: false, complete: false, reason: 'advisory-cap' };
  }
  return {
    fetch: true,
    startIndex: progress.advisoriesCollected,
    resultsPerPage: Math.min(
      bounds.pageSize,
      progress.totalMatching - progress.advisoriesCollected,
      bounds.maxAdvisories - progress.advisoriesCollected,
    ),
  };
}

export function buildNvdQuery(
  name: string,
  version: string,
  resultsPerPage = NVD_PAGE_SIZE,
  startIndex = 0,
): { url: string; strategy: NvdMatchStrategy } {
  const cpe = nvdCpeFor(name);
  const v = nvdVersion(version);
  const normalizedName = name.trim().toLowerCase();
  const params = cpe
    ? new URLSearchParams({
        virtualMatchString: `cpe:2.3:${nvdCpePart(name)}:${cpe}${v ? `:${v}` : ''}`,
        ...(normalizedName === 'linux-kernel' ? { sourceIdentifier: LINUX_KERNEL_CNA_SOURCE } : {}),
        resultsPerPage: String(resultsPerPage),
        ...(startIndex > 0 ? { startIndex: String(startIndex) } : {}),
      })
    : new URLSearchParams({
        keywordSearch: v ? `${name} ${v}` : name,
        resultsPerPage: String(resultsPerPage),
        ...(startIndex > 0 ? { startIndex: String(startIndex) } : {}),
      });
  return { url: `${NVD_ENDPOINT}?${params.toString()}`, strategy: cpe ? 'cpe' : 'keyword' };
}

/**
 * Pure: the cache key for one NVD question — the request URL itself, which is exactly what is asked and nothing
 * more (the API key travels in a header, so it never lands in a key or a filename). Keying on the URL means a
 * change to the query, `resultsPerPage` included, invalidates the entry rather than reusing the answer to a
 * different question.
 */
export function nvdCacheKey(name: string, version: string, startIndex = 0, resultsPerPage = NVD_PAGE_SIZE): string {
  return buildNvdQuery(name, version, resultsPerPage, startIndex).url;
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

/**
 * Pure: pull the highest-priority CVSS severity/score NVD attached (v4.0 → v3.1 → v3.0 → v2), tolerating gaps.
 *
 * Newest first, which is NVD's own presentation order and the only one that does not throw away the grading a CNA
 * took the trouble to publish. The chain matters more than the head of it: NVD carries `cvssMetricV40` on a small
 * and growing minority of records, so the overwhelmingly common case is a response with no v4 metric at all, and
 * that case must behave exactly as it did before — which is why each rung is read independently rather than
 * folded into one expression. NVD scores its own vectors, so nothing here recomputes one; `cvss-v4.ts` exists for
 * the feeds that publish a vector and no score.
 *
 * The two scales are not interchangeable and this returns no version label, so a caller ranking a mixed list is
 * comparing measurements taken with different instruments. That is the same compromise `osvSeverityScore` makes,
 * and for the same reason: an ungraded advisory ranks worse than an imperfectly graded one.
 */
function extractSeverity(metrics: NvdCveMetrics | undefined): { severity: string | null; score: number | null } {
  const v40 = metrics?.cvssMetricV40?.[0]?.cvssData;
  const v31 = metrics?.cvssMetricV31?.[0]?.cvssData;
  const v30 = metrics?.cvssMetricV30?.[0]?.cvssData;
  const v2 = metrics?.cvssMetricV2?.[0];
  if (v40) return { severity: v40.baseSeverity ?? null, score: v40.baseScore ?? null };
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
  cvssMetricV40?: { cvssData?: NvdCvssData }[];
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
  // Parse the response NVD actually returned. The caller owns the request/page bound and must measure any cut;
  // clipping here would erase the denominator before coverage can report it.
  return vulns.map((raw) => {
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

export interface NvdPageCoverage {
  attemptedOffsets: number[];
  completedOffsets: number[];
  pageSize: number;
  maxPages: number;
  maxAdvisories: number;
  totalMatching: number | null;
  complete: boolean;
  /** Null means the response omitted the denominator, so truncation cannot honestly be decided either way. */
  truncated: boolean | null;
  stopReason: NvdPaginationStopReason;
  /** Optional forever: entries returned beyond the requested page bound and therefore not retained. */
  droppedByPageBounds?: number;
}

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
