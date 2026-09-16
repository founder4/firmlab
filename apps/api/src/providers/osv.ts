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
 * **Two bounds live here, and only one of them may cut anything that matters.** A component's advisory LISTING is
 * capped (`OSV_ADVISORY_CAP`) and a run's number of QUESTIONS is capped (`queryOsvBatch`'s `cap`). Neither may
 * decide the answer by arrival order: the listing is ranked most-severe first and reports `totalMatching`, so a
 * prefix cannot read as the set; and the question budget is spent only on components OSV can actually be asked
 * about, because counting the unmappable ones against it spent the whole budget on syft's alphabetically-early
 * kernel modules and asked nothing answerable — the defect `rankNvdCandidates` was written for, one source over.
 * The listing cap also may not cut CVE identifiers: `kev.ts` builds the known-exploited cross-reference out of
 * them, so `cveIds` carries every CVE in the answer including the advisories the listing dropped. Cutting there
 * would have quietly concluded that a CVE CISA lists as actively exploited is not in this firmware.
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
import { cvssV4Score } from './cvss-v4.js';

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

/**
 * Pure: the ecosystem an OSV question about this component would be asked under, or null when it cannot be asked
 * at all. `/v1/query` answers "is THIS version affected", so a component with no version is unanswerable even
 * when its type maps. Single source for that rule: `queryOsv` reports the unanswerable component honestly and
 * `queryOsvBatch` keeps it out of the query budget, and those two have to agree or the budget is again spent on
 * questions that were never asked.
 */
export function osvQueryEcosystem(component: { version: string; type: string }): string | null {
  return component.version ? osvEcosystem(component.type) : null;
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
  /**
   * The advisories this record was derived from — for a distro record, the CVE it tracks. Optional forever, as
   * results stored before it was read do not carry it.
   *
   * It is read because `aliases` turned out to be empty on every advisory this deployment has cached: OSV's
   * Debian records are `DEBIAN-CVE-2016-2781` with `upstream: ["CVE-2016-2781"]` and no alias at all, so a
   * collector looking only at ids and aliases found ZERO CVEs in 133 real advisories — and the KEV
   * cross-reference, which is built from them, had never once seen an OSV-discovered CVE.
   */
  upstream?: string[];
  summary: string;
  severity: string | null;
  references: string[];
}

/**
 * How many advisories one component's listing may carry. It bounds what is SHOWN and stored, never what was read:
 * `OsvAnswer.totalMatching` states how many the answer held and `cveIds` keeps every CVE in it, so the cap can
 * shorten a table but cannot shrink a set anything downstream reasons over. It bites on real answers — of the
 * questions this deployment has cached, curl 8.6.0 holds 63 advisories and busybox 56.
 */
export const OSV_ADVISORY_CAP = 50;

/**
 * The floor of each band a feed can NAME instead of scoring. Used only to place a named level on the same axis as
 * a computed base score; the number is never shown, and the floor rather than the middle keeps a named "HIGH"
 * from outranking a measured 7.5.
 */
const NAMED_SEVERITY_FLOOR: Record<string, number> = {
  critical: 9,
  high: 7,
  moderate: 4,
  medium: 4,
  low: 0.1,
  negligible: 0.1,
  none: 0,
};

/** CVSS v3 metric weights, verbatim from the specification's base-score equations. */
const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as const;
const AC = { L: 0.77, H: 0.44 } as const;
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 } as const;
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 } as const;
const UI = { N: 0.85, R: 0.62 } as const;
const CIA = { H: 0.56, L: 0.22, N: 0 } as const;

/** Round UP to one decimal, as CVSS 3.1 defines it. Float error is why this counts in tenths, not in units. */
function roundUp1(value: number): number {
  const tenths = Math.round(value * 100_000);
  return tenths % 10_000 === 0 ? tenths / 100_000 : (Math.floor(tenths / 10_000) + 1) / 10;
}

/**
 * Pure: the CVSS v3.0/v3.1 base score a vector string states, or null for anything else — a v4.0 vector (scored
 * by `cvssV4Score` in `cvss-v4.ts`, whose procedure shares no arithmetic with this one), a v2 vector, a
 * malformed one.
 *
 * This is arithmetic on what the vector says, not an estimate of it: the equations are the specification's, so
 * the number is the one NVD would print for the same string. Deriving it is what makes the listing rankable at
 * all — measured against the answers this deployment has cached, 117 of 121 graded advisories state their
 * severity ONLY as a v3 vector, and 0 as a named level.
 */
export function cvssV3BaseScore(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = new Map<string, string>();
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':');
    if (k && v) m.set(k, v);
  }
  const scopeChanged = m.get('S') === 'C';
  const av = AV[m.get('AV') as keyof typeof AV];
  const ac = AC[m.get('AC') as keyof typeof AC];
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[m.get('PR') as keyof typeof PR_UNCHANGED];
  const ui = UI[m.get('UI') as keyof typeof UI];
  const c = CIA[m.get('C') as keyof typeof CIA];
  const i = CIA[m.get('I') as keyof typeof CIA];
  const a = CIA[m.get('A') as keyof typeof CIA];
  if ([av, ac, pr, ui, c, i, a].some((x) => x === undefined) || (m.get('S') !== 'C' && m.get('S') !== 'U')) {
    return null;
  }
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  return roundUp1(Math.min(scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability, 10));
}

/**
 * Pure: the severity of one advisory as a single comparable number, or null when OSV stated none this module can
 * read — which is a REFUSAL to grade, never a zero. `parseOsvAnswer` keeps the ungraded ones rather than cutting
 * them, because a bound that dropped an advisory for being unreadable would be deciding the question it failed to
 * answer.
 *
 * Four shapes reach here, in the order they are tried: a CVSS v3 vector (what Debian and Alpine actually
 * publish), a CVSS v4.0 vector (what newer GHSA and distro records are starting to publish, and what this
 * deployment's cached corpus held four ungradable advisories of), a bare numeric base score (what a few feeds put
 * in the same field), and a named level (GHSA-backed ecosystems), placed on the axis at the floor of its band.
 *
 * v3 and v4 are tried in that order only because the version prefixes are disjoint — a string is at most one of
 * them, so neither can shadow the other, and the order carries no preference. The two scales are not the same
 * measurement and the specification says as much; placing both on one axis is what ranking a mixed listing costs,
 * and it is still better than leaving a graded advisory unranked.
 */
export function osvSeverityScore(severity: string | null): number | null {
  const s = severity?.trim();
  if (!s) return null;
  const vector = cvssV3BaseScore(s) ?? cvssV4Score(s);
  if (vector !== null) return vector;
  const named = NAMED_SEVERITY_FLOOR[s.toLowerCase()];
  if (named !== undefined) return named;
  const numeric = Number(s);
  return Number.isFinite(numeric) && numeric >= 0 && numeric <= 10 ? numeric : null;
}

/**
 * The identifier shape `kev.ts` can cross-reference. Anything else OSV lists as an id, alias or upstream (GHSA,
 * DSA, RUSTSEC, DEBIAN-CVE-…) has no KEV counterpart, so collecting it here would only grow the payload.
 */
const CVE_ID = /^CVE-\d{4}-\d+$/i;

export interface OsvAnswer {
  /** The listing: ranked most-severe first, then capped at `OSV_ADVISORY_CAP`. A prefix, never presented as more. */
  advisories: OsvAdvisory[];
  /** How many advisories the answer actually held — the denominator `advisories.length` cannot supply once cut. */
  totalMatching: number;
  /** Every CVE in the answer, including advisories the listing cut. The KEV cross-reference is built from this. */
  cveIds: string[];
}

/**
 * Pure: parse an OSV /v1/query response. Tolerates missing fields; a non-array payload is an empty answer, never
 * an error. Ranks BEFORE capping, and reads the whole array for the count and the CVE set either way.
 */
export function parseOsvAnswer(json: unknown): OsvAnswer {
  const vulns = (json as { vulns?: unknown[] })?.vulns;
  if (!Array.isArray(vulns)) return { advisories: [], totalMatching: 0, cveIds: [] };
  const strings = (value: unknown): string[] =>
    Array.isArray(value) ? value.filter((a): a is string => typeof a === 'string') : [];
  const all = vulns.map((raw) => {
    const v = raw as {
      id?: string;
      aliases?: string[];
      upstream?: string[];
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
      aliases: strings(v.aliases),
      upstream: strings(v.upstream),
      summary: String(v.summary ?? v.details ?? '').slice(0, 240),
      severity: sev,
      references: (v.references ?? [])
        .map((r) => String(r.url ?? ''))
        .filter(Boolean)
        .slice(0, 5),
    };
  });
  const cveIds = new Set<string>();
  for (const a of all) {
    for (const id of [a.id, ...a.aliases, ...a.upstream]) if (CVE_ID.test(id)) cveIds.add(id.toUpperCase());
  }
  // Selection, then order — two different rules, and conflating them is what the cap used to get wrong.
  //
  // Graded advisories compete on their score, most severe first, stable within a score so re-asking the same
  // question does not reshuffle the table. Advisories OSV did not grade in a form this module reads (no severity
  // at all, a CVSS v2 vector, a scheme newer than v4.0) do NOT compete: they are kept ahead of the graded ones
  // the cap would cut, because dropping an advisory for being unreadable is the bound answering a question it
  // could not read. They are shown last all the same — the reader's first badges should be the severities that
  // are known.
  const scored = all.map((a, i) => ({ a, i, score: osvSeverityScore(a.severity) }));
  const graded = scored
    .filter((x): x is typeof x & { score: number } => x.score !== null)
    .sort((x, y) => y.score - x.score || x.i - y.i);
  const ungraded = scored.filter((x) => x.score === null).slice(0, OSV_ADVISORY_CAP);
  const advisories = [
    ...graded.slice(0, Math.max(0, OSV_ADVISORY_CAP - ungraded.length)).map((x) => x.a),
    ...ungraded.map((x) => x.a),
  ];
  return { advisories, totalMatching: all.length, cveIds: [...cveIds] };
}

export interface OsvComponentResult {
  name: string;
  version: string;
  ecosystem: string | null;
  queryable: boolean;
  /** Ranked most-severe first and capped at `OSV_ADVISORY_CAP`; read `totalMatching` before calling it the set. */
  advisories: OsvAdvisory[];
  /**
   * How many advisories OSV's answer held, which is not always how many are listed above. Optional forever: a
   * result stored before this field existed cannot supply it, and its ABSENCE is not a claim that the list is
   * complete — a reader that has no total must say so rather than reuse `advisories.length` as one.
   */
  totalMatching?: number;
  /**
   * Every CVE in the answer, including the advisories the listing cut. Optional for the same reason; where it is
   * missing, `kev.ts` falls back to the listed advisories and the cross-reference is as complete as they are.
   */
  cveIds?: string[];
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
  const ecosystem = osvQueryEcosystem(component);
  // `base.ecosystem` stays the type mapping, not the query one: a versionless component whose type OSV knows is a
  // different thing from one OSV cannot place at all, and the UI shows the difference.
  const base = { name: component.name, version: component.version, ecosystem: osvEcosystem(component.type) };
  if (!ecosystem) {
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
  // No answer means no totals either: a failed request leaves both fields absent rather than reporting a zero
  // that would read as "OSV holds nothing for this component".
  const parsed = answer.freshness ? parseOsvAnswer(answer.payload) : null;
  return {
    ...base,
    queryable: true,
    advisories: parsed?.advisories ?? [],
    ...(parsed ? { totalMatching: parsed.totalMatching, cveIds: parsed.cveIds } : {}),
    freshness: answer.freshness,
  };
}

export interface OsvBatchResult {
  queried: number;
  /**
   * Unique components OSV cannot be asked about at all — no ecosystem mapping, or no version. Counted over every
   * one of them, not only those the old cap happened to reach, so the number means the same thing on a 2,000-package
   * rootfs as on a 20-package one.
   */
  skipped: number;
  /**
   * Answerable components the query cap dropped — reported, never silently absent. Distinct from `skipped`: one
   * is a question OSV could not be asked, the other a question this run chose not to ask.
   */
  notQueried: number;
  /** What the cap dropped and by what rule. Empty when it dropped nothing. */
  notQueriedRule: string;
  withAdvisories: number;
  /** Advisories LISTED across `components`. `truncated` says where that is a prefix of what OSV returned. */
  totalAdvisories: number;
  components: OsvComponentResult[];
  /** How many of the `queried` answers came off the disk (those sent nothing) and how old the oldest one was. */
  cache: CacheSummary;
  /** Components whose advisory list is a PREFIX of OSV's answer, with both numbers. Empty when nothing was cut. */
  truncated: { name: string; version: string; shown: number; total: number }[];
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
  // Partition before capping. The cap used to be taken over `unique` whole, so a component OSV cannot be asked
  // about consumed a slot in a budget of QUESTIONS — and arrival order is syft's, which is alphabetical. On an
  // OpenWRT rootfs of ~2,000 packages that spent all 80 slots on unmappable kernel modules and asked nothing
  // answerable, the same shape `rankNvdCandidates` was written for. An unmappable component costs no request, so
  // it now costs no budget: every one of them is counted as skipped, and the cap bounds queries alone.
  const queryable = unique.filter((p) => osvQueryEcosystem(p) !== null);
  const skipped = unique.length - queryable.length;
  const toQuery = queryable.slice(0, cap);
  const notQueried = queryable.length - toQuery.length;

  const results: OsvComponentResult[] = [];
  const truncated: { name: string; version: string; shown: number; total: number }[] = [];
  // Freshness is collected for EVERY queried component, not only the ones that turned out to have advisories —
  // `components` keeps only the latter, so the summary is the sole place the age of a clean answer survives.
  const freshness: (Freshness | null)[] = [];
  let queried = 0;
  for (const p of toQuery) {
    const r = await queryOsv(p, cfg, cache);
    queried += 1;
    freshness.push(r.freshness);
    if (r.advisories.length > 0) results.push(r);
    if (r.totalMatching !== undefined && r.totalMatching > r.advisories.length) {
      truncated.push({ name: r.name, version: r.version, shown: r.advisories.length, total: r.totalMatching });
    }
  }
  return {
    queried,
    skipped,
    notQueried,
    notQueriedRule: describeOsvDrop(notQueried, cap),
    withAdvisories: results.length,
    totalAdvisories: results.reduce((n, r) => n + r.advisories.length, 0),
    components: results,
    cache: summarizeFreshness(freshness),
    truncated,
  };
}

/**
 * Pure: state what the query cap dropped and by which rule.
 *
 * Unlike NVD's, this drop has no answerability axis to rank by — every candidate that reaches here carries an
 * ecosystem and a version, so OSV can answer all of them equally well and there is nothing to prefer. What is
 * left is arrival order, which is syft's; a bound that cannot rank its input has to at least say that is what it
 * did, and say that the advisory count therefore covers `cap` components rather than the SBOM.
 */
export function describeOsvDrop(dropped: number, cap: number): string {
  if (dropped <= 0) return '';
  return `${dropped} ecosystem-mapped component(s) went unqueried: the per-run cap of ${cap} questions was reached. Every candidate here is equally answerable, so the ones asked are simply the first ${cap} in the order the SBOM lists them — the advisory count covers those, not the whole SBOM.`;
}
