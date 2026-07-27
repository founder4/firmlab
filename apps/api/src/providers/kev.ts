/**
 * CISA KEV provider (Phase 5, external-intelligence source #3) — the Known Exploited Vulnerabilities catalog. KEV
 * is the authoritative, free, single-file list of CVEs that are KNOWN to be exploited in the wild. It is the
 * highest-value prioritization signal in this track: of all the published advisories OSV + NVD surface for present
 * components, KEV tells us which CVEs attackers are ACTUALLY using.
 *
 * Privacy note: unlike OSV/NVD, KEV sends NOTHING about the firmware — it just downloads the public catalog, and
 * the cross-reference against the discovered CVEs happens entirely locally. So the egress ledger records it as a
 * one-way download.
 *
 * Honesty: KEV membership means the CVE is exploited SOMEWHERE globally — it does NOT mean it is reachable in THIS
 * image. It raises priority; it never confirms reachability (that stays per-image). The parser + cross-reference
 * are pure and unit-tested; only fetchKevCatalog touches the network.
 *
 * The catalog goes through the on-disk cache (research/cache.ts): it is a single multi-megabyte file that every
 * image in the corpus needs, so downloading it once a day instead of once a scan is the whole point. It is also
 * where staleness bites hardest — KEV grows by CVEs attackers started using THIS week, so a catalog served without
 * its age would answer "not known-exploited" on evidence that had since changed its mind. Hence `freshness` on the
 * result: whichever way the answer came, it states when the catalog behind it was pulled from CISA.
 */
import { type CacheOptions, type Freshness, cachedFetch } from '../research/cache.js';
import { type ResearchConfig, allowlistedFetch } from '../research/config.js';

export const KEV_ENDPOINT = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** Cache namespace for the KEV catalog — one entry, keyed by the feed URL, shared by every image. */
export const KEV_CACHE_SOURCE = 'kev';

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  /** CISA's flag for ransomware-campaign use ("Known" / "Unknown"). */
  knownRansomware: string;
}

/** Pure: parse the KEV JSON feed into a normalized entry list. Tolerates missing fields / a non-array payload. */
export function parseKevCatalog(json: unknown): KevEntry[] {
  const vulns = (json as { vulnerabilities?: unknown[] })?.vulnerabilities;
  if (!Array.isArray(vulns)) return [];
  return vulns
    .map((raw) => {
      const v = raw as {
        cveID?: string;
        vendorProject?: string;
        product?: string;
        vulnerabilityName?: string;
        dateAdded?: string;
        shortDescription?: string;
        knownRansomwareCampaignUse?: string;
      };
      return {
        cveID: String(v.cveID ?? '').toUpperCase(),
        vendorProject: String(v.vendorProject ?? ''),
        product: String(v.product ?? ''),
        vulnerabilityName: String(v.vulnerabilityName ?? ''),
        dateAdded: String(v.dateAdded ?? ''),
        shortDescription: String(v.shortDescription ?? '').slice(0, 240),
        knownRansomware: String(v.knownRansomwareCampaignUse ?? 'Unknown'),
      };
    })
    .filter((e) => /^CVE-\d{4}-\d+$/.test(e.cveID));
}

export interface KevMatch extends KevEntry {}

/**
 * Pure: cross-reference a set of discovered CVE IDs against the KEV catalog. Returns the KEV entries that match —
 * these are the "actively exploited" subset of everything OSV + NVD surfaced. Case-insensitive on the CVE ID.
 */
export function crossReferenceKev(cveIds: Iterable<string>, catalog: KevEntry[]): KevMatch[] {
  const wanted = new Set<string>();
  for (const id of cveIds) if (id) wanted.add(id.toUpperCase());
  return catalog.filter((e) => wanted.has(e.cveID));
}

export interface KevResult {
  /** Whether the catalog was fetched successfully (honest: a failed download → checked:false, no fabrication). */
  checked: boolean;
  /** Total entries in the downloaded catalog (0 when not checked). */
  catalogSize: number;
  /** The discovered CVEs that are in KEV — known exploited in the wild. */
  matches: KevMatch[];
  /** When the catalog behind this verdict was fetched from CISA, and whether it came off the wire or the disk. */
  freshness: Freshness | null;
  reason?: string;
}

/**
 * Download the KEV catalog (allowlisted, cached) and cross-reference the discovered CVEs locally. A fresh cached
 * catalog is used as-is; past the TTL it is downloaded again rather than served, and an HTTP error is reported the
 * way it always was — never stored, never substituted with the previous catalog, because "no known-exploited CVEs"
 * read out of a catalog we could not refresh is a claim nobody made.
 */
export async function fetchAndMatchKev(
  cveIds: Iterable<string>,
  cfg: ResearchConfig,
  cache: CacheOptions = {},
): Promise<KevResult> {
  const ids = [...cveIds];
  if (ids.length === 0) {
    return { checked: false, catalogSize: 0, matches: [], freshness: null, reason: 'no CVEs discovered to check' };
  }
  try {
    const answer = await cachedFetch(
      KEV_CACHE_SOURCE,
      KEV_ENDPOINT,
      async () => {
        const res = await allowlistedFetch(KEV_ENDPOINT, cfg);
        // Thrown, not returned as a non-answer, so the reason reaches the caller verbatim — as it did before.
        if (!res.ok) throw new Error(`KEV feed HTTP ${res.status}`);
        return await res.json();
      },
      cache,
    );
    if (!answer.freshness) {
      return { checked: false, catalogSize: 0, matches: [], freshness: null, reason: 'KEV feed returned no catalog' };
    }
    const catalog = parseKevCatalog(answer.payload);
    return {
      checked: true,
      catalogSize: catalog.length,
      matches: crossReferenceKev(ids, catalog),
      freshness: answer.freshness,
    };
  } catch (err) {
    return {
      checked: false,
      catalogSize: 0,
      matches: [],
      freshness: null,
      reason: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Pure: collect the CVE IDs from the OSV + NVD results (OSV advisories carry CVEs as aliases or the id itself; NVD
 * advisory ids ARE CVEs). Deduped, upper-cased — the input to the KEV cross-reference.
 */
export function collectCveIds(
  osvComponents: { advisories: { id: string; aliases: string[] }[] }[],
  nvdComponents: { advisories: { id: string }[] }[],
): string[] {
  const out = new Set<string>();
  const add = (s: string): void => {
    if (/^CVE-\d{4}-\d+$/i.test(s)) out.add(s.toUpperCase());
  };
  for (const c of osvComponents)
    for (const a of c.advisories) {
      add(a.id);
      for (const al of a.aliases) add(al);
    }
  for (const c of nvdComponents) for (const a of c.advisories) add(a.id);
  return [...out];
}
