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
 */
import { type ResearchConfig, allowlistedFetch } from '../research/config.js';

export const KEV_ENDPOINT = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

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
  reason?: string;
}

/** Download the KEV catalog (allowlisted) and cross-reference the discovered CVEs locally. */
export async function fetchAndMatchKev(cveIds: Iterable<string>, cfg: ResearchConfig): Promise<KevResult> {
  const ids = [...cveIds];
  if (ids.length === 0) return { checked: false, catalogSize: 0, matches: [], reason: 'no CVEs discovered to check' };
  try {
    const res = await allowlistedFetch(KEV_ENDPOINT, cfg);
    if (!res.ok) return { checked: false, catalogSize: 0, matches: [], reason: `KEV feed HTTP ${res.status}` };
    const catalog = parseKevCatalog(await res.json());
    return { checked: true, catalogSize: catalog.length, matches: crossReferenceKev(ids, catalog) };
  } catch (err) {
    return { checked: false, catalogSize: 0, matches: [], reason: err instanceof Error ? err.message : String(err) };
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
