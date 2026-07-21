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
 */
import { type ResearchConfig, allowlistedFetch } from '../research/config.js';

export const NVD_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

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
}

/** Query NVD for one component by keyword. An NVD API key (env, passed via cfg) lifts the rate limit but is optional. */
export async function queryNvd(
  component: { name: string; version: string },
  cfg: ResearchConfig,
): Promise<NvdComponentResult> {
  const url = buildNvdQuery(component.name, component.version);
  const headers: Record<string, string> = {};
  if (cfg.nvdApiKey) headers.apiKey = cfg.nvdApiKey;
  const res = await allowlistedFetch(url, cfg, { headers });
  if (!res.ok) return { name: component.name, version: component.version, advisories: [] };
  return { name: component.name, version: component.version, advisories: parseNvdResponse(await res.json()) };
}

export interface NvdBatchResult {
  queried: number;
  /** Candidate components not queried because of the rate-limit cap — reported, never silently dropped. */
  notQueried: number;
  withAdvisories: number;
  totalAdvisories: number;
  components: NvdComponentResult[];
}

/**
 * Correlate a set of components against NVD, capped to respect NVD's no-key rate limit. `delayMs` spaces the
 * requests (NVD asks for ~6 s between anonymous calls); it is 0 when an API key is present. The caller passes the
 * components OSV could not map, so NVD fills exactly OSV's coverage gap without re-querying what OSV already found.
 */
export async function queryNvdBatch(
  components: { name: string; version: string }[],
  cfg: ResearchConfig,
  opts: { cap?: number; delayMs?: number } = {},
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

  const results: NvdComponentResult[] = [];
  let queried = 0;
  const toQuery = unique.slice(0, cap);
  for (const [i, c] of toQuery.entries()) {
    if (i > 0 && delayMs > 0) await sleep(delayMs);
    const r = await queryNvd(c, cfg);
    queried += 1;
    if (r.advisories.length > 0) results.push(r);
  }
  return {
    queried,
    notQueried: Math.max(0, unique.length - toQuery.length),
    withAdvisories: results.length,
    totalAdvisories: results.reduce((n, r) => n + r.advisories.length, 0),
    components: results,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
