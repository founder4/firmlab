/**
 * OSV.dev provider (Phase 5) — correlate the firmware's SBOM against PUBLISHED vulnerability advisories. OSV is a
 * free, no-auth, authoritative aggregator; it's the cleanest first external source. Egress is minimal: only a
 * component's name, version and ecosystem leave the machine — never firmware bytes. Every request goes through the
 * allowlisted fetch, so only api.osv.dev is ever contacted.
 *
 * Honesty: a published advisory for a component that is PRESENT is a lead, not a confirmed vulnerability of THIS
 * image — reachability is decided per-image (the corpus / emulation), never by a version-string match. The request
 * builder and response parser are pure and unit-tested; only queryOsv touches the network.
 */
import { type ResearchConfig, allowlistedFetch } from '../research/config.js';

export const OSV_ENDPOINT = 'https://api.osv.dev/v1/query';

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
}

/** Query OSV for one component. Components with no OSV ecosystem mapping are reported as not-queryable (honest). */
export async function queryOsv(
  component: { name: string; version: string; type: string },
  cfg: ResearchConfig,
): Promise<OsvComponentResult> {
  const ecosystem = osvEcosystem(component.type);
  if (!ecosystem || !component.version) {
    return { name: component.name, version: component.version, ecosystem, queryable: false, advisories: [] };
  }
  const res = await allowlistedFetch(OSV_ENDPOINT, cfg, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(buildOsvQuery(component.name, component.version, ecosystem)),
  });
  if (!res.ok) return { name: component.name, version: component.version, ecosystem, queryable: true, advisories: [] };
  const advisories = parseOsvResponse(await res.json());
  return { name: component.name, version: component.version, ecosystem, queryable: true, advisories };
}

export interface OsvBatchResult {
  queried: number;
  skipped: number;
  withAdvisories: number;
  totalAdvisories: number;
  components: OsvComponentResult[];
}

/** Correlate a whole SBOM against OSV. Dedupes, caps the number of queries, and reports what it could/couldn't do. */
export async function queryOsvBatch(
  packages: { name: string; version: string; type: string }[],
  cfg: ResearchConfig,
  cap = 80,
): Promise<OsvBatchResult> {
  const seen = new Set<string>();
  const unique = packages.filter((p) => {
    const k = `${p.name}@${p.version}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const results: OsvComponentResult[] = [];
  let queried = 0;
  let skipped = 0;
  for (const p of unique.slice(0, cap)) {
    const r = await queryOsv(p, cfg);
    if (r.queryable) queried += 1;
    else skipped += 1;
    if (r.advisories.length > 0) results.push(r);
  }
  return {
    queried,
    skipped,
    withAdvisories: results.length,
    totalAdvisories: results.reduce((n, r) => n + r.advisories.length, 0),
    components: results,
  };
}
