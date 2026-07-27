/**
 * External-intelligence track config (Phase 5). This is the ONE place FirmLab is allowed to touch the internet,
 * and it is gated by its OWN flag — `FIRMLAB_RESEARCH`, deliberately separate from `FIRMLAB_AGENT` — because it
 * changes the privacy posture fundamentally. With the flag unset, `loadResearchConfig()` returns null and nothing
 * here ever makes a network request; FirmLab stays local-only, exactly as before.
 *
 * Every outbound request is checked against a host ALLOWLIST. Only derived data (component names/versions, vendor
 * strings, hashes) may leave — never raw firmware bytes; the egress ledger (research/egress.ts) makes that
 * explicit before a run.
 */

export interface ResearchConfig {
  /** Hosts this deployment is permitted to reach for external intelligence. Nothing else is contacted. */
  allowlist: string[];
  /** Per-request timeout for external calls. */
  timeoutMs: number;
  /** Optional NVD API key (env `NVD_API_KEY`) — lifts NVD's anonymous rate limit; unset → conservative caps. */
  nvdApiKey?: string;
  /**
   * Whether the online password-hash lookup provider is armed. This is a SECOND, independent opt-in on top of
   * FIRMLAB_RESEARCH (env `FIRMLAB_HASH_LOOKUP`): sending a password hash to a third-party lookup DB is a bigger
   * privacy step than sending a component name+version, so it gets its own flag — matching the convention that a
   * changed privacy posture gets a separate flag. Off by default even when the research track is on; when off, no
   * hash ever leaves and the lookup hosts are not added to the allowlist.
   */
  hashLookup: boolean;
}

// The published-vulnerability + exploited-in-the-wild sources FirmLab correlates against. Each is a free,
// no-auth, authoritative aggregator; nothing else is contacted unless the operator extends the allowlist.
const DEFAULT_ALLOWLIST = ['api.osv.dev', 'services.nvd.nist.gov', 'www.cisa.gov'];

// The online hash-lookup DBs, added to the allowlist ONLY when FIRMLAB_HASH_LOOKUP is set. Both are free, no-auth
// reverse-hash lookups over precomputed/wordlist tables (no cracking is performed on-box or requested from them).
export const HASH_LOOKUP_HOSTS = ['www.nitrxgen.net', 'weakpass.com'];

/**
 * Resolve the research config, or null when the track is off. Gated by FIRMLAB_RESEARCH so the deterministic,
 * local-only workbench is the default and no external host is contacted unless the operator opts in.
 */
export function loadResearchConfig(env: NodeJS.ProcessEnv = process.env): ResearchConfig | null {
  if (env.FIRMLAB_RESEARCH !== '1') return null;
  const extra = (env.FIRMLAB_RESEARCH_ALLOWLIST ?? '')
    .split(',')
    .map((h) => h.trim())
    .filter(Boolean);
  const hashLookup = env.FIRMLAB_HASH_LOOKUP === '1';
  return {
    allowlist: [...new Set([...DEFAULT_ALLOWLIST, ...(hashLookup ? HASH_LOOKUP_HOSTS : []), ...extra])],
    timeoutMs: Math.max(1000, Number(env.FIRMLAB_RESEARCH_TIMEOUT_MS ?? 15000)),
    ...(env.NVD_API_KEY ? { nvdApiKey: env.NVD_API_KEY } : {}),
    hashLookup,
  };
}

/** Pure: is a URL's host on the allowlist? The single choke point every external fetch must pass. */
export function isAllowed(url: string, allowlist: string[]): boolean {
  try {
    const host = new URL(url).hostname;
    return allowlist.includes(host);
  } catch {
    return false;
  }
}

/**
 * A fetch that refuses any host not on the allowlist — the enforcement point for "FirmLab only talks to sources
 * you approved". Throws before opening a socket to a disallowed host.
 */
export async function allowlistedFetch(url: string, cfg: ResearchConfig, init?: RequestInit): Promise<Response> {
  if (!isAllowed(url, cfg.allowlist)) {
    throw new Error(`Blocked: ${new URL(url).hostname} is not on the research allowlist`);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
