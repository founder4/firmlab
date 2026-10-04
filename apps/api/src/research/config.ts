/**
 * External-intelligence track config (Phase 5). This is the ONE place FirmLab's analysis is allowed to touch the
 * internet, and it is gated by its OWN flag — `FIRMLAB_RESEARCH`, deliberately separate from `FIRMLAB_AGENT` —
 * because it changes the privacy posture.
 *
 * **On by default, by operator decision (2026-10-04).** Trusted outbound research is habitually authorised on this
 * workbench, so an unset `FIRMLAB_RESEARCH` now means ON (`defaultOn` in `flags.ts`). It used to mean off, and the
 * difference matters for anyone reading an old compose file: absence is no longer an opt-out. The opt-out is a
 * STATED value — `FIRMLAB_RESEARCH=0` in the environment or a stored `0` from Settings › Privacy — and a stated
 * value always beats the default, with a stored override beating the environment (see `resolveFlags`). With it
 * off, `loadResearchConfig()` returns null and nothing here ever makes a network request.
 *
 * What the default does NOT change, and what makes it defensible: every outbound request is checked against a
 * host ALLOWLIST; only derived data (component names/versions, vendor strings) leaves — never raw firmware bytes;
 * the egress ledger (research/egress.ts) declares a ceiling before a run and reconciles it after; a run is still
 * started per image, never implicitly; and the online hash lookup — which sends hashes recovered FROM the
 * firmware — stays behind its own second opt-in, as does the capture lane.
 */
import { decideFlag, effectiveEnv } from '../flags.js';
import { linkJobCancellation } from '../job-cancellation.js';

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
   * changed privacy posture gets a separate flag. Off by default even though the research track now defaults on;
   * when off, no hash ever leaves and the lookup hosts are not added to the allowlist.
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
 * What every caller says when the track is off. It lives here, beside the gate itself, because both the route and
 * the runner have to say it and they had already drifted apart into two different sentences. It names the lane as
 * the Settings toggle names it, so the message points at a switch the operator can actually find, and keeps the
 * env var for the deployment that has no UI. Since the lane is on by default, off always means somebody stated a
 * value, and the sentence says so rather than implying the operator forgot to opt in.
 */
export const RESEARCH_DISABLED =
  'External intelligence was switched off (it is on by default) — turn it back on in Settings › Privacy, or ' +
  'set FIRMLAB_RESEARCH=1 (any other stated value, such as 0, keeps it off)';

/**
 * Resolve the research config, or null when the track is off. On unless a stated value says otherwise —
 * `decideFlag` honours the catalogue's `defaultOn`, so this and the Settings panel cannot disagree about absence.
 */
export function loadResearchConfig(env: NodeJS.ProcessEnv = effectiveEnv()): ResearchConfig | null {
  if (!decideFlag('FIRMLAB_RESEARCH', env).enabled) return null;
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
  // A cancelled job aborts this request — and its body read, since the link stays live after we return — promptly,
  // rather than waiting out `timeoutMs`. Outside a job (shared capability discovery) the signal is the timeout
  // controller alone, so one aborted job cannot abort or poison a shared lookup. The timeout, allowlist and error
  // semantics are unchanged: an abort still surfaces as the same AbortError this call already threw on timeout.
  const signal = linkJobCancellation(controller.signal) ?? controller.signal;
  try {
    return await fetch(url, { ...init, signal });
  } finally {
    clearTimeout(timer);
  }
}
