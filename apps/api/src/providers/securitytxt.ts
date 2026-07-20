/**
 * security.txt discovery (Phase 5.3) — find a vendor's responsible-disclosure contact from RFC 9116
 * (/.well-known/security.txt). This is the "how to report" half of disclosure assist. It respects the research
 * allowlist strictly: a vendor domain is contacted ONLY if the operator added it to FIRMLAB_RESEARCH_ALLOWLIST;
 * otherwise the domain is reported as "not checked (add it to the allowlist)" — no surprise egress to arbitrary
 * hosts. FirmLab drafts the report; the human sends it.
 *
 * The parser is pure and unit-tested; fetchSecurityTxt is the thin, allowlist-guarded network call.
 */
import { type ResearchConfig, allowlistedFetch, isAllowed } from '../research/config.js';

export interface SecurityTxt {
  domain: string;
  checked: boolean;
  found: boolean;
  reason?: string;
  contact: string[];
  policy: string[];
  encryption: string[];
}

/** Pure: parse an RFC 9116 security.txt body into its actionable fields (case-insensitive keys). */
export function parseSecurityTxt(domain: string, text: string): SecurityTxt {
  const contact: string[] = [];
  const policy: string[] = [];
  const encryption: string[] = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$/);
    if (!m) continue;
    const key = (m[1] as string).toLowerCase();
    const val = m[2] as string;
    if (key === 'contact') contact.push(val);
    else if (key === 'policy') policy.push(val);
    else if (key === 'encryption') encryption.push(val);
  }
  return { domain, checked: true, found: contact.length > 0, contact, policy, encryption };
}

/** Fetch a domain's security.txt — only if the domain is allowlisted. Honest not-checked / not-found otherwise. */
export async function fetchSecurityTxt(domain: string, cfg: ResearchConfig): Promise<SecurityTxt> {
  const empty = (checked: boolean, found: boolean, reason?: string): SecurityTxt => ({
    domain,
    checked,
    found,
    ...(reason ? { reason } : {}),
    contact: [],
    policy: [],
    encryption: [],
  });
  const url = `https://${domain}/.well-known/security.txt`;
  if (!isAllowed(url, cfg.allowlist)) {
    return empty(false, false, `add ${domain} to FIRMLAB_RESEARCH_ALLOWLIST to check its security.txt`);
  }
  try {
    const res = await allowlistedFetch(url, cfg);
    if (!res.ok) return empty(true, false, `no security.txt (HTTP ${res.status})`);
    return parseSecurityTxt(domain, await res.text());
  } catch (err) {
    return empty(true, false, err instanceof Error ? err.message : String(err));
  }
}
