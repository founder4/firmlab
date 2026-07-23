/**
 * hashlookup provider (Phase 5, external-intelligence source #5) — the sanctioned online counterpart to the
 * local, no-cracking credential audit. Where fsaudit flags a weak/legacy `/etc/shadow` hash statically, this
 * takes the UNSALTED password hashes an image ships (bare hex MD5/SHA1/SHA256/NTLM, and the RFC 2307 LDAP
 * `{SHA}`/`{MD5}`/`{SHA256}` base64 forms) and asks free, public reverse-hash databases whether the plaintext is
 * already known. It never cracks anything on-box and never asks a service to crack: it only queries precomputed
 * lookup tables.
 *
 * Non-negotiables, mirroring the rest of the research track:
 *  - Double opt-in. Runs only when BOTH FIRMLAB_RESEARCH=1 (network on) AND FIRMLAB_HASH_LOOKUP=1 (this hash
 *    egress specifically). With either unset, no hash leaves.
 *  - Only unsalted digests are ever sent. Salted crypt(3) hashes (md5crypt/sha256crypt/sha512crypt/bcrypt/
 *    yescrypt, DES, and salted LDAP `{SSHA}`) are NOT resolvable by these DBs, so they are never transmitted and
 *    a "miss" is never reported as strength.
 *  - Every returned plaintext is a CANDIDATE until it is VERIFIED locally with node:crypto — we recompute the
 *    digest of that one value and compare. Recomputing one known value is verification, not cracking (no keyspace
 *    search); it exists solely to reject a service that returns garbage, so we never emit a false positive.
 *  - Honesty about what can't be done here: CrackStation has no API (web + CAPTCHA), so it is surfaced as a
 *    manual link for the operator to run, never called. The recovered cleartext is masked in the stored result;
 *    its recoverability — not the secret itself — is the finding.
 *
 * The classifier, masker, verifier and response parsers are PURE and unit-tested; the network functions are thin
 * wrappers over `allowlistedFetch` (only the two hash-lookup hosts, and only when they are on the allowlist).
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import type { FindingDraft } from '../findings-normalize.js';
import { type ResearchConfig, allowlistedFetch, isAllowed } from '../research/config.js';

// CrackStation is a manual-only reverse-lookup (no API, CAPTCHA-gated). We surface it for the operator to run on a
// resolvable miss; FirmLab never submits to it automatically.
export const CRACKSTATION_URL = 'https://crackstation.net/';

/** The unsalted digest algorithms online reverse-hash DBs actually index (and that we can verify locally). */
export type LookupAlgo = 'md5' | 'sha1' | 'sha256' | 'ntlm';

/** The recognized password-hash schemes, resolvable (unsalted) or not (salted crypt / locked / absent). */
export type HashScheme =
  | 'md5-or-ntlm' // a bare 32-hex digest — ambiguously MD5 or NTLM; we try both when verifying
  | 'sha1'
  | 'sha256'
  | 'ldap-sha' // {SHA} base64 — unsalted SHA1
  | 'ldap-md5' // {MD5} base64 — unsalted MD5
  | 'ldap-sha256' // {SHA256} base64 — unsalted SHA256
  | 'md5crypt' // $1$  — salted
  | 'sha256crypt' // $5$ — salted
  | 'sha512crypt' // $6$ — salted
  | 'bcrypt' // $2a$/$2b$/$2y$ — salted
  | 'yescrypt' // $y$ — salted
  | 'descrypt' // 13-char DES crypt — salted
  | 'ldap-ssha' // {SSHA}/{SMD5}/… — salted
  | 'locked' // *, !, !! — no usable password
  | 'empty' // '' — no password set (handled as a critical finding elsewhere)
  | 'unknown';

export interface HashClass {
  scheme: HashScheme;
  /** Plausible verification/lookup algorithms for a resolvable hash (e.g. 32-hex → both md5 and ntlm); [] otherwise. */
  algos: LookupAlgo[];
  /** Lowercase hex digest to look up / verify against (base64 LDAP forms decoded to hex); null when not resolvable. */
  digestHex: string | null;
  /** Can an online reverse-hash DB even resolve this kind? Only unsalted digests. */
  resolvable: boolean;
  /** Salted scheme — recorded so the report can state plainly that a miss is not evidence of strength. */
  salted: boolean;
}

const HEX_RE = /^[0-9a-f]+$/i;

function resolvable(scheme: HashScheme, algos: LookupAlgo[], digestHex: string): HashClass {
  return { scheme, algos, digestHex: digestHex.toLowerCase(), resolvable: true, salted: false };
}
function saltedClass(scheme: HashScheme): HashClass {
  return { scheme, algos: [], digestHex: null, resolvable: false, salted: true };
}
function inert(scheme: HashScheme): HashClass {
  return { scheme, algos: [], digestHex: null, resolvable: false, salted: false };
}

/** Decode a base64 LDAP digest to hex only when it is exactly `bytes` long; else null (malformed / salted). */
function decodeLdap(b64: string, bytes: number): string | null {
  try {
    const buf = Buffer.from(b64, 'base64');
    return buf.length === bytes ? buf.toString('hex') : null;
  } catch {
    return null;
  }
}

/**
 * Pure: classify a password-hash field into its scheme and whether an online lookup can resolve it. The decisive
 * split is salted-vs-unsalted: every crypt(3) scheme carries a per-hash salt, so no precomputed table can reverse
 * it and we never transmit it; only bare unsalted digests (and their unsalted LDAP base64 encodings) are sent.
 */
export function classifyHash(hash: string): HashClass {
  const h = hash.trim();
  if (h === '') return inert('empty');
  if (h === '*' || h.startsWith('!')) return inert('locked');

  // crypt(3) modular scheme prefixes — all salted, none resolvable by a lookup DB.
  if (h.startsWith('$1$')) return saltedClass('md5crypt');
  if (h.startsWith('$5$')) return saltedClass('sha256crypt');
  if (h.startsWith('$6$')) return saltedClass('sha512crypt');
  if (/^\$2[abxy]\$/.test(h)) return saltedClass('bcrypt');
  if (h.startsWith('$y$') || h.startsWith('$7$') || h.startsWith('$gy$')) return saltedClass('yescrypt');

  // RFC 2307 LDAP userPassword encodings. The `{S…}` (salted) variants are not resolvable; the plain ones are.
  const ldap = h.match(/^\{([A-Za-z0-9]+)\}(.+)$/);
  if (ldap) {
    const tag = (ldap[1] as string).toUpperCase();
    const body = ldap[2] as string;
    // Unsalted encodings first (exact tags), THEN the salted `S…` variants — {SHA}/{SHA256} also start with 'S',
    // so a prefix check alone would wrongly bucket them as salted.
    if (tag === 'SHA') {
      const hex = decodeLdap(body, 20);
      return hex ? resolvable('ldap-sha', ['sha1'], hex) : inert('unknown');
    }
    if (tag === 'MD5') {
      const hex = decodeLdap(body, 16);
      return hex ? resolvable('ldap-md5', ['md5'], hex) : inert('unknown');
    }
    if (tag === 'SHA256') {
      const hex = decodeLdap(body, 32);
      return hex ? resolvable('ldap-sha256', ['sha256'], hex) : inert('unknown');
    }
    if (tag.startsWith('S')) return saltedClass('ldap-ssha'); // {SSHA}, {SMD5}, {SSHA256}, {SSHA512} — all salted
    return inert('unknown');
  }

  // Bare hex digests. A 32-hex value is ambiguously MD5 or NTLM; we verify against both.
  if (HEX_RE.test(h)) {
    if (h.length === 32) return resolvable('md5-or-ntlm', ['md5', 'ntlm'], h);
    if (h.length === 40) return resolvable('sha1', ['sha1'], h);
    if (h.length === 64) return resolvable('sha256', ['sha256'], h);
  }

  // A 13-char crypt-alphabet string with no `$` prefix is a salted DES crypt hash.
  if (/^[./0-9A-Za-z]{13}$/.test(h)) return saltedClass('descrypt');

  return inert('unknown');
}

/**
 * Pure: mask a recovered plaintext so its recoverability can be reported without persisting the secret. Keeps the
 * first and last character and the length as a fingerprint (`a****e (len 6)`); short strings are fully starred.
 */
export function maskSecret(s: string): string {
  if (s.length === 0) return '(empty)';
  if (s.length <= 2) return `${'*'.repeat(s.length)} (len ${s.length})`;
  return `${s[0]}${'*'.repeat(s.length - 2)}${s[s.length - 1]} (len ${s.length})`;
}

/** Compute one digest of a known candidate, or null when the algorithm is unavailable in this runtime. */
function computeDigest(algo: LookupAlgo, plaintext: string): string | null {
  try {
    if (algo === 'ntlm') {
      // NTLM = MD4 over the UTF-16LE password. MD4 may be disabled in a hardened OpenSSL build → unverifiable.
      return createHash('md4').update(Buffer.from(plaintext, 'utf16le')).digest('hex');
    }
    return createHash(algo).update(plaintext, 'utf8').digest('hex');
  } catch {
    return null;
  }
}

/** Constant-time hex comparison (equal length required). */
function hexEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a.toLowerCase(), 'hex');
  const bb = Buffer.from(b.toLowerCase(), 'hex');
  return ba.length > 0 && ba.length === bb.length && timingSafeEqual(ba, bb);
}

/**
 * Pure: verify a single candidate plaintext against a stored digest by recomputing it under each plausible algo.
 * Returns the algorithm that matched, or null when none do. One hash op per algo — verification, not cracking.
 */
export function verifyCandidate(digestHex: string, algos: LookupAlgo[], candidate: string): LookupAlgo | null {
  for (const algo of algos) {
    const computed = computeDigest(algo, candidate);
    if (computed && hexEqual(computed, digestHex)) return algo;
  }
  return null;
}

/**
 * Pure: nitrxgen's md5db returns the plaintext as the raw response body, and an empty body on a miss. It only
 * knows MD5. Treat only a plausible plaintext (non-empty, no HTML markup, bounded length) as a candidate — never
 * trusted until locally verified.
 */
export function parseNitrxgen(body: string): string | null {
  const t = body.trim();
  if (!t || t.length > 128 || /[<>]/.test(t)) return null;
  return t;
}

/**
 * Pure: weakpass' search endpoint answers with JSON carrying the recovered password under one of a few keys (the
 * exact field has varied across API versions), or nothing on a miss. Defensive: return the first non-empty
 * string-valued password-like field. Still only a candidate until verified locally.
 */
export function parseWeakpass(json: unknown): string | null {
  if (!json || typeof json !== 'object') return null;
  const o = json as Record<string, unknown>;
  for (const k of ['pass', 'password', 'plain', 'plaintext', 'value']) {
    const v = o[k];
    if (typeof v === 'string' && v.length > 0 && v.length <= 128) return v;
  }
  return null;
}

/** Query nitrxgen's MD5 database for one digest. Guarded by the allowlist; any error → a miss. */
async function lookupNitrxgen(digestHex: string, cfg: ResearchConfig): Promise<string | null> {
  const url = `https://www.nitrxgen.net/md5db/${digestHex}`;
  if (!isAllowed(url, cfg.allowlist)) return null;
  try {
    const res = await allowlistedFetch(url, cfg);
    if (!res.ok) return null;
    return parseNitrxgen(await res.text());
  } catch {
    return null;
  }
}

/** Query weakpass' search API for one digest. Guarded by the allowlist; any error → a miss. */
async function lookupWeakpass(digestHex: string, cfg: ResearchConfig): Promise<string | null> {
  const url = `https://weakpass.com/api/v1/search/${digestHex}.json`;
  if (!isAllowed(url, cfg.allowlist)) return null;
  try {
    const res = await allowlistedFetch(url, cfg);
    if (!res.ok) return null;
    return parseWeakpass(await res.json());
  } catch {
    return null;
  }
}

/**
 * Resolve one digest across the lookup DBs, stopping at the first candidate that VERIFIES locally. nitrxgen is
 * tried first for MD5 (fast, single-purpose); weakpass covers all unsalted algos. A candidate that comes back but
 * fails verification is remembered as `unverified` (service noise) and never promoted to a hit.
 */
async function resolveHash(
  digestHex: string,
  algos: LookupAlgo[],
  cfg: ResearchConfig,
): Promise<{ plaintext: string | null; verifiedAs?: LookupAlgo }> {
  const services: Array<() => Promise<string | null>> = [];
  if (algos.includes('md5')) services.push(() => lookupNitrxgen(digestHex, cfg));
  services.push(() => lookupWeakpass(digestHex, cfg));

  let unverified: string | null = null;
  for (const svc of services) {
    const candidate = await svc();
    if (!candidate) continue;
    const verifiedAs = verifyCandidate(digestHex, algos, candidate);
    if (verifiedAs) return { plaintext: candidate, verifiedAs };
    unverified = candidate;
  }
  return { plaintext: unverified };
}

/** A password-hash to look up, with the account and the file it came from (for evidence). */
export interface HashCandidate {
  account: string;
  hash: string;
  source: string;
}

export type LookupOutcome =
  | 'resolved' // a candidate came back AND verified locally — the plaintext is known
  | 'unverified' // a candidate came back but did not verify — discarded as noise, not a hit
  | 'miss' // resolvable type, queried, nothing came back
  | 'skipped_salted' // salted crypt — never sent (a miss would prove nothing)
  | 'skipped_other'; // locked / empty / unknown — nothing to look up

export interface HashLookupEntry {
  account: string;
  source: string;
  scheme: HashScheme;
  outcome: LookupOutcome;
  /** The algorithm that verified the recovery (resolved only). */
  verifiedAs?: LookupAlgo;
  /** Masked recovered password (resolved only) — the cleartext is never stored. */
  passwordMasked?: string;
  /** A manual, no-API lookup the operator can run for a resolvable miss/unverified (CrackStation). */
  manualLookupUrl?: string;
}

export interface HashLookupResult {
  enabled: boolean;
  reason: string;
  /** Unsalted hashes actually queried against the DBs. */
  attempted: number;
  /** Recoveries that were locally verified. */
  resolved: number;
  /** Resolvable hashes not queried because of the per-run cap — reported, never silently dropped. */
  notQueried: number;
  entries: HashLookupEntry[];
}

// A generous cap: a shadow file has a handful of accounts, but a bundle of admin-password hashes from configs
// could be larger. Anything beyond this is reported as notQueried rather than silently dropped.
const DEFAULT_CAP = 50;

/**
 * Run the online hash lookup over a set of candidates. Off unless FIRMLAB_HASH_LOOKUP is armed. Salted and inert
 * hashes are classified and reported but never sent; only unsalted digests are queried, and only a locally
 * verified recovery is reported as resolved.
 */
export async function runHashLookup(
  candidates: HashCandidate[],
  cfg: ResearchConfig,
  opts: { cap?: number } = {},
): Promise<HashLookupResult> {
  if (!cfg.hashLookup) {
    return {
      enabled: false,
      reason: 'Online hash lookup disabled — set FIRMLAB_HASH_LOOKUP=1 (it sends unsalted password hashes off-box).',
      attempted: 0,
      resolved: 0,
      notQueried: 0,
      entries: [],
    };
  }

  const cap = opts.cap ?? DEFAULT_CAP;
  const entries: HashLookupEntry[] = [];
  const seen = new Set<string>();
  let attempted = 0;
  let resolved = 0;
  let notQueried = 0;

  for (const cand of candidates) {
    const key = `${cand.account}:${cand.hash}`;
    if (seen.has(key)) continue; // a hash repeated across files is queried once
    seen.add(key);

    const cls = classifyHash(cand.hash);
    const base = { account: cand.account, source: cand.source, scheme: cls.scheme };

    if (cls.scheme === 'empty' || cls.scheme === 'locked' || cls.scheme === 'unknown') {
      entries.push({ ...base, outcome: 'skipped_other' });
      continue;
    }
    if (!cls.resolvable || !cls.digestHex) {
      entries.push({ ...base, outcome: 'skipped_salted' });
      continue;
    }
    if (attempted >= cap) {
      notQueried += 1;
      entries.push({ ...base, outcome: 'miss', manualLookupUrl: CRACKSTATION_URL });
      continue;
    }

    attempted += 1;
    const { plaintext, verifiedAs } = await resolveHash(cls.digestHex, cls.algos, cfg);
    if (plaintext && verifiedAs) {
      resolved += 1;
      entries.push({ ...base, outcome: 'resolved', verifiedAs, passwordMasked: maskSecret(plaintext) });
    } else if (plaintext) {
      entries.push({ ...base, outcome: 'unverified', manualLookupUrl: CRACKSTATION_URL });
    } else {
      entries.push({ ...base, outcome: 'miss', manualLookupUrl: CRACKSTATION_URL });
    }
  }

  const skipped = notQueried > 0 ? ` (${notQueried} more skipped — per-run cap)` : '';
  const reason = `Online hash lookup: ${attempted} unsalted hash(es) queried, ${resolved} recovered & locally verified${skipped}. Salted crypt hashes are never sent; a miss on them would not prove strength.`;
  return { enabled: true, reason, attempted, resolved, notQueried, entries };
}

/**
 * Normalize resolved recoveries into findings. Only a locally verified recovery becomes a finding — a miss is the
 * absence of evidence, not a finding. The recovered credential is `static_confirmed`: the plaintext demonstrably
 * reproduces the stored hash, offline. The cleartext is masked; its recoverability is the actionable fact.
 */
export function normalizeHashLookup(result: HashLookupResult): FindingDraft[] {
  return result.entries
    .filter((e) => e.outcome === 'resolved')
    .map((e) => ({
      kind: 'recovered-password',
      title: `Password for '${e.account}' recovered from a public hash database`,
      severity: 'critical' as const,
      proofState: 'static_confirmed' as const,
      evidence: {
        account: e.account,
        source: e.source,
        scheme: e.scheme,
        verifiedAs: e.verifiedAs,
        passwordMasked: e.passwordMasked,
      },
      rationale:
        'The stored password hash was found in a public reverse-hash database, and the returned plaintext was ' +
        'verified locally to reproduce the exact hash (a single-value check, not cracking). The credential is ' +
        'therefore public/known and must be rotated. The cleartext is masked by design — its recoverability is ' +
        'the finding.',
    }));
}
