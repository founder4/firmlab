/**
 * credmatch — cross-reference the credential hashes an image stores against the strings the same image ships.
 *
 * `fsaudit` already says *a weak hash exists*. That is where the app stopped, and docs/BACKLOG.md filed the rest as
 * "hashcat on /etc/shadow", blocked on a GPU and a wordlist this workbench does not ship. Both are the wrong
 * prerequisites for the case that actually occurs in firmware: the plaintext is very often **already in the image**,
 * because the same password is compiled into a service binary, written into a provisioning script, or left in a
 * `key=value` line of a config. Two of the three routers and cameras in this corpus are exactly that, and neither
 * needs a keyspace search — the candidate set is the image's own printable strings, the salt is in hand, and one
 * hash per candidate settles it.
 *
 * So this is not cracking and must never be presented as such. It is a JOIN: `{strings in this image} × {hashes in
 * this image}`, with `crypt(3)` as the join condition. What that buys, and what it costs, are both stated:
 *
 *  - **A hit is `static_confirmed`.** The password is then a fact about the bytes — this string, hashed with the
 *    salt stored beside the account, reproduces the stored hash exactly. It is NOT a claim that the account is
 *    enabled, that a login service is reachable, or that a physical unit still runs this firmware. The finding says
 *    so, and the proof state never rises above the bytes.
 *  - **A miss is a BOUNDED NEGATIVE, and never "the password is strong".** The result carries how many candidates
 *    were tried, how they were derived, how they were ranked, and what the cap dropped — because "N strings from
 *    this image did not reproduce this hash" is a true and useful sentence, and "this hash resisted cracking" is
 *    neither. The distinction is the whole reason the coverage numbers are on the result rather than in a log line.
 *  - **A scheme this deployment cannot compute is `blocked_by_platform`, naming the scheme.** Never a silent skip,
 *    never folded into the "not recovered" count. bcrypt and yescrypt land here by construction; anything else
 *    lands here when the tool that computes it is missing or fails its known-answer self-test.
 *
 * **Where the hashing happens, and the trap that decided it.** `openssl passwd` is the hasher for every `$id$`
 * scheme — `-1`, `-apr1`, `-5`, `-6`, with the salt (including a `rounds=N$` prefix) passed straight through, and
 * `-in` handing it the whole candidate list in ONE process. But `openssl passwd -crypt` was removed in OpenSSL 3.0,
 * and traditional DES is the dominant scheme in firmware of this vintage, so DES is computed in-process by
 * `descrypt.ts` instead. That module also owns the truncation rule that makes the Tenda case work at all: DES reads
 * eight bytes, so `Td2N3ww1.0_tenda_force_upgrade` and `Td2N3ww1` hash identically and only the latter is the
 * secret.
 *
 * **The guard nobody runs.** A backend is not trusted because its binary is on PATH. Every `openssl` flag is
 * self-tested against a recorded known answer before a single candidate is hashed with it, and every batch's output
 * is checked to carry the `$id$…$salt$` prefix of the hash it is supposed to be attacking. A build that silently
 * ignored `rounds=`, truncated an over-long salt, or quietly dropped an option would otherwise turn every account
 * into a confident false negative — which is the single worst thing this provider could produce.
 *
 * Everything that decides anything is pure and unit-tested: the account parsers, the crypt-hash reader, the
 * scheme/backend map, the candidate derivation and ranking, the verdict and the findings. The runner walks the
 * rootfs, shells out and composes them. Nothing here needs `openssl` to be installed to be tested.
 *
 * A note for whoever adds a field to `CredMatchResult`: results are JSON on a job row and re-read for as long as
 * the image exists, so a stored result is data written by an older build. Any field added after this commit is
 * OPTIONAL FOREVER.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import type { FindingSeverity } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';
import { isToolAvailable } from '../tools.js';
import { DES_PASSWORD_BYTES, desCrypt, desEffectivePassword, isDesHash } from './descrypt.js';
import type { JobHandle } from './jobs.js';

/** Stable finding source shared by manual and autonomous entry points. */
export const CREDMATCH_SOURCE = 'credmatch';

const execFileAsync = promisify(execFile);

// ---------------------------------------------------------------------------------------------------------------
// Reading the account database (pure)
// ---------------------------------------------------------------------------------------------------------------

/** The hash schemes this module can NAME. Naming one it cannot compute is the point of the blocked path. */
export type CryptScheme =
  | 'descrypt'
  | 'md5crypt'
  | 'apr1'
  | 'sha256crypt'
  | 'sha512crypt'
  | 'bcrypt'
  | 'yescrypt'
  | 'scrypt'
  | 'sunmd5'
  | 'unknown';

/** A stored password hash, decomposed into the parts a hasher needs and a reader can check. */
export interface ParsedCryptHash {
  scheme: CryptScheme;
  /** How a human names it, marker included — `md5crypt ($1$)`. Used verbatim in titles and blocked reasons. */
  label: string;
  /** The `$id$` marker, or `''` for DES, which has none. */
  marker: string;
  /**
   * Exactly what a hasher must be handed as the salt. For sha-crypt this INCLUDES a `rounds=N$` prefix when the
   * hash declares one, because the cost parameter is part of the salt string every crypt implementation parses.
   */
  salt: string;
  /** The prefix every hash of this (scheme, salt) must carry. The batch output is checked against it. */
  prefix: string;
  digest: string;
  full: string;
}

/** How a `passwd`/`shadow` password field actually presents. Four of these are not hashes, and none is "clean". */
export type CredentialFieldState =
  | { state: 'hash'; hash: ParsedCryptHash; locked: boolean }
  | { state: 'empty' }
  | { state: 'locked'; marker: string }
  | { state: 'deferred' }
  | { state: 'unrecognized'; value: string };

/** Markers that mean "this account has no usable password", as opposed to one we failed to parse. */
const LOCK_MARKERS = new Set(['*', '!', '!!', '!*', '*LK*', 'NP', 'LOCKED', '*NP*']);

/** Salt/digest characters. Anything outside this in a `$id$` field means the field is not a crypt hash. */
const CRYPT_FIELD_RE = /^[./0-9A-Za-z]*$/;

/** `$5$`/`$6$` may carry a cost prefix in the salt position. */
const ROUNDS_RE = /^rounds=\d+$/;

const SCHEME_BY_MARKER: Record<string, { scheme: CryptScheme; label: string }> = {
  '1': { scheme: 'md5crypt', label: 'md5crypt ($1$)' },
  apr1: { scheme: 'apr1', label: 'Apache md5crypt ($apr1$)' },
  '5': { scheme: 'sha256crypt', label: 'sha256crypt ($5$)' },
  '6': { scheme: 'sha512crypt', label: 'sha512crypt ($6$)' },
  '2': { scheme: 'bcrypt', label: 'bcrypt ($2$)' },
  '2a': { scheme: 'bcrypt', label: 'bcrypt ($2a$)' },
  '2b': { scheme: 'bcrypt', label: 'bcrypt ($2b$)' },
  '2x': { scheme: 'bcrypt', label: 'bcrypt ($2x$)' },
  '2y': { scheme: 'bcrypt', label: 'bcrypt ($2y$)' },
  y: { scheme: 'yescrypt', label: 'yescrypt ($y$)' },
  gy: { scheme: 'yescrypt', label: 'gost-yescrypt ($gy$)' },
  '7': { scheme: 'scrypt', label: 'scrypt ($7$)' },
  md5: { scheme: 'sunmd5', label: 'Solaris md5crypt ($md5$)' },
};

/**
 * Pure: decompose a stored password hash.
 *
 * Two shapes exist and they are not variations of one another. Traditional DES is thirteen bare characters whose
 * first two are the salt — there is no marker, so it is recognised by shape. Everything since is
 * `$id$[params$]salt$digest`, where `id` selects the algorithm and the number of `$`-separated fields varies by
 * scheme. A field that matches neither returns null, which the caller reports as *unrecognised*, never as absent.
 */
export function parseCryptHash(value: string): ParsedCryptHash | null {
  if (isDesHash(value)) {
    const salt = value.slice(0, 2);
    return {
      scheme: 'descrypt',
      label: 'DES crypt (13-char)',
      marker: '',
      salt,
      prefix: salt,
      digest: value.slice(2),
      full: value,
    };
  }
  if (!value.startsWith('$')) return null;

  const parts = value.split('$');
  // `$1$salt$digest` splits to ['', '1', 'salt', 'digest'] — four fields minimum.
  if (parts.length < 4) return null;
  const marker = parts[1] as string;
  const known = SCHEME_BY_MARKER[marker];
  if (!known) return null;

  // bcrypt is `$2a$cost$salt+digest` — one field where every other scheme has two, and this module never computes
  // it, so it is named and left undecomposed rather than forced into a shape it does not have.
  if (known.scheme === 'bcrypt' || known.scheme === 'yescrypt' || known.scheme === 'scrypt') {
    return {
      scheme: known.scheme,
      label: known.label,
      marker: `$${marker}$`,
      salt: '',
      prefix: '',
      digest: '',
      full: value,
    };
  }

  const digest = parts[parts.length - 1] as string;
  const saltFields = parts.slice(2, parts.length - 1);
  if (saltFields.length === 0 || digest === '') return null;
  // Only a `rounds=N` cost prefix may precede the salt; anything else means this is not the shape we think it is.
  if (saltFields.length > 2) return null;
  if (saltFields.length === 2 && !ROUNDS_RE.test(saltFields[0] as string)) return null;
  const saltValue = saltFields[saltFields.length - 1] as string;
  if (!CRYPT_FIELD_RE.test(saltValue) || !CRYPT_FIELD_RE.test(digest)) return null;

  const salt = saltFields.join('$');
  return {
    scheme: known.scheme,
    label: known.label,
    marker: `$${marker}$`,
    salt,
    prefix: `$${marker}$${salt}$`,
    digest,
    full: value,
  };
}

/**
 * Pure: what a password field IS.
 *
 * The `!` prefix is kept rather than stripped-and-forgotten: a locked account still stores a hash, that hash is
 * still testable, and the password behind it is very often the same one a live service uses — but the finding must
 * say the account is disabled in this file, so the state carries it.
 */
export function classifyCredentialField(value: string): CredentialFieldState {
  const field = value.trim();
  if (field === '') return { state: 'empty' };
  if (field === 'x' || field === '*x*') return { state: 'deferred' };
  if (LOCK_MARKERS.has(field)) return { state: 'locked', marker: field };

  const locked = field.startsWith('!');
  const body = locked ? field.replace(/^!+/, '') : field;
  const hash = parseCryptHash(body);
  if (hash) return { state: 'hash', hash, locked };
  if (locked) return { state: 'locked', marker: '!' };
  return { state: 'unrecognized', value: field };
}

/** One account, as one file states it. */
export interface AccountRecord {
  name: string;
  /** UID when the file carries one (`/etc/passwd` does, `/etc/shadow` does not). */
  uid: number | null;
  field: CredentialFieldState;
  /** Rootfs-relative path of the file this came from. */
  file: string;
}

/**
 * Which layout a file has, and this is NOT cosmetic: `passwd` is `name:pw:uid:gid:…` and `shadow` is
 * `name:hash:lastchg:…`, so the third field is a UID in one and a day count in the other. Reading it as a UID in
 * both is how `bin:*:10933:…` becomes "an account with UID 10933" and `root:…:0:…` becomes UID 0 by luck — the
 * severity of a recovered password turns on that number, so the caller states which file it is handing over.
 */
export type AccountFileKind = 'passwd' | 'shadow';

/**
 * Pure: parse `/etc/passwd` or `/etc/shadow`.
 *
 * One parser for both, because their first two fields are the same two fields and the difference is only whether a
 * numeric UID follows. Comments, blank lines and lines with fewer than two fields are skipped — a shadow line with
 * one field carries no password to test, and inventing an empty one would manufacture a critical finding.
 */
export function parseAccountFile(text: string, file: string, kind: AccountFileKind): AccountRecord[] {
  const out: AccountRecord[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const fields = line.split(':');
    if (fields.length < 2) continue;
    const name = fields[0] ?? '';
    if (!name) continue;
    const uidRaw = kind === 'passwd' ? fields[2] : undefined;
    const uid = uidRaw !== undefined && /^\d+$/.test(uidRaw) ? Number.parseInt(uidRaw, 10) : null;
    out.push({ name, uid, field: classifyCredentialField(fields[1] ?? ''), file });
  }
  return out;
}

/** A hash this run will try to reproduce, with everything a finding needs to name it. */
export interface CredentialTarget {
  account: string;
  uid: number | null;
  hash: ParsedCryptHash;
  /** The account is disabled in the file that stores the hash. The hash is still tested; the finding says so. */
  locked: boolean;
  file: string;
}

/** Separator for composite map keys. Written as an escape: a literal NUL byte in a source file breaks grep. */
const KEY_SEP = '\u0000';

/**
 * Pure: the set of hashes worth attacking, from every account file that was readable.
 *
 * Deduped by (account, hash) so a rootfs that stores the same hash in both `passwd` and `shadow` yields one target
 * rather than two identical findings. The UID is taken from whichever record carries one, because `/etc/shadow`
 * never does and the severity of a recovered password turns on whether the account is UID 0.
 */
export function collectTargets(
  files: Array<{ path: string; text: string; kind: AccountFileKind }>,
): CredentialTarget[] {
  const records = files.flatMap((f) => parseAccountFile(f.text, f.path, f.kind));
  const uidByName = new Map<string, number>();
  for (const r of records) {
    if (r.uid !== null && !uidByName.has(r.name)) uidByName.set(r.name, r.uid);
  }
  const seen = new Set<string>();
  const targets: CredentialTarget[] = [];
  for (const r of records) {
    if (r.field.state !== 'hash') continue;
    const key = `${r.name}${KEY_SEP}${r.field.hash.full}`;
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push({
      account: r.name,
      uid: uidByName.get(r.name) ?? null,
      hash: r.field.hash,
      locked: r.field.locked,
      file: r.file,
    });
  }
  return targets;
}

/**
 * Pure: the order stored hashes are attacked in.
 *
 * There is a cap on how many hashes one run attacks, and a cap that takes them in file order would let a rootfs
 * with forty service accounts push `root` past it — the same defect `selectFindings` in `binvuln.ts` was written
 * for, one level up. UID 0 first, then accounts that are not locked, then by name so two runs over the same rootfs
 * attack the same hashes in the same order.
 */
export function rankTargets(targets: CredentialTarget[]): CredentialTarget[] {
  const rootish = (t: CredentialTarget): number => (t.uid === 0 || t.account === 'root' ? 0 : 1);
  return [...targets].sort(
    (a, b) => rootish(a) - rootish(b) || Number(a.locked) - Number(b.locked) || a.account.localeCompare(b.account),
  );
}

/**
 * Pure: a stored hash with its digest removed, for evidence.
 *
 * `fsaudit` redacts the hash field of a shadow line and this stays consistent with it — but it keeps the scheme
 * marker and the salt, which are public parameters of the scheme and are exactly what a reader needs to reproduce
 * the check by hand. What never appears is the digest.
 */
export function redactHash(hash: ParsedCryptHash): string {
  if (hash.scheme === 'descrypt') return `${hash.salt}<redacted>`;
  // bcrypt, yescrypt and scrypt are named but never decomposed, so there is no `$id$salt$` prefix to show. The
  // marker alone still tells a reader which algorithm the redaction is standing in for; a bare `<redacted>` would
  // make three different schemes render identically in the ledger.
  return `${hash.prefix || hash.marker}<redacted>`;
}

// ---------------------------------------------------------------------------------------------------------------
// Which schemes this build can compute (pure map + a runtime self-test)
// ---------------------------------------------------------------------------------------------------------------

/** How a scheme gets hashed here, or why it does not. */
export type SchemeBackend =
  | { kind: 'internal-des' }
  | { kind: 'openssl'; flag: string }
  | { kind: 'unsupported'; reason: string };

/**
 * Pure: the hasher for a scheme, before anything about this machine is known.
 *
 * `openssl passwd` covers the four `$id$` schemes it has options for. It has never had an option for bcrypt,
 * yescrypt or scrypt, and — the discovery that shaped this module — **it lost `-crypt` in OpenSSL 3.0**, so DES is
 * computed in process. The unsupported reasons are written as facts about the TOOL, not about the hash: a scheme
 * that cannot be computed here is a question this deployment cannot ask, which is a different thing from a hash
 * that resisted the attempt.
 */
export function backendForScheme(scheme: CryptScheme): SchemeBackend {
  switch (scheme) {
    case 'descrypt':
      return { kind: 'internal-des' };
    case 'md5crypt':
      return { kind: 'openssl', flag: '-1' };
    case 'apr1':
      return { kind: 'openssl', flag: '-apr1' };
    case 'sha256crypt':
      return { kind: 'openssl', flag: '-5' };
    case 'sha512crypt':
      return { kind: 'openssl', flag: '-6' };
    case 'bcrypt':
      return {
        kind: 'unsupported',
        reason: '`openssl passwd` has no bcrypt option, and nothing else here computes it',
      };
    case 'yescrypt':
      return {
        kind: 'unsupported',
        reason: '`openssl passwd` has no yescrypt option, and nothing else here computes it',
      };
    case 'scrypt':
      return {
        kind: 'unsupported',
        reason: '`openssl passwd` has no scrypt option, and nothing else here computes it',
      };
    case 'sunmd5':
      return {
        kind: 'unsupported',
        reason: 'the Solaris `$md5$` variant is not the same algorithm as `$1$` and `openssl passwd` cannot produce it',
      };
    default:
      return { kind: 'unsupported', reason: 'the scheme marker is not one this build knows how to compute' };
  }
}

/**
 * Known-answer vectors, one per `openssl passwd` flag, all for the password `firmlab` and the salt `abcdefgh`.
 *
 * These are recorded from a real run (OpenSSL 3.0.20), and `-1`, `-5` and `-6` were additionally cross-checked
 * against glibc's own `crypt(3)` so they are not merely openssl agreeing with itself. Their job is the one this
 * codebase keeps paying for: exercise the branch where the guard finds nothing wrong. A flag that has been removed,
 * renamed, or silently changed fails here and its scheme becomes `blocked_by_platform` — instead of producing a
 * confident, wrong "not recovered" for every account that uses it.
 */
export const OPENSSL_SELF_TEST: ReadonlyArray<{ flag: string; salt: string; password: string; expect: string }> = [
  { flag: '-1', salt: 'abcdefgh', password: 'firmlab', expect: '$1$abcdefgh$yJ.hV5eJ/EhduYlPaq/q91' },
  { flag: '-apr1', salt: 'abcdefgh', password: 'firmlab', expect: '$apr1$abcdefgh$gJMluSMz0rV0BAFuFN4MM1' },
  {
    flag: '-5',
    salt: 'abcdefgh',
    password: 'firmlab',
    expect: '$5$abcdefgh$o29Y9Wp8l6xnpvy3tINcwTDJjTn0LhRjWrHSSQETyF5',
  },
  {
    flag: '-6',
    salt: 'abcdefgh',
    password: 'firmlab',
    expect: '$6$abcdefgh$aLwRNQZAqFVsLbfxa5UxnEQFuOBGwDmx6qDS64dbpEDTYUHFND5/b2FoPO7r/pF9d7IerebnnXNg6JWBoA0If.',
  },
];

/** What the runtime learned about `openssl passwd` on this box. */
export interface OpensslCapability {
  available: boolean;
  /** Flags whose known-answer self-test passed. A flag absent from here is never used to hash anything. */
  verifiedFlags: string[];
  /** Flags whose self-test ran and did not produce the recorded answer, with what happened. */
  failures: Array<{ flag: string; reason: string }>;
}

/** Pure: fold the static map and the runtime probe into the backend actually used for one scheme. */
export function resolveBackend(scheme: CryptScheme, capability: OpensslCapability): SchemeBackend {
  const backend = backendForScheme(scheme);
  if (backend.kind !== 'openssl') return backend;
  if (!capability.available) {
    return { kind: 'unsupported', reason: 'openssl is not installed in this deployment' };
  }
  if (capability.verifiedFlags.includes(backend.flag)) return backend;
  const failure = capability.failures.find((f) => f.flag === backend.flag);
  return {
    kind: 'unsupported',
    reason: failure
      ? `this build's \`openssl passwd ${backend.flag}\` did not reproduce a known answer (${failure.reason})`
      : `this build's \`openssl passwd\` does not support ${backend.flag}`,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Candidates: harvesting, deriving, ranking (pure)
// ---------------------------------------------------------------------------------------------------------------

/** How a candidate was obtained from a harvested string. Reported on a hit, so the reader can go and look. */
export type CandidateDerivation = 'literal' | 'assignment-value' | 'quoted' | 'token';

/** One thing that will be hashed, and where it came from. */
export interface Candidate {
  value: string;
  derivation: CandidateDerivation;
  /** The left-hand side of the `key=value` this came from. The single strongest ranking signal there is. */
  key?: string;
  /** Rootfs-relative path of the file the string was harvested from. */
  file: string;
  /** Byte offset of the harvested string in that file. */
  offset: number;
}

/** A harvested string, with where it was found. */
export interface HarvestedString {
  value: string;
  offset: number;
}

/**
 * Shortest run of printable bytes kept. Three, not the customary four: `abc` is a real firmware password and the
 * extra strings a shorter minimum admits are cheap next to missing one.
 */
export const MIN_STRING_LENGTH = 3;

/**
 * Longest candidate hashed, and this bound is a correctness one, not a budget.
 *
 * `openssl passwd` silently truncates its input at 256 characters — measured, not read: a 257-character password
 * hashes to the same value as its 256-character prefix, with no warning, on both the command line and `-in`. A
 * candidate above the limit would therefore be tested as something other than itself, and a match would be reported
 * with the wrong plaintext. Staying an order below the limit means every candidate this provider reports on was
 * hashed in full.
 */
export const MAX_CANDIDATE_LENGTH = 128;

/**
 * Pure: every run of printable ASCII in a buffer, with its offset.
 *
 * Printable means 0x20–0x7e: no tabs and no newlines, which is what makes every candidate safely writable as one
 * line of the file `openssl passwd -in` reads. A run longer than `maxLength` is not truncated but DROPPED — a
 * truncated string is a candidate that is not in the image, and this provider only ever tests strings that are.
 */
export function extractPrintableStrings(
  buf: Uint8Array,
  opts: { minLength?: number; maxLength?: number } = {},
): HarvestedString[] {
  const minLength = opts.minLength ?? MIN_STRING_LENGTH;
  const maxLength = opts.maxLength ?? MAX_CANDIDATE_LENGTH;
  const out: HarvestedString[] = [];
  // A whole rootfs is millions of printable runs, so the slice is taken by the buffer's own decoder when there is
  // one; `latin1` is byte-for-byte over the range this function admits, so both paths produce the same string.
  const source = Buffer.isBuffer(buf) ? buf : null;
  const slice = (from: number, to: number): string => {
    if (source) return source.toString('latin1', from, to);
    let value = '';
    for (let i = from; i < to; i++) value += String.fromCharCode(buf[i] as number);
    return value;
  };
  let start = -1;
  const flush = (end: number): void => {
    if (start < 0) return;
    const len = end - start;
    if (len >= minLength && len <= maxLength) out.push({ value: slice(start, end), offset: start });
    start = -1;
  };
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i] as number;
    if (b >= 0x20 && b <= 0x7e) {
      if (start < 0) start = i;
    } else {
      flush(i);
    }
  }
  flush(buf.length);
  return out;
}

/** `key=value`, with the key an identifier-ish token — the shape a config line or a compiled-in default has. */
const ASSIGNMENT_RE = /^([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*)$/;

/** A quoted run inside a longer string. */
const QUOTED_RE = /["']([^"']{1,128})["']/g;

/**
 * Pure: the candidates one harvested string yields.
 *
 * The derivations exist because the raw string is frequently NOT the password even when it contains it, and DES
 * makes that fatal rather than merely untidy. The Tenda camera ships
 * `current_force_upgrade_pwd=Td2N3ww1.0_tenda_force_upgrade` as a single string; DES hashes the first eight bytes,
 * so testing the string as harvested tests `current_`, which matches nothing. Splitting the assignment first yields
 * `Td2N3ww1.0_tenda_force_upgrade`, whose first eight bytes are the credential.
 *
 * Bounded on purpose: at most one literal, one assignment value, one token list and the quoted runs, so a
 * pathological string cannot expand into thousands of candidates and quietly consume the cap.
 */
export function deriveCandidates(raw: string): Array<{ value: string; derivation: CandidateDerivation; key?: string }> {
  const out: Array<{ value: string; derivation: CandidateDerivation; key?: string }> = [];
  const seen = new Set<string>();
  const add = (value: string, derivation: CandidateDerivation, key?: string): void => {
    if (value === '' || value.length > MAX_CANDIDATE_LENGTH || seen.has(value)) return;
    seen.add(value);
    out.push(key === undefined ? { value, derivation } : { value, derivation, key });
  };

  add(raw, 'literal');

  const assignment = ASSIGNMENT_RE.exec(raw);
  if (assignment) add((assignment[2] ?? '').trim(), 'assignment-value', assignment[1] as string);

  QUOTED_RE.lastIndex = 0;
  for (let m = QUOTED_RE.exec(raw); m; m = QUOTED_RE.exec(raw)) add(m[1] as string, 'quoted');

  if (/\s/.test(raw)) {
    for (const token of raw.split(/\s+/)) add(token, 'token');
  }
  return out;
}

/** Keys whose VALUE is a credential by name. The one derivation signal that is about meaning rather than shape. */
const CREDENTIAL_KEY_RE = /(pass|pwd|secret|cred|auth|login|admin|token|passphrase)/i;

/** A string that is plainly not a password: a path, a format string, a URL, a C identifier list. */
const PATHLIKE_RE = /[/\\]/;
const FORMATLIKE_RE = /%[-0-9.]*[a-zA-Z]/;
const MACRO_RE = /^[A-Z][A-Z0-9_]{4,}$/;

/**
 * Pure: how strong a claim this candidate has on the cap.
 *
 * An ORDERING, never a verdict. A candidate that scores zero is not a candidate that was cleared — it is tested
 * exactly like any other whenever the cap does not bind, and the cap's own rule is stated on the result when it
 * does. The weights put PROVENANCE above shape, because "it is the value of something whose name contains `pwd`"
 * is evidence and "it is nine lowercase letters" is a guess.
 */
export function candidateScore(candidate: Candidate): number {
  const { value, derivation, key } = candidate;
  let score = 0;
  if (key !== undefined && CREDENTIAL_KEY_RE.test(key)) score += 6;
  if (derivation === 'assignment-value') score += 3;
  else if (derivation === 'quoted') score += 1;
  if (value.length >= 4 && value.length <= 24) score += 2;
  else if (value.length <= 48) score += 1;
  if (!/\s/.test(value)) score += 1;
  if (/[A-Za-z]/.test(value) && /[0-9]/.test(value)) score += 1;
  if (PATHLIKE_RE.test(value)) score -= 2;
  if (FORMATLIKE_RE.test(value)) score -= 2;
  if (MACRO_RE.test(value)) score -= 1;
  return score;
}

/** Pure: the rule `rankCandidates` applies, in words, so a truncated candidate set states what dropped it. */
export function describeRankRule(cap: number): string {
  return [
    `a cap of ${cap} candidate(s), taken in order of provenance first (the value of an assignment whose key names a`,
    'credential, then any assignment value, then a quoted run), then shape (password-like length, no whitespace, a',
    'mix of letters and digits, penalised for looking like a path, a format string or a macro name), then the string',
    'itself — never harvest order',
  ].join(' ');
}

/**
 * Pure: choose which candidates the run tests, and hand back the ones the cap dropped.
 *
 * The second sort key is the candidate value, not the walk order, for the reason `selectFindings` in `binvuln.ts`
 * exists: a cap filled in traversal order makes the tested SET an artifact of how the rootfs happens to be laid
 * out, and two runs over the same image would then test different things.
 */
export function rankCandidates(input: { candidates: Candidate[]; cap: number }): {
  selected: Candidate[];
  dropped: number;
} {
  const ordered = [...input.candidates].sort(
    (a, b) => candidateScore(b) - candidateScore(a) || a.value.localeCompare(b.value),
  );
  if (input.cap <= 0) return { selected: ordered, dropped: 0 };
  return { selected: ordered.slice(0, input.cap), dropped: Math.max(0, ordered.length - input.cap) };
}

/**
 * Pure: the candidates a scheme actually has to hash, and what each stands for.
 *
 * DES reads eight bytes, so every candidate sharing an eight-byte prefix is ONE test — which both shrinks the work
 * and, more importantly, fixes what a hit means. The representative kept is the shortest (ties broken by the
 * string) so a match reports `Td2N3ww1` rather than whichever 30-character string happened to be first.
 */
export function collapseForScheme(
  scheme: CryptScheme,
  candidates: Candidate[],
): { tests: Array<{ password: string; candidate: Candidate }>; collapsed: number } {
  if (scheme !== 'descrypt') {
    return { tests: candidates.map((candidate) => ({ password: candidate.value, candidate })), collapsed: 0 };
  }
  const byPrefix = new Map<string, { password: string; candidate: Candidate }>();
  for (const candidate of candidates) {
    const password = desEffectivePassword(candidate.value);
    const held = byPrefix.get(password);
    if (
      held === undefined ||
      candidate.value.length < held.candidate.value.length ||
      (candidate.value.length === held.candidate.value.length && candidate.value < held.candidate.value)
    ) {
      byPrefix.set(password, { password, candidate });
    }
  }
  return { tests: [...byPrefix.values()], collapsed: candidates.length - byPrefix.size };
}

// ---------------------------------------------------------------------------------------------------------------
// The verdict, and the sentences it is not allowed to be without (pure)
// ---------------------------------------------------------------------------------------------------------------

/** What happened to one stored hash. Three outcomes, and none of them may be represented by silence. */
export type TargetOutcome =
  | { outcome: 'recovered'; password: string; candidate: Candidate; tested: number }
  | { outcome: 'not-recovered'; tested: number; collapsed: number }
  | { outcome: 'blocked'; reason: string };

/** One stored hash and what this run established about it. */
export interface TargetResult {
  account: string;
  uid: number | null;
  file: string;
  scheme: CryptScheme;
  schemeLabel: string;
  hashRedacted: string;
  locked: boolean;
  result: TargetOutcome;
}

/** How the candidate set was built, and every bound that kept it from being larger. */
export interface CandidateSummary {
  root: string;
  filesFound: number;
  filesRead: number;
  filesTooLarge: number;
  filesUnreadable: number;
  dirsUnreadable: number;
  deepDirsSkipped: number;
  bytesRead: number;
  /** Printable runs harvested, before derivation and de-duplication. */
  stringsHarvested: number;
  /** Distinct candidates after derivation and de-duplication — the real denominator. */
  candidatesDistinct: number;
  /** Candidates actually tested (the cap applied). */
  candidatesTested: number;
  /** Candidates the cap dropped, after ranking. */
  candidatesDropped: number;
  cap: number;
  capRule: string;
  minStringLength: number;
  maxCandidateLength: number;
}

/** Which question this run answered, or which one it could not. */
export type CredMatchState = 'no_target' | 'no_account_files' | 'no_hashes' | 'no_candidates' | 'scanned';

export interface CredMatchResult {
  available: boolean;
  state: CredMatchState;
  reason: string;
  /** Null whenever no candidate set was ever built — different from a set that matched nothing. */
  candidates: CandidateSummary | null;
  targets: TargetResult[];
  openssl: OpensslCapability;
  findings: FindingDraft[];
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Where a candidate came from, in words — quoted verbatim by a hit's rationale. */
export function describeProvenance(candidate: Candidate): string {
  const where = `\`${candidate.file}\` at offset 0x${candidate.offset.toString(16)}`;
  switch (candidate.derivation) {
    case 'assignment-value':
      return `the value of \`${candidate.key ?? '?'}=\` in a string shipped in ${where}`;
    case 'quoted':
      return `a quoted run inside a string shipped in ${where}`;
    case 'token':
      return `a whitespace-separated token of a string shipped in ${where}`;
    default:
      return `a string shipped in ${where}`;
  }
}

/**
 * Pure: the sentence a miss is not allowed to be without.
 *
 * "Not recovered" has exactly one honest reading — these N strings, and no others, failed to reproduce this hash —
 * and one dishonest one that every reader will reach for unless it is refused explicitly. So the wording names the
 * number, the source of the candidates and the bound, and then says the thing outright.
 */
export function describeBoundedNegative(target: TargetResult, tested: number, summary: CandidateSummary): string {
  const collapse =
    target.scheme === 'descrypt'
      ? ` The ${summary.candidatesTested} candidate(s) collapse to ${tested} distinct ${DES_PASSWORD_BYTES}-byte prefix(es), because traditional DES hashes only the first ${DES_PASSWORD_BYTES} bytes of a password — so those are the tests actually performed.`
      : '';
  const dropped = summary.candidatesDropped
    ? ` ${summary.candidatesDropped} further candidate(s) were dropped by ${summary.capRule}, so they were not tested at all.`
    : '';
  return [
    `${plural(tested, 'candidate', 'candidates')} drawn from this image's own printable strings did not reproduce`,
    `the ${target.schemeLabel} hash stored for '${target.account}'.${collapse}${dropped}`,
    'This is a bounded negative and nothing more: the candidate set is the strings this firmware ships',
    `(${summary.stringsHarvested} run(s) of ${summary.minStringLength}+ printable bytes over ${summary.filesRead} file(s)`,
    `under ${summary.root}), so a password that is not written down anywhere in the image cannot be found this way.`,
    'It does NOT mean the password is strong, unknown, or absent from a vendor default list — no keyspace was',
    'searched and no wordlist was consulted.',
  ].join(' ');
}

/** Pure: the run-level sentence — what was joined against what, and what the result is bounded by. */
export function describeCoverage(targets: TargetResult[], summary: CandidateSummary): string {
  const recovered = targets.filter((t) => t.result.outcome === 'recovered').length;
  const blocked = targets.filter((t) => t.result.outcome === 'blocked').length;
  const missed = targets.length - recovered - blocked;
  return [
    `${plural(recovered, 'password', 'passwords')} recovered from ${plural(targets.length, 'stored hash', 'stored hashes')}`,
    `(${missed} not reproduced by the candidate set, ${blocked} in a scheme this deployment cannot compute).`,
    `The candidate set is ${summary.candidatesTested} of ${summary.candidatesDistinct} distinct string(s) derived from`,
    `${summary.stringsHarvested} printable run(s) over ${summary.filesRead} of ${summary.filesFound} file(s) under`,
    `${summary.root}. This is a cross-reference of the image against itself, not a password crack: no wordlist and no`,
    'keyspace search took part, so it finds a password only when the firmware ships the plaintext somewhere.',
  ].join(' ');
}

// ---------------------------------------------------------------------------------------------------------------
// Findings (pure)
// ---------------------------------------------------------------------------------------------------------------

/** A recovered UID-0 password is unauthenticated root the moment any login path is live; anything else is high. */
function severityForRecovery(target: TargetResult): FindingSeverity {
  if (target.locked) return 'medium';
  return target.uid === 0 || target.account === 'root' ? 'critical' : 'high';
}

/**
 * Pure: turn the per-hash outcomes into findings.
 *
 * Every target produces exactly one finding, whichever way it went, because the three outcomes need three different
 * responses and an outcome represented by an absent row is an outcome the ledger cannot show. The recovered ones
 * carry the plaintext — that IS the finding — while the stored hash stays redacted, which is the convention
 * `fsaudit` set for hash material and there is no reason for this provider to break it.
 */
export function buildCredMatchFindings(targets: TargetResult[], summary: CandidateSummary): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  for (const target of targets) {
    const base = {
      account: target.account,
      uid: target.uid,
      file: target.file,
      scheme: target.scheme,
      schemeLabel: target.schemeLabel,
      hashRedacted: target.hashRedacted,
      ...(target.locked ? { accountLockedInFile: true } : {}),
    };

    if (target.result.outcome === 'recovered') {
      const { password, candidate, tested } = target.result;
      const truncation =
        target.scheme === 'descrypt' && candidate.value.length > DES_PASSWORD_BYTES
          ? ` The string as shipped is \`${candidate.value}\`; traditional DES hashes only its first ${DES_PASSWORD_BYTES} bytes, so the credential is \`${password}\` and any longer string with that prefix authenticates identically.`
          : '';
      drafts.push({
        kind: 'credential-recovered-from-image',
        title: `Password for '${target.account}' is recoverable from this image's own strings (${target.schemeLabel}): ${password}`,
        severity: severityForRecovery(target),
        proofState: 'static_confirmed',
        evidenceChannel: 'static_bytes',
        evidence: {
          ...base,
          password,
          candidate: candidate.value,
          derivation: candidate.derivation,
          ...(candidate.key === undefined ? {} : { assignmentKey: candidate.key }),
          candidateFile: candidate.file,
          candidateOffset: candidate.offset,
          candidatesTested: tested,
        },
        rationale: [
          `Hashing this string with the salt stored beside the account reproduces the stored ${target.schemeLabel}`,
          `hash byte for byte. The string is not a guess and did not come from a wordlist: it is ${describeProvenance(candidate)},`,
          `found by cross-referencing this firmware's ${summary.stringsHarvested} printable string(s) against its own`,
          `credential store.${truncation}`,
          'What is confirmed is a property of the bytes — this plaintext maps to that stored hash. It is NOT a claim',
          'that the account is enabled, that any login service is reachable, or that a physical unit still runs this',
          `firmware.${target.locked ? ' The account is marked locked in the file that stores the hash, so the credential is recorded here as a reusable secret rather than as a live login.' : ''}`,
          'The stored hash is redacted in the evidence, as elsewhere in this workbench; the recovered plaintext is',
          'shown because it is the finding.',
        ].join(' '),
      });
      continue;
    }

    if (target.result.outcome === 'blocked') {
      drafts.push({
        kind: 'credential-scheme-not-computable',
        title: `Password for '${target.account}' could not be tested — this deployment cannot compute ${target.schemeLabel}`,
        severity: 'info',
        proofState: 'blocked_by_platform',
        evidence: { ...base, reason: target.result.reason, candidatesAvailable: summary.candidatesTested },
        rationale: [
          `${target.result.reason}. The cross-reference was requested for this account and produced no answer, which`,
          'is recorded so the absence of a result is visible as a missing capability rather than mistaken for a hash',
          `that held. The ${summary.candidatesTested} candidate(s) harvested from this image were never hashed against`,
          'it. This is NOT "the password was not found": nothing was tried.',
        ].join(' '),
      });
      continue;
    }

    const { tested } = target.result;
    drafts.push({
      kind: 'credential-not-recovered-from-image',
      title: `Password for '${target.account}' not recovered — ${plural(tested, 'candidate', 'candidates')} from this image's own strings did not reproduce the ${target.schemeLabel} hash`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidenceChannel: 'static_bytes',
      evidence: {
        ...base,
        candidatesTested: tested,
        candidatesDistinct: summary.candidatesDistinct,
        candidatesDropped: summary.candidatesDropped,
        capRule: summary.capRule,
        stringsHarvested: summary.stringsHarvested,
        filesRead: summary.filesRead,
        root: summary.root,
      },
      rationale: describeBoundedNegative(target, tested, summary),
    });
  }
  return drafts;
}

/** Titles for the states where the question was asked and could not be answered. Each names a DIFFERENT cause. */
const BLOCKED_TITLE: Record<Exclude<CredMatchState, 'scanned'>, string> = {
  no_target: 'Credential cross-reference could not run — there is nothing to read',
  no_account_files: 'Credential cross-reference examined no account: no /etc/passwd or /etc/shadow could be read',
  no_hashes: 'Credential cross-reference had no hash to test',
  no_candidates: 'Credential cross-reference had no candidates — no printable strings were harvested',
};

/**
 * Pure: a result for a run that never got as far as hashing anything.
 *
 * All four carry `blocked_by_platform`, which in this codebase means the question was asked and could not be
 * answered. They are kept as four states because they need four different responses: run an extraction, look for
 * the credentials somewhere other than the account files (DVRF symlinks its whole account database to /dev/null),
 * accept that every account is locked or passwordless, or find out why the rootfs yielded no strings.
 */
export function blockedResult(state: Exclude<CredMatchState, 'scanned'>, reason: string): CredMatchResult {
  return {
    available: false,
    state,
    reason,
    candidates: null,
    targets: [],
    openssl: { available: false, verifiedFlags: [], failures: [] },
    findings: [
      {
        kind: 'credmatch-blocked',
        title: BLOCKED_TITLE[state],
        severity: 'info',
        proofState: 'blocked_by_platform',
        evidence: { state, reason },
        rationale: [
          `${reason}.`,
          'The cross-reference of the stored password hashes in this image against its own printable strings',
          'produced no answer, recorded here so the absence of credential findings is visible as a question that was',
          'never asked. It is NOT "no recoverable password": nothing was hashed.',
        ].join(' '),
      },
    ],
  };
}

// ---------------------------------------------------------------------------------------------------------------
// The runner (walks the disk and shells out; everything it decides lives above)
// ---------------------------------------------------------------------------------------------------------------

/** The account files read, in the order a real system consults them, each with the layout it actually has. */
const ACCOUNT_FILES: ReadonlyArray<{ path: string; kind: AccountFileKind }> = [
  { path: 'etc/shadow', kind: 'shadow' },
  { path: 'etc/passwd', kind: 'passwd' },
];

/** How many candidates one run tests before `rankCandidates` has to choose. */
export const DEFAULT_CANDIDATE_CAP = 200_000;

/** How many distinct stored hashes one run attacks. A rootfs with more accounts than this states the bound. */
export const DEFAULT_TARGET_CAP = 12;

/** How long one `openssl passwd` batch may take. sha512crypt over 200k candidates is minutes, not seconds. */
export const DEFAULT_TIMEOUT_MS = 20 * 60 * 1000;

/** Files above this are not read for strings. A cap on bytes, and it is reported as one. */
const MAX_FILE_BYTES = 64 * 1024 * 1024;

/** How deep the rootfs walk descends before it refuses and counts what it refused. */
const MAX_WALK_DEPTH = 24;

export interface CredMatchOptions {
  candidateCap?: number;
  targetCap?: number;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
}

/** `FIRMLAB_CREDMATCH_CANDIDATE_CAP` — how many candidates a run tests. `0` means "no cap". */
export function credmatchCandidateCap(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.FIRMLAB_CREDMATCH_CANDIDATE_CAP;
  if (raw === undefined || raw.trim() === '') return DEFAULT_CANDIDATE_CAP;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_CANDIDATE_CAP;
}

/** Confine a rootfs-relative path to the rootfs; returns the absolute path, or null on traversal. */
function safeJoin(root: string, rel: string): string | null {
  const abs = path.resolve(root, rel);
  if (abs !== root && !abs.startsWith(root + path.sep)) return null;
  return abs;
}

/** Best-effort UTF-8 read of a rootfs-relative file. Null means "not readable", which is not "empty". */
function readInside(root: string, rel: string): string | null {
  const abs = safeJoin(root, rel);
  if (!abs) return null;
  try {
    return fs.readFileSync(abs, 'utf8');
  } catch {
    return null;
  }
}

/** Walk the rootfs harvesting printable strings, counting everything that kept the harvest from being larger. */
function harvestStrings(root: string): {
  strings: Array<{ value: string; file: string; offset: number }>;
  filesFound: number;
  filesRead: number;
  filesTooLarge: number;
  filesUnreadable: number;
  dirsUnreadable: number;
  deepDirsSkipped: number;
  bytesRead: number;
} {
  const strings: Array<{ value: string; file: string; offset: number }> = [];
  let filesFound = 0;
  let filesRead = 0;
  let filesTooLarge = 0;
  let filesUnreadable = 0;
  let dirsUnreadable = 0;
  let deepDirsSkipped = 0;
  let bytesRead = 0;

  const walk = (dir: string, depth: number): void => {
    if (depth > MAX_WALK_DEPTH) {
      deepDirsSkipped++;
      return;
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      dirsUnreadable++;
      return;
    }
    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      // lstat semantics: a symlink is neither a file nor a directory here, so the walk never follows one out of
      // the rootfs and never reads the same bytes twice through a link.
      if (entry.isDirectory()) {
        walk(abs, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      filesFound++;
      let size = 0;
      try {
        size = fs.statSync(abs).size;
      } catch {
        filesUnreadable++;
        continue;
      }
      if (size > MAX_FILE_BYTES) {
        filesTooLarge++;
        continue;
      }
      let buf: Buffer;
      try {
        buf = fs.readFileSync(abs);
      } catch {
        filesUnreadable++;
        continue;
      }
      filesRead++;
      bytesRead += buf.length;
      const rel = path.relative(root, abs);
      for (const hit of extractPrintableStrings(buf)) {
        strings.push({ value: hit.value, file: rel, offset: hit.offset });
      }
    }
  };

  walk(root, 0);
  return { strings, filesFound, filesRead, filesTooLarge, filesUnreadable, dirsUnreadable, deepDirsSkipped, bytesRead };
}

/** Derive and de-duplicate candidates from the harvested strings, keeping the first provenance seen for each. */
function buildCandidates(strings: Array<{ value: string; file: string; offset: number }>): Candidate[] {
  const byValue = new Map<string, Candidate>();
  for (const s of strings) {
    for (const derived of deriveCandidates(s.value)) {
      const held = byValue.get(derived.value);
      const candidate: Candidate = {
        value: derived.value,
        derivation: derived.derivation,
        ...(derived.key === undefined ? {} : { key: derived.key }),
        file: s.file,
        offset: s.offset,
      };
      // Keep whichever provenance ranks higher, so a value that appears both as a bare literal and as the value of
      // a `…_pwd=` assignment is reported with the assignment — the provenance a reader can act on.
      if (held === undefined || candidateScore(candidate) > candidateScore(held)) byValue.set(derived.value, candidate);
    }
  }
  return [...byValue.values()];
}

/** Run one `openssl passwd` invocation and return its stdout, or the reason it failed. */
async function openssl(
  args: string[],
  timeoutMs: number,
): Promise<{ ok: true; stdout: string } | { ok: false; reason: string }> {
  try {
    const r = await execFileAsync('openssl', args, { timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024 });
    return { ok: true, stdout: r.stdout };
  } catch (err) {
    const e = err as { stderr?: string; message?: string };
    const reason = (e.stderr ?? '').trim().split('\n')[0] || e.message || String(err);
    return { ok: false, reason };
  }
}

/**
 * Probe what `openssl passwd` on THIS box can actually do, by making it answer a question we know the answer to.
 *
 * The recorded vectors are the point. `openssl` being on PATH says nothing about which schemes its `passwd`
 * subcommand still has — OpenSSL 3.0 dropped `-crypt` outright — and a flag that has quietly changed behaviour is
 * worse than one that is missing, because it turns every account into a confident false negative. A flag only ends
 * up in `verifiedFlags` after reproducing its known answer exactly.
 */
export async function probeOpenssl(timeoutMs = 30_000): Promise<OpensslCapability> {
  if (!(await isToolAvailable('openssl'))) return { available: false, verifiedFlags: [], failures: [] };
  const verifiedFlags: string[] = [];
  const failures: Array<{ flag: string; reason: string }> = [];
  for (const vector of OPENSSL_SELF_TEST) {
    const run = await openssl(['passwd', vector.flag, '-salt', vector.salt, vector.password], timeoutMs);
    if (!run.ok) {
      failures.push({ flag: vector.flag, reason: run.reason });
      continue;
    }
    const got = run.stdout.trim();
    if (got === vector.expect) verifiedFlags.push(vector.flag);
    else failures.push({ flag: vector.flag, reason: `expected ${vector.expect}, got ${got || '(no output)'}` });
  }
  return { available: true, verifiedFlags, failures };
}

/**
 * Hash a candidate list against one salt with `openssl passwd`, in one process.
 *
 * `-in` reads one password per line and prints one hash per line, preserving leading and trailing spaces — verified
 * against per-invocation hashing. Every candidate is printable ASCII by construction (`extractPrintableStrings`
 * keeps 0x20–0x7e only), so no candidate can contain the newline that would desynchronise the two lists; the count
 * is checked anyway, because a silent desync would attribute a hit to the wrong string.
 *
 * The returned hashes are checked to carry the target's own `$id$…$salt$` prefix. That is what catches a build that
 * ignores a `rounds=` cost, truncates an over-long salt, or otherwise answers a different question from the one
 * asked — all of which would produce a clean, confident, wrong "not recovered".
 */
async function hashBatchWithOpenssl(
  flag: string,
  hash: ParsedCryptHash,
  passwords: string[],
  timeoutMs: number,
): Promise<{ ok: true; hashes: string[] } | { ok: false; reason: string }> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-credmatch-'));
  const listFile = path.join(dir, 'candidates.txt');
  try {
    fs.writeFileSync(listFile, passwords.length ? `${passwords.join('\n')}\n` : '');
    const run = await openssl(['passwd', flag, '-salt', hash.salt, '-in', listFile], timeoutMs);
    if (!run.ok) return { ok: false, reason: `openssl passwd ${flag} failed: ${run.reason}` };
    const hashes = run.stdout.split('\n');
    // `-in` emits a trailing newline; drop exactly that one empty tail rather than filtering empties, which would
    // hide a desync instead of reporting it.
    if (hashes[hashes.length - 1] === '') hashes.pop();
    if (hashes.length !== passwords.length) {
      return {
        ok: false,
        reason: `openssl passwd ${flag} returned ${hashes.length} hash(es) for ${passwords.length} candidate(s), so the two lists cannot be lined up`,
      };
    }
    const stray = hashes.findIndex((h) => !h.startsWith(hash.prefix));
    if (stray >= 0) {
      return {
        ok: false,
        reason: `openssl passwd ${flag} returned \`${hashes[stray]}\` where a hash beginning \`${hash.prefix}\` was required, so this build is not hashing with the salt it was given`,
      };
    }
    return { ok: true, hashes };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Cross-reference the credential hashes in an extracted rootfs against the printable strings the same rootfs ships.
 *
 * Degrades honestly at every step, and the steps stay distinguishable: nothing to read, no account file, no
 * testable hash, no strings, and a run that happened. Only the last may be read as a statement about the firmware,
 * and even then only together with its candidate denominator.
 */
export async function runCredMatch(
  scanRoot: string,
  handle: JobHandle,
  opts: CredMatchOptions = {},
): Promise<CredMatchResult> {
  const env = opts.env ?? process.env;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const root = path.resolve(scanRoot);

  let isDir = false;
  try {
    isDir = fs.statSync(root).isDirectory();
  } catch {
    isDir = false;
  }
  if (!isDir) return blockedResult('no_target', `there is nothing to read: ${root} is not an extracted directory`);

  const accountFiles: Array<{ path: string; text: string; kind: AccountFileKind }> = [];
  const unreadable: string[] = [];
  for (const source of ACCOUNT_FILES) {
    const text = readInside(root, source.path);
    if (text === null) unreadable.push(source.path);
    else accountFiles.push({ path: source.path, text, kind: source.kind });
  }
  if (accountFiles.length === 0) {
    return blockedResult(
      'no_account_files',
      `none of ${ACCOUNT_FILES.map((f) => f.path).join(', ')} could be read under ${root} (${unreadable.join(', ')} absent or unreadable), so no stored hash was examined`,
    );
  }

  const allTargets = collectTargets(accountFiles);
  if (allTargets.length === 0) {
    return blockedResult(
      'no_hashes',
      `${accountFiles.map((f) => f.path).join(' and ')} were read and hold no testable password hash (every account is empty, locked or unrecognised), so there is nothing to cross-reference`,
    );
  }
  const targetCap = opts.targetCap ?? DEFAULT_TARGET_CAP;
  const targets = rankTargets(allTargets);
  if (targets.length > targetCap) {
    handle.log(
      `credmatch: ${targets.length} stored hash(es); the cap tests ${targetCap} and records the rest as untested.`,
    );
  }

  const harvest = harvestStrings(root);
  const candidates = buildCandidates(harvest.strings);
  if (candidates.length === 0) {
    return blockedResult(
      'no_candidates',
      `${harvest.filesRead} file(s) under ${root} yielded no printable run of ${MIN_STRING_LENGTH}+ bytes, so the candidate set is empty and no hash could be tested`,
    );
  }

  const cap = opts.candidateCap ?? credmatchCandidateCap(env);
  const { selected, dropped } = rankCandidates({ candidates, cap });
  const summary: CandidateSummary = {
    root,
    filesFound: harvest.filesFound,
    filesRead: harvest.filesRead,
    filesTooLarge: harvest.filesTooLarge,
    filesUnreadable: harvest.filesUnreadable,
    dirsUnreadable: harvest.dirsUnreadable,
    deepDirsSkipped: harvest.deepDirsSkipped,
    bytesRead: harvest.bytesRead,
    stringsHarvested: harvest.strings.length,
    candidatesDistinct: candidates.length,
    candidatesTested: selected.length,
    candidatesDropped: dropped,
    cap,
    capRule: describeRankRule(cap),
    minStringLength: MIN_STRING_LENGTH,
    maxCandidateLength: MAX_CANDIDATE_LENGTH,
  };
  handle.log(
    `credmatch: ${summary.candidatesTested} of ${summary.candidatesDistinct} candidate(s) from ${summary.stringsHarvested} string(s) in ${summary.filesRead} file(s), against ${targets.length} stored hash(es).`,
  );

  const capability = await probeOpenssl();
  if (!capability.available) handle.log('credmatch: openssl is not installed — only DES crypt hashes can be tested.');
  for (const failure of capability.failures) {
    handle.log(`credmatch: openssl passwd ${failure.flag} failed its known-answer self-test (${failure.reason}).`);
  }

  const results: TargetResult[] = [];
  for (const [index, target] of targets.entries()) {
    const shell: Omit<TargetResult, 'result'> = {
      account: target.account,
      uid: target.uid,
      file: target.file,
      scheme: target.hash.scheme,
      schemeLabel: target.hash.label,
      hashRedacted: redactHash(target.hash),
      locked: target.locked,
    };
    // A hash past the cap is not tested, and that is reported as its own outcome rather than as an absent row: an
    // account this run never looked at must not be indistinguishable from one whose hash held.
    if (targetCap > 0 && index >= targetCap) {
      results.push({
        ...shell,
        result: {
          outcome: 'blocked',
          reason: `this run tests at most ${targetCap} stored hash(es) and this rootfs holds ${targets.length}, ordered UID 0 first, then unlocked accounts, then by name — so this one was never hashed against`,
        },
      });
      continue;
    }
    const backend = resolveBackend(target.hash.scheme, capability);
    if (backend.kind === 'unsupported') {
      handle.log(`credmatch: '${target.account}' (${target.hash.label}) — ${backend.reason}.`);
      results.push({ ...shell, result: { outcome: 'blocked', reason: backend.reason } });
      continue;
    }

    const { tests, collapsed } = collapseForScheme(target.hash.scheme, selected);
    let hit: { password: string; candidate: Candidate } | null = null;

    if (backend.kind === 'internal-des') {
      for (const test of tests) {
        if (desCrypt(test.password, target.hash.salt) === target.hash.full) {
          hit = test;
          break;
        }
      }
    } else {
      const batch = await hashBatchWithOpenssl(
        backend.flag,
        target.hash,
        tests.map((t) => t.password),
        timeoutMs,
      );
      if (!batch.ok) {
        handle.log(`credmatch: '${target.account}' (${target.hash.label}) — ${batch.reason}.`);
        results.push({ ...shell, result: { outcome: 'blocked', reason: batch.reason } });
        continue;
      }
      const index = batch.hashes.indexOf(target.hash.full);
      if (index >= 0) hit = tests[index] ?? null;
    }

    if (hit) {
      handle.log(`credmatch: recovered the ${target.hash.label} password for '${target.account}'.`);
      results.push({
        ...shell,
        result: { outcome: 'recovered', password: hit.password, candidate: hit.candidate, tested: tests.length },
      });
    } else {
      results.push({ ...shell, result: { outcome: 'not-recovered', tested: tests.length, collapsed } });
    }
  }

  const reason = describeCoverage(results, summary);
  handle.log(reason);
  return {
    available: true,
    state: 'scanned',
    reason,
    candidates: summary,
    targets: results,
    openssl: capability,
    findings: buildCredMatchFindings(results, summary),
  };
}
