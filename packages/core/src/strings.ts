/**
 * ASCII string extraction with a firmware-tuned secret/credential classifier.
 *
 * Equivalent to `strings -n <min>` plus a set of heuristics that flag the literals that actually matter in
 * firmware audits: hardcoded default passwords, private-key blocks, API tokens, connection strings, and the
 * well-known vendor default-credential markers. Pure and testable; the API can additionally shell out to
 * `gitleaks` for a second opinion on extracted rootfs files.
 */
import type { StringHit } from './types.js';

const PRINTABLE_MIN = 0x20;
const PRINTABLE_MAX = 0x7e;

export interface StringOptions {
  /** Minimum run length to emit. Default 5. */
  minLength?: number;
  /** Cap on emitted strings. Default 20000. */
  maxStrings?: number;
}

/**
 * A string walk and how far it actually got.
 *
 * `maxStrings` ends the walk, and the walk proceeds from offset 0 upward, so the cap truncates by FILE OFFSET —
 * by arrival order, which is the one thing a bound in this codebase may not silently do. Measured: the 106 MB
 * GL.iNet image hits the 20 000-string cap at 11% of the file, so 89% of it is never looked at; the 34.5 MB
 * Framework BIOS capsule stops at 92.5%. Both then rendered as "no secret-like strings detected".
 *
 * `scannedBytes` is what makes that statable. Equal to `totalBytes` on a complete walk; below it, everything past
 * that offset was not read and nothing at all is known about it.
 */
export interface StringScan {
  hits: StringHit[];
  /** Offset the walk reached. Less than `totalBytes` means the cap stopped it and the remainder is unexamined. */
  scannedBytes: number;
  totalBytes: number;
}

/**
 * Extract printable-ASCII runs of at least `minLength`, classify each for secret-likeness, and report how much of
 * the buffer the walk covered. Prefer this over `extractStrings` wherever the result is shown to a person: an
 * empty hit list means "nothing in the first `scannedBytes`", never "nothing in this image".
 */
export function scanStrings(buf: Uint8Array, options: StringOptions = {}): StringScan {
  const minLength = Math.max(1, options.minLength ?? 5);
  const maxStrings = options.maxStrings ?? 20000;
  const hits: StringHit[] = [];

  let start = -1;
  const flush = (end: number): void => {
    if (start < 0) return;
    const len = end - start;
    if (len >= minLength) {
      const value = asciiSlice(buf, start, end);
      const { secretKind, severity } = classifySecret(value);
      const hit: StringHit = { offset: start, value };
      if (secretKind !== undefined) hit.secretKind = secretKind;
      if (severity !== undefined) hit.severity = severity;
      hits.push(hit);
    }
    start = -1;
  };

  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i] ?? 0;
    if (byte >= PRINTABLE_MIN && byte <= PRINTABLE_MAX) {
      if (start < 0) start = i;
    } else {
      flush(i);
      if (hits.length >= maxStrings) return { hits, scannedBytes: i, totalBytes: buf.length };
    }
  }
  flush(buf.length);
  return { hits, scannedBytes: buf.length, totalBytes: buf.length };
}

/** Extract printable-ASCII runs of at least `minLength`, then classify each for secret-likeness. */
export function extractStrings(buf: Uint8Array, options: StringOptions = {}): StringHit[] {
  return scanStrings(buf, options).hits;
}

function asciiSlice(buf: Uint8Array, start: number, end: number): string {
  let s = '';
  for (let i = start; i < end; i++) s += String.fromCharCode(buf[i] ?? 0);
  return s;
}

interface SecretClassification {
  secretKind?: string;
  severity?: StringHit['severity'];
}

/** Vendor default-credential markers seen across consumer router firmware. */
const DEFAULT_CRED_MARKERS = ['SYS_ADMPASS', 'WLN_WPAPSK', 'PTP_PASS', 'L2T_PASS', 'WLN_WscNewKey', 'ATESTART'];

const SECRET_PATTERNS: Array<{ kind: string; severity: StringHit['severity']; re: RegExp }> = [
  { kind: 'private-key', severity: 'critical', re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { kind: 'aws-access-key', severity: 'high', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { kind: 'github-token', severity: 'high', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { kind: 'slack-token', severity: 'high', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { kind: 'jwt', severity: 'medium', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/ },
  {
    kind: 'connection-string',
    severity: 'high',
    re: /\b(mysql|postgres|postgresql|mongodb(\+srv)?|redis|amqp):\/\/[^\s"']*:[^\s"'@]+@/,
  },
  {
    kind: 'password-assignment',
    severity: 'medium',
    // No leading \b: firmware configs prefix the key (admin_password=, sys_secret:) with word chars.
    re: /(pass(word|wd)?|passwd|secret|api[_-]?key|token)\s*[=:]\s*\S{3,}/i,
  },
  { kind: 'shadow-hash', severity: 'high', re: /\$(1|2[aby]?|5|6|y)\$[./A-Za-z0-9$]{8,}/ },
  { kind: 'telnet-backdoor', severity: 'high', re: /\b(telnetd|utelnetd)\b.*(-l\s*\/bin\/sh|-p)/ },
];

/** Classify a string against the secret patterns and vendor markers. Returns empty object when benign. */
export function classifySecret(value: string): SecretClassification {
  for (const marker of DEFAULT_CRED_MARKERS) {
    if (value.includes(marker)) {
      return { secretKind: 'vendor-default-credential', severity: 'high' };
    }
  }
  for (const pat of SECRET_PATTERNS) {
    if (pat.re.test(value)) {
      return { secretKind: pat.kind, severity: pat.severity };
    }
  }
  return {};
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * The secret scan and the two bounds that shape it, stated rather than applied silently.
 *
 * Two different caps are at work and they truncate on different axes, which is why both are reported. The string
 * walk's cap cuts by file offset — arrival order — and is the dangerous one: what it drops was never examined.
 * The listing cap cuts by severity, after the sort, so what it drops was examined and ranked; `matched` says how
 * many there were so a reader can tell "none found" from "more than fit".
 */
export interface SecretScan {
  /** The listed secrets, severity-first, at most `listCap` of them. */
  secrets: StringHit[];
  /** How many classified as secrets before the listing cap — `secrets.length` when nothing was dropped. */
  matched: number;
  /** Offset the string walk reached. Below `totalBytes`, the remainder was never read. */
  scannedBytes: number;
  totalBytes: number;
}

/**
 * Only the strings that classified as a secret, severity-first, with the coverage the walk achieved.
 *
 * `listCap` bounds what is RETURNED, never what is counted: an empty `secrets` with a non-zero `matched` is
 * impossible, but a short `secrets` with a large `matched` is exactly the case a caller must be able to state.
 */
export function scanSecrets(buf: Uint8Array, options?: StringOptions, listCap = Number.POSITIVE_INFINITY): SecretScan {
  const scan = scanStrings(buf, options);
  const matched = scan.hits
    .filter((h) => h.secretKind)
    .sort((a, b) => (SEVERITY_ORDER[a.severity ?? 'info'] ?? 9) - (SEVERITY_ORDER[b.severity ?? 'info'] ?? 9));
  return {
    secrets: Number.isFinite(listCap) ? matched.slice(0, listCap) : matched,
    matched: matched.length,
    scannedBytes: scan.scannedBytes,
    totalBytes: scan.totalBytes,
  };
}

/** Convenience: only the strings that classified as a secret, sorted by severity. */
export function extractSecrets(buf: Uint8Array, options?: StringOptions): StringHit[] {
  return scanSecrets(buf, options).secrets;
}
