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

/** Extract printable-ASCII runs of at least `minLength`, then classify each for secret-likeness. */
export function extractStrings(buf: Uint8Array, options: StringOptions = {}): StringHit[] {
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
      if (hits.length >= maxStrings) return hits;
    }
  }
  flush(buf.length);
  return hits;
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

/** Convenience: only the strings that classified as a secret, sorted by severity. */
export function extractSecrets(buf: Uint8Array, options?: StringOptions): StringHit[] {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return extractStrings(buf, options)
    .filter((h) => h.secretKind)
    .sort((a, b) => (order[a.severity ?? 'info'] ?? 9) - (order[b.severity ?? 'info'] ?? 9));
}
