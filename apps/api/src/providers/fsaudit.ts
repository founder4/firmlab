/**
 * fsaudit provider — a firmwalker / FACT-style static security audit over an ALREADY-EXTRACTED Linux rootfs.
 * Where the SBOM/gitleaks tracks look at components and secrets, this track reads the classic
 * misconfiguration surface a firmware analyst checks by hand: /etc/passwd + /etc/shadow (empty root password,
 * weak legacy hashes, extra UID-0 accounts), /etc/inittab (a root shell or telnetd spawned by init), the
 * service start-up scripts (dropbear/sshd permitting root+empty passwords, telnetd in an rc script, anonymous
 * ftp) and notable files left in the image (private keys, authorized_keys, .htpasswd, packet captures).
 *
 * The detectors are PURE (each takes text/paths and returns FindingDraft[]) and unit-tested against synthetic
 * real-format inputs. Proof states are HONEST: a fact that is literally in the bytes (an empty password, a
 * weak hash, a private key on disk) is `static_confirmed`; a *service exposure* whose reachability depends on
 * the device being wired/powered (an init shell, telnetd, anon ftp) is `needs_runtime_reproduction` — a lead,
 * never a device verdict. Evidence carries the file path and the offending line, TRUNCATED, with any password
 * hash REDACTED (never the secret value). The runner tolerates every file being missing and degrades to
 * available:false when there is no rootfs — it never fabricates a finding.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FindingSeverity, ProofState } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';

const MAX_EVIDENCE = 200;
const MAX_PROCESS = 160;

/** Truncate an evidence string so a pathological line can't bloat the finding row. */
function truncate(s: string, max = MAX_EVIDENCE): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

// ============================================================================
// /etc/passwd + /etc/shadow
// ============================================================================

interface PasswdEntry {
  name: string;
  pw: string;
  uid: number;
  raw: string;
}

interface ShadowEntry {
  name: string;
  hash: string;
  raw: string;
}

/** Pure: parse /etc/passwd `name:pw:uid:gid:…` lines (comments/blank/malformed skipped). */
export function parsePasswd(passwd: string): PasswdEntry[] {
  const out: PasswdEntry[] = [];
  for (const raw of passwd.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const f = line.split(':');
    if (f.length < 3) continue;
    const name = f[0] ?? '';
    const uid = Number.parseInt(f[2] ?? '', 10);
    if (!name || Number.isNaN(uid)) continue;
    out.push({ name, pw: f[1] ?? '', uid, raw: line });
  }
  return out;
}

/** Pure: parse /etc/shadow `name:hash:…` lines (comments/blank/malformed skipped). */
export function parseShadow(shadow: string): ShadowEntry[] {
  const out: ShadowEntry[] = [];
  for (const raw of shadow.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const f = line.split(':');
    if (f.length < 2) continue;
    const name = f[0] ?? '';
    if (!name) continue;
    out.push({ name, hash: f[1] ?? '', raw: line });
  }
  return out;
}

// A DES crypt hash: exactly 13 chars from the crypt alphabet, no `$` scheme prefix.
const DES_CRYPT_RE = /^[./0-9A-Za-z]{13}$/;

/** Pure: classify a shadow hash as a weak/legacy scheme, or null when it is strong/absent/locked. */
function classifyWeakHash(hash: string): { scheme: string } | null {
  if (hash.startsWith('$1$')) return { scheme: 'md5crypt ($1$)' };
  if (DES_CRYPT_RE.test(hash)) return { scheme: 'DES crypt (13-char)' };
  return null; // $5$/$6$ (SHA), $2*/$y$ (bcrypt/yescrypt) are strong; *, !, !! are locked; '' is handled elsewhere
}

/** Redact the hash field of a shadow line so the offending line can be shown without leaking the secret. */
function redactShadowLine(raw: string): string {
  const f = raw.split(':');
  if (f.length >= 2 && f[1]) f[1] = '<redacted>';
  return f.join(':');
}

/**
 * Pure: audit the credential store. Flags (all `static_confirmed` — facts about the files):
 *   - a UID-0 account with an EMPTY password (passwd field empty, or `x` deferring to an empty shadow hash) → CRITICAL
 *   - a weak/legacy shadow hash (`$1$` MD5, or a 13-char DES crypt) → HIGH (hash value redacted in evidence)
 *   - a second UID-0 account besides root → HIGH
 */
export function auditCredentials(passwd: string, shadow: string): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const users = parsePasswd(passwd);
  const shadows = parseShadow(shadow);
  const shadowByName = new Map(shadows.map((s) => [s.name, s]));
  const uid0 = users.filter((u) => u.uid === 0);

  // Empty-password UID-0 accounts (unauthenticated root).
  for (const u of uid0) {
    let empty = false;
    let evPath = '/etc/passwd';
    let evLine = u.raw;
    if (u.pw === '') {
      empty = true; // password stored directly in passwd, and it is empty
    } else if (u.pw === 'x') {
      const sh = shadowByName.get(u.name);
      if (sh && sh.hash === '') {
        empty = true;
        evPath = '/etc/shadow';
        evLine = sh.raw;
      }
    }
    if (empty) {
      drafts.push({
        kind: 'empty-uid0-password',
        title: `UID-0 account '${u.name}' has an empty password`,
        severity: 'critical',
        proofState: 'static_confirmed',
        evidence: { path: evPath, account: u.name, uid: 0, line: truncate(evLine) },
        rationale:
          'A UID-0 account with an empty password grants unauthenticated root — the empty field is literally ' +
          'present in the extracted rootfs (static fact).',
      });
    }
  }

  // Second UID-0 accounts besides root (classic backdoor pattern).
  for (const u of uid0) {
    if (u.name === 'root') continue;
    drafts.push({
      kind: 'extra-uid0-account',
      title: `Second UID-0 account besides root: '${u.name}'`,
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: { path: '/etc/passwd', account: u.name, uid: 0, line: truncate(u.raw) },
      rationale:
        'A non-root account with UID 0 has full root privileges — present in /etc/passwd. A common backdoor ' +
        'pattern; confirm the account is expected.',
    });
  }

  // Weak/legacy shadow hashes (any account).
  for (const s of shadows) {
    const weak = classifyWeakHash(s.hash);
    if (!weak) continue;
    drafts.push({
      kind: 'weak-password-hash',
      title: `Weak/legacy ${weak.scheme} password hash for '${s.name}'`,
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: { path: '/etc/shadow', account: s.name, scheme: weak.scheme, line: truncate(redactShadowLine(s.raw)) },
      rationale: `A ${weak.scheme} hash is trivially brute-forced with modern hardware. The hash value is redacted in evidence; its presence is a static fact about the rootfs.`,
    });
  }

  return drafts;
}

// ============================================================================
// /etc/inittab
// ============================================================================

/**
 * Pure: audit /etc/inittab for a process that init spawns as root without authentication — a bare shell
 * (`::respawn:/bin/sh`), a getty told to skip login (`-n`) or run a shell as its login program (`-l /bin/sh`),
 * or telnetd. Both → HIGH / `needs_runtime_reproduction` (reachability depends on the device console/network).
 */
export function auditInittab(inittab: string): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  for (const raw of inittab.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(':');
    // inittab process is everything after the third colon (id:runlevels:action:process).
    const process = parts.length >= 4 ? parts.slice(3).join(':').trim() : '';
    if (!process) continue;

    if (/\btelnetd\b/.test(process)) {
      drafts.push({
        kind: 'inittab-telnetd',
        title: 'inittab spawns telnetd directly from init',
        severity: 'high',
        proofState: 'needs_runtime_reproduction',
        evidence: { path: '/etc/inittab', line: truncate(line), process: truncate(process, MAX_PROCESS) },
        rationale:
          'telnet is a cleartext, frequently unauthenticated remote-shell service started by init — a remote ' +
          'root exposure if the network interface comes up. Reachability needs runtime reproduction.',
      });
      continue;
    }

    const cmd = (process.split(/\s+/)[0] ?? '').replace(/^-/, '');
    const bareShell = /(?:^|\/)(?:ba|a)?sh$/.test(cmd);
    const isGetty = /getty\b/.test(process);
    const gettyNoLogin = isGetty && (/\s-n(?:\s|$)/.test(process) || /-l\s+\S*(?:ba|a)?sh(?:\s|$)/.test(process));
    if (bareShell || gettyNoLogin) {
      drafts.push({
        kind: 'inittab-root-shell',
        title: 'inittab spawns a root shell without login',
        severity: 'high',
        proofState: 'needs_runtime_reproduction',
        evidence: { path: '/etc/inittab', line: truncate(line), process: truncate(process, MAX_PROCESS) },
        rationale:
          'The init table launches a shell (or a getty that skips login) on a console/serial line — an ' +
          'unauthenticated root prompt if that line is reachable. Reachability depends on device wiring, so ' +
          'this needs runtime reproduction.',
      });
    }
  }
  return drafts;
}

// ============================================================================
// service configs / rc scripts
// ============================================================================

// A path that is an rc/init start-up script (etc/init.d/*, etc/rc*).
const RC_PATH_RE = /(?:^|\/)etc\/(?:init\.d\/|rc)/i;

/** Return the first line of `content` matching `re`, trimmed, or '' when none. */
function firstMatchingLine(content: string, re: RegExp): string {
  for (const raw of content.split('\n')) {
    if (re.test(raw)) return raw.trim();
  }
  return '';
}

/**
 * Pure: audit service start-up configuration.
 *   - an sshd/dropbear config with BOTH `PermitRootLogin yes` and `PermitEmptyPasswords yes` → HIGH / static_confirmed
 *   - telnetd launched from an rc/init script (etc/init.d/*, etc/rc*) → MEDIUM / needs_runtime_reproduction
 *   - anonymous ftp enabled (vsftpd `anonymous_enable=YES`) → MEDIUM / needs_runtime_reproduction
 */
export function auditServiceConfigs(files: { path: string; content: string }[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  for (const { path: p, content } of files) {
    const permitRoot = /^\s*PermitRootLogin\s+yes\b/im.test(content);
    const emptyPw = /^\s*PermitEmptyPasswords\s+yes\b/im.test(content);
    if (permitRoot && emptyPw) {
      drafts.push({
        kind: 'ssh-permit-root-empty',
        title: `SSH/dropbear config permits root login with empty passwords: ${p}`,
        severity: 'high',
        proofState: 'static_confirmed',
        evidence: { path: p, directives: ['PermitRootLogin yes', 'PermitEmptyPasswords yes'] },
        rationale:
          'The SSH server config both allows root login and accepts empty passwords — both directives are ' +
          'literally present. Combined with a passwordless UID-0 account this is unauthenticated remote root.',
      });
    }

    if (RC_PATH_RE.test(p) && /\btelnetd\b/.test(content)) {
      drafts.push({
        kind: 'rc-telnetd',
        title: `telnetd started from an rc/init script: ${p}`,
        severity: 'medium',
        proofState: 'needs_runtime_reproduction',
        evidence: { path: p, line: truncate(firstMatchingLine(content, /\btelnetd\b/)) },
        rationale:
          'A start-up script launches telnetd, a cleartext remote-shell service. Whether it is actually exposed ' +
          'depends on runtime (interface up, not firewalled), so this needs runtime reproduction.',
      });
    }

    if (/^\s*anonymous_enable\s*=\s*yes\b/im.test(content)) {
      drafts.push({
        kind: 'anon-ftp',
        title: `Anonymous FTP enabled: ${p}`,
        severity: 'medium',
        proofState: 'needs_runtime_reproduction',
        evidence: { path: p, line: truncate(firstMatchingLine(content, /anonymous_enable/i)) },
        rationale:
          'The FTP server config enables anonymous access. Exposure depends on the service running and being ' +
          'reachable, so this needs runtime reproduction.',
      });
    }
  }
  return drafts;
}

// ============================================================================
// content secret scan (a private key by CONTENT, not just by filename)
// ============================================================================

/** PEM private-key block headers → a human label for the key type. The block itself is unambiguous. */
const PEM_PRIVATE_KEYS: { re: RegExp; label: string }[] = [
  { re: /-----BEGIN RSA PRIVATE KEY-----/, label: 'RSA private key' },
  { re: /-----BEGIN DSA PRIVATE KEY-----/, label: 'DSA private key' },
  { re: /-----BEGIN EC PRIVATE KEY-----/, label: 'EC private key' },
  { re: /-----BEGIN OPENSSH PRIVATE KEY-----/, label: 'OpenSSH private key' },
  { re: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, label: 'PGP private key' },
  { re: /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/, label: 'PKCS#8 private key' },
];

/**
 * Pure: scan file CONTENTS for an embedded private key. Where `notableFiles` flags a key by *filename*, this
 * catches the case the re-run exposed — a device-wide TLS private key shipped inside a file whose name gives no
 * hint (Tenda-Camera's `O=Tenda` RSA key). A PEM private-key block is unambiguous, so this is HIGH /
 * `static_confirmed`; the key body is NEVER included in evidence, only its type and the path. Dedupes by path so
 * a multi-key bundle is one finding per file.
 */
export function scanContentSecrets(files: { path: string; content: string }[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const seen = new Set<string>();
  for (const { path: p, content } of files) {
    if (seen.has(p)) continue;
    const hit = PEM_PRIVATE_KEYS.find((k) => k.re.test(content));
    if (!hit) continue;
    seen.add(p);
    drafts.push({
      kind: 'embedded-private-key',
      title: `Embedded ${hit.label} in firmware: ${p}`,
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: { path: p, keyType: hit.label },
      rationale:
        'A PEM private-key block is literally present in this file — a device-wide/shared private key baked into ' +
        'the firmware (e.g. a TLS server key identical on every unit) enables impersonation/decryption. The key ' +
        'body is redacted; its presence is a static fact about the rootfs. Found by content, not filename.',
    });
  }
  return drafts;
}

// ============================================================================
// notable files (path-convention leads)
// ============================================================================

/**
 * Pure: flag sensitive files present in the rootfs by filename convention — private key material (`*_rsa`,
 * `id_rsa`, `*.key`, `*.pem` under /etc or /root), an `authorized_keys`, a `.htpasswd`, or a `*.pcap` capture.
 * INFO/LOW / `static_confirmed` — the file is literally on disk; each is a lead to confirm by reading the file
 * (an embedded private key may be a shared secret), never a verdict on its own.
 */
export function notableFiles(relPaths: string[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  for (const rel of relPaths) {
    const norm = rel.replace(/^\.?\/+/, '');
    const lower = norm.toLowerCase();
    const base = lower.split('/').pop() ?? lower;
    const underEtcOrRoot = lower.startsWith('etc/') || lower.startsWith('root/');

    let hit: { kind: string; label: string; severity: FindingSeverity } | null = null;
    if (base === 'authorized_keys') {
      hit = { kind: 'notable-authorized-keys', label: 'SSH authorized_keys (pre-authorized access)', severity: 'low' };
    } else if (base === '.htpasswd') {
      hit = { kind: 'notable-htpasswd', label: 'HTTP basic-auth credential store (.htpasswd)', severity: 'low' };
    } else if (base.endsWith('.pcap') || base.endsWith('.pcapng')) {
      hit = { kind: 'notable-pcap', label: 'Packet capture bundled in firmware', severity: 'info' };
    } else if (
      base === 'id_rsa' ||
      base.endsWith('_rsa') ||
      base.endsWith('_dsa') ||
      base.endsWith('_ecdsa') ||
      base.endsWith('_ed25519') ||
      base.endsWith('.key') ||
      (base.endsWith('.pem') && underEtcOrRoot)
    ) {
      hit = { kind: 'notable-private-key', label: 'Possible private key material', severity: 'low' };
    }
    if (!hit) continue;

    drafts.push({
      kind: hit.kind,
      title: `${hit.label}: ${norm}`,
      severity: hit.severity,
      proofState: 'static_confirmed',
      evidence: { path: norm },
      rationale:
        'Filename convention indicates sensitive material present in the extracted rootfs — a lead surfaced by ' +
        'path. Confirm by reading the file (an embedded private key here may be a shared/leaked secret).',
    });
  }
  return drafts;
}

// ============================================================================
// runner
// ============================================================================

export interface FsAuditResult {
  available: boolean;
  findings: FindingDraft[];
  filesScanned: number;
  reason: string;
}

const WALK_CAP = 5000;
const SERVICE_FILE_CAP = 200;
const SERVICE_READ_BYTES = 256 * 1024;
const SERVICE_DIRS = ['etc/init.d', 'etc/rc.d', 'etc/dropbear', 'etc/ssh'];
// Well-known standalone service configs the rc/ssh/ftp checks care about, outside the scanned dirs.
const STANDALONE_CONFIGS = [
  'etc/rc.local',
  'etc/rc',
  'etc/rcS',
  'etc/inetd.conf',
  'etc/xinetd.conf',
  'etc/vsftpd.conf',
  'etc/vsftpd/vsftpd.conf',
  'etc/proftpd.conf',
  'etc/proftpd/proftpd.conf',
  'etc/sshd_config',
  'etc/ssh/sshd_config',
  'etc/dropbear/dropbear.conf',
];

/** Confine a rootfs-relative path to the rootfs; returns the absolute path, or null on traversal. */
function safeJoin(root: string, rel: string): string | null {
  const abs = path.resolve(root, rel);
  if (abs !== root && !abs.startsWith(root + path.sep)) return null;
  return abs;
}

/** Best-effort UTF-8 read of a rootfs-relative file (missing/unreadable/escaping → ''). */
function readInside(root: string, rel: string): string {
  const abs = safeJoin(root, rel);
  if (!abs) return '';
  try {
    return fs.readFileSync(abs, 'utf8');
  } catch {
    return '';
  }
}

/** Read at most `cap` bytes of a file as UTF-8 (a mis-sized config can't blow up the scan). */
function readBounded(abs: string, cap: number): string {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, cap);
      const buf = Buffer.allocUnsafe(size);
      fs.readSync(fd, buf, 0, size, 0);
      return buf.toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return '';
  }
}

/** Collect a bounded set of service/rc config files (contents) from the known service directories + standalones. */
function collectServiceConfigs(root: string): { path: string; content: string }[] {
  const out: { path: string; content: string }[] = [];
  const seen = new Set<string>();
  const add = (rel: string): void => {
    if (out.length >= SERVICE_FILE_CAP || seen.has(rel)) return;
    const abs = safeJoin(root, rel);
    if (!abs) return;
    let stat: fs.Stats;
    try {
      stat = fs.statSync(abs);
    } catch {
      return;
    }
    if (!stat.isFile()) return;
    seen.add(rel);
    out.push({ path: rel, content: readBounded(abs, SERVICE_READ_BYTES) });
  };

  for (const dir of SERVICE_DIRS) {
    const abs = safeJoin(root, dir);
    if (!abs) continue;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (out.length >= SERVICE_FILE_CAP) break;
      if (e.isFile()) add(path.posix.join(dir, e.name));
    }
  }
  for (const rel of STANDALONE_CONFIGS) add(rel);
  return out;
}

// Extensions worth reading for an embedded private key (PEM is text; binary DER/p12 is out of scope here).
const CONTENT_SCAN_EXT = new Set([
  '.pem',
  '.key',
  '.crt',
  '.cer',
  '.conf',
  '.cfg',
  '.config',
  '.xml',
  '.json',
  '.ini',
  '.txt',
  '.sh',
  '.lua',
  '.js',
]);
const CONTENT_SCAN_FILE_CAP = 500;
const CONTENT_SCAN_BYTES = 512 * 1024;

/** Is this rootfs-relative path a candidate for a content secret scan (key-ish extension, or extensionless under etc/)? */
function isContentScanCandidate(rel: string): boolean {
  const lower = rel.toLowerCase();
  const base = lower.split('/').pop() ?? lower;
  const dot = base.lastIndexOf('.');
  const ext = dot > 0 ? base.slice(dot) : '';
  if (CONTENT_SCAN_EXT.has(ext)) return true;
  // Extensionless files under etc/ (many embedded keys/configs have no extension).
  return ext === '' && lower.startsWith('etc/');
}

/** Read a bounded set of candidate files' contents for the content secret scan. */
function collectContentScanFiles(root: string, relPaths: string[]): { path: string; content: string }[] {
  const out: { path: string; content: string }[] = [];
  for (const rel of relPaths) {
    if (out.length >= CONTENT_SCAN_FILE_CAP) break;
    if (!isContentScanCandidate(rel)) continue;
    const abs = safeJoin(root, rel);
    if (!abs) continue;
    out.push({ path: rel, content: readBounded(abs, CONTENT_SCAN_BYTES) });
  }
  return out;
}

/** Bounded, symlink-safe walk collecting rootfs-relative file paths (never follows a link out of the rootfs). */
function walkRootfs(root: string): { relPaths: string[]; entriesWalked: number } {
  const relPaths: string[] = [];
  let entriesWalked = 0;
  const stack: string[] = [root];
  while (stack.length > 0 && entriesWalked < WALK_CAP) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (entriesWalked >= WALK_CAP) break;
      entriesWalked++;
      if (e.isSymbolicLink()) continue; // never follow a symlink (could point outside the rootfs)
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) stack.push(abs);
      else if (e.isFile()) relPaths.push(path.relative(root, abs));
    }
  }
  return { relPaths, entriesWalked };
}

/**
 * Run the static rootfs security audit. Reads /etc/passwd, /etc/shadow, /etc/inittab and the service configs
 * (all best-effort — tolerate any missing), does a bounded rootfs walk for notable files, and applies the pure
 * detectors. Honest: a missing/unreadable rootfs → available:false with no findings (never fabricated).
 */
export function runFsAudit(rootfsPath: string): FsAuditResult {
  const root = path.resolve(rootfsPath);
  let isDir = false;
  try {
    isDir = fs.statSync(root).isDirectory();
  } catch {
    isDir = false;
  }
  if (!isDir) {
    return { available: false, findings: [], filesScanned: 0, reason: 'No extracted rootfs — run extraction first.' };
  }

  const passwd = readInside(root, 'etc/passwd');
  const shadow = readInside(root, 'etc/shadow');
  const inittab = readInside(root, 'etc/inittab');
  const serviceFiles = collectServiceConfigs(root);
  const { relPaths, entriesWalked } = walkRootfs(root);
  const contentScanFiles = collectContentScanFiles(root, relPaths);

  const findings: FindingDraft[] = [
    ...auditCredentials(passwd, shadow),
    ...auditInittab(inittab),
    ...auditServiceConfigs(serviceFiles),
    ...notableFiles(relPaths),
    ...scanContentSecrets(contentScanFiles),
  ];

  const reason = `Static rootfs audit: ${findings.length} finding(s) across ${entriesWalked} path(s) (${serviceFiles.length} service config(s) read). Credential/private-key facts are static_confirmed; service exposures (init shell, telnetd, anon ftp) need runtime reproduction.`;
  return { available: true, findings, filesScanned: entriesWalked, reason };
}
