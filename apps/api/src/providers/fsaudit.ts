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
 *
 * **The key lane, and what it had wrong.** `scanContentSecrets` was documented "found by content, not filename"
 * and was — but the runner only ever handed it files whose EXTENSION was on a whitelist (plus extensionless files
 * under `etc/`), read to 512 KB. So a private key inside a binary was unreachable by construction: the WR940N's
 * 1.9 MB `usr/bin/httpd` carries a complete RSA-1024 key and its matching certificate in plain PEM, and this
 * provider reported nothing. The scan is now the byte-level one in `certs.ts` (`scanTreeForPem`) over EVERY file
 * the walk finds, and the bound it applies is reported instead of being read as a negative.
 *
 * **What is claimed, and what is not.** A private-key label is not a private key: this codebase has already had
 * to withdraw a "private_key.pem" claim made without opening the file. So a block is claimed only when its BODY
 * decodes — `node:crypto` parses it and reports the algorithm and size — or when it is explicitly an encrypted
 * key block. Measured on the corpus, that distinction is not academic: of 11 well-formed private-key blocks in
 * one `libgnutls.so`, 7 do not decode at all, and a `DH PARAMETERS` / `ROOT PUBLIC KEY` block is not a secret in
 * the first place. Blocks that do not decode are counted and named in the reason — never silently dropped, never
 * claimed as key material.
 */
import { createPrivateKey } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { FindingSeverity, ProofState } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';
import {
  DEFAULT_PEM_BUDGET,
  type PemBlock,
  type PemScanCoverage,
  findPemBlocks,
  scanTreeForPem,
  summarizePemScan,
} from './certs.js';

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
// embedded key material (by CONTENT, not by filename — and read before it is named)
// ============================================================================

/** What a private-key-labelled block turned out to be once its body was actually decoded. */
export interface KeyBlockRead {
  /** `rsa` / `ec` / `dsa` / `ed25519` …, or null when nothing was decoded (encrypted, or not key material). */
  keyType: string | null;
  /** RSA/DSA modulus length or the EC curve size in bits, when the parser reports one. */
  keyBits: number | null;
  namedCurve: string | null;
  encrypted: boolean;
  /** True only when the bytes ARE key material: the body decoded, or the block is an explicitly encrypted key. */
  isKey: boolean;
  /** Why it was not claimed, when it was not. */
  note: string;
}

// EC named-curve → key size in bits, so an EC key can be described by strength like an RSA one.
const EC_CURVE_BITS: Record<string, number> = {
  prime192v1: 192,
  secp192r1: 192,
  secp224r1: 224,
  prime256v1: 256,
  secp256r1: 256,
  secp256k1: 256,
  secp384r1: 384,
  secp521r1: 521,
};

/**
 * Read a private-key block instead of trusting its label. `node:crypto` either decodes the body — in which case
 * the algorithm and size come from the key itself and the claim is beyond argument — or it does not, in which
 * case this returns `isKey:false` and the caller must not call it a key. An ENCRYPTED block is key material by
 * construction (the RFC 1421 headers are not something a placeholder carries), and is reported as such without
 * a passphrase being attempted. The parsed key object never leaves this function; only its shape does.
 */
export function readPrivateKeyBlock(block: PemBlock): KeyBlockRead {
  const base = { keyType: null, keyBits: null, namedCurve: null, encrypted: block.encrypted };
  if (block.encrypted) {
    return { ...base, isKey: true, note: 'encrypted key block — passphrase not attempted' };
  }
  // The same DER, re-framed: a key that travelled through an nvram value or a C string literal arrives with its
  // line breaks gone, and OpenSSL's PEM reader wants them. Re-wrapping changes no byte of the payload.
  const b64 = block.text
    .replace(/-----(?:BEGIN|END)[^-]*-----/g, '')
    .replace(/\s+/g, '')
    .replace(/(.{64})/g, '$1\n');
  const candidates = [block.text, `-----BEGIN ${block.label}-----\n${b64}\n-----END ${block.label}-----\n`];
  let lastError = 'no candidate parsed';
  for (const pem of candidates) {
    try {
      const key = createPrivateKey(pem);
      const details = key.asymmetricKeyDetails;
      const namedCurve = details?.namedCurve ?? null;
      const keyBits =
        typeof details?.modulusLength === 'number' ? details.modulusLength : (EC_CURVE_BITS[namedCurve ?? ''] ?? null);
      return { keyType: key.asymmetricKeyType ?? null, keyBits, namedCurve, encrypted: false, isKey: true, note: '' };
    } catch (err) {
      lastError = String((err as Error).message ?? err);
    }
  }
  return { ...base, isKey: false, note: `body did not decode as a key (${lastError})` };
}

/** A human description built from what was decoded, never from the label alone. */
function describeKey(read: KeyBlockRead, label: string): string {
  if (read.encrypted) {
    // Nothing was decoded here, so the description falls back to the block's own label — deduped, since a
    // PKCS#8 block is already labelled `ENCRYPTED PRIVATE KEY`.
    const human = label.toLowerCase();
    return human.startsWith('encrypted ') ? human : `encrypted ${human}`;
  }
  const alg = read.keyType?.toUpperCase() ?? '';
  const size = read.keyBits ? `${read.keyBits}-bit` : (read.namedCurve ?? '');
  return [alg, size, 'private key'].filter(Boolean).join(' ');
}

/** A PEM block that looks like key material but whose body did not decode — reported, never claimed. */
export interface UnclaimedKeyBlock {
  path: string;
  label: string;
  offset: number;
  note: string;
}

/**
 * Pure: turn the PEM blocks found in each file into key-material findings. Where `notableFiles` flags a key by
 * *filename*, this catches the case the re-run exposed — a device-wide TLS private key shipped inside a file whose
 * name gives no hint (Tenda-Camera's `O=Tenda` RSA key, the WR940N's key inside `usr/bin/httpd`).
 *
 * A file yields at most ONE finding (a multi-key bundle is one problem), HIGH / `static_confirmed` because a
 * decoded private key is a fact about the bytes. Severity drops to MEDIUM when every key in the file is encrypted,
 * since possession then also needs the passphrase — which this provider does not look for. The key body is NEVER
 * included in evidence: only its algorithm, size, offset and path. Blocks that are certificates, public keys or
 * parameters are not key material and are not claimed; blocks that are private-key-labelled but do not decode come
 * back in `unclaimed` so the caller can say they were seen and rejected.
 */
export function keyMaterialFindings(files: { path: string; blocks: PemBlock[] }[]): {
  findings: FindingDraft[];
  unclaimed: UnclaimedKeyBlock[];
} {
  const findings: FindingDraft[] = [];
  const unclaimed: UnclaimedKeyBlock[] = [];
  const seen = new Set<string>();
  for (const { path: p, blocks } of files) {
    if (seen.has(p)) continue;
    seen.add(p);
    const keys: { label: string; read: KeyBlockRead; offset: number }[] = [];
    for (const block of blocks) {
      if (block.kind !== 'private-key') continue;
      const read = readPrivateKeyBlock(block);
      if (read.isKey) keys.push({ label: block.label, read, offset: block.offset });
      else unclaimed.push({ path: p, label: block.label, offset: block.offset, note: read.note });
    }
    const first = keys[0];
    if (!first) continue;
    const described = describeKey(first.read, first.label);
    const allEncrypted = keys.every((k) => k.read.encrypted);
    // Two different claims, because two different things were established. Saying "its body decodes as …" about a
    // block nobody decrypted would be the same overstatement this lane exists to avoid.
    const rationale = allEncrypted
      ? [
          `A PEM ${described} block is literally present in this file: RFC 1421 encryption headers framing a`,
          'base64 body, which is key material by construction and not a shape a placeholder carries. The',
          'passphrase was NOT attempted, so this says the material is here — not that it can be used. A',
          'device-wide/shared key baked into firmware enables impersonation/decryption once its passphrase (often',
          'shipped in the same image) is known. The body is never stored here. Found by content, not filename.',
        ]
      : [
          `A PEM private-key block is literally present in this file and its body decodes as ${described} with`,
          'node:crypto — the label alone was not trusted. A device-wide/shared private key baked into the firmware',
          '(e.g. a TLS server key identical on every unit) enables impersonation/decryption. The key body is never',
          'stored here; its presence is a static fact about the rootfs. Found by content, not filename, and read',
          'before it was named.',
        ];
    findings.push({
      kind: 'embedded-private-key',
      title:
        keys.length === 1
          ? `Embedded ${described} in firmware: ${p}`
          : `Embedded private key material in firmware: ${p} (${keys.length} blocks, first: ${described})`,
      severity: allEncrypted ? 'medium' : 'high',
      proofState: 'static_confirmed',
      evidence: {
        path: p,
        keyCount: keys.length,
        // Shape only — algorithm, strength, where it sits. Never the key.
        keys: keys.slice(0, 8).map((k) => ({
          label: k.label,
          keyType: k.read.keyType,
          keyBits: k.read.keyBits,
          namedCurve: k.read.namedCurve,
          encrypted: k.read.encrypted,
          offset: k.offset,
        })),
      },
      rationale: rationale.join(' '),
    });
  }
  return { findings, unclaimed };
}

/** How many unclaimed blocks are named in the aggregate finding (the count itself stays exact). */
const UNCLAIMED_SAMPLE_CAP = 10;

/**
 * Pure: ONE aggregate INFO finding for the private-key-labelled blocks whose bodies did not decode. Each is a
 * fact about the bytes — a well-formed PEM block really is there — but not evidence of key material, so it is
 * neither claimed as a key nor dropped in silence. One finding rather than one per block on purpose: a single
 * `libgnutls.so` in this corpus contributes seven, and a per-block finding would bury the real key beside it.
 */
export function unclaimedKeyBlockFindings(unclaimed: UnclaimedKeyBlock[]): FindingDraft[] {
  if (unclaimed.length === 0) return [];
  const paths = [...new Set(unclaimed.map((u) => u.path))];
  return [
    {
      kind: 'pem-block-unclaimed',
      title: `${unclaimed.length} PEM private-key block(s) present whose body does not decode as a key`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: {
        count: unclaimed.length,
        files: paths.length,
        sample: unclaimed.slice(0, UNCLAIMED_SAMPLE_CAP).map((u) => ({
          path: u.path,
          label: u.label,
          offset: u.offset,
          note: u.note,
        })),
        sampleCap: UNCLAIMED_SAMPLE_CAP,
      },
      rationale:
        'These blocks carry a private-key label and a well-formed base64 body, but node:crypto could not decode ' +
        'them — a template/placeholder, a test vector compiled into a TLS library, or a truncated fragment. The ' +
        'block being present is a static fact; that it IS a key is not, so this audit reports them without ' +
        'claiming them. They are listed here precisely so a zero private-key count is not read as "nothing key-' +
        'shaped was in the bytes".',
    },
  ];
}

/**
 * Pure: the text-in, findings-out entry point — finds the PEM blocks in each file's content and applies
 * `keyMaterialFindings`. The runner uses the byte-level scanner instead (a binary must not be decoded as UTF-8),
 * but the decision is identical, which is what keeps this testable without touching a disk.
 */
export function scanContentSecrets(files: { path: string; content: string }[]): FindingDraft[] {
  return keyMaterialFindings(files.map((f) => ({ path: f.path, blocks: findPemBlocks(f.content) }))).findings;
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
  /**
   * What the key-material scan read and what it left unread. OPTIONAL FOREVER: a result persisted by an older
   * build does not carry it, and a required field would be a claim about data this code does not own.
   */
  scan?: PemScanCoverage;
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

// === The account database, and the four ways it can be silent ==============================================

/** How an account file actually presents on disk. `readInside` collapses all of these to `''`. */
export type AccountFileState =
  | { state: 'present'; bytes: number }
  | { state: 'absent' }
  | { state: 'empty' }
  | { state: 'symlink-escapes'; target: string }
  | { state: 'unreadable'; reason: string };

export interface AccountSource {
  /** Rootfs-relative path, e.g. `etc/passwd`. */
  path: string;
  state: AccountFileState;
}

/** The files whose silence would otherwise be read as "this image has no credential problems". */
const ACCOUNT_FILES = ['etc/passwd', 'etc/shadow', 'etc/group', 'etc/gshadow'];

/**
 * Pure: say what the credential audit is entitled to conclude, given how the account files present.
 *
 * `readInside` returns `''` for a file that is absent, empty, unreadable, or a symlink pointing outside the
 * rootfs — and `auditCredentials('', '')` then emits nothing, which renders as "no credential findings" and reads
 * as "no credential problems". Those are not the same claim, and DVRF is the worked example: it symlinks its
 * ENTIRE account database — `passwd`, `shadow`, `group`, `gshadow`, plus `hosts`, `resolv.conf` and `cron.d` — to
 * `/dev/null`. Every read returns empty, every check passes, and the image looks clean on the one axis this
 * provider exists to examine. (Its real credentials live in the Broadcom `router_defaults[]` string pool inside
 * `usr/lib/libshared.so`, which is a different provider's problem — the point here is that this one must not
 * imply it looked and found nothing.)
 *
 * Rule 3 of the proof-state discipline, applied to a provider that had it backwards: an empty result must say why.
 */
export function auditAccountSources(sources: AccountSource[]): FindingDraft[] {
  const neutered = sources.filter((s) => s.state.state === 'symlink-escapes');
  const missing = sources.filter((s) => s.state.state === 'absent');
  const empty = sources.filter((s) => s.state.state === 'empty');
  const unreadable = sources.filter((s) => s.state.state === 'unreadable');
  const readable = sources.filter((s) => s.state.state === 'present');

  const drafts: FindingDraft[] = [];

  if (neutered.length > 0) {
    const targets = [...new Set(neutered.map((s) => (s.state as { target: string }).target))];
    drafts.push({
      kind: 'account-db-redirected',
      title: `Account database is redirected out of the filesystem: ${neutered.map((s) => s.path).join(', ')} → ${targets.join(', ')}`,
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: {
        redirected: neutered.map((s) => ({ path: s.path, target: (s.state as { target: string }).target })),
        readableAccountFiles: readable.map((s) => s.path),
      },
      rationale: `These account files are symlinks whose target lies outside the extracted filesystem, so reading them yields nothing. The credential checks in this audit therefore examined NO accounts for those paths — that is a gap in what was asked, not a clean result, and an empty credential finding list for this image must not be read as "no weak accounts". Where the real credentials live (a vendor NVRAM store, a string pool inside a shared library, a cloud provisioning step) is a separate question this provider does not answer.`,
    });
  }

  // Absent and empty are reported together and only when NOTHING was readable: a rootfs with a real `etc/passwd`
  // and no `etc/gshadow` is ordinary, and flagging it would be noise. A rootfs where none of the four could be
  // read is a credential audit that examined nothing at all.
  if (readable.length === 0 && neutered.length === 0 && sources.length > 0) {
    const detail = [
      missing.length ? `${missing.length} absent (${missing.map((s) => s.path).join(', ')})` : '',
      empty.length ? `${empty.length} present but empty` : '',
      unreadable.length ? `${unreadable.length} unreadable` : '',
    ]
      .filter(Boolean)
      .join('; ');
    drafts.push({
      kind: 'account-db-unreadable',
      title: 'No account file in this rootfs could be read, so no account was examined',
      severity: 'info',
      proofState: 'blocked_by_platform',
      evidence: { sources: sources.map((s) => ({ path: s.path, state: s.state.state })), detail },
      rationale: `The credential checks read ${ACCOUNT_FILES.join(', ')}; on this image ${detail}. Zero credential findings here means the question could not be asked, never that the accounts are sound.`,
    });
  }
  return drafts;
}

/**
 * Read how one account file presents. Separated from the pure decision above because it needs `lstat`/`realpath`:
 * the interesting case is a symlink that RESOLVES outside the rootfs, which `safeJoin` cannot catch — it validates
 * the path it was handed, and `etc/passwd` is perfectly in-root right up until the kernel follows it to /dev/null.
 */
export function inspectAccountFile(root: string, rel: string): AccountFileState {
  const abs = safeJoin(root, rel);
  if (!abs) return { state: 'absent' };
  let st: fs.Stats;
  try {
    st = fs.lstatSync(abs);
  } catch {
    return { state: 'absent' };
  }
  if (st.isSymbolicLink()) {
    let target = '';
    try {
      target = fs.readlinkSync(abs);
    } catch {
      return { state: 'unreadable', reason: 'symlink could not be read' };
    }
    const resolved = path.resolve(path.dirname(abs), target);
    if (resolved !== root && !resolved.startsWith(root + path.sep)) return { state: 'symlink-escapes', target };
    // An in-root symlink is followed normally; fall through to the size check on its target.
  }
  try {
    const s = fs.statSync(abs);
    return s.size === 0 ? { state: 'empty' } : { state: 'present', bytes: s.size };
  } catch {
    return { state: 'unreadable', reason: 'target could not be stat-ed' };
  }
}

/** Inspect every account file this audit depends on, so its silence can be explained rather than assumed. */
export function collectAccountSources(root: string): AccountSource[] {
  return ACCOUNT_FILES.map((rel) => ({ path: rel, state: inspectAccountFile(root, rel) }));
}

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

/**
 * Bounded, symlink-safe walk collecting rootfs-relative file paths WITH their sizes (never follows a link out of
 * the rootfs). The size comes back because the key scan's budget is measured in bytes, and because a walk that
 * stopped at its own cap has to say so — `walkTruncated` is the difference between "no key in this rootfs" and
 * "no key in the part of this rootfs we got to".
 */
function walkRootfs(root: string): {
  relPaths: string[];
  files: { path: string; bytes: number }[];
  entriesWalked: number;
  walkTruncated: boolean;
} {
  const relPaths: string[] = [];
  const files: { path: string; bytes: number }[] = [];
  let entriesWalked = 0;
  let walkTruncated = false;
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
      if (entriesWalked >= WALK_CAP) {
        walkTruncated = true;
        break;
      }
      entriesWalked++;
      if (e.isSymbolicLink()) continue; // never follow a symlink (could point outside the rootfs)
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(abs);
        continue;
      }
      if (!e.isFile()) continue;
      const rel = path.relative(root, abs);
      relPaths.push(rel);
      try {
        files.push({ path: rel, bytes: fs.statSync(abs).size });
      } catch {
        // Unreadable entry: it is listed as a path but contributes no bytes to the key scan.
      }
    }
  }
  if (stack.length > 0) walkTruncated = true;
  return { relPaths, files, entriesWalked, walkTruncated };
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
  const { relPaths, files, entriesWalked, walkTruncated } = walkRootfs(root);

  // Every file the walk found, read as BYTES under a stated budget — no extension whitelist, binaries included.
  const { scanned, skipped, rule } = scanTreeForPem(root, files, DEFAULT_PEM_BUDGET);
  const scan = summarizePemScan(scanned, skipped, rule);
  const keyMaterial = keyMaterialFindings(scanned.map((e) => ({ path: e.path, blocks: e.blocks })));

  const findings: FindingDraft[] = [
    // First, whether the credential checks below could examine anything at all — an empty result from them is
    // only a negative when the files they read were actually readable.
    ...auditAccountSources(collectAccountSources(root)),
    ...auditCredentials(passwd, shadow),
    ...auditInittab(inittab),
    ...auditServiceConfigs(serviceFiles),
    ...notableFiles(relPaths),
    ...keyMaterial.findings,
    ...unclaimedKeyBlockFindings(keyMaterial.unclaimed),
  ];

  const bounds: string[] = [scan.note];
  if (walkTruncated) {
    bounds.push(
      [
        `The walk stopped at its ${WALK_CAP}-entry cap, so part of this rootfs was never offered to any check`,
        'here — the counts above describe what was reached, not what exists.',
      ].join(' '),
    );
  }
  const reason = [
    `Static rootfs audit: ${findings.length} finding(s) across ${entriesWalked} path(s)`,
    `(${serviceFiles.length} service config(s) read). Credential/private-key facts are static_confirmed;`,
    'service exposures (init shell, telnetd, anon ftp) need runtime reproduction.',
    ...bounds,
  ].join(' ');
  return { available: true, findings, filesScanned: entriesWalked, reason, scan };
}
