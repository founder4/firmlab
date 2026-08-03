/**
 * Embedded X.509 certificate provider — the honest read on the trust anchors a firmware ships. No external tool is
 * needed: Node's built-in `X509Certificate` parses each PEM block found in the rootfs files and in the raw image
 * bytes. Every finding is `static_confirmed` — a fact about the certificate bytes, never a device claim — and
 * certificates are public material, so surfacing their subject/issuer/validity leaks nothing (we never touch a
 * private key). `findPemBlocks`, `analyzeCert`, `planPemScan` and `summarizePemScan` are PURE and unit-tested; the
 * runner only walks the rootfs / reads bytes and composes them.
 *
 * **Why this file also owns the PEM scanner.** The first version only read rootfs files under 256 KB and only a
 * 8 MB prefix of the raw image, and reported `certCount: 0` / "No X.509 certificates found." when it found nothing
 * — a cap answering as if it were a measurement. The WR940N's `usr/bin/httpd` is 1.9 MB and carries a complete
 * RSA-1024 private key and the matching `CN=tplinkwifi.net` certificate in plain PEM; both were silently outside
 * the cap. So the scan is now byte-oriented (chunked search for the `-----BEGIN ` marker, no extension whitelist,
 * binaries included) and every bound it applies is reported: files scanned, files truncated, files skipped, bytes
 * left unread, and the rule that chose them. Rule 4 of the proof-state discipline — a bound is not an answer.
 *
 * **What separates a key from a format string.** A TLS library's string table is full of bare `-----BEGIN …`
 * markers: measured on that same rootfs, 19 markers exist and only 3 are real blocks — the other 16 live in
 * `libwolfssl`, `dropbearmulti` and `libwpa_common` and are printf templates with no body. A block is therefore
 * only recognised when a matching `-----END <same label>-----` closes a body that is base64 armor (plus optional
 * RFC 1421 headers) and nothing else. And the label is READ, never assumed: `DH PARAMETERS` and
 * `ROOT PUBLIC KEY` occur in this corpus beside real keys, and neither is a secret.
 *
 * Honest degradation: this layer always runs (built-in crypto), so it never blocks — an image with no certificates
 * returns certCount:0 with a reason that states what was and was not read, and it never fabricates a certificate
 * that isn't in the bytes.
 */
import { X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings-normalize.js';

/** A parsed embedded certificate — the factual, public identity of a trust anchor in the image. */
export interface CertInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  /** Public-key algorithm as reported by the key object (e.g. `rsa`, `ec`, `ed25519`). */
  keyType: string;
  /** Key strength in bits: RSA modulus length, or the EC curve size; null when it can't be determined. */
  keyBits: number | null;
  /** Subject === issuer and (best-effort) the signature verifies against the cert's own public key. */
  selfSigned: boolean;
}

export interface CertResult {
  available: boolean;
  /** Distinct certificates parsed (deduped by subject+validTo); always exact, even when `certs` is capped. */
  certCount: number;
  /** A capped sample of the parsed certificates. */
  certs: CertInfo[];
  findings: FindingDraft[];
  reason: string;
  /**
   * What the scan actually read, and what it did not. OPTIONAL FOREVER: a result persisted by an older build has
   * no `scan`, and a required field here would be a claim about data this code does not own.
   */
  scan?: PemScanCoverage;
}

// ============================================================================
// PEM blocks — structure first, claims later
// ============================================================================

/** What a PEM block actually is, read from its own BEGIN/END label rather than guessed from the filename. */
export type PemKind = 'certificate' | 'private-key' | 'public-key' | 'other';

export interface PemBlock {
  /** The label between the dashes, verbatim: `CERTIFICATE`, `RSA PRIVATE KEY`, `DH PARAMETERS`, … */
  label: string;
  kind: PemKind;
  /** The armored block, verbatim (BEGIN…END). A caller must never persist this for a private key. */
  text: string;
  /** Byte offset of the BEGIN marker in the file it was found in (exact for the latin1/byte scanner below). */
  offset: number;
  /** RFC 1421 `Proc-Type: 4,ENCRYPTED` header, or an `ENCRYPTED PRIVATE KEY` label. */
  encrypted: boolean;
}

const BEGIN_MARKER = '-----BEGIN ';
const BEGIN_MARKER_BUF = Buffer.from(BEGIN_MARKER, 'latin1');
// Labels are short and upper-case; `-` is excluded so the greedy class stops at the closing dashes.
const LABEL_RE = /^([A-Z][A-Z0-9 #.]{0,63})-----/;
// RFC 1421 headers (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: …`) sit between the BEGIN line and the base64 body.
const PEM_HEADERS_RE = /^[ \t]*\r?\n(?:[A-Za-z][A-Za-z0-9-]*:[^\r\n]{0,200}\r?\n)+/;
// Base64 armor + whitespace and NOTHING else: this is what tells a real block from a printf template in a .so.
const PEM_BODY_RE = /^[\sA-Za-z0-9+/=]+$/;
const PEM_MIN_BODY_CHARS = 24; // shorter than the smallest conceivable DER payload — cannot be key material
const PEM_MAX_BODY_CHARS = 64 * 1024; // an armored body larger than this is not a key/cert we can parse anyway

/**
 * Pure: classify a PEM label. Deliberately literal — `DH PARAMETERS`, `CERTIFICATE REQUEST` and `RSA TESTING KEY`
 * (Go's testdata convention) are `other`, because none of them is a certificate and none is a private key we are
 * entitled to claim as one. `PGP PRIVATE KEY BLOCK` is, hence the optional ` BLOCK` suffix.
 */
export function classifyPemLabel(label: string): PemKind {
  if (/(?:^|\s)PRIVATE KEY(?: BLOCK)?$/.test(label)) return 'private-key';
  if (/(?:^|\s)PUBLIC KEY(?: BLOCK)?$/.test(label)) return 'public-key';
  if (label === 'CERTIFICATE' || label === 'TRUSTED CERTIFICATE' || label === 'X509 CERTIFICATE') return 'certificate';
  return 'other';
}

/**
 * Pure: parse the PEM block that starts at `index`, or null when what starts there is not one. A block needs a
 * label, a matching `-----END <label>-----`, and a body that is base64 armor (after any RFC 1421 headers) — the
 * three conditions that a bare marker in a binary's string table cannot satisfy. `offset` is what the block will
 * report as its position; it defaults to `index` and is overridden when the text is a window read from a file.
 */
export function parsePemBlockAt(text: string, index: number, offset = index): PemBlock | null {
  if (!text.startsWith(BEGIN_MARKER, index)) return null;
  const afterBegin = index + BEGIN_MARKER.length;
  const label = LABEL_RE.exec(text.slice(afterBegin, afterBegin + 72))?.[1];
  if (!label) return null;
  const afterLabel = afterBegin + label.length + 5; // the label's own closing `-----`
  const headers = PEM_HEADERS_RE.exec(text.slice(afterLabel, afterLabel + 1024));
  const bodyStart = afterLabel + (headers?.[0].length ?? 0);
  const endMarker = `-----END ${label}-----`;
  const endIndex = text.indexOf(endMarker, bodyStart);
  if (endIndex < 0 || endIndex - bodyStart > PEM_MAX_BODY_CHARS) return null;
  const body = text.slice(bodyStart, endIndex);
  if (!PEM_BODY_RE.test(body)) return null;
  if (body.replace(/\s+/g, '').length < PEM_MIN_BODY_CHARS) return null;
  return {
    label,
    kind: classifyPemLabel(label),
    text: text.slice(index, endIndex + endMarker.length),
    offset,
    encrypted: /Proc-Type:\s*4,\s*ENCRYPTED/i.test(headers?.[0] ?? '') || label.startsWith('ENCRYPTED '),
  };
}

/**
 * Pure: every complete PEM block in a text blob, in order. Offsets are byte-exact when `text` came from a latin1
 * (byte-per-char) read — which is what `scanFileForPem` does; a UTF-8 decode would make them character offsets.
 */
export function findPemBlocks(text: string, baseOffset = 0): PemBlock[] {
  const out: PemBlock[] = [];
  let i = text.indexOf(BEGIN_MARKER);
  while (i >= 0) {
    const block = parsePemBlockAt(text, i, baseOffset + i);
    if (block) {
      out.push(block);
      i = text.indexOf(BEGIN_MARKER, i + block.text.length);
    } else {
      i = text.indexOf(BEGIN_MARKER, i + 1);
    }
  }
  return out;
}

/** Pure: the certificate blocks of a text blob, as raw PEM. Kept as the narrow entry point the cert path uses. */
export function extractPems(text: string): string[] {
  return findPemBlocks(text)
    .filter((b) => b.kind === 'certificate')
    .map((b) => b.text);
}

// ============================================================================
// The bounded scan — and the report of what it cost
// ============================================================================

/** One file the scan actually read, with what it read and what it found. */
export interface PemScanEntry {
  path: string;
  /** Size on disk. */
  bytes: number;
  /** Bytes actually read (≤ bytes when the per-file cap truncated it). */
  read: number;
  /** `-----BEGIN ` markers seen — including the ones that turned out to be bare format strings. */
  markers: number;
  /** Markers past the per-file marker cap that were never examined. */
  markersDropped: number;
  blocks: PemBlock[];
}

/** A file the plan decided not to read at all, and under which rule. */
export interface PemScanSkip {
  path: string;
  bytes: number;
  why: 'total-byte-budget' | 'file-count-cap';
}

/** What the scan read and what it left — so an empty result can never pass for a clean one. */
export interface PemScanCoverage {
  filesConsidered: number;
  filesScanned: number;
  filesTruncated: number;
  filesSkipped: number;
  bytesConsidered: number;
  bytesScanned: number;
  /** Bytes present in the considered files that were never read (truncated tails + skipped files). */
  bytesUnread: number;
  markersSeen: number;
  markersDropped: number;
  blocks: { certificate: number; privateKey: number; publicKey: number; other: number };
  /** Capped samples — the dropped set is stated, not merely counted. */
  skippedSample: PemScanSkip[];
  truncatedSample: { path: string; bytes: number; read: number }[];
  /** The selection rule, in words. */
  rule: string;
  /** The sentence a caller can print verbatim: what this scan does and does not cover. */
  note: string;
}

export interface PemScanBudget {
  /** Bytes read from any one file before its tail is left unread. */
  maxFileBytes: number;
  /** Bytes read across the whole scan. */
  totalBytes: number;
  /** Files read at all. */
  maxFiles: number;
}

/**
 * The bounds, chosen from measurement rather than taste (2026-08-03, in-container, against the real corpus):
 *   - the WR940N rootfs is 496 files / 11.8 MB and is read END TO END, every byte, in 78 ms — the common case
 *     pays nothing, and `runCertAnalysis` over that rootfs plus its 4 MB image takes 24 ms;
 *   - the largest tree in the corpus (the BE3600 extract, 6499 files, 1.50 GB logical) reads 450 MB in 261 ms at
 *     these settings, because five files hold most of it (one is a 1.0 GB sparse blob);
 *   - across all 18 extractions, no file was ever dropped by the total budget: only the handful above 32 MB were
 *     truncated, and each says so.
 * Under a smaller per-file cap those five files would silently hide 1.1 GB; under none, one sparse blob would set
 * the cost of every scan. 32 MB / 768 MB is where the whole corpus is covered and the pathological tree still
 * finishes in well under a second.
 */
export const DEFAULT_PEM_BUDGET: PemScanBudget = {
  maxFileBytes: 32 * 1024 * 1024,
  totalBytes: 768 * 1024 * 1024,
  maxFiles: 20000,
};

/** Markers examined per file. A cert bundle in this corpus holds ~145; anything past this is reported, not silent. */
const PEM_MAX_MARKERS_PER_FILE = 1024;
/** Bytes read from a marker to parse the block it opens (a 64 KB armored body plus its markers and headers). */
const PEM_BLOCK_WINDOW = 72 * 1024;
/** How many dropped paths are named in the result (the counts stay exact). */
const SAMPLE_CAP = 10;

/**
 * Pure: decide which files the byte budget buys, and say what it drops.
 *
 * Smallest-file-first, ties broken by path — NOT directory order, which would make the scanned set an artifact of
 * how the extractor happened to lay the tree out. Smallest-first is the right rule for this question: PEM material
 * in this corpus is overwhelmingly small (a `.crt` is 1–2 KB), the one large carrier measured is a 1.9 MB binary
 * far below the per-file cap, and spending the budget on the small files buys the most files per byte. A file over
 * the per-file cap is still read — up to the cap — rather than skipped, and its unread tail is counted.
 */
export function planPemScan(
  files: { path: string; bytes: number }[],
  budget: PemScanBudget = DEFAULT_PEM_BUDGET,
): { scan: { path: string; bytes: number; read: number }[]; skipped: PemScanSkip[]; rule: string } {
  const ordered = [...files].sort((a, b) => a.bytes - b.bytes || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const scan: { path: string; bytes: number; read: number }[] = [];
  const skipped: PemScanSkip[] = [];
  let spent = 0;
  for (const f of ordered) {
    const read = Math.min(f.bytes, budget.maxFileBytes);
    if (scan.length >= budget.maxFiles) {
      skipped.push({ path: f.path, bytes: f.bytes, why: 'file-count-cap' });
      continue;
    }
    if (spent + read > budget.totalBytes) {
      skipped.push({ path: f.path, bytes: f.bytes, why: 'total-byte-budget' });
      continue;
    }
    spent += read;
    scan.push({ path: f.path, bytes: f.bytes, read });
  }
  const rule =
    `smallest file first (ties by path), reading at most ${formatBytes(budget.maxFileBytes)} per file, ` +
    `${formatBytes(budget.totalBytes)} and ${budget.maxFiles} files in total`;
  return { scan, skipped, rule };
}

/** Human byte size for the reported sentences (exact counts live in the numeric fields). */
function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/**
 * Pure: turn what was read into the coverage report, including the sentence that states what the scan does not
 * cover. The counts are exact; only the named samples are capped, and the cap on them is stated too.
 */
export function summarizePemScan(scanned: PemScanEntry[], skipped: PemScanSkip[], rule: string): PemScanCoverage {
  // Ordered by how much each left unread: the sample names what was dropped MOST, not what came first.
  const truncated = scanned.filter((e) => e.read < e.bytes).sort((a, b) => b.bytes - b.read - (a.bytes - a.read));
  const skippedByLoss = [...skipped].sort((a, b) => b.bytes - a.bytes);
  const bytesScanned = scanned.reduce((a, e) => a + e.read, 0);
  const bytesConsidered = scanned.reduce((a, e) => a + e.bytes, 0) + skipped.reduce((a, s) => a + s.bytes, 0);
  const markersSeen = scanned.reduce((a, e) => a + e.markers, 0);
  const markersDropped = scanned.reduce((a, e) => a + e.markersDropped, 0);
  const blocks = { certificate: 0, privateKey: 0, publicKey: 0, other: 0 };
  for (const e of scanned) {
    for (const b of e.blocks) {
      if (b.kind === 'certificate') blocks.certificate++;
      else if (b.kind === 'private-key') blocks.privateKey++;
      else if (b.kind === 'public-key') blocks.publicKey++;
      else blocks.other++;
    }
  }
  const bytesUnread = bytesConsidered - bytesScanned;

  const parts: string[] = [];
  if (skipped.length === 0 && truncated.length === 0) {
    parts.push(
      `Read every byte of all ${scanned.length} file(s) (${formatBytes(bytesScanned)}) looking for PEM material.`,
    );
  } else {
    parts.push(
      [
        `Read ${formatBytes(bytesScanned)} of ${formatBytes(bytesConsidered)} across ${scanned.length} of`,
        `${scanned.length + skipped.length} file(s): ${truncated.length} truncated at the per-file cap and`,
        `${skipped.length} not read at all (${rule}). ${formatBytes(bytesUnread)} went unread, so a PEM block`,
        'inside those bytes would not have been seen — this is the scan stating its bound, not a clean result.',
      ].join(' '),
    );
    const names = [
      ...truncated.map((t) => ({ path: t.path, unread: t.bytes - t.read })),
      ...skippedByLoss.map((s) => ({ path: s.path, unread: s.bytes })),
    ]
      .sort((a, b) => b.unread - a.unread)
      .slice(0, SAMPLE_CAP)
      .map((f) => `${f.path} (${formatBytes(f.unread)})`);
    if (names.length > 0) parts.push(`Largest unread: ${names.join(', ')}.`);
  }
  if (markersDropped > 0) {
    parts.push(
      [
        `${markersDropped} '-----BEGIN ' marker(s) past the ${PEM_MAX_MARKERS_PER_FILE}-per-file cap were not`,
        'examined and are neither counted as blocks nor claimed to be absent.',
      ].join(' '),
    );
  }
  const bare = markersSeen - scanned.reduce((a, e) => a + e.blocks.length, 0);
  if (bare > 0) {
    parts.push(
      [
        `${bare} of ${markersSeen} marker(s) open no complete block (no matching END, or a body that is not`,
        'base64 armor) — those are format strings in a binary, not key material, and are deliberately not claimed.',
      ].join(' '),
    );
  }

  return {
    filesConsidered: scanned.length + skipped.length,
    filesScanned: scanned.length,
    filesTruncated: truncated.length,
    filesSkipped: skipped.length,
    bytesConsidered,
    bytesScanned,
    bytesUnread,
    markersSeen,
    markersDropped,
    blocks,
    skippedSample: skippedByLoss.slice(0, SAMPLE_CAP),
    truncatedSample: truncated.slice(0, SAMPLE_CAP).map((t) => ({ path: t.path, bytes: t.bytes, read: t.read })),
    rule,
    note: parts.join(' '),
  };
}

/**
 * Scan one file for PEM blocks by BYTES, not by extension: a chunked `-----BEGIN ` search over at most `maxBytes`,
 * then a bounded window read at each marker to parse the block it opens. Nothing is decoded as UTF-8 (a binary
 * would lose bytes to replacement characters) and the whole file is never held in memory. A block that STARTS
 * inside the budget is completed even if its END lies past the cap — half a key is not a useful thing to report.
 */
export function scanFileForPem(abs: string, relPath: string, maxBytes: number): PemScanEntry {
  const entry: PemScanEntry = { path: relPath, bytes: 0, read: 0, markers: 0, markersDropped: 0, blocks: [] };
  let fd: number;
  try {
    fd = fs.openSync(abs, 'r');
  } catch {
    return entry;
  }
  try {
    const size = fs.fstatSync(fd).size;
    entry.bytes = size;
    const limit = Math.min(size, maxBytes);
    if (limit === 0) return entry;

    const chunk = Math.min(limit, 1024 * 1024);
    const overlap = BEGIN_MARKER_BUF.length - 1;
    const buf = Buffer.allocUnsafe(chunk + overlap);
    const markers: number[] = [];
    let filePos = 0;
    let carry = 0;
    while (filePos < limit) {
      const want = Math.min(chunk, limit - filePos);
      const n = fs.readSync(fd, buf, carry, want, filePos);
      if (n <= 0) break;
      entry.read += n;
      const end = carry + n;
      const view = buf.subarray(0, end);
      const base = filePos - carry;
      let from = 0;
      for (;;) {
        const i = view.indexOf(BEGIN_MARKER_BUF, from);
        if (i < 0) break;
        if (markers.length < PEM_MAX_MARKERS_PER_FILE) markers.push(base + i);
        else entry.markersDropped++;
        from = i + 1;
      }
      filePos += n;
      const keep = Math.min(overlap, end);
      buf.copy(buf, 0, end - keep, end);
      carry = keep;
    }
    entry.markers = markers.length + entry.markersDropped;

    for (const off of markers) {
      const len = Math.min(PEM_BLOCK_WINDOW, size - off);
      if (len <= BEGIN_MARKER_BUF.length) continue;
      const win = Buffer.allocUnsafe(len);
      const got = fs.readSync(fd, win, 0, len, off);
      if (got <= 0) continue;
      const block = parsePemBlockAt(win.subarray(0, got).toString('latin1'), 0, off);
      if (block) entry.blocks.push(block);
    }
    return entry;
  } catch {
    return entry;
  } finally {
    fs.closeSync(fd);
  }
}

/** A bounded, symlink-safe walk collecting every regular file with its size (the plan decides what is read). */
export function collectScanCandidates(
  root: string,
  maxDepth = 12,
  maxEntries = 50000,
): { files: { path: string; bytes: number }[]; walkTruncated: boolean } {
  const files: { path: string; bytes: number }[] = [];
  let entriesSeen = 0;
  let walkTruncated = false;
  const walk = (dir: string, depth: number): void => {
    if (entriesSeen >= maxEntries) {
      walkTruncated = true;
      return;
    }
    if (depth > maxDepth) {
      walkTruncated = true;
      return;
    }
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (entriesSeen >= maxEntries) {
        walkTruncated = true;
        return;
      }
      entriesSeen++;
      if (e.isSymbolicLink()) continue; // never follow a link out of the rootfs
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        walk(full, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      try {
        files.push({ path: path.relative(root, full), bytes: fs.statSync(full).size });
      } catch {
        // Unreadable entry: it contributes nothing and is not counted as scanned.
      }
    }
  };
  walk(root, 0);
  return { files, walkTruncated };
}

/**
 * Scan a whole tree for PEM blocks under the budget. Returns one entry per file actually read plus the files the
 * plan dropped, so the caller can report both. Used by the certificate lane here and by the private-key lane in
 * `fsaudit.ts` — the two questions differ, the bytes and the bound do not.
 */
export function scanTreeForPem(
  root: string,
  files: { path: string; bytes: number }[],
  budget: PemScanBudget = DEFAULT_PEM_BUDGET,
): { scanned: PemScanEntry[]; skipped: PemScanSkip[]; rule: string } {
  const { scan, skipped, rule } = planPemScan(files, budget);
  const scanned = scan.map((f) => scanFileForPem(path.join(root, f.path), f.path, f.read));
  return { scanned, skipped, rule };
}

// ============================================================================
// Certificate analysis
// ============================================================================

// A test / self-signed marker in the certificate's CN — none of these belong in a shipping trust store.
const TEST_CN_RE = /DO NOT TRUST|Test|localhost|example\.com|snakeoil/i;

// EC named-curve → key size in bits (OpenSSL/Node curve names), for the strength read on EC keys.
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

/** Extract the CN value from a subject/issuer string (Node emits one RDN per line for multi-RDN names). */
function commonName(subject: string): string {
  const m = /CN=([^\n]+)/.exec(subject);
  return m?.[1]?.trim() ?? subject;
}

/**
 * Pure: parse one PEM certificate with Node's built-in X509 parser and derive the honest findings from it. Returns
 * null when the block does not parse as a certificate. Findings are all `static_confirmed` (facts about the bytes)
 * and never carry private material — a certificate is public by construction.
 */
export function analyzeCert(pem: string, now: number): { info: CertInfo; findings: FindingDraft[] } | null {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pem);
  } catch {
    return null;
  }

  const subject = cert.subject;
  const issuer = cert.issuer;
  const keyType = cert.publicKey.asymmetricKeyType ?? 'unknown';
  const details = cert.publicKey.asymmetricKeyDetails;
  let keyBits: number | null = null;
  if (typeof details?.modulusLength === 'number') keyBits = details.modulusLength;
  else if (details?.namedCurve) keyBits = EC_CURVE_BITS[details.namedCurve] ?? null;

  // Self-signed: subject === issuer, corroborated (best-effort) by verifying the signature with the cert's own key.
  let selfSigned = subject === issuer;
  if (selfSigned) {
    try {
      selfSigned = cert.verify(cert.publicKey);
    } catch {
      // Unsupported key/signature algorithm — keep the subject===issuer determination rather than overclaiming.
    }
  }

  const info: CertInfo = {
    subject,
    issuer,
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    keyType,
    keyBits,
    selfSigned,
  };

  const findings: FindingDraft[] = [];
  const cn = commonName(subject);
  // Subject/issuer/validity are the only evidence — public certificate metadata, never a key.
  const base: Record<string, unknown> = { subject, issuer, validTo: cert.validTo };
  const validToMs = Date.parse(cert.validTo);
  const validFromMs = Date.parse(cert.validFrom);

  if (!Number.isNaN(validToMs) && validToMs < now) {
    findings.push({
      kind: 'cert-expired',
      title: `Expired certificate: ${cn}`,
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { ...base },
      rationale:
        'The certificate shipped in the firmware is past its notAfter date. Clients that validate expiry will ' +
        'reject it; clients that ignore expiry are trusting stale material. A fact about the image bytes.',
    });
  }

  if (!Number.isNaN(validFromMs) && validFromMs > now) {
    findings.push({
      kind: 'cert-not-yet-valid',
      title: `Certificate not yet valid: ${cn}`,
      severity: 'low',
      proofState: 'static_confirmed',
      evidence: { ...base, validFrom: cert.validFrom },
      rationale:
        'The certificate’s notBefore date is in the future — a clock/provisioning issue, present in the bytes.',
    });
  }

  if (keyType === 'rsa' && keyBits !== null && keyBits < 2048) {
    findings.push({
      kind: 'cert-weak-rsa',
      title: `Weak RSA key (${keyBits}-bit) in certificate: ${cn}`,
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: { ...base, keyType, keyBits },
      rationale: `An RSA key below 2048 bits (${keyBits}-bit) is factorable at feasible cost — the trust anchor is weak.`,
    });
  }

  if (TEST_CN_RE.test(cn)) {
    findings.push({
      kind: 'cert-test',
      title: `Test/self-signed certificate shipped: ${cn}`,
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: { ...base, cn },
      rationale:
        'The certificate CN carries a documented test / placeholder marker (DO NOT TRUST / Test / localhost / ' +
        'example.com / snakeoil). A test certificate in shipping firmware means clients trust publicly-known key ' +
        'material — a supply-chain weakness present in the image bytes.',
    });
  }

  if (selfSigned && cert.ca) {
    findings.push({
      kind: 'cert-self-signed-ca',
      title: `Self-signed CA certificate embedded: ${cn}`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { ...base, keyType, keyBits },
      rationale:
        'A self-signed certificate with CA:TRUE is a root of trust baked into the firmware. Legitimate (a vendor ' +
        'root), but worth reviewing where it is trusted — a lead, backed by the bytes, not a verdict.',
    });
  }

  return { info, findings };
}

// ============================================================================
// runner
// ============================================================================

const CERT_SAMPLE_CAP = 40; // capped sample of parsed certs (certCount stays exact)

/**
 * Scan a rootfs (if extracted) and the raw image for embedded X.509 certificates, parse each with Node's built-in
 * crypto, dedupe by (subject+validTo), and compose the honest findings. Always `available` (no external tool).
 *
 * Zero certificates is never reported bare: the reason carries what was read, what was left unread and — when the
 * rootfs has not been extracted — the fact that only the packed image bytes were available, where a certificate
 * inside a compressed filesystem is invisible by construction.
 */
export function runCertAnalysis(
  rootfsPath: string | null,
  imagePath: string,
  now?: number,
  budget: PemScanBudget = DEFAULT_PEM_BUDGET,
): CertResult {
  const ts = now ?? Date.now();

  const scanned: PemScanEntry[] = [];
  const skipped: PemScanSkip[] = [];
  let rule = '';
  let walkTruncated = false;
  if (rootfsPath) {
    const { files, walkTruncated: wt } = collectScanCandidates(rootfsPath);
    walkTruncated = wt;
    const tree = scanTreeForPem(rootfsPath, files, budget);
    scanned.push(...tree.scanned);
    skipped.push(...tree.skipped);
    rule = tree.rule;
  }
  // The raw image is always read (up to the per-file cap), outside the tree's budget — a PEM stored beyond any
  // parsed filesystem still counts, and dropping the image itself would be the one bound nobody expects.
  scanned.push(scanFileForPem(imagePath, `<raw image> ${path.basename(imagePath)}`, budget.maxFileBytes));
  // With no rootfs there was no plan to state a rule; the empty plan still names the bounds that applied.
  if (!rule) rule = planPemScan([], budget).rule;

  const scan = summarizePemScan(scanned, skipped, rule);

  const certs: CertInfo[] = [];
  const findings: FindingDraft[] = [];
  const seen = new Set<string>();
  let unparsedCertBlocks = 0;
  for (const entry of scanned) {
    for (const block of entry.blocks) {
      if (block.kind !== 'certificate') continue;
      const res = analyzeCert(block.text, ts);
      if (!res) {
        unparsedCertBlocks++;
        continue;
      }
      const key = `${res.info.subject}\n${res.info.validTo}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (certs.length < CERT_SAMPLE_CAP) certs.push(res.info);
      findings.push(...res.findings);
    }
  }

  const context: string[] = [];
  if (!rootfsPath) {
    context.push(
      'No extracted rootfs was available, so only the raw image bytes were read — a certificate inside a ' +
        'compressed/packed filesystem is invisible until extraction runs.',
    );
  }
  if (walkTruncated) {
    context.push('The rootfs walk hit its depth/entry cap, so part of the tree was never offered to the scan.');
  }
  if (unparsedCertBlocks > 0) {
    context.push(
      `${unparsedCertBlocks} CERTIFICATE block(s) did not parse as X.509 and are counted here rather than claimed.`,
    );
  }
  if (scan.blocks.privateKey > 0 || scan.blocks.publicKey > 0 || scan.blocks.other > 0) {
    context.push(
      [
        `Non-certificate PEM material is present in the same bytes (${scan.blocks.privateKey} private-key,`,
        `${scan.blocks.publicKey} public-key, ${scan.blocks.other} other block(s)); this lane does not claim it —`,
        'the private-key lane in fsaudit does.',
      ].join(' '),
    );
  }

  if (seen.size === 0) {
    return {
      available: true,
      certCount: 0,
      certs: [],
      findings: [],
      reason: ['No X.509 certificates found in what was scanned.', scan.note, ...context].join(' '),
      scan,
    };
  }
  return {
    available: true,
    certCount: seen.size,
    certs,
    findings,
    reason: [
      `Parsed ${seen.size} embedded X.509 certificate${seen.size === 1 ? '' : 's'} from the image bytes with`,
      "Node's built-in crypto — static analysis of the certificate material, not device behavior.",
      scan.note,
      ...context,
    ].join(' '),
    scan,
  };
}
