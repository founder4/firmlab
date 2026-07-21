/**
 * Embedded X.509 certificate provider — the honest read on the trust anchors a firmware ships. No external tool is
 * needed: Node's built-in `X509Certificate` parses each PEM block found in the rootfs files and in the raw image
 * bytes. Every finding is `static_confirmed` — a fact about the certificate bytes, never a device claim — and
 * certificates are public material, so surfacing their subject/issuer/validity leaks nothing (we never touch a
 * private key). `extractPems`, `analyzeCert` and the finding logic are PURE and unit-tested; the runner only walks
 * the rootfs / reads a bounded image prefix and composes them.
 *
 * Honest degradation: this layer always runs (built-in crypto), so it never blocks — an image with no certificates
 * simply returns certCount:0 with an explicit reason, and it never fabricates a certificate that isn't in the bytes.
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
}

// A CERTIFICATE PEM block: the armored base64 between the BEGIN/END markers (non-greedy so adjacent blocks split).
const PEM_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const PEM_MARKER = '-----BEGIN CERTIFICATE-----';

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

/** Pure: return every `-----BEGIN CERTIFICATE-----…-----END CERTIFICATE-----` block found in a text blob. */
export function extractPems(text: string): string[] {
  return text.match(PEM_RE) ?? [];
}

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

// Bounds for the runner: keep the walk and the raw scan from blowing up on a huge / adversarial image.
const ROOTFS_FILE_CAP = 256 * 1024; // only scan text files under 256KB
const RAW_IMAGE_PREFIX = 8 * 1024 * 1024; // bounded prefix of the raw image scanned as latin1
const CERT_SAMPLE_CAP = 40; // capped sample of parsed certs (certCount stays exact)
const WALK_MAX_DEPTH = 12;
const WALK_MAX_FILES = 20000;

function safeReadLatin1(p: string): string {
  try {
    return fs.readFileSync(p, 'latin1');
  } catch {
    return '';
  }
}

/** Bounded walk of the rootfs collecting the text of every small file that contains a PEM certificate marker. */
function collectRootfsPemBlobs(root: string): string[] {
  const out: string[] = [];
  let filesRead = 0;
  const walk = (dir: string, depth: number): void => {
    if (depth > WALK_MAX_DEPTH || filesRead >= WALK_MAX_FILES) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (filesRead >= WALK_MAX_FILES) return;
      if (e.isSymbolicLink()) continue; // never follow symlinks out of the rootfs
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        walk(full, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      let size: number;
      try {
        size = fs.statSync(full).size;
      } catch {
        continue;
      }
      if (size >= ROOTFS_FILE_CAP) continue;
      filesRead++;
      const text = safeReadLatin1(full);
      if (text.includes(PEM_MARKER)) out.push(text);
    }
  };
  walk(root, 0);
  return out;
}

/** Read a bounded latin1 prefix of the raw image so a PEM stored outside any parsed filesystem is still found. */
function readRawPrefix(imagePath: string): string {
  try {
    const fd = fs.openSync(imagePath, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, RAW_IMAGE_PREFIX);
      const buf = Buffer.allocUnsafe(size);
      fs.readSync(fd, buf, 0, size, 0);
      return buf.toString('latin1');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return '';
  }
}

/**
 * Scan a rootfs (if extracted) and a bounded prefix of the raw image for embedded X.509 certificates, parse each
 * with Node's built-in crypto, dedupe by (subject+validTo), and compose the honest findings. Always `available`
 * (no external tool); no certificates found is an explicit, non-fabricated result — never a blocked/absent tool.
 */
export function runCertAnalysis(rootfsPath: string | null, imagePath: string, now?: number): CertResult {
  const ts = now ?? Date.now();
  const blobs: string[] = [];
  if (rootfsPath) blobs.push(...collectRootfsPemBlobs(rootfsPath));
  blobs.push(readRawPrefix(imagePath));

  const pems = blobs.flatMap(extractPems);

  const certs: CertInfo[] = [];
  const findings: FindingDraft[] = [];
  const seen = new Set<string>();
  for (const pem of pems) {
    const res = analyzeCert(pem, ts);
    if (!res) continue;
    const key = `${res.info.subject}\n${res.info.validTo}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (certs.length < CERT_SAMPLE_CAP) certs.push(res.info);
    findings.push(...res.findings);
  }

  if (seen.size === 0) {
    return { available: true, certCount: 0, certs: [], findings: [], reason: 'No X.509 certificates found.' };
  }
  return {
    available: true,
    certCount: seen.size,
    certs,
    findings,
    reason: `Parsed ${seen.size} embedded X.509 certificate${seen.size === 1 ? '' : 's'} from the image bytes with Node's built-in crypto — static analysis of the certificate material, not device behavior.`,
  };
}
