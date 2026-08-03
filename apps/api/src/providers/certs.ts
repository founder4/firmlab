/**
 * Embedded X.509 certificate provider — the honest read on the trust anchors a firmware ships. No external tool is
 * needed: Node's built-in `X509Certificate` parses each PEM block found in the rootfs files and in the raw image
 * bytes. Every finding is `static_confirmed` — a fact about the certificate bytes, never a device claim — and
 * certificates are public material, so surfacing their subject/issuer/validity leaks nothing (we never touch a
 * private key). `analyzeCert` is PURE and unit-tested; the runner only walks the rootfs / reads bytes and
 * composes them.
 *
 * **Where the PEM scanner went.** It used to live here, and finding blocks is not a certificate question: three
 * other providers want the same scan (`fsaudit` for keys in the rootfs, `auxsecrets` for the carved partitions
 * beside it, `nvram` for a key stuffed into a store value), and a certificate provider being their dependency is
 * the arrow pointing the wrong way. It is now `providers/pem-scan.ts`, which also documents the two rules this
 * file depends on: a block is only a block when a matching END closes a base64 body, and every bound the scan
 * applies is reported rather than silently answering as a measurement.
 *
 * Honest degradation: this layer always runs (built-in crypto), so it never blocks — an image with no certificates
 * returns certCount:0 with a reason that states what was and was not read, and it never fabricates a certificate
 * that isn't in the bytes.
 */
import { X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings-normalize.js';
import {
  DEFAULT_PEM_BUDGET,
  type PemBlock,
  type PemScanBudget,
  type PemScanCoverage,
  type PemScanEntry,
  type PemScanSkip,
  collectScanCandidates,
  findPemBlocks,
  planPemScan,
  scanFileForPem,
  scanTreeForPem,
  summarizePemScan,
} from './pem-scan.js';

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
