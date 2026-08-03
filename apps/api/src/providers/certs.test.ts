import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  analyzeCert,
  classifyPemLabel,
  extractPems,
  findPemBlocks,
  parsePemBlockAt,
  planPemScan,
  runCertAnalysis,
  scanFileForPem,
  summarizePemScan,
} from './certs.js';
import type { PemScanEntry, PemScanSkip } from './certs.js';

// A STATIC, self-signed RSA-2048 certificate generated with:
//   openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=DO NOT TRUST snakeoil" -days 3650 -keyout /dev/null -out -
// Subject === issuer, CA:TRUE, CN carries the "DO NOT TRUST … snakeoil" test markers. Valid 2026-07-21 → 2036-07-18.
const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUB+sbW6eejC94ba6BElWzVJ9N+T4wDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVRE8gTk9UIFRSVVNUIHNuYWtlb2lsMB4XDTI2MDcyMTE3
MzUxNVoXDTM2MDcxODE3MzUxNVowIDEeMBwGA1UEAwwVRE8gTk9UIFRSVVNUIHNu
YWtlb2lsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoEYGRctzT12V
6Jt/4VqBkG3I6OwPPE7UgORuHlv8TML2nzN/ZZcLKLEcvqxk0S4PG1olAw8T2kDW
IhE/dH6Reqakodi3BbpFpaHj5dpW32xQm3wSf45fBbeDYz38cfgnQctDEL5PUB2R
Uls8CAhy8X1TuCbjUGtNMNKbPN+XfH8PM9RhsMyOWVHeQYC4xB1wU7wHQ5KM0wTp
PzRud+86bjlJGsvitcBjtX3nbjXqfEYlyPVkUaL7TKvyICC5HFbNAkUz1bgeDYCI
P9SeRILy/7EnaCsi63c+DT4Ig4wiaIZapDJSUYomqrel3LVuUFflNGDyFhz6O/wH
wPTed1/OvQIDAQABo1MwUTAdBgNVHQ4EFgQU8VLLfEsxFcXu9FpFLo0HWBimIwsw
HwYDVR0jBBgwFoAU8VLLfEsxFcXu9FpFLo0HWBimIwswDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAD/3HQR+9GsvQMcV0StKgtBV+4XArvI1PLLqP
z6AoFEjTAkejkA1FLMiuBfW/Qv+dq8PDXFpJ9uUz9jIqhVsWyCfMNpNlWysL5lkT
ex2RJ6xBQ5lcNIU14/Ku62O70KWnot1jeL1K+r3g2pEsbEIkLUOduDd8jYI5L4NY
AreUAFDFPdOjDrnDFRmHVdH/hG5fl9NqCJ2WWIkEUqQCrB9BySLjkOcOabpQ9zMy
FhB5Wa+t1Zdbn3cTvWTkP0yidQPUXdH3OgmMGte75GGRl0cERQ6WeX4gBcnLD++f
omGkU090kYqO0WtpmLLQa5+qckEwF41avo+ux2t1us3s3u3G5A==
-----END CERTIFICATE-----`;

// A STATIC prime256v1 key generated for these tests only (`openssl ecparam -name prime256v1 -genkey -noout`).
// It is here to prove the scan tells key material from certificate material by READING the block's label.
const TEST_EC_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMnKvCNhfc2dphEJ4Lu1Hc23eKCVLCFxWERzpx53Em0HoAoGCCqGSM49
AwEHoUQDQgAEsDgQ1td4rd00bUluvh9sSP25M/r3G7NEr5QqiEMSzPp1ARYrAk0g
Uo/GdmR1u1+TpcvdqoqZnpfjLHtoIbdHJQ==
-----END EC PRIVATE KEY-----`;

// A timestamp comfortably inside the certificate's validity window (so no expiry noise).
const IN_WINDOW = Date.parse('2030-01-01T00:00:00Z');
// A timestamp far past notAfter, to exercise the expiry finding deterministically.
const FAR_FUTURE = Date.parse('2099-01-01T00:00:00Z');

describe('extractPems', () => {
  it('finds a certificate block embedded in surrounding text', () => {
    const blob = `# some config file\nca_bundle = /etc/ssl/ca.pem\n\n${TEST_CERT}\n\ntrailing junk after the block`;
    const pems = extractPems(blob);
    expect(pems).toHaveLength(1);
    expect(pems[0]).toContain('-----BEGIN CERTIFICATE-----');
    expect(pems[0]).toContain('-----END CERTIFICATE-----');
  });

  it('finds multiple concatenated certificate blocks', () => {
    expect(extractPems(`${TEST_CERT}\n# separator\n${TEST_CERT}`)).toHaveLength(2);
  });

  it('returns [] for text with no PEM block', () => {
    expect(extractPems('just some random configuration text, no certificates here at all')).toEqual([]);
  });
});

describe('analyzeCert', () => {
  it('parses the certificate and reports selfSigned:true with the RSA-2048 key', () => {
    const res = analyzeCert(TEST_CERT, IN_WINDOW);
    expect(res).not.toBeNull();
    expect(res?.info.selfSigned).toBe(true);
    expect(res?.info.keyType).toBe('rsa');
    expect(res?.info.keyBits).toBe(2048);
    expect(res?.info.subject).toContain('DO NOT TRUST');
    expect(res?.info.subject).toBe(res?.info.issuer);
  });

  it('flags the test/self-signed marker in the CN as a HIGH static_confirmed finding', () => {
    const res = analyzeCert(TEST_CERT, IN_WINDOW);
    const testFinding = res?.findings.find((f) => f.kind === 'cert-test');
    expect(testFinding).toBeDefined();
    expect(testFinding?.severity).toBe('high');
    expect(testFinding?.proofState).toBe('static_confirmed');
    // Evidence carries public metadata only — never a private key.
    expect(testFinding?.evidence).toMatchObject({ subject: expect.stringContaining('DO NOT TRUST') });
  });

  it('does not flag expiry while inside the validity window', () => {
    const res = analyzeCert(TEST_CERT, IN_WINDOW);
    expect(res?.findings.some((f) => f.kind === 'cert-expired')).toBe(false);
  });

  it('flags an expired certificate MEDIUM when now is past notAfter', () => {
    const res = analyzeCert(TEST_CERT, FAR_FUTURE);
    const expired = res?.findings.find((f) => f.kind === 'cert-expired');
    expect(expired).toBeDefined();
    expect(expired?.severity).toBe('medium');
    expect(expired?.proofState).toBe('static_confirmed');
  });

  it('returns null for a block that does not parse as a certificate', () => {
    expect(
      analyzeCert('-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----', IN_WINDOW),
    ).toBeNull();
    expect(analyzeCert('not a certificate at all', IN_WINDOW)).toBeNull();
  });
});

describe('classifyPemLabel — the label is read, never assumed', () => {
  it('separates certificates, private keys, public keys and everything else', () => {
    expect(classifyPemLabel('CERTIFICATE')).toBe('certificate');
    expect(classifyPemLabel('TRUSTED CERTIFICATE')).toBe('certificate');
    expect(classifyPemLabel('RSA PRIVATE KEY')).toBe('private-key');
    expect(classifyPemLabel('PRIVATE KEY')).toBe('private-key');
    expect(classifyPemLabel('ENCRYPTED PRIVATE KEY')).toBe('private-key');
    expect(classifyPemLabel('OPENSSH PRIVATE KEY')).toBe('private-key');
    expect(classifyPemLabel('PGP PRIVATE KEY BLOCK')).toBe('private-key');
    expect(classifyPemLabel('PUBLIC KEY')).toBe('public-key');
    // Measured in the corpus next to real keys — a public key is not a secret, whatever it is called.
    expect(classifyPemLabel('ROOT PUBLIC KEY')).toBe('public-key');
    // Neither a certificate nor a key: claiming either would be a claim about bytes nobody read.
    expect(classifyPemLabel('DH PARAMETERS')).toBe('other');
    expect(classifyPemLabel('CERTIFICATE REQUEST')).toBe('other');
    expect(classifyPemLabel('RSA TESTING KEY')).toBe('other');
  });
});

describe('findPemBlocks — a marker is not a block', () => {
  it('ignores a bare BEGIN marker with no END (the string-table case in a TLS library)', () => {
    // Measured: libwolfssl / dropbearmulti / libwpa_common contribute 16 of the 19 markers in the WR940N rootfs
    // and not one of them opens a block. Matching on the marker alone would invent 16 findings per rootfs.
    const junk = '\u0000\u0000-----BEGIN RSA PRIVATE KEY-----\u0000\u0000-----BEGIN CERTIFICATE-----\u0000';
    expect(findPemBlocks(junk)).toEqual([]);
  });

  it('ignores a BEGIN/END pair whose body is not base64 armor', () => {
    expect(findPemBlocks('-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----')).toEqual([]);
    // A body too short to be any DER payload is not a block either.
    expect(findPemBlocks('-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----')).toEqual([]);
  });

  it('finds a certificate and a key in one binary blob, classified apart, at exact offsets', () => {
    const prefix = '\u0000'.repeat(64);
    const blob = `${prefix}${TEST_CERT}\u0000\u0000${TEST_EC_KEY}\u0000`;
    const blocks = findPemBlocks(blob);
    expect(blocks.map((b) => b.kind)).toEqual(['certificate', 'private-key']);
    expect(blocks[0]?.offset).toBe(64);
    expect(blocks[1]?.offset).toBe(64 + TEST_CERT.length + 2);
    expect(blocks[1]?.label).toBe('EC PRIVATE KEY');
    expect(blocks[0]?.text).toBe(TEST_CERT);
  });

  it('reads an RFC 1421 encrypted block, headers and all', () => {
    const pem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'Proc-Type: 4,ENCRYPTED',
      'DEK-Info: AES-256-CBC,1B6FCF64864BF4B5E152BB9D5670A7D9',
      '',
      'sH/DHWN9W6sXUXuKe2HjHuXhVDCYvgUwGZwZk/Z2vCh68d14UXm1FBTVQcNerzRm',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n');
    const block = parsePemBlockAt(pem, 0);
    expect(block?.kind).toBe('private-key');
    expect(block?.encrypted).toBe(true);
  });

  it('offsets a window read back to its position in the file', () => {
    expect(parsePemBlockAt(TEST_CERT, 0, 1_894_844)?.offset).toBe(1_894_844);
  });
});

describe('planPemScan — the bound, and what it drops', () => {
  const budget = { maxFileBytes: 1000, totalBytes: 2500, maxFiles: 10 };

  it('orders by size then path, so the scanned set is not an artifact of directory layout', () => {
    const plan = planPemScan(
      [
        { path: 'z/late.bin', bytes: 10 },
        { path: 'a/early.bin', bytes: 500 },
        { path: 'a/also.bin', bytes: 10 },
      ],
      budget,
    );
    expect(plan.scan.map((f) => f.path)).toEqual(['a/also.bin', 'z/late.bin', 'a/early.bin']);
    expect(plan.skipped).toEqual([]);
  });

  it('truncates a file over the per-file cap rather than skipping it, and says how much it read', () => {
    const plan = planPemScan([{ path: 'big.bin', bytes: 5000 }], budget);
    expect(plan.scan[0]).toEqual({ path: 'big.bin', bytes: 5000, read: 1000 });
  });

  it('drops the LARGEST files when the total budget runs out, naming the rule', () => {
    const plan = planPemScan(
      [
        { path: 'a', bytes: 900 },
        { path: 'b', bytes: 900 },
        { path: 'c', bytes: 900 },
        { path: 'd', bytes: 5000 },
      ],
      budget,
    );
    expect(plan.scan.map((f) => f.path)).toEqual(['a', 'b']);
    expect(plan.skipped).toEqual([
      { path: 'c', bytes: 900, why: 'total-byte-budget' },
      { path: 'd', bytes: 5000, why: 'total-byte-budget' },
    ]);
    expect(plan.rule).toMatch(/smallest file first/);
  });

  it('applies the file-count cap with its own reason', () => {
    const files = Array.from({ length: 4 }, (_, i) => ({ path: `f${i}`, bytes: 10 }));
    const plan = planPemScan(files, { maxFileBytes: 100, totalBytes: 10_000, maxFiles: 2 });
    expect(plan.scan).toHaveLength(2);
    expect(plan.skipped.map((s) => s.why)).toEqual(['file-count-cap', 'file-count-cap']);
  });
});

describe('summarizePemScan — a bound is not an answer', () => {
  const entry = (over: Partial<PemScanEntry> = {}): PemScanEntry => ({
    path: 'f',
    bytes: 100,
    read: 100,
    markers: 0,
    markersDropped: 0,
    blocks: [],
    ...over,
  });

  it('says so plainly when nothing was left out', () => {
    const cov = summarizePemScan([entry(), entry({ path: 'g' })], [], 'the rule');
    expect(cov.filesScanned).toBe(2);
    expect(cov.bytesUnread).toBe(0);
    expect(cov.note).toMatch(/Read every byte of all 2 file\(s\)/);
  });

  it('states the unread bytes, names the largest of them, and refuses to read as clean', () => {
    const skipped: PemScanSkip[] = [{ path: 'huge.bin', bytes: 10_000, why: 'total-byte-budget' }];
    const cov = summarizePemScan([entry({ path: 'cut.bin', bytes: 900, read: 100 })], skipped, 'the rule');
    expect(cov.filesTruncated).toBe(1);
    expect(cov.filesSkipped).toBe(1);
    expect(cov.bytesUnread).toBe(800 + 10_000);
    expect(cov.note).toContain('huge.bin');
    expect(cov.note).toMatch(/not a clean result/);
    expect(cov.skippedSample[0]?.path).toBe('huge.bin');
  });

  it('reports markers that opened no block instead of letting them pass as absence', () => {
    const cov = summarizePemScan([entry({ markers: 12 })], [], 'the rule');
    expect(cov.markersSeen).toBe(12);
    expect(cov.note).toMatch(/12 marker\(s\) open no complete block/);
  });
});

describe('scanFileForPem — bytes, not extensions', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-pemscan-'));
  afterAll(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  /** A binary with NUL padding around a PEM block, at a known offset — the `usr/bin/httpd` shape. */
  function writeBinary(name: string, offset: number, pem: string, tail = 4096): string {
    const abs = path.join(tmpDir, name);
    const buf = Buffer.concat([Buffer.alloc(offset), Buffer.from(`${pem}\n`, 'latin1'), Buffer.alloc(tail)]);
    fs.writeFileSync(abs, buf);
    return abs;
  }

  it('finds a certificate 600 KB into an ELF-shaped binary, at its exact offset', () => {
    const abs = writeBinary('httpd', 600 * 1024, TEST_CERT);
    const entry = scanFileForPem(abs, 'usr/bin/httpd', 32 * 1024 * 1024);
    expect(entry.blocks).toHaveLength(1);
    expect(entry.blocks[0]?.kind).toBe('certificate');
    expect(entry.blocks[0]?.offset).toBe(600 * 1024);
    expect(entry.read).toBe(entry.bytes);
    expect(analyzeCert(entry.blocks[0]?.text ?? '', IN_WINDOW)).not.toBeNull();
  });

  it('finds a block that straddles the 1 MB chunk boundary', () => {
    // The marker itself is split across two reads — the overlap between chunks is what keeps it findable.
    const abs = writeBinary('straddle', 1024 * 1024 - 5, TEST_CERT);
    const entry = scanFileForPem(abs, 'straddle', 32 * 1024 * 1024);
    expect(entry.blocks.map((b) => b.offset)).toEqual([1024 * 1024 - 5]);
  });

  it('counts the bytes it did not read when the per-file cap cuts before the block', () => {
    const abs = writeBinary('capped', 600 * 1024, TEST_CERT);
    const entry = scanFileForPem(abs, 'capped', 64 * 1024);
    expect(entry.blocks).toEqual([]);
    expect(entry.read).toBe(64 * 1024);
    expect(entry.bytes - entry.read).toBeGreaterThan(500 * 1024);
  });
});

describe('runCertAnalysis', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-certs-test-'));
  afterAll(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  it('is honest when no certificates are found — and says what it read and what it did not', () => {
    const empty = path.join(tmpDir, 'empty.bin');
    fs.writeFileSync(empty, 'no certificates in these bytes whatsoever');
    const res = runCertAnalysis(null, empty, IN_WINDOW);
    expect(res.available).toBe(true);
    expect(res.certCount).toBe(0);
    expect(res.certs).toEqual([]);
    expect(res.findings).toEqual([]);
    expect(res.reason).toMatch(/^No X\.509 certificates found in what was scanned\./);
    // The zero is bounded by what was available: no rootfs means the packed bytes were all there was.
    expect(res.reason).toMatch(/No extracted rootfs was available/);
    expect(res.scan?.filesScanned).toBe(1);
    expect(res.scan?.bytesUnread).toBe(0);
  });

  it('finds, parses and dedupes a certificate embedded in the raw image bytes', () => {
    const img = path.join(tmpDir, 'image.bin');
    // Same certificate appears twice — dedupe by (subject+validTo) should collapse it to one.
    fs.writeFileSync(img, `firmware header bytes\n${TEST_CERT}\n...\n${TEST_CERT}\nfooter`);
    const res = runCertAnalysis(null, img, IN_WINDOW);
    expect(res.available).toBe(true);
    expect(res.certCount).toBe(1);
    expect(res.certs[0]?.selfSigned).toBe(true);
    expect(res.findings.some((f) => f.kind === 'cert-test' && f.severity === 'high')).toBe(true);
  });

  it('reads a certificate out of a 1.5 MB binary in the rootfs — the cap that used to answer for it', () => {
    // The measured defect: ROOTFS_FILE_CAP skipped every file ≥ 256 KB, so the WR940N's 1.9 MB usr/bin/httpd —
    // which carries a complete RSA key and its matching CN=tplinkwifi.net certificate — produced certCount:0
    // under the reason "No X.509 certificates found."
    const rootfs = path.join(tmpDir, 'rootfs');
    fs.mkdirSync(path.join(rootfs, 'usr/bin'), { recursive: true });
    fs.writeFileSync(
      path.join(rootfs, 'usr/bin/httpd'),
      Buffer.concat([
        Buffer.alloc(1_500_000),
        Buffer.from(`${TEST_EC_KEY}\n\u0000\u0000${TEST_CERT}\n`, 'latin1'),
        Buffer.alloc(4096),
      ]),
    );
    const img = path.join(tmpDir, 'packed.bin');
    fs.writeFileSync(img, 'compressed payload, no PEM visible here');

    const res = runCertAnalysis(rootfs, img, IN_WINDOW);
    expect(res.certCount).toBe(1);
    expect(res.certs[0]?.subject).toContain('DO NOT TRUST');
    expect(res.scan?.blocks).toMatchObject({ certificate: 1, privateKey: 1 });
    expect(res.scan?.bytesUnread).toBe(0);
    // The certificate lane does not claim the key it walked past — it says the material is there and whose it is.
    expect(res.reason).toMatch(/1 private-key/);
    expect(res.findings.some((f) => f.kind === 'cert-test')).toBe(true);
  });
});
