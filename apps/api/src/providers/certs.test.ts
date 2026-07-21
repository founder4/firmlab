import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { analyzeCert, extractPems, runCertAnalysis } from './certs.js';

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

describe('runCertAnalysis', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-certs-test-'));
  afterAll(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  it('is honest when no certificates are found', () => {
    const empty = path.join(tmpDir, 'empty.bin');
    fs.writeFileSync(empty, 'no certificates in these bytes whatsoever');
    const res = runCertAnalysis(null, empty, IN_WINDOW);
    expect(res.available).toBe(true);
    expect(res.certCount).toBe(0);
    expect(res.certs).toEqual([]);
    expect(res.findings).toEqual([]);
    expect(res.reason).toBe('No X.509 certificates found.');
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
});
