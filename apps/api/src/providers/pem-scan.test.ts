import { describe, expect, it } from 'vitest';
import { findPemBlocks, keyMatchesCertificate, matchKeyToCertificates, readPrivateKeyBlock } from './pem-scan.js';

/**
 * A real RSA-1024 key and a real self-signed certificate FOR THAT KEY, generated for these tests only
 * (`openssl genrsa 1024` + `openssl req -x509 -new -key …`). The pair has to be genuine: the whole function under
 * test is a byte comparison of the two public halves, so a fixture that merely looked like a pair would assert
 * nothing. Not a credential — this key opens nothing that exists.
 */
const KEY = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCbXuNIEpNWcjq88lQ1lWlXd1kU2S67TX0xits4GGWjZawrq6Ms
eizb7Gi8pu8Z2oB1KuY8fz0kDtx0gLYVlmZXDz6k22AYrJnfjHyb611PKFbR6Uo1
cARDO3cItB6w8cfb71EFL2fcg1al0Z31hbBODvTKeHIcYAvKHO9Ijs7pPwIDAQAB
AoGABEUKR+vCwshm1tRt/f76Ix4zg4AoaZtKinb/aT46ZNAheB3CYTGGVBDeG/kW
bwZzK0UfiKAShRAnfMgguN0mOMlKqF1qYsfS/MLVnPJAsiSP3Tu2FQCi5LA7GYaO
YMXK/jzTYt1fN+1uxoiPHbf57yJhlCiYeGNdmacHQIzL80ECQQDL2W0uXU9jhRV7
bvdbCmd+v/uJ7G+7xnwi2QjZdPh/Kki1gQEvkdAcl34aSfh/nvsQ2fUypW75uBks
Tz7wPmafAkEAwx56nWkZ/jRnccy261itNHZQ0XZnXGlemmyRdS+3AIH+tj3LUY6C
AN9Iybbhb02Tw93rR7M8a0239S/yTQuZYQJATmSAE0t5A0mjuEM1RsKaiGjmH+VY
Frs+89vJBm9wPN8S9RH2VcfaY5Ryv0NhGBsYbCOVovNx2QDOVXboOlWU+wJAHzUW
w2p1/9R93xOxBf9O5J8v2fCoI32u5eALe8S/7lLcXGWRyV+Tp3QO/kRD1juAMMmj
wfoG5dquW4bpqCz8wQJASX38vRM+1fnCU/Qs8mN7/vVvxiLL8vjkH+UVfwsUaGDk
s+q0B/YV4bkgTmF7RZUkbqpYxGEcSVYIOKLtFn8F1A==
-----END RSA PRIVATE KEY-----`;

const CERT_FOR_KEY = `-----BEGIN CERTIFICATE-----
MIICGjCCAYOgAwIBAgIUaz9DP2bDaJGN3nr2TuQhB6Qn2rEwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUZmlybWxhYi1wYWlyaW5nLXRlc3QwHhcNMjYwODAzMTky
NzE3WhcNMzYwNzMxMTkyNzE3WjAfMR0wGwYDVQQDDBRmaXJtbGFiLXBhaXJpbmct
dGVzdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAm17jSBKTVnI6vPJUNZVp
V3dZFNkuu019MYrbOBhlo2WsK6ujLHos2+xovKbvGdqAdSrmPH89JA7cdIC2FZZm
Vw8+pNtgGKyZ34x8m+tdTyhW0elKNXAEQzt3CLQesPHH2+9RBS9n3INWpdGd9YWw
Tg70ynhyHGALyhzvSI7O6T8CAwEAAaNTMFEwHQYDVR0OBBYEFBuHaVjSsH8hgh9i
EPAEbIn4awbcMB8GA1UdIwQYMBaAFBuHaVjSsH8hgh9iEPAEbIn4awbcMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEARWx3npUGiks/X3njr8GvdUMJ
0dLbqVry8I6ql/nJJNajEZcU7uPh0hzNKcJ5ZkM0uOnLdDlXHpfW2Xm6zoU4XWO5
x7O3ZO+Nw4NIiPZ0fItXCVvdtafhGJMfwnqbIjsCB6YXh/Oniy3MG7f0IOC1fpj2
Mz5bKwXg2tj+b6hbExY=
-----END CERTIFICATE-----`;

/** A different, unrelated certificate — the negative control, without which the test proves nothing. */
const OTHER_CERT = `-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIULt3EX1PBn+d3wPFEQKPmCX3TZ+MwDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwURE8gTk9UIFRSVVNUIHNuYWtlb2lsMB4XDTI2MDcyMTA5
NTMxNVoXDTM2MDcxODA5NTMxNVowHzEdMBsGA1UEAwwURE8gTk9UIFRSVVNUIHNu
YWtlb2lsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8SBtCQO4hqI
YXCFimGpVWyEV6BvI1YkLcOQ3qJ+9SPWLbYYd2W3tGWRDkC1cYuGkuKuMPjq5x7Q
KXrjRxu8ZuJEcNJVQmCVOxSbCoU2eIYCC7DsvR9QGMYd4tE6+WMBKgJUyBRQIWLC
+8SG1ktCEgTKr4mkPYVBpEsRIxIFo9uFPzUqBmPYJZoARHVBUE5wxCVFXHCcMQvV
oCoxfXHkKz8ihaP4EQIkyPXeeuFTuVOCcAqBPPu5ubtWjHUXChD8FLGgLmn7Lm7L
KpAEMOwbe7EOsw6R+Fzo7cQzSdmNqTpmpe4Yg5cvRfmxDwe2ZDhSVCxRwZDdMbLM
XKwEqBqkjQIDAQABo1MwUTAdBgNVHQ4EFgQU9SlSXOZ6BiBnvhF5cVaFuyKtLo0w
HwYDVR0jBBgwFoAU9SlSXOZ6BiBnvhF5cVaFuyKtLo0wDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAKKGeGDbNmQOQKVMWjKKY1Qkn0Y5eKhLmA3xz
J8xTqTsWCLLBQFCLTdgAvbA3zGpFDGV2HZLQ1EFAHu1qxKk2rHVDzfLNiDoUXvfU
+3rTFvCJBBl0lLZOc1uOOEMFYcMLpVFDLXCwNPMlM8LKzMWxYxLdJnBQ7lLwxLKZ
0iRPBRQFqfJEMhbLZVE0iBVCLRb0UvLBSuNXtGxLtjkfLXWPAYUCPQCBLpMfYMDb
lLKlBEBAKq0rlIhGpFYUV3nRQFRYnGxLQfBLdLVZfIGWKKvMPTLAOZuJv8oB5Dqv
qIRJhcVKzGxRJPCcVBjJLGDLJvVwZLLLrCLdQKgVpXKlLQ==
-----END CERTIFICATE-----`;

describe('keyMatchesCertificate — the pair is established, never inferred', () => {
  it('says yes when the key really opens the certificate', () => {
    expect(keyMatchesCertificate(KEY, CERT_FOR_KEY)).toBe(true);
  });

  it('says no for an unrelated certificate, which is what makes the yes mean anything', () => {
    expect(keyMatchesCertificate(KEY, OTHER_CERT)).toBe(false);
  });

  // Anything that fails to parse must read as UNPROVEN. An exception swallowed into `true` would turn a garbled
  // block into a critical claim about a forgeable identity.
  it('says no rather than throwing when either side is not parseable', () => {
    expect(keyMatchesCertificate('not a key', CERT_FOR_KEY)).toBe(false);
    expect(keyMatchesCertificate(KEY, 'not a certificate')).toBe(false);
    expect(keyMatchesCertificate('', '')).toBe(false);
  });
});

describe('matchKeyToCertificates', () => {
  const blocks = findPemBlocks(`${OTHER_CERT}\n${CERT_FOR_KEY}\n`);

  it('picks the certificate the key opens out of the ones present, and reports its public metadata', () => {
    const m = matchKeyToCertificates(KEY, blocks);
    expect(m).not.toBeNull();
    expect(m?.subject).toContain('firmlab-pairing-test');
    expect(m?.validTo).toBeTruthy();
    // The offset is the matched certificate's, not the first block's — the pair has to be re-readable.
    expect(m?.offset).toBe(blocks[1]?.offset);
  });

  it('returns null when none of the certificates present belong to the key', () => {
    expect(matchKeyToCertificates(KEY, findPemBlocks(OTHER_CERT))).toBeNull();
  });

  it('ignores blocks that are not certificates', () => {
    expect(matchKeyToCertificates(KEY, findPemBlocks(KEY))).toBeNull();
  });
});

describe('readPrivateKeyBlock — decoded, never taken on the label', () => {
  it('reads the algorithm and size out of the key itself', () => {
    const block = findPemBlocks(KEY)[0];
    expect(block).toBeDefined();
    const read = readPrivateKeyBlock(block as NonNullable<typeof block>);
    expect(read.isKey).toBe(true);
    expect(read.keyType).toBe('rsa');
    expect(read.keyBits).toBe(1024);
  });

  /**
   * The nvram/C-string shape: the armor survives but the line breaks do not. Re-wrapping changes no byte of the
   * payload, and refusing to try would lose a real key for a formatting reason.
   */
  it('re-wraps a key that lost its line breaks and still decodes it', () => {
    const flattened = KEY.replace(/\n/g, '');
    const block = findPemBlocks(flattened)[0];
    expect(block).toBeDefined();
    expect(readPrivateKeyBlock(block as NonNullable<typeof block>).keyBits).toBe(1024);
  });

  it('refuses a well-formed block whose body is not a key', () => {
    const fake =
      '-----BEGIN RSA PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqaw==\n-----END RSA PRIVATE KEY-----';
    const block = findPemBlocks(fake)[0];
    expect(block).toBeDefined();
    const read = readPrivateKeyBlock(block as NonNullable<typeof block>);
    expect(read.isKey).toBe(false);
    expect(read.note).toContain('did not decode');
  });
});
