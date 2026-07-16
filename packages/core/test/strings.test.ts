import { describe, expect, it } from 'vitest';
import { classifySecret, extractSecrets, extractStrings } from '../src/strings.js';

function bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe('extractStrings', () => {
  it('extracts printable runs at or above minLength', () => {
    const buf = bytes('ab\x00hello\x00world!!\x01x');
    const hits = extractStrings(buf, { minLength: 5 });
    const values = hits.map((h) => h.value);
    expect(values).toContain('hello');
    expect(values).toContain('world!!');
    expect(values).not.toContain('ab');
  });

  it('records correct offsets', () => {
    const buf = bytes('\x00\x00secret\x00');
    const hit = extractStrings(buf, { minLength: 5 })[0];
    expect(hit?.offset).toBe(2);
    expect(hit?.value).toBe('secret');
  });
});

describe('classifySecret', () => {
  it('flags vendor default-credential markers', () => {
    expect(classifySecret('SYS_ADMPASS=admin').secretKind).toBe('vendor-default-credential');
    expect(classifySecret('WLN_WPAPSK1=12345678').severity).toBe('high');
  });

  it('flags private keys as critical', () => {
    const c = classifySecret('-----BEGIN OPENSSH PRIVATE KEY-----');
    expect(c.secretKind).toBe('private-key');
    expect(c.severity).toBe('critical');
  });

  it('flags AWS keys and connection strings', () => {
    expect(classifySecret('AKIAIOSFODNN7EXAMPLE').secretKind).toBe('aws-access-key');
    expect(classifySecret('mysql://root:hunter2@10.0.0.1/db').secretKind).toBe('connection-string');
  });

  it('flags password assignments', () => {
    expect(classifySecret('admin_password=letmein').secretKind).toBe('password-assignment');
  });

  it('returns empty for benign strings', () => {
    expect(classifySecret('just a normal log line').secretKind).toBeUndefined();
  });
});

describe('extractSecrets', () => {
  it('returns only secrets, sorted by severity', () => {
    const buf = bytes('noise here\x00admin_pass=abc123\x00-----BEGIN RSA PRIVATE KEY-----\x00more benign text here');
    const secrets = extractSecrets(buf, { minLength: 6 });
    expect(secrets.length).toBeGreaterThanOrEqual(2);
    // critical (private key) must sort before medium (password assignment).
    expect(secrets[0]?.severity).toBe('critical');
  });
});
