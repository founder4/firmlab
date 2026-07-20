import type { StringHit } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import { summarizeKeyMaterial } from './keys.js';

const hit = (secretKind: string, value: string, offset = 0): StringHit => ({ offset, value, secretKind });

describe('summarizeKeyMaterial', () => {
  it('picks cryptographic key material and marks embedded private keys effectively public', () => {
    const keys = summarizeKeyMaterial([
      hit('private-key', '-----BEGIN RSA PRIVATE KEY-----\nMIIEabc...', 100),
      hit('certificate', '-----BEGIN CERTIFICATE-----\nMIID...', 200),
      hit('password', 'hunter2', 300),
      hit('connection-string', 'mongodb://a:b@h/db', 400),
    ]);
    expect(keys.map((k) => k.kind)).toEqual(['private-key', 'certificate']);
    expect(keys[0]?.effectivelyPublic).toBe(true); // embedded private key → extractable → shared
    expect(keys[1]?.effectivelyPublic).toBe(false); // a certificate (public) is not
  });

  it('redacts values (never emits the raw key)', () => {
    const [k] = summarizeKeyMaterial([hit('private-key', '-----BEGIN RSA PRIVATE KEY-----\nDEADBEEFDEADBEEFDEADBEEF')]);
    expect(k?.redacted).toMatch(/…$/);
    expect(k?.redacted.length).toBeLessThan(40);
  });

  it('returns nothing when there is no key material', () => {
    expect(summarizeKeyMaterial([hit('password', 'x'), hit('shadow-hash', 'y')])).toHaveLength(0);
  });
});
