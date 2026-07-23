import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { ResearchConfig } from '../research/config.js';
import {
  classifyHash,
  maskSecret,
  normalizeHashLookup,
  parseNitrxgen,
  parseWeakpass,
  runHashLookup,
  verifyCandidate,
} from './hashlookup.js';

const md5 = (s: string): string => createHash('md5').update(s).digest('hex');
const sha1 = (s: string): string => createHash('sha1').update(s).digest('hex');
const sha256 = (s: string): string => createHash('sha256').update(s).digest('hex');

describe('classifyHash — resolvable vs salted', () => {
  it('classifies bare unsalted hex digests and marks them resolvable', () => {
    const m = classifyHash(md5('admin'));
    expect(m.scheme).toBe('md5-or-ntlm');
    expect(m.algos).toEqual(['md5', 'ntlm']);
    expect(m.resolvable).toBe(true);
    expect(m.digestHex).toBe(md5('admin'));

    expect(classifyHash(sha1('admin')).scheme).toBe('sha1');
    expect(classifyHash(sha1('admin')).algos).toEqual(['sha1']);
    expect(classifyHash(sha256('admin')).scheme).toBe('sha256');
  });

  it('decodes RFC 2307 unsalted LDAP forms to hex', () => {
    const shaB64 = Buffer.from(sha1('admin'), 'hex').toString('base64');
    const c = classifyHash(`{SHA}${shaB64}`);
    expect(c.scheme).toBe('ldap-sha');
    expect(c.resolvable).toBe(true);
    expect(c.digestHex).toBe(sha1('admin'));

    const md5B64 = Buffer.from(md5('admin'), 'hex').toString('base64');
    expect(classifyHash(`{MD5}${md5B64}`).digestHex).toBe(md5('admin'));
  });

  it('treats every salted crypt scheme as unresolvable and never yields a digest to send', () => {
    for (const salted of [
      '$1$abcd$xxxxxxxxxxxxxxxxxxxxx0', // md5crypt
      '$5$rounds=5000$salt$hash', // sha256crypt
      '$6$saltsalt$loooonghash', // sha512crypt
      '$2y$10$abcdefghijklmnopqrstuv', // bcrypt
      '$y$j9T$salt$hash', // yescrypt
      '{SSHA}c2FsdGVkc2FsdGVk', // salted LDAP
    ]) {
      const c = classifyHash(salted);
      expect(c.resolvable, salted).toBe(false);
      expect(c.salted, salted).toBe(true);
      expect(c.digestHex, salted).toBeNull();
    }
    // 13-char DES crypt (no $ prefix) is salted too.
    expect(classifyHash('kR3Vo5WznTZjs').salted).toBe(true);
    expect(classifyHash('kR3Vo5WznTZjs').scheme).toBe('descrypt');
  });

  it('marks locked/empty/unknown as inert (nothing to look up)', () => {
    expect(classifyHash('').scheme).toBe('empty');
    expect(classifyHash('*').scheme).toBe('locked');
    expect(classifyHash('!').scheme).toBe('locked');
    expect(classifyHash('!!').scheme).toBe('locked');
    expect(classifyHash('not-a-hash').scheme).toBe('unknown');
    for (const s of ['empty', 'locked', 'unknown']) {
      expect(classifyHash(s === 'empty' ? '' : s === 'locked' ? '*' : 'zzz').resolvable).toBe(false);
    }
  });
});

describe('maskSecret — recoverability without the secret', () => {
  it('keeps first/last + length for longer strings, fully stars short ones', () => {
    expect(maskSecret('password')).toBe('p******d (len 8)');
    expect(maskSecret('ab')).toBe('** (len 2)');
    expect(maskSecret('a')).toBe('* (len 1)');
    expect(maskSecret('')).toBe('(empty)');
  });
});

describe('verifyCandidate — single-value verification, not cracking', () => {
  it('confirms a correct plaintext under the right algo', () => {
    expect(verifyCandidate(md5('admin'), ['md5', 'ntlm'], 'admin')).toBe('md5');
    expect(verifyCandidate(sha1('letmein'), ['sha1'], 'letmein')).toBe('sha1');
    expect(verifyCandidate(sha256('root'), ['sha256'], 'root')).toBe('sha256');
  });

  it('rejects a wrong plaintext (a lookup service returning garbage → no false positive)', () => {
    expect(verifyCandidate(md5('admin'), ['md5', 'ntlm'], 'not-the-password')).toBeNull();
  });
});

describe('response parsers — defensive, candidate-only', () => {
  it('parseNitrxgen returns a plausible plaintext and rejects empties/HTML/oversized bodies', () => {
    expect(parseNitrxgen('hunter2')).toBe('hunter2');
    expect(parseNitrxgen('   ')).toBeNull();
    expect(parseNitrxgen('<html>404</html>')).toBeNull();
    expect(parseNitrxgen('x'.repeat(200))).toBeNull();
  });

  it('parseWeakpass pulls the password from any of the known JSON keys', () => {
    expect(parseWeakpass({ pass: 'secret' })).toBe('secret');
    expect(parseWeakpass({ password: 'secret2' })).toBe('secret2');
    expect(parseWeakpass({ type: 'md5', hash: 'abc' })).toBeNull(); // a miss carries no password field
    expect(parseWeakpass(null)).toBeNull();
    expect(parseWeakpass('nope')).toBeNull();
  });
});

describe('runHashLookup — gating and no-network paths', () => {
  const cfg = (hashLookup: boolean): ResearchConfig => ({
    allowlist: ['www.nitrxgen.net', 'weakpass.com'],
    timeoutMs: 5000,
    hashLookup,
  });

  it('is disabled (and sends nothing) when FIRMLAB_HASH_LOOKUP is off', async () => {
    const r = await runHashLookup([{ account: 'root', hash: md5('admin'), source: '/etc/shadow' }], cfg(false));
    expect(r.enabled).toBe(false);
    expect(r.attempted).toBe(0);
    expect(r.entries).toHaveLength(0);
  });

  it('classifies without querying when there are only salted/locked/empty hashes (attempted=0, no fetch)', async () => {
    const r = await runHashLookup(
      [
        { account: 'root', hash: '$6$salt$longhash', source: '/etc/shadow' },
        { account: 'admin', hash: '*', source: '/etc/shadow' },
        { account: 'nobody', hash: '', source: '/etc/shadow' },
      ],
      cfg(true),
    );
    expect(r.enabled).toBe(true);
    expect(r.attempted).toBe(0);
    expect(r.resolved).toBe(0);
    expect(r.entries.map((e) => e.outcome)).toEqual(['skipped_salted', 'skipped_other', 'skipped_other']);
  });
});

describe('normalizeHashLookup — only verified recoveries become findings', () => {
  it('emits a critical, static_confirmed finding per resolved entry and nothing for misses', () => {
    const drafts = normalizeHashLookup({
      enabled: true,
      reason: 'test',
      attempted: 2,
      resolved: 1,
      notQueried: 0,
      entries: [
        {
          account: 'root',
          source: '/etc/shadow',
          scheme: 'md5-or-ntlm',
          outcome: 'resolved',
          verifiedAs: 'md5',
          passwordMasked: 'a***n (len 5)',
        },
        {
          account: 'admin',
          source: '/etc/shadow',
          scheme: 'sha1',
          outcome: 'miss',
          manualLookupUrl: 'https://crackstation.net/',
        },
      ],
    });
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('recovered-password');
    expect(drafts[0]?.severity).toBe('critical');
    expect(drafts[0]?.proofState).toBe('static_confirmed');
    expect(drafts[0]?.evidence?.passwordMasked).toBe('a***n (len 5)');
  });
});
