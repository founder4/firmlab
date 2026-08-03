import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  type Candidate,
  type CandidateSummary,
  type TargetResult,
  backendForScheme,
  blockedResult,
  buildCredMatchFindings,
  candidateScore,
  classifyCredentialField,
  collapseForScheme,
  collectTargets,
  deriveCandidates,
  describeBoundedNegative,
  extractPrintableStrings,
  parseAccountFile,
  parseCryptHash,
  rankCandidates,
  rankTargets,
  redactHash,
  resolveBackend,
  runCredMatch,
} from './credmatch.js';
import { CRYPT64, desCrypt, desEffectivePassword, isDesHash } from './descrypt.js';
import type { JobHandle } from './jobs.js';

/** A job handle that swallows its log, for the runner tests. */
const handle: JobHandle = { id: 'test', log: () => {} };

// The two real corpus credentials this provider was built for.
const WR940N_SHADOW = 'root:$1$GTN.gpri$DlSyKvZKMR9A9Uj9e9wR3/:15502:0:99999:7:::\n';
const TENDA_SHADOW = 'root:E0HKrpNhcmto6:0:0:99999:7:::\nbin:*:10933:0:99999:7:::\nnobody:*:10933:0:99999:7:::\n';
const TENDA_PASSWD = 'root:x:0:0:root:/:/bin/sh\nnobody:x:99:99:nobody:/home:/bin/sh\n';

// ---------------------------------------------------------------------------------------------------------------
// descrypt — checked against glibc's own crypt(3) (captured via perl 5.36 in the deployed container)
// ---------------------------------------------------------------------------------------------------------------

describe('desCrypt', () => {
  // Every expected value here was produced by libcrypt itself, not by a second copy of this implementation.
  const vectors: Array<[string, string, string]> = [
    ['', 'aa', 'aaQSqAReePlq6'],
    ['a', 'ab', 'abxxB7HlIeckU'],
    ['abc', 'zZ', 'zZSSO/CvvSML6'],
    ['password', './', './xZjzHv5vzVE'],
    ['12345678', '9z', '9zkR2aQutwZAE'],
    ['ABCDEFGHIJK', 'Q1', 'Q1pEMx2rUre86'],
    ['~!@#$%^&', 'xY', 'xY/HhBHN4sB82'],
    ['root', 'ro', 'roK20XGbWEsSM'],
    ['admin', 'aB', 'aBOWLUKH4hQdw'],
    ['8charspw', '//', '//tOwg9c9d86.'],
    ['z', '..', '..xGT4Kwqpo7o'],
  ];

  for (const [password, salt, expected] of vectors) {
    it(`reproduces crypt(3) for ${JSON.stringify(password)} with salt ${salt}`, () => {
      expect(desCrypt(password, salt)).toBe(expected);
    });
  }

  it('reproduces the Tenda camera hash from the real corpus', () => {
    expect(desCrypt('Td2N3ww1', 'E0')).toBe('E0HKrpNhcmto6');
  });

  it('truncates at 8 bytes: the shipped string and its 8-char prefix hash identically', () => {
    expect(desCrypt('Td2N3ww1.0_tenda_force_upgrade', 'E0')).toBe('E0HKrpNhcmto6');
    expect(desEffectivePassword('Td2N3ww1.0_tenda_force_upgrade')).toBe('Td2N3ww1');
  });

  it('does NOT match on a 7-character prefix — the truncation boundary is exactly 8', () => {
    expect(desCrypt('Td2N3ww', 'E0')).toBe('E0FfupRh4qu7o');
    expect(desCrypt('Td2N3ww', 'E0')).not.toBe('E0HKrpNhcmto6');
  });

  it('uses the crypt alphabet, not RFC 4648 base64', () => {
    expect(CRYPT64.slice(0, 4)).toBe('./01');
    expect(desCrypt('a', 'ab')).toMatch(/^ab[./0-9A-Za-z]{11}$/);
  });

  it('recognises a 13-char crypt hash and rejects anything else', () => {
    expect(isDesHash('E0HKrpNhcmto6')).toBe(true);
    expect(isDesHash('E0HKrpNhcmto')).toBe(false);
    expect(isDesHash('$1$GTN.gpri$DlSyKvZKMR9A9Uj9e9wR3/')).toBe(false);
    expect(isDesHash('*')).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Reading the account database
// ---------------------------------------------------------------------------------------------------------------

describe('parseCryptHash', () => {
  it('decomposes the WR940N md5crypt hash', () => {
    const hash = parseCryptHash('$1$GTN.gpri$DlSyKvZKMR9A9Uj9e9wR3/');
    expect(hash?.scheme).toBe('md5crypt');
    expect(hash?.salt).toBe('GTN.gpri');
    expect(hash?.prefix).toBe('$1$GTN.gpri$');
    expect(hash?.digest).toBe('DlSyKvZKMR9A9Uj9e9wR3/');
  });

  it('decomposes a DES hash by shape, with the salt as its first two characters', () => {
    const hash = parseCryptHash('E0HKrpNhcmto6');
    expect(hash?.scheme).toBe('descrypt');
    expect(hash?.salt).toBe('E0');
    expect(hash?.prefix).toBe('E0');
    expect(hash?.marker).toBe('');
  });

  it('keeps a `rounds=` cost inside the salt, because that is what a hasher must be handed', () => {
    const hash = parseCryptHash('$5$rounds=1000$abcdefgh$RUGFi09CBLSH..oQjMUX2fVgTQ9U4LdVTJRFKUEmOzB');
    expect(hash?.scheme).toBe('sha256crypt');
    expect(hash?.salt).toBe('rounds=1000$abcdefgh');
    expect(hash?.prefix).toBe('$5$rounds=1000$abcdefgh$');
  });

  it('names bcrypt and yescrypt without pretending to decompose them', () => {
    expect(parseCryptHash('$2y$10$abcdefghijklmnopqrstuv0123456789ABCDEFGHIJKLMNOPQRS')?.scheme).toBe('bcrypt');
    expect(parseCryptHash('$y$j9T$abcdefgh$0123456789')?.scheme).toBe('yescrypt');
    expect(parseCryptHash('$6$abcdefgh$0123456789')?.label).toBe('sha512crypt ($6$)');
  });

  it('returns null for a field that is not a crypt hash', () => {
    expect(parseCryptHash('*')).toBeNull();
    expect(parseCryptHash('')).toBeNull();
    expect(parseCryptHash('$99$abcdefgh$0123456789')).toBeNull();
    // A `$1$` field whose salt carries characters the crypt alphabet does not have is not this shape.
    expect(parseCryptHash('$1$bad salt$0123456789')).toBeNull();
  });
});

describe('classifyCredentialField', () => {
  it('separates empty, deferred, locked and unrecognised from an actual hash', () => {
    expect(classifyCredentialField('').state).toBe('empty');
    expect(classifyCredentialField('x').state).toBe('deferred');
    expect(classifyCredentialField('*').state).toBe('locked');
    expect(classifyCredentialField('!!').state).toBe('locked');
    expect(classifyCredentialField('nonsense').state).toBe('unrecognized');
    expect(classifyCredentialField('E0HKrpNhcmto6').state).toBe('hash');
  });

  it('keeps a `!`-prefixed hash as a testable hash, flagged locked', () => {
    const field = classifyCredentialField('!$1$GTN.gpri$DlSyKvZKMR9A9Uj9e9wR3/');
    expect(field.state).toBe('hash');
    if (field.state !== 'hash') throw new Error('unreachable');
    expect(field.locked).toBe(true);
    expect(field.hash.salt).toBe('GTN.gpri');
  });
});

describe('parseAccountFile / collectTargets', () => {
  it('reads the Tenda shadow and passwd, taking the UID from passwd', () => {
    const targets = collectTargets([
      { path: 'etc/shadow', text: TENDA_SHADOW, kind: 'shadow' },
      { path: 'etc/passwd', text: TENDA_PASSWD, kind: 'passwd' },
    ]);
    expect(targets).toHaveLength(1);
    expect(targets[0]?.account).toBe('root');
    expect(targets[0]?.uid).toBe(0);
    expect(targets[0]?.hash.scheme).toBe('descrypt');
    expect(targets[0]?.file).toBe('etc/shadow');
  });

  it('skips comments, blanks and lines with fewer than two fields', () => {
    expect(parseAccountFile('# comment\n\nbroken\nroot:E0HKrpNhcmto6:0\n', 'etc/shadow', 'shadow')).toHaveLength(1);
  });

  it('never reads a UID out of /etc/shadow, where the third field is a date', () => {
    // `bin:*:10933:…` is a last-change day, not UID 10933 — and a recovered password's severity turns on the UID.
    const records = parseAccountFile('bin:E0HKrpNhcmto6:10933:0:99999:7:::\n', 'etc/shadow', 'shadow');
    expect(records[0]?.uid).toBeNull();
    expect(parseAccountFile('bin:x:2:2:bin:/bin:/bin/sh\n', 'etc/passwd', 'passwd')[0]?.uid).toBe(2);
  });

  it('dedupes the same hash stored in both files', () => {
    const both = [
      { path: 'etc/shadow', text: WR940N_SHADOW, kind: 'shadow' as const },
      {
        path: 'etc/passwd',
        text: 'root:$1$GTN.gpri$DlSyKvZKMR9A9Uj9e9wR3/:0:0:root:/root:/bin/sh\n',
        kind: 'passwd' as const,
      },
    ];
    expect(collectTargets(both)).toHaveLength(1);
  });

  it('ranks UID 0 first, then unlocked accounts, so the target cap cannot drop root', () => {
    const targets = collectTargets([
      {
        path: 'etc/shadow',
        text: ['zebra:E0HKrpNhcmto6:0', 'root:$1$GTN.gpri$DlSyKvZKMR9A9Uj9e9wR3/:0'].join('\n'),
        kind: 'shadow' as const,
      },
      {
        path: 'etc/passwd',
        text: 'root:x:0:0:root:/root:/bin/sh\nzebra:x:1000:1000:z:/home/z:/bin/sh\n',
        kind: 'passwd' as const,
      },
    ]);
    expect(rankTargets(targets).map((t) => t.account)).toEqual(['root', 'zebra']);
  });

  it('redacts the digest but keeps the scheme and salt', () => {
    const hash = parseCryptHash('$1$GTN.gpri$DlSyKvZKMR9A9Uj9e9wR3/');
    if (!hash) throw new Error('unreachable');
    expect(redactHash(hash)).toBe('$1$GTN.gpri$<redacted>');
    expect(redactHash(hash)).not.toContain('DlSyKvZKMR9A9Uj9e9wR3/');
    const des = parseCryptHash('E0HKrpNhcmto6');
    if (!des) throw new Error('unreachable');
    expect(redactHash(des)).toBe('E0<redacted>');
    expect(redactHash(des)).not.toContain('HKrpNhcmto6');
    // A scheme that is named but never decomposed still shows which one it was, not a bare `<redacted>`.
    const yes = parseCryptHash('$y$j9T$abcdefgh$0123456789');
    if (!yes) throw new Error('unreachable');
    expect(redactHash(yes)).toBe('$y$<redacted>');
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Which schemes can be computed here
// ---------------------------------------------------------------------------------------------------------------

describe('backendForScheme / resolveBackend', () => {
  it('computes DES in process and the $id$ schemes with openssl', () => {
    expect(backendForScheme('descrypt')).toEqual({ kind: 'internal-des' });
    expect(backendForScheme('md5crypt')).toEqual({ kind: 'openssl', flag: '-1' });
    expect(backendForScheme('sha512crypt')).toEqual({ kind: 'openssl', flag: '-6' });
  });

  it('refuses bcrypt and yescrypt by naming the scheme, never by silence', () => {
    const bcrypt = backendForScheme('bcrypt');
    expect(bcrypt.kind).toBe('unsupported');
    if (bcrypt.kind !== 'unsupported') throw new Error('unreachable');
    expect(bcrypt.reason).toContain('bcrypt');
  });

  it('DES stays computable when openssl is absent — it never needed it', () => {
    const backend = resolveBackend('descrypt', { available: false, verifiedFlags: [], failures: [] });
    expect(backend).toEqual({ kind: 'internal-des' });
  });

  it('an absent openssl blocks the $id$ schemes with a reason naming the tool', () => {
    const backend = resolveBackend('md5crypt', { available: false, verifiedFlags: [], failures: [] });
    expect(backend.kind).toBe('unsupported');
    if (backend.kind !== 'unsupported') throw new Error('unreachable');
    expect(backend.reason).toContain('openssl is not installed');
  });

  it('a flag that fails its known-answer self-test is not used, and the failure is quoted', () => {
    const backend = resolveBackend('md5crypt', {
      available: true,
      verifiedFlags: ['-6'],
      failures: [{ flag: '-1', reason: 'expected $1$abc, got $1$xyz' }],
    });
    expect(backend.kind).toBe('unsupported');
    if (backend.kind !== 'unsupported') throw new Error('unreachable');
    expect(backend.reason).toContain('known answer');
    expect(backend.reason).toContain('$1$xyz');
  });
});

// ---------------------------------------------------------------------------------------------------------------
// Candidates
// ---------------------------------------------------------------------------------------------------------------

describe('extractPrintableStrings', () => {
  it('finds printable runs with their offsets and stops at a non-printable byte', () => {
    const buf = Buffer.from('\x00\x00sohoadmin\x00\x01ab\x00', 'latin1');
    const hits = extractPrintableStrings(buf, { minLength: 3 });
    expect(hits).toEqual([{ value: 'sohoadmin', offset: 2 }]);
  });

  it('never emits a newline, so every candidate is one safe line of an openssl -in list', () => {
    const buf = Buffer.from('alpha\nbravo\r\ncharlie', 'latin1');
    for (const hit of extractPrintableStrings(buf, { minLength: 3 })) {
      expect(hit.value).not.toMatch(/[\r\n]/);
    }
  });

  it('drops an over-long run rather than truncating it — a truncated string is not in the image', () => {
    const buf = Buffer.from(`\x00${'A'.repeat(200)}\x00`, 'latin1');
    expect(extractPrintableStrings(buf, { minLength: 3, maxLength: 128 })).toEqual([]);
  });
});

describe('deriveCandidates', () => {
  it('splits a key=value assignment, which is what makes the Tenda case reachable at all', () => {
    const derived = deriveCandidates('current_force_upgrade_pwd=Td2N3ww1.0_tenda_force_upgrade');
    const value = derived.find((d) => d.derivation === 'assignment-value');
    expect(value?.value).toBe('Td2N3ww1.0_tenda_force_upgrade');
    expect(value?.key).toBe('current_force_upgrade_pwd');
    // Without the split, DES would test the first 8 bytes of the whole string, which are not the credential.
    expect(desEffectivePassword('current_force_upgrade_pwd=Td2N3ww1.0_tenda_force_upgrade')).toBe('current_');
    expect(desEffectivePassword(value?.value ?? '')).toBe('Td2N3ww1');
  });

  it('keeps the literal, quoted runs and whitespace tokens, deduped', () => {
    const values = deriveCandidates('set pw "hunter2"').map((d) => d.value);
    expect(values).toContain('set pw "hunter2"');
    expect(values).toContain('hunter2');
    expect(values).toContain('set');
    expect(new Set(values).size).toBe(values.length);
  });

  it('drops an over-long derivation rather than testing a truncated string', () => {
    expect(deriveCandidates(`k=${'A'.repeat(200)}`).map((d) => d.derivation)).not.toContain('assignment-value');
  });
});

describe('candidateScore / rankCandidates', () => {
  const at = (value: string, extra: Partial<Candidate> = {}): Candidate => ({
    value,
    derivation: 'literal',
    file: 'usr/bin/x',
    offset: 0,
    ...extra,
  });

  it('puts the value of a credential-named assignment above a bare literal', () => {
    const named = at('Td2N3ww1.0_tenda_force_upgrade', {
      derivation: 'assignment-value',
      key: 'current_force_upgrade_pwd',
    });
    expect(candidateScore(named)).toBeGreaterThan(candidateScore(at('Td2N3ww1.0_tenda_force_upgrade')));
  });

  it('penalises a path and a format string', () => {
    expect(candidateScore(at('/usr/lib/libc.so'))).toBeLessThan(candidateScore(at('sohoadmin')));
    expect(candidateScore(at('%s: %d bytes'))).toBeLessThan(candidateScore(at('sohoadmin')));
  });

  it('breaks ties on the value, never on harvest order, so two runs test the same set', () => {
    const a = rankCandidates({ candidates: [at('bbb'), at('aaa'), at('ccc')], cap: 2 });
    const b = rankCandidates({ candidates: [at('ccc'), at('bbb'), at('aaa')], cap: 2 });
    expect(a.selected.map((c) => c.value)).toEqual(b.selected.map((c) => c.value));
    expect(a.dropped).toBe(1);
  });

  it('a cap of 0 means no cap and drops nothing', () => {
    expect(rankCandidates({ candidates: [at('a'), at('b')], cap: 0 }).dropped).toBe(0);
  });
});

describe('collapseForScheme', () => {
  const at = (value: string): Candidate => ({ value, derivation: 'literal', file: 'f', offset: 0 });

  it('collapses DES candidates to distinct 8-byte prefixes and keeps the shortest representative', () => {
    const { tests, collapsed } = collapseForScheme('descrypt', [
      at('Td2N3ww1.0_tenda_force_upgrade'),
      at('Td2N3ww1'),
      at('unrelated'),
    ]);
    expect(collapsed).toBe(1);
    expect(tests.map((t) => t.password).sort()).toEqual(['Td2N3ww1', 'unrelate']);
    expect(tests.find((t) => t.password === 'Td2N3ww1')?.candidate.value).toBe('Td2N3ww1');
  });

  it('leaves every other scheme alone — only DES truncates', () => {
    const { tests, collapsed } = collapseForScheme('md5crypt', [at('abcdefghij'), at('abcdefghXX')]);
    expect(collapsed).toBe(0);
    expect(tests).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------------------------------------------
// The verdict and its findings
// ---------------------------------------------------------------------------------------------------------------

const SUMMARY: CandidateSummary = {
  root: '/data/extract/x/squashfs-root',
  filesFound: 496,
  filesRead: 490,
  filesTooLarge: 0,
  filesUnreadable: 6,
  dirsUnreadable: 0,
  deepDirsSkipped: 0,
  bytesRead: 13_000_000,
  stringsHarvested: 400_000,
  candidatesDistinct: 120_000,
  candidatesTested: 100_000,
  candidatesDropped: 20_000,
  cap: 100_000,
  capRule: 'a cap of 100000 candidate(s), taken in order of provenance first',
  minStringLength: 3,
  maxCandidateLength: 128,
};

const CANDIDATE: Candidate = {
  value: 'Td2N3ww1.0_tenda_force_upgrade',
  derivation: 'assignment-value',
  key: 'current_force_upgrade_pwd',
  file: 'usr/bin/force_upgrade',
  offset: 0x2a00,
};

function target(result: TargetResult['result'], over: Partial<TargetResult> = {}): TargetResult {
  return {
    account: 'root',
    uid: 0,
    file: 'etc/shadow',
    scheme: 'descrypt',
    schemeLabel: 'DES crypt (13-char)',
    hashRedacted: 'E0<redacted>',
    locked: false,
    result,
    ...over,
  };
}

describe('buildCredMatchFindings', () => {
  it('a hit is static_confirmed, critical for root, and names the derivation and the file', () => {
    const [finding] = buildCredMatchFindings(
      [target({ outcome: 'recovered', password: 'Td2N3ww1', candidate: CANDIDATE, tested: 23_148 })],
      SUMMARY,
    );
    expect(finding?.kind).toBe('credential-recovered-from-image');
    expect(finding?.proofState).toBe('static_confirmed');
    expect(finding?.severity).toBe('critical');
    expect(finding?.evidenceChannel).toBe('static_bytes');
    expect(finding?.title).toContain('Td2N3ww1');
    expect((finding?.evidence as { password: string }).password).toBe('Td2N3ww1');
    expect((finding?.evidence as { candidateFile: string }).candidateFile).toBe('usr/bin/force_upgrade');
    expect(finding?.rationale).toContain('current_force_upgrade_pwd');
    // The DES truncation is spelled out, because the shipped string is longer than the credential.
    expect(finding?.rationale).toContain('first 8 bytes');
  });

  it('a hit never overstates itself into a device claim, and never leaks the stored hash', () => {
    const [finding] = buildCredMatchFindings(
      [target({ outcome: 'recovered', password: 'Td2N3ww1', candidate: CANDIDATE, tested: 10 })],
      SUMMARY,
    );
    expect(finding?.rationale).toContain('NOT a claim that the account is enabled');
    expect(JSON.stringify(finding)).not.toContain('HKrpNhcmto6');
    expect(JSON.stringify(finding?.evidence)).toContain('<redacted>');
  });

  it('a recovered password on a locked account is filed lower and says the account is locked', () => {
    const [finding] = buildCredMatchFindings(
      [target({ outcome: 'recovered', password: 'Td2N3ww1', candidate: CANDIDATE, tested: 10 }, { locked: true })],
      SUMMARY,
    );
    expect(finding?.severity).toBe('medium');
    expect(finding?.rationale).toContain('locked');
  });

  it('a miss is a BOUNDED NEGATIVE that states the count and refuses the strength claim', () => {
    const [finding] = buildCredMatchFindings(
      [target({ outcome: 'not-recovered', tested: 32_430, collapsed: 5000 })],
      SUMMARY,
    );
    expect(finding?.kind).toBe('credential-not-recovered-from-image');
    expect(finding?.proofState).toBe('static_confirmed');
    expect(finding?.severity).toBe('info');
    expect(finding?.title).toContain('32430 candidates');
    expect(finding?.rationale).toContain('bounded negative');
    expect(finding?.rationale).toContain('does NOT mean the password is strong');
    // The cap that dropped candidates is named, not merely counted.
    expect(finding?.rationale).toContain('dropped by');
    expect((finding?.evidence as { candidatesTested: number }).candidatesTested).toBe(32_430);
  });

  it('an uncomputable scheme is blocked_by_platform and NAMES the scheme', () => {
    const [finding] = buildCredMatchFindings(
      [
        target(
          { outcome: 'blocked', reason: '`openssl passwd` has no yescrypt option' },
          { scheme: 'yescrypt', schemeLabel: 'yescrypt ($y$)' },
        ),
      ],
      SUMMARY,
    );
    expect(finding?.kind).toBe('credential-scheme-not-computable');
    expect(finding?.proofState).toBe('blocked_by_platform');
    expect(finding?.title).toContain('yescrypt ($y$)');
    expect(finding?.rationale).toContain('nothing was tried');
  });

  it('every target yields exactly one finding, whichever way it went', () => {
    const findings = buildCredMatchFindings(
      [
        target({ outcome: 'recovered', password: 'a', candidate: CANDIDATE, tested: 1 }),
        target({ outcome: 'not-recovered', tested: 2, collapsed: 0 }, { account: 'b' }),
        target({ outcome: 'blocked', reason: 'nope' }, { account: 'c' }),
      ],
      SUMMARY,
    );
    expect(findings).toHaveLength(3);
  });
});

describe('describeBoundedNegative', () => {
  it('explains the DES collapse as the reason the test count is lower than the candidate count', () => {
    const text = describeBoundedNegative(target({ outcome: 'not-recovered', tested: 50, collapsed: 10 }), 50, SUMMARY);
    expect(text).toContain('collapse to 50 distinct 8-byte prefix');
    expect(text).toContain('only the first 8 bytes');
  });

  it('says nothing about collapsing for a scheme that does not truncate', () => {
    const md5 = target({ outcome: 'not-recovered', tested: 50, collapsed: 0 }, { scheme: 'md5crypt' });
    expect(describeBoundedNegative(md5, 50, SUMMARY)).not.toContain('collapse');
  });
});

describe('blockedResult', () => {
  it('records the question as unasked, with a reason, for each of the four causes', () => {
    for (const state of ['no_target', 'no_account_files', 'no_hashes', 'no_candidates'] as const) {
      const result = blockedResult(state, 'because');
      expect(result.available).toBe(false);
      expect(result.state).toBe(state);
      expect(result.candidates).toBeNull();
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.proofState).toBe('blocked_by_platform');
      expect(result.findings[0]?.rationale).toContain('nothing was hashed');
    }
  });
});

// ---------------------------------------------------------------------------------------------------------------
// The runner, end to end, on a synthetic rootfs — no openssl needed, because DES needs none
// ---------------------------------------------------------------------------------------------------------------

describe('runCredMatch', () => {
  function makeRootfs(files: Record<string, string>): string {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-credmatch-test-'));
    for (const [rel, content] of Object.entries(files)) {
      const abs = path.join(root, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, content, 'latin1');
    }
    return root;
  }

  it('recovers the real Tenda credential from a string the rootfs ships, end to end', async () => {
    const root = makeRootfs({
      'etc/shadow': TENDA_SHADOW,
      'etc/passwd': TENDA_PASSWD,
      // The string as it really appears in the camera's /usr/bin/force_upgrade, surrounded by binary noise.
      'usr/bin/force_upgrade': '\x00\x01current_force_upgrade_pwd=Td2N3ww1.0_tenda_force_upgrade\x00\x02',
    });
    try {
      const result = await runCredMatch(root, handle, { targetCap: 4 });
      expect(result.state).toBe('scanned');
      expect(result.targets).toHaveLength(1);
      const outcome = result.targets[0]?.result;
      expect(outcome?.outcome).toBe('recovered');
      if (outcome?.outcome !== 'recovered') throw new Error('unreachable');
      expect(outcome.password).toBe('Td2N3ww1');
      expect(outcome.candidate.derivation).toBe('assignment-value');
      expect(result.findings[0]?.proofState).toBe('static_confirmed');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('returns a bounded negative when the plaintext is NOT in the image', async () => {
    const root = makeRootfs({
      'etc/shadow': TENDA_SHADOW,
      'etc/passwd': TENDA_PASSWD,
      'usr/bin/httpd': 'nothing here resembles the password at all',
    });
    try {
      const result = await runCredMatch(root, handle, { targetCap: 4 });
      const outcome = result.targets[0]?.result;
      expect(outcome?.outcome).toBe('not-recovered');
      const finding = result.findings.find((f) => f.kind === 'credential-not-recovered-from-image');
      expect(finding?.rationale).toContain('bounded negative');
      expect(finding?.rationale).not.toContain('strong password');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('records a hash past the target cap as untested, never as an absent row', async () => {
    const root = makeRootfs({
      'etc/shadow': ['root:E0HKrpNhcmto6:0', 'alpha:aaQSqAReePlq6:0', 'zulu:abxxB7HlIeckU:0'].join('\n'),
      'etc/passwd': 'root:x:0:0:root:/:/bin/sh\nalpha:x:1000:1000:a:/:/bin/sh\nzulu:x:1001:1001:z:/:/bin/sh\n',
      'bin/busybox': 'Td2N3ww1.0_tenda_force_upgrade',
    });
    try {
      const result = await runCredMatch(root, handle, { targetCap: 1 });
      expect(result.targets).toHaveLength(3);
      // root sorts first, so the cap keeps it and records the other two as never hashed.
      expect(result.targets[0]?.account).toBe('root');
      expect(result.targets[0]?.result.outcome).toBe('recovered');
      const untested = result.targets.filter((t) => t.result.outcome === 'blocked');
      expect(untested).toHaveLength(2);
      expect(result.findings.filter((f) => f.proofState === 'blocked_by_platform')).toHaveLength(2);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('degrades honestly with no rootfs, no account files and no testable hash', async () => {
    expect((await runCredMatch('/nonexistent/rootfs', handle)).state).toBe('no_target');

    const empty = makeRootfs({ 'bin/busybox': 'x' });
    try {
      expect((await runCredMatch(empty, handle)).state).toBe('no_account_files');
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }

    const locked = makeRootfs({ 'etc/shadow': 'root:*:0\ndaemon:!:0\n', 'etc/passwd': 'root:x:0:0:r:/:/bin/sh\n' });
    try {
      const result = await runCredMatch(locked, handle);
      expect(result.state).toBe('no_hashes');
      expect(result.findings[0]?.proofState).toBe('blocked_by_platform');
    } finally {
      fs.rmSync(locked, { recursive: true, force: true });
    }
  });

  it('reports the candidate denominator, so a miss is never a bare empty list', async () => {
    const root = makeRootfs({ 'etc/shadow': TENDA_SHADOW, 'etc/passwd': TENDA_PASSWD, 'bin/x': 'abcdef ghijkl' });
    try {
      const result = await runCredMatch(root, handle, { candidateCap: 0, targetCap: 4 });
      expect(result.candidates?.candidatesDropped).toBe(0);
      expect(result.candidates?.candidatesTested).toBeGreaterThan(0);
      expect(result.reason).toContain('not a password crack');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

// The provider must not need a store, or a test could not load it at all (vitest cannot resolve node:sqlite).
describe('module boundaries', () => {
  it('does not import the store', () => {
    const src = fs.readFileSync(new URL('./credmatch.ts', import.meta.url), 'utf8');
    expect(src).not.toContain("from '../store.js'");
  });

  it('carries no literal NUL byte, which would make grep skip the file silently', () => {
    for (const file of ['./credmatch.ts', './descrypt.ts']) {
      expect(fs.readFileSync(new URL(file, import.meta.url), 'utf8')).not.toContain('\u0000');
    }
  });
});
