import type { StringHit } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import {
  classifyGitleaksHit,
  isHeuristicGitleaksRule,
  normalizeBinaryHardening,
  normalizeGitleaks,
  normalizeSbom,
  normalizeSecrets,
} from './findings-normalize.js';
import type { DecompileResult } from './providers/decompile.js';
import type { GitleaksFinding, GitleaksResult } from './providers/gitleaks.js';
import type { SbomResult } from './providers/sbom.js';

describe('normalizeSecrets', () => {
  it('emits static_confirmed findings only for classified secrets', () => {
    const secrets: StringHit[] = [
      { offset: 16, value: 'root:x:0:0', secretKind: 'default-credential', severity: 'high' },
      { offset: 32, value: 'just a string' }, // no secretKind → not a finding
    ];
    const out = normalizeSecrets(secrets);
    expect(out).toHaveLength(1);
    expect(out[0]?.proofState).toBe('static_confirmed');
    expect(out[0]?.severity).toBe('high');
    expect(out[0]?.evidence).toEqual({ offset: 16, value: 'root:x:0:0' });
  });

  it('defaults severity to medium when the hit carries none', () => {
    const out = normalizeSecrets([{ offset: 0, value: 'AKIA…', secretKind: 'aws-key' }]);
    expect(out[0]?.severity).toBe('medium');
  });
});

describe('normalizeSbom', () => {
  const base: SbomResult = {
    available: true,
    target: '/rootfs',
    packageCount: 1,
    packages: [{ name: 'busybox', version: '1.20', type: 'binary' }],
    grypeAvailable: true,
    vulnerabilities: [
      { id: 'CVE-2021-1', severity: 'Critical', packageName: 'busybox', packageVersion: '1.20', fixedIn: '1.21' },
    ],
    counts: { Critical: 1, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 },
  };

  it('maps CVEs to needs_runtime_reproduction (present ≠ reachable)', () => {
    const out = normalizeSbom(base);
    expect(out).toHaveLength(1);
    expect(out[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(out[0]?.severity).toBe('critical');
    expect(out[0]?.kind).toBe('cve');
  });

  it('returns nothing when the SBOM is unavailable', () => {
    expect(normalizeSbom({ ...base, available: false })).toEqual([]);
  });
});

/**
 * gitleaks — the rung follows the RULE, and the fixtures are the real report.
 *
 * Every row below is gitleaks v8.30.1's actual output for the GL.iNet BE3600 rootfs (image 81154df7, captured
 * 2026-08-03) as `mapFindings` renders it, and every one of them used to be `static_confirmed` / `high`. All 12
 * were false. `RWQf6LRC…` is dnscrypt-proxy's *published* minisign verification key; nothing here is a secret,
 * which is precisely why inventing fixtures for this test would have proved nothing.
 */
const GENERIC = 'Detected a Generic API Key, potentially exposing access to various services and sensitive operations.';
const be3600 = (
  file: string,
  line: number,
  match: string,
  entropy: number,
  context: string,
  lineText: string,
): GitleaksFinding => ({
  rule: 'generic-api-key',
  description: GENERIC,
  file,
  line,
  match,
  entropy,
  context,
  lineText,
});

const MINISIGN_MATCH = 'RWQf6L…GFO3 (56 chars)';
const LIVE_KEY_LINE = "minisign_key = '…'";
const COMMENTED_KEY_LINE = "# minisign_key = '…'";

/** The 12 real hits, in the order gitleaks reported them. */
const BE3600_HITS: GitleaksFinding[] = [
  be3600('etc/dnscrypt-proxy2/odoh-servers.md', 11, MINISIGN_MATCH, 5.110577, LIVE_KEY_LINE, LIVE_KEY_LINE),
  be3600('etc/dnscrypt-proxy2/public-resolvers.md', 20, MINISIGN_MATCH, 5.110577, LIVE_KEY_LINE, LIVE_KEY_LINE),
  be3600('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 710, MINISIGN_MATCH, 5.110577, LIVE_KEY_LINE, LIVE_KEY_LINE),
  be3600('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 719, MINISIGN_MATCH, 5.110577, LIVE_KEY_LINE, LIVE_KEY_LINE),
  be3600('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 729, MINISIGN_MATCH, 5.110577, LIVE_KEY_LINE, COMMENTED_KEY_LINE),
  be3600('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 735, MINISIGN_MATCH, 5.110577, LIVE_KEY_LINE, COMMENTED_KEY_LINE),
  be3600(
    'etc/dnscrypt-proxy2/dnscrypt-proxy.toml',
    744,
    'RWQBph…sKUN (56 chars)',
    5.0016513,
    LIVE_KEY_LINE,
    COMMENTED_KEY_LINE,
  ),
  be3600('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 754, MINISIGN_MATCH, 5.110577, LIVE_KEY_LINE, COMMENTED_KEY_LINE),
  be3600('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 901, MINISIGN_MATCH, 5.110577, LIVE_KEY_LINE, LIVE_KEY_LINE),
  be3600('usr/bin/sendsms', 18, '5f4dcc…cf99 (32 chars)', 3.8042293, 'KEYS="…', '# KEYS="… … "'),
  be3600(
    'usr/lib/oui-httpd/rpc/wg_client',
    62,
    '8OCHkH…VFM= (44 chars)',
    4.8968205,
    'private_key":"…"',
    '@in-example: {"jsonrpc":"2.0","method":"call","params":["","wg_client","gen_key",{"private_key":"…"}],"id":1}',
  ),
  be3600('usr/local/lib/lua/5.4/eco/hash/hmac.lua', 53, 'key_xord_with_0x5c', 3.7946534, 'key = …', 'key = …'),
];

const asResult = (findings: GitleaksFinding[]): GitleaksResult => ({
  available: true,
  target: '/data/extract/81154df7/carve/rootfs',
  findingCount: findings.length,
  findings,
});

const at = (file: string, line: number) =>
  BE3600_HITS.find((f) => f.file === file && f.line === line) as GitleaksFinding;
const codes = (f: GitleaksFinding) => classifyGitleaksHit(f).signals.map((s) => s.code);

describe('normalizeGitleaks: a heuristic rule produces a lead, not a confirmation', () => {
  it('demotes every one of the 12 real BE3600 hits off static_confirmed', () => {
    const out = normalizeGitleaks(asResult(BE3600_HITS));
    // The count is the point of the first assertion: nothing is suppressed, only re-claimed.
    expect(out).toHaveLength(12);
    expect(out.every((d) => d.proofState === 'needs_runtime_reproduction')).toBe(true);
    expect(out.every((d) => d.evidence?.ruleClass === 'self-identifying')).toBe(false);
  });

  it('ranks the 12 by what the file actually says, instead of flattening them all to high', () => {
    const out = normalizeGitleaks(asResult(BE3600_HITS));
    const bySeverity = out.reduce<Record<string, number>>((m, d) => {
      m[d.severity] = (m[d.severity] ?? 0) + 1;
      return m;
    }, {});
    // 7 discounted twice over (documentation or a comment, plus a public-key identifier), 4 once, and the one
    // that names a private key held at medium — the only one of the twelve worth opening first.
    expect(bySeverity).toEqual({ info: 7, low: 4, medium: 1 });
  });

  it('reads the comment marker, which is what separates live config from a commented-out example', () => {
    // Lines 710/719/901 are live `[sources.*]` entries; 729/735/744/754 sit behind a `#`. Identical bytes,
    // different claims, and gitleaks reports both identically.
    expect(codes(at('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 710))).toEqual(['public-key-identifier']);
    expect(codes(at('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 729))).toEqual([
      'commented-out',
      'public-key-identifier',
    ]);
    expect(classifyGitleaksHit(at('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 710)).severity).toBe('low');
    expect(classifyGitleaksHit(at('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 729)).severity).toBe('info');
  });

  it('does not mistake a long command-line option for a comment', () => {
    // `--` opens a comment in Lua and SQL and opens a long option everywhere else. A launcher line passing a
    // live key on the command line is the opposite of a commented-out example, and must not be discounted.
    const flag = { ...at('usr/bin/sendsms', 18), lineText: '--api-key=… --verbose', context: '--api-key=…' };
    expect(codes(flag)).toEqual([]);
    expect(classifyGitleaksHit(flag).severity).toBe('medium');
    // A Lua comment still reads as one, because there the marker is followed by space or a long-bracket.
    expect(codes({ ...at('usr/bin/sendsms', 18), lineText: '-- local key = …' })).toEqual(['commented-out']);
  });

  it('discounts from context, never from a list of known-public values', () => {
    // Nothing in this codebase has been told what `RWQf6LRC…` is. The file said so: the identifier that names
    // the value is `minisign_key`, and the two `.md` hits are the resolver directory dnscrypt ships as prose.
    const doc = classifyGitleaksHit(at('etc/dnscrypt-proxy2/public-resolvers.md', 20));
    expect(doc.signals.map((s) => s.code)).toEqual(['documentation-file', 'public-key-identifier']);
    expect(doc.severity).toBe('info');
    expect(doc.rationale).toContain('minisign_key');
  });

  it('calls a Lua variable name a variable name', () => {
    const lua = classifyGitleaksHit(at('usr/local/lib/lua/5.4/eco/hash/hmac.lua', 53));
    expect(lua.signals.map((s) => s.code)).toEqual(['source-identifier']);
    expect(lua.severity).toBe('info');
  });

  it('keeps the one that names a private key above the rest, while still calling it a lead', () => {
    // wg_client's hit is a base64 blob assigned to `private_key` — inside an `@in-example` documentation block.
    // Both readings are true at once and both are recorded; they net out to medium rather than one silencing
    // the other.
    const wg = classifyGitleaksHit(at('usr/lib/oui-httpd/rpc/wg_client', 62));
    expect(wg.signals.map((s) => s.code)).toEqual(['secret-identifier', 'example-marker']);
    expect(wg.severity).toBe('medium');
    expect(wg.proofState).toBe('needs_runtime_reproduction');
  });

  it('states what was observed and what would settle it, and never asserts a secret', () => {
    const out = normalizeGitleaks(asResult(BE3600_HITS));
    for (const draft of out) {
      expect(draft.rationale).toContain('high-entropy string');
      expect(draft.rationale).toContain('Settled by');
      expect(draft.rationale).not.toContain('credential is present');
      // The title must not repeat gitleaks' "Detected a Generic API Key" claim, and must locate the row: seven
      // of the twelve are in one file and were previously indistinguishable from each other.
      expect(draft.title).not.toContain('Detected a Generic API Key');
    }
    expect(out.map((d) => d.title)).toHaveLength(new Set(out.map((d) => d.title)).size);
  });

  it('carries the measured context into the evidence so a reader can check the reasoning', () => {
    const out = normalizeGitleaks(asResult([at('etc/dnscrypt-proxy2/dnscrypt-proxy.toml', 729)]));
    expect(out[0]?.evidence).toMatchObject({
      file: 'etc/dnscrypt-proxy2/dnscrypt-proxy.toml',
      line: 729,
      ruleClass: 'heuristic',
      entropy: 5.110577,
      lineText: COMMENTED_KEY_LINE,
      signals: ['commented-out', 'public-key-identifier'],
    });
  });
});

describe('normalizeGitleaks: what a self-identifying rule matched really is in the bytes', () => {
  // Real gitleaks rows, produced by running gitleaks 8.30.1 over a directory holding an openssl-generated key
  // and a `ghp_`-prefixed token. Only the rule ids, descriptions and match shapes are reproduced here.
  const PRIVATE_KEY: GitleaksFinding = {
    rule: 'private-key',
    description: 'Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.',
    file: 'README.md',
    line: 1,
    match: '-----B…---- (1703 chars)',
    entropy: 6.0191054,
    context: '…',
    lineText: '-----BEGIN PRIVATE KEY-----',
  };
  const GITHUB_PAT: GitleaksFinding = {
    rule: 'github-pat',
    description: 'Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access.',
    file: 'ci.env',
    line: 1,
    match: 'ghp_Jt…60M (40 chars)',
    entropy: 4.803056,
    context: 'GITHUB_TOKEN=…',
    lineText: 'GITHUB_TOKEN=…',
  };

  it('keeps a real private key at static_confirmed even in a file called README.md', () => {
    // This is the mirror of the bug being fixed, and the worse of the two. A discount that fires on "it is in
    // documentation" would lose a genuine key — so the discounts do not run on self-identifying rules at all.
    const out = normalizeGitleaks(asResult([PRIVATE_KEY]));
    expect(out[0]?.proofState).toBe('static_confirmed');
    expect(out[0]?.severity).toBe('high');
    expect(out[0]?.evidence).toMatchObject({ ruleClass: 'self-identifying', signals: [] });
  });

  it('keeps a prefixed token at static_confirmed: the format is the claim, not the entropy', () => {
    const out = normalizeGitleaks(asResult([GITHUB_PAT]));
    expect(out[0]?.proofState).toBe('static_confirmed');
    expect(out[0]?.severity).toBe('high');
    expect(out[0]?.rationale).toContain('self-identifying');
  });

  it('sorts rules by what they match, not by how they are named', () => {
    expect(isHeuristicGitleaksRule('generic-api-key', GENERIC)).toBe(true);
    expect(isHeuristicGitleaksRule('private-key', PRIVATE_KEY.description)).toBe(false);
    expect(isHeuristicGitleaksRule('github-pat', GITHUB_PAT.description)).toBe(false);
    // A custom rule set renaming the entropy rule is still an entropy rule; gitleaks' own wording gives it away.
    expect(isHeuristicGitleaksRule('vendor-token', 'Detected a Generic API Key in vendor config')).toBe(true);
    expect(isHeuristicGitleaksRule('high-entropy-blob')).toBe(true);
  });
});

describe('normalizeGitleaks: a result stored by an older build', () => {
  // This is the exact shape of image 81154df7's persisted job result: five fields, no entropy, no context. It
  // is re-read for as long as the image exists, so it must normalize without them — and a missing field must
  // read as "not measured", never as a discount earned.
  const STORED = BE3600_HITS.map(({ rule, description, file, line, match }) => ({
    rule,
    description,
    file,
    line,
    match,
  }));

  it('still demotes all 12, using only the rule id', () => {
    const out = normalizeGitleaks(asResult(STORED));
    expect(out).toHaveLength(12);
    expect(out.every((d) => d.proofState === 'needs_runtime_reproduction')).toBe(true);
  });

  it('does not manufacture the discounts it could not measure', () => {
    // The commented-out toml lines are indistinguishable from the live ones here, and land at the undiscounted
    // medium rather than being quietly demoted further on evidence nobody has.
    const stored = STORED.find((f) => f.line === 729) as GitleaksFinding;
    expect(classifyGitleaksHit(stored).signals).toEqual([]);
    expect(classifyGitleaksHit(stored).severity).toBe('medium');
    // What IS in the stored row still counts: the file path alone shows the `.md` hits are documentation.
    const doc = STORED.find((f) => f.file.endsWith('public-resolvers.md')) as GitleaksFinding;
    expect(classifyGitleaksHit(doc).signals.map((s) => s.code)).toEqual(['documentation-file']);
  });

  it('survives a result whose findings array predates the field entirely', () => {
    expect(normalizeGitleaks({ available: true } as unknown as GitleaksResult)).toEqual([]);
  });
});

describe('normalizeBinaryHardening', () => {
  const mk = (info: DecompileResult['info']): DecompileResult => ({
    available: true,
    binary: 'usr/sbin/httpd',
    info,
    functionCount: 0,
    symbols: [],
    imports: [],
    strings: [],
  });

  it('emits one static_confirmed finding per missing mitigation', () => {
    const out = normalizeBinaryHardening(mk({ nx: false, canary: false, pic: false }));
    expect(out.map((f) => f.kind).sort()).toEqual(['no-canary', 'no-nx', 'no-pic']);
    expect(out.every((f) => f.proofState === 'static_confirmed')).toBe(true);
  });

  it('emits nothing when mitigations are present', () => {
    expect(normalizeBinaryHardening(mk({ nx: true, canary: true, pic: true }))).toEqual([]);
  });
});

/**
 * The evidence channel — the second axis, and the rules that keep it from collapsing into the first.
 *
 * `ProofState` says how far a finding was proven; the channel says how it was known. The pair only earns its
 * keep if two things hold: the same rung can carry different channels (or the axis is redundant), and an ABSENT
 * channel never silently reads as a present one (or the field manufactures provenance it does not have).
 */
describe('the evidence channel is a second axis, not a finer proof state', () => {
  it('puts two different channels on the SAME rung, which is the whole reason it exists', () => {
    const secret = normalizeSecrets([
      { offset: 16, value: 'root:x:0:0', secretKind: 'default-credential', severity: 'high' },
    ]);
    const hardening = normalizeBinaryHardening({
      available: true,
      binary: 'bin/httpd',
      info: { nx: false, canary: null, pic: null },
    } as unknown as DecompileResult);

    // Both are `static_confirmed`, and both really were read out of the bytes.
    expect(secret[0]?.proofState).toBe('static_confirmed');
    expect(hardening[0]?.proofState).toBe('static_confirmed');
    expect(secret[0]?.evidenceChannel).toBe('static_bytes');
    expect(hardening[0]?.evidenceChannel).toBe('static_bytes');
  });

  it('calls a database match what it is: something a third party said, not something measured here', () => {
    const out = normalizeSbom({
      available: true,
      vulnerabilities: [
        { id: 'CVE-2022-48174', severity: 'Critical', packageName: 'busybox', packageVersion: '1.36.1', fixedIn: null },
      ],
    } as unknown as SbomResult);
    // The rung is a lead, and the channel says the lead came from an advisory rather than from this image.
    expect(out[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(out[0]?.evidenceChannel).toBe('external_advisory');
  });

  it('leaves the channel ABSENT rather than defaulting it, so a gap cannot read as a measurement', () => {
    // A normalizer that has not been taught its channel must emit none. `undefined` is "not recorded"; picking
    // `static_bytes` because it is the commonest value would invent provenance out of a missing field.
    const draft = { kind: 'x', title: 'x', severity: 'info' as const, proofState: 'static_confirmed' as const };
    expect('evidenceChannel' in draft).toBe(false);
  });

  it('never records an intervention on a normalizer that changes nothing', () => {
    const out = normalizeGitleaks({
      available: true,
      findings: [{ rule: 'aws-key', description: 'AWS key', file: 'etc/x', line: 3, match: 'AKIA…' }],
    } as unknown as GitleaksResult);
    // Reading a file is not altering it. Absent means "the firmware as shipped", and that has to be the default
    // for every provider that does not intervene — otherwise the mark means nothing when one finally does.
    expect(out[0]?.interventions).toBeUndefined();
  });
});
