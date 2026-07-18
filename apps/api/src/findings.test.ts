import type { StringHit } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import { normalizeBinaryHardening, normalizeGitleaks, normalizeSbom, normalizeSecrets } from './findings-normalize.js';
import type { DecompileResult } from './providers/decompile.js';
import type { GitleaksResult } from './providers/gitleaks.js';
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

describe('normalizeGitleaks', () => {
  it('maps file-matched secrets to static_confirmed', () => {
    const result: GitleaksResult = {
      available: true,
      target: '/rootfs',
      findingCount: 1,
      findings: [{ rule: 'generic-api-key', description: 'API key', file: 'etc/config', line: 4, match: 'k…y' }],
    };
    const out = normalizeGitleaks(result);
    expect(out[0]?.proofState).toBe('static_confirmed');
    expect(out[0]?.severity).toBe('high');
    expect(out[0]?.evidence).toMatchObject({ file: 'etc/config', line: 4 });
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
