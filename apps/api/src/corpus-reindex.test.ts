import { describe, expect, it } from 'vitest';
import {
  type ReindexFindingRow,
  type ReindexImageInput,
  type ReindexImagePlan,
  planCredentialHashes,
  planGitleaksCredentials,
  planImageReindex,
  planStaticCredentials,
  summarizeReindex,
} from './corpus-reindex.js';
import type { GitleaksResult } from './providers/gitleaks.js';
import type { SbomResult } from './providers/sbom.js';

const analysis = (secrets: { value: string; secretKind?: string; severity?: string }[], scan?: unknown) =>
  ({
    secrets: secrets.map((s, i) => ({ offset: i, value: s.value, secretKind: s.secretKind, severity: s.severity })),
    ...(scan ? { secretScan: scan } : {}),
  }) as never;

const finding = (over: Partial<ReindexFindingRow>): ReindexFindingRow => ({
  source: 'fsaudit',
  kind: 'credential',
  severity: 'high',
  proofState: 'static_confirmed',
  evidenceJson: null,
  ...over,
});

const emptyInput = (over: Partial<ReindexImageInput>): ReindexImageInput => ({
  imageId: 'img1',
  filename: 'fw.bin',
  analysis: null,
  gitleaks: null,
  sbom: null,
  findings: [],
  binaries: [],
  ...over,
});

describe('planStaticCredentials', () => {
  it('takes only the hits the classifier called a secret', () => {
    const rows = planStaticCredentials(
      analysis([{ value: 'admin123', secretKind: 'password', severity: 'high' }, { value: 'just a string' }]),
    );
    expect(rows).toEqual([{ value: 'admin123', kind: 'password', severity: 'high' }]);
  });

  it('contributes nothing for an image whose analysis never landed', () => {
    expect(planStaticCredentials(null)).toEqual([]);
  });
});

describe('planGitleaksCredentials', () => {
  const hit = (over: Record<string, unknown>) =>
    ({
      rule: 'generic-api-key',
      description: 'Generic API Key',
      file: 'etc/x.conf',
      line: 1,
      match: 'S3CR3T',
      ...over,
    }) as never;

  it('classifies with the same function the ledger row gets, not a hardcoded severity', () => {
    // A self-identifying rule is high; the dnscrypt public keys the route comment warns about are not, and the
    // point of routing through the classifier is that a reindex cannot disagree with the ledger about which.
    const result = {
      available: true,
      target: 'rootfs',
      findingCount: 1,
      findings: [hit({ rule: 'private-key', description: 'Private Key' })],
    } as unknown as GitleaksResult;
    expect(planGitleaksCredentials(result)).toEqual([{ value: 'S3CR3T', kind: 'private-key', severity: 'high' }]);
  });

  it('keys the corpus on the exact local value when a new result carries it', () => {
    const result = {
      available: true,
      target: 'rootfs',
      findingCount: 1,
      findings: [hit({ value: 'complete-token-value', match: 'comple…alue (20 chars)' })],
    } as unknown as GitleaksResult;
    expect(planGitleaksCredentials(result)[0]?.value).toBe('complete-token-value');
  });

  it('contributes nothing when gitleaks was unavailable', () => {
    expect(planGitleaksCredentials({ available: false, target: '', findingCount: 0, findings: [] })).toEqual([]);
    expect(planGitleaksCredentials(null)).toEqual([]);
  });
});

describe('planCredentialHashes', () => {
  it('collects both the single hash and the key-material list', () => {
    const rows = planCredentialHashes([
      finding({ evidenceJson: JSON.stringify({ secretHash: 'aaa' }) }),
      finding({ source: 'nvram', kind: 'secret', evidenceJson: JSON.stringify({ secretHashes: ['bbb', 'ccc'] }) }),
    ]);
    expect(rows.map((r) => r.hash)).toEqual(['aaa', 'bbb', 'ccc']);
  });

  it('never lets an operator assertion into the corpus', () => {
    // Both tests independently, because either alone has a way to be absent on a row written by an older build.
    const rows = planCredentialHashes([
      finding({ source: 'operator:alice', evidenceJson: JSON.stringify({ secretHash: 'from-source-prefix' }) }),
      finding({ proofState: 'operator_assertion', evidenceJson: JSON.stringify({ secretHash: 'from-proof-state' }) }),
      finding({ evidenceJson: JSON.stringify({ secretHash: 'computed' }) }),
    ]);
    expect(rows.map((r) => r.hash)).toEqual(['computed']);
  });

  it('drops a row whose evidence does not parse rather than failing the image', () => {
    const rows = planCredentialHashes([
      finding({ evidenceJson: '{not json' }),
      finding({ evidenceJson: JSON.stringify({ secretHash: 'ok' }) }),
    ]);
    expect(rows.map((r) => r.hash)).toEqual(['ok']);
  });
});

describe('planImageReindex', () => {
  it('separates "the provider never ran" from "it ran and found nothing"', () => {
    const neverRan = planImageReindex(emptyInput({}));
    expect(neverRan.inputs.gitleaks).toBe(false);
    expect(neverRan.inputs.components).toBe(false);

    const ranClean = planImageReindex(
      emptyInput({
        gitleaks: { available: true, target: 'rootfs', findingCount: 0, findings: [] },
        sbom: { available: true, packages: [], vulnerabilities: [] } as unknown as SbomResult,
      }),
    );
    expect(ranClean.inputs.gitleaks).toBe(true);
    expect(ranClean.inputs.components).toBe(true);
    expect(ranClean.gitleaksCredentials).toEqual([]);
    expect(ranClean.components).toEqual([]);
  });

  it('reports a static scan that stopped short, and stays silent when the file was read whole', () => {
    // The raw values in `secretScan.secrets` must NOT come along: this object is returned over HTTP.
    const bounded = planImageReindex(
      emptyInput({
        analysis: analysis([], {
          secrets: [{ value: 'admin123' }],
          matched: 1,
          scannedBytes: 11_000,
          totalBytes: 100_000,
        }),
      }),
    );
    expect(bounded.boundedInputs).toEqual([{ kind: 'static-scan', covered: 11_000, total: 100_000 }]);

    const whole = planImageReindex(
      emptyInput({ analysis: analysis([], { secrets: [], matched: 0, scannedBytes: 100_000, totalBytes: 100_000 }) }),
    );
    expect(whole.boundedInputs).toEqual([]);
    expect(whole.unrecordedBounds).toEqual([]);
  });

  it('separates a bound that is recorded from one that predates the field', () => {
    // Measured on the deployed bench: 7 of the 8 stored SBOMs predate `packageTotal`, and the one that has it
    // holds 500 of the 2019 packages syft catalogued. Both must read differently from "covered everything".
    const unrecorded = planImageReindex(
      emptyInput({
        analysis: analysis([{ value: 'x', secretKind: 'password' }]),
        sbom: { available: true, packages: [{ name: 'curl', version: '8.6.0' }], vulnerabilities: [] } as never,
      }),
    );
    expect(unrecorded.boundedInputs).toEqual([]);
    expect(unrecorded.unrecordedBounds).toEqual(['static-scan', 'sbom-packages']);

    const cappedSbom = planImageReindex(
      emptyInput({
        sbom: {
          available: true,
          packages: [{ name: 'curl', version: '8.6.0' }],
          packageTotal: 2019,
          vulnerabilities: [],
        } as never,
      }),
    );
    expect(cappedSbom.boundedInputs).toEqual([{ kind: 'sbom-packages', covered: 1, total: 2019 }]);
  });

  it('counts credential-bearing rows without identity, not unrelated posture from the same providers', () => {
    const plan = planImageReindex(
      emptyInput({
        findings: [
          finding({ source: 'fsaudit', kind: 'embedded-private-key', evidenceJson: JSON.stringify({ path: 'key' }) }),
          finding({ source: 'nvram', kind: 'nvram-credential', evidenceJson: JSON.stringify({ secretHash: 'aaa' }) }),
          finding({ source: 'auxsecrets:etc/keys', kind: 'embedded-private-key', evidenceJson: null }),
          // Same providers, but these rows describe posture or a filename heuristic — no reusable credential.
          finding({ source: 'fsaudit', kind: 'weak-password-hash', evidenceJson: null }),
          finding({ source: 'fsaudit', kind: 'notable-private-key', evidenceJson: null }),
          finding({ source: 'nvram', kind: 'nvram-boot-interruptible', evidenceJson: null }),
          // Not a stamping source: a missing hash here says nothing about when it was written.
          finding({ source: 'sbom', evidenceJson: null }),
          // An operator row is never counted towards a gap in code-authored measurement.
          finding({ source: 'operator:alice', evidenceJson: null }),
        ],
      }),
    );
    expect(plan.unstampedCredentialRows).toBe(2);
  });

  it('counts rows the corpus can hold, not calls to insert', () => {
    // The corpus key is (name, version, imageId), so a package listed twice is ONE row. Reporting the call count
    // as "offered" would invite reading 500 offered / 0 inserted as "the corpus holds 500 of these".
    const plan = planImageReindex(
      emptyInput({
        sbom: {
          available: true,
          packageTotal: 2,
          packages: [
            { name: 'curl', version: '8.6.0' },
            { name: 'curl', version: '8.6.0' },
          ],
          vulnerabilities: [],
        } as never,
        binaries: [
          { path: 'bin/sh', sha1: 'aa', arch: 'mips' },
          { path: 'bin/sh', sha1: 'aa', arch: 'mips' },
        ],
      }),
    );
    expect(plan.components).toHaveLength(1);
    expect(plan.artifacts).toHaveLength(1);
  });

  it('skips a binary with no hash and keeps its architecture otherwise', () => {
    const plan = planImageReindex(
      emptyInput({
        binaries: [
          { path: 'bin/busybox', sha1: 'abc', arch: 'mips' },
          { path: 'bin/unhashed', sha1: null, arch: 'mips' },
        ],
      }),
    );
    expect(plan.artifacts).toEqual([{ sha1: 'abc', path: 'bin/busybox', arch: 'mips' }]);
    expect(plan.inputs.artifacts).toBe(true);
  });

  it('pairs each component with the CVEs grype matched to that exact version', () => {
    const plan = planImageReindex(
      emptyInput({
        sbom: {
          available: true,
          packages: [
            { name: 'curl', version: '8.6.0' },
            { name: 'zlib', version: '1.2.11' },
          ],
          vulnerabilities: [
            { packageName: 'curl', packageVersion: '8.6.0' },
            { packageName: 'curl', packageVersion: '8.6.0' },
            { packageName: 'curl', packageVersion: '7.0.0' },
          ],
        } as unknown as SbomResult,
      }),
    );
    expect(plan.components).toEqual([
      { name: 'curl', version: '8.6.0', cveCount: 2 },
      { name: 'zlib', version: '1.2.11', cveCount: 0 },
    ]);
  });
});

describe('summarizeReindex', () => {
  const text = {
    verdict: (p: { imageCount: number; inserted: number; offered: number }) =>
      `${p.imageCount}/${p.inserted}/${p.offered}`,
    boundedNote: (p: { count: number }) => `bounded:${p.count}`,
    unrecordedNote: (p: { count: number }) => `unrecorded:${p.count}`,
    unstampedNote: (p: { rows: number; imageCount: number }) => `unstamped:${p.rows}/${p.imageCount}`,
  };
  const plan = (over: Partial<ReindexImagePlan>): ReindexImagePlan => ({
    imageId: 'i',
    filename: 'f',
    staticCredentials: [],
    gitleaksCredentials: [],
    credentialHashes: [],
    components: [],
    artifacts: [],
    inputs: {
      'static-secrets': false,
      gitleaks: false,
      'credential-hashes': false,
      components: false,
      artifacts: false,
    },
    boundedInputs: [],
    unrecordedBounds: [],
    unstampedCredentialRows: 0,
    ...over,
  });

  it('counts images with and without input per source, and totals the offered rows', () => {
    const report = summarizeReindex(
      [
        plan({
          inputs: {
            'static-secrets': true,
            gitleaks: false,
            'credential-hashes': false,
            components: false,
            artifacts: false,
          },
          staticCredentials: [{ value: 'a', kind: null, severity: null }],
        }),
        plan({}),
      ],
      { 'static-secrets': 1, gitleaks: 0, 'credential-hashes': 0, components: 0, artifacts: 0 },
      text,
      [],
    );
    const statics = report.sources.find((s) => s.source === 'static-secrets');
    expect(statics).toEqual({
      source: 'static-secrets',
      imagesWithInput: 1,
      imagesWithoutInput: 1,
      rowsOffered: 1,
      rowsInserted: 1,
    });
    expect(report.verdict).toBe('2/1/1');
  });

  it('appends each note only when it applies, so a caveat printed every time cannot stop being read', () => {
    const zeros = { 'static-secrets': 0, gitleaks: 0, 'credential-hashes': 0, components: 0, artifacts: 0 };
    expect(summarizeReindex([plan({})], zeros, text, []).verdict).toBe('1/0/0');

    const bounded = summarizeReindex(
      [plan({ boundedInputs: [{ kind: 'static-scan', covered: 1, total: 2 }] })],
      zeros,
      text,
      [],
    );
    expect(bounded.verdict).toBe('1/0/0 bounded:1');
    expect(bounded.boundedInputs).toEqual([{ imageId: 'i', filename: 'f', kind: 'static-scan', covered: 1, total: 2 }]);

    const unrecorded = summarizeReindex(
      [plan({ unrecordedBounds: ['static-scan'] }), plan({ unrecordedBounds: ['static-scan', 'sbom-packages'] })],
      zeros,
      text,
      [],
    );
    expect(unrecorded.verdict).toBe('2/0/0 unrecorded:3');
    expect(unrecorded.unrecordedBounds).toEqual([
      { kind: 'static-scan', imageCount: 2 },
      { kind: 'sbom-packages', imageCount: 1 },
    ]);
  });

  it('names a ledger written before the stamping, so "0 offered" cannot read as "no key material"', () => {
    const zeros = { 'static-secrets': 0, gitleaks: 0, 'credential-hashes': 0, components: 0, artifacts: 0 };
    const report = summarizeReindex([plan({ unstampedCredentialRows: 22 }), plan({})], zeros, text, []);
    expect(report.unstampedCredentials).toEqual([{ imageId: 'i', filename: 'f', rows: 22 }]);
    expect(report.verdict).toBe('2/0/0 unstamped:22/1');
  });

  it('carries the tables it cannot rebuild, so their emptiness is not read as a measurement', () => {
    const report = summarizeReindex(
      [],
      { 'static-secrets': 0, gitleaks: 0, 'credential-hashes': 0, components: 0, artifacts: 0 },
      text,
      [{ table: 'reachability_prior', reason: 'only a live confirmation writes one' }],
    );
    expect(report.notReconciled.map((t) => t.table)).toEqual(['reachability_prior']);
  });
});
