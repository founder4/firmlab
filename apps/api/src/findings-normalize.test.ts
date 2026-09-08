import { describe, expect, it } from 'vitest';
import { type FindingDraft, credentialHashesFromFindings } from './findings-normalize.js';

/**
 * `credentialHashesFromFindings` is the one place a finding becomes a corpus credential occurrence, and the whole
 * point is that it reads ONLY the redaction-safe hash a provider stamped — never a raw value, never a certificate.
 * These tests pin exactly which findings feed the cross-image ledger and which must not, because the failure mode
 * is silent: a certificate wrongly counted as a credential travels into a claim about OTHER images (the same
 * over-claim the gitleaks route already paid for with dnscrypt public keys).
 */
const draft = (kind: string, evidence: Record<string, unknown>): FindingDraft => ({
  kind,
  title: kind,
  severity: 'high',
  proofState: 'static_confirmed',
  evidence,
});

describe('credentialHashesFromFindings', () => {
  it('reads a single redaction-safe secretHash (nvram value)', () => {
    const out = credentialHashesFromFindings([
      draft('nvram-credential', { key: 'passwd', secretHash: 'a'.repeat(40) }),
    ]);
    expect(out).toEqual([{ hash: 'a'.repeat(40), kind: 'nvram-credential', severity: 'high' }]);
  });

  it('expands a secretHashes array (a file holding several keys)', () => {
    const out = credentialHashesFromFindings([
      draft('embedded-private-key', { path: 'x', secretHashes: ['b'.repeat(40), 'c'.repeat(40)] }),
    ]);
    expect(out.map((o) => o.hash)).toEqual(['b'.repeat(40), 'c'.repeat(40)]);
  });

  it('takes both secretHash and secretHashes when a finding carries each', () => {
    const out = credentialHashesFromFindings([
      draft('k', { secretHash: 'a'.repeat(40), secretHashes: ['b'.repeat(40)] }),
    ]);
    expect(out.map((o) => o.hash)).toEqual(['a'.repeat(40), 'b'.repeat(40)]);
  });

  it('never reads a raw evidence.value — that path records at upload, not here', () => {
    // A `secrets` finding stores its value verbatim; feeding it here would double-record and duplicate the upload.
    expect(credentialHashesFromFindings([draft('secret', { offset: 0, value: 'hunter2' })])).toEqual([]);
  });

  it('ignores a finding with no hash at all (a certificate is PUBLIC material, never a credential)', () => {
    expect(
      credentialHashesFromFindings([draft('cert-expired', { subject: 'CN=x', issuer: 'CN=x', validTo: 'y' })]),
    ).toEqual([]);
  });

  it('drops non-string / empty hash entries defensively', () => {
    const out = credentialHashesFromFindings([
      draft('k', { secretHash: '' }),
      draft('k', { secretHashes: ['', 42 as unknown as string, 'd'.repeat(40)] }),
    ]);
    expect(out.map((o) => o.hash)).toEqual(['d'.repeat(40)]);
  });
});
