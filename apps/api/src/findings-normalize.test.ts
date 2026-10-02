import { type FindingDraft, parseVendorVex } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import { credentialHashesFromFindings, normalizeSbom } from './findings-normalize.js';
import type { SbomResult } from './providers/sbom.js';

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

/** Parsed OpenVEX documents, one per call, for the vendor-verdict tests. */
function vexDocs(...docs: { cve: string; products: string[]; status: string; justification?: string }[][]) {
  return {
    documents: docs.map((statements, i) => {
      const parsed = parseVendorVex(
        JSON.stringify({
          '@context': 'https://openvex.dev/ns/v0.2.0',
          '@id': `https://vendor.example/vex/${i}`,
          author: 'Vendor PSIRT',
          timestamp: '2026-01-01T00:00:00Z',
          version: 1,
          statements: statements.map((s) => ({
            vulnerability: { name: s.cve },
            products: s.products,
            status: s.status,
            ...(s.justification ? { justification: s.justification } : {}),
          })),
        }),
        `/etc/vex/${i}.openvex.json`,
      );
      if (!parsed.ok) throw new Error(parsed.reason);
      return parsed;
    }),
  };
}

/** The fields a vendor verdict must never move. */
const rung = (rows: readonly FindingDraft[]) =>
  rows.map((r) => ({ kind: r.kind, title: r.title, proofState: r.proofState, severity: r.severity }));

/**
 * Vendor VEX on grype rows, beside `curatedCveVerdict` and under its contract: a stamp on the row, never a rung,
 * never a deletion — the same rows with the same proof states and severities whatever the vendor says.
 */
describe('normalizeSbom with vendor VEX', () => {
  const sbom: SbomResult = {
    available: true,
    target: '/rootfs',
    packageCount: 2,
    packages: [],
    grypeAvailable: true,
    vulnerabilities: [
      { id: 'CVE-2011-2716', severity: 'High', packageName: 'busybox', packageVersion: '1.18.4', fixedIn: null },
      { id: 'CVE-2021-0001', severity: 'Medium', packageName: 'lighttpd', packageVersion: '1.4.35', fixedIn: null },
      { id: 'GHSA-aaaa-bbbb-cccc', severity: 'Low', packageName: 'busybox', packageVersion: '1.18.4', fixedIn: null },
    ],
    counts: { Critical: 0, High: 1, Medium: 1, Low: 1, Negligible: 0, Unknown: 0 },
  } as SbomResult;

  it('never changes rows, proof states or severities, with a fixed or not_affected statement present', () => {
    const without = normalizeSbom(sbom);
    for (const status of ['fixed', 'not_affected']) {
      const vex = vexDocs([
        { cve: 'CVE-2011-2716', products: ['pkg:apk/alpine/busybox@1.18.4'], status },
        { cve: 'CVE-2021-0001', products: ['lighttpd'], status },
      ]);
      const rows = normalizeSbom(sbom, undefined, vex);
      expect(rows).toHaveLength(without.length);
      expect(rung(rows)).toEqual(rung(without));
      expect(rows.every((r) => r.proofState === 'needs_runtime_reproduction')).toBe(true);
    }
  });

  it('sits beside the curated verdict without replacing it', () => {
    const vex = vexDocs([{ cve: 'CVE-2011-2716', products: ['busybox'], status: 'fixed' }]);
    const [row] = normalizeSbom(sbom, undefined, vex);
    const ev = row?.evidence as { curatedVerdict?: string; vendorVex?: { verdict?: string; basis?: string } };
    expect(ev.curatedVerdict).toBe(normalizeSbom(sbom)[0]?.evidence?.curatedVerdict as string);
    expect(ev.curatedVerdict).toBeDefined();
    expect(ev.vendorVex).toMatchObject({ verdict: 'vendor_states_fixed', basis: 'vendor_assertion' });
  });

  it('attaches nothing when the vendor is silent, names another package, or the row is not a CVE id', () => {
    const without = normalizeSbom(sbom);
    const vex = vexDocs([
      { cve: 'CVE-2011-2716', products: ['busybox-extras', 'pkg:apk/alpine/busybox@1.35'], status: 'fixed' },
      { cve: 'GHSA-aaaa-bbbb-cccc', products: ['busybox'], status: 'fixed' },
    ]);
    expect(normalizeSbom(sbom, undefined, vex)).toEqual(without);
    expect(normalizeSbom(sbom, undefined, { documents: [] })).toEqual(without);
  });

  it('conflicting vendor statements are carried as conflicting, nothing more', () => {
    const vex = vexDocs(
      [{ cve: 'CVE-2021-0001', products: ['lighttpd'], status: 'not_affected' }],
      [{ cve: 'CVE-2021-0001', products: ['lighttpd'], status: 'affected' }],
    );
    const rows = normalizeSbom(sbom, undefined, vex);
    expect(rung(rows)).toEqual(rung(normalizeSbom(sbom)));
    expect((rows[1]?.evidence as { vendorVex?: { verdict?: string } }).vendorVex?.verdict).toBe('conflicting');
  });
});
