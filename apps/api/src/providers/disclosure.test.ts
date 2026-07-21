import type { Finding } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import { type DisclosureContext, buildDisclosureReport } from './disclosure.js';

function finding(over: Partial<Finding>): Finding {
  return {
    id: over.id ?? 'f1',
    imageId: 'img1',
    source: over.source ?? 'secrets',
    kind: over.kind ?? 'hardcoded-credential',
    title: over.title ?? 'Hardcoded root password in /etc/shadow',
    severity: over.severity ?? 'high',
    proofState: over.proofState ?? 'static_confirmed',
    createdAt: 0,
    ...(over.evidence ? { evidence: over.evidence } : {}),
    ...(over.rationale ? { rationale: over.rationale } : {}),
  };
}

const base: DisclosureContext = {
  image: { filename: 'router.bin', sha256: 'abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef567890' },
  identity: { firmwareClass: 'embedded-linux', arch: 'mipsel', endianness: 'little', filesystems: ['squashfs'] },
  provenance: { vendors: ['acme-networks'], models: ['AC1200'], versions: ['1.2.3'] },
  securityContacts: [{ domain: 'acme.com', checked: true, found: true, contact: ['mailto:security@acme.com'] }],
  generatedAt: '2026-07-21T00:00:00.000Z',
  findings: [],
};

describe('buildDisclosureReport', () => {
  it('is a defensive DRAFT, never auto-sent, and carries image identity', () => {
    const md = buildDisclosureReport(base);
    expect(md).toMatch(/DRAFT/);
    expect(md).toMatch(/FirmLab does not contact anyone/);
    expect(md).toContain('router.bin');
    expect(md).toContain('acme-networks / AC1200');
    expect(md).toContain('mailto:security@acme.com');
  });

  it('separates confirmed issues from unverified leads and never reports leads as confirmed', () => {
    const md = buildDisclosureReport({
      ...base,
      findings: [
        finding({ id: 'a', title: 'Confirmed hardcoded key', proofState: 'static_confirmed', severity: 'critical' }),
        finding({
          id: 'b',
          title: 'Possible command injection',
          proofState: 'needs_runtime_reproduction',
          severity: 'high',
        }),
      ],
    });
    expect(md).toMatch(/## Confirmed issues \(1\)/);
    expect(md).toMatch(/## Unverified leads \(1\) — reachability unverified/);
    // The lead appears only under the leads section, after the confirmed section.
    expect(md.indexOf('Confirmed hardcoded key')).toBeLessThan(md.indexOf('Possible command injection'));
    expect(md).toMatch(/not confirmed/i);
  });

  it('orders confirmed findings by severity (critical first)', () => {
    const md = buildDisclosureReport({
      ...base,
      findings: [
        finding({ id: 'lo', title: 'Low sev issue', severity: 'low', proofState: 'static_confirmed' }),
        finding({ id: 'hi', title: 'Critical sev issue', severity: 'critical', proofState: 'static_confirmed' }),
      ],
    });
    expect(md.indexOf('Critical sev issue')).toBeLessThan(md.indexOf('Low sev issue'));
  });

  it('states plainly when there are no confirmed issues (no overclaiming)', () => {
    const md = buildDisclosureReport({
      ...base,
      findings: [finding({ proofState: 'needs_runtime_reproduction' })],
    });
    expect(md).toMatch(/## Confirmed issues \(0\)/);
    expect(md).toMatch(/No confirmed issues/);
  });

  it('surfaces KEV context as priority-not-confirmation, and drafts an email listing confirmed issues', () => {
    const md = buildDisclosureReport({
      ...base,
      findings: [finding({ title: 'Outdated dropbear', severity: 'high', proofState: 'static_confirmed' })],
      kevMatches: [{ cveID: 'CVE-2021-44228', product: 'Log4j2' }],
    });
    expect(md).toMatch(/Known-exploited context \(CISA KEV\)/);
    expect(md).toContain('CVE-2021-44228');
    expect(md).toMatch(/does \*\*not\*\* confirm/);
    // Draft email lists the confirmed finding.
    expect(md).toMatch(/Subject: Security disclosure/);
    expect(md).toContain('[high] Outdated dropbear');
  });

  it('handles a missing security contact by pointing at the allowlist / a CERT', () => {
    const md = buildDisclosureReport({
      ...base,
      securityContacts: [{ domain: 'acme.com', checked: false, found: false, contact: [] }],
    });
    expect(md).toMatch(/add it to `FIRMLAB_RESEARCH_ALLOWLIST`/);
  });
});
