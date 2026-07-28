import type { Finding } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import type { StoredAssertion } from '../operator-findings.js';
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
    ...(over.assertion ? { assertion: over.assertion } : {}),
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

/**
 * The operator ledger in the document that leaves the building. Everything here exists because a vendor reading
 * this draft has no access to the workbench, cannot ask a follow-up question, and will act on what the page says.
 */
const assertion = (over: Partial<StoredAssertion> = {}): StoredAssertion => ({
  assertedBy: 'aaron',
  authorKind: 'human',
  assertedAt: 1_700_000_000_000,
  claim: 'asserted_from_device',
  rationale: 'Logged in over telnet on hardware rev B, serial 41F2.',
  title: 'Telnet root shell on the shipped unit',
  status: 'active',
  ...over,
});

const asserted = (over: Partial<StoredAssertion> = {}): Finding =>
  finding({
    id: 'op-1',
    source: 'operator:aaron',
    kind: over.claim ?? 'asserted_from_device',
    title: over.title ?? 'Telnet root shell on the shipped unit',
    severity: 'high',
    proofState: 'operator_assertion',
    rationale: over.rationale ?? 'Logged in over telnet on hardware rev B, serial 41F2.',
    assertion: assertion(over),
  });

const measured = (): Finding =>
  finding({ id: 'f-1', title: 'Hardcoded root password in /etc/shadow', proofState: 'static_confirmed' });

const contesting = (over: Partial<StoredAssertion> = {}, targetId = 'f-1'): Finding =>
  finding({
    id: 'op-9',
    source: 'operator:aaron',
    kind: 'disputes_finding',
    title: 'That hash is a placeholder, not a credential',
    severity: 'info',
    proofState: 'operator_assertion',
    rationale: 'The field is the string "x" on the shipped unit; the hash never ships.',
    assertion: assertion({
      claim: 'disputes_finding',
      title: 'That hash is a placeholder, not a credential',
      rationale: 'The field is the string "x" on the shipped unit; the hash never ships.',
      disputesFindingId: targetId,
      ...over,
    }),
  });

describe('buildDisclosureReport — a contested finding says so where the vendor will read it', () => {
  it('annotates the finding in place, prints its proof state unchanged, and keeps it in the count', () => {
    const md = buildDisclosureReport({ ...base, findings: [measured(), contesting()] });
    expect(md).toMatch(/## Confirmed issues \(1\)/);
    expect(md).toMatch(/CONTESTED BY AN OPERATOR/);
    expect(md).toContain('aaron asserts on 2023-11-14 that this finding is wrong');
    expect(md).toContain('“That hash is a placeholder, not a credential”');
    expect(md).toMatch(/Stated basis: The field is the string "x"/);
    // The measurement is untouched: still printed, still static_confirmed, and the draft says the dispute did
    // not move it.
    expect(md).toMatch(/- \*\*Proof state:\*\* `static_confirmed`/);
    expect(md).toMatch(/the proof state above is still `static_confirmed`/);
    expect(md).toMatch(/neither changes it, downgrades it nor removes the finding/);
  });

  it('marks the contested issue in the DRAFT email, not only in the attachment', () => {
    const md = buildDisclosureReport({ ...base, findings: [measured(), contesting()] });
    const email = md.slice(md.indexOf('## Draft email'));
    expect(email).toContain('[high] Hardcoded root password in /etc/shadow — CONTESTED on my side');
    expect(email).toMatch(/One issue above is marked CONTESTED/);
    expect(email).toMatch(/have not removed or downgraded the finding/);
  });

  it('annotates an unverified lead the same way, without promoting it', () => {
    const md = buildDisclosureReport({
      ...base,
      findings: [
        finding({ id: 'f-2', title: 'Possible command injection', proofState: 'needs_runtime_reproduction' }),
        contesting({}, 'f-2'),
      ],
    });
    expect(md).toMatch(/## Unverified leads \(1\) — reachability unverified/);
    expect(md).toMatch(/CONTESTED BY AN OPERATOR/);
    expect(md).toMatch(/the proof state above is still `needs_runtime_reproduction`/);
  });

  it('leaves an undisputed draft with no contest language at all', () => {
    const md = buildDisclosureReport({ ...base, findings: [measured()] });
    expect(md).not.toMatch(/CONTESTED/);
    expect(md).not.toMatch(/contested/i);
    expect(md).toMatch(/## Confirmed issues \(1\)/);
  });

  it('stops annotating a finding once the contest is withdrawn, and prints the retraction instead', () => {
    const md = buildDisclosureReport({
      ...base,
      findings: [
        measured(),
        contesting({ status: 'withdrawn', withdrawnBy: 'aaron', withdrawnReason: 'I was reading the wrong build' }),
      ],
    });
    expect(md).not.toMatch(/CONTESTED BY AN OPERATOR/);
    expect(md).toMatch(/## Withdrawn assertions \(1\) — retracted, and kept/);
    expect(md).toMatch(/WITHDRAWN by aaron: I was reading the wrong build/);
    expect(md).toMatch(/none of them is a claim any longer and none contests anything/i);
    // Rendering the draft caught this: the live wording sends the reader to an annotation that was deliberately
    // withheld, so a retracted contest names its former target with its own sentence.
    expect(md).toMatch(/\*\*Contested until withdrawn:\*\* “Hardcoded root password in \/etc\/shadow”/);
    expect(md).toMatch(/carries no contest annotation above/);
  });

  it('says plainly when the contested finding is no longer in the ledger', () => {
    const md = buildDisclosureReport({ ...base, findings: [measured(), contesting({}, 'f-vanished')] });
    expect(md).not.toMatch(/CONTESTED BY AN OPERATOR/);
    expect(md).toMatch(/finding `f-vanished`, which is no longer in this image's ledger/);
  });
});

/**
 * The Spanish draft. This is the document that leaves the building, so the test is mostly about what did NOT
 * change: a vendor grepping for `static_confirmed`, `CVE-2021-44228` or a finding's exact title has to find the
 * same token in either language, and the caveats that stop a lead being read as a vulnerability have to survive.
 */
describe('buildDisclosureReport — the draft composes in Spanish without translating the evidence', () => {
  const ctx: DisclosureContext = {
    ...base,
    findings: [
      finding({ id: 'a', title: 'Confirmed hardcoded key', proofState: 'static_confirmed', severity: 'critical' }),
      finding({
        id: 'b',
        title: 'Possible command injection',
        proofState: 'needs_runtime_reproduction',
        severity: 'high',
        rationale: 'A sink is reachable from a parsed parameter; reachability from the network is unproven.',
      }),
    ],
    kevMatches: [{ cveID: 'CVE-2021-44228', product: 'Log4j2' }],
  };

  it('defaults to English when no locale is given', () => {
    expect(buildDisclosureReport(ctx)).toBe(buildDisclosureReport(ctx, 'en'));
    expect(buildDisclosureReport(ctx)).toMatch(/## Confirmed issues \(1\)/);
  });

  it('translates the scaffolding and the draft email', () => {
    const md = buildDisclosureReport(ctx, 'es');
    expect(md).toMatch(/# Divulgación coordinada de vulnerabilidades — borrador/);
    expect(md).toMatch(/## Problemas confirmados \(1\)/);
    expect(md).toMatch(/## Pistas sin verificar \(1\) — alcanzabilidad no verificada/);
    expect(md).toMatch(/## Borrador de correo/);
    expect(md).toContain('Asunto: Divulgación de seguridad');
    expect(md).not.toMatch(/## Confirmed issues/);
    expect(md).not.toMatch(/Subject: Security disclosure/);
  });

  it('keeps it a DRAFT nobody sends, in Spanish', () => {
    const md = buildDisclosureReport(ctx, 'es');
    expect(md).toMatch(/BORRADOR/);
    expect(md).toMatch(/FirmLab no contacta con nadie/);
    expect(md).toMatch(/Sólo un borrador — revísalo antes de enviarlo/);
  });

  it('prints proof states, CVE ids, severities and finding titles verbatim', () => {
    const md = buildDisclosureReport(ctx, 'es');
    expect(md).toContain('- **Estado de prueba:** `static_confirmed`');
    expect(md).toContain('- **Estado de prueba:** `needs_runtime_reproduction`');
    expect(md).toContain('#### Confirmed hardcoded key');
    expect(md).toContain('#### Possible command injection');
    expect(md).toContain('A sink is reachable from a parsed parameter');
    expect(md).toContain('- **Gravedad:** critical');
    expect(md).toContain('`CVE-2021-44228`');
    expect(md).toContain('[critical] Confirmed hardcoded key');
    expect(md).not.toContain('confirmado_estático');
  });

  it('still refuses to present a lead as a vulnerability, in Spanish', () => {
    const md = buildDisclosureReport(ctx, 'es');
    expect(md).toMatch(/Esto \*\*no está confirmado\*\*/);
    expect(md).toMatch(/no las presentes como vulnerabilidades/);
    // The lead is listed after the confirmed section and never inside it.
    expect(md.indexOf('Confirmed hardcoded key')).toBeLessThan(md.indexOf('Possible command injection'));
  });

  it('states plainly, in Spanish, when there is nothing confirmed', () => {
    const md = buildDisclosureReport(
      { ...base, findings: [finding({ proofState: 'needs_runtime_reproduction' })] },
      'es',
    );
    expect(md).toMatch(/## Problemas confirmados \(0\)/);
    expect(md).toMatch(/Ningún problema confirmado/);
  });

  it('keeps KEV as priority, not confirmation, in Spanish', () => {
    const md = buildDisclosureReport(ctx, 'es');
    expect(md).toMatch(/## Contexto de explotación conocida \(CISA KEV\)/);
    expect(md).toMatch(/\*\*no\*\* confirma que el CVE sea alcanzable/);
    expect(md).toContain('alcanzabilidad no verificada');
  });

  it('separates the operator ledger in Spanish, with no proof state anywhere in it', () => {
    const md = buildDisclosureReport({ ...base, findings: [measured(), asserted()] }, 'es');
    expect(md).toMatch(/## Afirmaciones de operador \(1\) — afirmadas por una persona, no medidas aquí/);
    expect(md).toContain('- **Gravedad (afirmada):** high');
    expect(md).toContain('Afirmado por aaron el 2023-11-14 (asserted_from_device)');
    expect(md).toMatch(/no lleva estado de prueba/);
    // The assertion block never prints one, and the measured finding still does.
    expect(md).toContain('- **Estado de prueba:** `static_confirmed`');
    expect((md.match(/\*\*Estado de prueba:\*\*/g) ?? []).length).toBe(1);
  });

  it('carries a contest into the Spanish draft, into the email, and moves nothing', () => {
    const md = buildDisclosureReport({ ...base, findings: [measured(), contesting()] }, 'es');
    expect(md).toMatch(/IMPUGNADO POR UN OPERADOR/);
    expect(md).toContain('aaron afirma el 2023-11-14 que este hallazgo es incorrecto');
    expect(md).toMatch(/el estado de prueba de arriba sigue siendo `static_confirmed`/);
    expect(md).toMatch(/ni lo cambia, ni lo rebaja, ni elimina el hallazgo/);
    const email = md.slice(md.indexOf('## Borrador de correo'));
    expect(email).toContain('IMPUGNADO en mi lado');
    expect(email).toMatch(/No he eliminado ni rebajado el hallazgo/);
  });

  it('keeps a withdrawn assertion visible as withdrawn, in Spanish', () => {
    const md = buildDisclosureReport(
      {
        ...base,
        findings: [
          measured(),
          contesting({ status: 'withdrawn', withdrawnBy: 'aaron', withdrawnReason: 'I was reading the wrong build' }),
        ],
      },
      'es',
    );
    expect(md).not.toMatch(/IMPUGNADO POR UN OPERADOR/);
    expect(md).toMatch(/## Afirmaciones retiradas \(1\) — retractadas, y conservadas/);
    expect(md).toMatch(/RETIRADA por aaron: I was reading the wrong build/);
    expect(md).toMatch(/\*\*Impugnado hasta su retirada:\*\* “Hardcoded root password in \/etc\/shadow”/);
  });

  it('formats the preparation date for the locale while keeping the ISO stamp beside it', () => {
    const md = buildDisclosureReport(ctx, 'es');
    expect(md).toMatch(/\*\*Preparado:\*\* .*julio.*2026.*\(2026-07-21T00:00:00\.000Z\)/);
    expect(buildDisclosureReport(ctx, 'en')).toContain('(2026-07-21T00:00:00.000Z)');
  });
});

describe('buildDisclosureReport — an amendment reaches the vendor with what it replaced', () => {
  const amended = (): Finding =>
    asserted({
      claim: 'asserted_unverified',
      title: 'Telnet root shell on the DEV BOARD',
      rationale: 'Only reproducible on the dev board, not the shipped unit.',
      amendedAt: 1_700_500_000_000,
      supersedes: [
        {
          claim: 'asserted_from_device',
          rationale: 'Logged in over telnet on hardware rev B, serial 41F2.',
          title: 'Telnet root shell on the shipped unit',
          from: 1_700_000_000_000,
          supersededAt: 1_700_500_000_000,
        },
      ],
    });

  it('prints the superseded claim, its basis and the window it stood in — under the current one', () => {
    const md = buildDisclosureReport({ ...base, findings: [amended()] });
    expect(md).toContain('#### Telnet root shell on the DEV BOARD');
    expect(md).toMatch(/\*\*Amended 2023-11-20, superseding 1 earlier claim\.\*\*/);
    expect(md).toMatch(/An amendment appends; it never overwrites/);
    expect(md).toContain('`asserted_from_device`, stood from 2023-11-14 to 2023-11-20');
    expect(md).toContain('“Telnet root shell on the shipped unit”');
    expect(md).toMatch(/Basis given at the time: Logged in over telnet/);
    // The current claim is the one on the heading; the superseded one is only inside the history line.
    expect(md.indexOf('#### Telnet root shell on the DEV BOARD')).toBeLessThan(md.indexOf('stood from 2023-11-14'));
  });

  it('reads an assertion from a build with no `supersedes` as no history, never as a throw', () => {
    const md = buildDisclosureReport({ ...base, findings: [asserted()] });
    expect(md).toMatch(/## Operator assertions \(1\)/);
    expect(md).not.toMatch(/superseding/);
    expect(md).not.toMatch(/Amended/);
    expect(md).toContain('Telnet root shell on the shipped unit');
  });

  it('reports an amendment whose predecessor was overwritten as a hole rather than as "never amended"', () => {
    const md = buildDisclosureReport({ ...base, findings: [asserted({ amendedAt: 1_700_500_000_000 })] });
    expect(md).toMatch(/\*\*Amended 2023-11-20:\*\* the claim it replaced was not preserved/);
    expect(md).toMatch(/not necessarily the original one/);
  });

  it('degrades a `supersedes` column of the wrong shape instead of failing the draft', () => {
    const junk = asserted({
      amendedAt: 1_700_500_000_000,
      supersedes: 'not an array' as unknown as NonNullable<StoredAssertion['supersedes']>,
    });
    expect(() => buildDisclosureReport({ ...base, findings: [junk] })).not.toThrow();
    expect(buildDisclosureReport({ ...base, findings: [junk] })).toMatch(/was not preserved/);
  });

  it('keeps assertions out of the confirmed count and gives them no proof state', () => {
    const md = buildDisclosureReport({ ...base, findings: [amended()] });
    expect(md).toMatch(/## Confirmed issues \(0\)/);
    expect(md).toMatch(/asserted by a person, not measured here/);
    expect(md).not.toContain('**Proof state:**');
    expect(md).toContain('**Severity (asserted):** high');
  });

  it('is still a DRAFT nobody sends, with the ledger in it', () => {
    const md = buildDisclosureReport({ ...base, findings: [measured(), contesting(), amended()] });
    expect(md).toMatch(/DRAFT/);
    expect(md).toMatch(/FirmLab does not contact anyone/);
    expect(md).toMatch(/Draft only — review before sending/);
  });
});
