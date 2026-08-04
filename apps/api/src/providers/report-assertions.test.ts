import type { OperatorAssertion } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import { type StoredAssertion, amendAssertion, assertionToDraft, validateAssertion } from '../operator-findings.js';
import { indexDisputes } from '../operator-findings.js';
import { MAX_MEASURED_ROWS, type ReportFinding, renderLedgerSections } from './report-assertions.js';

const DAY = 1_700_000_000_000; // 2023-11-14

function valid(over: Record<string, unknown> = {}): ReturnType<typeof assertionToDraft> {
  const r = validateAssertion({
    assertedBy: 'aaron',
    title: 'Telnet root shell reachable on the shipped unit',
    claim: 'asserted_from_device',
    rationale: 'Logged in over telnet on hardware rev B; transcript in ticket 412.',
    ...over,
  });
  if (!r.ok) throw new Error(`fixture invalid: ${r.error}`);
  return assertionToDraft(r.value, 'human', DAY);
}

/** A stored operator row, shaped as the store hands it back after `rowToFinding`. */
function assertedRow(id: string, over: Record<string, unknown> = {}, assertion?: OperatorAssertion): ReportFinding {
  const draft = valid(over);
  return {
    id,
    source: 'operator:aaron',
    kind: draft.kind,
    title: draft.title,
    severity: draft.severity,
    proofState: 'operator_assertion',
    rationale: draft.rationale,
    evidence: draft.evidence,
    assertion: assertion ?? draft.assertion,
  };
}

const measuredRow: ReportFinding = {
  id: 'f0001',
  source: 'binvuln',
  kind: 'unsafe-call',
  title: 'strcpy reachable from the CGI entry point',
  severity: 'high',
  proofState: 'static_confirmed',
  rationale: 'The call is present in the bytes; reachability from network input is not established.',
};

const otherMeasured: ReportFinding = {
  id: 'f0002',
  source: 'sbom',
  kind: 'cve',
  title: 'CVE-2019-0000 — busybox 1.20',
  severity: 'medium',
  proofState: 'needs_runtime_reproduction',
};

describe('an assertion is rendered as testimony, never as a measurement', () => {
  const html = renderLedgerSections([measuredRow, assertedRow('a1')]);

  it('gives assertions their own section, and never lets one into the measured table', () => {
    expect(html.measured).toContain('Findings — measured (1)');
    expect(html.measured).toContain('strcpy reachable');
    expect(html.measured).not.toContain('Telnet root shell');
    expect(html.operator).toContain('Telnet root shell');
    expect(html.operator).not.toContain('strcpy reachable');
  });

  it('emits no proof-state badge in the operator section — the ladder does not appear there at all', () => {
    expect(html.measured).toContain('class="proof"');
    expect(html.operator).not.toContain('class="proof"');
    expect(html.operator).toContain('asserted · not measured');
  });

  it('states the author, the date and the claim on the row itself', () => {
    expect(html.operator).toContain('Asserted by aaron on 2023-11-14');
    expect(html.operator).toContain('asserted_from_device');
    expect(html.operator).toContain('Stated basis:');
    expect(html.operator).toContain('ticket 412');
  });

  it('carries the sentence saying it counts towards no analysis stage', () => {
    expect(html.operator).toContain('counts towards no analysis stage');
    expect(html.operator).toContain('none of it is included in the measured count');
  });

  it('marks an agent author as one, so a reader never takes it for a person', () => {
    const draft = valid({ assertedBy: 'claude' });
    const agentRow: ReportFinding = {
      ...assertedRow('a2'),
      assertion: { ...draft.assertion, assertedBy: 'claude', authorKind: 'agent' },
    };
    expect(renderLedgerSections([agentRow]).operator).toContain('claude (agent)');
  });

  it('escapes what an author typed — the report is opened in a browser', () => {
    const row = assertedRow('a3', { title: '<img src=x onerror=alert(1)>' });
    const out = renderLedgerSections([row]).operator;
    expect(out).not.toContain('<img src=x');
    expect(out).toContain('&lt;img src=x');
  });
});

describe('a dispute annotates the computed row without overriding it', () => {
  const dispute = assertedRow(
    'd1',
    {
      claim: 'disputes_finding',
      title: 'That strcpy is in dead code — the CGI never links this object',
      rationale: 'Checked the linked symbols on the shipped binary; the object is not in the image.',
      disputesFindingId: 'f0001',
    },
    undefined,
  );
  const html = renderLedgerSections([measuredRow, otherMeasured, dispute]);

  it('says so where the finding is rendered', () => {
    expect(html.measured).toContain('CONTESTED BY AN OPERATOR');
    expect(html.measured).toContain('aaron asserts on 2023-11-14');
    expect(html.measured).toContain('dead code');
    expect(html.measured).toContain('class="contested"');
  });

  it('leaves the computed proof state exactly as code decided it', () => {
    expect(html.measured).toContain('<code class="proof">static_confirmed</code>');
    // Stated in the annotation, not only implied by the badge still being there.
    expect(html.measured).toContain('the proof state of this row is still <code>static_confirmed</code>');
    expect(html.measured).toContain('neither changes it, downgrades it nor removes the row');
  });

  it('does not delete or hide the disputed row, and still counts it as measured', () => {
    expect(html.measured).toContain('Findings — measured (2)');
    expect(html.measured).toContain('strcpy reachable from the CGI entry point');
  });

  it('leaves an undisputed row completely unannotated', () => {
    const rowHtml = html.measured.slice(html.measured.indexOf('CVE-2019-0000'));
    expect(rowHtml).not.toContain('CONTESTED');
    const plain = renderLedgerSections([measuredRow, otherMeasured]);
    expect(plain.measured).not.toContain('CONTESTED');
    expect(plain.measured).not.toContain('class="contested"');
    expect(plain.operator).toBe('');
  });

  it('names the finding it contests from the assertion side too', () => {
    expect(html.operator).toContain('Contests finding <code>f0001</code>');
    expect(html.operator).toContain('That row stands exactly as code decided it');
  });

  it('says plainly when the contested row is no longer in the ledger', () => {
    const orphan = assertedRow('d2', {
      claim: 'disputes_finding',
      title: 'Disputes a row a provider re-run has since replaced',
      rationale: 'The binary was rebuilt; this id no longer exists.',
      disputesFindingId: 'gone-9999',
    });
    const out = renderLedgerSections([measuredRow, orphan]).operator;
    expect(out).toContain('no longer in this image');
    expect(out).toContain('replaces its rows with new ids');
  });

  it('stops annotating once the dispute is withdrawn, but keeps the withdrawn claim visible', () => {
    const retracted: ReportFinding = {
      ...dispute,
      assertion: {
        ...(dispute.assertion as OperatorAssertion),
        status: 'withdrawn',
        withdrawnBy: 'aaron',
        withdrawnAt: DAY,
        withdrawnReason: 'I read the wrong map file; the object IS linked.',
      },
    };
    const out = renderLedgerSections([measuredRow, retracted]);
    expect(out.measured).not.toContain('CONTESTED');
    expect(out.operator).toContain('Withdrawn assertions (1)');
    expect(out.operator).toContain('wrong map file');
    expect(indexDisputes([retracted]).size).toBe(0);
  });
});

describe('an amended assertion shows what it superseded', () => {
  it('renders the current claim and the one it replaced, with both bases', () => {
    const first = valid().assertion;
    const secondInput = validateAssertion({
      assertedBy: 'aaron',
      title: 'Telnet root shell reachable on the DEV BOARD, not the shipped unit',
      claim: 'asserted_unverified',
      rationale: 'Re-checked the label: the unit I logged into was an engineering sample.',
    });
    if (!secondInput.ok) throw new Error('fixture');
    const amended = amendAssertion(first, secondInput.value, DAY + 86_400_000);
    const row: ReportFinding = {
      ...assertedRow('a4'),
      title: secondInput.value.title,
      rationale: secondInput.value.rationale,
      assertion: amended,
    };
    const out = renderLedgerSections([row]).operator;

    expect(out).toContain('DEV BOARD');
    expect(out).toContain('superseding 1 earlier claim');
    expect(out).toContain('An amendment appends; it never overwrites');
    // The predecessor, verbatim: its claim, its window and the basis originally given for it.
    expect(out).toContain('asserted_from_device');
    expect(out).toContain('stood from 2023-11-14 to 2023-11-15');
    expect(out).toContain('ticket 412');
  });

  it('says so, rather than pretending nothing was replaced, when an older build lost the predecessor', () => {
    const legacy: StoredAssertion = { ...valid().assertion, amendedAt: DAY + 1, supersedes: [] };
    const out = renderLedgerSections([{ ...assertedRow('a5'), assertion: legacy }]).operator;
    expect(out).toContain('The claim it replaced was not preserved');
  });

  it('renders nothing about amendment for a claim that was never amended', () => {
    expect(renderLedgerSections([assertedRow('a6')]).operator).not.toContain('Amended');
  });
});

describe('a withdrawn assertion stays visible as withdrawn', () => {
  const withdrawn: ReportFinding = {
    ...assertedRow('w1'),
    assertion: {
      ...valid().assertion,
      status: 'withdrawn',
      withdrawnBy: 'reviewer',
      withdrawnAt: DAY,
      withdrawnReason: 'Could not reproduce on three further units.',
    },
  };

  it('is shown, not dropped, with who retracted it and why', () => {
    const out = renderLedgerSections([withdrawn]).operator;
    expect(out).toContain('Withdrawn assertions (1)');
    expect(out).toContain('WITHDRAWN by reviewer');
    expect(out).toContain('Could not reproduce on three further units.');
    expect(out).toContain('withdrawn · not measured');
  });

  it('is excluded from the active count, so a retraction is not cosmetic', () => {
    const out = renderLedgerSections([withdrawn, assertedRow('a7')]).operator;
    expect(out).toContain('Operator assertions (1)');
    expect(out).toContain('Withdrawn assertions (1)');
  });

  it('is still shown when it is the only operator row left standing', () => {
    const out = renderLedgerSections([measuredRow, withdrawn]).operator;
    expect(out).toContain('Operator assertions (0)');
    expect(out).toContain('No assertion currently stands');
    expect(out).toContain('Could not reproduce');
  });
});

describe('the empty cases', () => {
  it('renders no operator section at all when there are no assertions', () => {
    expect(renderLedgerSections([measuredRow]).operator).toBe('');
    expect(renderLedgerSections([]).operator).toBe('');
  });

  it('renders the measured section even when empty, saying an empty ledger is not a clean image', () => {
    const out = renderLedgerSections([]).measured;
    expect(out).toContain('Findings — measured (0)');
    expect(out).toContain('not evidence that the image is clean');
    expect(out).not.toContain('<table>');
  });
});

/**
 * The Spanish ledger. The rule under test is not "the words changed" — it is that the things a reader matches
 * against something else did NOT change: proof states, sources, kinds, ids, severities, and the finding's own
 * title and rationale, which a provider wrote and the store keeps as evidence.
 */
describe('the ledger composes in Spanish without translating any of the data', () => {
  const blocked: ReportFinding = {
    id: 'f0003',
    source: 'chipsec',
    kind: 'secure-boot-state',
    title: 'Secure boot state could not be read',
    severity: 'medium',
    proofState: 'blocked_by_platform',
    rationale: 'The platform exposes no interface this deployment can query.',
  };

  it('defaults to English when no locale is given — an absent parameter is not a half-translated document', () => {
    const rows = [measuredRow, blocked, assertedRow('a10')];
    expect(renderLedgerSections(rows)).toEqual(renderLedgerSections(rows, 'en'));
  });

  it('translates the scaffolding', () => {
    const out = renderLedgerSections([measuredRow, blocked], 'es').measured;
    expect(out).toContain('Hallazgos — medidos (2)');
    expect(out).toContain('<th class="narrow">Estado de prueba</th>');
    expect(out).toContain('<th>Hallazgo</th>');
    expect(out).not.toContain('Findings — measured');
    expect(out).not.toContain('Proof state');
  });

  it('prints the proof-state CODE verbatim and glosses it in Spanish beside it', () => {
    const out = renderLedgerSections([measuredRow, blocked], 'es').measured;
    // The identifier, untouched, exactly as it crosses the API and sits in SQLite.
    expect(out).toContain('<code class="proof">static_confirmed</code>');
    expect(out).toContain('<code class="proof">blocked_by_platform</code>');
    expect(out).toContain('<dt><code>static_confirmed</code></dt>');
    // ...and the reader still gets what it means, in their language.
    expect(out).toContain('La propiedad está literalmente presente en los bytes');
    expect(out).not.toContain('confirmado_estático');
  });

  it('keeps the blocked state saying it is NOT a negative result, in both languages', () => {
    const es = renderLedgerSections([blocked], 'es').measured;
    const en = renderLedgerSections([blocked], 'en').measured;
    expect(en).toContain('This is NOT a negative result.');
    expect(es).toContain('Esto NO es un resultado negativo.');
    expect(es).not.toMatch(/sin problemas/i);
  });

  it('only glosses the states actually present, so the legend is about this image', () => {
    const out = renderLedgerSections([blocked], 'es').measured;
    expect(out).toContain('<dt><code>blocked_by_platform</code></dt>');
    expect(out).not.toContain('<dt><code>static_confirmed</code></dt>');
  });

  it('prints a proof state this build does not know rather than dropping or guessing it', () => {
    const future: ReportFinding = { ...measuredRow, id: 'f9', proofState: 'confirmed_on_hardware_2031' };
    const out = renderLedgerSections([future], 'es').measured;
    expect(out).toContain('<code class="proof">confirmed_on_hardware_2031</code>');
    expect(out).toContain('Un estado de prueba que esta versión no reconoce');
  });

  it('leaves the finding title, rationale and source exactly as the provider recorded them', () => {
    const out = renderLedgerSections([measuredRow], 'es').measured;
    expect(out).toContain('strcpy reachable from the CGI entry point');
    expect(out).toContain('The call is present in the bytes; reachability from network input is not established.');
    expect(out).toContain('<code>binvuln</code>');
    expect(out).toContain('<span class="mono">high</span>');
  });

  it('says an empty measured ledger is not a clean image, in Spanish', () => {
    const out = renderLedgerSections([], 'es').measured;
    expect(out).toContain('Hallazgos — medidos (0)');
    expect(out).toContain('no es evidencia de que la imagen esté limpia');
  });

  it('states the cut rule in Spanish and still never cuts by arrival order', () => {
    const many: ReportFinding[] = Array.from({ length: MAX_MEASURED_ROWS + 5 }, (_, i) => ({
      id: `bulk${String(i).padStart(4, '0')}`,
      source: 'sbom',
      kind: 'cve',
      title: `CVE-2020-${1000 + i} — filler`,
      severity: 'medium',
      proofState: 'needs_runtime_reproduction',
    }));
    const out = renderLedgerSections(many, 'es').measured;
    expect(out).toContain(`Se muestran ${MAX_MEASURED_ROWS} de ${many.length}`);
    expect(out).toContain('nunca el orden en que se escribieron las filas');
  });
});

describe('an assertion reads as testimony in Spanish too', () => {
  it('attributes it, keeps the claim code verbatim, and says it counts towards no stage', () => {
    const out = renderLedgerSections([assertedRow('a11')], 'es').operator;
    expect(out).toContain('Afirmaciones de operador (1)');
    expect(out).toContain('Afirmado por aaron el 2023-11-14 (asserted_from_device)');
    expect(out).toContain('<code>asserted_from_device</code>');
    expect(out).toContain('no cuenta para ninguna etapa del análisis');
    expect(out).toContain('afirmado · no medido');
    // The ladder never appears in this section, in any language.
    expect(out).not.toContain('class="proof"');
  });

  it('marks an agent author as an agent in Spanish', () => {
    const draft = valid({ assertedBy: 'claude' });
    const agentRow: ReportFinding = {
      ...assertedRow('a12'),
      assertion: { ...draft.assertion, assertedBy: 'claude', authorKind: 'agent' },
    };
    expect(renderLedgerSections([agentRow], 'es').operator).toContain('claude (agente)');
  });

  it('annotates a contested row in Spanish while leaving its proof state exactly as code decided it', () => {
    const dispute = assertedRow('d10', {
      claim: 'disputes_finding',
      title: 'That strcpy is in dead code — the CGI never links this object',
      rationale: 'Checked the linked symbols on the shipped binary.',
      disputesFindingId: 'f0001',
    });
    const out = renderLedgerSections([measuredRow, dispute], 'es');
    expect(out.measured).toContain('IMPUGNADO POR UN OPERADOR');
    expect(out.measured).toContain('aaron afirma el 2023-11-14');
    expect(out.measured).toContain('el estado de prueba de esta fila sigue siendo <code>static_confirmed</code>');
    expect(out.measured).toContain('ni lo cambia, ni lo rebaja, ni elimina la fila');
    expect(out.operator).toContain('Impugna el hallazgo <code>f0001</code>');
  });

  it('shows a withdrawn assertion as withdrawn, in Spanish, rather than dropping it', () => {
    const withdrawn: ReportFinding = {
      ...assertedRow('w10'),
      assertion: {
        ...valid().assertion,
        status: 'withdrawn',
        withdrawnBy: 'reviewer',
        withdrawnAt: DAY,
        withdrawnReason: 'Could not reproduce on three further units.',
      },
    };
    const out = renderLedgerSections([withdrawn], 'es').operator;
    expect(out).toContain('Afirmaciones retiradas (1)');
    expect(out).toContain('RETIRADA por reviewer');
    expect(out).toContain('Could not reproduce on three further units.');
    expect(out).toContain('retirado · no medido');
  });

  it('renders an amendment and its superseded claim in Spanish, keeping both claim codes verbatim', () => {
    const first = valid().assertion;
    const second = validateAssertion({
      assertedBy: 'aaron',
      title: 'Telnet root shell reachable on the DEV BOARD, not the shipped unit',
      claim: 'asserted_unverified',
      rationale: 'Re-checked the label: the unit I logged into was an engineering sample.',
    });
    if (!second.ok) throw new Error('fixture');
    const row: ReportFinding = {
      ...assertedRow('a13'),
      title: second.value.title,
      rationale: second.value.rationale,
      assertion: amendAssertion(first, second.value, DAY + 86_400_000),
    };
    const out = renderLedgerSections([row], 'es').operator;
    expect(out).toContain('sustituyendo 1 afirmación anterior');
    expect(out).toContain('Una modificación añade; nunca sobrescribe');
    expect(out).toContain('<code>asserted_from_device</code>');
    expect(out).toContain('vigente del 2023-11-14 al 2023-11-15');
  });

  it('still escapes what an author typed — the language does not change who opens the file', () => {
    const row = assertedRow('a14', { title: '<img src=x onerror=alert(1)>' });
    const out = renderLedgerSections([row], 'es').operator;
    expect(out).not.toContain('<img src=x');
    expect(out).toContain('&lt;img src=x');
  });
});

describe('the population split cannot be gamed, and the cap cannot hide a contest', () => {
  it('classifies by the provenance sentinel, not by the source string', () => {
    const laundered: ReportFinding = { ...assertedRow('l1'), source: 'sbom' };
    const out = renderLedgerSections([laundered]);
    expect(out.measured).toContain('Findings — measured (0)');
    expect(out.operator).toContain('Telnet root shell');
  });

  it('cuts by severity with the rule stated, and never drops a contested row', () => {
    const many: ReportFinding[] = Array.from({ length: MAX_MEASURED_ROWS + 40 }, (_, i) => ({
      id: `bulk${String(i).padStart(4, '0')}`,
      source: 'sbom',
      kind: 'cve',
      title: `CVE-2020-${1000 + i} — filler`,
      severity: 'medium',
      proofState: 'needs_runtime_reproduction',
    }));
    const lowAndContested: ReportFinding = {
      id: 'quiet1',
      source: 'fsaudit',
      kind: 'world-writable',
      title: 'World-writable /etc/passwd',
      severity: 'info',
      proofState: 'static_confirmed',
    };
    const dispute = assertedRow('d9', {
      claim: 'disputes_finding',
      title: 'That path is a symlink into /tmp on the running device',
      rationale: 'Observed on the unit; the extracted tree does not reflect the runtime overlay.',
      disputesFindingId: 'quiet1',
    });
    const out = renderLedgerSections([...many, lowAndContested, dispute]).measured;

    expect(out).toContain(`Showing ${MAX_MEASURED_ROWS} of ${many.length + 1}`);
    expect(out).toContain('ordered by severity');
    expect(out).toContain('never by the order the rows were written');
    // The info-severity row would have been cut on severity alone; the contest keeps it in.
    expect(out).toContain('World-writable /etc/passwd');
    expect(out).toContain('CONTESTED BY AN OPERATOR');
  });
});

describe('the report and the screen order the same rows the same way', () => {
  const row = (o: Partial<ReportFinding>): ReportFinding => ({
    id: 'r1',
    source: 'kernel',
    kind: 'k',
    title: 'a finding',
    severity: 'high',
    proofState: 'static_confirmed',
    ...o,
  });

  it('breaks a severity tie by the ladder rather than the alphabet', () => {
    // This module carried its own copy of the rule with the same defect as the ledger's: `blocked_by_platform`
    // sorted above `confirmed_full_system` because 'b' precedes 'c'.
    const html = renderLedgerSections(
      [
        row({ id: 'a', proofState: 'blocked_by_platform', title: 'the blocked one' }),
        row({ id: 'b', proofState: 'confirmed_full_system', title: 'the booted one' }),
      ],
      'en',
    ).measured;
    expect(html.indexOf('the booted one')).toBeLessThan(html.indexOf('the blocked one'));
  });

  it('still puts a higher severity first, whatever its proof state', () => {
    const html = renderLedgerSections(
      [
        row({ id: 'a', severity: 'info', proofState: 'confirmed_full_system', title: 'proven trivium' }),
        row({ id: 'b', severity: 'critical', proofState: 'needs_runtime_reproduction', title: 'critical lead' }),
      ],
      'en',
    ).measured;
    expect(html.indexOf('critical lead')).toBeLessThan(html.indexOf('proven trivium'));
  });

  it('prints a proof state it does not recognise rather than throwing on it', () => {
    // `ReportFinding` widens both fields on purpose: a row persisted by an older build may carry a label this
    // build's unions do not name, and the comparator must cope rather than the document failing to render.
    const html = renderLedgerSections([row({ proofState: 'confirmed_on_physical_device' })], 'en').measured;
    expect(html).toContain('confirmed_on_physical_device');
  });
});
