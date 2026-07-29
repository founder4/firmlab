import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Finding } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { FindingsLedger, danglingDisputes, indexDisputes, selectLedgerRows } from './FindingsLedger';

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
});

const measured = (o: Partial<Finding> = {}): Finding => ({
  id: 'f1',
  imageId: 'img1',
  source: 'binvuln',
  kind: 'unsafe-call',
  title: 'strcpy reachable from the HTTP handler',
  severity: 'high',
  proofState: 'static_confirmed',
  createdAt: 1,
  ...o,
});

const dispute = (targetId: string, o: Partial<Finding> = {}): Finding => ({
  id: 'a1',
  imageId: 'img1',
  source: 'operator:aaron',
  kind: 'disputes_finding',
  title: 'That handler is compiled out of shipping units',
  severity: 'info',
  proofState: 'operator_assertion',
  rationale: 'Checked the release config on hardware rev B; CONFIG_HTTPD is off.',
  createdAt: 2,
  assertion: {
    assertedBy: 'aaron',
    authorKind: 'human',
    assertedAt: 1_700_000_000_000,
    claim: 'disputes_finding',
    rationale: 'Checked the release config on hardware rev B; CONFIG_HTTPD is off.',
    status: 'active',
    disputesFindingId: targetId,
  },
  ...o,
});

describe('FindingsLedger — a dispute annotates a measurement, and moves nothing', () => {
  it('annotates the contested row with who, when and on what basis', () => {
    const { container } = render(<FindingsLedger findings={[measured(), dispute('f1')]} />);
    const text = container.textContent ?? '';
    expect(screen.getByText('Contested by an operator')).toBeTruthy();
    expect(text).toContain('aaron asserts on 2023-11-14 that this finding is wrong');
    expect(text).toContain('That handler is compiled out of shipping units');
    expect(text).toContain('CONFIG_HTTPD is off');
    // The contest names the assertion it came from, so a reader can find the full claim in the operator ledger.
    expect(text).toContain('Recorded as operator assertion');
  });

  it('leaves the proof state exactly as code decided it, and says so in the same block', () => {
    const { container } = render(<FindingsLedger findings={[measured(), dispute('f1')]} />);
    // The badge is unchanged — not greyed, not downgraded, not removed.
    expect(screen.getByText('static-confirmed')).toBeTruthy();
    const text = container.textContent ?? '';
    expect(text).toContain('the proof state of this row is still static_confirmed');
    expect(text).toContain('decided by code from the evidence');
    expect(text).toContain('neither changes it, downgrades it nor removes the row');
  });

  it('keeps the contested row in its severity position rather than promoting or demoting it', () => {
    const rows = [
      measured({ id: 'f1', severity: 'high', title: 'high finding' }),
      measured({ id: 'f0', severity: 'critical', title: 'critical finding', proofState: 'static_confirmed' }),
      dispute('f1'),
    ];
    render(<FindingsLedger findings={rows} />);
    const titles = Array.from(document.querySelectorAll('tbody tr td:nth-child(2)')).map((td) =>
      (td.textContent ?? '').slice(0, 16),
    );
    expect(titles[0]).toContain('critical finding');
    expect(titles[1]).toContain('high finding');
  });

  it('leaves an undisputed row exactly as it was — no annotation, no tint, no extra prose', () => {
    const { container } = render(<FindingsLedger findings={[measured()]} />);
    expect(screen.queryByText('Contested by an operator')).toBeNull();
    expect(screen.getByText('static-confirmed')).toBeTruthy();
    expect(container.textContent ?? '').not.toContain('contested by an operator and annotated in place');
  });

  it('does not mark a row contested once the dispute has been withdrawn', () => {
    const w = dispute('f1', {
      assertion: {
        assertedBy: 'aaron',
        authorKind: 'human',
        assertedAt: 1_700_000_000_000,
        claim: 'disputes_finding',
        rationale: 'r',
        status: 'withdrawn',
        disputesFindingId: 'f1',
        withdrawnBy: 'aaron',
        withdrawnReason: 'I was reading the wrong build',
      },
    });
    render(<FindingsLedger findings={[measured(), w]} />);
    expect(screen.queryByText('Contested by an operator')).toBeNull();
    // The withdrawn row itself is still shown — retraction is kept, never deleted.
    expect(screen.getByText(/That handler is compiled out/)).toBeTruthy();
  });
});

describe('FindingsLedger — a dispute whose target is gone is stated, not dropped', () => {
  it('names the missing target and why it can be missing', () => {
    const { container } = render(
      <FindingsLedger findings={[measured({ id: 'f9' }), dispute('f1-from-an-older-run')]} />,
    );
    const text = container.textContent ?? '';
    expect(text).toContain('f1-from-an-older-run');
    expect(text).toContain('is not in this ledger');
    expect(text).toContain('Re-running a provider replaces its rows with new ids');
    // It is reported, not annotated onto some other row.
    expect(screen.queryByText('Contested by an operator')).toBeNull();
  });

  it('says nothing about dangling disputes when every target is present', () => {
    const { container } = render(<FindingsLedger findings={[measured(), dispute('f1')]} />);
    expect(container.textContent ?? '').not.toContain('is not in this ledger');
  });
});

describe('FindingsLedger — the pure selection rules', () => {
  it('indexes only active disputes that name a target', () => {
    const noTarget = dispute('x', {
      id: 'a2',
      assertion: {
        assertedBy: 'b',
        authorKind: 'agent',
        assertedAt: 1,
        claim: 'asserted_unverified',
        rationale: 'r',
        status: 'active',
      },
    });
    const idx = indexDisputes([measured(), dispute('f1'), noTarget]);
    expect([...idx.keys()]).toEqual(['f1']);
    expect(danglingDisputes([measured(), dispute('f1')])).toEqual([]);
  });

  it('exempts a contested row from the display cap — the cut can never delete the annotation', () => {
    const rows: Finding[] = [];
    for (let i = 0; i < 12; i++) {
      rows.push(measured({ id: `f${i}`, severity: 'critical', title: `finding ${i}` }));
    }
    // The contested row is the lowest-ranked thing in the ledger, so an arithmetic cap would drop it first.
    rows.push(measured({ id: 'low', severity: 'info', title: 'the contested one' }));
    const view = selectLedgerRows(rows, new Set(['low']), 5);
    expect(view.rows.some((r) => r.id === 'low')).toBe(true);
    expect(view.omitted).toBe(8);
    // The sentence still travels WITH the selection; it is now the catalogue's, so the two are pinned together
    // rather than the wording being restated here and drifting from what a reader actually sees.
    expect(view.rule).toBe(en.findings.cutRule(5, 13, 8));
    expect(view.rule).toContain('Every contested row is shown regardless of the cap');
    expect(view.rule).toContain('never by the order the rows were written');
  });

  it('states no rule when nothing was cut', () => {
    const view = selectLedgerRows([measured()], new Set(), 5);
    expect(view.rule).toBeNull();
    expect(view.omitted).toBe(0);
  });
});

/**
 * The dispute annotation is the one piece of prose here a translation can quietly invert. Drop the half saying the
 * proof state is untouched and what is left is a bare "DISPUTADO" — precisely the override the design refuses. So
 * both halves are asserted in Spanish, and so is the fact that the two identifiers the sentence is built around,
 * the assertion id and the proof-state CODE, came through untranslated.
 */
describe('FindingsLedger — the dispute annotation in Spanish', () => {
  it('records the contest AND that the state code decided still stands', () => {
    setLocale('es');
    const { container } = render(<FindingsLedger findings={[measured(), dispute('f1')]} />);
    const text = container.textContent ?? '';

    expect(screen.getByText('Impugnado por un operador')).toBeTruthy();
    expect(text).toContain('aaron afirma el 2023-11-14 que este hallazgo es incorrecto');
    // The half a bare chip would drop: the state is unchanged, not downgraded, and the row is not removed.
    expect(text).toContain('el estado de prueba de esta fila sigue siendo');
    expect(text).toContain('no lo cambia, no lo rebaja ni retira la fila');
    expect(text).toContain('no cambia nada de lo que decidió el código');
    // The badge carries the shared gloss; the CODE is still the code, because it crosses the API into SQLite.
    expect(screen.getByText('confirmado en los bytes')).toBeTruthy();
    expect(screen.getByText('static_confirmed')).toBeTruthy();
    // Recorded evidence — the provider's title, the operator's claim and the source string — is shown as written.
    expect(text).toContain('strcpy reachable from the HTTP handler');
    expect(text).toContain('That handler is compiled out of shipping units');
    expect(screen.getByText('binvuln')).toBeTruthy();
  });

  it('states a dangling dispute in Spanish rather than dropping a recorded claim', () => {
    setLocale('es');
    const { container } = render(<FindingsLedger findings={[measured({ id: 'f9' }), dispute('f1-older-run')]} />);
    const text = container.textContent ?? '';
    expect(text).toContain('no está en este registro');
    expect(text).toContain('sustituye sus filas por ids nuevos');
    expect(screen.getByText('f1-older-run')).toBeTruthy();
  });
});

/**
 * The evidence channel in the ledger. Two renderings and one refusal, and the refusal is the load-bearing one.
 */
describe('FindingsLedger — how it was known, beside how far it was proven', () => {
  it('prints the channel under the rung, because they answer different questions', () => {
    render(<FindingsLedger findings={[measured({ source: 'symreach', evidenceChannel: 'symbolic_execution' })]} />);
    // The rung says how far it was proven; the channel says a solver concluded it and nothing was executed.
    expect(screen.getByText(en.proofState.label.static_confirmed)).toBeTruthy();
    expect(screen.getByText('symbolic_execution')).toBeTruthy();
  });

  it('prints NOTHING when no channel was recorded, rather than an "unknown" chip', () => {
    // An `unknown` badge would say the question was asked and came back empty. It was not asked: the row was
    // written by a provider not yet taught its channel, and inventing a value is the failure the field exists
    // to avoid.
    const { container } = render(<FindingsLedger findings={[measured()]} />);
    expect(screen.getByText(en.proofState.label.static_confirmed)).toBeTruthy();
    expect(container.textContent).not.toMatch(/unknown|not recorded|static_bytes/i);
  });

  it('marks a row whose subject was not the firmware as shipped, without lowering its rung', () => {
    render(
      <FindingsLedger
        findings={[
          measured({
            proofState: 'confirmed_in_emulation',
            evidenceChannel: 'probe_response',
            interventions: ['guest firewall rules flushed before boot'],
          }),
        ]}
      />,
    );
    // Printed verbatim: the intervention qualifies the claim, it does not downgrade it. Those are different acts
    // and conflating them would be the mirror of the dispute rule above.
    expect(screen.getByText(en.proofState.label.confirmed_in_emulation)).toBeTruthy();
    expect(screen.getByText(/not as shipped/i)).toBeTruthy();
    // The provider's own words survive, in the tooltip, rather than being summarised into a category.
    expect(screen.getByTitle('guest firewall rules flushed before boot')).toBeTruthy();
  });
});
