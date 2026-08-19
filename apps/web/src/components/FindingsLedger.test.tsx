import { fireEvent, render, screen } from '@testing-library/react';
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
    // Third cell: the reasoning toggle took column one and severity moved to two. Queried by position because
    // the ORDER of the rows is what is under test, and that is exactly what a position query asserts.
    const titles = Array.from(document.querySelectorAll('tbody tr td:nth-child(3)')).map((td) =>
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

/**
 * A retracted assertion.
 *
 * The row printed "— WITHDRAWN" beside the author, and the chevron expanded the assertion's ORIGINAL rationale —
 * so the only prose a reader could reach was the argument FOR a claim that no longer stands, and the reason it
 * was taken back was in the data and nowhere on screen.
 */
describe('FindingsLedger — a retraction is readable without a click', () => {
  const withdrawn = (assertion: Record<string, unknown>) =>
    measured({
      id: 'w1',
      title: 'That handler is compiled out of this build',
      rationale: 'I traced the symbol and found no caller.',
      proofState: 'operator_assertion',
      assertion: {
        assertedBy: 'aaron',
        authorKind: 'human',
        assertedAt: 1_700_000_000_000,
        claim: 'asserted_unverified',
        rationale: 'I traced the symbol and found no caller.',
        status: 'withdrawn',
        ...assertion,
      },
    });

  it('names the reason and the person who withdrew it, on the row itself', () => {
    render(
      <FindingsLedger
        findings={[withdrawn({ withdrawnBy: 'aaron', withdrawnReason: 'I was reading the wrong build' })]}
      />,
    );
    expect(screen.getByText(/withdrawn by aaron:/)).toBeTruthy();
    expect(screen.getByText(/I was reading the wrong build/)).toBeTruthy();
  });

  it('says a retraction recorded no reason, rather than looking like no retraction', () => {
    render(<FindingsLedger findings={[withdrawn({ withdrawnBy: 'aaron' })]} />);
    expect(screen.getByText(/withdrawn by aaron — no reason was recorded/)).toBeTruthy();
  });

  it('does not invent an author for a retraction that recorded none', () => {
    render(<FindingsLedger findings={[withdrawn({ withdrawnReason: 'could not reproduce' })]} />);
    expect(screen.getByText(/withdrawn by an unrecorded author:/)).toBeTruthy();
  });

  it('labels the expanded reasoning as the RETRACTED claim’s, not as a standing argument', () => {
    render(<FindingsLedger findings={[withdrawn({ withdrawnBy: 'aaron', withdrawnReason: 'wrong build' })]} />);
    fireEvent.click(screen.getByRole('button', { name: /Show why this finding sits at this proof state/ }));
    expect(screen.getByText('Why this state — for the claim that was retracted')).toBeTruthy();
    expect(screen.getByText(/I traced the symbol and found no caller/)).toBeTruthy();
  });

  it('leaves a standing assertion’s label and row alone', () => {
    const standing = withdrawn({});
    const live = { ...standing, assertion: { ...standing.assertion, status: 'active' } };
    render(<FindingsLedger findings={[live as never]} />);
    expect(screen.queryByText(/withdrawn by/)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /Show why this finding sits at this proof state/ }));
    expect(screen.getByText('Why this state')).toBeTruthy();
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

describe('FindingsLedger — analyst controls', () => {
  const rows = [
    measured({ id: 'critical', severity: 'critical', title: 'Remote command execution', source: 'symreach' }),
    measured({
      id: 'lead',
      severity: 'medium',
      title: 'Possible unsafe parser',
      source: 'yarascan',
      proofState: 'needs_runtime_reproduction',
    }),
  ];

  it('filters to priority findings without hiding the corpus-wide severity summary', () => {
    render(<FindingsLedger findings={rows} />);
    fireEvent.click(screen.getByRole('button', { name: 'Critical + high' }));
    expect(screen.getByText('Remote command execution')).toBeInTheDocument();
    expect(screen.queryByText('Possible unsafe parser')).not.toBeInTheDocument();
    expect(screen.getByText('1 of 2')).toBeInTheDocument();
    expect(screen.getByText('1 medium (all unproven)')).toBeInTheDocument();
  });

  it('searches evidence metadata as well as the visible title', () => {
    render(<FindingsLedger findings={rows} />);
    fireEvent.change(screen.getByRole('searchbox', { name: 'Search findings' }), { target: { value: 'yarascan' } });
    expect(screen.queryByText('Remote command execution')).not.toBeInTheDocument();
    expect(screen.getByText('Possible unsafe parser')).toBeInTheDocument();
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

/**
 * The reasoning disclosure. `rationale` is the sentence saying WHY a finding sits at its proof state — the
 * difference between "this is a lead" and "this is a lead BECAUSE the bounded search expired" — and it reached
 * the reader on operator disputes only. 98% of the rows in the real corpus carry one, median ~200 characters, so
 * it opens rather than prints.
 */
describe('FindingsLedger — why a finding sits where it does', () => {
  const why = 'The bounded symbolic search did not reach this sink before it stopped.';

  it('does not print the reasoning until it is asked for', () => {
    render(<FindingsLedger findings={[measured({ rationale: why })]} />);
    expect(screen.queryByText(new RegExp(why))).not.toBeInTheDocument();
  });

  it('opens it under the row, verbatim, as the provider wrote it', () => {
    render(<FindingsLedger findings={[measured({ rationale: why })]} />);
    fireEvent.click(screen.getByRole('button', { name: /why this finding sits/i }));
    expect(screen.getByText(new RegExp(why))).toBeInTheDocument();
  });

  it('reports its state to assistive tech rather than only by a glyph', () => {
    render(<FindingsLedger findings={[measured({ rationale: why })]} />);
    const toggle = screen.getByRole('button', { name: /why this finding sits/i });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(toggle);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
  });

  it('offers NO toggle when the provider wrote no reasoning', () => {
    // An empty chevron would promise an explanation that does not exist, which is the same shape as an "unknown"
    // chip over a question nobody asked.
    render(<FindingsLedger findings={[measured()]} />);
    expect(screen.queryByRole('button', { name: /why this finding sits/i })).not.toBeInTheDocument();
  });

  it('opens one row without opening the others', () => {
    render(
      <FindingsLedger
        findings={[
          measured({ id: 'a', title: 'first', rationale: 'reason A' }),
          measured({ id: 'b', title: 'second', rationale: 'reason B' }),
        ]}
      />,
    );
    const toggles = screen.getAllByRole('button', { name: /why this finding sits/i });
    fireEvent.click(toggles[0] as HTMLElement);
    expect(screen.getByText(/reason A/)).toBeInTheDocument();
    expect(screen.queryByText(/reason B/)).not.toBeInTheDocument();
  });
});

describe('the two axes — how bad if true, and how much was established', () => {
  it('gives a lead and an established row of the same severity different marks', () => {
    // The defect: both rendered as the same red `●`, so the most emphatic mark in the table was on the rows the
    // workbench had established least. 48 of this corpus's 72 criticals are leads.
    render(
      <FindingsLedger
        findings={[
          measured({ id: 'a', severity: 'critical', proofState: 'static_confirmed', title: 'in the bytes' }),
          measured({
            id: 'b',
            severity: 'critical',
            proofState: 'needs_runtime_reproduction',
            title: 'a reason to look',
          }),
        ]}
      />,
    );
    expect(screen.getAllByRole('img', { name: 'critical — established' })).toHaveLength(1);
    expect(screen.getAllByRole('img', { name: 'critical if true — not established' })).toHaveLength(1);
  });

  it('states both axes in words, so the distinction is not carried by fill alone', () => {
    render(<FindingsLedger findings={[measured({ severity: 'high', proofState: 'blocked_by_platform' })]} />);
    // A block is a question that could not be answered — it must not read as established.
    expect(screen.getByRole('img', { name: 'high if true — not established' })).toBeInTheDocument();
  });

  it('splits every severity band into established and unproven above the table', () => {
    render(
      <FindingsLedger
        findings={[
          measured({ id: 'a', severity: 'critical', proofState: 'static_confirmed' }),
          measured({ id: 'b', severity: 'critical', proofState: 'needs_runtime_reproduction' }),
          measured({ id: 'c', severity: 'critical', proofState: 'needs_runtime_reproduction' }),
        ]}
      />,
    );
    expect(screen.getByText('3 critical (1 established, 2 unproven)')).toBeInTheDocument();
  });

  it('says outright when a whole band is unproven', () => {
    render(
      <FindingsLedger findings={[measured({ severity: 'critical', proofState: 'needs_runtime_reproduction' })]} />,
    );
    expect(screen.getByText('1 critical (all unproven)')).toBeInTheDocument();
  });

  it('censuses the whole ledger, not the rows that happened to fit under the cap', () => {
    const many = Array.from({ length: 320 }, (_, i) =>
      measured({ id: `f${i}`, severity: 'low', proofState: 'needs_runtime_reproduction', title: `row ${i}` }),
    );
    render(<FindingsLedger findings={many} />);
    expect(screen.getByText('320 low (all unproven)')).toBeInTheDocument();
  });

  it('carries the legend that makes the fill readable, rather than leaving it to be inferred', () => {
    render(<FindingsLedger findings={[measured()]} />);
    expect(screen.getByText(/how bad a row would be if true, never that it was established/i)).toBeInTheDocument();
  });

  it('orders a severity tie by the ladder, not by the alphabet', () => {
    // `a.proofState < b.proofState` put `blocked_by_platform` above `confirmed_full_system` because 'b' < 'c'.
    const view = selectLedgerRows(
      [
        measured({ id: 'a', severity: 'high', proofState: 'blocked_by_platform', title: 'blocked' }),
        measured({ id: 'b', severity: 'high', proofState: 'confirmed_full_system', title: 'booted' }),
      ],
      new Set(),
    );
    expect(view.rows.map((r) => r.proofState)).toEqual(['confirmed_full_system', 'blocked_by_platform']);
  });

  it('prints no census at all for an empty ledger rather than a row of zeroes', () => {
    render(<FindingsLedger findings={[]} />);
    expect(screen.queryByText(/established,/)).not.toBeInTheDocument();
  });
});
