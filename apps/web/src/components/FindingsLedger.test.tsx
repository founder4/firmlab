import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Finding } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import {
  FindingsLedger,
  SHAPE_ELISION,
  danglingDisputes,
  groupLabel,
  groupLedgerRows,
  indexDisputes,
  isFoldable,
  selectLedgerRows,
  titleShape,
} from './FindingsLedger';

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
    expect(screen.getByText('1 medium: 1 lead')).toBeInTheDocument();
  });

  it('searches evidence metadata as well as the visible title', () => {
    render(<FindingsLedger findings={rows} />);
    fireEvent.change(screen.getByRole('searchbox', { name: 'Search findings' }), { target: { value: 'yarascan' } });
    expect(screen.queryByText('Remote command execution')).not.toBeInTheDocument();
    expect(screen.getByText('Possible unsafe parser')).toBeInTheDocument();
  });

  it('gives a lead and a blocked question separate filters with the same definitions as the census', () => {
    const blocked = measured({
      id: 'blocked',
      severity: 'info',
      title: 'No readable device tree in this image',
      source: 'devicetree',
      proofState: 'blocked_by_platform',
    });
    render(<FindingsLedger findings={[...rows, blocked]} />);

    fireEvent.click(screen.getByRole('button', { name: 'Leads' }));
    expect(screen.getByText('Possible unsafe parser')).toBeInTheDocument();
    expect(screen.queryByText('No readable device tree in this image')).not.toBeInTheDocument();
    expect(screen.queryByText('Remote command execution')).not.toBeInTheDocument();
    expect(screen.getByText('1 of 3')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Blocked' }));
    expect(screen.getByText('No readable device tree in this image')).toBeInTheDocument();
    expect(screen.queryByText('Possible unsafe parser')).not.toBeInTheDocument();
    expect(screen.getByText('1 of 3')).toBeInTheDocument();
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

  it('splits every severity band into its semantic categories above the table', () => {
    render(
      <FindingsLedger
        findings={[
          measured({ id: 'a', severity: 'critical', proofState: 'static_confirmed' }),
          measured({ id: 'b', severity: 'critical', proofState: 'needs_runtime_reproduction' }),
          measured({ id: 'c', severity: 'critical', proofState: 'needs_runtime_reproduction' }),
        ]}
      />,
    );
    expect(screen.getByText('3 critical: 1 established · 2 leads')).toBeInTheDocument();
  });

  it('says outright when a whole band is leads', () => {
    render(
      <FindingsLedger findings={[measured({ severity: 'critical', proofState: 'needs_runtime_reproduction' })]} />,
    );
    expect(screen.getByText('1 critical: 1 lead')).toBeInTheDocument();
  });

  it('censuses the whole ledger, not the rows that happened to fit under the cap', () => {
    const many = Array.from({ length: 320 }, (_, i) =>
      measured({ id: `f${i}`, severity: 'low', proofState: 'needs_runtime_reproduction', title: `row ${i}` }),
    );
    render(<FindingsLedger findings={many} />);
    expect(screen.getByText('320 low: 320 leads')).toBeInTheDocument();
  });

  it('counts and filters dismissals and operator assertions instead of hiding them under an aggregate', () => {
    const dismissed = measured({ id: 'dismissed', title: 'Disproved candidate', proofState: 'false_positive' });
    const asserted = dispute('missing', {
      id: 'asserted',
      title: 'Observed on a physical unit',
      severity: 'high',
      assertion: {
        assertedBy: 'aaron',
        authorKind: 'human',
        assertedAt: 1,
        claim: 'asserted_unverified',
        rationale: 'Observed on the bench.',
        status: 'active',
      },
    });
    render(<FindingsLedger findings={[dismissed, asserted]} />);
    expect(screen.getByText('2 high: 1 dismissed · 1 asserted')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Dismissed' }));
    expect(screen.getByText('Disproved candidate')).toBeInTheDocument();
    expect(screen.queryByText('Observed on a physical unit')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Assertions' }));
    expect(screen.getByText('Observed on a physical unit')).toBeInTheDocument();
    expect(screen.queryByText('Disproved candidate')).not.toBeInTheDocument();
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

/**
 * The fold, exercised against the titles that motivated it.
 *
 * The fixtures below are the REAL titles from DVRF (`57c12e70`), not invented ones: CLAUDE.md's own record of this
 * codebase's traps says a test whose fixture was written from the same assumption as the code proves only that the
 * two agree. `Stack-overflow candidate: … imports sprintf …` and `… imports sscanf …` are in here specifically
 * because they must NOT collapse together.
 */
describe('FindingsLedger — a run of rows saying one thing about many subjects', () => {
  const canary = (path: string, fn: string, id: string): Finding =>
    measured({
      id,
      source: 'binvuln',
      severity: 'medium',
      proofState: 'needs_runtime_reproduction',
      title: `Stack-overflow candidate: ${path} imports ${fn} with no stack canary`,
    });

  const sprintfRun = [
    canary('sbin/store_domain_sid', 'sprintf', 'c1'),
    canary('sbin/store_machine_password', 'sprintf', 'c2'),
    canary('sbin/diag_tracertbutton', 'sprintf', 'c3'),
  ];

  it('masks the subject but never an ordinary word, so two unsafe functions stay two shapes', () => {
    expect(titleShape('Stack-overflow candidate: sbin/store_domain_sid imports sprintf with no stack canary')).toBe(
      `Stack-overflow candidate: ${SHAPE_ELISION} imports sprintf with no stack canary`,
    );
    // The whole reason the mask is conservative: sprintf and sscanf are different findings about different calls.
    expect(
      titleShape('Stack-overflow candidate: usr/lib/libxt_CLASSIFY.so imports sscanf with no stack canary'),
    ).not.toBe(titleShape('Stack-overflow candidate: sbin/store_domain_sid imports sprintf with no stack canary'));
  });

  it('masks versions, CVE ids and digests — the tokens that name a subject rather than describe it', () => {
    expect(titleShape('CVE-2011-5325 — busybox 1.7.2')).toBe(titleShape('CVE-2013-1813 — busybox 1.7.2'));
    // A different component is a different statement and must not fold into the same group.
    expect(titleShape('CVE-2011-5325 — busybox 1.7.2')).not.toBe(titleShape('CVE-2011-5325 — dropbear 2015.67'));
  });

  it('folds a run into one line and reaches every row behind it', () => {
    const g = groupLedgerRows(sprintfRun, new Set());
    expect(g.groups).toHaveLength(1);
    expect(g.groups[0]?.folded).toBe(true);
    expect(g.groups[0]?.members.map((m) => m.id)).toEqual(['c1', 'c2', 'c3']);
    expect(g.foldedRows).toBe(3);
    // Nothing is dropped: the members of every group put back together are exactly the rows that went in.
    expect(g.groups.flatMap((x) => x.members)).toHaveLength(sprintfRun.length);
  });

  it('leaves a pair alone — below the threshold, folding hides more than it saves', () => {
    const g = groupLedgerRows(sprintfRun.slice(0, 2), new Set());
    expect(g.groups.every((x) => !x.folded)).toBe(true);
    expect(g.rule).toBeNull();
  });

  it('says nothing at all when no row repeats — the path nobody runs', () => {
    const g = groupLedgerRows(
      [measured({ id: 'a', title: 'Shipped TLS identity is forgeable: holds a private key' })],
      new Set(),
    );
    expect(g.rule).toBeNull();
    expect(g.foldedRows).toBe(0);
    expect(g.groups).toHaveLength(1);
    expect(g.groups[0]?.folded).toBe(false);
  });

  it('never folds a contested row, an assertion, or a row obtained against an altered subject', () => {
    const contested = canary('sbin/a', 'sprintf', 'x1');
    const withIntervention = canary('sbin/b', 'sprintf', 'x2');
    withIntervention.interventions = ['patched /etc/passwd'];
    const asserted = canary('sbin/c', 'sprintf', 'x3');
    asserted.assertion = {
      assertedBy: 'aaron',
      authorKind: 'human',
      assertedAt: 1,
      claim: 'asserted_unverified',
      rationale: 'r',
      status: 'active',
    };
    const g = groupLedgerRows([contested, withIntervention, asserted], new Set(['x1']));
    // Three exempt rows cannot form a group of three, however identical their shapes are.
    expect(g.groups).toHaveLength(3);
    expect(g.groups.every((x) => !x.folded)).toBe(true);
    expect(isFoldable(contested, new Set(['x1']))).toBe(false);
    expect(isFoldable(withIntervention, new Set())).toBe(false);
    expect(isFoldable(asserted, new Set())).toBe(false);
  });

  it('keeps a group at the position its members held — folding redraws, it never reorders', () => {
    const critical = measured({ id: 'crit', severity: 'critical', title: 'Shipped TLS identity is forgeable' });
    const info = measured({
      id: 'info',
      severity: 'info',
      proofState: 'needs_runtime_reproduction',
      title: 'Command-exec sink: sbin/other imports system',
    });
    const rows = [critical, ...sprintfRun, info];
    const g = groupLedgerRows(rows, new Set());
    // critical first, the medium group where its members were, the info row last: the order compareFindings gave.
    expect(g.groups.map((x) => x.lead.id)).toEqual(['crit', 'c1', 'info']);
  });

  it('labels a group from what its members agree on, not from the mask', () => {
    const cves = [
      measured({ id: 'v1', severity: 'high', title: 'CVE-2011-5325 — busybox 1.7.2' }),
      measured({ id: 'v2', severity: 'high', title: 'CVE-2013-1813 — busybox 1.7.2' }),
      measured({ id: 'v3', severity: 'high', title: 'CVE-2016-2147 — busybox 1.7.2' }),
    ];
    // The mask keys them together but reads as `⋯ — busybox ⋯`, which names neither the component version nor
    // what actually varies. The label is a fact about these three rows instead.
    expect(titleShape(cves[0]?.title ?? '')).toBe(`${SHAPE_ELISION} — busybox ${SHAPE_ELISION}`);
    expect(groupLabel(cves)).toBe(`${SHAPE_ELISION} — busybox 1.7.2`);
  });

  it('keeps the elision where members genuinely disagree, rather than picking one to show', () => {
    const mixed = [
      canary('usr/lib/l2tp/cmd.so', 'sprintf/sscanf', 'm1'),
      canary('lib/libcrypt.so.0', 'strcpy/strcat', 'm2'),
      canary('sbin/wan_auto_detect', 'strcpy/sscanf', 'm3'),
    ];
    // Two positions vary, so two stay elided: this group really is "several binaries importing several unsafe
    // functions", and naming one member's functions in the header would misrepresent the other two.
    expect(groupLabel(mixed)).toBe(
      `Stack-overflow candidate: ${SHAPE_ELISION} imports ${SHAPE_ELISION} with no stack canary`,
    );
  });

  it('prints a single row’s title untouched, and falls back to the shape when titles do not align', () => {
    expect(groupLabel([measured({ title: 'Kernel 2.6.22 — the 2.6 series is 22 years old' })])).toBe(
      'Kernel 2.6.22 — the 2.6 series is 22 years old',
    );
    const ragged = [
      measured({ id: 'r1', title: 'Expired certificate: localhost' }),
      measured({ id: 'r2', title: 'Expired certificate: PolarSSL Test CA' }),
    ];
    // Different token counts cannot be compared position by position; the shape is the honest fallback.
    expect(groupLabel(ragged)).toBe(titleShape('Expired certificate: localhost'));
  });

  it('states what it folded, and states that it dropped nothing', () => {
    const g = groupLedgerRows(sprintfRun, new Set());
    expect(g.rule).toBe(en.findings.foldRule(3, 1, 3));
    expect(g.rule).toContain('drops no row and reorders none');
  });

  it('draws the run as a single line, and expands it to the real titles on demand', () => {
    render(<FindingsLedger findings={sprintfRun} />);
    // Folded: the shared shape is on screen and no subject is.
    expect(screen.queryByText(/store_domain_sid/)).toBeNull();
    expect(screen.getByText(/imports sprintf with no stack canary/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: en.findings.group.toggle(3, false) }));
    expect(screen.getByText(/sbin\/store_domain_sid imports sprintf/)).toBeTruthy();
    expect(screen.getByText(/sbin\/diag_tracertbutton imports sprintf/)).toBeTruthy();
  });

  it('renders a member through the same row component, so a dispute inside a group still annotates', () => {
    const target = sprintfRun[0];
    if (!target) throw new Error('fixture');
    const rows = [...sprintfRun, dispute(target.id)];
    render(<FindingsLedger findings={rows} />);
    // The contested member is exempt, so it is drawn outside the group and its annotation is visible unexpanded.
    expect(screen.getByText(/asserts on/)).toBeTruthy();
    expect(screen.getByText(/sbin\/store_domain_sid imports sprintf/)).toBeTruthy();
  });

  it('states the fold in Spanish without turning it into the cut', () => {
    setLocale('es');
    const g = groupLedgerRows(sprintfRun, new Set());
    expect(g.rule).toContain('no descarta ninguna fila ni reordena ninguna');
    expect(g.rule).not.toContain('descartaron');
    setLocale('en');
  });
});
