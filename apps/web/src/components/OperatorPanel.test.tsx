import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type AssertedFinding, type AssertionRevision, type OperatorLedger, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { OperatorPanel, revisionsOf } from './OperatorPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const asserted = (o: Partial<AssertedFinding> = {}): AssertedFinding => ({
  id: 'a1',
  imageId: 'img1',
  source: 'operator:aaron',
  kind: 'asserted_from_device',
  title: 'Telnet root shell on the shipped unit',
  severity: 'high',
  proofState: 'operator_assertion',
  rationale: 'Logged in on hardware rev B.',
  createdAt: 1_700_000_000_000,
  attribution: 'Asserted by aaron on 2023-11-14 (asserted_from_device).',
  assertion: {
    assertedBy: 'aaron',
    authorKind: 'human',
    assertedAt: 1_700_000_000_000,
    claim: 'asserted_from_device',
    rationale: 'Logged in on hardware rev B.',
    status: 'active',
  },
  ...o,
});

const ledger = (o: Partial<OperatorLedger> = {}): OperatorLedger => ({
  notAMeasurement: 'This row was asserted by a named author, not measured by FirmLab.',
  claimMeanings: {
    asserted_unverified: 'a',
    asserted_from_device: 'b',
    asserted_from_external_evidence: 'c',
    disputes_finding: 'd',
  },
  measuredFindingCount: 101,
  assertions: [],
  withdrawn: [],
  ...o,
});

function mount(l: OperatorLedger = ledger()) {
  mockApi.operatorLedger.mockResolvedValue(l);
  mockApi.notes.mockResolvedValue([]);
  return render(<OperatorPanel imageId="img1" />);
}

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
});

describe('OperatorPanel — the form cannot express a proof state', () => {
  it('offers claims, and no proof-state control of any kind', async () => {
    mount();
    await screen.findByLabelText('On what basis');
    const basis = screen.getByLabelText('On what basis') as HTMLSelectElement;
    const options = Array.from(basis.options).map((o) => o.value);
    expect(options).toEqual([
      'asserted_unverified',
      'asserted_from_device',
      'asserted_from_external_evidence',
      'disputes_finding',
    ]);
    // Not disabled, not warned — absent. The ladder is not part of this form's vocabulary.
    for (const rung of ['static_confirmed', 'needs_runtime_reproduction', 'confirmed_in_emulation']) {
      expect(options).not.toContain(rung);
      expect(screen.queryByText(rung)).toBeNull();
    }
  });

  it('sends no proofState field when recording, only a claim', async () => {
    mount();
    mockApi.addAssertion.mockResolvedValue({ finding: asserted(), attribution: 'x' });
    fireEvent.change(await screen.findByLabelText('Who is asserting this'), { target: { value: 'aaron' } });
    fireEvent.change(screen.getByLabelText('The claim'), { target: { value: 'Telnet root shell' } });
    fireEvent.change(screen.getByLabelText('On what basis'), { target: { value: 'asserted_from_device' } });
    fireEvent.change(screen.getByLabelText('Stated basis'), { target: { value: 'Logged in on rev B.' } });
    fireEvent.click(screen.getByRole('button', { name: 'Record assertion' }));
    await waitFor(() => expect(mockApi.addAssertion).toHaveBeenCalled());
    const body = mockApi.addAssertion.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(body.proofState).toBeUndefined();
    expect(body.claim).toBe('asserted_from_device');
    expect(body.assertedBy).toBe('aaron');
  });

  it('will not record without a stated basis', async () => {
    mount();
    fireEvent.change(await screen.findByLabelText('Who is asserting this'), { target: { value: 'aaron' } });
    fireEvent.change(screen.getByLabelText('The claim'), { target: { value: 'something' } });
    expect(screen.getByRole('button', { name: 'Record assertion' })).toBeDisabled();
  });

  it('surfaces the route’s refusal verbatim rather than a status code', async () => {
    mount();
    mockApi.addAssertion.mockRejectedValue(
      new Error("'static_confirmed' is a PROOF STATE, and only code may decide one"),
    );
    fireEvent.change(await screen.findByLabelText('Who is asserting this'), { target: { value: 'aaron' } });
    fireEvent.change(screen.getByLabelText('The claim'), { target: { value: 'x' } });
    fireEvent.change(screen.getByLabelText('Stated basis'), { target: { value: 'because' } });
    fireEvent.click(screen.getByRole('button', { name: 'Record assertion' }));
    await waitFor(() => expect(screen.getByText(/only code may decide one/)).toBeTruthy());
  });
});

describe('OperatorPanel — an assertion never reads as a measurement', () => {
  it('badges the row as asserted and names its author, never as a proof state', async () => {
    mount(ledger({ assertions: [asserted()] }));
    await waitFor(() => expect(screen.getByText('asserted · not measured')).toBeTruthy());
    expect(screen.getByText(/Asserted by aaron on 2023-11-14/)).toBeTruthy();
    expect(screen.queryByText('static-confirmed')).toBeNull();
  });

  it('states the caveat the API serves, so the UI cannot word it differently', async () => {
    mount(ledger({ assertions: [asserted()] }));
    await waitFor(() => expect(screen.getByText(/asserted by a named author, not measured by FirmLab/)).toBeTruthy());
  });

  it('reports the measured count separately, so the two are never read as one total', async () => {
    mount(ledger({ assertions: [asserted()] }));
    await waitFor(() => expect(screen.getByText(/101 measured finding\(s\)/)).toBeTruthy());
  });
});

describe('OperatorPanel — withdrawal is first-class', () => {
  it('keeps a withdrawn claim visible with its reason instead of deleting it', async () => {
    const w = asserted({
      id: 'a2',
      attribution: 'WITHDRAWN by aaron: written from a filename without opening the file.',
      assertion: {
        assertedBy: 'aaron',
        authorKind: 'human',
        assertedAt: 1_700_000_000_000,
        claim: 'asserted_unverified',
        rationale: 'r',
        status: 'withdrawn',
        withdrawnBy: 'aaron',
        withdrawnReason: 'written from a filename without opening the file',
      },
    });
    mount(ledger({ withdrawn: [w] }));
    await waitFor(() => expect(screen.getByText(/Withdrawn \(1\)/)).toBeTruthy());
    expect(screen.getByText(/written from a filename without opening the file/)).toBeTruthy();
    expect(screen.getByText('withdrawn')).toBeTruthy();
  });

  it('offers no way to delete an assertion — only to withdraw one', async () => {
    mount(ledger({ assertions: [asserted()] }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Withdraw' })).toBeTruthy());
    expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull();
  });
});

describe('OperatorPanel — an amendment appends, and the panel shows what it replaced', () => {
  const amended = (supersedes: AssertionRevision[] | undefined) =>
    asserted({
      id: 'a3',
      title: 'The dev board shipped with telnet open as root',
      attribution: 'Asserted by aaron on 2023-11-14 (asserted_from_device). Amended 2023-11-20',
      rationale: 'Narrowed to the dev board after re-checking a retail unit.',
      assertion: {
        assertedBy: 'aaron',
        authorKind: 'human',
        assertedAt: 1_700_000_000_000,
        claim: 'asserted_from_device',
        rationale: 'Narrowed to the dev board after re-checking a retail unit.',
        status: 'active',
        amendedAt: 1_700_500_000_000,
        title: 'The dev board shipped with telnet open as root',
        ...(supersedes ? { supersedes } : {}),
      },
    });

  const revision: AssertionRevision = {
    claim: 'asserted_from_device',
    rationale: 'Telnet answered as root on the unit I was sent.',
    title: 'Every shipped unit has telnet open as root',
    from: 1_700_000_000_000,
    supersededAt: 1_700_500_000_000,
  };

  it('offers the history behind its own affordance rather than beside the claim that stands', async () => {
    mount(ledger({ assertions: [amended([revision])] }));
    const toggle = await screen.findByRole('button', { name: /Amended 2023-11-20 — show 1 superseded claim/ });
    // Collapsed: the superseded sentence is nowhere on screen, so it cannot be read as a second live claim.
    expect(screen.queryByText(/Every shipped unit has telnet open as root/)).toBeNull();
    fireEvent.click(toggle);
    expect(screen.getByText(/History — superseded, no longer claimed/)).toBeTruthy();
    expect(screen.getByText(/Every shipped unit has telnet open as root/)).toBeTruthy();
    expect(screen.getByText(/Telnet answered as root on the unit I was sent/)).toBeTruthy();
    expect(screen.getByText(/stood from 2023-11-14 to 2023-11-20/)).toBeTruthy();
    // Labelled as superseded, never with the live "asserted" badge the current claim carries.
    expect(screen.getByText(/superseded · asserted_from_device/)).toBeTruthy();
    expect(screen.getByText(/An amendment appends; it never overwrites/)).toBeTruthy();
  });

  it('reads as "no history" for a row amended by a build that did not keep the predecessor', async () => {
    mount(ledger({ assertions: [amended(undefined)] }));
    await waitFor(() => expect(screen.getByText(/No history is readable/)).toBeTruthy());
    expect(screen.getByText(/overwrote its predecessor/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /show 1 superseded/ })).toBeNull();
  });

  it('shows no history affordance at all on a claim that was never amended', async () => {
    mount(ledger({ assertions: [asserted()] }));
    await waitFor(() => expect(screen.getByText('asserted · not measured')).toBeTruthy());
    expect(screen.queryByText(/superseded/i)).toBeNull();
    expect(screen.queryByText(/No history is readable/)).toBeNull();
  });

  it('reads a malformed or absent supersedes defensively instead of throwing', () => {
    expect(revisionsOf(undefined)).toEqual([]);
    const bad = { supersedes: 'not an array' } as unknown as AssertedFinding['assertion'];
    expect(revisionsOf(bad)).toEqual([]);
    const holes = {
      supersedes: [null, 7, { claim: 'asserted_unverified' }],
    } as unknown as AssertedFinding['assertion'];
    expect(revisionsOf(holes)).toEqual([{ claim: 'asserted_unverified' }]);
  });

  it('states a revision whose fields an older build never wrote, rather than dropping it', async () => {
    mount(ledger({ assertions: [amended([{ claim: 'asserted_unverified' }])] }));
    const toggle = await screen.findByRole('button', { name: /show 1 superseded claim/ });
    fireEvent.click(toggle);
    expect(screen.getByText(/superseded · asserted_unverified/)).toBeTruthy();
    expect(screen.getByText(/No basis was recorded with this revision/)).toBeTruthy();
    expect(screen.getByText(/stood from an unrecorded date to an unrecorded date/)).toBeTruthy();
  });

  /**
   * In Spanish the history has to stay history. A superseded claim rendered in the present tense is a second live
   * claim to anyone skimming, which is the erasure this ledger refuses — and the row must still carry no proof
   * state, only the shared asserted gloss.
   */
  it('keeps the superseded history from reading as a live claim in Spanish', async () => {
    setLocale('es');
    mount(ledger({ assertions: [amended([revision])] }));
    const toggle = await screen.findByRole('button', {
      name: /Enmendada el 2023-11-20 — ver 1 afirmación sustituida/,
    });
    // Collapsed, the superseded claim is nowhere on screen — it cannot be weighed beside the one that stands.
    expect(screen.queryByText(/Every shipped unit has telnet open as root/)).toBeNull();
    fireEvent.click(toggle);

    expect(screen.getByText('Histórico — sustituidas, ya no se afirman')).toBeTruthy();
    expect(screen.getByText(/Una enmienda añade; nunca sobrescribe/)).toBeTruthy();
    expect(screen.getByText(/Nada de lo de abajo se sostiene/)).toBeTruthy();
    expect(screen.getByText(/vigente de 2023-11-14 a 2023-11-20/)).toBeTruthy();
    // The claim CODE is an identifier and survives; the badge is the shared gloss, never a proof-state rung.
    expect(screen.getByText(/sustituida · asserted_from_device/)).toBeTruthy();
    expect(screen.getByText('afirmado · no medido')).toBeTruthy();
    expect(screen.queryByText('confirmado en los bytes')).toBeNull();
    // The author's own words, and the attribution the API serves, are the record and are shown as written.
    expect(screen.getByText(/Every shipped unit has telnet open as root/)).toBeTruthy();
    expect(screen.getByText(/Asserted by aaron on 2023-11-14/)).toBeTruthy();
  });
});

/**
 * The form cannot express a proof state in any language: the ladder is absent from its vocabulary, not disabled in
 * it, and the panel-sub still states the three things an assertion is not.
 */
describe('OperatorPanel — Spanish', () => {
  it('offers claims and no proof state, and says an assertion covers no stage', async () => {
    setLocale('es');
    mount(ledger({ assertions: [asserted()] }));

    const basis = (await screen.findByLabelText('Con qué base')) as HTMLSelectElement;
    expect(Array.from(basis.options).map((o) => o.value)).toEqual([
      'asserted_unverified',
      'asserted_from_device',
      'asserted_from_external_evidence',
      'disputes_finding',
    ]);
    for (const rung of ['static_confirmed', 'needs_runtime_reproduction', 'confirmed_in_emulation']) {
      expect(screen.queryByText(rung)).toBeNull();
    }
    const text = document.body.textContent ?? '';
    expect(text).toContain('No llevan estado de prueba, no cuentan para ninguna etapa del análisis');
    expect(text).toContain('sólo se retiran, dejando dicho el motivo');
    expect(screen.getByText(/101 hallazgo\(s\) medido\(s\)/)).toBeTruthy();
    // The severity option is the CODE, because that is what is submitted and stored.
    const sev = screen.getByLabelText('Gravedad afirmada') as HTMLSelectElement;
    expect(Array.from(sev.options).map((o) => o.text)).toEqual(['info', 'low', 'medium', 'high', 'critical']);
    // The caveat the API serves wins over the local fallback, in Spanish as in English.
    expect(screen.getByText(/asserted by a named author, not measured by FirmLab/)).toBeTruthy();
  });
});

describe('OperatorPanel — notes are not findings', () => {
  it('says so on the panel, and allows deletion precisely because nobody relied on one', async () => {
    mockApi.operatorLedger.mockResolvedValue(ledger());
    mockApi.notes.mockResolvedValue([
      { id: 'n1', imageId: 'img1', author: 'aaron', body: 'check the second partition', createdAt: 1, updatedAt: 1 },
    ]);
    render(<OperatorPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/never rendered as findings/)).toBeTruthy());
    expect(screen.getByText('check the second partition')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeTruthy();
  });
});
