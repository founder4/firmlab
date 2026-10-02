import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type AssertedFinding,
  type AssertionRevision,
  type ImageNote,
  type OperatorLedger,
  type RetireFindingsResult,
  api,
} from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import {
  MAX_NOTE,
  MAX_NOTE_AUTHOR,
  MAX_NOTE_EDIT,
  MAX_RETIRE_REASON,
  MAX_RETIRE_SOURCE,
  OperatorPanel,
  noteAuthorTooLong,
  noteBodyProblem,
  retireProblem,
  revisionsOf,
} from './OperatorPanel';

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
    mockApi.addAssertion.mockClear();
    mount();
    fireEvent.change(await screen.findByLabelText('Who is asserting this'), { target: { value: 'aaron' } });
    fireEvent.change(screen.getByLabelText('The claim'), { target: { value: 'something' } });
    fireEvent.click(screen.getByRole('button', { name: 'Record assertion' }));
    expect(mockApi.addAssertion).not.toHaveBeenCalled();
    // The click names what is missing instead of a disabled button that says nothing.
    expect(screen.getByRole('alert')).toHaveTextContent('Stated basis');
    expect(screen.getByLabelText('Stated basis')).toHaveAttribute('aria-invalid', 'true');
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

/**
 * The writer for a history this panel could already display. `api.amendAssertion` existed with the right shape, the
 * route existed, `revisionsOf` rendered every superseded revision — and nothing in the app could produce one.
 */
describe('amending an assertion — the ledger gets a writer, and refuses a change that is not one', () => {
  const assertion = {
    id: 'f1',
    title: 'The telnet daemon is compiled out of this build',
    severity: 'medium' as const,
    rationale: 'I read the applet table on the retail unit.',
    attribution: 'Asserted by aaron on 2026-07-30 (asserted_from_device).',
    provenance: 'operator_assertion' as const,
    assertion: {
      assertedBy: 'aaron',
      assertedAt: 1_780_000_000_000,
      claim: 'asserted_from_device' as const,
      status: 'active' as const,
      authorKind: 'human' as const,
    },
  };

  beforeEach(() => {
    setLocale('en');
    mockedApi(api).operatorLedger.mockResolvedValue({ assertions: [assertion], withdrawn: [] });
    mockedApi(api).notes.mockResolvedValue([]);
    // Cleared, not just re-stubbed: a `not.toHaveBeenCalled()` that only passes because it runs before the tests
    // that DO call is an assertion about file order, not about the form.
    mockedApi(api).amendAssertion.mockClear();
    mockedApi(api).amendAssertion.mockResolvedValue(undefined as never);
  });

  it('offers an Amend action and opens a form pre-filled with what is stored', async () => {
    render(<OperatorPanel imageId="abc" />);
    fireEvent.click(await screen.findByText('Amend'));
    const form = await screen.findByTestId('amend-f1');
    expect(form).toBeTruthy();
    expect((screen.getByLabelText('amend-title') as HTMLInputElement).value).toBe(assertion.title);
    expect((screen.getByLabelText('amend-rationale') as HTMLTextAreaElement).value).toBe(assertion.rationale);
  });

  it('will not send an untouched form, and says why in its own words', async () => {
    render(<OperatorPanel imageId="abc" />);
    fireEvent.click(await screen.findByText('Amend'));
    await screen.findByTestId('amend-f1');
    expect(document.querySelector('[data-role="refusal-untouched"]')).toBeTruthy();
    expect(screen.getByText('Save amendment').getAttribute('disabled')).not.toBeNull();
    fireEvent.click(screen.getByText('Save amendment'));
    expect(mockedApi(api).amendAssertion).not.toHaveBeenCalled();
  });

  /** Same values as untouched, different event, different sentence — the distinction the pure diff exists for. */
  it('says a field retyped to the same text is not the same as having edited nothing', async () => {
    render(<OperatorPanel imageId="abc" />);
    fireEvent.click(await screen.findByText('Amend'));
    await screen.findByTestId('amend-f1');
    // Typed away and typed back — which is what retyping IS, and the only way to express it here: fireEvent.change
    // with the value already in the DOM fires no React onChange at all, so a single same-value change would have
    // tested nothing and passed as "untouched".
    const box = screen.getByLabelText('amend-rationale');
    fireEvent.change(box, { target: { value: 'something else entirely' } });
    fireEvent.change(box, { target: { value: assertion.rationale } });
    expect(document.querySelector('[data-role="refusal-retyped"]')).toBeTruthy();
    expect(document.querySelector('[data-role="refusal-untouched"]')).toBeNull();
    expect(mockedApi(api).amendAssertion).not.toHaveBeenCalled();
  });

  it('names the fields it is about to change before sending, and sends the trimmed values', async () => {
    render(<OperatorPanel imageId="abc" />);
    fireEvent.click(await screen.findByText('Amend'));
    await screen.findByTestId('amend-f1');
    fireEvent.change(screen.getByLabelText('amend-by'), { target: { value: 'nadia' } });
    fireEvent.change(screen.getByLabelText('amend-rationale'), { target: { value: '  I re-read it: it ships.  ' } });
    fireEvent.change(screen.getByLabelText('amend-severity'), { target: { value: 'high' } });
    expect(document.querySelector('[data-role="changing"]')?.textContent).toMatch(/rationale, severity/);
    fireEvent.click(screen.getByText('Save amendment'));
    await waitFor(() => expect(mockedApi(api).amendAssertion).toHaveBeenCalled());
    const [, findingId, body] = mockedApi(api).amendAssertion.mock.calls[0] as [
      string,
      string,
      Record<string, unknown>,
    ];
    expect(findingId).toBe('f1');
    expect(body.rationale).toBe('I re-read it: it ships.');
    expect(body.severity).toBe('high');
  });

  /**
   * The panel is driven BY somebody, and that somebody is not necessarily the author of the row they are editing.
   * The form asks who is amending, sends it, and sends no author kind at all — the transport stamps that, and a
   * body that offered one would be ignored.
   */
  it('sends the amender’s name, which is not the asserter’s, and never an author kind', async () => {
    render(<OperatorPanel imageId="abc" />);
    fireEvent.click(await screen.findByText('Amend'));
    await screen.findByTestId('amend-f1');
    fireEvent.change(screen.getByLabelText('amend-by'), { target: { value: '  nadia  ' } });
    fireEvent.change(screen.getByLabelText('amend-rationale'), { target: { value: 'It was the dev board.' } });
    fireEvent.click(screen.getByText('Save amendment'));
    await waitFor(() => expect(mockedApi(api).amendAssertion).toHaveBeenCalled());
    const [, , body] = mockedApi(api).amendAssertion.mock.calls[0] as [string, string, Record<string, unknown>];
    expect(body.amendedBy).toBe('nadia');
    expect(body.assertedBy).toBeUndefined();
    expect(body.authorKind).toBeUndefined();
    expect(body.amendedByKind).toBeUndefined();
  });

  it('refuses a real edit that nobody signed, and says what the record needs rather than naming a field', async () => {
    render(<OperatorPanel imageId="abc" />);
    fireEvent.click(await screen.findByText('Amend'));
    await screen.findByTestId('amend-f1');
    fireEvent.change(screen.getByLabelText('amend-rationale'), { target: { value: 'It was the dev board.' } });
    // A real change, so this is not the untouched refusal — it is the unsigned one, which reads differently.
    expect(document.querySelector('[data-role="refusal-unsigned"]')).toBeTruthy();
    expect(document.querySelector('[data-role="refusal-untouched"]')).toBeNull();
    expect(screen.getByText(/recorded beside the original author/)).toBeTruthy();
    expect(screen.getByText('Save amendment').getAttribute('disabled')).not.toBeNull();
    fireEvent.click(screen.getByText('Save amendment'));
    expect(mockedApi(api).amendAssertion).not.toHaveBeenCalled();
    // Whitespace is not a signature either.
    fireEvent.change(screen.getByLabelText('amend-by'), { target: { value: '   ' } });
    expect(document.querySelector('[data-role="refusal-unsigned"]')).toBeTruthy();
  });

  it('prefills the amender from who the panel is being driven as, not from the row’s author', async () => {
    render(<OperatorPanel imageId="abc" />);
    fireEvent.change(screen.getByLabelText('Who is asserting this'), { target: { value: 'nadia' } });
    fireEvent.click(await screen.findByText('Amend'));
    await screen.findByTestId('amend-f1');
    expect((screen.getByLabelText('amend-by') as HTMLInputElement).value).toBe('nadia');
  });

  it('attributes each superseded claim to whoever stated it, and credits nobody when it is unrecorded', async () => {
    mockedApi(api).operatorLedger.mockResolvedValue({
      assertions: [
        {
          ...assertion,
          attribution: 'Asserted by aaron on 2026-07-30 (asserted_from_device). Amended 2026-08-02 by claude (agent)',
          assertion: {
            ...assertion.assertion,
            amendedAt: 1_780_300_000_000,
            amendedBy: 'claude',
            amendedByKind: 'agent' as const,
            supersedes: [
              { claim: 'asserted_from_device' as const, rationale: 'the first wording', from: 1, supersededAt: 2 },
              {
                claim: 'asserted_unverified' as const,
                rationale: 'the second wording',
                from: 2,
                supersededAt: 3,
                amendedBy: 'nadia',
                amendedByKind: 'human' as const,
              },
            ],
          },
        },
      ],
      withdrawn: [],
    });
    render(<OperatorPanel imageId="abc" />);
    // The attribution sentence is the API's, so the panel cannot word the amender differently from the report.
    await waitFor(() => expect(screen.getByText(/Amended 2026-08-02 by claude \(agent\)/)).toBeTruthy());
    fireEvent.click(screen.getByText(/show 2 superseded claims/));
    expect(screen.getByText(/stated by nadia/)).toBeTruthy();
    // The first claim is the author's own: no editor introduced it, so none is named.
    const items = Array.from(document.querySelectorAll('li'));
    const firstItem = items.find((li) => li.textContent?.includes('the first wording'));
    expect(firstItem?.textContent).not.toMatch(/stated by/);
  });

  it('does NOT offer amending on the withdrawn ledger, which is history and stands as written', async () => {
    mockedApi(api).operatorLedger.mockResolvedValue({ assertions: [], withdrawn: [assertion] });
    render(<OperatorPanel imageId="abc" />);
    await waitFor(() => expect(screen.queryByText(assertion.title)).toBeTruthy());
    expect(screen.queryByText('Amend')).toBeNull();
  });
});

describe('OperatorPanel — withdrawing asks both questions in one dialog', () => {
  it('names the missing reason instead of silently doing nothing, then records reason and author', async () => {
    mockApi.withdrawAssertion.mockResolvedValue(undefined as never);
    mount(ledger({ assertions: [asserted()] }));
    fireEvent.click(await screen.findByRole('button', { name: 'Withdraw' }));
    const dialog = screen.getByRole('dialog');
    const reason = within(dialog).getByLabelText('Why does this claim no longer stand?');
    expect(reason).toHaveFocus();
    expect(within(dialog).getByLabelText('Who is retracting it?')).toHaveValue('aaron');

    fireEvent.click(within(dialog).getByRole('button', { name: 'Withdraw' }));
    expect(within(dialog).getByRole('alert')).toHaveTextContent('Why does this claim no longer stand?');
    expect(mockApi.withdrawAssertion).not.toHaveBeenCalled();

    fireEvent.change(reason, { target: { value: 'Rev C removed telnet' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Withdraw' }));
    await waitFor(() =>
      expect(mockApi.withdrawAssertion).toHaveBeenCalledWith('img1', 'a1', {
        withdrawnBy: 'aaron',
        reason: 'Rev C removed telnet',
      }),
    );
  });
});

const note = (o: Partial<ImageNote> = {}): ImageNote => ({
  id: 'n1',
  imageId: 'img1',
  author: 'aaron',
  body: 'check the second partition',
  createdAt: 1,
  updatedAt: 1,
  ...o,
});

describe('editing a working note — in place, because a note is reasoning and keeps no history', () => {
  it('sends the trimmed body through api.updateNote and renders the refreshed list', async () => {
    mockApi.operatorLedger.mockResolvedValue(ledger());
    mockApi.notes.mockReset();
    mockApi.notes
      .mockResolvedValueOnce([note()])
      .mockResolvedValue([note({ body: 'the second partition is jffs2', updatedAt: 2 })]);
    mockApi.updateNote.mockResolvedValue(note({ body: 'the second partition is jffs2', updatedAt: 2 }));
    render(<OperatorPanel imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const box = screen.getByLabelText('Edit note body');
    expect(box).toHaveValue('check the second partition');
    fireEvent.change(box, { target: { value: '  the second partition is jffs2  ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(mockApi.updateNote).toHaveBeenCalledWith('img1', 'n1', 'the second partition is jffs2'));
    expect(await screen.findByText('the second partition is jffs2')).toBeTruthy();
    expect(screen.queryByText('check the second partition')).toBeNull();
    expect(screen.queryByLabelText('Edit note body')).toBeNull();
    // Saving re-reads the notes, so the list is the store's, not only the local patch.
    expect(mockApi.notes.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it('refuses an empty or over-long body, says which, and sends nothing', async () => {
    mockApi.updateNote.mockClear();
    mockApi.operatorLedger.mockResolvedValue(ledger());
    mockApi.notes.mockReset();
    mockApi.notes.mockResolvedValue([note()]);
    render(<OperatorPanel imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const box = screen.getByLabelText('Edit note body');
    fireEvent.change(box, { target: { value: '   ' } });
    expect(screen.getByRole('alert')).toHaveTextContent('A note cannot be empty');
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();

    fireEvent.change(box, { target: { value: 'x'.repeat(MAX_NOTE + 1) } });
    expect(screen.getByRole('alert')).toHaveTextContent(`at most ${MAX_NOTE} characters; this one has ${MAX_NOTE + 1}`);
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();

    fireEvent.change(box, { target: { value: 'x'.repeat(MAX_NOTE) } });
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeEnabled();
    expect(mockApi.updateNote).not.toHaveBeenCalled();
  });

  it('disables the form while the save is in flight', async () => {
    mockApi.operatorLedger.mockResolvedValue(ledger());
    mockApi.notes.mockReset();
    mockApi.notes.mockResolvedValue([note()]);
    let resolve: (n: ImageNote) => void = () => undefined;
    mockApi.updateNote.mockReturnValue(
      new Promise<ImageNote>((r) => {
        resolve = r;
      }),
    );
    render(<OperatorPanel imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByLabelText('Edit note body'), { target: { value: 'revised' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByRole('button', { name: 'Saving…' })).toBeDisabled();
    expect(screen.getByLabelText('Edit note body')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeDisabled();
    resolve(note({ body: 'revised' }));
    await waitFor(() => expect(screen.queryByLabelText('Edit note body')).toBeNull());
  });

  /**
   * The edit cap is the API's own `MAX_NOTE`, so anything the create route accepted — or a retirement note the API
   * wrote, which it holds to the same bound — can be saved back. The old 4000 cap made a long audit note uneditable.
   */
  it('accepts an edit to a note the API stored at its full length', async () => {
    mockApi.operatorLedger.mockResolvedValue(ledger());
    mockApi.notes.mockReset();
    const audit = `Retired 47 computed finding(s) under source \`symreach:lib/x.so\`.\n${'  - row\n'.repeat(1500)}`;
    expect(audit.length).toBeGreaterThan(4000);
    mockApi.notes.mockResolvedValue([note({ body: audit })]);
    mockApi.updateNote.mockResolvedValue(note({ body: `${audit.trim()} (checked)` }));
    render(<OperatorPanel imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const box = screen.getByLabelText('Edit note body');
    fireEvent.change(box, { target: { value: `${audit} (checked)` } });
    expect(screen.queryByRole('alert')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(mockApi.updateNote).toHaveBeenCalledWith('img1', 'n1', `${audit} (checked)`));
  });

  /** A note stored past the bound (by an older build) opens with the reason it cannot be saved, not a dead button. */
  it('names the bound when a stored note is already over it', async () => {
    mockApi.operatorLedger.mockResolvedValue(ledger());
    mockApi.notes.mockReset();
    mockApi.notes.mockResolvedValue([note({ body: 'x'.repeat(MAX_NOTE + 5) })]);
    render(<OperatorPanel imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    expect(screen.getByRole('alert')).toHaveTextContent(`at most ${MAX_NOTE} characters; this one has ${MAX_NOTE + 5}`);
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
  });

  it('pure: measures the body trimmed, as it is sent', () => {
    expect(MAX_NOTE_EDIT).toBe(MAX_NOTE);
    expect(noteBodyProblem('a'.repeat(5000))).toBeNull();
    expect(noteBodyProblem('  ')).toEqual({ kind: 'empty' });
    expect(noteBodyProblem(` ${'a'.repeat(MAX_NOTE)} `)).toBeNull();
    expect(noteBodyProblem('a'.repeat(MAX_NOTE + 1))).toEqual({ kind: 'tooLong', length: MAX_NOTE + 1 });
    expect(noteAuthorTooLong(` ${'a'.repeat(MAX_NOTE_AUTHOR)} `)).toBe(false);
    expect(noteAuthorTooLong('a'.repeat(MAX_NOTE_AUTHOR + 1))).toBe(true);
  });
});

describe('creating a working note — bounded exactly as the API bounds it', () => {
  it('sends a note within the bounds, trimmed', async () => {
    mockApi.operatorLedger.mockResolvedValue(ledger());
    mockApi.notes.mockReset();
    mockApi.notes.mockResolvedValue([]);
    mockApi.addNote.mockClear();
    render(<OperatorPanel imageId="img1" />);

    fireEvent.change(await screen.findByLabelText('Note author'), { target: { value: ' aaron ' } });
    fireEvent.change(screen.getByLabelText('Note body'), { target: { value: ` ${'y'.repeat(MAX_NOTE)} ` } });
    expect(screen.queryByRole('alert')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Save note' }));
    await waitFor(() =>
      expect(mockApi.addNote).toHaveBeenCalledWith('img1', { author: 'aaron', body: 'y'.repeat(MAX_NOTE) }),
    );
  });

  it('refuses an over-long body or author before the request, and says which', async () => {
    mockApi.operatorLedger.mockResolvedValue(ledger());
    mockApi.notes.mockReset();
    mockApi.notes.mockResolvedValue([]);
    mockApi.addNote.mockClear();
    render(<OperatorPanel imageId="img1" />);

    const author = await screen.findByLabelText('Note author');
    const body = screen.getByLabelText('Note body');
    fireEvent.change(author, { target: { value: 'aaron' } });
    // An empty draft is merely not ready; it is not announced as an error.
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('button', { name: 'Save note' })).toBeDisabled();

    fireEvent.change(body, { target: { value: 'z'.repeat(MAX_NOTE + 1) } });
    expect(screen.getByRole('alert')).toHaveTextContent(`at most ${MAX_NOTE} characters; this one has ${MAX_NOTE + 1}`);
    expect(body).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('button', { name: 'Save note' })).toBeDisabled();

    fireEvent.change(body, { target: { value: 'fine' } });
    fireEvent.change(author, { target: { value: 'a'.repeat(MAX_NOTE_AUTHOR + 1) } });
    expect(screen.getByRole('alert')).toHaveTextContent(`The author holds at most ${MAX_NOTE_AUTHOR} characters`);
    expect(author).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('button', { name: 'Save note' })).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: 'Save note' }));
    expect(mockApi.addNote).not.toHaveBeenCalled();
  });
});

describe('retiring a computed source — removed only because re-running restores it, and never silently', () => {
  const removed = [
    { kind: 'symbolic_reachability', title: 'system() reachable from argv', proofState: 'needs_runtime_reproduction' },
  ];
  const retirement = (o: Partial<RetireFindingsResult> = {}): RetireFindingsResult => ({
    source: 'symreach:lib/libutil-0.9.30.so',
    dryRun: false,
    removedCount: 1,
    removed,
    summary: 'Retired 1 finding(s) under `symreach:lib/libutil-0.9.30.so` (proof states: needs_runtime_reproduction).',
    note: note({ id: 'n9', body: 'Retired 1 computed finding(s) under source `symreach:lib/libutil-0.9.30.so`.' }),
    ...o,
  });

  async function openRetire(): Promise<HTMLElement> {
    const panel = await screen.findByTestId('retire-source');
    fireEvent.click(within(panel).getByRole('button', { name: 'Retire source…' }));
    return panel;
  }

  function fill(panel: HTMLElement, v: { source?: string; who?: string; reason?: string }): void {
    if (v.source !== undefined)
      fireEvent.change(within(panel).getByLabelText('Findings source'), { target: { value: v.source } });
    if (v.who !== undefined) fireEvent.change(within(panel).getByLabelText('Retired by'), { target: { value: v.who } });
    if (v.reason !== undefined)
      fireEvent.change(within(panel).getByLabelText('Why these rows should go'), { target: { value: v.reason } });
  }

  it('previews by default: lists what would go, removes nothing, and re-reads nothing', async () => {
    mockApi.retireFindings.mockReset();
    const { note: _none, ...preview } = retirement({
      dryRun: true,
      summary: 'Would retire 1 finding(s) under `symreach:lib/libutil-0.9.30.so`.',
    });
    mockApi.retireFindings.mockResolvedValue(preview);
    mockApi.operatorLedger.mockReset();
    mockApi.notes.mockReset();
    mount();
    const panel = await openRetire();
    expect(within(panel).getByRole('checkbox')).toBeChecked();
    fill(panel, { source: 'symreach:lib/libutil-0.9.30.so', who: 'aaron', reason: 'uClibc is not a program' });
    const ledgerReads = mockApi.operatorLedger.mock.calls.length;
    const noteReads = mockApi.notes.mock.calls.length;
    fireEvent.click(within(panel).getByRole('button', { name: 'Preview retirement' }));

    await waitFor(() =>
      expect(mockApi.retireFindings).toHaveBeenCalledWith('img1', {
        source: 'symreach:lib/libutil-0.9.30.so',
        retiredBy: 'aaron',
        reason: 'uClibc is not a program',
        dryRun: true,
      }),
    );
    expect(await within(panel).findByText(/Preview — nothing has been removed/)).toBeTruthy();
    expect(within(panel).getByText(/Would retire 1 finding/)).toBeTruthy();
    expect(within(panel).getByText(/system\(\) reachable from argv/)).toBeTruthy();
    expect(within(panel).queryByText('The note left in the ledger')).toBeNull();
    // Nothing changed, so nothing is re-read — and the form keeps its reason for the real run.
    expect(mockApi.operatorLedger.mock.calls.length).toBe(ledgerReads);
    expect(mockApi.notes.mock.calls.length).toBe(noteReads);
    expect(within(panel).getByLabelText('Why these rows should go')).toHaveValue('uClibc is not a program');
  });

  it('retires for real only once the preview is unticked, then shows the note and refreshes ledger and notes', async () => {
    mockApi.retireFindings.mockReset();
    mockApi.retireFindings.mockResolvedValue(retirement());
    mockApi.operatorLedger.mockReset();
    mockApi.operatorLedger.mockResolvedValue(ledger());
    mockApi.notes.mockReset();
    mockApi.notes.mockResolvedValueOnce([]).mockResolvedValue([note({ id: 'n9', body: 'Retirement record' })]);
    render(<OperatorPanel imageId="img1" />);
    const panel = await openRetire();
    fill(panel, { source: ' symreach:lib/libutil-0.9.30.so ', who: 'aaron', reason: 'uClibc is not a program' });
    fireEvent.click(within(panel).getByRole('checkbox'));
    fireEvent.click(within(panel).getByRole('button', { name: 'Retire findings' }));

    await waitFor(() =>
      expect(mockApi.retireFindings).toHaveBeenCalledWith('img1', {
        source: 'symreach:lib/libutil-0.9.30.so',
        retiredBy: 'aaron',
        reason: 'uClibc is not a program',
        dryRun: false,
      }),
    );
    expect(await within(panel).findByText(/Retired — a note was recorded/)).toBeTruthy();
    expect(within(panel).getByText('The note left in the ledger')).toBeTruthy();
    expect(within(panel).getByText(/Retired 1 computed finding\(s\) under source/)).toBeTruthy();
    // The ledger and the notes are both re-read, and the note the route left appears in the notes list.
    await waitFor(() => expect(mockApi.operatorLedger).toHaveBeenCalledTimes(2));
    expect(mockApi.notes).toHaveBeenCalledTimes(2);
    expect(await screen.findByText('Retirement record')).toBeTruthy();
    // Back to the safe side for the next one.
    expect(within(panel).getByRole('checkbox')).toBeChecked();
    expect(within(panel).getByLabelText('Why these rows should go')).toHaveValue('');
  });

  it('refuses an operator: source before any request, and names the surface that was meant', async () => {
    mockApi.retireFindings.mockReset();
    mount();
    const panel = await openRetire();
    fill(panel, { source: 'operator:aaron', who: 'aaron', reason: 'tidy up' });
    expect(within(panel).getByRole('alert')).toHaveTextContent('is a hand-authored operator assertion');
    expect(within(panel).getByRole('alert')).toHaveTextContent('withdraw it from the assertions ledger');
    expect(within(panel).getByLabelText('Findings source')).toHaveAttribute('aria-invalid', 'true');
    fireEvent.click(within(panel).getByRole('checkbox'));
    fireEvent.click(within(panel).getByRole('button', { name: 'Retire findings' }));
    expect(mockApi.retireFindings).not.toHaveBeenCalled();
  });

  it('names the missing fields, and refuses a reason over the route’s bound', async () => {
    mockApi.retireFindings.mockReset();
    mount();
    const panel = await openRetire();
    fireEvent.change(within(panel).getByLabelText('Retired by'), { target: { value: '' } });
    fireEvent.click(within(panel).getByRole('button', { name: 'Preview retirement' }));
    expect(within(panel).getByRole('alert')).toHaveTextContent(
      'Fill in before retiring: Findings source, Retired by, Why these rows should go.',
    );
    expect(within(panel).getByLabelText('Why these rows should go')).toHaveAttribute('aria-invalid', 'true');
    fill(panel, { source: 'cve', who: 'aaron', reason: 'r'.repeat(MAX_RETIRE_REASON + 1) });
    fireEvent.click(within(panel).getByRole('button', { name: 'Preview retirement' }));
    expect(within(panel).getByRole('alert')).toHaveTextContent(`at most ${MAX_RETIRE_REASON} characters`);
    expect(mockApi.retireFindings).not.toHaveBeenCalled();
  });

  it('prefills the author from who the panel is being driven as', async () => {
    mount();
    fireEvent.change(await screen.findByLabelText('Note author'), { target: { value: 'maria' } });
    const panel = await openRetire();
    expect(within(panel).getByLabelText('Retired by')).toHaveValue('maria');
  });

  it('pure: an operator source is refused ahead of any missing field', () => {
    expect(retireProblem({ source: 'operator:x', retiredBy: '', reason: '' })).toEqual({
      kind: 'operatorSource',
      source: 'operator:x',
    });
    expect(retireProblem({ source: ' crypto ', retiredBy: 'a', reason: 'b' })).toBeNull();
    expect(retireProblem({ source: 'crypto', retiredBy: 'a'.repeat(81), reason: 'b' })).toEqual({ kind: 'whoTooLong' });
    expect(retireProblem({ source: 's'.repeat(MAX_RETIRE_SOURCE + 1), retiredBy: 'a', reason: 'b' })).toEqual({
      kind: 'sourceTooLong',
      length: MAX_RETIRE_SOURCE + 1,
    });
    expect(retireProblem({ source: 's'.repeat(MAX_RETIRE_SOURCE), retiredBy: 'a', reason: 'b' })).toBeNull();
  });
});

describe('note editing and retirement — Spanish', () => {
  it('edits a note and previews a retirement in Spanish, and refuses an operator source in Spanish', async () => {
    setLocale('es');
    mockApi.operatorLedger.mockResolvedValue(ledger());
    mockApi.notes.mockReset();
    mockApi.notes.mockResolvedValue([note()]);
    mockApi.updateNote.mockReset();
    mockApi.updateNote.mockResolvedValue(note({ body: 'revisada' }));
    mockApi.retireFindings.mockReset();
    mockApi.retireFindings.mockResolvedValue({
      source: 'crypto',
      dryRun: true,
      removedCount: 0,
      removed: [],
      summary: 'No findings carry the source `crypto` on this image, so nothing would be removed.',
    });
    render(<OperatorPanel imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Editar' }));
    fireEvent.change(screen.getByLabelText('Editar el cuerpo de la nota'), { target: { value: '' } });
    expect(screen.getByRole('alert')).toHaveTextContent('Una nota no puede quedar vacía');
    fireEvent.change(screen.getByLabelText('Editar el cuerpo de la nota'), { target: { value: 'revisada' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar cambios' }));
    await waitFor(() => expect(mockApi.updateNote).toHaveBeenCalledWith('img1', 'n1', 'revisada'));

    const panel = screen.getByTestId('retire-source');
    expect(within(panel).getByText('Retirar una fuente calculada')).toBeTruthy();
    fireEvent.click(within(panel).getByRole('button', { name: 'Retirar fuente…' }));
    fireEvent.change(within(panel).getByLabelText('Fuente de hallazgos'), { target: { value: 'operator:aaron' } });
    expect(within(panel).getByRole('alert')).toHaveTextContent('Una afirmación no se quita nunca');

    fireEvent.change(within(panel).getByLabelText('Fuente de hallazgos'), { target: { value: 'crypto' } });
    fireEvent.change(within(panel).getByLabelText('Retirado por'), { target: { value: 'aaron' } });
    fireEvent.change(within(panel).getByLabelText('Por qué deben irse estas filas'), { target: { value: 'ruido' } });
    fireEvent.click(within(panel).getByRole('button', { name: 'Previsualizar retirada' }));
    await waitFor(() =>
      expect(mockApi.retireFindings).toHaveBeenCalledWith('img1', {
        source: 'crypto',
        retiredBy: 'aaron',
        reason: 'ruido',
        dryRun: true,
      }),
    );
    expect(await within(panel).findByText(/Vista previa: no se ha quitado nada/)).toBeTruthy();
    expect(within(panel).getByText(/0 fila\(s\)/)).toBeTruthy();
  });
});
