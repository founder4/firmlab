import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { type AssertedFinding, type OperatorLedger, api } from '../api';
import { OperatorPanel } from './OperatorPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  return {
    ...actual,
    api: {
      ...actual.api,
      operatorLedger: vi.fn(),
      notes: vi.fn(),
      addAssertion: vi.fn(),
      withdrawAssertion: vi.fn(),
      addNote: vi.fn(),
      deleteNote: vi.fn(),
    },
  };
});

const mockApi = api as unknown as {
  operatorLedger: ReturnType<typeof vi.fn>;
  notes: ReturnType<typeof vi.fn>;
  addAssertion: ReturnType<typeof vi.fn>;
  withdrawAssertion: ReturnType<typeof vi.fn>;
  addNote: ReturnType<typeof vi.fn>;
  deleteNote: ReturnType<typeof vi.fn>;
};

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
