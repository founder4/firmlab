import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { type SymReachResult, api } from '../api';
import { SymReachPanel } from './SymReachPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  return {
    ...actual,
    api: { ...actual.api, symreach: vi.fn(), symreachResult: vi.fn(), job: vi.fn() },
  };
});

const mockApi = api as unknown as {
  symreach: ReturnType<typeof vi.fn>;
  symreachResult: ReturnType<typeof vi.fn>;
  job: ReturnType<typeof vi.fn>;
};

const result = (o: Partial<SymReachResult> = {}): SymReachResult => ({
  available: true,
  reason: 'angr on usr/sbin/bpalogin: 1/2 sink(s) proven reachable from the entry point.',
  binary: 'usr/sbin/bpalogin',
  arch: 'MIPS32',
  entry: '0x400610',
  asked: ['sscanf', 'strcpy'],
  sinks: [
    {
      sink: 'sscanf',
      outcome: 'reached',
      addresses: ['0x4008a0'],
      steps: 12,
      pruned: false,
      errors: 0,
      argv1: 'AAAA',
      path: ['0x400700', '0x4008a0'],
    },
    {
      sink: 'strcpy',
      outcome: 'not_reached_in_budget',
      addresses: ['0x400920'],
      steps: 400,
      pruned: true,
      errors: 3,
      reason: 'step budget (400 steps) reached',
    },
  ],
  ...o,
});

describe('SymReachPanel', () => {
  it('renders a reached sink as reachability with its concrete input, never as exploitability', async () => {
    mockApi.symreachResult.mockResolvedValue(result());
    render(<SymReachPanel imageId="img1" binary="usr/sbin/bpalogin" onBinary={() => {}} />);
    await waitFor(() => expect(screen.getByText('reachable from entry')).toBeTruthy());
    expect(screen.getByText(/argv\[1\]="AAAA"/)).toBeTruthy();
    expect(screen.getByText(/Whether the copy overflows.*separate questions/s)).toBeTruthy();
  });

  it('never renders an exhausted search as clean — it says which budget stopped it and what was lost', async () => {
    mockApi.symreachResult.mockResolvedValue(result());
    render(<SymReachPanel imageId="img1" binary="usr/sbin/bpalogin" onBinary={() => {}} />);
    await waitFor(() => expect(screen.getByText('inconclusive — search bounded')).toBeTruthy());
    expect(screen.getByText(/step budget \(400 steps\) reached/)).toBeTruthy();
    expect(screen.getByText(/states pruned/)).toBeTruthy();
    expect(screen.getByText(/3 state\(s\) lost to angr-internal errors/)).toBeTruthy();
  });

  it('reports an unanswerable probe as a missing capability, not as a result', async () => {
    mockApi.symreachResult.mockResolvedValue(
      result({ available: false, reason: 'angr not installed in this deployment', sinks: [] }),
    );
    render(<SymReachPanel imageId="img1" binary="bin/x" onBinary={() => {}} />);
    await waitFor(() => expect(screen.getByText('angr not installed in this deployment')).toBeTruthy());
    expect(screen.getByText(/nothing about .* was ruled out/)).toBeTruthy();
  });

  it('asks about the operator’s own sinks — the whole point of a manual route', async () => {
    mockApi.symreachResult.mockResolvedValue(null);
    mockApi.symreach.mockResolvedValue({ jobId: 'j1' });
    mockApi.job.mockResolvedValue({ id: 'j1', status: 'running', log: '' });
    render(<SymReachPanel imageId="img1" binary="usr/sbin/httpd" onBinary={() => {}} />);

    fireEvent.change(screen.getByLabelText('Sink symbols to ask about'), { target: { value: 'system, popen' } });
    fireEvent.click(screen.getByRole('button', { name: 'Ask' }));
    await waitFor(() =>
      expect(mockApi.symreach).toHaveBeenCalledWith('img1', {
        binary: 'usr/sbin/httpd',
        sinks: ['system', 'popen'],
        budgetSeconds: 90,
      }),
    );
  });

  it('omits the sink list entirely when none are named, so the server derives them from the imports', async () => {
    mockApi.symreachResult.mockResolvedValue(null);
    mockApi.symreach.mockResolvedValue({ jobId: 'j2' });
    mockApi.job.mockResolvedValue({ id: 'j2', status: 'running', log: '' });
    render(<SymReachPanel imageId="img1" binary="usr/sbin/httpd" onBinary={() => {}} />);

    fireEvent.change(screen.getByLabelText('Sink symbols to ask about'), { target: { value: '  ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Ask' }));
    // An empty `sinks: []` would mean "ask about nothing"; omitting the key is what requests derivation.
    await waitFor(() =>
      expect(mockApi.symreach).toHaveBeenCalledWith('img1', { binary: 'usr/sbin/httpd', budgetSeconds: 90 }),
    );
  });
});
