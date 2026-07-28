import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type SymReachResult, api } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { es } from '../locales/es';
import { mockedApi } from '../test-api-mock';
import { SymReachPanel } from './SymReachPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
  // The panel drops a RunHistory under its result, which reads the run ledger. Before the shared mock this call
  // was left pointing at the real client and fetched over the network in every test in this file.
  mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
});

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
    await waitFor(() => expect(screen.getByText(en.panels.symreach.outcome.reached)).toBeTruthy());
    expect(screen.getByText(/argv\[1\]="AAAA"/)).toBeTruthy();
    expect(screen.getByText(en.panels.symreach.reachedNote)).toBeTruthy();
    expect(en.panels.symreach.reachedNote).toMatch(/Whether the copy overflows.*separate questions/s);
  });

  it('never renders an exhausted search as clean — it says which budget stopped it and what was lost', async () => {
    mockApi.symreachResult.mockResolvedValue(result());
    render(<SymReachPanel imageId="img1" binary="usr/sbin/bpalogin" onBinary={() => {}} />);
    await waitFor(() => expect(screen.getByText(en.panels.symreach.outcome.not_reached_in_budget)).toBeTruthy());
    expect(screen.getByText(/step budget \(400 steps\) reached/)).toBeTruthy();
    // Substring: the reason, the pruning note and the lost-state count share one line, joined with ' · '.
    expect(screen.getByText(en.panels.symreach.pruned, { exact: false })).toBeTruthy();
    expect(screen.getByText(en.panels.symreach.errors(3), { exact: false })).toBeTruthy();
  });

  it('reports an unanswerable probe as a missing capability, not as a result', async () => {
    mockApi.symreachResult.mockResolvedValue(
      result({ available: false, reason: 'angr not installed in this deployment', sinks: [] }),
    );
    render(<SymReachPanel imageId="img1" binary="bin/x" onBinary={() => {}} />);
    await waitFor(() => expect(screen.getByText('angr not installed in this deployment')).toBeTruthy());
    // The binary named in the caveat is the one the PROBE ran on, as the stored result recorded it — not whatever
    // the input box happens to hold now.
    expect(screen.getByText(en.panels.symreach.notAnsweredHint('usr/sbin/bpalogin'))).toBeTruthy();
  });

  it('asks about the operator’s own sinks — the whole point of a manual route', async () => {
    mockApi.symreachResult.mockResolvedValue(null);
    mockApi.symreach.mockResolvedValue({ jobId: 'j1' });
    mockApi.job.mockResolvedValue({ id: 'j1', status: 'running', log: '' });
    render(<SymReachPanel imageId="img1" binary="usr/sbin/httpd" onBinary={() => {}} />);

    fireEvent.change(screen.getByLabelText(en.panels.symreach.sinksLabel), { target: { value: 'system, popen' } });
    fireEvent.click(screen.getByRole('button', { name: en.panels.symreach.ask }));
    // The sink names are symbols in the binary — they cross the API exactly as typed, in any locale.
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

    fireEvent.change(screen.getByLabelText(en.panels.symreach.sinksLabel), { target: { value: '  ' } });
    fireEvent.click(screen.getByRole('button', { name: en.panels.symreach.ask }));
    // An empty `sinks: []` would mean "ask about nothing"; omitting the key is what requests derivation.
    await waitFor(() =>
      expect(mockApi.symreach).toHaveBeenCalledWith('img1', { binary: 'usr/sbin/httpd', budgetSeconds: 90 }),
    );
  });
});

/**
 * The bound, in Spanish. This is the sentence the panel exists for and the one a translation can silently invert: a
 * search that stopped has proven NOTHING about the sinks it did not reach, so "no alcanzado" must never be readable
 * as "no explotable" or "seguro". The two proof states are printed as the codes they are, and the prose around them
 * says which one every sink keeps and which one it never drops to.
 */
describe('SymReachPanel — the bounded search in Spanish', () => {
  it('keeps an unreached sink a lead: needs_runtime_reproduction stands, false_positive never does', async () => {
    setLocale('es');
    mockApi.symreachResult.mockResolvedValue(
      result({
        sinks: [
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
      }),
    );
    render(<SymReachPanel imageId="img1" binary="usr/sbin/bpalogin" onBinary={() => {}} />);

    // The outcome reads as inconclusive, never as a clean sink.
    expect(await screen.findByText(es.panels.symreach.outcome.not_reached_in_budget)).toBeTruthy();
    expect(es.panels.symreach.outcome.not_reached_in_budget).toMatch(/no concluyente/i);
    // The caveat: the sinks keep their lead state, and an exhausted search is not a demotion.
    expect(screen.getByText(es.panels.symreach.notReached.lead, { exact: false })).toBeTruthy();
    expect(es.panels.symreach.notReached.lead).toMatch(/no es prueba de inalcanzabilidad/i);
    expect(es.panels.symreach.notReached.beforeFalsePositive).toMatch(/nunca es una rebaja/i);
    // The proof states themselves are identifiers and are rendered verbatim in every language.
    expect(screen.getByText('needs_runtime_reproduction')).toBeTruthy();
    expect(screen.getByText('false_positive')).toBeTruthy();
    // …and so are the sink name (twice: the hint's example list and this row) and the tool.
    expect(screen.getAllByText(/strcpy/).length).toBeGreaterThan(0);
    expect(screen.getByText(es.panels.symreach.title)).toBeTruthy();
    expect(es.panels.symreach.title).toMatch(/angr/);
  });

  it('states what the run did not ask about, and by what rule', async () => {
    setLocale('es');
    mockApi.symreachResult.mockResolvedValue(result({ dropped: ['sprintf', 'memcpy'], derivedSinks: true }));
    render(<SymReachPanel imageId="img1" binary="usr/sbin/bpalogin" onBinary={() => {}} />);

    expect(await screen.findByText(es.panels.symreach.dropped(2), { exact: false })).toBeTruthy();
    expect(es.panels.symreach.dropped(2)).toMatch(/tope por ejecución/i);
  });
});
