import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type OpacidadResult, api } from '../api';
import { mockedApi } from '../test-api-mock';
import { OpacidadPanel } from './OpacidadPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const result = (o: Partial<OpacidadResult> = {}): OpacidadResult => ({
  firmwareClass: 'esp-soc',
  arch: 'xtensa',
  classRationale: 'ESP SoC flash dump — not a Linux image.',
  plan: [{ worker: 'W6 · ESP / IoT-SoC', reason: 'NVS keys + eFuse posture' }],
  steps: [
    {
      worker: 'W6 · ESP / IoT-SoC',
      status: 'not-built',
      summary: 'NVS keys + eFuse posture',
      note: 'worker not built yet',
    },
  ],
  findings: { total: 0, bySeverity: {}, byProofState: {}, top: [] },
  attackPath: [],
  narrative: 'ESP SoC flash dump. Not Linux — the rootfs pipeline does not apply.',
  narrativeSource: 'deterministic',
  honestGaps: [
    'W6 · ESP / IoT-SoC: not built yet — worker not built yet',
    'Zero findings here does NOT mean "secure".',
  ],
  ...o,
});

beforeEach(() => {
  // The panel drops a RunHistory under its result, which reads the run ledger. Before the shared mock this call
  // was left pointing at the real client and fetched over the network in every test in this file.
  mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
  mockApi.opacidadResult.mockResolvedValue(null);
  mockApi.runOpacidad.mockResolvedValue({ jobId: 'j1' });
  mockApi.job.mockResolvedValue({ id: 'j1', status: 'done', result: result(), log: '' });
});

describe('OpacidadPanel — autonomous scan', () => {
  it('offers a run control when there is no prior scan', async () => {
    render(<OpacidadPanel imageId="img1" />);
    expect(await screen.findByRole('button', { name: 'Run autonomous scan' })).toBeInTheDocument();
  });

  it('kicks off the scan on click', async () => {
    render(<OpacidadPanel imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Run autonomous scan' }));
    await waitFor(() => expect(mockApi.runOpacidad).toHaveBeenCalledWith('img1'));
  });

  it('renders a prior scan: class, the routed worker, and the honest-gaps surface (not-built shown, never hidden)', async () => {
    mockApi.opacidadResult.mockResolvedValue(result());
    render(<OpacidadPanel imageId="img1" />);
    expect(await screen.findByText('esp-soc')).toBeInTheDocument();
    expect(screen.getByText('W6 · ESP / IoT-SoC')).toBeInTheDocument();
    expect(screen.getByText(/Honest gaps/i)).toBeInTheDocument();
    expect(screen.getByText(/does NOT mean/i)).toBeInTheDocument();
    // The narrative provenance is labelled (deterministic vs LLM) so the operator knows how it was written.
    expect(screen.getByText(/narrative: deterministic/i)).toBeInTheDocument();
  });
});
