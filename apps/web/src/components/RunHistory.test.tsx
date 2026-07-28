import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { type RunSummary, api } from '../api';
import { mockedApi } from '../test-api-mock';
import { RunHistory } from './RunHistory';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const run = (o: Partial<RunSummary>): RunSummary => ({
  jobId: 'j',
  kind: 'fuzz',
  status: 'done',
  startedAt: Date.now() - 120_000,
  finishedAt: Date.now(),
  target: 'sbin/one',
  question: null,
  headline: 'x',
  outcome: 'empty',
  bound: null,
  ...o,
});

describe('RunHistory', () => {
  it('stays silent while there is nothing the panel above is not already showing', async () => {
    // A panel renders its latest result. One run means this component has nothing to add, so it must not
    // occupy space saying so.
    mockApi.runs.mockResolvedValue({ runs: [run({ jobId: 'a' })], byTarget: [] });
    const { container } = render(<RunHistory imageId="img" kinds={['fuzz']} label="fuzzing" />);
    await waitFor(() => expect(mockApi.runs).toHaveBeenCalled());
    expect(container.textContent).toBe('');
  });

  it('says how many runs there are, and that the panel above shows only the newest', async () => {
    mockApi.runs.mockResolvedValue({ runs: [run({ jobId: 'a' }), run({ jobId: 'b' })], byTarget: [] });
    render(<RunHistory imageId="img" kinds={['fuzz']} label="fuzzing" />);
    expect(await screen.findByText(/2 fuzzing runs on this image/)).toBeTruthy();
    expect(screen.getByText(/shows only the most recent/)).toBeTruthy();
  });

  it('keeps blocked and empty apart, exactly as the ledger does', async () => {
    // The whole reason this reuses the shared summary rather than rendering a status: a provider whose tool was
    // missing and one that genuinely found nothing must never look alike.
    mockApi.runs.mockResolvedValue({
      runs: [
        run({ jobId: 'a', outcome: 'blocked', headline: 'angr is not installed in this deployment' }),
        run({ jobId: 'b', outcome: 'empty', headline: 'No crash in this budget — which is not "no bug"' }),
      ],
      byTarget: [],
    });
    render(<RunHistory imageId="img" kinds={['fuzz']} label="fuzzing" />);
    fireEvent.click(await screen.findByText(/2 fuzzing runs/));

    expect(screen.getByText('blocked')).toBeTruthy();
    expect(screen.getByText('nothing found')).toBeTruthy();
    expect(screen.getByText(/which is not "no bug"/)).toBeTruthy();
  });

  it('shows the bound each run operated under, so none reads as unbounded', async () => {
    mockApi.runs.mockResolvedValue({
      runs: [run({ jobId: 'a', bound: '60s' }), run({ jobId: 'b', bound: '120s budget' })],
      byTarget: [],
    });
    render(<RunHistory imageId="img" kinds={['fuzz']} label="fuzzing" />);
    fireEvent.click(await screen.findByText(/2 fuzzing runs/));
    expect(screen.getByText('60s')).toBeTruthy();
    expect(screen.getByText('120s budget')).toBeTruthy();
  });

  it('asks only for the kinds its panel drives', async () => {
    mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
    render(<RunHistory imageId="img" kinds={['uboot', 'certs']} label="deep-analysis" />);
    await waitFor(() => expect(mockApi.runs).toHaveBeenCalledWith('img', { kind: 'uboot,certs' }));
  });
});
