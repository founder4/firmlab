import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { FuzzPanel } from './FuzzPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  return {
    ...actual,
    api: { ...actual.api, fuzzStatus: vi.fn(), fuzzResult: vi.fn(), runFuzz: vi.fn(), job: vi.fn() },
  };
});

const mockApi = api as unknown as {
  fuzzStatus: ReturnType<typeof vi.fn>;
  fuzzResult: ReturnType<typeof vi.fn>;
  runFuzz: ReturnType<typeof vi.fn>;
  job: ReturnType<typeof vi.fn>;
};

const fuzzResult = (o: Record<string, unknown> = {}) => ({
  available: true,
  binary: 'bin/busybox',
  seconds: 60,
  execsDone: 12000,
  crashes: 0,
  crashSamples: [],
  isolation: 'full',
  command: 'afl-fuzz -Q -i seeds -o out -- ./bin/busybox @@',
  ...o,
});

beforeEach(() => {
  mockApi.fuzzStatus.mockResolvedValue({ available: true });
  mockApi.fuzzResult.mockResolvedValue(null);
  mockApi.runFuzz.mockResolvedValue({ jobId: 'j1' });
  mockApi.job.mockResolvedValue({ id: 'j1', status: 'done', result: fuzzResult(), log: '' });
});

describe('FuzzPanel — AFL++ honesty', () => {
  it('is honest when AFL++ is not installed: opt-in badge, an explanation, and no run button', async () => {
    mockApi.fuzzStatus.mockResolvedValue({ available: false });
    render(<FuzzPanel imageId="img1" />);
    expect(await screen.findByText('opt-in layer')).toBeInTheDocument();
    expect(screen.getByText(/AFL\+\+ isn't installed/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /fuzz/i })).not.toBeInTheDocument();
  });

  it('offers a run control when AFL++ is available', async () => {
    render(<FuzzPanel imageId="img1" />);
    expect(await screen.findByRole('button', { name: 'Fuzz' })).toBeInTheDocument();
  });

  it('refuses to run without a target binary', async () => {
    render(<FuzzPanel imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Fuzz' }));
    expect(await screen.findByText(/Enter a rootfs binary path/i)).toBeInTheDocument();
    expect(mockApi.runFuzz).not.toHaveBeenCalled();
  });

  it('runs the fuzzer against the entered binary', async () => {
    render(<FuzzPanel imageId="img1" />);
    fireEvent.change(await screen.findByPlaceholderText('bin/busybox'), { target: { value: 'sbin/httpd' } });
    fireEvent.click(screen.getByRole('button', { name: 'Fuzz' }));
    await waitFor(() => expect(mockApi.runFuzz).toHaveBeenCalledWith('img1', 'sbin/httpd', 60));
  });

  it('surfaces a reproduced crash as a recorded fuzz-crash finding', async () => {
    mockApi.fuzzResult.mockResolvedValue(
      fuzzResult({ crashes: 2, crashSamples: [{ name: 'id:000001,sig:11', hexPreview: 'de ad be ef' }] }),
    );
    render(<FuzzPanel imageId="img1" />);
    expect(await screen.findByText(/fuzz-crash/)).toBeInTheDocument();
    expect(screen.getByText('de ad be ef')).toBeInTheDocument();
  });

  it('reports a 0-crash run as an honest negative, not a guarantee of safety', async () => {
    mockApi.fuzzResult.mockResolvedValue(fuzzResult({ crashes: 0 }));
    render(<FuzzPanel imageId="img1" />);
    expect(await screen.findByText(/an honest negative/i)).toBeInTheDocument();
  });
});
