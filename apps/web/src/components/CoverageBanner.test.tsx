import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { type CoverageReport, api } from '../api';
import { CoverageBanner } from './CoverageBanner';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  return { ...actual, api: { ...actual.api, coverage: vi.fn() } };
});

const mockApi = api as unknown as { coverage: ReturnType<typeof vi.fn> };

const report = (o: Partial<CoverageReport> = {}): CoverageReport => ({
  firmwareClass: 'embedded-linux',
  applicable: 3,
  executed: 1,
  findingCount: 0,
  stages: [
    { worker: 'W1 · Extraction', reason: 'recover the rootfs', status: 'degraded', detail: 'no rootfs' },
    { worker: 'W3 · Credentials', reason: 'weak creds', status: 'no-input', detail: 'no extracted rootfs' },
    { worker: 'W5 · Binary-vuln', reason: 'pwnable candidates', status: 'no-input', detail: 'no extracted rootfs' },
  ],
  verdict: '1 of 3 stages ran and recorded nothing; 2 never ran. Zero findings covers only the stages that ran.',
  ambiguous: true,
  ...o,
});

describe('CoverageBanner', () => {
  it('states what zero findings actually covers instead of leaving the list to speak for itself', async () => {
    mockApi.coverage.mockResolvedValue(report());
    render(<CoverageBanner imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/Zero findings covers only/)).toBeTruthy());
    expect(screen.getByText(/Coverage · embedded-linux/)).toBeTruthy();
  });

  it('answers "what can run on this image" per stage, on demand', async () => {
    mockApi.coverage.mockResolvedValue(report());
    render(<CoverageBanner imageId="img1" />);
    const toggle = await screen.findByRole('button', { name: /What can run on this image\? \(1\/3\)/ });
    fireEvent.click(toggle);
    await waitFor(() => expect(screen.getByText('W5 · Binary-vuln')).toBeTruthy());
    // The stages that never ran are labelled as such, not left blank as if they were clean.
    expect(screen.getAllByText(/no input/).length).toBe(2);
  });

  it('renders nothing when coverage is unavailable rather than implying full coverage', async () => {
    mockApi.coverage.mockRejectedValue(new Error('offline'));
    const { container } = render(<CoverageBanner imageId="img1" />);
    await waitFor(() => expect(container.querySelector('.banner')).toBeNull());
  });
});
