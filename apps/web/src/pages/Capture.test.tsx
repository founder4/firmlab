import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type CaptureBackend, api } from '../api';
import { Capture } from './Capture';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  return {
    ...actual,
    api: {
      ...actual.api,
      captureStatus: vi.fn(),
      captureBackends: vi.fn(),
      captureDevices: vi.fn(),
      runCaptureDiscover: vi.fn(),
      captureScan: vi.fn(),
    },
  };
});

const mockApi = api as unknown as {
  captureStatus: ReturnType<typeof vi.fn>;
  captureBackends: ReturnType<typeof vi.fn>;
  captureDevices: ReturnType<typeof vi.fn>;
  runCaptureDiscover: ReturnType<typeof vi.fn>;
  captureScan: ReturnType<typeof vi.fn>;
};

const backend = (over: Partial<CaptureBackend>): CaptureBackend => ({
  id: 'network-proxy',
  role: 'interception',
  transports: ['http', 'https'],
  unlocks: 'Intercept an HTTP OTA',
  available: false,
  reason: 'mitmproxy not installed',
  capabilities: {},
  ...over,
});

beforeEach(() => {
  mockApi.captureStatus.mockResolvedValue({ enabled: true, gatewayDeclared: false, defaultSubnet: null });
  mockApi.captureBackends.mockResolvedValue({
    enabled: true,
    backends: [
      backend({}),
      backend({ id: 'ble', role: 'radio', transports: ['ble-gatt'], reason: 'No BLE sniffer attached' }),
    ],
    transports: [],
  });
  mockApi.captureDevices.mockResolvedValue([]);
  mockApi.runCaptureDiscover.mockResolvedValue({ scanId: 'scan1' });
  mockApi.captureScan.mockResolvedValue({
    session: { id: 'scan1', status: 'done', transcript: 'done', deviceCount: 0, error: null },
    devices: [],
  });
});

describe('Capture — Phase 6.0 discovery', () => {
  it('lists the detected backends with their honest reason', async () => {
    render(<Capture />);
    expect(await screen.findByText('mitmproxy not installed')).toBeInTheDocument();
    expect(screen.getByText('network-proxy')).toBeInTheDocument();
  });

  it('keeps the scan button disabled until the operator acknowledges authorization', async () => {
    render(<Capture />);
    const btn = (await screen.findByRole('button', { name: 'Scan network' })) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/authorized to test/i));
    expect(btn.disabled).toBe(false);
  });

  it('arms a discovery scan with the acknowledgement once confirmed', async () => {
    render(<Capture />);
    fireEvent.click(await screen.findByLabelText(/authorized to test/i));
    fireEvent.click(screen.getByRole('button', { name: 'Scan network' }));
    await waitFor(() => expect(mockApi.runCaptureDiscover).toHaveBeenCalledWith(null, true));
  });

  it('shows the lane-off banner and disables scanning when the flag is unset', async () => {
    mockApi.captureStatus.mockResolvedValue({ enabled: false });
    mockApi.captureBackends.mockResolvedValue({ enabled: false, backends: [backend({})], transports: [] });
    render(<Capture />);
    expect(await screen.findByText(/capture lane is/i)).toBeInTheDocument();
    const btn = (await screen.findByRole('button', { name: 'Scan network' })) as HTMLButtonElement;
    // Even after acknowledging, an off lane keeps the scan disabled.
    fireEvent.click(screen.getByLabelText(/authorized to test/i));
    expect(btn.disabled).toBe(true);
  });
});
