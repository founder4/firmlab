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
      startCaptureSession: vi.fn(),
      captureSession: vi.fn(),
      ingestCaptureFlow: vi.fn(),
      teardownCapture: vi.fn(),
      capturePreflight: vi.fn(),
    },
  };
});

const mockApi = api as unknown as {
  captureStatus: ReturnType<typeof vi.fn>;
  captureBackends: ReturnType<typeof vi.fn>;
  captureDevices: ReturnType<typeof vi.fn>;
  runCaptureDiscover: ReturnType<typeof vi.fn>;
  captureScan: ReturnType<typeof vi.fn>;
  startCaptureSession: ReturnType<typeof vi.fn>;
  captureSession: ReturnType<typeof vi.fn>;
  ingestCaptureFlow: ReturnType<typeof vi.fn>;
  teardownCapture: ReturnType<typeof vi.fn>;
  capturePreflight: ReturnType<typeof vi.fn>;
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
  mockApi.startCaptureSession.mockResolvedValue({
    sessionId: 'cap1',
    watching: true,
    reason: 'Proxy watching on :8788',
    port: 8788,
  });
  mockApi.ingestCaptureFlow.mockResolvedValue({ imageId: 'img99', filename: 'fw.bin' });
  mockApi.teardownCapture.mockResolvedValue({ session: null });
});

const device = {
  id: 'dev1',
  mac: 'aa:bb:cc:dd:ee:ff',
  ouiVendor: 'Espressif',
  ip: '192.168.1.42',
  mdnsIdentity: null,
  openPorts: null,
  typeGuess: 'ESP IoT device?',
  typeConfidence: 'low',
  firstSeen: 0,
  lastSeen: Date.now(),
};

const carvedFlow = {
  id: 'flowA',
  sessionId: 'cap1',
  host: 'cdn.x',
  url: 'https://cdn.x/ota/fw.bin',
  method: 'GET',
  contentType: 'application/octet-stream',
  size: 300 * 1024,
  tlsPosture: 'tls-unpinned',
  firmwareScore: 100,
  carved: 1,
  bodyPath: '/x',
  createdAt: 0,
};

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

describe('Capture — Phase 6.1 interception', () => {
  beforeEach(() => {
    mockApi.captureDevices.mockResolvedValue([device]);
    mockApi.captureSession.mockResolvedValue({
      session: { id: 'cap1', status: 'watching', targetDeviceId: 'dev1', transcript: 'armed', error: null },
      flows: [carvedFlow],
    });
  });

  it('arms a capture session for a device once authorization is acknowledged', async () => {
    render(<Capture />);
    fireEvent.click(await screen.findByLabelText(/authorized to test/i));
    fireEvent.click(await screen.findByRole('button', { name: 'Capture' }));
    await waitFor(() => expect(mockApi.startCaptureSession).toHaveBeenCalledWith('dev1', true));
  });

  it('renders the scored flow feed and ingests a carved firmware candidate', async () => {
    render(<Capture />);
    fireEvent.click(await screen.findByLabelText(/authorized to test/i));
    fireEvent.click(await screen.findByRole('button', { name: 'Capture' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Ingest' }));
    await waitFor(() => expect(mockApi.ingestCaptureFlow).toHaveBeenCalledWith('cap1', 'flowA'));
    expect(await screen.findByRole('link', { name: /ingested/i })).toBeInTheDocument();
  });
});

describe('Capture — Phase 6.3 capturability preflight', () => {
  beforeEach(() => {
    mockApi.captureDevices.mockResolvedValue([device]);
    mockApi.capturePreflight.mockResolvedValue({
      strategies: [
        { transport: 'http', positioning: 'gateway', viable: true, ceiling: 'captured_plaintext', reason: 'ready' },
        {
          transport: 'https',
          positioning: 'gateway',
          viable: true,
          ceiling: 'captured_plaintext',
          reason: 'unless pinned',
        },
      ],
      ceiling: 'captured_plaintext',
      reason: 'Best path: http via gateway.',
      unlockHint: null,
    });
  });

  it('shows the capturability ladder + honest ceiling for a target on demand', async () => {
    render(<Capture />);
    fireEvent.click(await screen.findByRole('button', { name: 'Preflight' }));
    await waitFor(() => expect(mockApi.capturePreflight).toHaveBeenCalledWith('dev1'));
    expect(await screen.findByText('captured_plaintext')).toBeInTheDocument();
    expect(screen.getByText(/Best path: http via gateway/)).toBeInTheDocument();
  });
});
