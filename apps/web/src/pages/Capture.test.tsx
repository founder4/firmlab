import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type CaptureBackend, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { Capture } from './Capture';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

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
  // Reset the locale BEFORE the render, never after it: the store notifies live subscribers, so switching back in
  // an `afterEach` re-renders a still-mounted tree and the suite fills with act(…) warnings.
  setLocale('en');
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
  mockApi.captureFamilies.mockResolvedValue({ families: [], vendorPriors: [], cdnGraph: [] });
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

/**
 * The lane's prose says what leaves this machine and under whose acknowledgement, so it is worth proving it still
 * says it in Spanish — and that the parts an operator has to TYPE (the env var, the Docker flag) and the parts the
 * API owns (backend ids, a tool's own reason) came through untouched.
 */
describe('Capture — Spanish', () => {
  it('states the lane is off without softening it, and leaves the env var and backend id alone', async () => {
    setLocale('es');
    mockApi.captureStatus.mockResolvedValue({ enabled: false });
    mockApi.captureBackends.mockResolvedValue({ enabled: false, backends: [backend({})], transports: [] });
    render(<Capture />);

    expect(await screen.findByText(/El carril de captura está/)).toBeInTheDocument();
    expect(screen.getByText('desactivado')).toBeInTheDocument();
    // Typed by the operator, not read by them: these must survive every translation verbatim.
    expect(screen.getByText('FIRMLAB_CAPTURE=1')).toBeInTheDocument();
    expect(screen.getByText('--network host')).toBeInTheDocument();
    // The backend id and the detector's own reason are API values, shown as they arrived.
    expect(screen.getByText('network-proxy')).toBeInTheDocument();
    expect(screen.getByText('mitmproxy not installed')).toBeInTheDocument();

    // And the gate still holds: acknowledging authorization does not enable a scan while the lane is off.
    const btn = screen.getByRole('button', { name: 'Escanear la red' }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/autorización para probarlos/i));
    expect(btn.disabled).toBe(true);
  });

  it('keeps the acknowledgement gating the scan when the lane is on', async () => {
    setLocale('es');
    render(<Capture />);
    const btn = (await screen.findByRole('button', { name: 'Escanear la red' })) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.click(screen.getByLabelText(/autorización para probarlos/i));
    expect(btn.disabled).toBe(false);
    fireEvent.click(btn);
    // The acknowledgement is what reaches the API — the flag it sends is not a display concern.
    await waitFor(() => expect(mockApi.runCaptureDiscover).toHaveBeenCalledWith(null, true));
  });

  it('reports a sweep that ran and found nothing as such, not as an absent sweep', async () => {
    setLocale('es');
    mockApi.captureScan.mockResolvedValue({
      session: { id: 'scan1', status: 'done', transcript: 'done', deviceCount: 0, error: null },
      devices: [],
    });
    render(<Capture />);
    expect(await screen.findByText('Todavía no se ha escaneado')).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/autorización para probarlos/i));
    fireEvent.click(screen.getByRole('button', { name: 'Escanear la red' }));
    expect(await screen.findByText('Barrido completado — no respondió ningún dispositivo')).toBeInTheDocument();
  });
});

describe('Capture — Phase 6.6 OTA learning', () => {
  it('renders a per-family OTA timeline + vendor priors from the corpus', async () => {
    mockApi.captureFamilies.mockResolvedValue({
      families: [
        {
          key: 'Acme',
          vendor: 'Acme',
          transports: ['http'],
          endpoints: ['http://cdn.acme.com/a'],
          captures: [
            {
              imageId: 'v1',
              filename: 'fw-1.2.bin',
              capturedAt: 1,
              endpoint: null,
              transport: 'http',
              tlsPosture: null,
              size: 100000,
              firmwareClass: 'embedded-linux',
            },
            {
              imageId: 'v2',
              filename: 'fw-1.3.bin',
              capturedAt: 2,
              endpoint: null,
              transport: 'http',
              tlsPosture: null,
              size: 110000,
              firmwareClass: 'embedded-linux',
            },
          ],
        },
      ],
      vendorPriors: [{ vendor: 'Acme', ships: 'plaintext-http', cdns: ['cdn.acme.com'], captureCount: 2 }],
      cdnGraph: [{ host: 'cdn.acme.com', families: ['Acme'] }],
    });
    render(<Capture />);
    expect(await screen.findByText('fw-1.2.bin')).toBeInTheDocument();
    expect(screen.getByText('fw-1.3.bin')).toBeInTheDocument();
    expect(screen.getByText('plaintext-http')).toBeInTheDocument();
    // The newer version offers a cross-version diff link.
    expect(screen.getByRole('link', { name: /diff prev/i })).toBeInTheDocument();
  });
});
