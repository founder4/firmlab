import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type CaptureDevice, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { WirelessReassemblyPanel } from './WirelessReassemblyPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const testDevice: CaptureDevice = {
  id: 'dev1',
  mac: 'aa:bb:cc:dd:ee:ff',
  ouiVendor: 'Espressif',
  ip: null,
  mdnsIdentity: null,
  openPorts: null,
  typeGuess: null,
  typeConfidence: null,
  firstSeen: Date.now(),
  lastSeen: Date.now(),
};

function renderPanel(props?: Partial<Parameters<typeof WirelessReassemblyPanel>[0]>) {
  return render(
    <MemoryRouter>
      <WirelessReassemblyPanel captureEnabled={true} devices={[testDevice]} {...props} />
    </MemoryRouter>,
  );
}

function buildZigbeeOtaBuffer(image: Uint8Array): Uint8Array {
  const HEADER = 56;
  const sub = 6 + image.length;
  const buf = new Uint8Array(HEADER + sub);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, 0x0beef11e, true);
  dv.setUint16(4, 0x0100, true);
  dv.setUint16(6, HEADER, true);
  dv.setUint16(8, 0, true);
  dv.setUint16(10, 0x1234, true);
  dv.setUint16(12, 0x0001, true);
  dv.setUint32(14, 0x00000003, true);
  dv.setUint16(18, 0x0002, true);
  for (let i = 0; i < 'TestFW'.length; i++) buf[20 + i] = 'TestFW'.charCodeAt(i);
  dv.setUint32(52, HEADER + sub, true);
  dv.setUint16(HEADER, 0x0000, true);
  dv.setUint32(HEADER + 2, image.length, true);
  buf.set(image, HEADER + 6);
  return buf;
}

beforeEach(() => {
  vi.clearAllMocks();
  setLocale('en');
  mockApi.createBleCaptureSession.mockResolvedValue({ sessionId: 'ble-sess-1' });
  mockApi.createZigbeeCaptureSession.mockResolvedValue({ sessionId: 'zig-sess-1' });
  mockApi.stageBleDfu.mockResolvedValue({
    flowId: 'flow-ble-1',
    size: 6,
    firmwareScore: 85,
    carved: true,
  });
  mockApi.stageZigbeeOta.mockResolvedValue({
    flowId: 'flow-zig-1',
    size: 4,
    manufacturerCode: 0x1234,
    imageType: 0x0001,
    fileVersion: 3,
    firmwareScore: 90,
    carved: true,
  });
  mockApi.ingestCaptureFlow.mockResolvedValue({
    imageId: 'img-reassembled-1',
    filename: 'firmware.bin',
  });
});

describe('WirelessReassemblyPanel', () => {
  it('renders the panel title, subtitle, and tabs', () => {
    renderPanel();
    expect(screen.getByText('Reconstruct firmware from wireless capture')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'BLE DFU' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Zigbee OTA' })).toBeInTheDocument();
  });

  it('explains how to enable FIRMLAB_CAPTURE when capture lane is off', () => {
    renderPanel({ captureEnabled: false });
    expect(screen.getByTestId('capture-disabled-banner')).toBeInTheDocument();
    expect(screen.getByText(/Set FIRMLAB_CAPTURE=1 to enable it/i)).toBeInTheDocument();
    const btn = screen.getByRole('button', { name: 'Reassemble BLE DFU' });
    expect(btn).toBeDisabled();
  });

  it('validates operator acknowledgement before submit', async () => {
    renderPanel();
    const submitBtn = screen.getByRole('button', { name: 'Reassemble BLE DFU' });
    fireEvent.click(submitBtn);
    expect(await screen.findByTestId('form-error')).toHaveTextContent(
      'Operator acknowledgement is required before creating a session or submitting captures.',
    );
  });

  it('validates session ID before submit', async () => {
    renderPanel();
    const ack = screen.getByLabelText(/I acknowledge authorization/i);
    fireEvent.click(ack);

    const submitBtn = screen.getByRole('button', { name: 'Reassemble BLE DFU' });
    fireEvent.click(submitBtn);

    expect(await screen.findByTestId('form-error')).toHaveTextContent(
      'A valid session ID is required. Create or specify one above.',
    );
  });

  it('validates files before submit', async () => {
    renderPanel({ initialSessionId: 'sess-abc' });
    const ack = screen.getByLabelText(/I acknowledge authorization/i);
    fireEvent.click(ack);

    const submitBtn = screen.getByRole('button', { name: 'Reassemble BLE DFU' });
    fireEvent.click(submitBtn);

    expect(await screen.findByTestId('form-error')).toHaveTextContent(
      'At least one capture file or chunk payload is required.',
    );
  });

  it('creates a session on demand for BLE and Zigbee tabs', async () => {
    renderPanel();
    const ack = screen.getByLabelText(/I acknowledge authorization/i);
    fireEvent.click(ack);

    const createBtn = screen.getByRole('button', { name: 'Create session' });
    fireEvent.click(createBtn);

    await waitFor(() => {
      expect(mockApi.createBleCaptureSession).toHaveBeenCalledWith(null, true);
    });
    expect(screen.getByDisplayValue('ble-sess-1')).toBeInTheDocument();

    // Switch to Zigbee OTA tab
    const zigTab = screen.getByRole('tab', { name: 'Zigbee OTA' });
    fireEvent.click(zigTab);

    const createBtnZig = screen.getByRole('button', { name: 'Create session' });
    fireEvent.click(createBtnZig);

    await waitFor(() => {
      expect(mockApi.createZigbeeCaptureSession).toHaveBeenCalledWith(null, true);
    });
    expect(screen.getByDisplayValue('zig-sess-1')).toBeInTheDocument();
  });

  it('successfully reassembles complete BLE DFU and links to image overview', async () => {
    renderPanel({ initialSessionId: 'ble-sess-active' });
    const ack = screen.getByLabelText(/I acknowledge authorization/i);
    fireEvent.click(ack);

    const json = JSON.stringify({
      chunks: ['AQID', 'BAUG'],
    });
    const file = new File([json], 'capture.json', { type: 'application/json' });
    const fileInput = screen.getByLabelText('Capture file(s)');
    fireEvent.change(fileInput, { target: { files: [file] } });

    // Matching init packet (6 bytes little endian)
    const initBuf = Uint8Array.from([0xde, 0xad, 0x06, 0x00, 0x00, 0x00]);
    const initFile = new File([initBuf], 'init.dat');
    const initInput = screen.getByLabelText(/Nordic DFU init packet/i);
    fireEvent.change(initInput, { target: { files: [initFile] } });

    const submitBtn = screen.getByRole('button', { name: 'Reassemble BLE DFU' });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockApi.stageBleDfu).toHaveBeenCalledWith('ble-sess-active', ['AQID', 'BAUG'], 'capture.bin');
    });

    await waitFor(() => {
      expect(mockApi.ingestCaptureFlow).toHaveBeenCalledWith('ble-sess-active', 'flow-ble-1');
    });

    expect(await screen.findByTestId('complete-banner')).toBeInTheDocument();
    expect(screen.getByText('Complete reassembly')).toBeInTheDocument();
    expect(screen.getAllByText(/6 bytes/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Matches declared init packet size/i)).toBeInTheDocument();

    const link = screen.getByTestId('image-overview-link');
    expect(link).toHaveAttribute('href', '/image/img-reassembled-1/overview');
  });

  it('detects incomplete BLE DFU and does not claim success', async () => {
    renderPanel({ initialSessionId: 'ble-sess-active' });
    const ack = screen.getByLabelText(/I acknowledge authorization/i);
    fireEvent.click(ack);

    // Only 3 bytes provided
    const json = JSON.stringify({
      chunks: ['AQID'],
    });
    const file = new File([json], 'capture.json', { type: 'application/json' });
    const fileInput = screen.getByLabelText('Capture file(s)');
    fireEvent.change(fileInput, { target: { files: [file] } });

    // Declares 20 bytes expected
    const initBuf = Uint8Array.from([0xde, 0xad, 0x14, 0x00, 0x00, 0x00]);
    const initFile = new File([initBuf], 'init.dat');
    const initInput = screen.getByLabelText(/Nordic DFU init packet/i);
    fireEvent.change(initInput, { target: { files: [initFile] } });

    const submitBtn = screen.getByRole('button', { name: 'Reassemble BLE DFU' });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockApi.stageBleDfu).toHaveBeenCalled();
    });

    // Incomplete results banner must appear
    expect(await screen.findByTestId('incomplete-banner')).toBeInTheDocument();
    expect(screen.getByText('Incomplete capture')).toBeInTheDocument();
    expect(screen.getAllByText(/Missing 17 bytes/i).length).toBeGreaterThan(0);
    expect(screen.queryByTestId('complete-banner')).not.toBeInTheDocument();
    // Auto-ingest should NOT be called for incomplete result
    expect(mockApi.ingestCaptureFlow).not.toHaveBeenCalled();
  });

  it('successfully reassembles complete Zigbee OTA, validates header and links to overview', async () => {
    renderPanel({ initialSessionId: 'zig-sess-active' });
    const zigTab = screen.getByRole('tab', { name: 'Zigbee OTA' });
    fireEvent.click(zigTab);

    const ack = screen.getByLabelText(/I acknowledge authorization/i);
    fireEvent.click(ack);

    const rawOta = buildZigbeeOtaBuffer(Uint8Array.from([1, 2, 3, 4]));
    const otaFile = new File([rawOta.buffer as ArrayBuffer], 'firmware.ota');
    const fileInput = screen.getByLabelText('Capture file(s)');
    fireEvent.change(fileInput, { target: { files: [otaFile] } });

    const submitBtn = screen.getByRole('button', { name: 'Reassemble Zigbee OTA' });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockApi.stageZigbeeOta).toHaveBeenCalledWith('zig-sess-active', expect.any(Array), 'firmware.ota');
    });

    await waitFor(() => {
      expect(mockApi.ingestCaptureFlow).toHaveBeenCalledWith('zig-sess-active', 'flow-zig-1');
    });

    expect(await screen.findByTestId('complete-banner')).toBeInTheDocument();
    expect(screen.getByText('Complete reassembly')).toBeInTheDocument();
    expect(screen.getByText(/Valid Zigbee OTA header \(0x0BEEF11E\)/i)).toBeInTheDocument();
    expect(screen.getByTestId('image-overview-link')).toHaveAttribute('href', '/image/img-reassembled-1/overview');
  });

  it('detects truncated Zigbee OTA container and reports missing bytes', async () => {
    renderPanel({ initialSessionId: 'zig-sess-active' });
    const zigTab = screen.getByRole('tab', { name: 'Zigbee OTA' });
    fireEvent.click(zigTab);

    const ack = screen.getByLabelText(/I acknowledge authorization/i);
    fireEvent.click(ack);

    const rawOta = buildZigbeeOtaBuffer(Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]));
    // Truncate to 50 bytes (less than 56 header + data)
    const truncated = rawOta.subarray(0, 50);
    const otaFile = new File([truncated.buffer.slice(0, 50) as ArrayBuffer], 'truncated.ota');
    const fileInput = screen.getByLabelText('Capture file(s)');
    fireEvent.change(fileInput, { target: { files: [otaFile] } });

    const submitBtn = screen.getByRole('button', { name: 'Reassemble Zigbee OTA' });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockApi.stageZigbeeOta).toHaveBeenCalled();
    });

    expect(await screen.findByTestId('incomplete-banner')).toBeInTheDocument();
    expect(screen.getByText('Incomplete capture')).toBeInTheDocument();
    expect(mockApi.ingestCaptureFlow).not.toHaveBeenCalled();
  });

  it('renders all UI elements in Spanish when locale is set to es', async () => {
    act(() => {
      setLocale('es');
    });
    renderPanel();

    expect(screen.getByText('Reconstruir firmware desde una captura inalámbrica')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'DFU de BLE' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'OTA de Zigbee' })).toBeInTheDocument();
    expect(screen.getByText(/Reconozco la autorización para reconstruir/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Crear sesión' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reconstruir DFU de BLE' })).toBeInTheDocument();
  });
});
