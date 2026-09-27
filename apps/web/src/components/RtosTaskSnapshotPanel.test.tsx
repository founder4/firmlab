/**
 * RtosTaskSnapshotPanel, on a DOM. The readings that would be wrong rather than ugly: a layout the form defaulted
 * instead of refusing, a walk shown as proof, a never-run panel reading as "no tasks", and an API refusal whose
 * field list was thrown away.
 */
import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { mockedApi } from '../test-api-mock';
import { MAX_SNAPSHOT_BYTES, RtosTaskSnapshotPanel, buildSnapshotRequest, parseAddress } from './RtosTaskSnapshotPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);
const m = en.rtosTasks;

beforeEach(() => {
  vi.clearAllMocks();
  setLocale('en');
  mockApi.rtosTasksResult.mockResolvedValue(null);
});

const fill = async () => {
  const file = new File([new Uint8Array(64)], 'ram.bin');
  fireEvent.change(screen.getByLabelText(m.field.file), { target: { files: [file] } });
  await screen.findByText(m.field.fileLoaded(64));
  fireEvent.change(screen.getByLabelText(m.field.base), { target: { value: '0x20000000' } });
  fireEvent.change(screen.getByLabelText(m.field.endian), { target: { value: 'little' } });
  fireEvent.change(screen.getByLabelText(m.field.pointerWidth), { target: { value: '4' } });
};

describe('RtosTaskSnapshotPanel', () => {
  it('says "not run" rather than "no tasks" when nothing was walked', async () => {
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    expect(await screen.findByText(m.notRun)).toBeInTheDocument();
  });

  it('refuses to submit an undeclared layout and names every missing field', async () => {
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    await screen.findByText(m.notRun);
    fireEvent.click(screen.getByRole('button', { name: m.run }));
    expect(await screen.findByText(m.error.fileMissing)).toBeInTheDocument();
    expect(screen.getByText(m.error.base)).toBeInTheDocument();
    expect(screen.getByText(m.error.endian)).toBeInTheDocument();
    expect(screen.getByText(m.error.pointerWidth)).toBeInTheDocument();
    expect(screen.getByLabelText(m.field.endian)).toHaveAttribute('aria-invalid', 'true');
    expect(mockApi.runRtosTasks).not.toHaveBeenCalled();
  });

  it('renders the API refusal details verbatim', async () => {
    mockApi.runRtosTasks.mockResolvedValue({
      refused: {
        error: 'Invalid RTOS snapshot',
        details: ['memory.base + snapshot length overflows the address space'],
      },
    });
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    await screen.findByText(m.notRun);
    await fill();
    fireEvent.click(screen.getByRole('button', { name: m.run }));
    expect(await screen.findByText('memory.base + snapshot length overflows the address space')).toBeInTheDocument();
    expect(screen.getByText(m.refusedHeading)).toBeInTheDocument();
    const input = mockApi.runRtosTasks.mock.calls[0]?.[1];
    expect(input?.memory).toMatchObject({ base: 0x20000000, endian: 'little', pointerWidth: 4 });
    expect(input?.memory.bytesBase64).toBe(btoa(String.fromCharCode(...new Uint8Array(64))));
  });

  it('shows the stored walk as a lead with per-lane coverage and hex TCBs', async () => {
    mockApi.rtosTasksResult.mockResolvedValue({
      proofState: 'needs_runtime_reproduction',
      coverage: 'partial',
      summary: '2 ready task record(s) found, but pxCurrentTCB: missing_symbol',
      snapshot: { base: 0x20000000, endian: 'little', pointerWidth: 4, bytesSupplied: 64 },
      limits: { maxSnapshotBytes: 524288, maxListItems: 256, maxReadyLists: 64 },
      currentTask: { coverage: 'missing_symbol', tcbAddress: null, evidence: ['pxCurrentTCB address not supplied'] },
      readyLists: [
        {
          priority: 1,
          listAddress: 0x20000010,
          coverage: 'complete',
          attempted: 2,
          completed: 2,
          bytesAttempted: 48,
          bytesCompleted: 48,
          tasks: [{ tcbAddress: 0x20000100 }, { tcbAddress: 0x20000200 }],
          evidence: [],
        },
      ],
    });
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    expect(await screen.findByText(/2 ready task record/)).toBeInTheDocument();
    expect(screen.getByText('partial')).toBeInTheDocument();
    expect(screen.getByText('needs reproduction')).toBeInTheDocument();
    expect(screen.getByText(m.result.proofLead)).toBeInTheDocument();
    expect(screen.getByText('0x20000100 0x20000200')).toBeInTheDocument();
    expect(screen.getByText('2 / 2')).toBeInTheDocument();
    expect(screen.getByText('pxCurrentTCB address not supplied')).toBeInTheDocument();
    expect(screen.getByText(m.result.limits(512, 256, 64))).toBeInTheDocument();
  });

  it('folds itself away on a Linux image', async () => {
    const { container } = render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="embedded-linux" />);
    await screen.findByText(m.notRun);
    const details = container.querySelector('details');
    expect(details).not.toBeNull();
    expect(details?.open).toBe(false);
  });
});

describe('buildSnapshotRequest', () => {
  const base = {
    bytes: new Uint8Array(4),
    base: '0',
    endian: 'big' as const,
    pointerWidth: '4' as const,
    pxCurrentTCB: '',
    readyLists: [],
  };

  it('reads 0x as hex and refuses a bare hex string instead of guessing', () => {
    expect(parseAddress('0x10')).toBe(16);
    expect(parseAddress('16')).toBe(16);
    expect(parseAddress('ff')).toBeNull();
  });

  it('enforces the snapshot cap, unique priorities and the 32-bit address space', () => {
    const r = buildSnapshotRequest(
      {
        ...base,
        bytes: new Uint8Array(MAX_SNAPSHOT_BYTES + 1),
        readyLists: [
          { priority: '1', address: '0x10' },
          { priority: '1', address: '0x100000000' },
        ],
      },
      m,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.errors.file).toBe(m.error.fileTooLarge(MAX_SNAPSHOT_BYTES + 1, 512));
    expect(r.errors['readyLists.1.priority']).toBe(m.error.priorityRepeated(1));
    expect(r.errors['readyLists.1.address']).toBe(m.error.address(32));
  });
});
