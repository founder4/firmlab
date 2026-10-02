/**
 * RtosTaskSnapshotPanel, on a DOM. The readings that would be wrong rather than ugly: a layout the form defaulted
 * instead of refusing, a walk shown as proof, a never-run panel reading as "no tasks", and an API refusal whose
 * field list was thrown away.
 */
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type RtosElfSymbolsResult, api } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { mockedApi } from '../test-api-mock';
import {
  EMPTY_FORM,
  MAX_SNAPSHOT_BYTES,
  RtosTaskSnapshotPanel,
  applyElfPrefill,
  buildSnapshotRequest,
  parseAddress,
} from './RtosTaskSnapshotPanel';

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
  mockApi.rtosElfSymbolsResult.mockResolvedValue(null);
  mockApi.renodeRamCaptureResult.mockResolvedValue(null);
});

const e = m.elfSymbols;

/** A read where most lists resolved, one name is ambiguous and the delayed lists resolved but are never filled. */
const ELF_READ: RtosElfSymbolsResult = {
  verdict: 'symbols-read',
  summary: '6 of 11 FreeRTOS kernel name(s) resolved from the static symbol table, 1 ambiguous.',
  identity: { elfClass: 'elf32', endian: 'little', pointerWidth: 4, machine: 40, machineName: 'ARM' },
  symbols: [
    {
      name: 'pxCurrentTCB',
      status: 'resolved',
      candidates: [{ address: 0x20000010, sizeHex: '0x4', binding: 'global' }],
    },
    {
      name: 'xPendingReadyList',
      status: 'ambiguous',
      candidates: [
        { address: 0x20000300, binding: 'local' },
        { address: 0x20000400, binding: 'local' },
      ],
      note: '2 definitions at different values; none is chosen by table order.',
    },
    { name: 'xSuspendedTaskList', status: 'resolved', candidates: [{ address: 0x200001d0, binding: 'local' }] },
    { name: 'xTasksWaitingTermination', status: 'absent', candidates: [] },
    { name: 'xDelayedTaskList1', status: 'resolved', candidates: [{ address: 0x200001a0, binding: 'local' }] },
    { name: 'pxCurrentTCBs', variant: 'smp', status: 'absent', candidates: [] },
  ],
  prefill: {
    pxCurrentTCB: 0x20000010,
    delayedLists: [{ name: 'xDelayedTaskList1', address: 0x200001a0 }],
    suspendedList: 0x200001d0,
    pendingReadyList: null,
    terminatedList: null,
  },
  notCarried: [
    {
      name: 'pxReadyTasksLists',
      reason: "Per-priority addresses need sizeof(List_t); the array's raw st_size is 0xa0.",
    },
  ],
};

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

  it('sends the state lists the analyst filled, and only those', async () => {
    mockApi.runRtosTasks.mockResolvedValue({ refused: { error: 'stop here', details: [] } });
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    await screen.findByText(m.notRun);
    await fill();
    fireEvent.change(screen.getByLabelText(m.field.delayedList), { target: { value: '0x20000100' } });
    fireEvent.change(screen.getByLabelText(m.field.suspendedList), { target: { value: '0x20000160' } });
    fireEvent.click(screen.getByRole('button', { name: m.run }));
    await screen.findByText('stop here');
    const symbols = mockApi.runRtosTasks.mock.calls[0]?.[1]?.symbols;
    expect(symbols).toEqual({
      pxCurrentTCB: null,
      readyLists: [],
      delayedLists: [{ name: 'pxDelayedTaskList', address: 0x20000100 }],
      suspendedList: 0x20000160,
    });
  });

  it('renders delayed lanes with wake ticks, other lanes without, and names what was not walked', async () => {
    mockApi.rtosTasksResult.mockResolvedValue({
      proofState: 'needs_runtime_reproduction',
      coverage: 'complete',
      summary: '0 ready task record(s) (plus 2 delayed, 1 suspended)',
      currentTask: { coverage: 'complete', tcbAddress: 0x20001000, pxCurrentTcbAddress: 0x20000080 },
      readyLists: [],
      delayedLists: [
        {
          kind: 'delayed',
          name: 'pxDelayedTaskList',
          listAddress: 0x20000100,
          coverage: 'complete',
          attempted: 2,
          completed: 2,
          itemValueMeaning: 'wake_tick',
          tasks: [
            { listItemAddress: 0x20000120, itemValue: 50, tcbAddress: 0x20003000 },
            { listItemAddress: 0x20000140, itemValue: 90, tcbAddress: 0x20004000 },
          ],
          evidence: [],
        },
      ],
      suspendedList: {
        kind: 'suspended',
        name: 'xSuspendedTaskList',
        listAddress: 0x20000160,
        coverage: 'truncated',
        attempted: 1,
        completed: 1,
        itemValueMeaning: 'not_maintained',
        tasks: [{ listItemAddress: 0x20000180, itemValue: 7, tcbAddress: 0x20005000 }],
        evidence: ['list item at 0x20000190 runs past the end of the supplied buffer'],
      },
      unwalkedKinds: ['delayed', 'pending', 'terminated'],
      tcbsOnSeveralLists: [0x20005000],
    });
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    const table = await screen.findByRole('table', { name: m.result.stateLanes });
    expect(table).toHaveTextContent('pxDelayedTaskList @ 0x20000100');
    expect(screen.getByText(m.result.wakeTick('0x20003000', 50))).toBeInTheDocument();
    expect(screen.getByText(m.result.wakeTick('0x20004000', 90))).toBeInTheDocument();
    // A suspended item's value is not a wake tick and is never shown as one.
    expect(screen.queryByText(m.result.wakeTick('0x20005000', 7))).toBeNull();
    expect(screen.getByText(m.result.kind.suspended)).toBeInTheDocument();
    expect(screen.getByText('truncated')).toBeInTheDocument();
    expect(
      screen.getByText(
        m.result.notWalked([m.result.secondDelayed, m.result.kind.pending, m.result.kind.terminated].join(', ')),
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(m.result.severalLists(1, '0x20005000'))).toBeInTheDocument();
  });

  it('shows no state-list section for a result stored before those lanes existed', async () => {
    mockApi.rtosTasksResult.mockResolvedValue({ coverage: 'complete', readyLists: [] });
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    await screen.findByText(m.result.heading);
    expect(screen.queryByRole('table', { name: m.result.stateLanes })).toBeNull();
  });

  it('folds itself away on a Linux image', async () => {
    const { container } = render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="embedded-linux" />);
    await screen.findByText(m.notRun);
    const details = container.querySelector('details');
    expect(details).not.toBeNull();
    expect(details?.open).toBe(false);
  });
});

describe('RtosTaskSnapshotPanel — ELF symbols', () => {
  it('reads the symbols on request and pre-fills only resolved fields, leaving the ambiguous one empty', async () => {
    mockApi.runRtosElfSymbols.mockResolvedValue({ jobId: 'j1' });
    mockApi.job.mockResolvedValue({ status: 'done', result: ELF_READ });
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    expect(await screen.findByText(e.notRun)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(m.field.pendingReadyList), { target: { value: '0x99' } });
    fireEvent.click(screen.getByRole('button', { name: e.read }));
    expect(mockApi.runRtosElfSymbols).toHaveBeenCalledWith('img');
    expect(await screen.findByText(e.filled('pxCurrentTCB, xSuspendedTaskList'), {}, { timeout: 3000 })).toBeVisible();
    expect(screen.getByLabelText(m.field.pxCurrentTCB)).toHaveValue('0x20000010');
    expect(screen.getByLabelText(m.field.suspendedList)).toHaveValue('0x200001d0');
    // Ambiguous: the analyst's own value is untouched. Absent: still empty. Delayed lists: never filled.
    expect(screen.getByLabelText(m.field.pendingReadyList)).toHaveValue('0x99');
    expect(screen.getByLabelText(m.field.terminatedList)).toHaveValue('');
    expect(screen.getByLabelText(m.field.delayedList)).toHaveValue('');
    expect(screen.getByLabelText(m.field.overflowDelayedList)).toHaveValue('');
    // Every name with its status, the ambiguous candidates side by side, and the reasons for what is not carried.
    const table = screen.getByRole('table', { name: e.symbolsTable });
    expect(table).toHaveTextContent('0x20000300 · 0x20000400');
    expect(table).toHaveTextContent(e.status.ambiguous);
    expect(table).toHaveTextContent(e.status.absent);
    expect(table).toHaveTextContent(e.smp);
    expect(screen.getByText(e.delayedNotFilled)).toBeInTheDocument();
    expect(screen.getByText(e.readyManual)).toBeInTheDocument();
    expect(screen.getByText(/raw st_size is 0xa0/)).toBeInTheDocument();
    // Byte order and pointer width are shown, never filled: the snapshot layout stays the analyst's declaration.
    expect(screen.getByLabelText(m.field.endian)).toHaveValue('');
    expect(screen.getByLabelText(m.field.pointerWidth)).toHaveValue('');
  });

  it('shows a stored read without applying it until the analyst asks', async () => {
    mockApi.rtosElfSymbolsResult.mockResolvedValue(ELF_READ);
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    expect(await screen.findByText(e.verdict['symbols-read'])).toBeInTheDocument();
    expect(screen.getByLabelText(m.field.pxCurrentTCB)).toHaveValue('');
    fireEvent.click(screen.getByRole('button', { name: e.fill }));
    await waitFor(() => expect(screen.getByLabelText(m.field.pxCurrentTCB)).toHaveValue('0x20000010'));
    expect(mockApi.runRtosElfSymbols).not.toHaveBeenCalled();
  });

  it('states a non-ELF image as a reason, never as "no FreeRTOS", and offers nothing to fill', async () => {
    mockApi.rtosElfSymbolsResult.mockResolvedValue({
      verdict: 'refused',
      summary: 'The image is not an ELF file, so it carries no symbol table to read.',
      refusal: { code: 'not-elf', detail: 'The input does not start with the ELF magic.' },
      symbols: [{ name: 'pxCurrentTCB', status: 'unavailable', candidates: [] }],
      prefill: null,
      notCarried: [],
    });
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    expect(await screen.findByText(e.verdict.refused)).toBeInTheDocument();
    expect(screen.getByText(/not-elf: The input does not start with the ELF magic/)).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: e.symbolsTable })).toBeNull();
    expect(screen.queryByRole('button', { name: e.fill })).toBeNull();
    expect(screen.queryByText(/no FreeRTOS\b(?! )/i)).toBeNull();
    expect(screen.getByRole('button', { name: e.reread })).toBeEnabled();
  });

  it('states a stripped ELF as not evidence against FreeRTOS', async () => {
    mockApi.rtosElfSymbolsResult.mockResolvedValue({ verdict: 'no-static-symbol-table', prefill: null });
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    expect(await screen.findByText(e.verdict['no-static-symbol-table'])).toBeInTheDocument();
    expect(e.verdict['no-static-symbol-table']).toMatch(/not evidence the image lacks FreeRTOS/);
  });

  it('a failed read is a stated fault, and the form stays as it was', async () => {
    mockApi.runRtosElfSymbols.mockRejectedValue(new Error('503 Service Unavailable'));
    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    await screen.findByText(e.notRun);
    fireEvent.click(screen.getByRole('button', { name: e.read }));
    expect(await screen.findByText('503 Service Unavailable')).toBeInTheDocument();
    expect(screen.getByText(e.failed)).toBeInTheDocument();
    expect(screen.getByLabelText(m.field.pxCurrentTCB)).toHaveValue('');
  });
});

describe('RtosTaskSnapshotPanel — Renode RAM capture', () => {
  const rc = m.ramCapture;

  it('says not run initially and triggers capture with chosen seconds', async () => {
    mockApi.runRenodeRamCapture.mockResolvedValue({ jobId: 'j-ram' });
    mockApi.job.mockResolvedValue({
      status: 'done',
      result: {
        available: true,
        ran: true,
        captured: true,
        reason: 'Captured 20480 bytes from sram',
        proofState: 'needs_runtime_reproduction',
        platform: 'cpus/stm32l072.repl',
        region: { name: 'sram', base: 0x20000000, size: 0x5000 },
        bytesBase64: btoa('HELLO_RAM_WORLD'),
        bytesCaptured: 15,
        seconds: 2,
        secondsRun: 2,
        layout: { endian: 'little', pointerWidth: 4 },
      },
    });

    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    expect(await screen.findByText(rc.notRun)).toBeInTheDocument();

    const btn = screen.getByRole('button', { name: rc.capture });
    fireEvent.click(btn);

    expect(mockApi.runRenodeRamCapture).toHaveBeenCalledWith('img', { seconds: 2 });
    expect(await screen.findByText(rc.capturedHeading)).toBeInTheDocument();
    expect(screen.getByText(rc.loadedIntoForm)).toBeInTheDocument();

    // Verify fields populated into the form
    expect(screen.getByLabelText(m.field.base)).toHaveValue('0x20000000');
    expect(screen.getByLabelText(m.field.endian)).toHaveValue('little');
    expect(screen.getByLabelText(m.field.pointerWidth)).toHaveValue('4');
  });

  it('renders refusal reason when RAM capture is refused', async () => {
    mockApi.runRenodeRamCapture.mockResolvedValue({ jobId: 'j-ram-refused' });
    mockApi.job.mockResolvedValue({
      status: 'done',
      result: {
        available: true,
        ran: false,
        captured: false,
        reason: 'Firmware is not an ELF binary; raw binaries carry no section headers.',
        proofState: 'needs_runtime_reproduction',
        platform: null,
        region: null,
        bytesBase64: null,
        bytesCaptured: 0,
        seconds: 2,
        secondsRun: 0,
      },
    });

    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    await screen.findByText(rc.notRun);

    fireEvent.click(screen.getByRole('button', { name: rc.capture }));
    expect(await screen.findByText(rc.refused)).toBeInTheDocument();
    expect(
      screen.getByText('Firmware is not an ELF binary; raw binaries carry no section headers.'),
    ).toBeInTheDocument();
  });

  it('displays stored ram capture and allows reloading into form', async () => {
    mockApi.renodeRamCaptureResult.mockResolvedValue({
      available: true,
      ran: true,
      captured: true,
      reason: 'Captured 20480 bytes from sram',
      proofState: 'needs_runtime_reproduction',
      platform: 'cpus/stm32l072.repl',
      region: { name: 'sram', base: 0x20000000, size: 0x5000 },
      bytesBase64: btoa('STORED_RAM_BYTES'),
      bytesCaptured: 16,
      seconds: 2,
      secondsRun: 2,
      layout: { endian: 'little', pointerWidth: 4 },
    });

    render(<RtosTaskSnapshotPanel imageId="img" firmwareClass="rtos" />);
    expect(await screen.findByText(rc.capturedHeading)).toBeInTheDocument();

    const loadBtn = screen.getByRole('button', { name: rc.loadIntoForm });
    fireEvent.click(loadBtn);

    expect(await screen.findByText(rc.loadedIntoForm)).toBeInTheDocument();
    expect(screen.getByLabelText(m.field.base)).toHaveValue('0x20000000');
  });
});

describe('applyElfPrefill', () => {
  it('fills a field only when its pre-fill address exists AND the symbol itself resolved', () => {
    const { form, filled } = applyElfPrefill(EMPTY_FORM, ELF_READ);
    expect(filled).toEqual(['pxCurrentTCB', 'xSuspendedTaskList']);
    expect(form).toMatchObject({ pxCurrentTCB: '0x20000010', suspendedList: '0x200001d0', pendingReadyList: '' });
    // A pre-fill address whose symbol is not `resolved` is refused even if the API carried one.
    const contradicted = applyElfPrefill(EMPTY_FORM, {
      ...ELF_READ,
      prefill: { ...ELF_READ.prefill, pendingReadyList: 0x20000300 },
    });
    expect(contradicted.form.pendingReadyList).toBe('');
  });

  it('changes nothing without a pre-fill', () => {
    expect(applyElfPrefill(EMPTY_FORM, null)).toEqual({ form: EMPTY_FORM, filled: [] });
    expect(applyElfPrefill(EMPTY_FORM, { verdict: 'refused', prefill: null }).filled).toEqual([]);
  });
});

describe('buildSnapshotRequest', () => {
  const base = {
    ...EMPTY_FORM,
    bytes: new Uint8Array(4),
    base: '0',
    endian: 'big' as const,
    pointerWidth: '4' as const,
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

  it('builds delayed lanes with their pointer names and leaves empty state fields out of the request', () => {
    const r = buildSnapshotRequest(
      { ...base, delayedList: '0x100', overflowDelayedList: '0x200', terminatedList: '768' },
      m,
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.input.symbols).toEqual({
      pxCurrentTCB: null,
      readyLists: [],
      delayedLists: [
        { name: 'pxDelayedTaskList', address: 0x100 },
        { name: 'pxOverflowDelayedTaskList', address: 0x200 },
      ],
      terminatedList: 768,
    });
  });

  it('refuses a state list that repeats another lane address or is not an address', () => {
    const r = buildSnapshotRequest(
      {
        ...base,
        readyLists: [{ priority: '1', address: '0x10' }],
        suspendedList: '0x10',
        pendingReadyList: 'ff',
      },
      m,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.errors.suspendedList).toBe(m.error.addressRepeated('0x10'));
    expect(r.errors.pendingReadyList).toBe(m.error.address(32));
  });
});
