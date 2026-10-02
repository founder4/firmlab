import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type SwitchFamilyAnalysis, api } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { es } from '../locales/es';
import { mockedApi } from '../test-api-mock';
import { SwitchFamilyPanel } from './SwitchFamilyPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);
const m = en.switchFamily;
const summary =
  'Only unverified family-template tokens are present; they cannot single out a family. Static leads never identify live hardware.';
const saved: SwitchFamilyAnalysis = {
  raw: { status: 'completed', reason: 'Scanned 20 raw bytes.', result: { verdict: 'none-observed' } },
  rootfs: {
    status: 'partial',
    reason: 'Examined 1 of 3 discovered regular files; 2 skipped.',
    result: { verdict: 'template-only' },
    coverage: {
      filesExamined: 1,
      filesDiscovered: 3,
      filesSkipped: 2,
      filesTruncated: 1,
      bytesScanned: 12,
      symlinksSkipped: 4,
      specialFilesSkipped: 5,
      entriesExamined: 9,
      inventoryComplete: false,
      selection: 'Sorted relative paths; scan bounded prefixes.',
      limits: { maxFiles: 1, maxBytesPerFile: 12, maxTotalBytes: 12, maxEntries: 9 },
    },
  },
  overall: {
    verdict: 'template-only',
    summary,
    candidates: [
      {
        family: 'rtl83xx',
        standing: 'family-template',
        distinctTokens: ['RTL8366'],
        hitCount: 2,
        evidence: [{ lane: 'rootfs', path: 'lib/modules/driver.ko', offset: 16, context: 'driver token RTL8366' }],
      },
    ],
    vendorMentions: [{ vendor: 'Realtek', count: 1 }],
    deferred: [{ what: 'Driver-name mappings', reason: 'Not backed by a repository source.' }],
  },
};

beforeEach(() => {
  vi.resetAllMocks();
  setLocale('en');
  mockApi.switchFamilyResult.mockResolvedValue(null);
});
afterEach(() => vi.useRealTimers());

describe('SwitchFamilyPanel', () => {
  it('shows the verbatim summary, template standing, tokens and file evidence without promoting them', async () => {
    mockApi.switchFamilyResult.mockResolvedValue(saved);
    render(<SwitchFamilyPanel imageId="image-1" />);
    expect(await screen.findByText(summary)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: `${m.overall}: ${m.verdict['template-only']}` })).toBeInTheDocument();
    const candidates = within(screen.getByRole('region', { name: m.candidates }));
    expect(candidates.getByText('family-template')).toBeInTheDocument();
    expect(candidates.getByText(/Distinct tokens: RTL8366/)).toBeInTheDocument();
    expect(candidates.getByText(/Matches counted: 2/)).toBeInTheDocument();
    fireEvent.click(candidates.getByText('Retained evidence (1)'));
    expect(candidates.getByText('lib/modules/driver.ko')).toBeVisible();
    expect(candidates.getByText('0x10', { exact: false })).toBeVisible();
    expect(candidates.getByText('driver token RTL8366')).toBeVisible();
    expect(screen.getByText('Driver-name mappings')).toBeInTheDocument();
    expect(screen.getByText(m.incompleteInventory)).toBeInTheDocument();
    expect(screen.getByText(m.links).nextElementSibling).toHaveTextContent('4');
    expect(screen.getByText(m.filesSkipped).nextElementSibling).toHaveTextContent('2');
  });

  it('shows a missing rootfs as not run, with the exact provider reason', async () => {
    mockApi.switchFamilyResult.mockResolvedValue({
      overall: { verdict: 'none-observed', summary: 'No literal in scanned raw bytes; not evidence of no switch.' },
      rootfs: { status: 'not-run', reason: 'not run: no extracted rootfs', result: null },
    } satisfies SwitchFamilyAnalysis);
    render(<SwitchFamilyPanel imageId="image-1" />);
    expect(await screen.findByText('not run: no extracted rootfs')).toBeInTheDocument();
    const lane = within(screen.getByRole('region', { name: m.rootfs }));
    expect(lane.getByRole('heading', { name: `${m.rootfs} — ${m.status['not-run']}` })).toBeInTheDocument();
    expect(lane.queryByText(/none found/i)).not.toBeInTheDocument();
    expect(lane.queryByText(m.incompleteInventory)).not.toBeInTheDocument();
    // Zero counts under a lane that never ran would read as "examined, found nothing".
    expect(lane.queryByText(m.filesExamined)).not.toBeInTheDocument();
    expect(lane.queryByRole('heading', { name: m.coverage })).not.toBeInTheDocument();
  });

  it('labels vendor-only evidence separately and never turns a vendor into a family candidate', async () => {
    mockApi.switchFamilyResult.mockResolvedValue({
      overall: {
        verdict: 'vendor-only',
        summary: 'Vendor names are not family evidence.',
        candidates: [],
        vendorMentions: [{ vendor: 'Broadcom', count: 7 }],
      },
    } satisfies SwitchFamilyAnalysis);
    render(<SwitchFamilyPanel imageId="image-1" />);
    expect(await screen.findByText('Vendor names are not family evidence.')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: m.vendors })).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: m.vendors })).getByText(/Broadcom.*7/)).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: m.candidates })).queryByText(/Broadcom/)).not.toBeInTheDocument();
    expect(screen.getByText(m.noCandidates)).toBeInTheDocument();
  });

  it('renders an older result without inventing zero counts or a negative verdict', async () => {
    mockApi.switchFamilyResult.mockResolvedValue({ rootfs: { coverage: {} }, overall: {} });
    render(<SwitchFamilyPanel imageId="image-1" />);
    expect(await screen.findByRole('heading', { name: `${m.overall}: ${m.notRecorded}` })).toBeInTheDocument();
    expect(screen.getByText(m.filesExamined).nextElementSibling).toHaveTextContent(m.notRecorded);
    expect(screen.queryByText(m.noCandidates)).not.toBeInTheDocument();
    expect(screen.queryByText(m.empty)).not.toBeInTheDocument();
  });

  it('distinguishes a failed saved-result fetch from a never-run scan', async () => {
    mockApi.switchFamilyResult.mockRejectedValue(new Error('offline'));
    render(<SwitchFamilyPanel imageId="image-1" />);
    expect(await screen.findByRole('alert')).toHaveTextContent(m.loadFailed);
    expect(screen.queryByText(m.empty)).not.toBeInTheDocument();
  });

  it('starts a job, polls queued/running work, then fetches its saved result', async () => {
    mockApi.runSwitchFamily.mockResolvedValue({ jobId: 'job-1' });
    mockApi.job.mockResolvedValueOnce({ status: 'running' }).mockResolvedValueOnce({ status: 'done' });
    mockApi.switchFamilyResult.mockResolvedValueOnce(null).mockResolvedValueOnce(saved);
    render(<SwitchFamilyPanel imageId="image-1" />);
    fireEvent.click(await screen.findByRole('button', { name: m.run }));
    await waitFor(() => expect(mockApi.job).toHaveBeenCalledWith('job-1'));
    expect(screen.getByRole('button', { name: m.running })).toBeDisabled();
    expect(await screen.findByText(summary, {}, { timeout: 2500 })).toBeInTheDocument();
    expect(mockApi.runSwitchFamily).toHaveBeenCalledWith('image-1');
    expect(mockApi.job).toHaveBeenCalledTimes(2);
    expect(mockApi.switchFamilyResult).toHaveBeenCalledTimes(2);
    expect(screen.getByRole('button', { name: m.rerun })).toBeEnabled();
  });

  it.each(['cancelled', 'error'] as const)(
    'shows %s and retains the clearly labelled previous result',
    async (status) => {
      mockApi.switchFamilyResult.mockResolvedValue(saved);
      mockApi.runSwitchFamily.mockResolvedValue({ jobId: 'job-1' });
      mockApi.job.mockResolvedValue({ status, error: 'Read failed' });
      render(<SwitchFamilyPanel imageId="image-1" />);
      fireEvent.click(await screen.findByRole('button', { name: m.rerun }));
      expect(await screen.findByRole('alert')).toHaveTextContent(status === 'cancelled' ? m.cancelled : 'Read failed');
      expect(screen.getByText(m.latest)).toBeInTheDocument();
      expect(screen.getByText(summary)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: m.rerun })).toBeEnabled();
    },
  );

  it('stops scheduled polling when unmounted', async () => {
    mockApi.runSwitchFamily.mockResolvedValue({ jobId: 'job-1' });
    mockApi.job.mockResolvedValue({ status: 'running' });
    const view = render(<SwitchFamilyPanel imageId="image-1" />);
    const button = await screen.findByRole('button', { name: m.run });
    vi.useFakeTimers();
    await act(async () => fireEvent.click(button));
    expect(mockApi.job).toHaveBeenCalledTimes(1);
    view.unmount();
    await act(async () => vi.advanceTimersByTimeAsync(3000));
    expect(mockApi.job).toHaveBeenCalledTimes(1);
  });

  it('ignores a late saved result after changing images', async () => {
    let resolveOld!: (result: SwitchFamilyAnalysis | null) => void;
    mockApi.switchFamilyResult
      .mockReturnValueOnce(
        new Promise((resolve) => {
          resolveOld = resolve;
        }),
      )
      .mockResolvedValueOnce(null);
    const view = render(<SwitchFamilyPanel imageId="old" />);
    view.rerender(<SwitchFamilyPanel imageId="new" />);
    expect(await screen.findByText(m.empty)).toBeInTheDocument();
    await act(async () => resolveOld(saved));
    expect(screen.queryByText(summary)).not.toBeInTheDocument();
  });

  it('paginates retained evidence without hiding that more rows exist', async () => {
    const read = structuredClone(saved);
    if (read.overall?.candidates?.[0])
      read.overall.candidates[0].evidence = Array.from({ length: 21 }, (_, i) => ({ path: `file-${i}`, offset: i }));
    mockApi.switchFamilyResult.mockResolvedValue(read);
    render(<SwitchFamilyPanel imageId="image-1" />);
    fireEvent.click(await screen.findByText('Retained evidence (21)'));
    expect(screen.getByText('file-0')).toBeVisible();
    expect(screen.queryByText('file-20')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: m.next }));
    expect(screen.getByText('file-20')).toBeVisible();
    expect(screen.getByRole('button', { name: m.next })).toBeDisabled();
  });

  it('renders Spanish labels while preserving the provider summary verbatim', async () => {
    setLocale('es');
    mockApi.switchFamilyResult.mockResolvedValue(saved);
    render(<SwitchFamilyPanel imageId="image-1" />);
    expect(await screen.findByText(summary)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: es.switchFamily.title })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: es.switchFamily.vendors })).toBeInTheDocument();
    expect(screen.getByText(es.switchFamily.filesTruncated)).toBeInTheDocument();
  });
});
