/**
 * KernelPosture, on a DOM.
 *
 * `kernel-posture.test.ts` already pins every decision — `answerClass`, `orderAnswers`, the censuses, `postureState`
 * — without a DOM. What it cannot show is that the panel WIRES them: that the four empty states reach four different
 * sentences instead of one empty table, that a fetch which failed reads as "has not run" rather than as a kernel with
 * nothing wrong with it, and that a `not-applicable` row prints "n/a here" beside a real gap's "unanswered". That
 * last one is the whole reason the class exists; a pure test proves the classifier and a render proves the reader
 * sees the difference.
 */
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type KernelPostureResult, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { KernelPosture } from './KernelPosture';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

// Before the render, never after: the locale store notifies live subscribers.
beforeEach(() => setLocale('en'));

const located = (o: Partial<KernelPostureResult> = {}): KernelPostureResult => ({
  available: true,
  located: true,
  version: '2.6.31',
  versionSource: 'kernel-banner',
  answers: [
    // Declaration order here is deliberately the reverse of the display order the panel must impose.
    {
      id: 'kaslr',
      option: 'CONFIG_RANDOMIZE_BASE',
      question: 'Is the kernel base randomised?',
      verdict: 'unknown',
      reason: 'option-postdates-kernel',
    },
    {
      id: 'stackprot',
      option: 'CONFIG_CC_STACKPROTECTOR',
      question: 'Is the stack protector compiled in?',
      verdict: 'unknown',
      reason: 'no-kernel-config-shipped',
    },
    {
      id: 'modsig',
      option: 'CONFIG_MODULE_SIG_FORCE',
      question: 'Are unsigned modules refused?',
      verdict: 'off',
      bad: true,
      source: 'kernel-blob',
      detail: 'The marker string is absent from the decompressed image.',
    },
  ],
  ...o,
});

describe('KernelPosture', () => {
  it('orders by what a reader must act on and labels a closed question apart from an open one', async () => {
    mockApi.kernelPosture.mockResolvedValue(located());
    render(<KernelPosture imageId="img1" />);

    const rows = await screen.findAllByRole('row');
    // Header, then weak, then unanswered, then not-applicable — never the provider's declaration order.
    expect(within(rows[1] as HTMLElement).getByText('weak')).toBeInTheDocument();
    expect(within(rows[1] as HTMLElement).getByText('CONFIG_MODULE_SIG_FORCE')).toBeInTheDocument();
    expect(within(rows[2] as HTMLElement).getByText('unanswered')).toBeInTheDocument();
    expect(within(rows[3] as HTMLElement).getByText('n/a here')).toBeInTheDocument();
    expect(within(rows[3] as HTMLElement).getByText('CONFIG_RANDOMIZE_BASE')).toBeInTheDocument();

    // The denominator a bare row count cannot give: one gap, not two.
    expect(
      screen.getByText(/3 questions — 1 weak, 0 ok, 1 unanswered, 1 not applicable to this kernel\./),
    ).toBeInTheDocument();
    // `source` on a settled answer, and the provider's own sentence beside the question.
    expect(screen.getByText('kernel-blob')).toBeInTheDocument();
    expect(screen.getByText(/marker string is absent/)).toBeInTheDocument();
    // `reason` where there is no source — which one the provider set is itself the information.
    expect(screen.getByText('no-kernel-config-shipped')).toBeInTheDocument();
  });

  it('carries the version provenance beside the version', async () => {
    mockApi.kernelPosture.mockResolvedValue(located({ age: { years: 15 }, configPath: 'etc/kernel.config' }));
    render(<KernelPosture imageId="img1" />);

    expect(await screen.findByText('2.6.31')).toBeInTheDocument();
    // A banner string and a shipped config are not the same standard of evidence, so the panel prints which.
    expect(screen.getByText('kernel-banner')).toBeInTheDocument();
    expect(screen.getByText('15 years')).toBeInTheDocument();
    expect(screen.getByText('etc/kernel.config')).toBeInTheDocument();
  });

  it('counts signed modules against what was inspected, not against what was found', async () => {
    mockApi.kernelPosture.mockResolvedValue(
      located({ modules: { moduleCount: 30, inspectedCount: 12, signedCount: 0, moduleInventoryComplete: false } }),
    );
    render(<KernelPosture imageId="img1" />);

    // A walk that could not read every module must not have its silence counted as unsigned modules — and an
    // incomplete inventory is printed as a floor, never as a total.
    expect(await screen.findByText('0 signed of 12 inspected (of ≥30)')).toBeInTheDocument();
  });

  it('keeps the three curated CVE states apart instead of collapsing two of them into zero', async () => {
    mockApi.kernelPosture.mockResolvedValue(
      located({
        cves: [
          { id: 'CVE-2016-5195', impact: 'LPE', state: 'applicable', reason: 'in range', note: '' },
          { id: 'CVE-2017-1000112', impact: 'LPE', state: 'ruled_out', reason: 'UFO absent', note: '' },
          { id: 'CVE-2019-11477', impact: 'DoS', state: 'unknown', reason: 'could not decide', note: '' },
        ],
      }),
    );
    render(<KernelPosture imageId="img1" />);

    expect(
      await screen.findByText(
        /3 curated, version-range kernel CVEs — 1 leads, 1 dismissed by configuration evidence, 1 undetermined\./,
      ),
    ).toBeInTheDocument();
  });

  it('tells the four empty states apart', async () => {
    mockApi.kernelPosture.mockResolvedValue(null);
    const { unmount } = render(<KernelPosture imageId="img1" />);
    expect(await screen.findByText(/has not been run for this image/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run kernel posture' })).toBeInTheDocument();
    unmount();

    mockApi.kernelPosture.mockResolvedValue({ available: false, reason: 'binwalk is not installed' });
    const second = render(<KernelPosture imageId="img2" />);
    // A gap in the workbench, said as one.
    expect(await screen.findByText(/could not answer them: binwalk is not installed/)).toBeInTheDocument();
    expect(screen.getByText(/gap in this workbench, not a property of the firmware/)).toBeInTheDocument();
    second.unmount();

    mockApi.kernelPosture.mockResolvedValue({
      available: true,
      located: false,
      reason: 'no vmlinux and no banner',
      searched: ['boot/vmlinux', 'proc/version'],
    });
    const third = render(<KernelPosture imageId="img3" />);
    expect(
      await screen.findByText(/No kernel was located in this image: no vmlinux and no banner/),
    ).toBeInTheDocument();
    // The list of places it looked, because that is a coverage gap and never a statement about the image.
    expect(screen.getByText('Looked in:')).toBeInTheDocument();
    expect(screen.getByText('boot/vmlinux')).toBeInTheDocument();
    third.unmount();

    mockApi.kernelPosture.mockResolvedValue(located({ answers: [] }));
    render(<KernelPosture imageId="img4" />);
    expect(await screen.findByText(/A kernel was located and no posture question was recorded/)).toBeInTheDocument();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('reads a failed fetch as "has not run", never as a kernel with nothing wrong with it', async () => {
    mockApi.kernelPosture.mockRejectedValue(new Error('502'));
    render(<KernelPosture imageId="img1" />);

    expect(await screen.findByText(/has not been run for this image/)).toBeInTheDocument();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('re-reads the result after running the stage', async () => {
    mockApi.kernelPosture.mockResolvedValueOnce(null).mockResolvedValue(located());
    mockApi.runKernelPosture.mockResolvedValue({ jobId: 'job-1' });
    render(<KernelPosture imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Run kernel posture' }));
    await waitFor(() => expect(mockApi.runKernelPosture).toHaveBeenCalledWith('img1'));
    // Without the reload the operator runs the stage and still reads "has not been run".
    // The first read resolved `null`, so a table on screen is only reachable through a SECOND read.
    expect(await screen.findByText('CONFIG_MODULE_SIG_FORCE')).toBeInTheDocument();
  });
});
