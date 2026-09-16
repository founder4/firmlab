/**
 * BinVulnPanel, on a DOM.
 *
 * The panel's whole job is the gaps between three numbers, and the one this file exists to pin is the arithmetic the
 * first draft got wrong: `findings.length` is legitimately LARGER than `candidates`, because `candidates` counts
 * stack-overflow candidates only while `findings` carries every kind the sweep emits. Any derived "dropped" figure
 * here would print a negative bound dressed as an answer, so the panel prints the provider's three numbers and the
 * provider's own `reason`, and nothing else.
 *
 * The second thing pinned is that a table of red rows cannot read as a table of bugs: the leads-only sentence sits
 * ABOVE the table, and every row's mark is hollow with a label that says "not established" — these are syntactic
 * candidates and nothing here was executed.
 */
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type BinVulnResult, type Finding, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { BinVulnPanel } from './BinVulnPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

beforeEach(() => setLocale('en'));

const finding = (o: Partial<Finding> = {}): Finding => ({
  id: 'f1',
  imageId: 'img1',
  source: 'binary:usr/sbin/httpd',
  kind: 'stack-overflow-candidate',
  title: 'usr/sbin/httpd imports strcpy with no stack canary',
  severity: 'high',
  proofState: 'needs_runtime_reproduction',
  createdAt: 0,
  ...o,
});

const result = (o: Partial<BinVulnResult> = {}): BinVulnResult => ({
  available: true,
  binariesScanned: 312,
  candidates: 37,
  findings: [finding(), finding({ id: 'f2', kind: 'no-relro', title: 'bin/busybox has no RELRO', severity: 'low' })],
  reason: 'Listed 49 of the sweep’s rows, ranked by exposure; the cut is by rank, never by directory order.',
  ...o,
});

describe('BinVulnPanel', () => {
  it('prints the three counts as the provider gave them, including a listed count above the candidate count', async () => {
    mockApi.binvuln.mockResolvedValue(result({ candidates: 1 }));
    render(<BinVulnPanel imageId="img1" />);

    expect(await screen.findByText('312')).toBeInTheDocument();
    // `candidates` counts stack-overflow candidates only; `findings` carries every kind. 2 listed against 1
    // candidate is correct, and any subtraction the panel did would print a negative drop count.
    expect(screen.getByText('1')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(screen.queryByText('-1')).toBeNull();
    // The cut rule is the provider's sentence, rendered verbatim rather than re-derived.
    expect(screen.getByText(/ranked by exposure; the cut is by rank, never by directory order/)).toBeInTheDocument();
  });

  it('omits the two skip counts a result written by an older build never recorded', async () => {
    mockApi.binvuln.mockResolvedValue(result());
    render(<BinVulnPanel imageId="img1" />);

    await screen.findByText('312');
    // `0` here would be a claim about a walk that never counted.
    expect(screen.queryByText('Relocatable, skipped')).toBeNull();
    expect(screen.queryByText('Cut by the extractor')).toBeNull();
  });

  it('keeps a relocatable object and a file the extractor cut apart when both were counted', async () => {
    mockApi.binvuln.mockResolvedValue(result({ relocatableSkipped: 14, neuteredSkipped: 3 }));
    render(<BinVulnPanel imageId="img1" />);

    // Two different silences — a `.ko` the question does not apply to, versus a file the carve destroyed.
    expect(await screen.findByText('Relocatable, skipped')).toBeInTheDocument();
    expect(screen.getByText('14')).toBeInTheDocument();
    expect(screen.getByText('Cut by the extractor')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('marks every row as a lead and says so before the table, never after it', async () => {
    mockApi.binvuln.mockResolvedValue(result());
    const { container } = render(<BinVulnPanel imageId="img1" />);

    const banner = await screen.findByText(/Every row here is a LEAD, not a bug/);
    const table = container.querySelector('table');
    expect(table).not.toBeNull();
    // DOCUMENT_POSITION_FOLLOWING: the sentence must be read before the rows, not under them.
    expect(banner.compareDocumentPosition(table as Node) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    // Hollow, always. The ledger fills its mark for established rows and nothing this sweep produces is established.
    const marks = screen.getAllByRole('img');
    expect(marks).toHaveLength(2);
    expect(marks[0]).toHaveAccessibleName('high if true — not established');
    expect(marks[0]).toHaveStyle({ background: 'transparent' });
  });

  it('names the exposed binaries that did not fit rather than counting them', async () => {
    mockApi.binvuln.mockResolvedValue(result({ exposedDropped: ['usr/sbin/telnetd', 'usr/bin/upnpd'] }));
    render(<BinVulnPanel imageId="img1" />);

    expect(await screen.findByText(/2 of them are network-exposed and still did not fit/)).toBeInTheDocument();
    // A count on a rootfs of 300 binaries tells a reader nothing about WHICH ones they are missing.
    expect(screen.getByText('usr/sbin/telnetd')).toBeInTheDocument();
    expect(screen.getByText('usr/bin/upnpd')).toBeInTheDocument();
  });

  it('bounds an empty sweep to its own precondition instead of reporting a clean rootfs', async () => {
    mockApi.binvuln.mockResolvedValue(result({ findings: [], candidates: 0 }));
    render(<BinVulnPanel imageId="img1" />);

    expect(
      await screen.findByText(/312 binaries were walked and none matched the sweep's precondition/),
    ).toBeInTheDocument();
    expect(screen.getByText(/every bug class this sweep does not ask about, are outside it/)).toBeInTheDocument();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('separates "has not run" from "could not run", and reads a failed fetch as the first', async () => {
    mockApi.binvuln.mockResolvedValue(null);
    const { unmount } = render(<BinVulnPanel imageId="img1" />);
    expect(await screen.findByText(/has not been run for this image/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run the sweep' })).toBeInTheDocument();
    unmount();

    mockApi.binvuln.mockResolvedValue({
      available: false,
      binariesScanned: 0,
      candidates: 0,
      findings: [],
      reason: 'no rootfs was extracted',
    });
    const second = render(<BinVulnPanel imageId="img2" />);
    expect(await screen.findByText(/could not run: no rootfs was extracted/)).toBeInTheDocument();
    // Absence of a run is not absence of a weak binary.
    expect(screen.getByText(/not the same as no binary being weak/)).toBeInTheDocument();
    second.unmount();

    mockApi.binvuln.mockRejectedValue(new Error('502'));
    render(<BinVulnPanel imageId="img3" />);
    expect(await screen.findByText(/has not been run for this image/)).toBeInTheDocument();
  });

  it('re-reads the result after running the sweep', async () => {
    mockApi.binvuln.mockResolvedValueOnce(null).mockResolvedValue(result());
    mockApi.runBinvuln.mockResolvedValue({ jobId: 'job-1' });
    render(<BinVulnPanel imageId="img1" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Run the sweep' }));
    await waitFor(() => expect(mockApi.runBinvuln).toHaveBeenCalledWith('img1'));
    // The first read resolved `null`, so a table on screen is only reachable through a SECOND read.
    expect(await screen.findByText(/imports strcpy with no stack canary/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Re-run' })).toBeInTheDocument();
  });
});
