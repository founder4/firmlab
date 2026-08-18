/**
 * The panel exists to keep three states legible, and each test below pins one. They are the corpus's real shapes,
 * not invented ones: NetUSB.ko recovers 340 functions with 228 entry points and 17 calling `__kmalloc`, the
 * WR940N's 64 libraries all come back with a zero-function graph, and a sink present-but-not-reached is the common
 * case because CFGFast leaves the indirect calls both target classes are built on unresolved.
 */
import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type ExportReachResult, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { ExportReachPanel } from './ExportReachPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const result = (o: Partial<ExportReachResult> = {}): ExportReachResult => ({
  available: true,
  reason: '',
  binary: 'lib/modules/2.6.31/nas/NetUSB.ko',
  arch: 'MIPS32',
  functionsRecovered: 340,
  entryPoints: 228,
  sinks: [],
  ...o,
});

beforeEach(() => {
  setLocale('en');
  // RunHistory reads the same ledger; keep it inert so it never counts as an unmocked call.
  mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
});

describe('ExportReachPanel', () => {
  it('files a reachable sink as a lead held at needs_runtime_reproduction, never as a proof', async () => {
    mockApi.exportreachResult.mockResolvedValue(
      result({
        sinks: [
          {
            sink: '__kmalloc',
            outcome: 'reachable',
            holders: 17,
            reachableFrom: 37,
            entryPointsNamed: ['KTCP_stop', 'run_init_sbus'],
            namedTruncated: 0,
          },
        ],
      }),
    );
    render(<ExportReachPanel imageId="img1" />);
    // The proof state renders as the code it is, and the caveat that keeps it below symreach is on screen.
    await waitFor(() => expect(screen.getByText('needs_runtime_reproduction')).toBeTruthy());
    expect(screen.getByText(/strictly weaker than symreach, and never a proof of exploitability/)).toBeTruthy();
    expect(screen.getByText(/37 of 228 entry point\(s\) reach one of 17 holder function\(s\)/)).toBeTruthy();
  });

  it('styles an empty graph as a block to analyse, not as a clean object', async () => {
    // The WR940N's section-stripped libraries land here; silent, they would read as analysed-and-clean.
    mockApi.exportreachResult.mockResolvedValue(
      result({ outcome: 'no_functions_recovered', functionsRecovered: 0, entryPoints: 0, sinks: [] }),
    );
    render(<ExportReachPanel imageId="img1" />);
    await waitFor(() =>
      expect(screen.getByText(/NOT a statement that the object is free of reachable sinks/)).toBeTruthy(),
    );
  });

  it('keeps "not reached" from reading as "cannot be reached" when a result is shown', async () => {
    mockApi.exportreachResult.mockResolvedValue(
      result({ sinks: [{ sink: 'system', outcome: 'not_reached', holders: 2, reachableFrom: 0 }] }),
    );
    render(<ExportReachPanel imageId="img1" />);
    await waitFor(() =>
      expect(screen.getByText(/A sink not reached is NOT a sink that cannot be reached/)).toBeTruthy(),
    );
  });

  it('reads no prior probe as "has not run", never as a clean result', async () => {
    mockApi.exportreachResult.mockResolvedValue(null);
    render(<ExportReachPanel imageId="img1" />);
    await waitFor(() => expect(screen.getByText(/no library or module here has been asked/)).toBeTruthy());
  });
});
