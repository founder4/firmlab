import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type FuncDiffResultView, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { FuncDiffPanel, funcDiffOutcome } from './FuncDiffPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const m = () => mockedApi(api);

const patched: FuncDiffResultView = {
  available: true,
  reason: '12 shared binaries: 10 identical, 2 differ, 2 compared.',
  older: 'fw-1.0.bin',
  newer: 'fw-1.1.bin',
  paired: 12,
  identical: 10,
  analyzed: 2,
  notAnalyzed: 0,
  diffs: [
    {
      path: 'usr/sbin/httpd',
      verdict: 'patched',
      matched: 80,
      changed: 2,
      added: 1,
      removed: 0,
      unmatchable: 4,
      functions: [
        { name: 'sym.parse_hdr', status: 'changed', delta: { size: 8, nbbs: 1, cc: 1, ninstrs: 2 } },
        { name: 'sym.auth', status: 'changed', delta: { size: -40, nbbs: -3, cc: 0, ninstrs: -12 } },
        { name: 'sym.fresh', status: 'added' },
      ],
    },
    { path: 'bin/busybox', verdict: 'recompiled', matched: 900, changed: 700, unmatchable: 3, functions: [] },
  ],
};

beforeEach(() => {
  setLocale('en');
  m().funcdiffResult.mockResolvedValue(null);
});

describe('funcDiffOutcome — three different empties', () => {
  const base = { available: true, paired: 5, identical: 5, analyzed: 0, notAnalyzed: 0, diffs: [] };
  it('calls byte-identical shared binaries identical', () => {
    expect(funcDiffOutcome(base)).toBe('identical-bytes');
  });
  it('never calls a capped diff identical', () => {
    expect(funcDiffOutcome({ ...base, identical: 3, notAnalyzed: 2 })).toBe('nothing-comparable');
  });
  it('reads a withheld list as not localized, not as no change', () => {
    expect(funcDiffOutcome({ ...base, diffs: [{ path: 'a', verdict: 'recompiled', functions: [] }] })).toBe(
      'not-localized',
    );
  });
  it('reads a tool refusal as blocked', () => {
    expect(funcDiffOutcome({ available: false, reason: 'radare2 is not installed' })).toBe('blocked');
  });
});

describe('FuncDiffPanel', () => {
  it('names the missing baseline instead of submitting', async () => {
    render(<FuncDiffPanel imageId="new" against="" />);
    fireEvent.click(screen.getByRole('button', { name: 'Diff functions' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/^Baseline image:/);
    expect(m().runFuncdiff).not.toHaveBeenCalled();
  });

  it('says nothing has run against this baseline yet rather than showing an empty diff', async () => {
    render(<FuncDiffPanel imageId="new" against="old" />);
    expect(await screen.findByText(/No function diff has been run against this baseline yet/)).toBeInTheDocument();
    expect(m().funcdiffResult).toHaveBeenCalledWith('new', 'old');
  });

  it('renders counts first, the unmatched sentence and a sortable table of changed functions', async () => {
    m().funcdiffResult.mockResolvedValue(patched);
    render(<FuncDiffPanel imageId="new" against="old" />);
    await screen.findByText(/2 changed function\(s\) across 1 binary pair/);
    const stat = (k: string) => document.querySelector(`[data-stat="${k}"] .stat-value`)?.textContent;
    expect([stat('changed'), stat('added'), stat('removed'), stat('unmatchable')]).toEqual(['702', '1', '0', '7']);
    expect(document.querySelector('[data-role="unmatchable"]')?.textContent).toMatch(
      /7 function\(s\) could not be matched/,
    );

    const table = screen.getByRole('button', { name: 'Sort by Function' }).closest('table') as HTMLElement;
    const names = () =>
      within(table)
        .getAllByRole('row')
        .slice(1)
        .map((r) => r.children[1]?.textContent);
    expect(names()).toEqual(['sym.parse_hdr', 'sym.auth']);
    fireEvent.click(screen.getByRole('button', { name: 'Sort by Δ instructions' }));
    fireEvent.click(screen.getByRole('button', { name: 'Sort by Δ instructions' }));
    expect(names()).toEqual(['sym.auth', 'sym.parse_hdr']);
    expect(screen.getByText('rebuilt — list withheld')).toBeInTheDocument();
  });

  it('says identical when every shared binary hashed equal', async () => {
    m().funcdiffResult.mockResolvedValue({
      available: true,
      paired: 40,
      identical: 40,
      analyzed: 0,
      notAnalyzed: 0,
      diffs: [],
    });
    render(<FuncDiffPanel imageId="new" against="old" />);
    expect(await screen.findByText(/Identical: all 40 binaries/)).toBeInTheDocument();
  });

  it('says nothing comparable — not identical — when no binary pairs', async () => {
    m().funcdiffResult.mockResolvedValue({
      available: false,
      reason: 'the two rootfs share no binary at the same path',
      diffs: [],
    });
    render(<FuncDiffPanel imageId="new" against="old" />);
    expect(await screen.findByText(/could not run — this is not a negative result/)).toBeInTheDocument();
    expect(screen.getByText(/share no binary at the same path/)).toBeInTheDocument();
    expect(screen.queryByText(/Identical/)).toBeNull();
  });

  it('runs the job, polls it and shows the route’s refusal as an error', async () => {
    m().runFuncdiff.mockRejectedValue(
      new Error('Run extraction on both images first — fw-1.0.bin has no extracted rootfs'),
    );
    render(<FuncDiffPanel imageId="new" against="old" />);
    await screen.findByText(/No function diff has been run/);
    fireEvent.click(screen.getByRole('button', { name: 'Diff functions' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/Run extraction on both images first/);
  });

  it('renders the result a finished job returns', async () => {
    m().runFuncdiff.mockResolvedValue({ jobId: 'j1' });
    m().job.mockResolvedValue({
      id: 'j1',
      status: 'done',
      log: 'diffing usr/sbin/httpd…',
      result: patched,
      error: null,
    });
    render(<FuncDiffPanel imageId="new" against="old" />);
    await screen.findByText(/No function diff has been run/);
    fireEvent.click(screen.getByRole('button', { name: 'Diff functions' }));
    await waitFor(() => expect(document.querySelector('[data-outcome="changes"]')).not.toBeNull());
    expect(m().runFuncdiff).toHaveBeenCalledWith('new', 'old');
  });
});
