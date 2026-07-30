import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { type BinaryEntry, type RunSummary, api } from '../api';
import { mockedApi } from '../test-api-mock';
import { TestBench } from './TestBench';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

// A mapped type over the real client, not a hand-written Record: the names stay checked against `api.ts`, and
// under `noUncheckedIndexedAccess` an index signature would make every lookup possibly-undefined, which the web
// build (unlike `check`) compiles and rejects.
const mockApi = mockedApi(api);

const bin = (path: string): BinaryEntry => ({
  imageId: 'img',
  path,
  sha1: null,
  size: 4096,
  arch: 'mipsel',
  bits: 32,
  endianness: 'little',
  nx: 0,
  canary: 0,
  pic: 0,
  networkFacing: 0,
  importsSummary: null,
  triaged: 1,
  emulationStatus: null,
});

const run = (o: Partial<RunSummary>): RunSummary => ({
  jobId: 'j',
  kind: 'dynprobe',
  status: 'done',
  startedAt: Date.now() - 60_000,
  finishedAt: Date.now(),
  target: 'sbin/one',
  question: 'strcpy',
  headline: 'x',
  outcome: 'empty',
  bound: null,
  ...o,
});

function setup(runs: RunSummary[], binaries: BinaryEntry[]) {
  mockApi.binaries.mockResolvedValue(binaries);
  mockApi.emulation.mockResolvedValue({ rootfsReady: true, identity: { arch: 'mipsel' }, capabilities: null });
  mockApi.runs.mockResolvedValue({ runs, byTarget: [] });
  mockApi.runDetail.mockResolvedValue({ summary: runs[0], params: null, result: null, log: '' });
}

describe('TestBench — the run ledger an operator can act on', () => {
  it('shows EVERY run against EVERY target, not just the most recent one', async () => {
    // The defect this surface exists for: three probes of three binaries used to render as one result.
    setup(
      [
        run({ jobId: 'a', target: 'sbin/one', headline: 'Crash, and the input controls the return address' }),
        run({ jobId: 'b', target: 'sbin/two', headline: 'The sink executed; the program did not fault' }),
        run({ jobId: 'c', target: 'sbin/one', headline: 'Ran without reaching the sink and without faulting' }),
      ],
      [bin('sbin/one'), bin('sbin/two')],
    );
    render(<TestBench imageId="img" />);

    await waitFor(() => expect(screen.getByText(/3 runs/)).toBeTruthy());
    expect(screen.getByText(/2 targets examined/)).toBeTruthy();

    fireEvent.click(screen.getByText('sbin/one'));
    await waitFor(() => expect(screen.getByText(/input controls the return address/)).toBeTruthy());
    // Both of that target's runs, not only the newest.
    expect(screen.getByText(/Ran without reaching the sink/)).toBeTruthy();
  });

  it('renders a blocked run as blocked, never as "nothing found"', async () => {
    // A probe that died for want of /dev/nvram asked a question this deployment could not answer. Rendering it
    // as an empty result is the exact conflation the workbench exists to prevent.
    setup(
      [run({ jobId: 'a', outcome: 'blocked', headline: 'The sandbox came up short — nothing was learned' })],
      [bin('sbin/one')],
    );
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('sbin/one')).toBeTruthy());

    const badges = screen.getAllByText('blocked');
    expect(badges.length).toBeGreaterThan(0);
    expect(screen.queryByText('nothing found')).toBeNull();
  });

  it('states the dynamic probe’s prerequisite instead of failing after the click', async () => {
    setup([], [bin('sbin/one')]);
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('sbin/one')).toBeTruthy());
    fireEvent.click(screen.getByText('sbin/one'));

    const blocked = await screen.findByText('Needs a sink address');
    expect((blocked as HTMLButtonElement).disabled).toBe(true);
    // Why it is blocked and what resolves it, both stated up front rather than in a 400 after the click.
    expect(screen.getByText(/breaks on an exact call site, so it needs an address/i)).toBeTruthy();
    expect(screen.getByText(/appears here\s+as a one-click probe/i)).toBeTruthy();
  });

  it('offers the probe pre-filled once a reachability run has produced an address', async () => {
    // The chain that used to be invisible: reachability produces the address the probe requires.
    setup([run({ jobId: 'r1', kind: 'symreach', outcome: 'proven', target: 'sbin/one' })], [bin('sbin/one')]);
    mockApi.runDetail.mockResolvedValue({
      summary: null,
      params: null,
      log: '',
      result: { sinks: [{ sink: 'sprintf', outcome: 'reached', addresses: ['0x500010'] }] },
    });
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('sbin/one')).toBeTruthy());
    fireEvent.click(screen.getByText('sbin/one'));

    const probe = await screen.findByText('Probe sprintf at 0x500010');
    expect((probe as HTMLButtonElement).disabled).toBe(false);
  });

  it('says an unexamined target is unexamined rather than implying it is clean', async () => {
    setup([], [bin('sbin/untouched')]);
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('sbin/untouched')).toBeTruthy());
    expect(screen.getByText('not examined')).toBeTruthy();

    fireEvent.click(screen.getByText('sbin/untouched'));
    expect(await screen.findByText(/empty history means unexamined/i)).toBeTruthy();
  });

  it('teaches the interface when there is no filesystem to run against', async () => {
    mockApi.binaries.mockResolvedValue([]);
    mockApi.emulation.mockResolvedValue({ rootfsReady: false, identity: { arch: 'mipsel' }, capabilities: null });
    mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
    render(<TestBench imageId="img" />);
    expect(await screen.findByText(/No extracted filesystem yet/)).toBeTruthy();
    expect(screen.getByText(/Run extraction on the\s+Filesystem tab/)).toBeTruthy();
  });
});

/**
 * `nx`, `canary`, `pic`, `bits`, `importsSummary` and `emulationStatus` were collected since the binaries table
 * existed and rendered NOWHERE, while the capability matrix reported `hardening: done`. Measured on the real corpus:
 * 2007 binaries, 2 triaged, 2 with any hardening flag — so almost every row is null, and this is the one place in
 * the workbench where the blank points at the ALARMING conclusion rather than the reassuring one.
 */
describe('per-binary hardening — a blank NX is not an absent NX', () => {
  const flag = (path: string, label: string): string | undefined => {
    const rows = [...document.querySelectorAll(`[data-hardening="${label}"]`)];
    return rows.map((e) => (e as HTMLElement).dataset.flag)[rows.length === 1 ? 0 : 0];
  };

  it('renders the three flags it has always collected', async () => {
    setup([], [bin('sbin/one')]);
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('sbin/one')).toBeTruthy());
    for (const label of ['NX', 'canary', 'PIC']) {
      expect(document.querySelector(`[data-hardening="${label}"]`)).toBeTruthy();
    }
  });

  it('reads a measured ZERO as OFF and an absent value as not-measured — opposite claims', async () => {
    setup([], [{ ...bin('sbin/off'), nx: 0 }]);
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('sbin/off')).toBeTruthy());
    expect(flag('sbin/off', 'NX')).toBe('off');

    setup([], [{ ...bin('sbin/unknown'), nx: null, canary: null, pic: null, triaged: 0 }]);
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('sbin/unknown')).toBeTruthy());
    const flags = [...document.querySelectorAll('[data-hardening="NX"]')].map((e) => (e as HTMLElement).dataset.flag);
    // Both renders are in the DOM; the second row must NOT read as off.
    expect(flags).toContain('not-measured');
  });

  it('leads with WHY when nothing has been measured, instead of drawing a grid of blanks', async () => {
    setup([], [{ ...bin('a'), nx: null, canary: null, pic: null, triaged: 0 }]);
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('a')).toBeTruthy());
    const note = document.querySelector('[data-role="hardening-coverage"]');
    expect(note?.textContent).toMatch(/a blank NX is not an absent NX/);
    expect(note?.textContent).not.toMatch(/measured on 0 of/);
  });

  it('prints the denominator once something HAS been measured', async () => {
    setup(
      [],
      [
        { ...bin('a'), nx: 1 },
        { ...bin('b'), nx: null, canary: null, pic: null, triaged: 0 },
      ],
    );
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('a')).toBeTruthy());
    expect(document.querySelector('[data-role="hardening-coverage"]')?.textContent).toMatch(
      /hardening measured on 1 of 2 binaries/,
    );
  });

  it('separates "triaged and yielded nothing" from "never triaged"', async () => {
    setup(
      [],
      [
        { ...bin('a'), nx: null, canary: null, pic: null, triaged: 1 },
        { ...bin('b'), nx: 1 },
      ],
    );
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('a')).toBeTruthy());
    expect(document.querySelector('[data-role="hardening-coverage"]')?.textContent).toMatch(
      /1 binary\(ies\) were triaged and yielded no hardening flags/,
    );
  });

  it('says RELRO is advertised by the matrix and measured by nothing', async () => {
    setup([], [bin('a')]);
    render(<TestBench imageId="img" />);
    await waitFor(() => expect(screen.getByText('a')).toBeTruthy());
    const note = document.querySelector('[data-role="hardening-coverage"]');
    expect(note?.textContent).toMatch(/RELRO is named in this workbench’s own capability matrix/);
    expect(note?.textContent).toMatch(/absent from every row rather than off/);
  });
});
