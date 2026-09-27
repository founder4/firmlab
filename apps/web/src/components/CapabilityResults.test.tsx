import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { CapabilityResults } from './CapabilityResults';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const m = () => mockedApi(api);

// The funcdiff row links to the Diff section, so the panel needs a router around it.
const renderCaps = () =>
  render(
    <MemoryRouter>
      <CapabilityResults imageId="abc" />
    </MemoryRouter>,
  );

const tools = (available: boolean) => ({
  tools: [{ id: 'analyzeHeadless', bin: 'analyzeHeadless', available, unlocks: '', group: 'analyze' }],
  groups: {},
});

/** The row for one capability, found by its data attribute rather than by prose that a translation would move. */
const row = (id: string): HTMLElement => {
  const el = document.querySelector(`[data-capability="${id}"]`);
  if (!el) throw new Error(`no row for ${id}`);
  return el as HTMLElement;
};

beforeEach(() => {
  setLocale('en');
  m().yarascanResult.mockResolvedValue(null);
  m().fwhuntResult.mockResolvedValue(null);
  m().nvramResult.mockResolvedValue(null);
  m().ghidraResult.mockResolvedValue(null);
  m().dynprobeResult.mockResolvedValue(null);
  m().jobs.mockResolvedValue([]);
  m().tools.mockResolvedValue(tools(true));
});

describe('CapabilityResults — the three states reach the screen and do not share a sentence', () => {
  it('reports a stage nobody ran as not-run, and says it is about the workbench', async () => {
    renderCaps();
    await waitFor(() => expect(row('yarascan').dataset.state).toBe('not-run'));
    expect(row('yarascan').textContent).toMatch(/has not run/);
    expect(row('yarascan').textContent).toMatch(/says nothing about the firmware/);
  });

  /**
   * The pair the whole panel exists for. Both of these produce NO findings, and only one of them is a measurement
   * of the firmware — so they must not render the same sentence.
   */
  it('separates "the tool could not answer" from "nobody asked", on identical zero findings', async () => {
    m().yarascanResult.mockResolvedValue({
      available: false,
      reason: 'yara is not installed in this deployment',
      findings: [],
    });
    renderCaps();
    await waitFor(() => expect(row('yarascan').dataset.state).toBe('unavailable'));

    const unavailable = row('yarascan').textContent ?? '';
    const notRun = row('fwhunt').textContent ?? '';
    expect(unavailable).toMatch(/could not answer/);
    expect(unavailable).toMatch(/not a negative result/);
    expect(unavailable).toMatch(/yara is not installed in this deployment/);
    // And it explicitly refuses to be read as the other one.
    expect(unavailable).toMatch(/not the same as the stage never having run/);
    expect(notRun).toMatch(/has not run/);
    expect(unavailable).not.toMatch(/has not run/);
  });

  it('reports a stage that ran with ZERO findings as a result, not as silence', async () => {
    m().fwhuntResult.mockResolvedValue({
      available: true,
      reason: '0 matches',
      rulesInCorpus: 108,
      rulesRun: 17,
      rulesNotApplicable: 91,
      findings: [],
    });
    renderCaps();
    await waitFor(() => expect(row('fwhunt').dataset.state).toBe('ran'));
    const text = row('fwhunt').textContent ?? '';
    expect(text).toMatch(/0 findings/);
    expect(text).toMatch(/read the coverage numbers beside it before treating it as clean/);
  });

  it('prints the denominator and what never applied, which is the part a bare count hides', async () => {
    m().fwhuntResult.mockResolvedValue({
      available: true,
      reason: 'scanned',
      rulesInCorpus: 108,
      rulesRun: 17,
      rulesNotApplicable: 91,
      findings: [],
    });
    renderCaps();
    await waitFor(() => expect(row('fwhunt').dataset.state).toBe('ran'));
    const text = row('fwhunt').textContent ?? '';
    expect(text).toMatch(/17 of 108 rules applied/);
    expect(text).toMatch(/91 rules never applied to this image/);
    expect(text).toMatch(/PARTIAL/);
  });

  it('runs the next FwHunt batch, keeps the button busy through job completion, and reloads accumulated coverage', async () => {
    m().fwhuntResult.mockClear();
    const initial = {
      available: true,
      reason: 'batch 1',
      rulesInCorpus: 108,
      rulesRun: 102,
      rulesNotApplicable: 6,
      modulePass: {
        batchIndex: 0,
        batchCount: 35,
        batchSize: 12,
        batchesCompleted: [0],
        batches: [{ index: 0, complete: true }],
        modulesCarved: 409,
        modulesScanned: Array.from({ length: 12 }, () => ({})),
        modulesScannedThisBatch: 12,
      },
      findings: [],
    };
    const accumulated = {
      ...initial,
      reason: 'batch 2 accumulated',
      modulePass: {
        ...initial.modulePass,
        batchIndex: 1,
        batchesCompleted: [0, 1],
        batches: [
          { index: 0, complete: true },
          { index: 1, complete: true },
        ],
        modulesScanned: Array.from({ length: 24 }, () => ({})),
      },
    };
    m().fwhuntResult.mockResolvedValueOnce(initial).mockResolvedValueOnce(accumulated);
    m().runFwhunt.mockResolvedValue({ jobId: 'fw-job' });
    m().job.mockResolvedValue({ status: 'done' });

    renderCaps();
    const button = await screen.findByRole('button', { name: /next FwHunt batch/i });
    expect(row('fwhunt').textContent).toContain('12/409 modules accumulated');
    fireEvent.click(button);
    await waitFor(() => expect(m().job).toHaveBeenCalledWith('fw-job'));
    await waitFor(() => expect(row('fwhunt').textContent).toContain('24/409 modules accumulated'));
    expect(m().runFwhunt).toHaveBeenCalledWith('abc');
    expect(m().fwhuntResult).toHaveBeenCalledTimes(2);
  });

  it('marks an incomplete FwHunt batch as resumable instead of presenting the next range as ready', async () => {
    m().fwhuntResult.mockResolvedValue({
      available: true,
      reason: 'budget expired',
      rulesInCorpus: 108,
      rulesRun: 102,
      rulesNotApplicable: 6,
      modulePass: {
        batchIndex: 3,
        batchCount: 35,
        batchesCompleted: [0, 1, 2],
        batches: [{ index: 3, complete: false }],
        modulesCarved: 409,
        modulesScanned: Array.from({ length: 39 }, () => ({})),
      },
      findings: [],
    });
    renderCaps();
    await waitFor(() => expect(row('fwhunt').textContent).toContain('batch is incomplete'));
    expect(screen.getByRole('button', { name: /resume FwHunt batch/i })).toBeTruthy();
  });

  it('offers to upgrade a useful legacy result that predates batch provenance', async () => {
    m().runFwhunt.mockClear();
    m().fwhuntResult.mockResolvedValue({
      available: true,
      reason: 'legacy bounded scan',
      rulesInCorpus: 108,
      rulesRun: 102,
      rulesNotApplicable: 6,
      modulePass: {
        modulesCarved: 409,
        modulesScanned: Array.from({ length: 12 }, () => ({})),
      },
      findings: [],
    });
    m().runFwhunt.mockResolvedValue({ jobId: 'legacy-upgrade' });
    m().job.mockResolvedValue({ status: 'error' });

    renderCaps();
    const button = await screen.findByRole('button', { name: /start resumable FwHunt campaign/i });
    fireEvent.click(button);
    await waitFor(() => expect(m().runFwhunt).toHaveBeenCalledWith('abc', undefined, true));
  });

  it('keeps a completed campaign rerunnable from a clean first batch', async () => {
    m().runFwhunt.mockClear();
    m().fwhuntResult.mockResolvedValue({
      available: true,
      reason: 'complete campaign',
      rulesInCorpus: 108,
      rulesRun: 106,
      rulesNotApplicable: 2,
      modulePass: {
        batchIndex: 1,
        batchCount: 2,
        batchesCompleted: [0, 1],
        batches: [
          { index: 0, complete: true },
          { index: 1, complete: true },
        ],
        modulesCarved: 24,
        modulesScanned: Array.from({ length: 24 }, () => ({})),
      },
      findings: [],
    });
    m().runFwhunt.mockResolvedValue({ jobId: 'campaign-restart' });
    m().job.mockResolvedValue({ status: 'error' });

    renderCaps();
    const button = await screen.findByRole('button', { name: /rerun full FwHunt campaign/i });
    fireEvent.click(button);
    await waitFor(() => expect(m().runFwhunt).toHaveBeenCalledWith('abc', undefined, true));
  });

  it('says the denominator is unknown rather than printing a zero for it', async () => {
    m().nvramResult.mockResolvedValue({ available: true, reason: 'scanned', stores: [{}, {}], findings: [] });
    renderCaps();
    await waitFor(() => expect(row('nvram').dataset.state).toBe('ran'));
    const text = row('nvram').textContent ?? '';
    expect(text).toMatch(/2 stores examined/);
    expect(text).toMatch(/reports no denominator/);
    expect(text).not.toMatch(/PARTIAL/);
  });

  it('names funcdiff’s missing BASELINE rather than reporting it as a stage nobody ran', async () => {
    renderCaps();
    await waitFor(() => expect(row('funcdiff').dataset.state).toBe('not-run'));
    // A third cause of nothing, and it is an input rather than an unrun stage.
    expect(row('funcdiff').textContent).toMatch(/no baseline has been chosen/);
    expect(row('funcdiff').textContent).toMatch(/missing input, not a result/);
  });

  it('reads a failed fetch as not-run, never as a clean result', async () => {
    m().ghidraResult.mockRejectedValue(new Error('boom'));
    renderCaps();
    await waitFor(() => expect(row('ghidra').dataset.state).toBe('not-run'));
    expect(row('ghidra').textContent).not.toMatch(/ran/i);
  });

  it('renders all five capabilities, so none of them is invisible again', async () => {
    renderCaps();
    await waitFor(() => expect(screen.getByTestId('capability-results')).toBeTruthy());
    for (const id of ['yarascan', 'fwhunt', 'nvram', 'ghidra', 'funcdiff', 'dynprobe']) {
      expect(row(id)).toBeTruthy();
    }
  });

  /**
   * `controlOffset` is the whole point of the dynamic probe and had nowhere to be read, because the client did not
   * type its result at all. A recovered offset and an unrecovered one must not read the same, and an unrecovered one
   * must not read as zero.
   */
  it('prints the control offset the probe recovered', async () => {
    m().dynprobeResult.mockResolvedValue({
      available: true,
      reason: 'crash_input_controlled',
      controlOffset: 204,
      sinkHits: 2,
      findings: [{}],
    });
    renderCaps();
    await waitFor(() => expect(row('dynprobe').dataset.state).toBe('ran'));
    expect(row('dynprobe').textContent).toMatch(/input controls the saved return address at offset 204/);
    expect(row('dynprobe').textContent).toMatch(/2 sink hits examined/);
  });

  it('refuses to read an unrecovered offset as zero', async () => {
    m().dynprobeResult.mockResolvedValue({ available: true, reason: 'ran_clean', controlOffset: null, findings: [] });
    renderCaps();
    await waitFor(() => expect(row('dynprobe').dataset.state).toBe('ran'));
    const text = row('dynprobe').textContent ?? '';
    expect(text).toMatch(/not the same as an offset of zero/);
    expect(text).not.toMatch(/at offset 0/);
  });

  it('says the same three things in Spanish', async () => {
    setLocale('es');
    m().yarascanResult.mockResolvedValue({ available: false, reason: 'yara no está instalado', findings: [] });
    renderCaps();
    await waitFor(() => expect(row('yarascan').dataset.state).toBe('unavailable'));
    expect(row('yarascan').textContent).toMatch(/no pudo responder/);
    expect(row('yarascan').textContent).toMatch(/no es un resultado negativo/);
    expect(row('fwhunt').textContent).toMatch(/no ha corrido/);
  });
});

describe('CapabilityResults — ghidra can be started, and funcdiff reflects its last run', () => {
  it('refuses to submit without a binary and names the field', async () => {
    renderCaps();
    fireEvent.click(await screen.findByRole('button', { name: 'Decompile with Ghidra' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/^Binary path:/);
    expect(m().ghidra).not.toHaveBeenCalled();
  });

  it('runs ghidra on a rootfs-relative path, polls the job and reloads the result', async () => {
    m().ghidra.mockResolvedValue({ jobId: 'j1' });
    m().job.mockResolvedValue({ id: 'j1', status: 'done', log: '', result: null, error: null });
    renderCaps();
    fireEvent.change(await screen.findByLabelText(/Binary to decompile/), { target: { value: '/usr/sbin/httpd' } });
    m().ghidraResult.mockResolvedValue({
      available: true,
      binary: 'usr/sbin/httpd',
      functionCount: 1,
      functions: [{}],
      eligibleCount: 9,
      findings: [],
    });
    fireEvent.click(screen.getByRole('button', { name: 'Decompile with Ghidra' }));
    await waitFor(() => expect(row('ghidra').dataset.state).toBe('ran'));
    expect(m().ghidra).toHaveBeenCalledWith('abc', 'usr/sbin/httpd');
    expect(row('ghidra').textContent).toMatch(/1 of 9 functions applied/);
  });

  it('shows the job’s error instead of a result when the run fails', async () => {
    m().ghidra.mockResolvedValue({ jobId: 'j1' });
    m().job.mockResolvedValue({ id: 'j1', status: 'error', log: '', result: null, error: 'extraction missing' });
    renderCaps();
    fireEvent.change(await screen.findByLabelText(/Binary to decompile/), { target: { value: 'bin/busybox' } });
    fireEvent.click(screen.getByRole('button', { name: 'Decompile with Ghidra' }));
    expect((await screen.findByRole('alert')).textContent).toBe('extraction missing');
  });

  it('disables the run and says the tool is missing — not a negative — when Ghidra is absent', async () => {
    m().tools.mockResolvedValue(tools(false));
    renderCaps();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Decompile with Ghidra' })).toBeDisabled());
    expect(row('ghidra').textContent).toMatch(/not installed in this deployment/);
    expect(row('ghidra').textContent).toMatch(/not a negative result/);
  });

  it('reads the last funcdiff through the baseline its job remembers', async () => {
    m().jobs.mockResolvedValue([{ id: 'j9', kind: 'funcdiff', status: 'done', params: { against: 'old1' } }]);
    m().funcdiffResult.mockResolvedValue({
      available: true,
      older: 'fw-1.0.bin',
      analyzed: 3,
      notAnalyzed: 1,
      diffs: [],
      findings: [],
    });
    renderCaps();
    await waitFor(() => expect(row('funcdiff').dataset.state).toBe('ran'));
    expect(m().funcdiffResult).toHaveBeenCalledWith('abc', 'old1');
    expect(row('funcdiff').textContent).toMatch(/fw-1\.0\.bin/);
    expect(row('funcdiff').textContent).toMatch(/3 of 4 differing binaries applied/);
    expect(screen.getByRole('link', { name: /Open the function diff/ }).getAttribute('href')).toBe('/image/abc/diff');
  });
});
