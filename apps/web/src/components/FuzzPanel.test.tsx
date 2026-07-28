import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { es } from '../locales/es';
import { mockedApi } from '../test-api-mock';
import { FuzzPanel } from './FuzzPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const fuzzResult = (o: Record<string, unknown> = {}) => ({
  available: true,
  binary: 'bin/busybox',
  harness: 'file',
  seconds: 60,
  execsDone: 12000,
  crashes: 0,
  crashSamples: [],
  isolation: 'full',
  command: 'afl-fuzz -Q -i seeds -o out -- ./bin/busybox @@',
  ...o,
});

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
  // The panel drops a RunHistory under its result, which reads the run ledger. Before the shared mock this call
  // was left pointing at the real client and fetched over the network in every test in this file.
  mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
  mockApi.fuzzStatus.mockResolvedValue({ available: true });
  mockApi.fuzzResult.mockResolvedValue(null);
  mockApi.runFuzz.mockResolvedValue({ jobId: 'j1' });
  mockApi.job.mockResolvedValue({ id: 'j1', status: 'done', result: fuzzResult(), log: '' });
});

describe('FuzzPanel — AFL++ honesty', () => {
  it('is honest when AFL++ is not installed: opt-in badge, an explanation, and no run button', async () => {
    mockApi.fuzzStatus.mockResolvedValue({ available: false });
    render(<FuzzPanel imageId="img1" />);
    expect(await screen.findByText(en.panels.fuzz.optIn)).toBeInTheDocument();
    // Substring: the sentence is split around the `Dockerfile.firmware` identifier, which is never translated.
    expect(screen.getByText(en.panels.fuzz.notInstalled.lead, { exact: false })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: en.panels.fuzz.run })).not.toBeInTheDocument();
  });

  it('offers a run control when AFL++ is available', async () => {
    render(<FuzzPanel imageId="img1" />);
    expect(await screen.findByRole('button', { name: en.panels.fuzz.run })).toBeInTheDocument();
  });

  it('refuses to run without a target binary', async () => {
    render(<FuzzPanel imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: en.panels.fuzz.run }));
    expect(await screen.findByText(en.panels.fuzz.needBinary)).toBeInTheDocument();
    expect(mockApi.runFuzz).not.toHaveBeenCalled();
  });

  it('runs the fuzzer against the entered binary (auto harness by default)', async () => {
    render(<FuzzPanel imageId="img1" />);
    fireEvent.change(await screen.findByPlaceholderText('bin/busybox'), { target: { value: 'sbin/httpd' } });
    fireEvent.click(screen.getByRole('button', { name: en.panels.fuzz.run }));
    await waitFor(() => expect(mockApi.runFuzz).toHaveBeenCalledWith('img1', 'sbin/httpd', 60, 'auto'));
  });

  it('lets you pick the network (desock) harness for a daemon', async () => {
    render(<FuzzPanel imageId="img1" />);
    fireEvent.change(await screen.findByPlaceholderText('bin/busybox'), { target: { value: 'sbin/httpd' } });
    // The harness CLASS stays `network` in every language — it is the value the API dispatches on.
    fireEvent.change(screen.getByLabelText(en.panels.fuzz.harnessLabel), { target: { value: 'network' } });
    fireEvent.click(screen.getByRole('button', { name: en.panels.fuzz.run }));
    await waitFor(() => expect(mockApi.runFuzz).toHaveBeenCalledWith('img1', 'sbin/httpd', 60, 'network'));
  });

  it('surfaces a reproduced crash as a recorded fuzz-crash finding', async () => {
    mockApi.fuzzResult.mockResolvedValue(
      fuzzResult({ crashes: 2, crashSamples: [{ name: 'id:000001,sig:11', hexPreview: 'de ad be ef' }] }),
    );
    render(<FuzzPanel imageId="img1" />);
    expect(await screen.findByText(/fuzz-crash/)).toBeInTheDocument();
    expect(screen.getByText('de ad be ef')).toBeInTheDocument();
  });

  it('reports a 0-crash run as an honest negative, not a guarantee of safety', async () => {
    mockApi.fuzzResult.mockResolvedValue(fuzzResult({ crashes: 0 }));
    render(<FuzzPanel imageId="img1" />);
    expect(await screen.findByText(en.panels.fuzz.noCrash)).toBeInTheDocument();
  });
});

/**
 * The bounded-campaign caveat, in Spanish. A run that found no crash is a statement about THIS harness for THIS
 * budget — a translation that let it read as "el binario es seguro" would turn an honest negative into a pass, which
 * is the one thing this panel must never say. The tool name and the finding kind are identifiers and stay put.
 */
describe('FuzzPanel — the honest negative survives translation', () => {
  it('says a 0-crash campaign is not a guarantee of safety, and what its budget covered', async () => {
    setLocale('es');
    mockApi.fuzzResult.mockResolvedValue(fuzzResult({ crashes: 0 }));
    render(<FuzzPanel imageId="img1" />);

    expect(await screen.findByText(es.panels.fuzz.noCrash)).toBeInTheDocument();
    expect(es.panels.fuzz.noCrash).toMatch(/no una garantía de seguridad/i);
    expect(es.panels.fuzz.noCrash).toMatch(/no dice nada de una ejecución más larga/i);
    // The badge for a runnable deployment is translated; the tool name in the title is not.
    expect(screen.getByText(es.panels.fuzz.runnable)).toBeInTheDocument();
    expect(screen.getByText(/AFL\+\+/)).toBeInTheDocument();
  });

  it('keeps the missing tool an absent answer rather than an absent problem', async () => {
    setLocale('es');
    mockApi.fuzzStatus.mockResolvedValue({ available: false });
    render(<FuzzPanel imageId="img1" />);

    expect(await screen.findByText(es.panels.fuzz.optIn)).toBeInTheDocument();
    expect(screen.getByText('Dockerfile.firmware')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: es.panels.fuzz.run })).not.toBeInTheDocument();
  });
});
