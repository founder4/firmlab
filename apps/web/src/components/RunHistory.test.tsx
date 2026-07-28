import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type RunSummary, api } from '../api';
import { setLocale } from '../i18n';
import { catalogues } from '../locales';
import { mockedApi } from '../test-api-mock';
import { RunHistory, ago } from './RunHistory';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const run = (o: Partial<RunSummary>): RunSummary => ({
  jobId: 'j',
  kind: 'fuzz',
  status: 'done',
  startedAt: Date.now() - 120_000,
  finishedAt: Date.now(),
  target: 'sbin/one',
  question: null,
  headline: 'x',
  outcome: 'empty',
  bound: null,
  ...o,
});

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
});

describe('RunHistory', () => {
  it('stays silent while there is nothing the panel above is not already showing', async () => {
    // A panel renders its latest result. One run means this component has nothing to add, so it must not
    // occupy space saying so.
    mockApi.runs.mockResolvedValue({ runs: [run({ jobId: 'a' })], byTarget: [] });
    const { container } = render(<RunHistory imageId="img" kinds={['fuzz']} label="fuzzing" />);
    await waitFor(() => expect(mockApi.runs).toHaveBeenCalled());
    expect(container.textContent).toBe('');
  });

  it('says how many runs there are, and that the panel above shows only the newest', async () => {
    mockApi.runs.mockResolvedValue({ runs: [run({ jobId: 'a' }), run({ jobId: 'b' })], byTarget: [] });
    render(<RunHistory imageId="img" kinds={['fuzz']} label="fuzzing" />);
    expect(await screen.findByText(/2 fuzzing runs on this image/)).toBeTruthy();
    expect(screen.getByText(/shows only the most recent/)).toBeTruthy();
  });

  it('keeps blocked and empty apart, exactly as the ledger does', async () => {
    // The whole reason this reuses the shared summary rather than rendering a status: a provider whose tool was
    // missing and one that genuinely found nothing must never look alike.
    mockApi.runs.mockResolvedValue({
      runs: [
        run({ jobId: 'a', outcome: 'blocked', headline: 'angr is not installed in this deployment' }),
        run({ jobId: 'b', outcome: 'empty', headline: 'No crash in this budget — which is not "no bug"' }),
      ],
      byTarget: [],
    });
    render(<RunHistory imageId="img" kinds={['fuzz']} label="fuzzing" />);
    fireEvent.click(await screen.findByText(/2 fuzzing runs/));

    expect(screen.getByText('blocked')).toBeTruthy();
    expect(screen.getByText('nothing found')).toBeTruthy();
    expect(screen.getByText(/which is not "no bug"/)).toBeTruthy();
  });

  it('shows the bound each run operated under, so none reads as unbounded', async () => {
    mockApi.runs.mockResolvedValue({
      runs: [run({ jobId: 'a', bound: '60s' }), run({ jobId: 'b', bound: '120s budget' })],
      byTarget: [],
    });
    render(<RunHistory imageId="img" kinds={['fuzz']} label="fuzzing" />);
    fireEvent.click(await screen.findByText(/2 fuzzing runs/));
    expect(screen.getByText('60s')).toBeTruthy();
    expect(screen.getByText('120s budget')).toBeTruthy();
  });

  it('asks only for the kinds its panel drives', async () => {
    mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
    render(<RunHistory imageId="img" kinds={['uboot', 'certs']} label="deep-analysis" />);
    await waitFor(() => expect(mockApi.runs).toHaveBeenCalledWith('img', { kind: 'uboot,certs' }));
  });
});

/**
 * The defect this component shipped with: the heading was an English frame — `{n} {label} run{s} on this image` —
 * with the noun punched in by the caller. Any language whose grammar is not English's came out half-translated, and
 * in English the frame fits, so nothing on screen ever looked wrong.
 *
 * The whole sentence is a catalogue function of the count and the noun now, so what is asserted here is that NO
 * English word survives it — not merely that some Spanish appears in it, which the broken version also managed.
 */
describe('RunHistory — the heading is one sentence, built by the language that says it', () => {
  it('builds the whole Spanish sentence, with no English frame left around the noun', async () => {
    setLocale('es');
    mockApi.runs.mockResolvedValue({ runs: [run({ jobId: 'a' }), run({ jobId: 'b' })], byTarget: [] });
    const { container } = render(<RunHistory imageId="img" kinds={['uboot']} runKind="deepAnalysis" />);

    expect(await screen.findByText('2 ejecuciones de análisis profundo sobre esta imagen')).toBeTruthy();
    const text = container.textContent ?? '';
    // The English frame, in every piece it used to leave behind.
    expect(text).not.toMatch(/\bruns?\b/);
    expect(text).not.toContain('on this image');
    expect(text).not.toContain('deep-analysis');
    expect(screen.getByText(/el panel de arriba sólo muestra la más reciente/)).toBeTruthy();
  });

  it('agrees in number, which is the reason the sentence cannot be a placeholder', async () => {
    // Spanish pluralises the noun the count governs — `ejecución` / `ejecuciones` — and English does not inflect
    // the same word at all. A single frame with a hole in it cannot produce both.
    setLocale('es');
    const three = ['a', 'b', 'c'].map((jobId) => run({ jobId }));
    mockApi.runs.mockResolvedValue({ runs: three, byTarget: [] });
    const { unmount } = render(<RunHistory imageId="img" kinds={['uboot']} runKind="deepAnalysis" />);
    expect(await screen.findByText(/^3 ejecuciones de/)).toBeTruthy();
    unmount();

    // A panel that owns its noun in its own namespace passes it through `label`, and the sentence around it is
    // still built here — that is what makes `ImageDetail`'s already-translated nouns read correctly.
    mockApi.runs.mockResolvedValue({ runs: [run({ jobId: 'a' }), run({ jobId: 'b' })], byTarget: [] });
    render(<RunHistory imageId="img" kinds={['diff']} label="comparativa" />);
    expect(await screen.findByText('2 ejecuciones de comparativa sobre esta imagen')).toBeTruthy();
  });

  it('puts the elapsed-time preposition where each language puts it', () => {
    // `2m ago` and `hace 2 min` are not the same string with a word swapped — the preposition leads in one and
    // trails in the other. One catalogue entry per unit is what lets both be written rather than derived.
    const now = 1_800_000_000_000;
    const en = catalogues.en.shell.runHistory.ago;
    const es = catalogues.es.shell.runHistory.ago;
    expect(ago(now - 30_000, en, now)).toBe('30s ago');
    expect(ago(now - 30_000, es, now)).toBe('hace 30 s');
    expect(ago(now - 7_200_000, en, now)).toBe('2h ago');
    expect(ago(now - 7_200_000, es, now)).toBe('hace 2 h');
    // A clock that has drifted backwards must not render a negative age.
    expect(ago(now + 5_000, es, now)).toBe('hace 0 s');
  });

  it('glosses each outcome in Spanish while the job kind and target stay identifiers', async () => {
    setLocale('es');
    mockApi.runs.mockResolvedValue({
      runs: [
        run({ jobId: 'a', kind: 'uboot', target: null, outcome: 'blocked', headline: 'radare2 no está instalado' }),
        run({ jobId: 'b', outcome: 'empty', headline: 'sin resultados en este presupuesto' }),
      ],
      byTarget: [],
    });
    render(<RunHistory imageId="img" kinds={['uboot']} runKind="deepAnalysis" />);
    fireEvent.click(await screen.findByText(/2 ejecuciones de/));

    expect(screen.getByText('bloqueada')).toBeTruthy();
    expect(screen.getByText('sin resultados')).toBeTruthy();
    // The pair that must never converge, stated in Spanish where the reader hovers.
    expect(screen.getByTitle(/NO es un resultado negativo/)).toBeTruthy();
    expect(screen.getByTitle(/No es un certificado de que esté limpio/)).toBeTruthy();
    // A job kind crosses the API into SQLite and a target is a path — both render verbatim in every language.
    expect(screen.getByText('uboot')).toBeTruthy();
    expect(screen.getByText('sbin/one')).toBeTruthy();
  });
});
