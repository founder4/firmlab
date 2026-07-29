import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type OpacidadResult, api } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { es } from '../locales/es';
import { mockedApi } from '../test-api-mock';
import { OpacidadPanel } from './OpacidadPanel';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const result = (o: Partial<OpacidadResult> = {}): OpacidadResult => ({
  firmwareClass: 'esp-soc',
  arch: 'xtensa',
  classRationale: 'ESP SoC flash dump — not a Linux image.',
  plan: [{ worker: 'W6 · ESP / IoT-SoC', reason: 'NVS keys + eFuse posture' }],
  steps: [
    {
      worker: 'W6 · ESP / IoT-SoC',
      status: 'not-built',
      summary: 'NVS keys + eFuse posture',
      note: 'worker not built yet',
    },
  ],
  findings: { total: 0, bySeverity: {}, byProofState: {}, top: [] },
  attackPath: [],
  narrative: 'ESP SoC flash dump. Not Linux — the rootfs pipeline does not apply.',
  narrativeSource: 'deterministic',
  honestGaps: [
    'W6 · ESP / IoT-SoC: not built yet — worker not built yet',
    'Zero findings here does NOT mean "secure".',
  ],
  ...o,
});

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
  // The panel drops a RunHistory under its result, which reads the run ledger. Before the shared mock this call
  // was left pointing at the real client and fetched over the network in every test in this file.
  mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
  mockApi.opacidadResult.mockResolvedValue(null);
  mockApi.runOpacidad.mockResolvedValue({ jobId: 'j1' });
  mockApi.job.mockResolvedValue({ id: 'j1', status: 'done', result: result(), log: '' });
});

describe('OpacidadPanel — autonomous scan', () => {
  it('offers a run control when there is no prior scan', async () => {
    render(<OpacidadPanel imageId="img1" />);
    expect(await screen.findByRole('button', { name: en.panels.opacidad.run })).toBeInTheDocument();
  });

  it('kicks off the scan on click', async () => {
    render(<OpacidadPanel imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: en.panels.opacidad.run }));
    await waitFor(() => expect(mockApi.runOpacidad).toHaveBeenCalledWith('img1'));
  });

  it('renders a prior scan: class, the routed worker, and the honest-gaps surface (not-built shown, never hidden)', async () => {
    mockApi.opacidadResult.mockResolvedValue(result());
    render(<OpacidadPanel imageId="img1" />);
    expect(await screen.findByText('esp-soc')).toBeInTheDocument();
    expect(screen.getByText('W6 · ESP / IoT-SoC')).toBeInTheDocument();
    expect(screen.getByText(en.panels.opacidad.honestGaps)).toBeInTheDocument();
    // The gap sentences are the server's own words and are rendered as it wrote them.
    expect(screen.getByText(/does NOT mean/i)).toBeInTheDocument();
    // The narrative provenance is labelled (deterministic vs LLM) so the operator knows how it was written.
    expect(screen.getByText(new RegExp(`${en.panels.opacidad.narrativeLabel} deterministic`, 'i'))).toBeInTheDocument();
  });

  /**
   * The narrative is Markdown on BOTH paths — `composeDeterministicNarrative` writes `##`, `- ` and `code` spans
   * by hand — so it was showing its own source with every LLM flag off. What the codes must survive is the
   * emphasis rules: `needs_runtime_reproduction` is an identifier, not two italicised words.
   */
  it('renders the narrative as prose, with the proof-state codes intact', async () => {
    mockApi.opacidadResult.mockResolvedValue(
      result({
        narrative:
          '## Findings\n\n- **[critical]** UID-0 `root` has an empty password — _needs_runtime_reproduction_ (sbom)',
      }),
    );
    const { container } = render(<OpacidadPanel imageId="img1" />);

    await waitFor(() => expect(container.querySelector('.md-box .md')).toBeTruthy());
    const md = container.querySelector('.md-box .md');
    expect(md?.querySelector('h3')?.textContent).toBe('Findings');
    expect(md?.querySelector('li strong')?.textContent).toBe('[critical]');
    expect(md?.querySelector('li code')?.textContent).toBe('root');
    expect(md?.querySelector('em')?.textContent).toBe('needs_runtime_reproduction');
    expect(md?.textContent).not.toContain('**');
    expect(md?.textContent).toContain('needs_runtime_reproduction');
  });
});

/**
 * The scan's coverage claim, in Spanish. A stage reported `not-built` or `skipped` is a stage nothing was asked of,
 * and the panel has to keep saying so in every language — a translation in which the status mark reads as "correcto"
 * would turn an unbuilt worker into a passed one, which is exactly the conflation the honest-gaps list exists to
 * prevent. The class, the worker id, the status codes and the narrative stay as the scan sent them.
 */
describe('OpacidadPanel — the honest gaps in Spanish', () => {
  it('shows an unbuilt worker as a stage nothing was asked of, never as one that passed', async () => {
    setLocale('es');
    mockApi.opacidadResult.mockResolvedValue(result());
    render(<OpacidadPanel imageId="img1" />);

    expect(await screen.findByText(es.panels.opacidad.honestGaps)).toBeInTheDocument();
    expect(es.panels.opacidad.honestGaps).toMatch(/lo que NO se ejecutó/);
    // The status gloss on the mark: the code opens it verbatim, the sentence refuses to call it a pass.
    expect(screen.getByTitle(es.panels.opacidad.status['not-built'])).toBeInTheDocument();
    expect(es.panels.opacidad.status['not-built']).toMatch(/^not-built —/);
    expect(es.panels.opacidad.status['not-built']).toMatch(/no es una etapa superada/i);
    expect(es.panels.opacidad.status.skipped).toMatch(/no es una etapa superada/i);
    // The class, the worker id and the narrative source are data — identical in either language.
    expect(screen.getByText('esp-soc')).toBeInTheDocument();
    expect(screen.getByText('W6 · ESP / IoT-SoC')).toBeInTheDocument();
    expect(screen.getByText(new RegExp(`${es.panels.opacidad.narrativeLabel} deterministic`, 'i'))).toBeInTheDocument();
  });

  it('never lets an empty findings list read as a clean firmware', async () => {
    setLocale('es');
    mockApi.opacidadResult.mockResolvedValue(result());
    render(<OpacidadPanel imageId="img1" />);

    expect(await screen.findByText(es.panels.opacidad.noFindings)).toBeInTheDocument();
    expect(es.panels.opacidad.noFindings).toMatch(/nunca un certificado de limpieza/i);
    expect(screen.getByText(es.panels.opacidad.findings(0))).toBeInTheDocument();
  });
});
