import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type CorpusReindexReport, api } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { es } from '../locales/es';
import { mockedApi } from '../test-api-mock';
import { Corpus } from './Corpus';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

beforeEach(() => {
  vi.clearAllMocks();
  setLocale('es');
  mockApi.corpusRules.mockResolvedValue([]);
  mockApi.corpusOverview.mockResolvedValue({
    imageCount: 2,
    ruleCount: 0,
    credentialReuse: [],
    componentPrevalence: [],
    deviceFamilies: [],
  });
});

describe('Corpus', () => {
  it('shows every row the API returned and says so when the API itself cut the list', async () => {
    // Two bounds used to stack here: the API ranks and cuts at 200, and the page cut the survivors again at 100
    // with nothing on screen to say so. Rows 101-200 simply were not there.
    const rows = Array.from({ length: 150 }, (_, i) => ({
      name: `pkg-${String(i).padStart(3, '0')}`,
      version: '1.0',
      cveCount: 0,
      imageCount: 2,
    }));
    mockApi.corpusOverview.mockResolvedValue({
      imageCount: 9,
      ruleCount: 0,
      credentialReuse: [],
      componentPrevalence: rows,
      componentPrevalenceTotal: 412,
      credentialReuseTotal: 0,
      listing: { cap: 200, rule: 'ordenadas por número de imágenes' },
      sbomImageCount: 9,
      deviceFamilies: [],
    });

    render(
      <MemoryRouter>
        <Corpus />
      </MemoryRouter>,
    );

    expect(await screen.findByText('pkg-000')).toBeInTheDocument();
    expect(screen.getByText('pkg-149')).toBeInTheDocument();
    expect(screen.getByText(/Mostrando 150 de 412/)).toBeInTheDocument();
  });

  it('counts reused credentials from the corpus total, never from the length of a truncated list', async () => {
    mockApi.corpusOverview.mockResolvedValue({
      imageCount: 9,
      ruleCount: 0,
      credentialReuse: [{ hash: 'aa', kind: 'password', imageCount: 2, watchlistLabel: null }],
      credentialReuseTotal: 37,
      componentPrevalence: [],
      componentPrevalenceTotal: 0,
      listing: { cap: 200, rule: 'ordenadas por número de imágenes' },
      sbomImageCount: 9,
      deviceFamilies: [],
    });

    render(
      <MemoryRouter>
        <Corpus />
      </MemoryRouter>,
    );

    expect(await screen.findByText('37')).toBeInTheDocument();
  });

  it('renders measured reuse and links every family member back to its image', async () => {
    mockApi.corpusOverview.mockResolvedValue({
      imageCount: 2,
      ruleCount: 1,
      credentialReuse: [
        { hash: 'abcdef0123456789abcdef', kind: 'password', imageCount: 2, watchlistLabel: 'default admin' },
      ],
      componentPrevalence: [{ name: 'busybox', version: '1.18.4', cveCount: 3, imageCount: 2 }],
      deviceFamilies: [
        {
          familyKey: 'acme/router',
          images: [
            { id: 'one', filename: 'router-v1.bin' },
            { id: 'two', filename: 'router-v2.bin' },
          ],
        },
      ],
    });

    render(
      <MemoryRouter>
        <Corpus />
      </MemoryRouter>,
    );

    expect(await screen.findByText('busybox')).toBeInTheDocument();
    expect(screen.getByText('default admin')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'router-v1.bin' })).toHaveAttribute('href', '/image/one');
    expect(screen.getByRole('link', { name: 'router-v2.bin' })).toHaveAttribute('href', '/image/two');
  });

  /**
   * Three unrelated things in this repository are called "corpus" (see "The three corpora" in
   * docs/ARCHITECTURE.md), and this screen was the only one naming none of them: it opened straight into the stat
   * tiles, so the sidebar entry — which read just "Corpus" — was the whole label. What is asserted is both halves
   * of the disambiguation, in both catalogues: the page says WHICH corpus this is, and says which two it is not.
   */
  it('names which of the three corpora it is, in both languages', async () => {
    const spanish = render(
      <MemoryRouter>
        <Corpus />
      </MemoryRouter>,
    );
    expect(await screen.findByRole('heading', { level: 1, name: 'Corpus entre imágenes' })).toBeInTheDocument();
    expect(screen.getByText(/no es el corpus de validación/i)).toBeInTheDocument();
    expect(screen.getByText(/ni el corpus de reglas YARA/i)).toBeInTheDocument();
    spanish.unmount();

    setLocale('en');
    render(
      <MemoryRouter>
        <Corpus />
      </MemoryRouter>,
    );
    expect(await screen.findByRole('heading', { level: 1, name: 'Cross-image corpus' })).toBeInTheDocument();
    expect(screen.getByText(/not the validation corpus/i)).toBeInTheDocument();
    expect(screen.getByText(/not the YARA rule corpus/i)).toBeInTheDocument();
  });

  /**
   * The sidebar is where the ambiguity actually reached an operator: one entry, reading "Corpus", for one of three
   * things. Asserted on the catalogues rather than through a full App render, because the claim is about the two
   * strings, and `pnpm check` already guarantees the Spanish one exists.
   */
  it('qualifies the sidebar entry in both catalogues', () => {
    expect(en.nav.corpus).toBe('Cross-image corpus');
    expect(es.nav.corpus).toBe('Corpus entre imágenes');
  });

  it('asks before removing a watchlist rule, and removes nothing on cancel', async () => {
    mockApi.corpusOverview.mockResolvedValue({
      imageCount: 1,
      ruleCount: 1,
      credentialReuse: [],
      componentPrevalence: [],
      deviceFamilies: [],
    });
    mockApi.corpusRules.mockResolvedValue([
      { id: 'r1', type: 'known-credential', key: 'abcdef0123456789abcdef', label: 'default admin' },
    ] as never);
    mockApi.deleteRule.mockResolvedValue({} as never);
    render(
      <MemoryRouter>
        <Corpus />
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole('button', { name: 'quitar' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByRole('button', { name: 'Cancelar' })).toHaveFocus();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancelar' }));
    expect(mockApi.deleteRule).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'quitar' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Quitar' }));
    await waitFor(() => expect(mockApi.deleteRule).toHaveBeenCalledWith('r1'));
  });

  it('promotes a reused credential through the operator-controlled label', async () => {
    mockApi.corpusOverview.mockResolvedValue({
      imageCount: 2,
      ruleCount: 0,
      credentialReuse: [{ hash: 'credential-hash', kind: 'password', imageCount: 2, watchlistLabel: null }],
      componentPrevalence: [],
      deviceFamilies: [],
    });
    mockApi.promoteRule.mockResolvedValue({});

    render(
      <MemoryRouter>
        <Corpus />
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole('button', { name: /vigilancia/i }));

    // The dialog offers the detector's own label, and refuses an empty one by naming the field.
    const dialog = screen.getByRole('dialog');
    const label = within(dialog).getByLabelText('Etiqueta');
    expect(label).toHaveValue('password');
    fireEvent.change(label, { target: { value: '  ' } });
    fireEvent.click(within(dialog).getByRole('button', { name: /vigilancia/i }));
    expect(within(dialog).getByRole('alert')).toHaveTextContent('Etiqueta');
    expect(mockApi.promoteRule).not.toHaveBeenCalled();

    fireEvent.change(label, { target: { value: 'vendor default' } });
    fireEvent.click(within(dialog).getByRole('button', { name: /vigilancia/i }));

    await waitFor(() =>
      expect(mockApi.promoteRule).toHaveBeenCalledWith('known-credential', 'credential-hash', 'vendor default'),
    );
    expect(mockApi.corpusOverview).toHaveBeenCalledTimes(2);
  });

  describe('reindex', () => {
    const report = (verdict: string, reason: string): CorpusReindexReport => ({
      imageCount: 3,
      sources: [
        { source: 'static-secrets', imagesWithInput: 3, imagesWithoutInput: 0, rowsOffered: 9, rowsInserted: 4 },
        { source: 'gitleaks', imagesWithInput: 1, imagesWithoutInput: 2, rowsOffered: 2, rowsInserted: 2 },
        { source: 'credential-hashes', imagesWithInput: 2, imagesWithoutInput: 1, rowsOffered: 1, rowsInserted: 0 },
        { source: 'components', imagesWithInput: 2, imagesWithoutInput: 1, rowsOffered: 40, rowsInserted: 11 },
        { source: 'artifacts', imagesWithInput: 3, imagesWithoutInput: 0, rowsOffered: 7, rowsInserted: 0 },
      ],
      boundedInputs: [{ imageId: 'one', filename: 'router-v1.bin', kind: 'static-scan', covered: 64, total: 128 }],
      unrecordedBounds: [{ kind: 'sbom-packages', imageCount: 2 }],
      unstampedCredentials: [],
      notReconciled: [
        { table: 'reachability_prior', reason },
        { table: 'corpus_rule', reason: 'curated' },
      ],
      verdict,
    });

    /** A promise the test settles by hand, so the in-flight state is observable rather than raced past. */
    function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
      let resolve!: (v: T) => void;
      const promise = new Promise<T>((r) => {
        resolve = r;
      });
      return { promise, resolve };
    }

    it.each([
      ['en', 'Reindex cross-image corpus', 'Reindexing…', '17 row(s) inserted across 3 image(s).', 'Not reconciled'],
      ['es', 'Reindexar corpus', 'Reindexando…', '17 fila(s) insertada(s) en 3 imagen(es).', 'Sin reconciliar'],
    ] as const)(
      'in %s: asks in the page locale, locks while busy, reports and refreshes',
      async (locale, run, running, total, unreconciled) => {
        setLocale(locale);
        const pending = deferred<CorpusReindexReport>();
        mockApi.reindexCorpus.mockReturnValue(pending.promise);
        render(
          <MemoryRouter>
            <Corpus />
          </MemoryRouter>,
        );

        fireEvent.click(await screen.findByRole('button', { name: run }));
        expect(mockApi.reindexCorpus).toHaveBeenCalledWith(locale);

        // In flight: the button is disabled and says so, and a second click cannot start a second run.
        const busy = screen.getByRole('button', { name: running });
        expect(busy).toBeDisabled();
        fireEvent.click(busy);
        expect(mockApi.reindexCorpus).toHaveBeenCalledTimes(1);
        expect(mockApi.corpusOverview).toHaveBeenCalledTimes(1);

        mockApi.corpusOverview.mockResolvedValue({
          imageCount: 3,
          ruleCount: 0,
          credentialReuse: [],
          credentialReuseTotal: 5,
          componentPrevalence: [],
          deviceFamilies: [],
        });
        pending.resolve(report(`verdict in ${locale}`, `prior reason in ${locale}`));

        // The API's own localised sentence, the sum, each source's counts and what the reindex cannot restore.
        expect(await screen.findByText(`verdict in ${locale}`)).toBeInTheDocument();
        expect(screen.getByText(total)).toBeInTheDocument();
        const components = screen.getByText('components').closest('tr');
        expect(components).not.toBeNull();
        expect(within(components as HTMLElement).getByText('11')).toBeInTheDocument();
        expect(within(components as HTMLElement).getByText('40')).toBeInTheDocument();
        expect(screen.getByText(unreconciled)).toBeInTheDocument();
        expect(screen.getByText('reachability_prior')).toBeInTheDocument();
        expect(screen.getByText(new RegExp(`prior reason in ${locale}`))).toBeInTheDocument();
        expect(screen.getByText('corpus_rule')).toBeInTheDocument();
        expect(screen.getByText(/router-v1\.bin — static-scan: 64/)).toBeInTheDocument();
        expect(screen.getByText(/sbom-packages: 2/)).toBeInTheDocument();

        // The overview and the rules are re-read, so the stat tiles carry the new counts.
        await waitFor(() => expect(mockApi.corpusOverview).toHaveBeenCalledTimes(2));
        expect(mockApi.corpusRules).toHaveBeenCalledTimes(2);
        expect(await screen.findByText('5')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: run })).toBeEnabled();
      },
    );

    it('re-enables the button and keeps the page when the reindex fails, without inventing a report', async () => {
      setLocale('en');
      mockApi.reindexCorpus.mockRejectedValue(new Error('boom'));
      render(
        <MemoryRouter>
          <Corpus />
        </MemoryRouter>,
      );
      fireEvent.click(await screen.findByRole('button', { name: 'Reindex cross-image corpus' }));
      await waitFor(() => expect(screen.getByRole('button', { name: 'Reindex cross-image corpus' })).toBeEnabled());
      expect(screen.queryByText('Not reconciled')).not.toBeInTheDocument();
      expect(mockApi.corpusOverview).toHaveBeenCalledTimes(1);
    });
  });
});
