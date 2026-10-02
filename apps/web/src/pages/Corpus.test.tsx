import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type CorpusReindexReport, type ReanalyzeAllReport, api } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { es } from '../locales/es';
import { mockedApi } from '../test-api-mock';
import { Corpus, filterComponentPrevalence, filterCredentialReuse, reclassifyStatus } from './Corpus';

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

  it.each([
    ['en', 'No device families discovered across images yet.'],
    ['es', 'Aún no se han descubierto familias de dispositivos entre imágenes.'],
  ] as const)(
    'in %s: says no family has been discovered instead of rendering an empty panel',
    async (locale, empty) => {
      setLocale(locale);
      render(
        <MemoryRouter>
          <Corpus />
        </MemoryRouter>,
      );
      expect(await screen.findByText(empty)).toBeInTheDocument();
    },
  );

  it('drops the families empty note once a family exists', async () => {
    setLocale('en');
    mockApi.corpusOverview.mockResolvedValue({
      imageCount: 2,
      ruleCount: 0,
      credentialReuse: [],
      componentPrevalence: [],
      deviceFamilies: [{ familyKey: 'acme/router', images: [{ id: 'one', filename: 'router-v1.bin' }] }],
    });
    render(
      <MemoryRouter>
        <Corpus />
      </MemoryRouter>,
    );
    expect(await screen.findByRole('link', { name: 'router-v1.bin' })).toBeInTheDocument();
    expect(screen.queryByText('No device families discovered across images yet.')).not.toBeInTheDocument();
  });

  /**
   * The quick filters narrow the rows the API listed. A credential matches on its full hash — not the 16 characters
   * the table shows — and on kind or watchlist label; a component on name or version. Case is ignored.
   */
  describe('quick filters', () => {
    const reuse = [
      { hash: 'aaaa1111bbbb2222cccc3333', kind: 'password', imageCount: 3, watchlistLabel: 'default admin' },
      { hash: 'dddd4444eeee5555ffff6666', kind: 'private-key', imageCount: 2, watchlistLabel: null },
    ];
    const prevalence = [
      { name: 'busybox', version: '1.18.4', cveCount: 3, imageCount: 4 },
      { name: 'dropbear', version: '2012.55', cveCount: 1, imageCount: 2 },
      { name: 'openssl', version: '1.0.1e', cveCount: 9, imageCount: 2 },
    ];

    it('matches credentials on the full hash, kind and label, and components on name and version', () => {
      expect(filterCredentialReuse(reuse, '')).toHaveLength(2);
      expect(filterCredentialReuse(reuse, 'ffff6666').map((r) => r.kind)).toEqual(['private-key']);
      expect(filterCredentialReuse(reuse, 'PASSWORD').map((r) => r.kind)).toEqual(['password']);
      expect(filterCredentialReuse(reuse, 'admin').map((r) => r.kind)).toEqual(['password']);
      expect(filterCredentialReuse(reuse, 'nothing')).toEqual([]);
      expect(filterComponentPrevalence(prevalence, 'Drop').map((r) => r.name)).toEqual(['dropbear']);
      expect(filterComponentPrevalence(prevalence, '1.0.1').map((r) => r.name)).toEqual(['openssl']);
      expect(filterComponentPrevalence(prevalence, '  ')).toHaveLength(3);
    });

    function renderTables(): void {
      mockApi.corpusOverview.mockResolvedValue({
        imageCount: 4,
        ruleCount: 0,
        credentialReuse: reuse,
        componentPrevalence: prevalence,
        deviceFamilies: [],
      });
      render(
        <MemoryRouter>
          <Corpus />
        </MemoryRouter>,
      );
    }

    it.each([
      [
        'en',
        'Filter reused credentials by hash, kind or watchlist label',
        '1 of 2 listed row(s) match.',
        'No listed row matches “nope”.',
        'Clear',
      ],
      [
        'es',
        'Filtrar credenciales reutilizadas por hash, tipo o etiqueta de vigilancia',
        '1 de 2 fila(s) listada(s) coinciden.',
        'Ninguna fila listada coincide con «nope».',
        'Limpiar',
      ],
    ] as const)('in %s: filters credential reuse by hash and kind', async (locale, label, count, noMatch, clear) => {
      setLocale(locale);
      renderTables();
      const search = await screen.findByRole('searchbox', { name: label });
      expect(screen.getByText('password')).toBeInTheDocument();
      expect(screen.getByText('private-key')).toBeInTheDocument();

      // By a part of the hash past the 16 characters the table shows.
      fireEvent.change(search, { target: { value: 'ffff6666' } });
      expect(screen.queryByText('password')).not.toBeInTheDocument();
      expect(screen.getByText('private-key')).toBeInTheDocument();
      expect(screen.getByText(count)).toBeInTheDocument();

      // By kind.
      fireEvent.change(search, { target: { value: 'pass' } });
      expect(screen.getByText('password')).toBeInTheDocument();
      expect(screen.queryByText('private-key')).not.toBeInTheDocument();

      fireEvent.change(search, { target: { value: 'nope' } });
      expect(screen.getByText(noMatch)).toBeInTheDocument();

      fireEvent.click(screen.getByRole('button', { name: clear }));
      expect(search).toHaveValue('');
      expect(screen.getByText('password')).toBeInTheDocument();
      expect(screen.getByText('private-key')).toBeInTheDocument();
      expect(screen.queryByText(count)).not.toBeInTheDocument();
    });

    it.each([
      ['en', 'Filter components by name or version', '1 of 3 listed row(s) match.', 'No listed row matches “zlib”.'],
      [
        'es',
        'Filtrar componentes por nombre o versión',
        '1 de 3 fila(s) listada(s) coinciden.',
        'Ninguna fila listada coincide con «zlib».',
      ],
    ] as const)('in %s: filters component prevalence by component name', async (locale, label, count, noMatch) => {
      setLocale(locale);
      renderTables();
      const search = await screen.findByRole('searchbox', { name: label });

      fireEvent.change(search, { target: { value: 'busy' } });
      expect(screen.getByText('busybox')).toBeInTheDocument();
      expect(screen.queryByText('dropbear')).not.toBeInTheDocument();
      expect(screen.queryByText('openssl')).not.toBeInTheDocument();
      expect(screen.getByText(count)).toBeInTheDocument();
      // The credential table is untouched by the component filter.
      expect(screen.getByText('private-key')).toBeInTheDocument();

      fireEvent.change(search, { target: { value: 'zlib' } });
      expect(screen.getByText(noMatch)).toBeInTheDocument();
      expect(screen.queryByText('busybox')).not.toBeInTheDocument();
    });
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
  /**
   * Re-running the classifier rewrites every image's stored identity, so it asks first; and its report must keep two
   * readings impossible — a failed image's class is the one it KEPT, and an unchanged image is not silently dropped
   * from the arithmetic.
   */
  describe('reanalyze', () => {
    const report: ReanalyzeAllReport = {
      total: 4,
      changed: 2,
      failed: 1,
      results: [
        { id: 'a', filename: 'ecos.bin', before: 'embedded-linux', after: 'rtos' },
        { id: 'b', filename: 'fresh.bin', before: null, after: 'esp-soc' },
        { id: 'c', filename: 'stable.bin', before: 'uefi-bios', after: 'uefi-bios' },
        {
          id: 'd',
          filename: 'gone.bin',
          before: 'baremetal',
          after: 'baremetal',
          error: "ENOENT: no such file or directory, open '/data/images/d'",
        },
      ],
    };

    function deferred<T>(): { promise: Promise<T>; resolve: (v: T) => void } {
      let resolve!: (v: T) => void;
      const promise = new Promise<T>((r) => {
        resolve = r;
      });
      return { promise, resolve };
    }

    it('classifies a row from the row alone, failure first', () => {
      expect(reclassifyStatus({ id: 'x', filename: 'x', before: 'rtos', after: 'rtos' })).toBe('unchanged');
      expect(reclassifyStatus({ id: 'x', filename: 'x', before: 'rtos', after: 'esp-soc' })).toBe('changed');
      expect(reclassifyStatus({ id: 'x', filename: 'x', before: null, after: 'rtos' })).toBe('changed');
      expect(reclassifyStatus({ id: 'x', filename: 'x', before: 'rtos', after: 'rtos', error: 'boom' })).toBe('failed');
    });

    it('re-analyzes nothing when the confirmation is cancelled', async () => {
      setLocale('en');
      render(
        <MemoryRouter>
          <Corpus />
        </MemoryRouter>,
      );
      fireEvent.click(await screen.findByRole('button', { name: 'Re-analyze all images' }));
      const dialog = screen.getByRole('dialog');
      expect(within(dialog).getByText('Re-classify every image?')).toBeInTheDocument();
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(mockApi.reanalyzeCorpus).not.toHaveBeenCalled();
    });

    it.each([
      [
        'en',
        'Re-analyze all images',
        'Re-analyzing…',
        'Re-analyze',
        '4 image(s) re-analyzed: 2 changed class, 1 unchanged, 1 failed.',
        'changed',
        'failed — stored class kept',
        'none stored',
      ],
      [
        'es',
        'Reanalizar todas las imágenes',
        'Reanalizando…',
        'Reanalizar',
        '4 imagen(es) reanalizada(s): 2 cambiaron de clase, 1 sin cambios, 1 fallaron.',
        'cambió',
        'falló — se conserva la clase guardada',
        'ninguna guardada',
      ],
    ] as const)(
      'in %s: confirms, locks while busy, lists changed and failed images and refreshes',
      async (locale, run, running, confirm, summary, changed, failed, none) => {
        setLocale(locale);
        const pending = deferred<ReanalyzeAllReport>();
        mockApi.reanalyzeCorpus.mockReturnValue(pending.promise);
        render(
          <MemoryRouter>
            <Corpus />
          </MemoryRouter>,
        );

        fireEvent.click(await screen.findByRole('button', { name: run }));
        fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: confirm }));
        expect(mockApi.reanalyzeCorpus).toHaveBeenCalledTimes(1);

        const busy = screen.getByRole('button', { name: running });
        expect(busy).toBeDisabled();
        fireEvent.click(busy);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(mockApi.corpusOverview).toHaveBeenCalledTimes(1);

        pending.resolve(report);

        expect(await screen.findByText(summary)).toBeInTheDocument();

        // A changed image: before → after, linked back to the image whose plan it re-routes.
        const ecos = screen.getByRole('link', { name: 'ecos.bin' });
        expect(ecos).toHaveAttribute('href', '/image/a');
        const ecosRow = ecos.closest('tr') as HTMLElement;
        expect(within(ecosRow).getByText('embedded-linux')).toBeInTheDocument();
        expect(within(ecosRow).getByText('rtos')).toBeInTheDocument();
        expect(within(ecosRow).getByText(changed)).toBeInTheDocument();

        // A first classification names the missing class instead of printing nothing.
        const freshRow = screen.getByRole('link', { name: 'fresh.bin' }).closest('tr') as HTMLElement;
        expect(within(freshRow).getByText(none)).toBeInTheDocument();
        expect(within(freshRow).getByText('esp-soc')).toBeInTheDocument();

        // A failure shows only the class it kept, with the route's own reason verbatim.
        const goneRow = screen.getByRole('link', { name: 'gone.bin' }).closest('tr') as HTMLElement;
        expect(within(goneRow).getAllByText('baremetal')).toHaveLength(1);
        expect(within(goneRow).queryByText('→')).not.toBeInTheDocument();
        expect(within(goneRow).getByText(failed)).toBeInTheDocument();
        expect(within(goneRow).getByText(/ENOENT: no such file/)).toBeInTheDocument();

        // An unchanged image is in the count, not the table.
        expect(screen.queryByText('stable.bin')).not.toBeInTheDocument();

        await waitFor(() => expect(mockApi.corpusOverview).toHaveBeenCalledTimes(2));
        expect(mockApi.corpusRules).toHaveBeenCalledTimes(2);
        expect(screen.getByRole('button', { name: run })).toBeEnabled();
      },
    );

    it('says why the report is empty on an empty bench', async () => {
      setLocale('en');
      mockApi.reanalyzeCorpus.mockResolvedValue({ total: 0, changed: 0, failed: 0, results: [] });
      render(
        <MemoryRouter>
          <Corpus />
        </MemoryRouter>,
      );
      fireEvent.click(await screen.findByRole('button', { name: 'Re-analyze all images' }));
      fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Re-analyze' }));
      expect(
        await screen.findByText('There are no images on this bench, so nothing was re-analyzed.'),
      ).toBeInTheDocument();
      expect(screen.queryByRole('table')).not.toBeInTheDocument();
    });

    it('re-enables the button and invents no report when the request fails', async () => {
      setLocale('en');
      mockApi.reanalyzeCorpus.mockRejectedValue(new Error('500 Internal Server Error'));
      render(
        <MemoryRouter>
          <Corpus />
        </MemoryRouter>,
      );
      fireEvent.click(await screen.findByRole('button', { name: 'Re-analyze all images' }));
      fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Re-analyze' }));
      await waitFor(() => expect(screen.getByRole('button', { name: 'Re-analyze all images' })).toBeEnabled());
      expect(screen.queryByText(/image\(s\) re-analyzed/)).not.toBeInTheDocument();
      expect(mockApi.corpusOverview).toHaveBeenCalledTimes(1);
    });
  });
});
