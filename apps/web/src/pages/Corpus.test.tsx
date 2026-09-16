import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
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

  it('promotes a reused credential through the operator-controlled label', async () => {
    mockApi.corpusOverview.mockResolvedValue({
      imageCount: 2,
      ruleCount: 0,
      credentialReuse: [{ hash: 'credential-hash', kind: 'password', imageCount: 2, watchlistLabel: null }],
      componentPrevalence: [],
      deviceFamilies: [],
    });
    mockApi.promoteRule.mockResolvedValue({});
    vi.spyOn(window, 'prompt').mockReturnValue('vendor default');

    render(
      <MemoryRouter>
        <Corpus />
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole('button', { name: /vigilancia/i }));

    await waitFor(() =>
      expect(mockApi.promoteRule).toHaveBeenCalledWith('known-credential', 'credential-hash', 'vendor default'),
    );
    expect(mockApi.corpusOverview).toHaveBeenCalledTimes(2);
  });
});
