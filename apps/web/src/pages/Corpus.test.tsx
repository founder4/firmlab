import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { setLocale } from '../i18n';
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
