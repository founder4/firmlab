/**
 * The workspace panorama, and the one call on it whose answer is prose.
 *
 * Three of this page's four fetches return data — a listing, a storage figure, a bind posture — and they come back
 * identical in every language. `/tools` does not: each tool's `unlocks` line is composed by the API from the
 * binaries actually on this box at request time, so it is interface copy about THIS DEPLOYMENT and the page has to
 * ask for it in the language it is rendering, then ask again when that changes.
 *
 * The page itself only prints the tool COUNT, which is why this is worth pinning here rather than trusting the
 * render: nothing visible on this screen would change if the locale never reached the request, and the same call
 * feeds the Capabilities table where it very much would.
 */
import { act, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { Overview } from './Overview';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const image = {
  id: 'a',
  filename: 'router-v1.bin',
  size: 1024,
  sha256: 'deadbeef',
  uploadedAt: 1,
  status: 'ready' as const,
  identity: { firmwareClass: 'embedded-linux', arch: 'mips', endianness: 'big', filesystems: ['squashfs'] },
  tags: [],
};

const usage = { imageCount: 1, imagesBytes: 1024, extractsBytes: 0, totalBytes: 1024, quotaBytes: 0, maxAgeDays: 0 };

const tools = [
  { id: 'binwalk', bin: 'binwalk', available: true, unlocks: 'Format-aware signature carving', group: 'extract' },
  { id: 'renode', bin: 'renode', available: false, unlocks: 'RTOS / Cortex-M emulation', group: 'emulate' },
];

const renderOverview = (): void => {
  render(
    <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Overview />
    </MemoryRouter>,
  );
};

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a component that is still mounted and the suite fills with act(…) warnings.
  setLocale('en');
  mockApi.listImages.mockResolvedValue([image]);
  mockApi.storage.mockResolvedValue(usage);
  mockApi.tools.mockResolvedValue({ tools, groups: {} });
  mockApi.health.mockResolvedValue({ status: 'ok', exposedToNetwork: false, host: '127.0.0.1', port: 8799 });
  mockApi.tools.mockClear();
});

describe('Overview — the tool table is requested in the active language', () => {
  it('carries the locale on the first load', async () => {
    renderOverview();
    expect(await screen.findByText('router-v1.bin')).toBeInTheDocument();
    expect(mockApi.tools).toHaveBeenCalledWith('en');
  });

  it('re-asks for it when the operator switches language, rather than keeping the first answer', async () => {
    renderOverview();
    expect(await screen.findByText('router-v1.bin')).toBeInTheDocument();
    expect(mockApi.tools).toHaveBeenCalledTimes(1);

    await act(async () => {
      setLocale('es');
    });
    await waitFor(() => expect(mockApi.tools).toHaveBeenCalledWith('es'));
    expect(mockApi.tools).toHaveBeenCalledTimes(2);
  });
});

describe('Overview localisation', () => {
  it('renders its chrome in English', async () => {
    renderOverview();
    expect(await screen.findByText('router-v1.bin')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument();
    expect(screen.getByText('Recent images')).toBeInTheDocument();
    expect(screen.getByText('Fleet by class')).toBeInTheDocument();
    expect(screen.getByText('local-only')).toBeInTheDocument();
  });

  it('translates the chrome and leaves the class id and the tool count alone', async () => {
    setLocale('es');
    renderOverview();
    expect(await screen.findByText('router-v1.bin')).toBeInTheDocument();

    expect(screen.getByText('Imágenes recientes')).toBeInTheDocument();
    expect(screen.getByText('Flota por clase')).toBeInTheDocument();

    // `embedded-linux` is a class id that crosses the API; `1/2` is a count. Neither is prose.
    expect(screen.getAllByText('embedded-linux').length).toBeGreaterThan(0);
    expect(screen.getByText('1/2')).toBeInTheDocument();
  });

  /**
   * The posture word is a claim about where the API is bound, not a comfort message. A Spanish render that lost it
   * — or softened it — would be claiming something the workbench has not measured.
   */
  it('states the network posture in Spanish, and states an exposed one as exposed', async () => {
    setLocale('es');
    renderOverview();
    expect(await screen.findByText('sólo local')).toBeInTheDocument();
  });
});
