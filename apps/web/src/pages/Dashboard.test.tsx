/**
 * The Dashboard's two halves, which must NOT move together when the locale does.
 *
 * The chrome — headings, column labels, the coverage wording — is prose the workbench writes, and it follows the
 * locale. The filename, the architecture and the firmware-class id are data the analysis produced: a Spanish render
 * that showed `arm` as `brazo`, or translated a file the operator uploaded, would be inventing values the API never
 * returned. The same run asserts both, because either one alone passes with the other broken.
 */
import { act, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import { Dashboard } from './Dashboard';

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

/** Nothing has run on this image: the one state the listing is most likely to render as a neutral blank. */
const unexamined = {
  imageId: 'a',
  filename: 'router-v1.bin',
  firmwareClass: 'embedded-linux',
  applicable: 12,
  executed: 0,
  findingCount: 0,
  ambiguous: true,
  verdict: 'Nothing has analyzed this image yet',
};

const renderDashboard = (): void => {
  render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>,
  );
};

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a component that is still mounted and the suite fills with act(…) warnings.
  setLocale('en');
  mockApi.listImages.mockResolvedValue([image]);
  mockApi.storage.mockResolvedValue(usage);
  mockApi.coverageAll.mockResolvedValue([unexamined]);
});

describe('Dashboard localisation', () => {
  it('renders its chrome in English', async () => {
    renderDashboard();
    // The table only mounts once the listing has loaded, which is the last of the three fetches to settle.
    expect(await screen.findByText('router-v1.bin')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Local analysis' })).toBeInTheDocument();
    expect(screen.getByText('Coverage')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Filter by filename/i)).toBeInTheDocument();
    expect(screen.getByText('unexamined')).toBeInTheDocument();
    expect(screen.getByText('1 of 1 unexamined')).toBeInTheDocument();
  });

  it('keeps a scanned image and an unexamined one distinguishable in the English listing', async () => {
    const scanned = { ...image, id: 'b', filename: 'camera.img' };
    mockApi.listImages.mockResolvedValue([image, scanned]);
    mockApi.coverageAll.mockResolvedValue([
      unexamined,
      { ...unexamined, imageId: 'b', executed: 12, ambiguous: false, verdict: '12 of 12 stages ran' },
    ]);
    renderDashboard();
    expect(await screen.findByText('camera.img')).toBeInTheDocument();
    expect(screen.getByText('12/12 stages')).toBeInTheDocument();
    expect(screen.getByText('unexamined')).toBeInTheDocument();
    expect(screen.getByText('1 of 2 unexamined')).toBeInTheDocument();
  });

  it('translates the chrome but leaves the filename, the arch and the class id alone', async () => {
    setLocale('es');
    renderDashboard();
    expect(await screen.findByText('router-v1.bin')).toBeInTheDocument();

    // Chrome: translated.
    expect(screen.getByRole('heading', { name: 'Análisis local' })).toBeInTheDocument();
    expect(screen.getByText('Cobertura')).toBeInTheDocument();
    expect(screen.getByText('Fichero')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Filtrar por fichero/)).toBeInTheDocument();

    // Data: untouched. The filename is the operator's file, `mips` is what the header said, and
    // `embedded-linux` is a class id that crosses the API — none of the three is prose.
    expect(screen.getByText('mips')).toBeInTheDocument();
    expect(screen.getByText('embedded-linux')).toBeInTheDocument();
    expect(screen.getByLabelText('Seleccionar router-v1.bin')).toBeInTheDocument();
  });

  it('says an unexamined image is unexamined in Spanish too, and never dresses it as a zero', async () => {
    setLocale('es');
    renderDashboard();
    expect(await screen.findByText('sin examinar')).toBeInTheDocument();
    expect(screen.getByText('1 de 1 sin examinar')).toBeInTheDocument();
    // The hover verdict arrives from the API already written in the requested language; this fixture answers the
    // same sentence whatever is asked for, so what is pinned here is that the page prints what it was given.
    expect(screen.getByTitle('Nothing has analyzed this image yet')).toBeInTheDocument();
  });
});

/**
 * The coverage verdict is composed by the server on every read, so the DASHBOARD has to ask for it in the language
 * it is rendering — and ask again when that changes.
 *
 * This is the half a render test cannot see. The row's badge is local prose and translated on the spot, so the
 * screen looks entirely Spanish while the sentence behind every hover is still English, and the panel that exists
 * to stop an unexamined image reading as a clean one is exactly the one that must not half-translate. What is
 * asserted is the CALL, because the fixture's answer is the same either way.
 */
describe('Dashboard — the corpus coverage is requested in the active language', () => {
  // The mocked client is module-scoped and its call log survives between tests, so "how many times" is only a
  // question this file can ask after clearing it. The outer `beforeEach` has already restored the resolved value.
  beforeEach(() => mockApi.coverageAll.mockClear());

  it('carries the locale on the first load', async () => {
    renderDashboard();
    expect(await screen.findByText('router-v1.bin')).toBeInTheDocument();
    expect(mockApi.coverageAll).toHaveBeenCalledWith('en');
  });

  it('re-asks for it when the operator switches language, rather than keeping the first answer', async () => {
    renderDashboard();
    expect(await screen.findByText('router-v1.bin')).toBeInTheDocument();
    expect(mockApi.coverageAll).toHaveBeenCalledTimes(1);

    // Inside `act`, because the locale store notifies live subscribers and this tree is mounted.
    await act(async () => {
      setLocale('es');
    });
    await waitFor(() => expect(mockApi.coverageAll).toHaveBeenCalledWith('es'));
    expect(mockApi.coverageAll).toHaveBeenCalledTimes(2);
  });
});
