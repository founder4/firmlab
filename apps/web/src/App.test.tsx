import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { api } from './api';
import { Dashboard } from './pages/Dashboard';
import { mockedApi } from './test-api-mock';

vi.mock('./api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./api')>();
  const { buildApiMock } = await import('./test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const image = (id: string, filename: string, arch: string) => ({
  id,
  filename,
  size: 1024,
  sha256: 'deadbeef',
  uploadedAt: 1,
  status: 'ready' as const,
  identity: { firmwareClass: 'embedded-linux', arch, endianness: 'little', filesystems: ['squashfs'] },
  tags: [],
});

const emptyUsage = { imageCount: 0, imagesBytes: 0, extractsBytes: 0, totalBytes: 0, quotaBytes: 0, maxAgeDays: 0 };

const coverage = (imageId: string, executed: number, applicable: number) => ({
  imageId,
  filename: imageId,
  firmwareClass: 'embedded-linux',
  applicable,
  executed,
  findingCount: executed ? 4 : 0,
  ambiguous: executed < applicable,
  verdict: executed === 0 ? 'Nothing has analyzed this image yet' : `${executed} of ${applicable} stages ran`,
});

beforeEach(() => {
  mockApi.health.mockResolvedValue({ status: 'ok', exposedToNetwork: true, trustedProxy: true });
  mockApi.listImages.mockResolvedValue([]);
  mockApi.storage.mockResolvedValue(emptyUsage);
  mockApi.coverageAll.mockResolvedValue([]);
  // Overview is the default route and reads the tool inventory for its capability tile. The hand-written mock
  // list never named it, so rendering `<App />` here made a live fetch for `/api/tools` in every test.
  mockApi.tools.mockResolvedValue({ tools: [], groups: {} });
});

describe('Dashboard image filter', () => {
  it('narrows the list to images matching the query', async () => {
    mockApi.listImages.mockResolvedValue([image('a', 'router-v1.bin', 'mips'), image('b', 'camera.img', 'arm')]);
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Dashboard />
      </MemoryRouter>,
    );
    await screen.findByText('router-v1.bin');
    expect(screen.getByText('camera.img')).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText(/Filter by filename/i), { target: { value: 'camera' } });
    expect(screen.queryByText('router-v1.bin')).not.toBeInTheDocument();
    expect(screen.getByText('camera.img')).toBeInTheDocument();
  });
});

describe('Dashboard coverage column', () => {
  // Without this, an image nothing has ever analyzed and a fully-scanned one render identically in the listing —
  // the same conflation the per-image coverage banner exists to prevent, reintroduced at corpus scale.
  it('distinguishes an unexamined image from a scanned one, and totals the unexamined', async () => {
    mockApi.listImages.mockResolvedValue([image('a', 'router-v1.bin', 'mips'), image('b', 'camera.img', 'arm')]);
    mockApi.coverageAll.mockResolvedValue([coverage('a', 0, 12), coverage('b', 12, 12)]);
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Dashboard />
      </MemoryRouter>,
    );
    expect(await screen.findByText('unexamined')).toBeInTheDocument();
    expect(screen.getByText('12/12 stages')).toBeInTheDocument();
    expect(screen.getByText('1 of 2 unexamined')).toBeInTheDocument();
  });

  it('says nothing about coverage rather than implying it when the corpus report is unavailable', async () => {
    mockApi.listImages.mockResolvedValue([image('a', 'router-v1.bin', 'mips')]);
    mockApi.coverageAll.mockRejectedValue(new Error('offline'));
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Dashboard />
      </MemoryRouter>,
    );
    await screen.findByText('router-v1.bin');
    expect(screen.queryByText(/unexamined/)).not.toBeInTheDocument();
  });
});

describe('App shell', () => {
  it('shows the auth-gated health pill and toggles the mobile drawer', async () => {
    const { container } = render(<App />);
    expect(await screen.findByText(/auth-gated/i)).toBeInTheDocument();

    const shell = container.querySelector('.app-shell');
    expect(shell?.className).not.toContain('nav-open');
    fireEvent.click(screen.getByLabelText('Toggle navigation'));
    expect(shell?.className).toContain('nav-open');
  });

  // The router opts into the v7 future flags, and `v7_startTransition` is the one with teeth: it marks router
  // state updates non-urgent, so a route change is no longer guaranteed to be on screen by the time the click
  // returns. Nothing else here navigates through the REAL HashRouter, which left the opt-in resting on a
  // suite that never exercised the behaviour it changes. Asserting asynchronously is not a workaround for a
  // flaky test — deferred arrival is precisely the contract, and this proves the destination still arrives.
  it('navigates between routes under the v7 startTransition opt-in', async () => {
    mockApi.listImages.mockResolvedValue([image('a', 'router-v1.bin', 'mips')]);
    render(<App />);
    await screen.findByText(/auth-gated/i);

    // The destination is identified by the filter box, which only Dashboard renders. The obvious assertion —
    // that the image filename appears — is worthless here: Overview lists filenames too, so it holds on the
    // ORIGIN route and the test would pass with the router torn out entirely.
    expect(screen.queryByPlaceholderText(/Filter by filename/i)).not.toBeInTheDocument();

    // Scoped to the sidebar on purpose: the Overview page links to the same destination, so an unscoped
    // query matches two links and the failure reads as ambiguity rather than as the routing fact under test.
    const sidebarLink = screen
      .getAllByRole('link', { name: /Local analysis/i })
      .find((a) => a.className.includes('nav-item'));
    if (!sidebarLink) throw new Error('the sidebar has no Local analysis link');
    fireEvent.click(sidebarLink);

    expect(await screen.findByPlaceholderText(/Filter by filename/i)).toBeInTheDocument();
  });
});

/**
 * The brand mark's easter egg. Nothing here checks that it looks nice — that is what eyes are for. What is worth
 * pinning is the three ways a decorative flourish in an always-visible shell turns into a defect.
 */
describe('the brand mark', () => {
  /** jsdom implements neither, so the component is exercised through stubs it can actually be asked about. */
  const setup = (reducedMotion: boolean) => {
    const animate = vi.fn(() => ({
      cancel: vi.fn(),
      finished: Promise.resolve(),
    })) as unknown as Element['animate'];
    Element.prototype.animate = animate;
    vi.stubGlobal('matchMedia', (q: string) => ({
      matches: reducedMotion && q.includes('reduce'),
      media: q,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }));
    return animate as unknown as ReturnType<typeof vi.fn>;
  };

  const markOf = (c: HTMLElement): HTMLElement => {
    const el = c.querySelector('.brand-mark');
    if (!(el instanceof HTMLElement)) throw new Error('the sidebar has no brand mark');
    return el;
  };

  it('is hidden from assistive tech and out of the tab order — it does nothing, so it announces nothing', () => {
    mockApi.listImages.mockResolvedValue([]);
    const { container } = render(<App />);
    const mark = markOf(container);
    expect(mark.getAttribute('aria-hidden')).toBe('true');
    expect(mark.getAttribute('tabindex')).toBe('-1');
    // And the image inside carries no alt: "FirmLab" is already the heading beside it, and a described mark
    // would be read out twice.
    expect(mark.querySelector('img')?.getAttribute('alt')).toBe('');
  });

  it('plays on click', () => {
    const animate = setup(false);
    mockApi.listImages.mockResolvedValue([]);
    const { container } = render(<App />);
    fireEvent.click(markOf(container));
    // The tumble plus one animation per heart.
    expect(animate.mock.calls.length).toBeGreaterThan(1);
  });

  it('plays NOTHING under prefers-reduced-motion', () => {
    // The press feedback survives, in CSS, because that is a response rather than decoration — but no element
    // here may be set in motion by script when the reader has asked for none.
    const animate = setup(true);
    mockApi.listImages.mockResolvedValue([]);
    const { container } = render(<App />);
    fireEvent.click(markOf(container));
    expect(animate).not.toHaveBeenCalled();
  });

  it('leaves no hearts behind in the DOM after a click', async () => {
    // They are appended to the button and removed when they finish. A leak here would grow the shell's DOM for
    // every click, forever, on the one element that is on screen all day.
    const animate = setup(false);
    mockApi.listImages.mockResolvedValue([]);
    const { container } = render(<App />);
    const mark = markOf(container);
    fireEvent.click(mark);
    expect(animate).toHaveBeenCalled();
    // `waitFor`, not one microtask: the cleanup hangs off `finished.catch().finally()`, which is two chained
    // promises deep. A single tick asserts before the removal and passes for the wrong reason.
    await waitFor(() => expect(mark.querySelectorAll('.brand-heart')).toHaveLength(0));
  });
});
