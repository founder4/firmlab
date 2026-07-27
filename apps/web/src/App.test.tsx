import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { api } from './api';
import { Dashboard } from './pages/Dashboard';

vi.mock('./api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./api')>();
  return {
    ...actual,
    api: {
      ...actual.api,
      health: vi.fn(),
      listImages: vi.fn(),
      storage: vi.fn(),
      deleteImage: vi.fn(),
      coverageAll: vi.fn(),
    },
  };
});

const mockApi = api as unknown as {
  health: ReturnType<typeof vi.fn>;
  listImages: ReturnType<typeof vi.fn>;
  storage: ReturnType<typeof vi.fn>;
  coverageAll: ReturnType<typeof vi.fn>;
};

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
});

describe('Dashboard image filter', () => {
  it('narrows the list to images matching the query', async () => {
    mockApi.listImages.mockResolvedValue([image('a', 'router-v1.bin', 'mips'), image('b', 'camera.img', 'arm')]);
    render(
      <MemoryRouter>
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
      <MemoryRouter>
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
      <MemoryRouter>
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
});
