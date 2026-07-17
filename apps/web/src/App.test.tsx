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
    },
  };
});

const mockApi = api as unknown as {
  health: ReturnType<typeof vi.fn>;
  listImages: ReturnType<typeof vi.fn>;
  storage: ReturnType<typeof vi.fn>;
};

const image = (id: string, filename: string, arch: string) => ({
  id,
  filename,
  size: 1024,
  sha256: 'deadbeef',
  uploadedAt: 1,
  status: 'ready' as const,
  identity: { firmwareClass: 'embedded-linux', arch, endianness: 'little', filesystems: ['squashfs'] },
});

const emptyUsage = { imageCount: 0, imagesBytes: 0, extractsBytes: 0, totalBytes: 0, quotaBytes: 0, maxAgeDays: 0 };

beforeEach(() => {
  mockApi.health.mockResolvedValue({ status: 'ok', exposedToNetwork: true, trustedProxy: true });
  mockApi.listImages.mockResolvedValue([]);
  mockApi.storage.mockResolvedValue(emptyUsage);
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
