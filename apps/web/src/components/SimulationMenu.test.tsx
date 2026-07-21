import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { SimulationMenu } from './SimulationMenu';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  return {
    ...actual,
    api: {
      ...actual.api,
      emulation: vi.fn(),
      job: vi.fn(),
      emulate: vi.fn(),
      emulateSystem: vi.fn(),
      runRenode: vi.fn(),
      extract: vi.fn(),
    },
  };
});

const mockApi = api as unknown as Record<
  'emulation' | 'job' | 'emulate' | 'emulateSystem' | 'runRenode' | 'extract',
  ReturnType<typeof vi.fn>
>;

const identity = { firmwareClass: 'embedded-linux', arch: 'mips', endianness: 'big', filesystems: ['squashfs'] };
type Recipe = {
  id: string;
  mode: 'user-qemu' | 'chroot-qemu' | 'system-qemu' | 'renode';
  title: string;
  description: string;
  requires: string[];
  runnable: boolean;
  command: string;
  rank: number;
};
const recipe = (o: Partial<Recipe> & { mode: Recipe['mode'] }): Recipe => ({
  id: o.id ?? o.mode,
  title: 'Recipe',
  description: 'What it does',
  requires: [],
  runnable: true,
  command: 'qemu-mipsel-static -L rootfs rootfs/bin/x',
  rank: 1,
  ...o,
});
const menu = (o: Record<string, unknown> = {}) => ({
  identity,
  rootfsReady: true,
  suggestedBinary: 'bin/busybox',
  recipes: [recipe({ mode: 'user-qemu', title: 'User-mode QEMU' })],
  capabilities: null,
  ...o,
});

beforeEach(() => {
  mockApi.emulation.mockResolvedValue(menu());
  mockApi.job.mockResolvedValue({ id: 'j1', status: 'done', result: null, log: '' });
  mockApi.emulate.mockResolvedValue({ jobId: 'j1' });
  mockApi.emulateSystem.mockResolvedValue({ jobId: 'j1' });
  mockApi.runRenode.mockResolvedValue({ jobId: 'j1' });
  mockApi.extract.mockResolvedValue({ jobId: 'j1' });
});

describe('SimulationMenu', () => {
  it('shows a loading state until the emulation plan arrives', () => {
    mockApi.emulation.mockReturnValueOnce(new Promise(() => {})); // never resolves
    render(<SimulationMenu imageId="img1" />);
    expect(screen.getByText(/Loading emulation plan/i)).toBeInTheDocument();
  });

  it('is honest per rung: a runnable recipe gets a run button, a non-runnable one does not', async () => {
    mockApi.emulation.mockResolvedValue(
      menu({
        recipes: [
          recipe({ mode: 'user-qemu', title: 'User-mode QEMU', runnable: true }),
          recipe({ mode: 'renode', title: 'Renode RTOS', runnable: false }),
        ],
      }),
    );
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText('User-mode QEMU')).toBeInTheDocument();
    expect(screen.getByText('Renode RTOS')).toBeInTheDocument();
    expect(screen.getByText('needs tools')).toBeInTheDocument(); // the non-runnable rung
    expect(screen.getByRole('button', { name: 'Run proof' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Boot under Renode' })).not.toBeInTheDocument();
  });

  it('prompts to extract a rootfs first and launches extraction', async () => {
    mockApi.emulation.mockResolvedValue(menu({ rootfsReady: false }));
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText(/needs an extracted rootfs/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Extract now' }));
    await waitFor(() => expect(mockApi.extract).toHaveBeenCalledWith('img1'));
  });

  it('dispatches the RTOS rung to Renode — not the user-mode emulator (guards the split-brain fix)', async () => {
    mockApi.emulation.mockResolvedValue(menu({ recipes: [recipe({ mode: 'renode', title: 'Renode RTOS' })] }));
    render(<SimulationMenu imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Boot under Renode' }));
    await waitFor(() => expect(mockApi.runRenode).toHaveBeenCalledWith('img1'));
    expect(mockApi.emulate).not.toHaveBeenCalled();
  });

  it('runs a user-mode proof against the entered binary', async () => {
    render(<SimulationMenu imageId="img1" />);
    fireEvent.change(await screen.findByPlaceholderText('bin/busybox'), { target: { value: 'sbin/httpd' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run proof' }));
    await waitFor(() => expect(mockApi.emulate).toHaveBeenCalledWith('img1', 'sbin/httpd'));
  });
});
