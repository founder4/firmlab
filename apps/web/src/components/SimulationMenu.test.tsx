import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api';
import { mockedApi } from '../test-api-mock';
import { SimulationMenu } from './SimulationMenu';

// The whole surface, throwing by default. This file is where the omission was found — `binaries` (the target
// selector) was left real and every test here fetched into jsdom — and it was found by luck, so the list is no
// longer hand-written. Anything this file forgets now names itself instead of reaching the network.
vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const identity = { firmwareClass: 'embedded-linux', arch: 'mips', endianness: 'big', filesystems: ['squashfs'] };
type Recipe = {
  id: string;
  mode: 'user-qemu' | 'chroot-qemu' | 'system-qemu' | 'renode' | 'uefi-chipsec';
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
  mockApi.runChipsec.mockResolvedValue({ jobId: 'j1' });
  mockApi.extract.mockResolvedValue({ jobId: 'j1' });
  mockApi.binaries.mockResolvedValue([]);
  // The menu drops a RunHistory under the rungs, which reads the run ledger — the second live fetch this file
  // was making, and the one the hand-written list still missed after `binaries` was fixed.
  mockApi.runs.mockResolvedValue({ runs: [], byTarget: [] });
});

describe('SimulationMenu', () => {
  it('shows a loading state until the emulation plan arrives', async () => {
    mockApi.emulation.mockReturnValueOnce(new Promise(() => {})); // never resolves
    render(<SimulationMenu imageId="img1" />);
    // findBy, not getBy: the binaries effect resolves a microtask later, and awaiting an async query lets
    // that settle inside act. The plan itself never arrives, so the loading state is still what is asserted.
    expect(await screen.findByText(/Loading emulation plan/i)).toBeInTheDocument();
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

  it('dispatches a UEFI image to chipsec and renders its offline decode result (not an emulator)', async () => {
    mockApi.emulation.mockResolvedValue(
      menu({
        identity: { firmwareClass: 'uefi-bios', arch: 'x86_64', endianness: 'little', filesystems: [] },
        recipes: [recipe({ mode: 'uefi-chipsec', title: 'chipsec UEFI decode' })],
      }),
    );
    mockApi.job.mockResolvedValue({
      id: 'j1',
      status: 'done',
      log: '',
      result: {
        available: true,
        ran: true,
        reason: 'Decoded 2 firmware volumes and 130 EFI modules offline with chipsec.',
        proofState: 'static_confirmed',
        volumes: 2,
        moduleCount: 130,
        byType: { DXE_DRIVER: 109, PEIM: 13, APPLICATION: 2 },
        modules: [],
        findings: [
          {
            kind: 'uefi-embedded-app',
            title: '2 UEFI applications embedded in firmware',
            severity: 'info',
            proofState: 'needs_runtime_reproduction',
            evidence: {},
            rationale: 'A planted UEFI app is a bootkit vector — verify each is expected.',
          },
        ],
        command: 'chipsec_util uefi decode image.fd',
      },
    });
    render(<SimulationMenu imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Decode & scan' }));
    await waitFor(() => expect(mockApi.runChipsec).toHaveBeenCalledWith('img1'));
    expect(mockApi.emulate).not.toHaveBeenCalled();
    expect(await screen.findByText('130 modules')).toBeInTheDocument();
    expect(screen.getByText('static_confirmed')).toBeInTheDocument();
    expect(screen.getByText('2 UEFI applications embedded in firmware')).toBeInTheDocument();
  });

  it('runs a user-mode proof against the entered binary', async () => {
    render(<SimulationMenu imageId="img1" />);
    fireEvent.change(await screen.findByPlaceholderText('bin/busybox'), { target: { value: 'sbin/httpd' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run proof' }));
    await waitFor(() => expect(mockApi.emulate).toHaveBeenCalledWith('img1', 'sbin/httpd'));
  });
});

/**
 * Where the booted firmware tried to go.
 *
 * The first version of this panel rendered only inside the running-job block, so the observation existed in the
 * tab that launched the boot and vanished on reload — the defect this project already closed once for twenty
 * per-kind routes, reappearing in a new panel. It reads the run LEDGER on mount now, and these tests are written
 * from that failure: nothing here launches anything.
 */
describe('SimulationMenu — the guest’s egress', () => {
  const ledger = { runs: [{ jobId: 'j9', kind: 'emulate', status: 'done' }], byTarget: [] };
  const detail = (o: Record<string, unknown>) => ({
    summary: ledger.runs[0],
    params: {},
    log: '',
    error: null,
    result: {
      egress: {
        attempts: [
          { address: '128.138.140.44', protocol: 'udp', port: 123, scope: 'external', frames: 1 },
          { address: '10.0.2.3', protocol: 'udp', port: 53, scope: 'emulator', frames: 2 },
        ],
        dnsQueries: [{ name: 'update.tplink.com', server: '10.0.2.3', frames: 2 }],
        dnsTruncated: 0,
        guestFrames: 19,
        truncated: false,
        problem: '',
      },
      ...o,
    },
  });

  it('shows the last finished run’s destinations without anything being launched', async () => {
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue(detail({ isolated: false }));
    render(<SimulationMenu imageId="img1" />);

    // The addresses and the hostname render as they were on the wire — they are measurements, not chrome.
    expect(await screen.findByText('128.138.140.44:123')).toBeInTheDocument();
    expect(screen.getByText('update.tplink.com')).toBeInTheDocument();
    expect(mockApi.emulateSystem).not.toHaveBeenCalled();
  });

  it('warns when the run was NOT isolated, which is the state that lets a firmware reach the internet', async () => {
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue(detail({ isolated: false }));
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText(/could reach these from this machine/i)).toBeInTheDocument();
    expect(screen.getByText('outbound open')).toBeInTheDocument();
  });

  it('says an isolated run reached nothing, and that blocking did not hide the attempt', async () => {
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue(detail({ isolated: true }));
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText(/does not hide the attempt/i)).toBeInTheDocument();
    expect(screen.getByText('outbound blocked')).toBeInTheDocument();
    // The destination is still listed — that is the whole point of the isolated mode.
    expect(screen.getByText('128.138.140.44:123')).toBeInTheDocument();
  });

  it('states that one boot is a floor, because three real boots of one image disagreed', async () => {
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue(detail({ isolated: true }));
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText(/floor and not a total/i)).toBeInTheDocument();
  });

  it('shows nothing at all for a run stored before the observation existed', async () => {
    // Optional forever: an older `emulate` result has no `egress`, and the panel must be absent rather than
    // rendering an empty one that reads as "it tried to reach nothing".
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue({ summary: ledger.runs[0], params: {}, log: '', error: null, result: {} });
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText('User-mode QEMU')).toBeInTheDocument();
    expect(screen.queryByText(/Where it tried to go/i)).not.toBeInTheDocument();
  });
});
