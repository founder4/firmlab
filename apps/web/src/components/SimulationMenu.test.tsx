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

  /**
   * The Secure Boot posture, and its absence.
   *
   * `unknown` beside a badge that says nothing else reads as a measurement, and `secureBoot: null` rendered as
   * blank space reads as "this image has no variable store" — which is the one conclusion none of the three
   * situations behind that null supports. Both sentences exist in the provider; neither reached the screen.
   */
  const chipsecResult = (o: Record<string, unknown>) => ({
    id: 'j1',
    status: 'done',
    log: '',
    result: {
      available: true,
      ran: true,
      reason: 'Decoded 1 firmware volume offline with chipsec.',
      proofState: 'static_confirmed',
      volumes: 1,
      moduleCount: 4,
      byType: {},
      modules: [],
      findings: [],
      command: 'chipsec_util uefi decode image.fd',
      ...o,
    },
  });
  const uefiMenu = () =>
    menu({
      identity: { firmwareClass: 'uefi-bios', arch: 'x86_64', endianness: 'little', filesystems: [] },
      recipes: [recipe({ mode: 'uefi-chipsec', title: 'chipsec UEFI decode' })],
    });

  it('prints the provider’s sentence beside an unknown Secure Boot state', async () => {
    mockApi.emulation.mockResolvedValue(uefiMenu());
    mockApi.job.mockResolvedValue(
      chipsecResult({
        secureBoot: {
          variableCount: 7,
          secureBoot: 'unknown',
          setupMode: 'unknown',
          customMode: 'unknown',
          hasPK: false,
          hasKEK: false,
          hasDb: false,
          hasDbx: false,
          testKey: null,
          variables: [],
          note: '7 variable(s) were read from this store and SecureBoot was not among them, so the state is not something this decode can say — it is NOT a platform with Secure Boot off.',
        },
      }),
    );
    render(<SimulationMenu imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Decode & scan' }));
    expect(await screen.findByText(/NOT a platform with Secure Boot off/)).toBeInTheDocument();
  });

  it('says WHY there is no posture instead of leaving the section blank', async () => {
    mockApi.emulation.mockResolvedValue(uefiMenu());
    mockApi.job.mockResolvedValue(
      chipsecResult({
        secureBoot: null,
        nvramStoreNote:
          'chipsec wrote 2 NVRAM listing(s) for this image and none of them parsed into a single variable.',
      }),
    );
    render(<SimulationMenu imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Decode & scan' }));
    expect(await screen.findByText(/none of them parsed into a single variable/)).toBeInTheDocument();
    // The heading comes with it, so the sentence is anchored to what it is about.
    expect(screen.getByText('Secure Boot:')).toBeInTheDocument();
  });

  it('stays silent for a decode stored before either sentence existed', async () => {
    // Optional forever: an older stored ChipsecResult has neither field, and inventing a line here would assert
    // a limitation that build never measured.
    mockApi.emulation.mockResolvedValue(uefiMenu());
    mockApi.job.mockResolvedValue(chipsecResult({ secureBoot: null }));
    render(<SimulationMenu imageId="img1" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Decode & scan' }));
    expect(await screen.findByText('4 modules')).toBeInTheDocument();
    expect(screen.queryByText('Secure Boot:')).not.toBeInTheDocument();
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

  const emptyEgress = {
    attempts: [],
    dnsQueries: [],
    dnsTruncated: 0,
    guestFrames: 0,
    truncated: false,
    problem: '',
  };

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

  it('says the frames it kept OUT of the list, so the bench’s own probes are not read as intent', async () => {
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue(detail({ isolated: true, egress: { ...emptyEgress, answeredFrames: 150 } }));
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText(/150 frames were this guest ANSWERING/)).toBeInTheDocument();
  });

  it('bounds the printed list and states what the bound cut, by frames and not by arrival', async () => {
    const many = Array.from({ length: 60 }, (_, i) => ({
      address: `203.0.113.${i + 1}`,
      protocol: 'tcp' as const,
      port: 80,
      scope: 'external' as const,
      frames: 60 - i,
    }));
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue(
      detail({ isolated: true, egress: { ...emptyEgress, attempts: many, attemptsDropped: 7 } }),
    );
    render(<SimulationMenu imageId="img1" />);
    // The most-addressed is printed, the least-addressed is not, and the page says so rather than just ending.
    expect(await screen.findByText('203.0.113.1:80')).toBeInTheDocument();
    expect(screen.queryByText('203.0.113.60:80')).not.toBeInTheDocument();
    expect(screen.getByText(/Showing the 40 most-addressed of 60/)).toBeInTheDocument();
    // And the cap the PARSER applied, which is a different loss and is stated separately.
    expect(screen.getByText(/7 further destinations went past this run's limit/)).toBeInTheDocument();
  });

  it('shows none of those sentences for a run stored before the counters existed', async () => {
    // Optional forever: an older stored egress carries no `answeredFrames`, and `0` and `absent` must both be
    // silent — a "0 frames were answers" line would assert a measurement that build never made.
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue(detail({ isolated: true }));
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText('128.138.140.44:123')).toBeInTheDocument();
    expect(screen.queryByText(/ANSWERING/)).not.toBeInTheDocument();
    expect(screen.queryByText(/went past this run's limit/)).not.toBeInTheDocument();
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

/**
 * The daemon list.
 *
 * `boot-diagnose` has always collected both lists and the panel read neither, so the two facts the module exists
 * to separate — "no network daemon was ever executed" and "one started and took SIGSEGV" — reached the screen as
 * the same empty space. These tests are written against that: each case asserts what the OTHER case must not say.
 */
describe('SimulationMenu — which daemons the boot saw', () => {
  const ledger = { runs: [{ jobId: 'j9', kind: 'emulate', status: 'done' }], byTarget: [] };
  const withDiagnosis = (unreachable: Record<string, unknown>) => ({
    summary: ledger.runs[0],
    params: {},
    log: '',
    error: null,
    result: { unreachable },
  });

  it('names the crash with its signal AND the file it died on', async () => {
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue(
      withDiagnosis({
        cause: 'service-died',
        summary: 'httpd died',
        evidence: [],
        daemonsStarted: ['httpd'],
        daemonsExited: [
          { binary: 'httpd', pid: '103', code: 139, signal: 11, lastOpen: '/proc/simple_config/system_mode' },
        ],
      }),
    );
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText('httpd')).toBeInTheDocument();
    // 139 alone means nothing; SIGSEGV means everything. Both are printed.
    expect(screen.getByText('SIGSEGV (exit 139)')).toBeInTheDocument();
    expect(screen.getByText(/\/proc\/simple_config\/system_mode/)).toBeInTheDocument();
    expect(screen.queryByText(/No network daemon was ever executed/i)).not.toBeInTheDocument();
  });

  it('separates "never started" from "started and died" — the claim the module exists for', async () => {
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue(
      withDiagnosis({
        cause: 'no-service-started',
        summary: 'nothing came up',
        evidence: [],
        daemonsStarted: [],
        daemonsExited: [],
      }),
    );
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText(/nothing died, nothing was started/i)).toBeInTheDocument();
  });

  it('lists a daemon that started and did NOT exit as running, not as missing', async () => {
    // The WR940N: httpd is provably still serving and the SYNs vanish anyway. Listing it is what stops a reader
    // concluding "no service" from an empty `open`.
    mockApi.runs.mockResolvedValue(ledger);
    mockApi.runDetail.mockResolvedValue(
      withDiagnosis({
        cause: 'guest-dropped',
        summary: '158 SYNs, no answer',
        evidence: [],
        daemonsStarted: ['httpd', 'telnetd'],
        daemonsExited: [{ binary: 'telnetd', pid: '5', code: 1, signal: null, lastOpen: null }],
      }),
    );
    render(<SimulationMenu imageId="img1" />);
    expect(await screen.findByText('started, did not exit')).toBeInTheDocument();
    // An ordinary status is reported as an exit, never dressed up as a crash.
    expect(screen.getByText('exited 1')).toBeInTheDocument();
    expect(screen.queryByText(/SIG/)).not.toBeInTheDocument();
  });
});
