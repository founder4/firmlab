/**
 * Emulation rungs 2 and 3 — the deeper, service-level bring-up that a static workbench doesn't reach, made
 * into deterministic providers (the fix for the parent platform's #1 fragility: hand-driven emulation that
 * hangs). The agent (later) only picks a rung and reads the result; the mechanics live here.
 *
 *   rung-2 "chroot service"  → start a network daemon under qemu-user in the rootfs with the libnvram shim.
 *   rung-3 "full-system"     → boot the rootfs under qemu-system + a firmadyne kernel.
 *
 * Two invariants, always:
 *   1. Teardown is GUARANTEED (a stray qemu httpd is what stalls a whole run) — every runner pkills its
 *      emulators in a finally, whatever happened.
 *   2. Honesty — proof is capped by what actually ran: `confirmed_in_emulation` (rung-2) / `confirmed_full_system`
 *      (rung-3) on success; `blocked_by_platform` when the required assets/tools aren't present. qemu output is
 *      never inflated to device compromise.
 *
 * These rungs need the opt-in assets baked by Dockerfile.firmware (libnvram + firmadyne kernels). Without them
 * the runners return a blocked result rather than attempting a half-baked bring-up.
 */
import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import { promisify } from 'node:util';
import type { Architecture, ProofState } from '@firmlab/core';
import { detectTools } from '../tools.js';
import type { JobHandle } from './jobs.js';
import { readPortMap } from './portmap-run.js';
import { type PortProtocol, planForwards } from './portmap.js';
import {
  FIRMADYNE_KERNELS_DIR,
  LIBNVRAM_DIR,
  QEMU_MACHINE_BY_ARCH,
  QEMU_SYSTEM_BY_ARCH,
  QEMU_USER_BY_ARCH,
} from './preflight.js';

const execFileAsync = promisify(execFile);

/** How long to hold the box open waiting for the guest to come up, and how often to knock on its ports. */
const BOOT_TIMEOUT_MS = 120_000;
const PROBE_INTERVAL_MS = 2000;
/** Console output kept per stream. A chatty boot must not be able to grow this without bound. */
const CONSOLE_CAP = 256 * 1024;

export interface SystemEmulationResult {
  ran: boolean;
  strategy: 'chroot-service' | 'full-system';
  proofState: ProofState;
  reason: string;
  command: string;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** The host→guest forwards this run actually set up, so a reader can see what WAS reachable. */
  forwards?: { host: number; guest: number; protocol: PortProtocol }[];
  /** Of those, the ones that accepted a TCP connection. Empty is a real, readable result. */
  open?: { host: number; guest: number }[];
}

// === Pure command builders (unit-tested; no I/O) ===

/** The libnvram shim path for an arch, both on the host (asset check) and inside the chroot (copied in). */
export function libnvramHostPath(arch: Architecture): string {
  return `${LIBNVRAM_DIR}/libnvram-${arch}.so`;
}

/**
 * rung-2 argv: run the service under qemu-user inside the rootfs chroot, preloading the NVRAM shim. cwd is the
 * rootfs; the qemu-static binary and the shim are copied to the rootfs root first (see runChrootService).
 */
export function buildChrootServiceArgs(qemuStaticName: string, service: string): string[] {
  const svc = `/${service.replace(/^\/+/, '')}`;
  return ['.', `/${qemuStaticName}`, '-E', 'LD_PRELOAD=/libnvram.so', svc];
}

/**
 * rung-3 argv: boot the rootfs under qemu-system with a firmadyne kernel, forwarding every port the firmware
 * declares rather than the one this file used to assume.
 *
 * It was `hostfwd=tcp::8080-:80`, a single forward with the guest side hardcoded. On the GL.iNet BE3600 that
 * reaches the HTTP listener and nothing else, while the image's own `/etc/config/uhttpd` also declares
 * `listen_https 0.0.0.0:443` and `/etc/config/dropbear` declares `Port '22'` — an entire remote surface left
 * unreachable inside a rung called `confirmed_full_system`. `-netdev user` accepts repeated `hostfwd`, so the
 * cost of forwarding what the firmware actually asks for is nil; the work was knowing what to ask for.
 */
export function buildFullSystemArgs(
  machine: string,
  kernelPath: string,
  rootfsImage: string,
  forwards: { host: number; guest: number }[],
): string[] {
  const fwd = forwards.map((f) => `hostfwd=tcp::${f.host}-:${f.guest}`).join(',');
  return [
    '-M',
    machine,
    '-kernel',
    kernelPath,
    // `-nodefaults` and an explicit serial are not tidiness — without them qemu instantiates its default VGA and
    // dies with `failed to find romfile "vgabios-cirrus.bin"` before executing a single guest instruction, which
    // is what this deployment did every time. A headless firmware boot wants no display at all, and the console
    // has to be a serial we can read: the whole boot verdict is drawn from what this stream prints.
    '-nodefaults',
    '-serial',
    'mon:stdio',
    '-append',
    'console=ttyS0 root=/dev/sda rootfstype=ext2 rw',
    '-drive',
    `file=${rootfsImage},format=raw`,
    '-netdev',
    `user,id=n0${fwd ? `,${fwd}` : ''}`,
    '-device',
    'e1000,netdev=n0',
    '-nographic',
  ];
}

/**
 * Pure: does the serial output show a kernel that actually came up?
 *
 * Needed because the previous verdict was drawn from a timeout: qemu still running after 120 s returned
 * `confirmed_full_system` with "booted and stayed up", and a kernel panic that hangs produces exactly the same
 * observation. The sibling provider already does this properly — `renode.ts` decides `booted` from real UART
 * captures — and this is the same discipline applied to qemu's console.
 *
 * Markers are deliberately drawn from what a Linux boot prints on the way up, and a panic is treated as evidence
 * AGAINST rather than merely as an absence.
 */
export function looksBooted(consoleOutput: string): { booted: boolean; marker: string | null; panicked: boolean } {
  const panic = /Kernel panic - not syncing|Attempted to kill init|VFS: Unable to mount root/i.exec(consoleOutput);
  if (panic) return { booted: false, marker: panic[0], panicked: true };
  const markers = [
    /Freeing unused kernel memory/i,
    /Please press Enter to activate this console/i,
    /init started:/i,
    /Starting kernel/i,
    /BusyBox v[\d.]+/i,
    /\blogin:\s*$/im,
  ];
  for (const re of markers) {
    const m = re.exec(consoleOutput);
    if (m) return { booted: true, marker: m[0].trim(), panicked: false };
  }
  return { booted: false, marker: null, panicked: false };
}

/**
 * Pure: the verdict for a full-system run, given what was actually observed.
 *
 * The ordering is the claim ladder. A port that accepted a TCP connection is the strongest evidence available
 * here — something inside the guest is serving — and it is the only observation that makes the forwarded surface
 * meaningful. A kernel that printed its way up is real but weaker: the system booted, its services may not have.
 * Everything else refuses `confirmed_full_system`, because "the process did not exit" is not a boot.
 */
export function classifyFullSystem(
  open: { host: number; guest: number }[],
  console: { booted: boolean; marker: string | null; panicked: boolean },
  timedOut: boolean,
): { proofState: ProofState; reason: string } {
  if (open.length > 0) {
    const list = open.map((p) => `guest ${p.guest}`).join(', ');
    return {
      proofState: 'confirmed_full_system',
      reason: `The system booted and answered TCP on ${list}. A service inside the guest accepted a connection, which is what makes this rung a full-system result rather than a process that stayed alive.`,
    };
  }
  if (console.panicked) {
    return {
      proofState: 'blocked_by_platform',
      reason: `The guest kernel panicked (${console.marker}), so nothing about the firmware was exercised. This is the emulation failing to bring the image up — not a result about the firmware, and not evidence it is sound.`,
    };
  }
  if (console.booted) {
    return {
      proofState: 'confirmed_full_system',
      reason: `The kernel booted (${console.marker}) but no forwarded port accepted a connection. The system came up; its network services did not, or they listen somewhere this run did not forward.`,
    };
  }
  return {
    proofState: 'needs_runtime_reproduction',
    reason: timedOut
      ? 'The emulator ran to the time box without printing a recognisable boot and without any forwarded port answering. That it did not exit is NOT a boot: a hung kernel looks the same from outside.'
      : 'The emulator exited without printing a recognisable boot and without any forwarded port answering.',
  };
}

/** The mandatory teardown: kill every emulator this provider could have spawned. */
export const TEARDOWN_PATTERNS = ['qemu-system-', 'qemu-mipsel-static', 'qemu-arm-static', 'qemu-aarch64-static'];

// === Runners (asset-gated; guaranteed teardown) ===

async function toolAvailable(id: string): Promise<boolean> {
  const tools = await detectTools();
  return tools.find((t) => t.id === id)?.available ?? false;
}

/** Best-effort kill of any emulator left running — the invariant that keeps a hung qemu from stalling the run. */
async function teardown(handle: JobHandle): Promise<void> {
  for (const pat of TEARDOWN_PATTERNS) {
    try {
      await execFileAsync('pkill', ['-f', pat], { timeout: 5000 });
    } catch {
      // pkill exits non-zero when nothing matched — that's the normal case, not an error.
    }
  }
  handle.log('Teardown complete (emulators killed).');
}

function blocked(strategy: SystemEmulationResult['strategy'], reason: string, command = ''): SystemEmulationResult {
  return {
    ran: false,
    strategy,
    proofState: 'blocked_by_platform',
    reason,
    command,
    stdout: '',
    stderr: '',
    timedOut: false,
  };
}

/**
 * rung-2: start a network service in a chroot with the NVRAM shim, bounded by a timeout, then always tear down.
 * Returns a blocked result if the arch has no qemu-user emulator installed or the libnvram asset is absent.
 */
export async function runChrootService(
  arch: Architecture,
  rootfsPath: string,
  service: string,
  handle: JobHandle,
): Promise<SystemEmulationResult> {
  const qemu = QEMU_USER_BY_ARCH[arch];
  if (!qemu || !(await toolAvailable(qemu))) {
    return blocked('chroot-service', `No qemu-user emulator for arch "${arch}" in this deployment.`);
  }
  if (!fs.existsSync(libnvramHostPath(arch))) {
    return blocked(
      'chroot-service',
      `libnvram shim missing (${libnvramHostPath(arch)}); enable it in Dockerfile.firmware to run rung-2.`,
    );
  }

  const qemuStaticName = `qemu-${arch}-static-firmlab`;
  const args = buildChrootServiceArgs(qemuStaticName, service);
  const command = `chroot ${args.join(' ')}`;
  handle.log(`Preparing chroot bring-up for ${service}`);
  try {
    // Stage the emulator + shim inside the rootfs so they resolve under chroot.
    fs.copyFileSync(`/usr/bin/${qemu}`, `${rootfsPath}/${qemuStaticName}`);
    fs.copyFileSync(libnvramHostPath(arch), `${rootfsPath}/libnvram.so`);
    handle.log(`Executing: ${command}`);
    const { stdout, stderr } = await execFileAsync('chroot', args, {
      cwd: rootfsPath,
      timeout: 30_000,
      maxBuffer: 4 * 1024 * 1024,
      killSignal: 'SIGKILL',
    });
    return {
      ran: true,
      strategy: 'chroot-service',
      proofState: 'confirmed_in_emulation',
      reason: 'Service started under qemu-user chroot with NVRAM shim.',
      command,
      stdout,
      stderr,
      timedOut: false,
    };
  } catch (err) {
    const e = err as { killed?: boolean; signal?: string; stdout?: string; stderr?: string };
    const timedOut = e.killed === true && e.signal === 'SIGKILL';
    // A daemon that keeps running until SIGKILL is the expected success shape for a long-lived service.
    return {
      ran: true,
      strategy: 'chroot-service',
      proofState: timedOut ? 'confirmed_in_emulation' : 'needs_runtime_reproduction',
      reason: timedOut ? 'Service ran until the timeout (long-lived daemon).' : 'Service exited early.',
      command,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
      timedOut,
    };
  } finally {
    await teardown(handle);
    try {
      fs.rmSync(`${rootfsPath}/${qemuStaticName}`, { force: true });
      fs.rmSync(`${rootfsPath}/libnvram.so`, { force: true });
    } catch {
      // Best-effort cleanup of the staged files.
    }
  }
}

/**
 * rung-3: boot the rootfs image under qemu-system + a firmadyne kernel, bounded by a timeout, always tearing
 * down. Returns blocked if the system emulator or the kernel assets are absent.
 */
export async function runFullSystem(
  arch: Architecture,
  rootfsImage: string,
  hostPort: number,
  handle: JobHandle,
  /**
   * The extracted rootfs DIRECTORY, read for the ports the firmware declares. Optional so an existing caller that
   * only has the disk image still works — it then falls back to forwarding port 80 alone, which is exactly the old
   * behaviour, stated rather than assumed.
   */
  rootfsDir?: string | null,
): Promise<SystemEmulationResult> {
  const qemu = QEMU_SYSTEM_BY_ARCH[arch];
  const machine = QEMU_MACHINE_BY_ARCH[arch];
  if (!qemu || !machine || !(await toolAvailable(qemu))) {
    return blocked('full-system', `No qemu-system emulator/machine for arch "${arch}" in this deployment.`);
  }
  if (!fs.existsSync(FIRMADYNE_KERNELS_DIR)) {
    return blocked(
      'full-system',
      `firmadyne kernels missing (${FIRMADYNE_KERNELS_DIR}); enable them in Dockerfile.firmware to run rung-3.`,
    );
  }
  const kernelPath = `${FIRMADYNE_KERNELS_DIR}/vmlinux.${arch}.4`;
  if (!fs.existsSync(kernelPath)) {
    return blocked('full-system', `No firmadyne kernel for arch "${arch}" at ${kernelPath}.`);
  }

  // What the firmware itself says it will serve. Read before boot, so the forwards match the image rather than
  // an assumption about it.
  const portMap = readPortMap(rootfsDir ?? null);
  const forwards = planForwards(portMap, hostPort);
  handle.log(portMap.reason);
  handle.log(`Forwarding ${forwards.map((f) => `host ${f.host} → guest ${f.guest}/${f.protocol}`).join(', ')}.`);

  const args = buildFullSystemArgs(machine, kernelPath, rootfsImage, forwards);
  const command = `${qemu} ${args.join(' ')}`;
  handle.log(`Executing: ${command}`);

  // Spawned rather than exec'd to completion: the previous version could only look at the run AFTER it ended,
  // which is why "did not exit" became the boot verdict. Watching it while it runs is what makes a TCP probe —
  // and therefore an evidenced answer — possible at all.
  const proc = spawn(qemu, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  const cap = (chunk: Buffer, which: 'o' | 'e'): void => {
    const s = chunk.toString('utf8');
    if (which === 'o') stdout = (stdout + s).slice(-CONSOLE_CAP);
    else stderr = (stderr + s).slice(-CONSOLE_CAP);
  };
  proc.stdout?.on('data', (c: Buffer) => cap(c, 'o'));
  proc.stderr?.on('data', (c: Buffer) => cap(c, 'e'));
  proc.on('error', () => undefined);

  let exited = false;
  proc.on('exit', () => {
    exited = true;
  });

  const open: { host: number; guest: number }[] = [];
  const deadline = Date.now() + BOOT_TIMEOUT_MS;
  try {
    while (Date.now() < deadline && !exited) {
      await new Promise((r) => setTimeout(r, PROBE_INTERVAL_MS));
      for (const f of forwards) {
        if (open.some((o) => o.host === f.host)) continue;
        if (await tcpAccepts(f.host)) {
          open.push({ host: f.host, guest: f.guest });
          handle.log(`  guest port ${f.guest} answered on host ${f.host} — a service inside the guest is up.`);
        }
      }
      // Every declared port answering is as much as this rung can establish; no reason to hold the box open.
      if (open.length === forwards.length) break;
    }
    const timedOut = !exited;
    const consoleState = looksBooted(`${stdout}\n${stderr}`);
    const { proofState, reason } = classifyFullSystem(open, consoleState, timedOut);
    handle.log(reason);
    if (open.length === 0 && portMap.declared.length > 0) {
      handle.log(
        `Declared but silent: ${portMap.declared.map((h) => `${h.port}/${h.protocol}`).join(', ')}. A port the firmware declares and no booted service answers is a gap worth reading, not a parse error.`,
      );
    }
    return {
      ran: true,
      strategy: 'full-system',
      proofState,
      reason,
      command,
      stdout,
      stderr,
      timedOut,
      forwards,
      open,
    };
  } finally {
    try {
      proc.kill('SIGKILL');
    } catch {}
    await teardown(handle);
  }
}

/** Does anything accept a TCP connection on this host port? The one observation that proves a service is up. */
async function tcpAccepts(port: number, timeoutMs = 1200): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    const done = (ok: boolean): void => {
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => done(true));
    sock.once('timeout', () => done(false));
    sock.once('error', () => done(false));
    sock.connect(port, '127.0.0.1');
  });
}
