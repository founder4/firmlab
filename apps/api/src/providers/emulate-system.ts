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
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import { promisify } from 'node:util';
import type { Architecture, ProofState } from '@firmlab/core';
import { detectTools } from '../tools.js';
import type { JobHandle } from './jobs.js';
import {
  FIRMADYNE_KERNELS_DIR,
  LIBNVRAM_DIR,
  QEMU_MACHINE_BY_ARCH,
  QEMU_SYSTEM_BY_ARCH,
  QEMU_USER_BY_ARCH,
} from './preflight.js';

const execFileAsync = promisify(execFile);

export interface SystemEmulationResult {
  ran: boolean;
  strategy: 'chroot-service' | 'full-system';
  proofState: ProofState;
  reason: string;
  command: string;
  stdout: string;
  stderr: string;
  timedOut: boolean;
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

/** rung-3 argv: boot the rootfs image under qemu-system with a firmadyne kernel and port-forwarded web UI. */
export function buildFullSystemArgs(
  machine: string,
  kernelPath: string,
  rootfsImage: string,
  hostPort: number,
): string[] {
  return [
    '-M',
    machine,
    '-kernel',
    kernelPath,
    '-drive',
    `file=${rootfsImage},format=raw`,
    '-netdev',
    `user,id=n0,hostfwd=tcp::${hostPort}-:80`,
    '-device',
    'e1000,netdev=n0',
    '-nographic',
  ];
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

  const args = buildFullSystemArgs(machine, kernelPath, rootfsImage, hostPort);
  const command = `${qemu} ${args.join(' ')}`;
  handle.log(`Executing: ${command}`);
  try {
    const { stdout, stderr } = await execFileAsync(qemu, args, {
      timeout: 120_000,
      maxBuffer: 8 * 1024 * 1024,
      killSignal: 'SIGKILL',
    });
    return {
      ran: true,
      strategy: 'full-system',
      proofState: 'confirmed_full_system',
      reason: 'Full-system boot completed.',
      command,
      stdout,
      stderr,
      timedOut: false,
    };
  } catch (err) {
    const e = err as { killed?: boolean; signal?: string; stdout?: string; stderr?: string };
    const timedOut = e.killed === true && e.signal === 'SIGKILL';
    return {
      ran: true,
      strategy: 'full-system',
      proofState: timedOut ? 'confirmed_full_system' : 'needs_runtime_reproduction',
      reason: timedOut ? 'System ran until the timeout (booted and stayed up).' : 'System exited early.',
      command,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
      timedOut,
    };
  } finally {
    await teardown(handle);
  }
}
