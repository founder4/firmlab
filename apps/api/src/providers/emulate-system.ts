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
import tls from 'node:tls';
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
    // `romfile=` (empty) disables the NIC's PXE option ROM. Without it qemu demands `efi-e1000.rom`, which the
    // Debian qemu packages do not ship, and refuses to start — the third romfile this rung tripped over. Nothing
    // is lost: the guest boots from `-kernel`, so a network boot ROM has no job here.
    '-device',
    'e1000,netdev=n0,romfile=',
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

/**
 * firmadyne's kernel filenames, which are NOT the architecture names this codebase uses.
 *
 * The path was built as `vmlinux.${arch}.4`, and that is right for exactly one architecture. firmadyne ships
 * `vmlinux.mipseb.4` for big-endian MIPS and `vmlinux.armel` (no `.4`) for ARM, so a TP-Link WR940N — plain
 * `mips` — was refused with "No firmadyne kernel at …/vmlinux.mips.4" while the kernel it needed sat in the same
 * directory under a different name. `mipsel` matched by coincidence, which is why this went unnoticed.
 *
 * Candidates are ordered most-specific first and every one is a real filename observed in the deployed image.
 */
export const FIRMADYNE_KERNEL_NAMES: Partial<Record<Architecture, string[]>> = {
  mipsel: ['vmlinux.mipsel.4', 'vmlinux.mipsel'],
  mips: ['vmlinux.mipseb.4', 'vmlinux.mipseb'],
  arm: ['vmlinux.armel', 'zImage.armel'],
};

/** The first firmadyne kernel that exists for an architecture, or null when this deployment ships none. */
export function firmadyneKernelFor(arch: Architecture, dir: string = FIRMADYNE_KERNELS_DIR): string | null {
  for (const name of FIRMADYNE_KERNEL_NAMES[arch] ?? []) {
    const p = `${dir}/${name}`;
    if (fs.existsSync(p)) return p;
  }
  return null;
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
  // `pkill` exits non-zero when nothing matched, which is the normal case — and it exits non-zero when it does
  // not EXIST, which is this deployment. Both landed in the same catch, and the log then said "emulators killed"
  // regardless. The module's first stated invariant is that teardown is guaranteed; it never was here, and the
  // message said otherwise. Strays then accumulated across runs holding their forwarded ports.
  let swept = false;
  for (const pat of TEARDOWN_PATTERNS) {
    try {
      await execFileAsync('pkill', ['-f', pat], { timeout: 5000 });
      swept = true;
    } catch (err) {
      // Exit 1 = matched nothing (fine). ENOENT = pkill is absent, and the sweep did not happen at all.
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') swept = true;
    }
  }
  handle.log(
    swept
      ? 'Teardown complete (emulators killed).'
      : 'Teardown: this run’s emulator was killed directly, but `pkill` is not installed here so no sweep for ' +
          'strays from earlier runs was possible. Each run takes a FRESH host port, so a survivor cannot be ' +
          'mistaken for this boot.',
  );
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
  const kernelPath = firmadyneKernelFor(arch);
  if (!kernelPath) {
    return blocked(
      'full-system',
      `No firmadyne kernel for arch "${arch}" in ${FIRMADYNE_KERNELS_DIR} (tried ${FIRMADYNE_KERNEL_NAMES[arch]?.join(', ') ?? 'nothing — this architecture has no mapping'}).`,
    );
  }

  // What the firmware itself says it will serve. Read before boot, so the forwards match the image rather than
  // an assumption about it.
  const portMap = readPortMap(rootfsDir ?? null);
  // A FRESH host port per forward, asked of the OS, rather than a fixed 8080. This is not tidiness: `pkill` is
  // absent in this deployment so the stray sweep never ran, an earlier run's qemu could still hold 8080, and the
  // probe below would then connect to IT and report `confirmed_full_system` for a boot that never happened. It
  // did, once, with the guest kernel still at NR_IRQS. The dynamic probe learned this exact lesson already.
  const basePort = await allocateHostPort(hostPort);
  const forwards = planForwards(portMap, basePort);
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
  // Keep the HEAD as well as the tail. Capping with `slice(-CAP)` evicted the earliest output first — which is
  // exactly where a kernel prints the markers the boot verdict is read from. The real WR940N boot proved it: the
  // firmware came all the way up (its own init printing `OPEN ALL PHY ETH!!`, its HTTPS daemon loading a
  // certificate) and was graded "no recognisable boot", because 262 KB of vendor chatter had pushed
  // `Freeing unused kernel memory` out of the window.
  const cap = (chunk: Buffer, which: 'o' | 'e'): void => {
    const s = chunk.toString('utf8');
    if (which === 'o') stdout = keepEnds(stdout + s);
    else stderr = keepEnds(stderr + s);
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
        if (await guestAnswers(f.host, f.protocol)) {
          open.push({ host: f.host, guest: f.guest });
          handle.log(
            `  guest port ${f.guest} ANSWERED on host ${f.host} — a service inside the guest replied, not just qemu accepting.`,
          );
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

/**
 * Keep both ends of a long console: the head carries the boot markers, the tail carries what it is doing now.
 * The elision is stated in the text rather than silently swallowing the middle.
 */
export function keepEnds(text: string, cap = CONSOLE_CAP): string {
  if (text.length <= cap) return text;
  const half = Math.floor(cap / 2);
  const dropped = text.length - cap;
  return `${text.slice(0, half)}\n… [FirmLab: ${dropped} bytes of console elided here] …\n${text.slice(-half)}`;
}

/** Ask the OS for a free host port to base the forwards on, so no two runs can share one. */
async function allocateHostPort(preferred: number): Promise<number> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.on('error', () => resolve(preferred));
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : preferred;
      srv.close(() => resolve(port));
    });
  });
}

/**
 * Does a service inside the GUEST answer on this forwarded port?
 *
 * Accepting the connection is necessary and not sufficient. qemu's user networking completes the host-side
 * handshake before it knows whether anything in the guest will take it, so "connected" alone can mean the
 * emulator is listening rather than the firmware is serving — and that is the difference between the strongest
 * claim on this ladder and no claim at all. So the probe SENDS a byte and requires the guest to send something
 * back, or at least to hold the connection open past the point where a refused forward would have reset it.
 */
async function guestAnswers(port: number, protocol: PortProtocol, timeoutMs = 3000): Promise<boolean> {
  if (protocol === 'https') return tlsAnswers(port, timeoutMs);
  const plan = probePlanFor(protocol);
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    const done = (ok: boolean): void => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => {
      // Only speak first where speaking first is correct. SSH and telnet greet the client — an HTTP request sent
      // into an SSH server is noise that can get the connection dropped before its banner arrives.
      if (plan.send) sock.write(plan.send);
    });
    sock.once('data', () => done(true));
    sock.once('timeout', () => done(false));
    sock.once('error', () => done(false));
    // Silence is not an answer. A forward with nothing behind it can also close cleanly, so only data coming
    // back counts — the 'data' handler above is the sole path to `true`.
    sock.once('close', () => done(false));
    sock.connect(port, '127.0.0.1');
  });
}

/**
 * Does a TLS server answer on this forwarded port?
 *
 * The plain-text probe could never see one. It sent `HEAD / HTTP/1.0` at a TLS socket, which replies with an
 * alert or nothing at all, so a firmware whose only service is HTTPS read as "the system came up, its services
 * did not" — measured on the real WR940N, whose own console shows its HTTPS daemon loading a certificate and a
 * private key while 443 was reported silent.
 *
 * `rejectUnauthorized: false` is mandatory rather than lax: firmware ships self-signed certificates by
 * construction, and this probe asks whether something is SERVING, not whether it is trustworthy. A TLS-level
 * failure still answers that question — an alert means a TLS implementation is on the other end — so it counts,
 * while a connection-level failure does not.
 */
async function tlsAnswers(port: number, timeoutMs = 3000): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok: boolean): void => {
      if (settled) return;
      settled = true;
      try {
        sock.destroy();
      } catch {}
      resolve(ok);
    };
    const sock = tls.connect(
      { port, host: '127.0.0.1', rejectUnauthorized: false, servername: 'localhost', timeout: timeoutMs },
      () => done(true),
    );
    sock.once('timeout', () => done(false));
    sock.once('error', (err) => done(isTlsSpeaker(err as { code?: string; message?: string })));
  });
}

/**
 * Pure: does this connection error still prove a TLS implementation answered?
 *
 * A refused or reset connection means nothing was there. A protocol-level failure — an alert, an unsupported
 * version, a malformed record — means something spoke TLS badly, and something speaking badly is still something
 * serving. Firmware TLS stacks are old and frequently fail modern handshakes; treating that as "no service" would
 * discard the result on precisely the images most worth looking at.
 */
export function isTlsSpeaker(err: { code?: string | undefined; message?: string | undefined }): boolean {
  const connectionLevel = new Set(['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'EPIPE']);
  if (err.code && connectionLevel.has(err.code)) return false;
  // Node surfaces TLS failures with codes like ERR_SSL_*, ERR_TLS_*, or an OpenSSL library string.
  return /^ERR_(SSL|TLS)_/.test(err.code ?? '') || /ssl|tls|handshake|alert|wrong version/i.test(err.message ?? '');
}

/**
 * Pure: whether to speak first on this port, and what to say.
 *
 * SSH and telnet greet the client, so the right move is to listen; HTTP will wait forever for a request. Getting
 * this backwards is not harmless — an HTTP request written into an SSH server is protocol noise that can have the
 * connection dropped before the banner arrives, turning a live service into a silent one.
 */
export function probePlanFor(protocol: PortProtocol): { send: string | null } {
  switch (protocol) {
    case 'ssh':
    case 'telnet':
      return { send: null };
    default:
      return { send: 'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n' };
  }
}
