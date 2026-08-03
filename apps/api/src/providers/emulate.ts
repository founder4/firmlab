/**
 * Emulation planner — the brain behind the workbench "Simulation" menu.
 *
 * Given an image's inferred identity and (optionally) an extracted rootfs, it proposes concrete, ranked
 * emulation recipes: user-mode QEMU of a single binary (the fastest win), full-system QEMU boot of a router
 * rootfs, and Renode for RTOS/Cortex-M blobs. Each recipe carries the exact command, the tools it needs, and
 * whether those tools are present in this deployment — so the UI can show a real, actionable menu that
 * degrades gracefully instead of pretending capabilities it lacks.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import type { Architecture, ImageIdentity } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';
import { type ToolId, detectTools } from '../tools.js';
import { parseTargetStderr } from './dynprobe.js';
import { libnvramHostPath } from './emulate-system.js';
import type { JobHandle } from './jobs.js';
import { FIRMADYNE_KERNELS_DIR, QEMU_MACHINE_BY_ARCH, QEMU_SYSTEM_BY_ARCH, QEMU_USER_BY_ARCH } from './preflight.js';

const execFileAsync = promisify(execFile);

export type EmulationMode = 'user-qemu' | 'chroot-qemu' | 'system-qemu' | 'renode' | 'uefi-chipsec';

export interface EmulationRecipe {
  id: string;
  mode: EmulationMode;
  title: string;
  description: string;
  /** Tools this recipe needs; the UI marks it runnable only when all are available. */
  requires: ToolId[];
  runnable: boolean;
  /** The concrete command a user (or the job runner) would execute. Illustrative for system/renode modes. */
  command: string;
  /** Ordering hint — lower is a better first attempt for this image. */
  rank: number;
  notes?: string;
}

export interface PlanContext {
  identity: ImageIdentity;
  /** Absolute path to an extracted rootfs, if extraction already ran. */
  rootfsPath?: string;
  /** A representative network-facing binary inside the rootfs, if known (e.g. usr/sbin/httpd). */
  suggestedBinary?: string;
}

/** Build the ranked emulation menu for an image. */
export async function planEmulation(ctx: PlanContext): Promise<EmulationRecipe[]> {
  const tools = await detectTools();
  const has = (id: ToolId): boolean => tools.find((t) => t.id === id)?.available ?? false;

  const recipes: EmulationRecipe[] = [];
  const { arch, firmwareClass } = ctx.identity;

  // === User-mode QEMU (single binary) ===
  const userBin = QEMU_USER_BY_ARCH[arch];
  if (firmwareClass === 'embedded-linux' || firmwareClass === 'unknown') {
    const rootfs = ctx.rootfsPath ?? '<rootfs>';
    const target = ctx.suggestedBinary ?? 'bin/busybox';
    const emulator = userBin ?? 'qemu-<arch>-static';
    recipes.push({
      id: 'user-qemu-binary',
      mode: 'user-qemu',
      title: `User-mode QEMU — run a single ${arch === 'unknown' ? '' : arch} binary`,
      description:
        'Fastest bring-up: run one extracted binary (CGI/daemon/parser) under qemu-user with the rootfs as ' +
        'the library path. Ideal for triaging a specific service or reproducing a crash.',
      requires: userBin ? [userBin] : [],
      runnable: Boolean(userBin && has(userBin) && ctx.rootfsPath),
      command: `${emulator} -L ${rootfs} ${rootfs}/${target}`,
      rank: 1,
      notes: userBin
        ? 'Add LD_PRELOAD=/opt/libnvram/libnvram-<arch>.so for NVRAM-backed router daemons.'
        : 'Architecture not resolved yet — extract the rootfs and identify a target ELF first.',
    });
  }

  // === rung-2: chroot service under qemu-user + NVRAM shim ===
  if ((firmwareClass === 'embedded-linux' || firmwareClass === 'unknown') && userBin) {
    const rootfs = ctx.rootfsPath ?? '<rootfs>';
    const target = ctx.suggestedBinary ?? 'usr/sbin/httpd';
    const shimPresent = fs.existsSync(libnvramHostPath(arch));
    recipes.push({
      id: 'chroot-service',
      mode: 'chroot-qemu',
      title: `Chroot service — run a daemon with NVRAM emulation (${arch})`,
      description:
        'Start a network daemon (httpd/upnpd/…) under qemu-user inside the rootfs chroot, with the libnvram ' +
        'shim satisfying NVRAM reads — the workhorse for reproducing router web-UI bugs. Deterministic bring-up ' +
        'with guaranteed teardown.',
      requires: [userBin],
      runnable: Boolean(has(userBin) && ctx.rootfsPath && shimPresent),
      command: `chroot ${rootfs} ./qemu-${arch}-static -E LD_PRELOAD=/libnvram.so /${target}`,
      rank: 2,
      notes: shimPresent
        ? 'Deterministic bring-up with guaranteed teardown.'
        : 'Needs the libnvram shim — enable the emulation-assets section in Dockerfile.firmware.',
    });
  }

  // === rung-3: Full-system QEMU (boot the rootfs under a kernel) ===
  const sysBin = QEMU_SYSTEM_BY_ARCH[arch];
  if (firmwareClass === 'embedded-linux') {
    const rootfs = ctx.rootfsPath ?? '<rootfs>';
    const emulator = sysBin ?? 'qemu-system-<arch>';
    const machine = QEMU_MACHINE_BY_ARCH[arch] ?? '<machine>';
    const kernelsPresent = fs.existsSync(FIRMADYNE_KERNELS_DIR);
    recipes.push({
      id: 'system-qemu-boot',
      mode: 'system-qemu',
      title: `Full-system QEMU — boot the rootfs (${arch})`,
      description:
        'Boot the extracted rootfs under a matched guest kernel with user-mode networking, so the real web ' +
        'UI / services come up and can be scanned end-to-end. Needs a FirmAE guest kernel for the arch.',
      requires: sysBin ? [sysBin] : [],
      runnable: Boolean(sysBin && has(sysBin) && ctx.rootfsPath && kernelsPresent),
      command:
        `${emulator} -M ${machine} -kernel /opt/firmae/kernels/vmlinux.${arch}.4 ` +
        `-drive file=${rootfs}.img,format=raw -netdev user,id=n0,hostfwd=tcp::8080-:80 -device e1000,netdev=n0 -nographic`,
      rank: 3,
      notes: kernelsPresent
        ? 'Assemble a rootfs image (mkfs) first; port-forward 8080→80 to reach the emulated web UI.'
        : 'Needs firmadyne kernels — enable the emulation-assets section in Dockerfile.firmware.',
    });
  }

  // === Renode (RTOS / Cortex-M) ===
  if (firmwareClass === 'rtos' || firmwareClass === 'unknown') {
    recipes.push({
      id: 'renode-rtos',
      mode: 'renode',
      title: 'Renode — emulate an RTOS / Cortex-M blob',
      description:
        'Full-system emulation of a baremetal/RTOS firmware (FreeRTOS/Zephyr/nRF/STM32/TI) by modelling the ' +
        'CPU + peripherals. The only path that gives RTOS images real dynamic execution.',
      requires: ['renode'],
      runnable: has('renode'),
      command:
        'renode --disable-xwt --console -e "mach create; machine LoadPlatformDescription @platform.repl; sysbus LoadELF @firmware.elf; start"',
      rank: firmwareClass === 'rtos' ? 1 : 3,
      notes: 'Provide or generate a .repl platform matching the MCU; load the raw blob at its base address.',
    });
  }

  // === UEFI / BIOS (chipsec, offline) ===
  // Not emulation: chipsec parses the firmware volumes and carves EFI modules from the bytes. Surfaced in the
  // same control surface as the emulators because it is this class's dynamic-analysis track, but its proof tops
  // out at static_confirmed — a fact about the image, never a device claim.
  if (firmwareClass === 'uefi-bios') {
    recipes.push({
      id: 'uefi-chipsec',
      mode: 'uefi-chipsec',
      title: 'chipsec — decode & scan the UEFI/BIOS image (offline)',
      description:
        'Parse the UEFI firmware volumes, carve every EFI module (PEI/DXE/SMM/applications), and scan the ' +
        'inventory for known-bad modules and bootkit-vector leads. Fully offline — no hardware, no emulation.',
      requires: ['chipsec'],
      runnable: has('chipsec'),
      command: 'chipsec_util uefi decode <image.fd>',
      rank: 1,
      notes: has('chipsec')
        ? 'Offline structural analysis; findings are static_confirmed. Point FIRMLAB_UEFI_IOC at a feed to match implant GUIDs.'
        : 'Needs chipsec — enable the UEFI-analysis section in Dockerfile.firmware.',
    });
  }

  return recipes.sort((a, b) => a.rank - b.rank);
}

export interface UserEmulationResult {
  ran: boolean;
  exitCode: number | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  command: string;
}

/**
 * qemu refusing the binary outright, as opposed to the binary running and failing.
 *
 * The distinction is the whole point and it was paid for on 2026-08-03: three of seven user-mode runs in the
 * corpus sweep exited 255 with `qemu-mipsel-static: …/usr/bin/httpd: Invalid ELF image for this architecture`,
 * because the arch map handed big-endian MIPS the little-endian emulator. Read as an exit code, that is a program
 * that failed; read for what it says, it is the HARNESS that never started the program. A ledger row must not
 * turn the second into the first — that is `emulation_artifact` versus a result, the separation the dynamic probe
 * already makes from qemu's stderr.
 *
 * **Anchored to qemu's own prefix**, not grepped over the whole stream, and that is the load-bearing part. The
 * target's own output is in this same buffer, so an unanchored `/unknown architecture/` would let a program that
 * prints those words for its own reasons downgrade a genuine execution to a platform block and discard the
 * result. `parseTargetStderr` in dynprobe.ts documents the same trap from the other side: it excludes
 * `qemu: uncaught target signal 11` precisely because qemu prints it when the TARGET misbehaves. Here the test is
 * the reverse — the line must be qemu speaking about the image it was handed, before any guest instruction ran.
 */
export function emulatorRefusal(stderr: string): string | null {
  const REFUSAL = /^qemu-\S*:\s.*(invalid elf image|unable to find dynamic linker|unknown architecture)/i;
  const line = stderr
    .split('\n')
    .map((l) => l.trim())
    .find((l) => REFUSAL.test(l));
  return line ?? null;
}

/**
 * Compose the ledger rows a user-mode run earns. Pure, so the honesty rules below are unit-testable.
 *
 * Severity is `info` on every branch: that a binary executes under emulation is evidence about the sandbox and
 * about the harness, never a defect in itself — the defects come from what the probe then asks of it. And a clean
 * exit is a statement about ONE input, which the rationale says out loud rather than leaving to be inferred.
 */
export function buildUserEmulationFindings(binary: string, r: UserEmulationResult): FindingDraft[] {
  const refusal = emulatorRefusal(r.stderr);
  // The target's own account of its run, split the way the dynamic probe splits it: a line naming a kernel
  // interface qemu-user does not implement is the SANDBOX coming up short, and everything else is the program
  // talking. Reusing that reading rather than writing a second one, because the second one always drifts.
  const { deficiencies, output } = parseTargetStderr(r.stderr);
  const evidence: Record<string, unknown> = {
    binary,
    command: r.command,
    exitCode: r.exitCode,
    timedOut: r.timedOut,
  };
  if (refusal) evidence.emulatorRefusal = refusal;
  if (deficiencies.length > 0) evidence.sandboxShortfalls = deficiencies.slice(0, 20);
  // The target's own output travels with EVERY row, including the ones this code does not classify. The WR940N's
  // httpd prints `cache '/etc/ld.so.cache' is corrupt` and then fails to create a thread — neither matches a
  // shortfall pattern, and both are the difference between a reader understanding the exit and guessing at it.
  // Evidence a rule does not recognise is still evidence; inventing a pattern to cover it would be the trap the
  // probe's own comment warns about.
  if (output.length > 0) evidence.targetOutput = output.slice(0, 20);

  // Two ways for nothing to have executed, and neither may be reported as the program failing. `ran: false` is the
  // emulator process never starting at all (`runIsolated` resolves it on a spawn error), and a refusal is qemu
  // starting and rejecting the image. Gating on `ran` mirrors the system composer, where the same field decides
  // whether the row may carry an evidence channel: a rung that never started learned nothing.
  if (!r.ran || refusal) {
    const why = refusal
      ? `${refusal.replace(/[.\s]*$/, '')}.`
      : 'The emulator process never started, so the binary was never executed.';
    return [
      {
        kind: 'binary-execution-blocked',
        title: refusal
          ? `${binary}: the emulator refused the binary before executing it — this is not a verdict about the firmware`
          : `${binary}: the emulator could not be started — this is not a verdict about the firmware`,
        severity: 'info',
        proofState: 'blocked_by_platform',
        evidence,
        rationale: `The harness could not run this binary here: ${why} Nothing about the program was observed, so this is a gap in the deployment, not a negative result about the code.`,
      },
    ];
  }

  if (r.timedOut) {
    return [
      {
        kind: 'binary-execution-timeboxed',
        title: `${binary}: executed under user-mode emulation and was still running at the time box`,
        severity: 'info',
        proofState: 'confirmed_in_emulation',
        evidence,
        evidenceChannel: 'emulated_run',
        rationale:
          'The binary ran under qemu-user until the time box killed it, which is what a daemon does. It proves the sandbox can execute this binary; it says nothing about the physical device, and a run that was ended by the clock has no exit code to read.',
      },
    ];
  }

  const clean = r.exitCode === 0;

  // A non-zero exit from a run in which the sandbox demonstrably came up short is not a statement about the
  // program, and filing it as one is how an emulation artefact becomes a finding. The binary still EXECUTED — the
  // shortfalls happen after it starts — so the proof state stays `confirmed_in_emulation` for the fact of
  // execution; what changes is that the row stops attributing the exit to the code and names what the sandbox
  // failed to provide. A CLEAN exit is left alone: it succeeded despite the shortfall, which is a stronger result,
  // not a weaker one.
  if (!clean && deficiencies.length > 0) {
    return [
      {
        kind: 'binary-execution-sandbox-shortfall',
        title: `${binary}: executed under user-mode emulation and exited ${r.exitCode ?? 'on a signal'}, on a run where the sandbox came up short`,
        severity: 'info',
        proofState: 'confirmed_in_emulation',
        evidence,
        evidenceChannel: 'emulated_run',
        rationale: `The binary executed, and this run was missing something the sandbox does not provide: ${deficiencies[0]}${deficiencies.length > 1 ? ` (and ${deficiencies.length - 1} more)` : ''}. The exit is therefore not attributable to the program — qemu-user has a different libc, no NVRAM and no peripherals, and a firmware daemon that needs any of them will fail here and work on the device. Recorded as what happened to the HARNESS; it is not a defect in the code and not a clean bill of health either.`,
      },
    ];
  }

  return [
    {
      kind: clean ? 'binary-executed-in-emulation' : 'binary-execution-nonzero',
      title: clean
        ? `${binary}: executed under user-mode emulation and exited cleanly`
        : `${binary}: executed under user-mode emulation and exited ${r.exitCode ?? 'on a signal'}`,
      severity: 'info',
      proofState: 'confirmed_in_emulation',
      evidence,
      evidenceChannel: 'emulated_run',
      rationale: clean
        ? 'The binary executed under qemu-user and exited 0 on the input it was given. That proves the sandbox can run it — it is a statement about ONE input and about the emulator, never about the physical device, and it is nowhere near enough to call the binary sound.'
        : 'The binary executed under qemu-user and exited non-zero on the input it was given. Under a different libc, with no NVRAM and no peripherals, a non-zero exit is as likely to be the sandbox as the program — it is recorded as what happened, not as a defect. Its own output travels in the evidence, because no rule here classified why it exited.',
    },
  ];
}

/**
 * Actually execute a user-mode QEMU proof: run one target binary from the extracted rootfs under
 * qemu-<arch>-static with the rootfs as the library search path, capturing output. Bounded by a timeout and
 * an output cap so a hung or chatty daemon can't wedge the job. This is the one emulation mode we auto-run;
 * full-system boot and Renode need per-image kernel/platform assembly and are surfaced as guided recipes.
 */
export async function runUserModeEmulation(
  arch: Architecture,
  rootfsPath: string,
  targetBinary: string,
  handle: JobHandle,
  args: string[] = [],
): Promise<UserEmulationResult> {
  const emulator = QEMU_USER_BY_ARCH[arch];
  if (!emulator) throw new Error(`No qemu-user emulator mapped for arch "${arch}"`);
  const tools = await detectTools();
  if (!(tools.find((t) => t.id === emulator)?.available ?? false)) {
    throw new Error(`${emulator} is not available in this deployment`);
  }

  const absTarget = path.resolve(rootfsPath, targetBinary);
  // Confine the target to the rootfs (no traversal outside the extracted tree).
  const rootfsAbs = path.resolve(rootfsPath);
  if (!absTarget.startsWith(rootfsAbs + path.sep)) {
    throw new Error('Target binary escapes the rootfs');
  }
  if (!fs.existsSync(absTarget)) throw new Error(`Target binary not found: ${targetBinary}`);

  const cmdArgs = ['-L', rootfsAbs, absTarget, ...args];
  const command = `${emulator} ${cmdArgs.join(' ')}`;
  handle.log(`Executing: ${command}`);

  try {
    const { stdout, stderr } = await execFileAsync(emulator, cmdArgs, {
      timeout: 20_000,
      maxBuffer: 4 * 1024 * 1024,
      killSignal: 'SIGKILL',
    });
    handle.log('Process exited 0');
    return { ran: true, exitCode: 0, timedOut: false, stdout, stderr, command };
  } catch (err) {
    const e = err as { killed?: boolean; code?: number; signal?: string; stdout?: string; stderr?: string };
    const timedOut = e.killed === true && e.signal === 'SIGKILL';
    handle.log(timedOut ? 'Process killed after timeout (likely a long-running daemon)' : `Process exited ${e.code}`);
    return {
      ran: true,
      exitCode: typeof e.code === 'number' ? e.code : null,
      timedOut,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
      command,
    };
  }
}
