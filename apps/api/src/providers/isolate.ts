/**
 * Session isolation (Phase 4) — the contained blast radius that lets emulation run WITHOUT a human-approval gate.
 * Galert's weakness is exactly here (docker socket, seccomp=unconfined, no CPU/RAM caps); FirmLab bounds the
 * radius with OS primitives instead of a nested container, so it is portable and needs no privileged daemon:
 *
 *   - prlimit: hard CPU-time, address-space (RAM), file-size and fd caps — enforced by the kernel, no shell.
 *   - unshare: a fresh network namespace with no interfaces, so a booted service cannot reach the network. We
 *     prefer `-n` (needs CAP_SYS_ADMIN) but fall back to `-rn` (a user namespace mapping to root first), which
 *     gives full network isolation UNPRIVILEGED when the kernel allows unprivileged user namespaces.
 *   - a private throwaway workdir, removed in a finally — teardown is guaranteed, never "creative".
 *
 * `runIsolated` composes these without a shell (spawn of unshare/prlimit directly), so a rootfs path with odd
 * characters can't inject a command, and it can drive the target with a trigger via stdin/env/argv while capturing
 * the exit signal (a crash) for the trigger harness. When the primitives aren't present the level degrades honestly.
 */
import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export type IsolationLevel = 'full' | 'partial' | 'none';

export interface IsolationLimits {
  cpuSeconds: number;
  addressSpaceBytes: number;
  fileSizeBytes: number;
  openFiles: number;
  wallMs: number;
}

export interface IsolatedResult {
  ran: boolean;
  exitCode: number | null;
  /** The signal that killed the process, if any — SIGSEGV/SIGABRT is a reproduced crash for the trigger harness. */
  signal: string | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  isolation: IsolationLevel;
  command: string;
}

export function loadIsolationLimits(env: NodeJS.ProcessEnv = process.env): IsolationLimits {
  return {
    cpuSeconds: Math.max(1, Number(env.FIRMLAB_ISOLATE_CPU ?? 30)),
    addressSpaceBytes: Math.max(64, Number(env.FIRMLAB_ISOLATE_MEM_MB ?? 512)) * 1024 * 1024,
    fileSizeBytes: Math.max(1, Number(env.FIRMLAB_ISOLATE_FSIZE_MB ?? 64)) * 1024 * 1024,
    openFiles: 256,
    wallMs: Math.max(1, Number(env.FIRMLAB_ISOLATE_WALL_SECONDS ?? 45)) * 1000,
  };
}

/**
 * Pure: compose the isolation invocation for an inner argv. `prlimit` applies the kernel caps; `unshare <netns>`
 * (only at level 'full') drops network access with whichever flag the probe found works. No shell in the chain.
 */
export function buildIsolatedInvocation(
  argv: string[],
  limits: IsolationLimits,
  level: IsolationLevel,
  netnsArgs: string[] = ['-n'],
): { file: string; args: string[] } {
  const asBytes = Math.floor(limits.addressSpaceBytes / 1024) * 1024;
  const fsizeBytes = Math.floor(limits.fileSizeBytes / 1024) * 1024;
  const prlimit = [
    'prlimit',
    `--cpu=${limits.cpuSeconds}`,
    // An address-space cap is skipped when addressSpaceBytes <= 0. Managed runtimes (Renode's .NET GC on arm64)
    // reserve a huge virtual region up front and abort under any --as ceiling; the cpu/fsize/nofile/netns caps
    // still apply, so isolation is preserved without breaking those workloads.
    ...(asBytes > 0 ? [`--as=${asBytes}`] : []),
    // Likewise skipped when <= 0: Renode's memory-mapped emulation files trip a --fsize ceiling (SIGXFSZ). The
    // wall-clock + cpu caps still bound a runaway, and sparse mmaps don't actually consume disk.
    ...(fsizeBytes > 0 ? [`--fsize=${fsizeBytes}`] : []),
    `--nofile=${limits.openFiles}`,
    '--core=0',
    '--',
    ...argv,
  ];
  if (level === 'full') return { file: 'unshare', args: [...netnsArgs, ...prlimit] };
  if (level === 'partial') return { file: prlimit[0] as string, args: prlimit.slice(1) };
  return { file: argv[0] as string, args: argv.slice(1) };
}

let cachedLevel: IsolationLevel | null = null;
let cachedNetns: string[] = ['-n'];

async function canRun(file: string, args: string[]): Promise<boolean> {
  try {
    await execFileAsync(file, args, { timeout: 4000 });
    return true;
  } catch (err) {
    // A tool that exists but exits non-zero still proves availability; ENOENT does not. For `unshare -n true`,
    // failure means the namespace couldn't be created (no privilege), which we DO want to treat as "can't".
    const e = err as { code?: string };
    if (e.code === 'ENOENT') return false;
    // Distinguish "ran but exited nonzero" (fine) from "failed to create ns". execFile rejects with code number
    // for a nonzero exit; unshare failing to create the ns exits nonzero too — so for the netns probe we require
    // a clean exit. canRunClean handles that; this looser check is for `--version` probes.
    return true;
  }
}

async function canRunClean(file: string, args: string[]): Promise<boolean> {
  try {
    await execFileAsync(file, args, { timeout: 4000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Detect the best isolation level this deployment can enforce, and remember which unshare flag creates a netns.
 *   full    = prlimit + a usable network namespace (`unshare -n`, else rootless `unshare -rn`) → auto-run, no gate.
 *   partial = prlimit only → approval still required.
 *   none    = neither (macOS dev, util-linux absent) → Phase-3 approval flow.
 */
export async function detectIsolation(): Promise<IsolationLevel> {
  if (cachedLevel) return cachedLevel;
  if (process.platform !== 'linux') {
    cachedLevel = 'none';
    return cachedLevel;
  }
  if (!(await canRun('prlimit', ['--version']))) {
    cachedLevel = 'none';
    return cachedLevel;
  }
  if (await canRunClean('unshare', ['-n', 'true'])) {
    cachedNetns = ['-n'];
    cachedLevel = 'full';
  } else if (await canRunClean('unshare', ['-rn', 'true'])) {
    cachedNetns = ['-rn']; // rootless: map to root in a new userns, then a fresh netns — no CAP_SYS_ADMIN needed
    cachedLevel = 'full';
  } else {
    cachedLevel = 'partial';
  }
  return cachedLevel;
}

/** The unshare flags the probe found usable for network isolation (for callers building their own invocation). */
export function isolationNetnsArgs(): string[] {
  return cachedNetns;
}

/** Test seam — reset the cached probe. */
export function resetIsolationCache(): void {
  cachedLevel = null;
  cachedNetns = ['-n'];
}

/**
 * Run an argv under the strongest available isolation, in a private throwaway workdir that is always removed.
 * Supports driving the target with a trigger (stdin/env/argv) and reports the exit signal so a crash is visible.
 */
export async function runIsolated(
  argv: string[],
  opts: { limits?: IsolationLimits; env?: NodeJS.ProcessEnv; input?: string } = {},
): Promise<IsolatedResult> {
  const limits = opts.limits ?? loadIsolationLimits();
  const level = await detectIsolation();
  const { file, args } = buildIsolatedInvocation(argv, limits, level, cachedNetns);
  const command = `${file} ${args.join(' ')}`;
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-iso-'));
  const maxBuffer = 8 * 1024 * 1024;

  try {
    return await new Promise<IsolatedResult>((resolve) => {
      const child = spawn(file, args, {
        cwd: workdir,
        env: opts.env ?? { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: workdir },
      });
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, limits.wallMs);
      child.stdout?.on('data', (d: Buffer) => {
        if (stdout.length < maxBuffer) stdout += d.toString();
      });
      child.stderr?.on('data', (d: Buffer) => {
        if (stderr.length < maxBuffer) stderr += d.toString();
      });
      child.on('error', () => {
        clearTimeout(timer);
        resolve({ ran: false, exitCode: null, signal: null, timedOut, stdout, stderr, isolation: level, command });
      });
      child.on('close', (code, signal) => {
        clearTimeout(timer);
        resolve({
          ran: true,
          exitCode: code,
          signal: signal ?? null,
          timedOut,
          stdout,
          stderr,
          isolation: level,
          command,
        });
      });
      if (opts.input != null) child.stdin?.write(opts.input);
      child.stdin?.end();
    });
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}
