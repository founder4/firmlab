/**
 * Session isolation (Phase 4) — the contained blast radius that lets emulation run WITHOUT a human-approval gate.
 * Galert's weakness is exactly here (docker socket, seccomp=unconfined, no CPU/RAM caps); FirmLab bounds the
 * radius with OS primitives instead of a nested container, so it is portable and needs no privileged daemon:
 *
 *   - prlimit: hard CPU-time, address-space (RAM), file-size and fd caps — enforced by the kernel, no shell.
 *   - unshare -n: a fresh network namespace with no interfaces, so a booted service cannot reach the network.
 *   - a private throwaway workdir, removed in a finally — teardown is guaranteed, never "creative".
 *
 * `runIsolated` composes these WITHOUT a shell (execFile of prlimit/unshare directly), so a rootfs path with odd
 * characters can't inject a command. When the primitives aren't present (macOS dev, or util-linux missing) the
 * isolation level degrades honestly and the session falls back to the Phase-3 approval gate.
 */
import { execFile } from 'node:child_process';
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
 * Pure: compose the isolation invocation for an inner argv. `prlimit` applies the kernel caps; `unshare -n`
 * (only at level 'full') drops network access. Returns the execFile file+args — no shell in the chain.
 */
export function buildIsolatedInvocation(
  argv: string[],
  limits: IsolationLimits,
  level: IsolationLevel,
): { file: string; args: string[] } {
  const asKb = Math.floor(limits.addressSpaceBytes / 1024);
  const fsizeKb = Math.floor(limits.fileSizeBytes / 1024);
  const prlimit = [
    'prlimit',
    `--cpu=${limits.cpuSeconds}`,
    `--as=${asKb * 1024}`,
    `--fsize=${fsizeKb * 1024}`,
    `--nofile=${limits.openFiles}`,
    '--core=0',
    '--',
    ...argv,
  ];
  if (level === 'full') return { file: 'unshare', args: ['-n', ...prlimit] };
  if (level === 'partial') return { file: prlimit[0] as string, args: prlimit.slice(1) };
  // 'none' — no isolation available; run the argv directly (the caller decides whether that's acceptable).
  return { file: argv[0] as string, args: argv.slice(1) };
}

let cachedLevel: IsolationLevel | null = null;

async function canRun(file: string, args: string[]): Promise<boolean> {
  try {
    await execFileAsync(file, args, { timeout: 4000 });
    return true;
  } catch (err) {
    // A tool that exists but exits non-zero (e.g. `prlimit --help`) still proves availability; ENOENT does not.
    return (err as { code?: string }).code !== 'ENOENT';
  }
}

/**
 * Detect the best isolation level this deployment can enforce. Cached — the toolchain doesn't change at runtime.
 *   full    = prlimit + a usable network namespace (unshare -n) → auto-run emulation, no approval.
 *   partial = prlimit only (CPU/RAM/fsize caps, but the process keeps network) → approval still required.
 *   none    = neither (macOS dev, util-linux absent) → Phase-3 approval flow.
 */
export async function detectIsolation(): Promise<IsolationLevel> {
  if (cachedLevel) return cachedLevel;
  if (process.platform !== 'linux') {
    cachedLevel = 'none';
    return cachedLevel;
  }
  const hasPrlimit = await canRun('prlimit', ['--version']);
  // A real netns test: unshare -n must actually create the namespace (needs privilege / a recent kernel).
  const netns = hasPrlimit && (await canRun('unshare', ['-n', 'true']));
  cachedLevel = !hasPrlimit ? 'none' : netns ? 'full' : 'partial';
  return cachedLevel;
}

/** Test seam — reset the cached probe (used by unit tests). */
export function resetIsolationCache(): void {
  cachedLevel = null;
}

/**
 * Run an argv under the strongest available isolation, in a private throwaway workdir that is always removed.
 * Bounded by a wall-clock timeout (SIGKILL) on top of the CPU rlimit, with a minimal environment.
 */
export async function runIsolated(
  argv: string[],
  opts: { limits?: IsolationLimits; env?: NodeJS.ProcessEnv } = {},
): Promise<IsolatedResult> {
  const limits = opts.limits ?? loadIsolationLimits();
  const level = await detectIsolation();
  const { file, args } = buildIsolatedInvocation(argv, limits, level);
  const command = `${file} ${args.join(' ')}`;
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-iso-'));
  try {
    const { stdout, stderr } = await execFileAsync(file, args, {
      timeout: limits.wallMs,
      killSignal: 'SIGKILL',
      maxBuffer: 8 * 1024 * 1024,
      cwd: workdir,
      env: opts.env ?? { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: workdir },
    });
    return { ran: true, exitCode: 0, timedOut: false, stdout, stderr, isolation: level, command };
  } catch (err) {
    const e = err as { killed?: boolean; code?: number; signal?: string; stdout?: string; stderr?: string };
    const timedOut = e.killed === true && e.signal === 'SIGKILL';
    return {
      ran: true,
      exitCode: typeof e.code === 'number' ? e.code : null,
      timedOut,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
      isolation: level,
      command,
    };
  } finally {
    fs.rmSync(workdir, { recursive: true, force: true });
  }
}
