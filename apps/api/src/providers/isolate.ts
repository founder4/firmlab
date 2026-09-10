/**
 * Best-effort resource and network restrictions for emulation. These primitives do not isolate the filesystem,
 * credentials, or host processes, and therefore cannot authorize unattended execution by themselves:
 *
 *   - prlimit: hard CPU-time, address-space (RAM), file-size and fd caps — enforced by the kernel, no shell.
 *   - unshare: a fresh network namespace with no interfaces, so a booted service cannot reach the network. We
 *     prefer `-n` (needs CAP_SYS_ADMIN) but fall back to `-rn` (a user namespace mapping to root first), which
 *     gives full network isolation UNPRIVILEGED when the kernel allows unprivileged user namespaces.
 *   - a private throwaway workdir, removed in a finally. This is NOT a filesystem sandbox.
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

/** 'full' remains a legacy result value; the current runtime never detects full containment. */
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
 * Pure: compose the restrictions for an inner argv. A probed netns may strengthen partial isolation, but does
 * not make it full containment. The legacy 'full' invocation is retained for compatibility, not detection.
 */
export function buildIsolatedInvocation(
  argv: string[],
  limits: IsolationLimits,
  level: IsolationLevel,
  netnsArgs: string[] = level === 'full' ? ['-n'] : [],
): { file: string; args: string[] } {
  const asBytes = Math.floor(limits.addressSpaceBytes / 1024) * 1024;
  const fsizeBytes = Math.floor(limits.fileSizeBytes / 1024) * 1024;
  const prlimit = [
    'prlimit',
    `--cpu=${limits.cpuSeconds}`,
    // An address-space cap is skipped when addressSpaceBytes <= 0. Managed runtimes (Renode's .NET GC on arm64)
    // reserve a huge virtual region up front and abort under any --as ceiling; the cpu/fsize/nofile/netns caps
    // still apply, although the address-space resource bound is lost.
    ...(asBytes > 0 ? [`--as=${asBytes}`] : []),
    // Likewise skipped when <= 0: Renode's memory-mapped emulation files trip a --fsize ceiling (SIGXFSZ). The
    // wall-clock + cpu caps still bound a runaway, and sparse mmaps don't actually consume disk.
    ...(fsizeBytes > 0 ? [`--fsize=${fsizeBytes}`] : []),
    `--nofile=${limits.openFiles}`,
    '--core=0',
    '--',
    ...argv,
  ];
  if (level !== 'none' && netnsArgs.length > 0) return { file: 'unshare', args: [...netnsArgs, ...prlimit] };
  if (level === 'partial') return { file: prlimit[0] as string, args: prlimit.slice(1) };
  return { file: argv[0] as string, args: argv.slice(1) };
}

let cachedLevel: IsolationLevel | null = null;
let cachedNetns: string[] = [];

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
 *   full    = reserved for a future containment implementation; never reported here.
 *   partial = prlimit, optionally with a network namespace → approval or explicit preauthorization required.
 *   none    = neither (macOS dev, util-linux absent) → Phase-3 approval flow.
 */
export async function detectIsolation(): Promise<IsolationLevel> {
  if (cachedLevel) return cachedLevel;
  if (process.platform !== 'linux') {
    cachedLevel = 'none';
    return cachedLevel;
  }
  if (!(await canRunClean('prlimit', ['--cpu=1', '--', 'true']))) {
    cachedLevel = 'none';
    return cachedLevel;
  }
  if (await canRunClean('unshare', ['-n', 'true'])) {
    cachedNetns = ['-n'];
    cachedLevel = 'partial';
  } else if (await canRunClean('unshare', ['-rn', 'true'])) {
    cachedNetns = ['-rn']; // rootless: map to root in a new userns, then a fresh netns — no CAP_SYS_ADMIN needed
    cachedLevel = 'partial';
  } else {
    cachedLevel = 'partial';
  }
  return cachedLevel;
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
      const grouped = process.platform !== 'win32';
      const child = spawn(file, args, {
        detached: grouped,
        cwd: workdir,
        env: opts.env ?? { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: workdir },
      });
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      const killGroup = () => {
        if (!child.pid) return;
        try {
          if (grouped) process.kill(-child.pid, 'SIGKILL');
          else child.kill('SIGKILL');
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ESRCH') child.kill('SIGKILL');
        }
      };
      const timer = setTimeout(() => {
        timedOut = true;
        killGroup();
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
        // Reap same-group background children even when the direct process exited normally.
        killGroup();
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
