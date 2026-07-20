/**
 * AFL++ fuzzing provider (Phase 4, opt-in). A coverage-guided fuzz of one extracted binary under AFL++'s
 * qemu mode (binary-only, no source), time-bounded, run inside the Phase-4 isolation sandbox. Like Ghidra, the
 * heavy AFL++ layer is NOT baked into the shipped image: when afl-fuzz/afl-qemu-trace are absent the provider
 * degrades honestly to `available:false` — it never pretends to have fuzzed. A reproduced crash is real dynamic
 * evidence (proof-state confirmed_in_emulation); no crash is reported as no crash, not as "secure".
 *
 * The command builder is pure and unit-tested; the runner composes it with runIsolated.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { resolveInsideRootfs } from './decompile.js';
import { type IsolationLevel, detectIsolation, runIsolated } from './isolate.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

export interface FuzzResult {
  available: boolean;
  reason?: string;
  binary: string;
  seconds: number;
  crashes: number;
  crashInputs: string[];
  isolation: IsolationLevel;
  command: string;
}

/** Pure: the AFL++ qemu-mode invocation for a target binary. File input is delivered via the `@@` placeholder. */
export function buildFuzzCommand(
  target: string,
  seedsDir: string,
  outDir: string,
  seconds: number,
  dictPath?: string,
): string[] {
  return [
    'afl-fuzz',
    '-Q', // qemu mode — binary-only fuzzing, no instrumentation/source required
    '-i',
    seedsDir,
    '-o',
    outDir,
    '-V',
    String(seconds),
    ...(dictPath ? ['-x', dictPath] : []),
    '--',
    target,
    '@@',
  ];
}

async function canRun(file: string): Promise<boolean> {
  try {
    await execFileAsync(file, ['--version'], { timeout: 4000 });
    return true;
  } catch (err) {
    return (err as { code?: string }).code !== 'ENOENT';
  }
}

/** Whether coverage-guided fuzzing is available (AFL++ present). Not baked into the shipped image by default. */
export async function detectFuzzing(): Promise<boolean> {
  return (await canRun('afl-fuzz')) && (await canRun('afl-qemu-trace'));
}

function unavailable(binary: string, reason: string): FuzzResult {
  return { available: false, reason, binary, seconds: 0, crashes: 0, crashInputs: [], isolation: 'none', command: '' };
}

/** Fuzz one rootfs binary for a bounded time under isolation, then report reproduced crashes (honest, no guess). */
export async function runFuzz(
  rootfsPath: string,
  binary: string,
  handle: JobHandle,
  seconds = 60,
): Promise<FuzzResult> {
  if (!(await detectFuzzing())) {
    handle.log('AFL++ not installed — coverage-guided fuzzing unavailable (opt-in layer, like Ghidra).');
    return unavailable(binary, 'AFL++ not installed');
  }
  const abs = resolveInsideRootfs(rootfsPath, binary);
  if (!abs) return unavailable(binary, 'binary not found in rootfs');

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-fuzz-'));
  const seeds = path.join(work, 'seeds');
  const out = path.join(work, 'out');
  fs.mkdirSync(seeds, { recursive: true });
  fs.writeFileSync(path.join(seeds, 'seed0'), 'A'); // a minimal seed; the corpus grows from coverage
  const argv = buildFuzzCommand(abs, seeds, out, seconds);
  handle.log(`Fuzzing ${binary} for ${seconds}s under isolation: ${argv.join(' ')}`);

  try {
    const res = await runIsolated(argv, {
      env: { ...process.env, AFL_SKIP_CPUFREQ: '1', AFL_NO_AFFINITY: '1', AFL_BENCH_UNTIL_CRASH: '1' },
    });
    const crashDir = path.join(out, 'default', 'crashes');
    let crashInputs: string[] = [];
    try {
      crashInputs = fs.readdirSync(crashDir).filter((f) => f !== 'README.txt');
    } catch {
      // no crashes dir — no crashes
    }
    return {
      available: true,
      binary,
      seconds,
      crashes: crashInputs.length,
      crashInputs: crashInputs.slice(0, 20),
      isolation: await detectIsolation(),
      command: res.command,
    };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}
