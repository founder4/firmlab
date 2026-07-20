/**
 * AFL++ fuzzing provider (Phase 4). A coverage-guided fuzz of one extracted binary under AFL++'s qemu mode
 * (binary-only, no source), seeded with a corpus and a dictionary mined from the binary's own strings
 * (`rabin2 -z`), time-bounded, and run inside the Phase-4 isolation sandbox. Opt-in like Ghidra: when
 * afl-fuzz/afl-qemu-trace are absent it degrades honestly to `available:false` — it never pretends to have
 * fuzzed. A reproduced crash is real dynamic evidence (the caller records it as confirmed_in_emulation); no crash
 * is reported as no crash, not as "secure". AFL's qemu mode is host-arch: a cross-arch target is reported honestly.
 *
 * The command + dictionary builders are pure and unit-tested; the runner composes them with runIsolated.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { resolveInsideRootfs } from './decompile.js';
import { type IsolationLevel, detectIsolation, loadIsolationLimits, runIsolated } from './isolate.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

export interface FuzzResult {
  available: boolean;
  reason?: string;
  binary: string;
  seconds: number;
  execsDone: number | null;
  crashes: number;
  crashSamples: { name: string; hexPreview: string }[];
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
    '-Q',
    // qemu mode maps a large virtual address space per exec; a memory cap makes the fork server's
    // child die on first spawn ("Unable to request new process (OOM?)"). No cap is the documented default here.
    '-m',
    'none',
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

/** Pure: turn a binary's strings into an AFL++ dictionary (`name="value"`), printable + escaped + deduped + capped. */
export function buildAflDict(strings: string[]): string {
  const seen = new Set<string>();
  const lines: string[] = [];
  for (const s of strings) {
    const v = s.replace(/[^\x20-\x7e]/g, '').slice(0, 64);
    if (v.length < 3 || seen.has(v)) continue;
    seen.add(v);
    lines.push(`fw_${lines.length}="${v.replace(/[\\"]/g, (c) => `\\${c}`)}"`);
    if (lines.length >= 512) break;
  }
  return lines.join('\n');
}

async function canRun(file: string): Promise<boolean> {
  try {
    await execFileAsync(file, ['--version'], { timeout: 4000 });
    return true;
  } catch (err) {
    return (err as { code?: string }).code !== 'ENOENT';
  }
}

export async function detectFuzzing(): Promise<boolean> {
  return (await canRun('afl-fuzz')) && (await canRun('afl-qemu-trace'));
}

/** Mine the target's strings with rabin2 for the AFL dictionary (empty if radare2 is absent). */
async function rabin2Strings(target: string): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync('rabin2', ['-zzqq', target], {
      timeout: 30_000,
      maxBuffer: 8 * 1024 * 1024,
    });
    return stdout
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

function unavailable(binary: string, reason: string): FuzzResult {
  return {
    available: false,
    reason,
    binary,
    seconds: 0,
    execsDone: null,
    crashes: 0,
    crashSamples: [],
    isolation: 'none',
    command: '',
  };
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
  // A small, varied seed corpus so AFL has something to mutate from.
  for (const [i, s] of ['A', 'GET / HTTP/1.0\n', '0000', 'admin=1&x=2'].entries())
    fs.writeFileSync(path.join(seeds, `seed${i}`), s);

  // Dictionary from the binary's own strings — big fuzzing win for text protocols/parsers.
  const dictStrings = await rabin2Strings(abs);
  let dictPath: string | undefined;
  if (dictStrings.length > 0) {
    dictPath = path.join(work, 'dict.txt');
    fs.writeFileSync(dictPath, buildAflDict(dictStrings));
    handle.log(`Dictionary: ${dictStrings.length} strings from rabin2.`);
  }

  const argv = buildFuzzCommand(abs, seeds, out, seconds, dictPath);
  handle.log(`Fuzzing ${binary} for ${seconds}s under isolation: ${argv.join(' ')}`);

  try {
    const res = await runIsolated(argv, {
      // Fuzzing is memory-hungry (AFL's qemu maps a lot of virtual address space) — raise the AS cap for it.
      limits: { ...loadIsolationLimits(), addressSpaceBytes: 4096 * 1024 * 1024, wallMs: (seconds + 30) * 1000 },
      env: {
        ...process.env,
        AFL_SKIP_CPUFREQ: '1',
        AFL_NO_AFFINITY: '1',
        AFL_BENCH_UNTIL_CRASH: '1',
        // In a container we can't rewrite /proc/sys/kernel/core_pattern — tell AFL to proceed anyway.
        AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: '1',
        // Real firmware binaries are dynamically linked (musl/uClibc). Point qemu-user at the rootfs so it
        // resolves the guest's own loader + libraries; without this, only static binaries run (execs stays 0).
        QEMU_LD_PREFIX: rootfsPath,
      },
    });
    const crashDir = path.join(out, 'default', 'crashes');
    let crashSamples: { name: string; hexPreview: string }[] = [];
    let crashes = 0;
    try {
      const files = fs.readdirSync(crashDir).filter((f) => f !== 'README.txt');
      crashes = files.length;
      crashSamples = files.slice(0, 10).map((name) => ({
        name,
        hexPreview: fs.readFileSync(path.join(crashDir, name)).subarray(0, 32).toString('hex'),
      }));
    } catch {
      // no crashes dir — no crashes
    }
    // Best-effort exec count from AFL's stats file.
    let execsDone: number | null = null;
    try {
      const stats = fs.readFileSync(path.join(out, 'default', 'fuzzer_stats'), 'utf8');
      const m = stats.match(/execs_done\s*:\s*(\d+)/);
      if (m) execsDone = Number(m[1]);
    } catch {}
    if (crashes === 0 && !res.stderr.includes('All set') && res.stderr)
      handle.log(`AFL note: ${res.stderr.split('\n').slice(-3).join(' ').slice(0, 200)}`);
    return {
      available: true,
      binary,
      seconds,
      execsDone,
      crashes,
      crashSamples,
      isolation: await detectIsolation(),
      command: res.command,
    };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}
