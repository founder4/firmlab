/**
 * AFL++ fuzzing provider (Phase 4). A coverage-guided fuzz of one extracted binary under AFL++'s qemu mode
 * (binary-only, no source), seeded with a corpus and a dictionary mined from the binary's own strings
 * (`rabin2 -z`), time-bounded, and run inside the Phase-4 isolation sandbox. Opt-in like Ghidra: when
 * afl-fuzz/afl-qemu-trace are absent it degrades honestly to `available:false` — it never pretends to have
 * fuzzed. A reproduced crash is real dynamic evidence (the caller records it as confirmed_in_emulation); no crash
 * is reported as no crash, not as "secure". AFL's qemu mode is host-arch: a cross-arch target is reported honestly.
 *
 * Per-class harnesses (debt): the input-delivery method is chosen for the target, not fixed to file input.
 *   - `file`    — a parser that reads a path from argv: AFL substitutes the testcase file for `@@` (the default).
 *   - `stdin`   — a filter/CLI that reads stdin: no `@@`, AFL feeds the testcase on stdin.
 *   - `network` — a socket daemon (httpd/telnetd/…): a desock preload redirects the daemon's socket I/O to the
 *                 fuzzed stdin. desock is opt-in (FIRMLAB_DESOCK → a guest-arch libdesock); without it the network
 *                 harness degrades honestly to raw stdin with a note, rather than pretending the socket was fuzzed.
 *
 * The command/dictionary builders and the harness picker are pure and unit-tested; the runner composes them.
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

/** How the fuzzed testcase reaches the target. */
export type HarnessClass = 'file' | 'stdin' | 'network';

export interface FuzzResult {
  available: boolean;
  reason?: string;
  binary: string;
  /** The input-delivery harness actually used. */
  harness: HarnessClass;
  /** An honest caveat when the harness degraded (e.g. a network daemon fuzzed without a desock preload). */
  harnessNote?: string;
  seconds: number;
  execsDone: number | null;
  crashes: number;
  crashSamples: { name: string; hexPreview: string }[];
  isolation: IsolationLevel;
  command: string;
}

/** Common firmware network-daemon / CGI names — the signal for auto-selecting the desock (network) harness. */
const NETWORK_DAEMON_NAMES = [
  'httpd',
  'lighttpd',
  'uhttpd',
  'mini_httpd',
  'goahead',
  'boa',
  'thttpd',
  'telnetd',
  'utelnetd',
  'dropbear',
  'sshd',
  'upnpd',
  'miniupnpd',
  'wscd',
  'dnsmasq',
  'ftpd',
  'vsftpd',
  'tr069',
  'cwmpd',
];

/** Pure: is this target a network daemon / CGI (so the network/desock harness fits)? */
export function isNetworkDaemon(binaryPath: string): boolean {
  const base = binaryPath.split('/').pop() ?? '';
  return NETWORK_DAEMON_NAMES.includes(base) || binaryPath.endsWith('.cgi');
}

/**
 * Pure: pick the input-delivery harness for a target from its path. A network daemon/CGI → the desock `network`
 * harness; everything else → a `file` (`@@`) parser (the safe default, and what most standalone fuzz targets are).
 * `stdin` is never auto-selected from a path alone — a caller who knows the tool reads stdin selects it explicitly.
 */
export function chooseHarness(binaryPath: string): HarnessClass {
  return isNetworkDaemon(binaryPath) ? 'network' : 'file';
}

/**
 * Pure: the AFL++ qemu-mode invocation for a target. File input is delivered via the `@@` placeholder; the
 * `stdin` option drops `@@` so AFL feeds each testcase on stdin (also how the network/desock harness runs).
 */
export function buildFuzzCommand(
  target: string,
  seedsDir: string,
  outDir: string,
  seconds: number,
  opts: { dictPath?: string; stdin?: boolean } = {},
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
    ...(opts.dictPath ? ['-x', opts.dictPath] : []),
    '--',
    target,
    ...(opts.stdin ? [] : ['@@']),
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

/**
 * A desock preload for the network harness — a compiled libdesock/libaflppdesock that redirects a daemon's
 * socket syscalls to stdin/stdout so AFL can fuzz "the network". Opt-in and arch-specific: `FIRMLAB_DESOCK`
 * points at a `.so` built for the TARGET arch. Absent → the network harness degrades honestly to raw stdin.
 */
export function detectDesockPreload(env: NodeJS.ProcessEnv = process.env): string | null {
  const p = env.FIRMLAB_DESOCK;
  return p && safeExists(p) ? p : null;
}

function safeExists(p: string): boolean {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
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
    harness: 'file',
    seconds: 0,
    execsDone: null,
    crashes: 0,
    crashSamples: [],
    isolation: 'none',
    command: '',
  };
}

/** A varied seed corpus per harness — protocol-shaped inputs for network daemons, generic bytes otherwise. */
const GENERIC_SEEDS = ['A', '0000', 'admin=1&x=2', '\x7fELF', '\x00\x01\x02\x03'];
const NETWORK_SEEDS = [
  'GET / HTTP/1.0\r\n\r\n',
  'POST /cgi-bin/test HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc',
  'USER admin\r\n',
  'M-SEARCH * HTTP/1.1\r\n\r\n',
];

/** Fuzz one rootfs binary for a bounded time under isolation, then report reproduced crashes (honest, no guess). */
export async function runFuzz(
  rootfsPath: string,
  binary: string,
  handle: JobHandle,
  opts: { seconds?: number; harness?: HarnessClass | 'auto' } = {},
): Promise<FuzzResult> {
  const seconds = opts.seconds ?? 60;
  if (!(await detectFuzzing())) {
    handle.log('AFL++ not installed — coverage-guided fuzzing unavailable (opt-in layer, like Ghidra).');
    return unavailable(binary, 'AFL++ not installed');
  }
  const abs = resolveInsideRootfs(rootfsPath, binary);
  if (!abs) return unavailable(binary, 'binary not found in rootfs');

  const harness: HarnessClass = !opts.harness || opts.harness === 'auto' ? chooseHarness(binary) : opts.harness;
  const stdinDelivery = harness !== 'file';

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-fuzz-'));
  const seeds = path.join(work, 'seeds');
  const out = path.join(work, 'out');
  fs.mkdirSync(seeds, { recursive: true });
  const corpus = harness === 'network' ? NETWORK_SEEDS : GENERIC_SEEDS;
  for (const [i, s] of corpus.entries()) fs.writeFileSync(path.join(seeds, `seed${i}`), s);

  // Real firmware binaries are dynamically linked (musl/uClibc). Point qemu-user at the rootfs so it resolves the
  // guest's own loader + libraries; without this, only static binaries run (execs stays 0).
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    AFL_SKIP_CPUFREQ: '1',
    AFL_NO_AFFINITY: '1',
    AFL_BENCH_UNTIL_CRASH: '1',
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES: '1',
    QEMU_LD_PREFIX: rootfsPath,
  };

  // The network harness needs a desock preload to turn the daemon's socket I/O into the fuzzed stdin.
  let harnessNote: string | undefined;
  if (harness === 'network') {
    const desock = detectDesockPreload();
    if (desock) {
      env.AFL_PRELOAD = desock;
      env.QEMU_SET_ENV = `LD_PRELOAD=${desock}`; // qemu-user passes this into the guest
      handle.log(`Network harness: desock preload ${desock} — socket I/O redirected to the fuzzed stdin.`);
    } else {
      harnessNote =
        'No desock preload (set FIRMLAB_DESOCK to a guest-arch libdesock) — fuzzing the daemon on raw stdin ' +
        'instead of its socket; a socket-only daemon may not consume the input. Honest degradation.';
      handle.log(harnessNote);
    }
  }

  // Dictionary from the binary's own strings — big fuzzing win for text protocols/parsers.
  const dictStrings = await rabin2Strings(abs);
  let dictPath: string | undefined;
  if (dictStrings.length > 0) {
    dictPath = path.join(work, 'dict.txt');
    fs.writeFileSync(dictPath, buildAflDict(dictStrings));
    handle.log(`Dictionary: ${dictStrings.length} strings from rabin2.`);
  }

  const argv = buildFuzzCommand(abs, seeds, out, seconds, {
    ...(dictPath ? { dictPath } : {}),
    stdin: stdinDelivery,
  });
  handle.log(`Fuzzing ${binary} for ${seconds}s under isolation [${harness} harness]: ${argv.join(' ')}`);

  try {
    const res = await runIsolated(argv, {
      // Fuzzing is memory-hungry (AFL's qemu maps a lot of virtual address space) — raise the AS cap for it.
      limits: { ...loadIsolationLimits(), addressSpaceBytes: 4096 * 1024 * 1024, wallMs: (seconds + 30) * 1000 },
      env,
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
      harness,
      ...(harnessNote ? { harnessNote } : {}),
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
