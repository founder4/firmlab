/**
 * AFL++ fuzzing provider (Phase 4). A coverage-guided fuzz of one extracted binary under AFL++'s qemu mode
 * (binary-only, no source), seeded with a corpus and a dictionary mined from the binary's own strings
 * (`rabin2 -z`), time-bounded, and run inside the Phase-4 isolation sandbox. Opt-in like Ghidra: when
 * afl-fuzz/afl-qemu-trace are absent it degrades honestly to `available:false` — it never pretends to have
 * fuzzed. A reproduced crash is real dynamic evidence (the caller records it as confirmed_in_emulation); no crash
 * is reported as no crash, not as "secure". AFL's qemu mode is host-arch: a cross-arch target is reported honestly.
 *
 * Per-class harnesses: the input-delivery method is chosen for the target, not fixed to file input.
 *   - `file`    — a parser that reads a path from argv: AFL substitutes the testcase file for `@@` (the default).
 *   - `stdin`   — a filter/CLI that reads stdin: no `@@`, AFL feeds the testcase on stdin.
 *   - `network` — a socket daemon (httpd/telnetd/…): a desock preload redirects the daemon's socket I/O to the
 *                 fuzzed stdin.
 *
 * `planFuzz` is the advanced rung, and it is a PLAN, not a promise: before anything runs it decides which qemu
 * comparison instrumentation this target can actually carry (CompCov via `AFL_COMPCOV_LEVEL`, CmpLog via `-c 0`
 * — AFL++ implements both for x86/x86_64/arm/aarch64 only, so a MIPS target gets plain qemu mode *with the
 * reason said out loud* rather than a silent downgrade), which channel the testcase reaches the target through,
 * and whether the target is runnable here at all. Three prerequisites are modelled rather than assumed:
 *
 *   - **The qemu CPU target.** AFL++'s qemu mode is built per CPU_TARGET. A cross-arch target needs an
 *     `afl-qemu-trace-<suffix>` build, driven through `AFL_QEMU_CUSTOM_BIN`; absent, the target is reported
 *     unfuzzable naming the build that would fix it, and is never quietly fed to the host's emulator.
 *   - **desock.** FirmLab ships NO prebuilt multi-arch libdesock and there is none lying around to point at: the
 *     preload has to be built for the GUEST arch and handed over in `FIRMLAB_DESOCK`. Its architecture is read
 *     from its own ELF header, because a wrong-arch preload is dropped by the guest loader without a word — the
 *     daemon then runs unpreloaded while the run still looks like a network fuzz.
 *   - **The target itself.** A shared object, a kernel module, a script or a non-ELF has no entry point qemu mode
 *     can run. That is reported as a reason, not as zero crashes.
 *
 * An empty crash set is never "clean": `fuzzCoverageStatement` states what the run covered — mode, channel, exec
 * count, wall-clock bound — and therefore what it does not claim. Zero execs is not zero crashes, and a run that
 * fed raw stdin to a socket-only daemon proves nothing about that daemon's parser.
 *
 * The plan, the ELF classifier, the command/dictionary builders and the coverage sentence are pure and
 * unit-tested; the runner composes them.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { type Architecture, decodeElfArch } from '@firmlab/core';
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
  /** The plan this run executed. Optional forever: results stored by an older build carry none. */
  plan?: FuzzPlan;
  /** What the run covered and what it refuses to claim — see `fuzzCoverageStatement`. Optional forever. */
  coverage?: string;
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

/** Comparison instrumentation for AFL++'s qemu mode. `plain` is qemu mode with edge coverage only. */
export type FuzzMode = 'plain' | 'compcov' | 'cmplog';

/**
 * The arches whose AFL++ qemu mode carries the comparison instrumentation CompCov and CmpLog. Upstream
 * implements both for x86, x86_64, arm and aarch64 and for nothing else, so the MIPS targets that make up most
 * of this corpus can only ever run plain qemu mode — a fact the plan states instead of discovering at runtime.
 */
export const CMP_INSTRUMENTED_ARCHES: readonly Architecture[] = ['x86', 'x86_64', 'arm', 'arm64'];

/**
 * arch → the `CPU_TARGET` suffix the matching `afl-qemu-trace-<suffix>` build carries. AFL++ compiles its qemu
 * once per CPU target; an arch missing from this map has no qemu-mode build to ask for at all.
 */
export const AFL_QEMU_TRACE_SUFFIX: Partial<Record<Architecture, string>> = {
  mips: 'mips',
  mipsel: 'mipsel',
  mips64: 'mips64',
  arm: 'arm',
  arm64: 'aarch64',
  x86: 'i386',
  x86_64: 'x86_64',
  ppc: 'ppc',
  riscv: 'riscv64',
};

/** What the target on disk actually is — the first question, because most of these are not fuzzable at all. */
export type TargetKind =
  | { kind: 'elf'; arch: Architecture; bits: number }
  | { kind: 'shared-object' }
  | { kind: 'not-elf'; detail: string }
  | { kind: 'unreadable' };

/**
 * Pure: classify a fuzz target from its path and its first 20 bytes. The path decides `.so`/`.ko` because a PIE
 * executable and a shared library share `ET_DYN` in the header — the name is the honest signal here; the bytes
 * decide ELF-ness and arch.
 */
export function classifyTarget(binaryPath: string, head: Buffer | null): TargetKind {
  if (/\.(?:so|ko)(?:\.\d+)*$/.test(binaryPath)) return { kind: 'shared-object' };
  if (!head || head.length < 20) return { kind: 'unreadable' };
  if (head[0] !== 0x7f || head[1] !== 0x45 || head[2] !== 0x4c || head[3] !== 0x46)
    return {
      kind: 'not-elf',
      detail:
        head[0] === 0x23 && head[1] === 0x21
          ? 'it starts with a #! shebang, i.e. it is a script'
          : `its magic is ${head.subarray(0, 4).toString('hex')}`,
    };
  const bits = head[4] === 2 ? 64 : 32;
  const endianBig = head[5] === 2;
  const machine = endianBig ? head.readUInt16BE(18) : head.readUInt16LE(18);
  const { arch } = decodeElfArch(machine, endianBig, bits);
  return { kind: 'elf', arch, bits };
}

/** A desock preload and the guest arch it was built for — both are prerequisites, and neither is assumed. */
export interface DesockAsset {
  path: string;
  /** Read from the `.so`'s own ELF header; `unknown` when it could not be read (treated as unusable). */
  arch: Architecture;
}

/** What this deployment can actually run, measured — never inferred from the fact that afl-fuzz exists. */
export interface FuzzDeployment {
  /** The arch the unsuffixed `afl-qemu-trace` runs natively. */
  hostArch: Architecture;
  /** Guest arches with an `afl-qemu-trace-<suffix>` build present here. */
  traceArches: readonly Architecture[];
  desock: DesockAsset | null;
}

export interface FuzzPlanInput {
  binary: string;
  target: TargetKind;
  seconds: number;
  harness?: HarnessClass | 'auto';
  mode?: FuzzMode | 'auto';
}

export interface FuzzPlan {
  fuzzable: boolean;
  /** Why this target cannot be fuzzed in this deployment. Set exactly when `fuzzable` is false. */
  blocked?: string;
  binary: string;
  arch: Architecture;
  harness: HarnessClass;
  /** Set when the harness could not be delivered as intended (e.g. a network daemon without a usable desock). */
  harnessNote?: string;
  /** The concrete input channel: how one testcase reaches the target, in one sentence. */
  inputChannel: string;
  mode: FuzzMode;
  /** Why this mode — including a requested mode that was refused, and what that costs. */
  modeNote: string;
  /** afl-fuzz arguments contributed by the mode. */
  modeArgs: string[];
  /** Environment contributed by the mode, the cross-arch qemu build and the desock preload. */
  env: Record<string, string>;
  /** The qemu binary to prepend under `AFL_QEMU_CUSTOM_BIN`, when the target is not host-arch. */
  qemuTraceBin?: string;
  /** What the run will and will not have covered, stated before it runs. */
  bounds: string;
}

const HARNESS_CHANNEL: Record<HarnessClass, string> = {
  file: 'One testcase file per exec, substituted for AFL’s `@@` in argv: the target opens and parses the path it is handed.',
  stdin:
    'One testcase per exec on the target’s stdin (no `@@`): a target that does not read stdin consumes nothing and the run tests nothing.',
  network: 'One testcase per exec on stdin, redirected into the daemon’s socket calls by the desock preload.',
};

/**
 * Pure: decide how (and whether) this target can be fuzzed here. Every branch that cannot fuzz says why in the
 * words of the thing that is missing, because "0 crashes" and "never ran" are the answers most easily confused.
 */
export function planFuzz(input: FuzzPlanInput, deployment: FuzzDeployment): FuzzPlan {
  const { binary, target, seconds } = input;
  const harness: HarnessClass = !input.harness || input.harness === 'auto' ? chooseHarness(binary) : input.harness;
  const requested = input.mode && input.mode !== 'auto' ? input.mode : null;

  const blocked = (reason: string, arch: Architecture = 'unknown'): FuzzPlan => ({
    fuzzable: false,
    blocked: reason,
    binary,
    arch,
    harness,
    inputChannel: 'None: no testcase was ever delivered, because the target was never runnable here.',
    mode: 'plain',
    modeNote: 'No mode applies — nothing ran.',
    modeArgs: [],
    env: {},
    bounds: `This run bounds nothing and says nothing about ${binary}: ${reason}`,
  });

  if (target.kind === 'shared-object')
    return blocked(
      `${binary} is a shared object or kernel module: it has no entry point for qemu mode to start. Fuzz a program that loads it, or build a harness that calls the export (exportreach lists them) — fuzzing it directly is not something this deployment declines, it is something AFL++ cannot do.`,
    );
  if (target.kind === 'unreadable')
    return blocked(
      `${binary} could not be read far enough to identify it (fewer than 20 bytes, or the read failed), so neither its format nor its architecture is known. That is a missing answer, not an empty one.`,
    );
  if (target.kind === 'not-elf')
    return blocked(
      `${binary} is not an ELF (${target.detail}). AFL++ qemu mode executes an ELF; to fuzz a script, fuzz its interpreter with the script as argv.`,
    );

  const arch = target.arch;
  if (arch === 'unknown')
    return blocked(
      `${binary} is an ELF whose e_machine FirmLab does not map to an architecture, so no qemu CPU target can be chosen for it.`,
      arch,
    );

  const native = arch === deployment.hostArch;
  const suffix = AFL_QEMU_TRACE_SUFFIX[arch];
  if (!native && !suffix)
    return blocked(
      `The target is ${arch} and the host runs ${deployment.hostArch}. AFL++'s qemu mode is built per CPU target and FirmLab maps no CPU target for ${arch}, so there is no afl-qemu-trace build to ask for.`,
      arch,
    );
  if (!native && !deployment.traceArches.includes(arch))
    return blocked(
      `The target is ${arch} and the host runs ${deployment.hostArch}. AFL++'s qemu mode is built per CPU target and this deployment has no afl-qemu-trace-${suffix}; building one (CPU_TARGET=${suffix}) makes this target fuzzable. Until then it is not fuzzed at all — it is never handed to the host-arch emulator, which would refuse the ELF anyway.`,
      arch,
    );

  const env: Record<string, string> = {};
  const modeArgs: string[] = [];
  const cmpCapable = CMP_INSTRUMENTED_ARCHES.includes(arch);
  const cmpList = CMP_INSTRUMENTED_ARCHES.join('/');
  const noCmpCost =
    'Multi-byte comparisons — magic values, length/checksum fields, string compares — stay unsolved, so input shapes behind them are unlikely ever to be reached.';

  let mode: FuzzMode;
  let modeNote: string;
  if (requested && requested !== 'plain' && !cmpCapable) {
    mode = 'plain';
    modeNote = `${requested} was requested and cannot be run: AFL++ implements CompCov and CmpLog in qemu mode for ${cmpList} only, and this target is ${arch}. Downgraded to plain qemu mode, said out loud rather than silently. ${noCmpCost}`;
  } else if (requested) {
    mode = requested;
    modeNote =
      requested === 'plain'
        ? `Plain qemu mode was requested explicitly${cmpCapable ? ` although ${arch} could carry CompCov/CmpLog` : ''}. ${noCmpCost}`
        : `${requested} was requested and ${arch} carries it.`;
  } else if (cmpCapable) {
    mode = 'cmplog';
    modeNote = `Auto: ${arch} carries qemu-mode comparison instrumentation, so CmpLog (-c 0, the target as its own cmplog binary) is used — it feeds the operands of comparisons back into mutation, which is what gets past magic values.`;
  } else {
    mode = 'plain';
    modeNote = `Auto: plain qemu mode, because AFL++ implements CompCov/CmpLog in qemu mode for ${cmpList} only and this target is ${arch}. Not a choice about this binary — a limit of the instrumentation. ${noCmpCost}`;
  }
  if (mode === 'compcov') env.AFL_COMPCOV_LEVEL = '2';
  if (mode === 'cmplog') modeArgs.push('-c', '0');

  let qemuTraceBin: string | undefined;
  if (!native && suffix) {
    qemuTraceBin = `afl-qemu-trace-${suffix}`;
    // afl-fuzz otherwise prepends its own host-arch afl-qemu-trace; this tells it we supply the emulator.
    env.AFL_QEMU_CUSTOM_BIN = '1';
  }

  let harnessNote: string | undefined;
  let inputChannel = HARNESS_CHANNEL[harness];
  if (harness === 'network') {
    const desock = deployment.desock;
    if (!desock)
      harnessNote = `No desock preload. FirmLab ships none — there is no prebuilt multi-arch libdesock to fall back on — so one built for ${arch} has to be pointed at by FIRMLAB_DESOCK. Without it the daemon is fed raw stdin: a socket-only daemon reads nothing, and the run then says nothing about its protocol parser.`;
    else if (desock.arch === 'unknown')
      harnessNote = `The desock preload ${desock.path} exists but its architecture could not be read from its ELF header, so it cannot be shown to match this ${arch} target. A wrong-arch preload is dropped by the guest loader without a word and the daemon runs unpreloaded, which looks exactly like a successful network fuzz — so it is treated as absent and the daemon is fed raw stdin.`;
    else if (desock.arch !== arch)
      harnessNote = `The desock preload ${desock.path} is ${desock.arch} and the target is ${arch}. The guest loader drops a wrong-arch preload silently, so using it would produce a run that claims to fuzz a socket while fuzzing nothing; the daemon is fed raw stdin instead, and a ${arch} libdesock in FIRMLAB_DESOCK is what fixes this.`;
    else {
      env.AFL_PRELOAD = desock.path;
      env.QEMU_SET_ENV = `LD_PRELOAD=${desock.path}`; // qemu-user passes this into the guest
      inputChannel = `One testcase per exec on stdin, redirected into the daemon's accept/recv by the ${arch} desock preload ${desock.path} (AFL_PRELOAD + QEMU_SET_ENV=LD_PRELOAD).`;
    }
    if (harnessNote)
      inputChannel = `One testcase per exec on the daemon's raw stdin; its SOCKET is not fuzzed (no usable desock preload).`;
  }

  return {
    fuzzable: true,
    binary,
    arch,
    harness,
    ...(harnessNote ? { harnessNote } : {}),
    inputChannel,
    mode,
    modeNote,
    modeArgs,
    env,
    ...(qemuTraceBin ? { qemuTraceBin } : {}),
    bounds: `Bounded by ${seconds}s of wall clock, ${mode} instrumentation, the built-in seed corpus (kept per run, never carried over or mutated between runs) and a dictionary of the binary's own strings when radare2 is present. Whatever those do not reach is unexamined — which is not the same as clean.`,
  };
}

/**
 * Pure: what the finished run covered, and what it therefore refuses to claim. An empty crash set is a bound, not
 * a verdict, and zero execs is a broken harness rather than a quiet binary — the two are reported as the
 * different answers they are.
 */
export function fuzzCoverageStatement(
  plan: FuzzPlan,
  outcome: { crashes: number; execsDone: number | null; seconds: number },
): string {
  if (!plan.fuzzable) return plan.bounds;
  const where = `${plan.mode} instrumentation, ${plan.harness} channel, ${outcome.seconds}s budget`;
  if (outcome.execsDone === 0)
    return `The fuzzer executed ${plan.binary} 0 times (${where}). Nothing was tested: this is a harness failure, not a result about the binary, and the crash count carries no information whatsoever.`;
  const execs = outcome.execsDone === null ? 'an unrecorded number of' : String(outcome.execsDone);
  const caveats: string[] = [];
  if (plan.mode === 'plain')
    caveats.push(
      'comparisons were not instrumented, so paths behind a magic value, a length field or a string compare were most likely never entered',
    );
  if (plan.harnessNote) caveats.push('the input arrived on raw stdin rather than through the socket the daemon reads');
  else if (plan.harness === 'stdin')
    caveats.push('a target that never reads stdin consumes nothing, and that is indistinguishable from this result');
  const tail = caveats.length > 0 ? ` Within that bound: ${caveats.join('; ')}.` : '';
  if (outcome.crashes > 0)
    return `${outcome.crashes} crashing input${outcome.crashes === 1 ? '' : 's'} reproduced in ${execs} execs (${where}) — dynamic evidence about the qemu-user sandbox, never about the physical device.${tail}`;
  return `No crash in ${execs} execs (${where}). That is the bound this run reached, not a verdict on ${plan.binary}: the seed corpus, the budget and the chosen channel decide what was executed at all, and everything outside them is unexamined rather than clean.${tail}`;
}

/** Pure: POSIX-quote one argument so the reported command line can be pasted into a shell unchanged. */
export function shellQuote(arg: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(arg) && arg.length > 0 ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}

/** Pure: the copy-pasteable command line — env prefix included, because the mode lives half in the env. */
export function formatFuzzCommand(argv: string[], env: Record<string, string> = {}): string {
  const prefix = Object.keys(env)
    .sort()
    .map((k) => `${k}=${shellQuote(env[k] ?? '')}`);
  return [...prefix, ...argv.map(shellQuote)].join(' ');
}

/**
 * Pure: the AFL++ qemu-mode invocation for a target. File input is delivered via the `@@` placeholder; the
 * `stdin` option drops `@@` so AFL feeds each testcase on stdin (also how the network/desock harness runs).
 * `modeArgs` carries the comparison instrumentation the plan chose (CmpLog's `-c 0`), and `qemuTraceBin` the
 * cross-arch emulator that goes in front of the target under `AFL_QEMU_CUSTOM_BIN`.
 */
export function buildFuzzCommand(
  target: string,
  seedsDir: string,
  outDir: string,
  seconds: number,
  opts: { dictPath?: string; stdin?: boolean; modeArgs?: string[]; qemuTraceBin?: string } = {},
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
    ...(opts.modeArgs ?? []),
    '--',
    ...(opts.qemuTraceBin ? [opts.qemuTraceBin] : []),
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

/**
 * Is there a fuzzer here at all? afl-fuzz plus a qemu-mode emulator — and the emulator may be a cross-arch
 * `afl-qemu-trace-<suffix>` build rather than the host one, which is the only emulator a MIPS corpus can use.
 * Requiring the unsuffixed binary reported "AFL++ not installed" on a deployment that could fuzz every image it holds.
 */
export async function detectFuzzing(): Promise<boolean> {
  if (!(await canRun('afl-fuzz'))) return false;
  return (await canRun('afl-qemu-trace')) || (await detectTraceArches()).length > 0;
}

/** node's `process.arch` → our `Architecture`, so "host arch" is measured rather than assumed to be x86_64. */
const HOST_ARCH: Record<string, Architecture> = {
  x64: 'x86_64',
  ia32: 'x86',
  arm64: 'arm64',
  arm: 'arm',
  mips: 'mips',
  mipsel: 'mipsel',
  ppc64: 'ppc',
  riscv64: 'riscv',
};

/** Pure: the architecture the unsuffixed `afl-qemu-trace` runs natively on this host. */
export function hostArch(nodeArch: string = process.arch): Architecture {
  return HOST_ARCH[nodeArch] ?? 'unknown';
}

/** Which guest arches this deployment has an `afl-qemu-trace-<suffix>` build for. Probed, never assumed. */
export async function detectTraceArches(): Promise<Architecture[]> {
  const found: Architecture[] = [];
  await Promise.all(
    Object.entries(AFL_QEMU_TRACE_SUFFIX).map(async ([arch, suffix]) => {
      if (await canRun(`afl-qemu-trace-${suffix}`)) found.push(arch as Architecture);
    }),
  );
  return found.sort();
}

/** Read the first 20 bytes of a file — enough for the ELF identification + `e_machine`. */
function readHead(file: string): Buffer | null {
  let fd: number | null = null;
  try {
    fd = fs.openSync(file, 'r');
    const head = Buffer.alloc(20);
    const read = fs.readSync(fd, head, 0, 20, 0);
    return read < 20 ? null : head;
  } catch {
    return null;
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
}

/**
 * A desock preload for the network harness — a compiled libdesock/libaflppdesock that redirects a daemon's
 * socket syscalls to stdin/stdout so AFL can fuzz "the network". Opt-in and arch-specific: `FIRMLAB_DESOCK`
 * points at a `.so` built for the GUEST arch, and nothing here ships one for any arch. The arch comes from the
 * `.so`'s own ELF header rather than from the operator's word, because a mismatched preload is dropped by the
 * guest loader in silence: the daemon then runs unpreloaded and the run still looks like a network fuzz.
 */
export function detectDesockPreload(env: NodeJS.ProcessEnv = process.env): DesockAsset | null {
  const p = env.FIRMLAB_DESOCK;
  if (!p) return null;
  const head = readHead(p);
  if (!head) return safeExists(p) ? { path: p, arch: 'unknown' } : null;
  const kind = classifyTarget('libdesock.bin', head); // path deliberately neutral: we want the header's verdict
  return { path: p, arch: kind.kind === 'elf' ? kind.arch : 'unknown' };
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

function unavailable(binary: string, reason: string, plan?: FuzzPlan): FuzzResult {
  return {
    available: false,
    reason,
    binary,
    harness: plan?.harness ?? 'file',
    seconds: 0,
    execsDone: null,
    crashes: 0,
    crashSamples: [],
    isolation: 'none',
    command: '',
    ...(plan ? { plan, coverage: plan.bounds } : {}),
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
  opts: { seconds?: number; harness?: HarnessClass | 'auto'; mode?: FuzzMode | 'auto' } = {},
): Promise<FuzzResult> {
  const seconds = opts.seconds ?? 60;
  if (!(await detectFuzzing())) {
    handle.log('AFL++ not installed — coverage-guided fuzzing unavailable (opt-in layer, like Ghidra).');
    return unavailable(binary, 'AFL++ not installed');
  }
  const abs = resolveInsideRootfs(rootfsPath, binary);
  if (!abs) return unavailable(binary, 'binary not found in rootfs');

  const plan = planFuzz(
    {
      binary,
      target: classifyTarget(binary, readHead(abs)),
      seconds,
      ...(opts.harness ? { harness: opts.harness } : {}),
      ...(opts.mode ? { mode: opts.mode } : {}),
    },
    { hostArch: hostArch(), traceArches: await detectTraceArches(), desock: detectDesockPreload() },
  );
  if (!plan.fuzzable) {
    const reason = plan.blocked ?? 'target not fuzzable here';
    handle.log(reason);
    return unavailable(binary, reason, plan);
  }
  const harness = plan.harness;
  const stdinDelivery = harness !== 'file';
  handle.log(`Mode: ${plan.modeNote}`);
  handle.log(`Input channel: ${plan.inputChannel}`);

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
    ...plan.env,
  };
  const harnessNote = plan.harnessNote;
  if (harnessNote) handle.log(harnessNote);

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
    modeArgs: plan.modeArgs,
    ...(plan.qemuTraceBin ? { qemuTraceBin: plan.qemuTraceBin } : {}),
  });
  // Quoted, not joined: a rootfs path with a space in it made the logged line unrunnable exactly when someone
  // wanted to rerun it by hand.
  handle.log(
    `Fuzzing ${binary} for ${seconds}s under isolation [${harness} harness, ${plan.mode}]: ${formatFuzzCommand(argv, plan.env)}`,
  );

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
    const coverage = fuzzCoverageStatement(plan, { crashes, execsDone, seconds });
    handle.log(coverage);
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
      plan,
      coverage,
    };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}
