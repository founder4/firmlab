/**
 * Dynamic-probe runner — drives qemu-user's gdbstub with gdb-multiarch.
 *
 * The judgement lives in dynprobe.ts; this only orchestrates two processes. The shape is: start the target under
 * `qemu-<arch>-static -L <rootfs> -g <port>` (which halts before the first instruction, waiting for a client),
 * attach gdb-multiarch with a generated batch script, collect its output, and make sure the emulator is dead
 * afterwards on every path — a stranded qemu holding a port would break the next run.
 */
import { type ChildProcess, execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import type { Architecture } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';
import { isToolAvailable } from '../tools.js';
import {
  DEFAULT_PATTERN_LEN,
  MAX_PATTERN_LEN,
  type ProbeResult,
  buildDynFindings,
  buildGdbScript,
  classifyRun,
  cyclicPattern,
  parseGdbOutput,
} from './dynprobe.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

/** qemu-user binary per guest architecture — the same mapping the emulation provider uses. */
const QEMU_BY_ARCH: Partial<Record<Architecture, string>> = {
  mipsel: 'qemu-mipsel-static',
  mips: 'qemu-mips-static',
  arm: 'qemu-arm-static',
  arm64: 'qemu-aarch64-static',
  x86: 'qemu-i386-static',
  x86_64: 'qemu-x86_64-static',
};

/**
 * Argument registers to snapshot per architecture, and which of them holds the source pointer of a copy.
 * MIPS passes in `a0..a3` with the return address in `ra`; ARM in `r0..r3` with `lr`; x86-64 in `rdi/rsi`.
 */
const ABI: Partial<Record<Architecture, { args: string[]; stringArg?: string }>> = {
  mipsel: { args: ['ra', 'sp', 'a0', 'a1'], stringArg: 'a1' },
  mips: { args: ['ra', 'sp', 'a0', 'a1'], stringArg: 'a1' },
  arm: { args: ['lr', 'sp', 'r0', 'r1'], stringArg: 'r1' },
  arm64: { args: ['lr', 'sp', 'x0', 'x1'], stringArg: 'x1' },
  x86_64: { args: ['rsp', 'rdi', 'rsi'], stringArg: 'rsi' },
  x86: { args: ['esp', 'eax', 'edx'] },
};

const GDB_TIMEOUT_MS = 120 * 1000;
/** A high, fixed-ish port. Randomising it would need Math.random, and one probe runs at a time per job anyway. */
const BASE_PORT = 14500;

export interface DynProbeResult {
  available: boolean;
  reason: string;
  binary: string;
  sink: string;
  arch: string;
  patternLength: number;
  probe: ProbeResult | null;
  findings: FindingDraft[];
}

function unavailable(binary: string, sink: string, arch: string, reason: string): DynProbeResult {
  return {
    available: false,
    reason,
    binary,
    sink,
    arch,
    patternLength: 0,
    probe: null,
    findings: [
      {
        kind: 'memory-safety-probe-blocked',
        title: `Dynamic reproduction of ${sink} in ${binary} could not run`,
        severity: 'info',
        proofState: 'blocked_by_platform',
        evidence: { binary, sink, arch, reason },
        rationale:
          'The reproduction was attempted and this deployment could not perform it. Recorded so the absence of a ' +
          'confirmed crash reads as a missing capability rather than as evidence the binary is sound.',
      },
    ],
  };
}

/**
 * Reproduce one memory-safety candidate under emulation.
 *
 * `addresses` are the sink call sites — normally taken straight from the `symreach` finding that proved the sink
 * reachable, so the dynamic probe targets exactly the call site the static claim was made about.
 */
export async function runDynProbe(
  rootfsPath: string | null,
  binary: string,
  sink: string,
  addresses: string[],
  arch: Architecture,
  handle: JobHandle,
  patternLength = DEFAULT_PATTERN_LEN,
): Promise<DynProbeResult> {
  const emulator = QEMU_BY_ARCH[arch];
  if (!rootfsPath) return unavailable(binary, sink, arch, 'no extracted rootfs');
  if (!emulator) return unavailable(binary, sink, arch, `no qemu-user emulator mapped for arch "${arch}"`);
  if (!(await isToolAvailable('gdb-multiarch'))) {
    handle.log('gdb-multiarch not available — rebuild the tools base to enable dynamic reproduction.');
    return unavailable(binary, sink, arch, 'gdb-multiarch is not installed in this deployment');
  }

  const rootfsAbs = path.resolve(rootfsPath);
  const absTarget = path.resolve(rootfsAbs, binary);
  // Same confinement rule the emulation provider enforces: never execute outside the extracted tree.
  if (!absTarget.startsWith(rootfsAbs + path.sep) || !fs.existsSync(absTarget)) {
    return unavailable(binary, sink, arch, `binary not found inside the rootfs: ${binary}`);
  }
  if (addresses.length === 0) return unavailable(binary, sink, arch, 'no sink address to break on');

  const len = Math.min(MAX_PATTERN_LEN, Math.max(16, patternLength));
  const pattern = cyclicPattern(len);
  const abi = ABI[arch] ?? { args: ['sp'] };
  const port = BASE_PORT;

  const script = buildGdbScript({
    sysroot: rootfsAbs,
    addresses,
    argRegisters: abi.args,
    port,
    ...(abi.stringArg ? { stringArgRegister: abi.stringArg } : {}),
  });
  const workDir = fs.mkdtempSync(path.join(path.dirname(rootfsAbs), 'firmlab-dyn-'));
  const scriptPath = path.join(workDir, 'probe.gdb');
  fs.writeFileSync(scriptPath, script);

  let qemu: ChildProcess | null = null;
  try {
    handle.log(`${emulator}: running ${binary} under a gdbstub with a ${len}-byte cyclic input.`);
    qemu = spawn(emulator, ['-L', rootfsAbs, '-g', String(port), absTarget, pattern], { stdio: 'ignore' });
    qemu.on('error', () => undefined);
    // The stub listens before executing anything, but the process still needs a moment to bind.
    await new Promise((r) => setTimeout(r, 1500));

    let stdout = '';
    try {
      const r = await execFileAsync('gdb-multiarch', ['-batch', '-x', scriptPath, absTarget], {
        timeout: GDB_TIMEOUT_MS,
        maxBuffer: 16 * 1024 * 1024,
      });
      stdout = r.stdout;
    } catch (err) {
      // gdb exits non-zero on plenty of normal paths (a script command failing after the target died, say), and
      // its stdout up to that point is exactly what we came for.
      const e = err as { stdout?: string; message?: string };
      stdout = e.stdout ?? '';
      if (!stdout.trim()) {
        return unavailable(binary, sink, arch, `gdb produced no output: ${e.message ?? 'unknown failure'}`);
      }
    }

    const probe = classifyRun(parseGdbOutput(stdout), pattern);
    handle.log(`${binary}:${sink} → ${probe.verdict}`);
    handle.log(probe.reason);

    return {
      available: true,
      reason: probe.reason,
      binary,
      sink,
      arch,
      patternLength: len,
      probe,
      findings: buildDynFindings(binary, sink, probe),
    };
  } finally {
    // Guaranteed teardown: a surviving qemu keeps the gdb port and would silently break the next probe.
    try {
      qemu?.kill('SIGKILL');
    } catch {}
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}
