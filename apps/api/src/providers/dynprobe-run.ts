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
import net from 'node:net';
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
/** How long to wait for the emulator's gdbstub to accept connections before giving up on it. */
const STUB_WAIT_MS = 8000;
/** Ceiling on the target's captured stderr. A program in a loop must not be able to grow this without bound. */
const TARGET_STDERR_CAP = 64 * 1024;

/**
 * Ask the OS for a free port.
 *
 * This used to be a constant, 14500, justified by "one probe runs at a time per job anyway" — true per job, and
 * false the moment W9 schedules reproductions in two scans at once, which the job runner happily does at its
 * default concurrency of 2. Reproduced deliberately: two probes launched together, the first returns a verdict and
 * the second reports "gdb produced no output" even when its target is the binary this workbench crashes most
 * reliably. The blocked probe was the GOOD outcome. The bad one is available on the same constant: gdb connecting
 * to the other probe's stub and returning a verdict about a different binary entirely, attributed to this one.
 */
async function allocatePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => (port ? resolve(port) : reject(new Error('could not allocate a port'))));
    });
  });
}

/**
 * Wait until the emulator has actually taken the port — WITHOUT connecting to it.
 *
 * The obvious readiness check is to connect and hang up, and it is wrong here in a way that only a real run shows:
 * qemu's gdbstub accepts exactly ONE client. Probing it by connecting consumes that accept, qemu sees its debugger
 * attach and immediately drop, and the gdb that follows finds nothing — which reported as "gdb produced no output"
 * and turned a fix for the port collision into a harness that failed BOTH concurrent probes instead of one.
 *
 * So readiness is tested by trying to bind the port ourselves. While qemu holds it the bind fails with EADDRINUSE,
 * which is the signal; while it does not, the bind succeeds and we hand the port straight back and wait again.
 */
async function waitForStub(port: number, timeoutMs = STUB_WAIT_MS): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const taken = await new Promise<boolean>((resolve) => {
      const srv = net.createServer();
      srv.once('error', (err: NodeJS.ErrnoException) => resolve(err.code === 'EADDRINUSE'));
      srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(false)));
    });
    if (taken) return true;
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

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
  const port = await allocatePort();

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
  let targetStderr = '';
  let stderrTruncated = false;
  try {
    handle.log(`${emulator}: running ${binary} under a gdbstub on port ${port} with a ${len}-byte cyclic input.`);
    // stderr is PIPED, not ignored. It was ignored, and that discarded the target's own account of why it died:
    // DVRF's `diag_tracertbutton` exits printing `/dev/nvram: No such file or directory` and was graded
    // `ran_clean`, identical to a genuinely uneventful run. Bounded, because a chatty target must not be able to
    // grow this without limit, and truncation is recorded rather than silent.
    qemu = spawn(emulator, ['-L', rootfsAbs, '-g', String(port), absTarget, pattern], {
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    qemu.on('error', () => undefined);
    qemu.stderr?.on('error', () => undefined);
    qemu.stderr?.on('data', (chunk: Buffer) => {
      if (targetStderr.length >= TARGET_STDERR_CAP) {
        if (!stderrTruncated) {
          stderrTruncated = true;
          targetStderr += `\n[FirmLab: the target's stderr passed ${TARGET_STDERR_CAP} bytes and the rest was dropped]`;
        }
        return;
      }
      targetStderr += chunk.toString('utf8');
    });
    // The stub listens before executing anything, but the process still needs a moment to bind — so wait for the
    // socket rather than for a guessed interval, and say so when it never comes up.
    if (!(await waitForStub(port))) {
      return unavailable(
        binary,
        sink,
        arch,
        `the emulator's gdbstub never accepted a connection on port ${port} within ${STUB_WAIT_MS}ms — the target may have failed to load under ${emulator}`,
      );
    }

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

    const probe = classifyRun(parseGdbOutput(stdout), pattern, targetStderr);
    handle.log(`${binary}:${sink} → ${probe.verdict}`);
    handle.log(probe.reason);
    for (const d of probe.environmentFailures.slice(0, 5)) handle.log(`  target stderr (sandbox): ${d}`);

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
