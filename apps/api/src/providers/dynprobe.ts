/**
 * Dynamic reproduction — the missing rung of the proof ladder.
 *
 * Across this corpus, **75% of every finding FirmLab produces sits at `needs_runtime_reproduction`**. That is not
 * a reporting quirk; it is the honest ceiling of static analysis. `binvuln` finds a precondition (an unbounded
 * copy with no canary). `symreach` proves the sink is on a live path from the entry point. Neither can say the
 * program actually misbehaves, so both stop short — correctly — and the lead stays a lead forever.
 *
 * This runs the binary. qemu-user already ships here and exposes a gdbstub (`-g PORT`), so gdb-multiarch can
 * breakpoint the sink, watch it execute against a real input, and read the registers when it faults. Three claims
 * become available, in increasing strength:
 *
 *  1. **The sink executed.** The call site ran with this input — a runtime fact, stronger than symreach's static
 *     reachability, and the first thing here that is not an assertion about bytes at rest.
 *  2. **The program crashed.** A fault under this input, with the signal and faulting address recorded.
 *  3. **The crash is input-controlled.** The faulting PC contains bytes from the cyclic pattern that was fed in,
 *     which means the input reached the saved return address. That is a memory-safety confirmation, and the
 *     offset is derivable from the pattern — self-evidencing rather than asserted.
 *
 * Three things this deliberately does NOT do:
 *
 *  - **It is not a device claim.** Everything here happens under qemu-user, so the proof state is
 *    `confirmed_in_emulation` and never higher. The emulator is not the router: different libc, no NVRAM, no
 *    peripherals. A crash proves the sandbox crashed.
 *  - **It is not an exploit.** Finding the offset of the saved return address is crash triage — it is what a
 *    crash report contains. FirmLab stops there by design (docs/BACKLOG.md, out of scope): no ROP chain, no
 *    shellcode, no working PoC.
 *  - **It never reads a non-crash as safety.** A binary that ran clean did so on ONE input, under an emulator
 *    that diverges from the device in ways that routinely suppress faults. And an emulation artefact — a missing
 *    library, an unimplemented syscall, a fault before the sink was ever reached — is reported as the artefact it
 *    is, not as a negative result.
 *
 * Everything here is pure and unit-tested; the runner (dynprobe-run.ts) supplies gdb's output.
 */
import type { FindingDraft } from '../findings-normalize.js';

/** How much input to feed by default. Long enough to overflow a typical stack buffer, short enough to stay sane. */
export const DEFAULT_PATTERN_LEN = 400;
export const MAX_PATTERN_LEN = 4096;

/**
 * Pure: the classic cyclic pattern (`Aa0Aa1Aa2…`), whose every 4-byte window is unique.
 *
 * Uniqueness is the point: when the faulting PC turns out to be four bytes of this, the offset those bytes sat at
 * in the input is recoverable, which turns "it crashed" into "the input reached the saved return address at
 * offset N" — a fact the operator can check rather than take on trust.
 */
export function cyclicPattern(length: number): string {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';
  let out = '';
  for (const a of upper) {
    for (const b of lower) {
      for (const c of digits) {
        out += a + b + c;
        if (out.length >= length) return out.slice(0, length);
      }
    }
  }
  return out.slice(0, length);
}

/**
 * Pure: where a 32-bit register value sits in the pattern, or null.
 *
 * The register is read as a number, so its bytes must be laid back out in the target's byte order before they can
 * be looked for — a little-endian target loads `"Ag8A"` from memory and shows it as `0x41386741`. Both orders are
 * tried and the one that hits is reported, because guessing wrong would silently turn a real hit into "no match".
 */
export function patternOffset(
  value: number,
  pattern: string,
): { offset: number; bytes: string; endian: 'little' | 'big' } | null {
  const be = [24, 16, 8, 0].map((s) => (value >>> s) & 0xff);
  const le = [...be].reverse();
  for (const [endian, bytes] of [
    ['little', le],
    ['big', be],
  ] as const) {
    if (bytes.some((b) => b < 0x20 || b > 0x7e)) continue;
    const needle = String.fromCharCode(...bytes);
    const offset = pattern.indexOf(needle);
    // Only a UNIQUE occurrence is an offset. A repeated window would make the answer arbitrary.
    if (offset >= 0 && pattern.indexOf(needle, offset + 1) < 0) return { offset, bytes: needle, endian };
  }
  return null;
}

/** One breakpoint hit, as the probe records it. */
export interface SinkHit {
  address: string;
  /** The register snapshot at the hit — `pc`, `ra`/`lr`, `sp` and the first argument registers. */
  registers: Record<string, string>;
  /** The string the sink was handed, when it could be read (bounded). */
  argument?: string;
}

export interface ProbeStop {
  pc: number;
  signal: string;
}

export interface GdbParse {
  /** The target reached the gdbstub and gdb attached at all. */
  attached: boolean;
  hits: SinkHit[];
  stop: ProbeStop | null;
  exited: boolean;
  exitCode?: number;
  /** Lines gdb emitted that indicate the EMULATOR failed, not the target — see `classifyRun`. */
  emulationWarnings: string[];
}

const HEX = (s: string): number => Number.parseInt(s, 16);

/**
 * Pure: parse gdb's batch output.
 *
 * The markers (`FIRMLAB_HIT` / `FIRMLAB_STOP`) are emitted by the script this module builds, so they are stable;
 * everything else keys off gdb's own wording, taken from a real run against DVRF under qemu-mipsel.
 */
export function parseGdbOutput(text: string): GdbParse {
  const hits: SinkHit[] = [];
  const emulationWarnings: string[] = [];
  // Tracked as two independent scalars: gdb prints the faulting address and the signal on SEPARATE lines, so
  // neither is complete on its own and composing them at the end avoids a half-built stop record.
  let stopPc: number | null = null;
  let stopSignal: string | null = null;
  let exited = false;
  let exitCode: number | undefined;
  let attached = false;

  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;

    if (/Remote debugging using|target remote/i.test(line)) attached = true;

    // `FIRMLAB_HIT addr=0x400a30 pc=0x400a30 ra=0x400820 sp=0x7ffff000 a0=0x... a1=0x...`
    const hit = /^FIRMLAB_HIT\s+(.*)$/.exec(line);
    if (hit) {
      const kv: Record<string, string> = {};
      for (const m of (hit[1] as string).matchAll(/(\w+)=(\S+)/g)) kv[m[1] as string] = m[2] as string;
      const address = kv.addr ?? kv.pc ?? '?';
      delete kv.addr;
      hits.push({ address, registers: kv });
      attached = true;
      continue;
    }
    // `FIRMLAB_ARG "the string the sink was handed"` — attaches to the most recent hit.
    const arg = /^FIRMLAB_ARG\s+(.*)$/.exec(line);
    if (arg && hits.length > 0) {
      (hits[hits.length - 1] as SinkHit).argument = (arg[1] as string).replace(/^"|"$/g, '').slice(0, 200);
      continue;
    }

    // gdb's own words, verbatim from a real run: `Program stopped at 0x41386741.` / `It stopped with signal SIGSEGV, …`
    const at = /Program stopped at (0x[0-9a-fA-F]+)/.exec(line);
    if (at) stopPc = HEX((at[1] as string).slice(2));
    const sig = /stopped with signal (SIG\w+)/.exec(line) ?? /received signal (SIG\w+)/.exec(line);
    if (sig) stopSignal = sig[1] as string;

    const ex = /exited (?:normally|with code (\d+))/.exec(line);
    if (ex) {
      exited = true;
      if (ex[1]) exitCode = Number.parseInt(ex[1], 10);
    }

    // The emulator failing is not the target misbehaving, and the two must not be confused.
    if (/Unsupported syscall|unimplemented|Could not load shared library|No such file or directory/i.test(line)) {
      emulationWarnings.push(line.slice(0, 200));
    }
  }

  const stop: ProbeStop | null =
    stopPc !== null || stopSignal !== null ? { pc: stopPc ?? 0, signal: stopSignal ?? 'unknown' } : null;
  return { attached, hits, stop, exited, ...(exitCode !== undefined ? { exitCode } : {}), emulationWarnings };
}

export type ProbeVerdict =
  | 'crash_input_controlled'
  | 'crash'
  | 'sink_executed'
  | 'ran_clean'
  | 'emulation_artifact'
  | 'not_attached';

export interface ProbeResult {
  verdict: ProbeVerdict;
  reason: string;
  hits: SinkHit[];
  stop: ProbeStop | null;
  /** Where the faulting PC's bytes sat in the input, when the crash is input-controlled. */
  controlOffset?: { offset: number; bytes: string; endian: 'little' | 'big' };
  emulationWarnings: string[];
}

/**
 * Pure: turn a parsed run into a verdict.
 *
 * The ordering encodes what may be claimed. A crash whose PC is input bytes is the strongest available result; a
 * crash with no sink hit and emulator warnings is most likely the emulator, and is reported as such rather than
 * counted as a reproduction. A run that neither hit nor crashed says only that THIS input did nothing — which is
 * not a statement about the binary.
 */
export function classifyRun(parse: GdbParse, pattern: string): ProbeResult {
  const base = { hits: parse.hits, stop: parse.stop, emulationWarnings: parse.emulationWarnings };

  if (!parse.attached && parse.hits.length === 0 && !parse.stop) {
    return {
      ...base,
      verdict: 'not_attached',
      reason:
        'gdb never attached to the emulated process, so nothing was observed at all. This is a failure of the ' +
        'harness, not a result about the binary.',
    };
  }

  if (parse.stop && /SIGSEGV|SIGBUS|SIGILL/.test(parse.stop.signal)) {
    const control = patternOffset(parse.stop.pc, pattern);
    if (control) {
      return {
        ...base,
        verdict: 'crash_input_controlled',
        controlOffset: control,
        reason: `The program faulted with ${parse.stop.signal} at 0x${parse.stop.pc.toString(16)}, and those four bytes are "${control.bytes}" from the input pattern at offset ${control.offset}. The input reached the saved return address: this is a memory-safety bug reproduced under emulation, not an inference.`,
      };
    }
    // A fault with no sink hit and the emulator complaining is most likely the emulator.
    if (parse.hits.length === 0 && parse.emulationWarnings.length > 0) {
      return {
        ...base,
        verdict: 'emulation_artifact',
        reason: `The process died with ${parse.stop.signal} without ever reaching the sink, and the emulator reported problems of its own (${parse.emulationWarnings[0]}). That is the emulation failing, not a reproduced bug — and it is not evidence the binary is sound either.`,
      };
    }
    return {
      ...base,
      verdict: 'crash',
      reason: `The program faulted with ${parse.stop.signal} at 0x${parse.stop.pc.toString(16)} on this input. The faulting address is not input bytes, so the input did not (or did not visibly) reach the saved return address — a real crash, but not a demonstrated control of execution.`,
    };
  }

  if (parse.hits.length > 0) {
    return {
      ...base,
      verdict: 'sink_executed',
      reason: `The sink executed ${parse.hits.length} time(s) under this input and the program did not fault. The call site really does run with attacker-supplied data — a runtime fact, stronger than static reachability — but nothing here shows it misbehaving.`,
    };
  }

  if (parse.emulationWarnings.length > 0) {
    return {
      ...base,
      verdict: 'emulation_artifact',
      reason: `The sink was never reached and the emulator reported problems (${parse.emulationWarnings[0]}). Nothing was learned about the binary.`,
    };
  }

  return {
    ...base,
    verdict: 'ran_clean',
    reason:
      'The program ran to completion without reaching the sink and without faulting. That is a statement about ' +
      'THIS ONE input under an emulator, not about the binary: a different input, or the real device, may behave ' +
      'differently.',
  };
}

/**
 * Pure: the gdb batch script.
 *
 * Breakpoints are set on ADDRESSES rather than symbol names, because that is what the upstream providers already
 * produce — `symreach` records the PLT/symbol address it asked about, and reusing it keeps the dynamic probe
 * pointed at exactly the sink the static claim was made about.
 */
export function buildGdbScript(input: {
  sysroot: string;
  addresses: string[];
  /** Register names to snapshot at each hit; the argument registers differ by architecture. */
  argRegisters: string[];
  port: number;
  /** The register that holds a pointer to the copied string, when the arch's ABI makes that knowable. */
  stringArgRegister?: string;
}): string {
  const regs = ['pc', ...input.argRegisters];
  const fmt = regs.map((r) => `${r}=%#x`).join(' ');
  const args = regs.map((r) => `$${r}`).join(', ');
  const lines = [
    'set confirm off',
    'set pagination off',
    'set height 0',
    `set sysroot ${input.sysroot}`,
    `target remote :${input.port}`,
  ];
  for (const a of input.addresses) lines.push(`break *${a}`);
  // Bounded: a sink inside a loop would otherwise stop forever. Each iteration prints its snapshot and continues.
  lines.push('set $n = 0');
  lines.push('while $n < 8');
  lines.push('  continue');
  lines.push(`  printf "FIRMLAB_HIT addr=%#x ${fmt}\\n", $pc, ${args}`);
  if (input.stringArgRegister) lines.push(`  printf "FIRMLAB_ARG "\n  x/s $${input.stringArgRegister}`);
  lines.push('  set $n = $n + 1');
  lines.push('end');
  lines.push('continue');
  lines.push('info program');
  return lines.join('\n');
}

/**
 * Pure: findings for one dynamic probe.
 *
 * `confirmed_in_emulation` is the ceiling and it is used deliberately: the sandbox is not the device. Nothing here
 * ever produces a clean result — `ran_clean` and `emulation_artifact` both emit a note saying what was and was not
 * shown, because a probe that found nothing is the case most likely to be misread as safety.
 */
export function buildDynFindings(binary: string, sink: string, r: ProbeResult): FindingDraft[] {
  const shared = {
    binary,
    sink,
    verdict: r.verdict,
    ...(r.stop ? { signal: r.stop.signal, faultPc: `0x${r.stop.pc.toString(16)}` } : {}),
    ...(r.emulationWarnings.length ? { emulationWarnings: r.emulationWarnings.slice(0, 3) } : {}),
  };

  if (r.verdict === 'crash_input_controlled') {
    return [
      {
        kind: 'memory-safety-reproduced',
        title: `${binary}: ${sink} overflow reproduced — input controls the saved return address at offset ${r.controlOffset?.offset}`,
        severity: 'critical',
        proofState: 'confirmed_in_emulation',
        evidence: { ...shared, controlOffset: r.controlOffset, hits: r.hits.length },
        rationale: `${r.reason} The proof state is confirmed_in_emulation and stops there on purpose: this ran under qemu-user, which has a different libc, no NVRAM and no peripherals, so it demonstrates the sandbox crashing rather than the device. FirmLab reports the offset because that is what crash triage is; it does not build a working exploit.`,
      },
    ];
  }

  if (r.verdict === 'crash') {
    return [
      {
        kind: 'memory-safety-crash',
        title: `${binary}: crashed (${r.stop?.signal}) while exercising ${sink}`,
        severity: 'high',
        proofState: 'confirmed_in_emulation',
        evidence: { ...shared, hits: r.hits.length },
        rationale: `${r.reason} Reproduced under qemu-user, so it is a claim about the sandbox, not the device.`,
      },
    ];
  }

  if (r.verdict === 'sink_executed') {
    return [
      {
        kind: 'sink-executed-at-runtime',
        title: `${binary}: ${sink} executed at runtime with the supplied input`,
        severity: 'medium',
        proofState: 'confirmed_in_emulation',
        evidence: { ...shared, hits: r.hits.length, sample: r.hits[0]?.argument },
        rationale: `${r.reason} This upgrades the static reachability claim to an observed execution, and no further: the copy was not shown to overflow anything.`,
      },
    ];
  }

  // Nothing shown — the case most likely to be misread as safety, so it is stated rather than left silent.
  return [
    {
      kind: 'memory-safety-not-reproduced',
      title: `${binary}: ${sink} was not reproduced under emulation — this is not a clean result`,
      severity: 'info',
      proofState: 'needs_runtime_reproduction',
      evidence: { ...shared, hits: r.hits.length },
      rationale: `${r.reason} The candidate keeps its needs-reproduction state: one input under one emulator that diverges from the device is nowhere near enough to call the binary sound. Fuzzing it, or driving it with a realistic input, is the next rung.`,
    },
  ];
}
