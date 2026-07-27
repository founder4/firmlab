import { describe, expect, it } from 'vitest';
import {
  buildDynFindings,
  buildGdbScript,
  classifyRun,
  cyclicPattern,
  parseGdbOutput,
  patternOffset,
} from './dynprobe.js';

describe('cyclicPattern', () => {
  it('produces the classic pattern at the requested length', () => {
    expect(cyclicPattern(12)).toBe('Aa0Aa1Aa2Aa3');
    expect(cyclicPattern(400)).toHaveLength(400);
  });

  it('every 4-byte window is unique — which is what makes an offset recoverable', () => {
    const p = cyclicPattern(400);
    const seen = new Set<string>();
    for (let i = 0; i + 4 <= p.length; i++) seen.add(p.slice(i, i + 4));
    expect(seen.size).toBe(p.length - 3);
  });
});

describe('patternOffset', () => {
  // Verbatim from the real DVRF run under qemu-mipsel: `Program stopped at 0x41386741.`
  it('recovers the offset from the real mipsel fault value', () => {
    const p = cyclicPattern(400);
    const hit = patternOffset(0x41386741, p);
    expect(hit).not.toBeNull();
    expect(hit?.endian).toBe('little');
    expect(p.slice(hit?.offset as number, (hit?.offset as number) + 4)).toBe(hit?.bytes);
  });

  it('returns null for a value that is not printable input bytes', () => {
    expect(patternOffset(0x00400a30, cyclicPattern(400))).toBeNull();
  });

  it('refuses an ambiguous window rather than picking one arbitrarily', () => {
    // 'AAAA' occurs many times, so no single offset is the answer.
    expect(patternOffset(0x41414141, 'AAAAAAAAAAAA')).toBeNull();
  });
});

describe('parseGdbOutput — against gdb 13.1 batch output', () => {
  // Verbatim from the real DVRF run. gdb reports a fault across two lines and the address is on the SECOND.
  // The first real run of this probe read `info program`'s later wording instead and reported 0x0, because by
  // then the script had continued past the fault.
  it('takes the faulting PC from the frame line that follows the signal', () => {
    const p = parseGdbOutput(
      [
        'Breakpoint 1, 0x00400a30 in strcpy ()',
        'FIRMLAB_HIT addr=0x400a30 pc=0x400a30 ra=0x4008e0',
        '',
        'Program received signal SIGSEGV, Segmentation fault.',
        '0x41386741 in ?? ()',
      ].join('\n'),
    );
    expect(p.hits).toHaveLength(1);
    expect(p.stop).toEqual({ pc: 0x41386741, signal: 'SIGSEGV' });
  });

  it('keeps the FIRST fault — re-delivering the signal must not overwrite the answer', () => {
    const p = parseGdbOutput(
      [
        'Program received signal SIGSEGV, Segmentation fault.',
        '0x41386741 in ?? ()',
        'Program received signal SIGSEGV, Segmentation fault.',
        '0x0 in ?? ()',
        'Program stopped at 0x0.',
      ].join('\n'),
    );
    expect(p.stop?.pc).toBe(0x41386741);
  });

  it('reads a crash: gdb prints the address and the signal on separate lines', () => {
    const p = parseGdbOutput(
      [
        'Remote debugging using :14500',
        'Program stopped at 0x41386741.',
        'It stopped with signal SIGSEGV, Segmentation fault.',
      ].join('\n'),
    );
    expect(p.attached).toBe(true);
    expect(p.stop).toEqual({ pc: 0x41386741, signal: 'SIGSEGV' });
  });

  it('reads sink hits and the string the sink was handed', () => {
    const p = parseGdbOutput(
      [
        'FIRMLAB_HIT addr=0x400a30 pc=0x400a30 ra=0x400820 sp=0x7ffff000 a0=0x7ffff100 a1=0x7ffff200',
        'FIRMLAB_ARG "Aa0Aa1Aa2Aa3"',
      ].join('\n'),
    );
    expect(p.hits).toHaveLength(1);
    expect(p.hits[0]?.address).toBe('0x400a30');
    expect(p.hits[0]?.registers.ra).toBe('0x400820');
    expect(p.hits[0]?.argument).toBe('Aa0Aa1Aa2Aa3');
  });

  it('separates the EMULATOR failing from the target misbehaving', () => {
    const p = parseGdbOutput('warning: Could not load shared library symbols for 3 libraries.');
    expect(p.emulationWarnings).toHaveLength(1);
    expect(p.stop).toBeNull();
  });

  it('reads a clean exit', () => {
    // Real DVRF output on a too-short input.
    const p = parseGdbOutput('[Inferior 1 (process 1) exited with code 0101]');
    expect(p.exited).toBe(true);
    expect(p.exitCode).toBe(101);
  });
});

describe('classifyRun — what may be claimed, in order of strength', () => {
  const pattern = cyclicPattern(400);

  it('an input-controlled fault is the strongest result and explains itself', () => {
    const r = classifyRun(
      parseGdbOutput('Program stopped at 0x41386741.\nIt stopped with signal SIGSEGV, x.'),
      pattern,
    );
    expect(r.verdict).toBe('crash_input_controlled');
    expect(r.controlOffset?.offset).toBeGreaterThanOrEqual(0);
    expect(r.reason).toContain('reached the saved return address');
  });

  it('a fault at an address that is not input bytes is a crash, not demonstrated control', () => {
    const r = classifyRun(
      parseGdbOutput(
        'FIRMLAB_HIT addr=0x400a30 pc=0x400a30\nProgram stopped at 0x400a30.\nIt stopped with signal SIGSEGV, x.',
      ),
      pattern,
    );
    expect(r.verdict).toBe('crash');
    expect(r.reason).toContain('not a demonstrated control of execution');
  });

  // The distinction that keeps a broken harness from being reported as a reproduced bug.
  it('a fault before the sink, with the emulator complaining, is an emulation artefact', () => {
    const r = classifyRun(
      parseGdbOutput(
        'warning: Could not load shared library symbols for 3 libraries.\nProgram stopped at 0x0.\nIt stopped with signal SIGSEGV, x.',
      ),
      pattern,
    );
    expect(r.verdict).toBe('emulation_artifact');
    expect(r.reason).toContain('not evidence the binary is sound either');
  });

  it('a sink that executed without a fault is a runtime fact and no more', () => {
    const r = classifyRun(parseGdbOutput('FIRMLAB_HIT addr=0x400a30 pc=0x400a30'), pattern);
    expect(r.verdict).toBe('sink_executed');
    expect(r.reason).toContain('nothing here shows it misbehaving');
  });

  it('a clean run is a statement about ONE input, not about the binary', () => {
    const r = classifyRun(parseGdbOutput('Remote debugging using :14500\n[Inferior 1 exited normally]'), pattern);
    expect(r.verdict).toBe('ran_clean');
    expect(r.reason).toContain('not about the binary');
  });

  it('a harness that never attached says so instead of reporting a result', () => {
    const r = classifyRun(parseGdbOutput(''), pattern);
    expect(r.verdict).toBe('not_attached');
    expect(r.reason).toContain('failure of the harness');
  });
});

describe('buildGdbScript', () => {
  it('breaks on the addresses the static providers already produced', () => {
    const s = buildGdbScript({
      sysroot: '/rootfs',
      addresses: ['0x400a30', '0x400b00'],
      argRegisters: ['ra', 'sp', 'a1'],
      port: 14500,
      stringArgRegister: 'a1',
    });
    expect(s).toContain('target remote :14500');
    expect(s).toContain('break *0x400a30');
    expect(s).toContain('break *0x400b00');
    expect(s).toContain('set sysroot /rootfs');
    expect(s).toContain('x/s $a1');
  });

  it('bounds the continue loop so a sink inside a loop cannot stop forever', () => {
    const s = buildGdbScript({ sysroot: '/r', addresses: ['0x1'], argRegisters: ['sp'], port: 1 });
    expect(s).toMatch(/while \$n < \d+/);
    expect(s).toContain('end');
  });
});

describe('buildDynFindings — confirmed_in_emulation is the ceiling, and nothing is ever clean', () => {
  const p = cyclicPattern(400);

  it('a reproduced overflow is critical, emulation-confirmed, and explicitly not a device claim', () => {
    const r = classifyRun(parseGdbOutput('Program stopped at 0x41386741.\nIt stopped with signal SIGSEGV, x.'), p);
    const [f] = buildDynFindings('pwnable/Intro/stack_bof_01', 'strcpy', r);
    expect(f?.kind).toBe('memory-safety-reproduced');
    expect(f?.severity).toBe('critical');
    expect(f?.proofState).toBe('confirmed_in_emulation');
    expect(f?.rationale).toContain('rather than the device');
    expect(f?.rationale).toContain('does not build a working exploit');
  });

  it('an executed sink upgrades static reachability and stops there', () => {
    const r = classifyRun(parseGdbOutput('FIRMLAB_HIT addr=0x400a30 pc=0x400a30'), p);
    const [f] = buildDynFindings('bin/x', 'strcpy', r);
    expect(f?.kind).toBe('sink-executed-at-runtime');
    expect(f?.proofState).toBe('confirmed_in_emulation');
    expect(f?.rationale).toContain('not shown to overflow');
  });

  // The case most likely to be misread as safety, so it must never be silent.
  it('a non-reproduction keeps needs_runtime_reproduction and says it is not a clean result', () => {
    const r = classifyRun(parseGdbOutput('Remote debugging using :1\n[Inferior 1 exited normally]'), p);
    const [f] = buildDynFindings('bin/x', 'strcpy', r);
    expect(f?.kind).toBe('memory-safety-not-reproduced');
    expect(f?.proofState).toBe('needs_runtime_reproduction');
    expect(f?.title).toContain('not a clean result');
    expect(f?.rationale).toContain('nowhere near enough to call the binary sound');
  });
});
