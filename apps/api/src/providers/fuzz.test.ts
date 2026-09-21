import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  type FuzzDeployment,
  type FuzzMode,
  type FuzzPlan,
  type HarnessClass,
  buildAflDict,
  buildFuzzCommand,
  chooseHarness,
  classifyTarget,
  detectDesockPreload,
  formatFuzzCommand,
  fuzzCoverageStatement,
  isNetworkDaemon,
  planFuzz,
  shellQuote,
} from './fuzz.js';

/** An ELF identification header — 20 bytes is all `classifyTarget` reads. */
function elfHead(machine: number, opts: { big?: boolean; bits?: number } = {}): Buffer {
  const b = Buffer.alloc(20);
  b[0] = 0x7f;
  b[1] = 0x45;
  b[2] = 0x4c;
  b[3] = 0x46;
  b[4] = opts.bits === 64 ? 2 : 1;
  b[5] = opts.big ? 2 : 1;
  if (opts.big) b.writeUInt16BE(machine, 18);
  else b.writeUInt16LE(machine, 18);
  return b;
}

const EM_386 = 3;
const EM_MIPS = 8;
const EM_ARM = 40;
const EM_SPARC = 2;

const ARM_ELF = elfHead(EM_ARM);
const MIPS_ELF = elfHead(EM_MIPS, { big: true });
const X86_ELF = elfHead(EM_386);

function deployment(over: Partial<FuzzDeployment> = {}): FuzzDeployment {
  return { hostArch: 'x86_64', traceArches: ['arm', 'mips', 'mipsel'], desock: null, ...over };
}

function plan(
  binary: string,
  head: Buffer | null,
  opts: { harness?: HarnessClass | 'auto'; mode?: FuzzMode | 'auto'; seconds?: number } = {},
  dep: FuzzDeployment = deployment(),
): FuzzPlan {
  return planFuzz({ binary, target: classifyTarget(binary, head), seconds: opts.seconds ?? 60, ...opts }, dep);
}

describe('buildFuzzCommand', () => {
  it('builds an AFL++ qemu-mode, time-bounded invocation with file input (@@) by default', () => {
    const cmd = buildFuzzCommand('/rootfs/bin/parser', '/w/seeds', '/w/out', 60);
    expect(cmd[0]).toBe('afl-fuzz');
    expect(cmd).toContain('-Q'); // binary-only qemu mode
    expect(cmd[cmd.indexOf('-V') + 1]).toBe('60');
    expect(cmd.slice(-2)).toEqual(['/rootfs/bin/parser', '@@']);
  });

  it('drops @@ for a stdin harness so AFL feeds the testcase on stdin', () => {
    const cmd = buildFuzzCommand('/rootfs/sbin/httpd', '/w/seeds', '/w/out', 60, { stdin: true });
    expect(cmd[cmd.length - 1]).toBe('/rootfs/sbin/httpd');
    expect(cmd).not.toContain('@@');
  });

  it('disables the memory limit (qemu mode forks die under an AS cap)', () => {
    const cmd = buildFuzzCommand('/rootfs/bin/parser', '/w/seeds', '/w/out', 60);
    expect(cmd[cmd.indexOf('-m') + 1]).toBe('none');
  });

  it('includes a dictionary when supplied and omits it otherwise', () => {
    const withDict = buildFuzzCommand('/b', '/s', '/o', 30, { dictPath: '/w/dict.txt' });
    expect(withDict[withDict.indexOf('-x') + 1]).toBe('/w/dict.txt');
    expect(buildFuzzCommand('/b', '/s', '/o', 10)).not.toContain('-x');
  });

  it('places the mode args before -- and the cross-arch qemu binary in front of the target', () => {
    const cmd = buildFuzzCommand('/rootfs/bin/p', '/s', '/o', 30, {
      modeArgs: ['-c', '0'],
      qemuTraceBin: 'afl-qemu-trace-arm',
    });
    expect(cmd.indexOf('-c')).toBeLessThan(cmd.indexOf('--'));
    expect(cmd[cmd.indexOf('-c') + 1]).toBe('0');
    expect(cmd.slice(cmd.indexOf('--'))).toEqual(['--', 'afl-qemu-trace-arm', '/rootfs/bin/p', '@@']);
  });
});

describe('chooseHarness / isNetworkDaemon', () => {
  it('routes network daemons and CGI to the desock (network) harness', () => {
    expect(chooseHarness('usr/sbin/httpd')).toBe('network');
    expect(chooseHarness('bin/dropbear')).toBe('network');
    expect(chooseHarness('www/cgi-bin/status.cgi')).toBe('network');
    expect(isNetworkDaemon('usr/sbin/telnetd')).toBe(true);
  });

  it('defaults everything else to the file (@@) harness', () => {
    expect(chooseHarness('bin/jsonparse')).toBe('file');
    expect(chooseHarness('usr/bin/libxml2test')).toBe('file');
    expect(isNetworkDaemon('bin/busybox')).toBe(false);
  });
});

describe('classifyTarget', () => {
  it('reads the arch from the ELF header, endianness included', () => {
    expect(classifyTarget('bin/p', ARM_ELF)).toEqual({ kind: 'elf', arch: 'arm', bits: 32 });
    expect(classifyTarget('bin/p', X86_ELF)).toEqual({ kind: 'elf', arch: 'x86', bits: 32 });
    expect(classifyTarget('bin/p', MIPS_ELF)).toEqual({ kind: 'elf', arch: 'mips', bits: 32 });
    expect(classifyTarget('bin/p', elfHead(EM_MIPS))).toEqual({ kind: 'elf', arch: 'mipsel', bits: 32 });
  });

  it('refuses a shared object or module by name, because a PIE shares ET_DYN with it', () => {
    expect(classifyTarget('lib/libc.so.0', ARM_ELF)).toEqual({ kind: 'shared-object' });
    expect(classifyTarget('lib/modules/wl.ko', ARM_ELF)).toEqual({ kind: 'shared-object' });
  });

  it('separates a script, a non-ELF and an unreadable head', () => {
    const script = Buffer.concat([Buffer.from('#!/bin/sh\n'), Buffer.alloc(10)]);
    expect(classifyTarget('www/cgi-bin/x.cgi', script)).toEqual({
      kind: 'not-elf',
      detail: 'it starts with a #! shebang, i.e. it is a script',
    });
    expect(classifyTarget('bin/x', Buffer.alloc(20))).toEqual({ kind: 'not-elf', detail: 'its magic is 00000000' });
    expect(classifyTarget('bin/x', null)).toEqual({ kind: 'unreadable' });
    expect(classifyTarget('bin/x', Buffer.alloc(4))).toEqual({ kind: 'unreadable' });
  });
});

describe('planFuzz — comparison instrumentation', () => {
  it('auto-selects cmplog (-c 0) on an arch whose qemu mode carries it', () => {
    const p = plan('bin/parser', ARM_ELF);
    expect(p.fuzzable).toBe(true);
    expect(p.mode).toBe('cmplog');
    expect(p.modeArgs).toEqual(['-c', '0']);
    expect(p.env.AFL_COMPCOV_LEVEL).toBeUndefined();
  });

  it('puts compcov in the environment, not in argv', () => {
    const p = plan('bin/parser', ARM_ELF, { mode: 'compcov' });
    expect(p.mode).toBe('compcov');
    expect(p.env.AFL_COMPCOV_LEVEL).toBe('2');
    expect(p.modeArgs).toEqual([]);
  });

  it('refuses cmplog on MIPS out loud and downgrades to plain, naming the arch and the cost', () => {
    const p = plan('bin/parser', MIPS_ELF, { mode: 'cmplog' });
    expect(p.fuzzable).toBe(true);
    expect(p.mode).toBe('plain');
    expect(p.modeArgs).toEqual([]);
    expect(p.env.AFL_COMPCOV_LEVEL).toBeUndefined();
    expect(p.modeNote).toMatch(/cmplog was requested and cannot be run/);
    expect(p.modeNote).toMatch(/mips/);
    expect(p.modeNote).toMatch(/Multi-byte comparisons/);
  });

  it('auto on MIPS lands on plain and says the instrumentation is the limit, not the binary', () => {
    const p = plan('bin/parser', MIPS_ELF);
    expect(p.mode).toBe('plain');
    expect(p.modeNote).toMatch(/x86\/x86_64\/arm\/arm64/);
    expect(p.modeNote).toMatch(/limit of the instrumentation/);
  });

  it('honours an explicit plain request on a capable arch and still states what it costs', () => {
    const p = plan('bin/parser', ARM_ELF, { mode: 'plain' });
    expect(p.mode).toBe('plain');
    expect(p.modeNote).toMatch(/requested explicitly/);
    expect(p.modeNote).toMatch(/Multi-byte comparisons/);
  });
});

describe('planFuzz — the qemu CPU target', () => {
  it('uses the host emulator for a host-arch target and no custom-bin env', () => {
    const p = plan('bin/parser', elfHead(62, { bits: 64 })); // x86_64
    expect(p.qemuTraceBin).toBeUndefined();
    expect(p.env.AFL_QEMU_CUSTOM_BIN).toBeUndefined();
  });

  it('drives a cross-arch target through afl-qemu-trace-<suffix> under AFL_QEMU_CUSTOM_BIN', () => {
    const p = plan('bin/parser', ARM_ELF);
    expect(p.qemuTraceBin).toBe('afl-qemu-trace-arm');
    expect(p.env.AFL_QEMU_CUSTOM_BIN).toBe('1');
  });

  it('refuses a cross-arch target with no build here, naming the CPU_TARGET that would fix it', () => {
    const p = plan('bin/parser', ARM_ELF, {}, deployment({ traceArches: ['mipsel'] }));
    expect(p.fuzzable).toBe(false);
    expect(p.blocked).toMatch(/afl-qemu-trace-arm/);
    expect(p.blocked).toMatch(/CPU_TARGET=arm/);
    expect(p.bounds).toMatch(/bounds nothing/);
  });

  it('refuses an arch AFL++ has no CPU target for at all', () => {
    const p = plan('bin/parser', elfHead(EM_SPARC, { big: true }));
    expect(p.fuzzable).toBe(false);
    expect(p.blocked).toMatch(/no CPU target for sparc/);
  });
});

describe('planFuzz — why a target cannot be fuzzed', () => {
  it('reports a shared object as a reason, not as zero crashes', () => {
    const p = plan('lib/libupnp.so.1', ARM_ELF);
    expect(p.fuzzable).toBe(false);
    expect(p.blocked).toMatch(/no entry point/);
    expect(p.inputChannel).toMatch(/^None:/);
    expect(p.modeArgs).toEqual([]);
  });

  it('separates "not an ELF" and "could not be read"', () => {
    expect(plan('etc/init.d/rcS', Buffer.concat([Buffer.from('#!/bin/sh\n'), Buffer.alloc(10)])).blocked).toMatch(
      /fuzz its interpreter/,
    );
    expect(plan('bin/parser', null).blocked).toMatch(/missing answer, not an empty one/);
  });

  it('reports an ELF whose e_machine is unmapped', () => {
    const p = plan('bin/parser', elfHead(0x9999));
    expect(p.fuzzable).toBe(false);
    expect(p.blocked).toMatch(/does not map to an architecture|e_machine/);
  });
});

describe('planFuzz — the input channel', () => {
  it('file input names the @@ substitution', () => {
    expect(plan('bin/parser', ARM_ELF).inputChannel).toMatch(/`@@`/);
  });

  it('stdin input warns that a target which never reads stdin consumes nothing', () => {
    const p = plan('bin/parser', ARM_ELF, { harness: 'stdin' });
    expect(p.harness).toBe('stdin');
    expect(p.inputChannel).toMatch(/does not read stdin/);
  });

  it('an arch-matched desock preload makes the socket the channel', () => {
    const p = plan(
      'usr/sbin/httpd',
      ARM_ELF,
      {},
      deployment({ desock: { path: '/opt/libdesock-arm.so', arch: 'arm' } }),
    );
    expect(p.harness).toBe('network');
    expect(p.harnessNote).toBeUndefined();
    expect(p.env.AFL_PRELOAD).toBe('/opt/libdesock-arm.so');
    expect(p.env.QEMU_SET_ENV).toBe('LD_PRELOAD=/opt/libdesock-arm.so');
    expect(p.inputChannel).toMatch(/accept\/recv/);
  });

  it('an arch-mismatched preload is not used, and the run says the socket was not fuzzed', () => {
    const p = plan(
      'usr/sbin/httpd',
      ARM_ELF,
      {},
      deployment({ desock: { path: '/opt/libdesock-mipsel.so', arch: 'mipsel' } }),
    );
    expect(p.env.AFL_PRELOAD).toBeUndefined();
    expect(p.harnessNote).toMatch(/is mipsel and the target is arm/);
    expect(p.harnessNote).toMatch(/drops a wrong-arch preload silently/);
    expect(p.inputChannel).toMatch(/SOCKET is not fuzzed/);
  });

  it('a preload whose arch could not be read is treated as unusable, not as a match', () => {
    const p = plan('usr/sbin/httpd', ARM_ELF, {}, deployment({ desock: { path: '/opt/x.so', arch: 'unknown' } }));
    expect(p.env.AFL_PRELOAD).toBeUndefined();
    expect(p.harnessNote).toMatch(/could not be read from its ELF header/);
  });

  it('a missing preload says FirmLab ships none and what has to be built', () => {
    const p = plan('usr/sbin/httpd', ARM_ELF);
    expect(p.harnessNote).toMatch(/ships none/);
    expect(p.harnessNote).toMatch(/built for arm/);
    expect(p.harnessNote).toMatch(/FIRMLAB_DESOCK/);
    expect(p.fuzzable).toBe(true); // degraded, not blocked
  });
});

describe('fuzzCoverageStatement', () => {
  const armPlan = plan('bin/parser', ARM_ELF);
  const mipsPlan = plan('bin/parser', MIPS_ELF);

  it('states the bound and refuses to read zero crashes as clean', () => {
    const s = fuzzCoverageStatement(armPlan, { crashes: 0, execsDone: 120_000, seconds: 60 });
    expect(s).toMatch(/No crash in 120000 execs/);
    expect(s).toMatch(/cmplog instrumentation, file channel, 60s budget/);
    expect(s).toMatch(/not a verdict/);
    expect(s).toMatch(/unexamined rather than clean/);
  });

  it('calls zero execs a harness failure, not a result', () => {
    const s = fuzzCoverageStatement(armPlan, { crashes: 0, execsDone: 0, seconds: 60 });
    expect(s).toMatch(/executed bin\/parser 0 times/);
    expect(s).toMatch(/harness failure/);
    expect(s).toMatch(/no information whatsoever/);
  });

  it('says the exec count is unrecorded rather than inventing one', () => {
    expect(fuzzCoverageStatement(armPlan, { crashes: 0, execsDone: null, seconds: 60 })).toMatch(
      /an unrecorded number of execs/,
    );
  });

  it('keeps a crash a claim about the sandbox, never the device', () => {
    const s = fuzzCoverageStatement(armPlan, { crashes: 3, execsDone: 900, seconds: 60 });
    expect(s).toMatch(/3 crashing inputs reproduced/);
    expect(s).toMatch(/qemu-user sandbox, never about the physical device/);
  });

  it('carries the uninstrumented-comparison caveat on a plain-mode run', () => {
    expect(fuzzCoverageStatement(mipsPlan, { crashes: 0, execsDone: 10, seconds: 60 })).toMatch(
      /comparisons were not instrumented/,
    );
  });

  it('carries the raw-stdin caveat when the socket was never fuzzed', () => {
    const daemon = plan('usr/sbin/httpd', ARM_ELF);
    expect(fuzzCoverageStatement(daemon, { crashes: 0, execsDone: 10, seconds: 60 })).toMatch(
      /arrived on raw stdin rather than through the socket/,
    );
  });

  it('for an unfuzzable target reports the reason instead of a coverage claim', () => {
    const s = fuzzCoverageStatement(plan('lib/libupnp.so.1', ARM_ELF), { crashes: 0, execsDone: null, seconds: 60 });
    expect(s).toMatch(/bounds nothing/);
    expect(s).not.toMatch(/No crash/);
  });
});

describe('formatFuzzCommand / shellQuote', () => {
  it('leaves shell-safe arguments — including AFL’s @@ — unquoted', () => {
    expect(shellQuote('afl-fuzz')).toBe('afl-fuzz');
    expect(shellQuote('@@')).toBe('@@');
    expect(shellQuote('/rootfs/usr/sbin/httpd')).toBe('/rootfs/usr/sbin/httpd');
  });

  it('quotes paths with spaces and escapes single quotes', () => {
    expect(shellQuote('/data/extract/my image/bin/sh')).toBe("'/data/extract/my image/bin/sh'");
    expect(shellQuote("it's")).toBe("'it'\\''s'");
    expect(shellQuote('')).toBe("''");
    expect(shellQuote('a;rm -rf /')).toBe("'a;rm -rf /'");
  });

  it('renders the env prefix in front of the command, sorted and quoted', () => {
    const line = formatFuzzCommand(buildFuzzCommand('/r/bin/p arser', '/s', '/o', 30, { modeArgs: ['-c', '0'] }), {
      AFL_QEMU_CUSTOM_BIN: '1',
      AFL_COMPCOV_LEVEL: '2',
    });
    expect(line.startsWith('AFL_COMPCOV_LEVEL=2 AFL_QEMU_CUSTOM_BIN=1 afl-fuzz')).toBe(true);
    expect(line).toContain("'/r/bin/p arser'");
    expect(line).toMatch(/-c 0 -- /);
    expect(line.endsWith(' @@')).toBe(true);
  });
});

describe('detectDesockPreload', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-desock-'));
  const armLib = path.join(tmp, 'libdesock-arm.so');
  const junk = path.join(tmp, 'empty.so');
  fs.writeFileSync(armLib, ARM_ELF);
  fs.writeFileSync(junk, '');
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('reads the preload’s arch from its own ELF header', () => {
    expect(detectDesockPreload({ FIRMLAB_DESOCK: armLib })).toEqual({ path: armLib, arch: 'arm' });
  });

  it('reports an unreadable preload as arch unknown rather than as a match', () => {
    expect(detectDesockPreload({ FIRMLAB_DESOCK: junk })).toEqual({ path: junk, arch: 'unknown' });
  });

  it('returns null when unset or missing (→ honest degradation)', () => {
    expect(detectDesockPreload({})).toBeNull();
    expect(detectDesockPreload({ FIRMLAB_DESOCK: path.join(tmp, 'nope.so') })).toBeNull();
  });
});

describe('buildAflDict', () => {
  it('emits AFL dictionary entries for printable strings, deduped', () => {
    const d = buildAflDict(['admin', 'admin', 'password', 'ab']).split('\n');
    expect(d).toHaveLength(2); // 'ab' too short, 'admin' deduped
    expect(d[0]).toMatch(/^fw_0="admin"$/);
    expect(d[1]).toMatch(/^fw_1="password"$/);
  });

  it('strips non-printable bytes and escapes quotes/backslashes', () => {
    const d = buildAflDict(['a\x00b"c\\d']);
    expect(d).toBe('fw_0="ab\\"c\\\\d"');
  });
});
