import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { FindingDraft } from './findings-normalize.js';
import {
  type ProbeInterest,
  daemonLeads,
  execTargetFromSnippet,
  handlerLeads,
  interestingBinaries,
  reachabilityLeads,
  reproductionLeads,
  resolveDaemonBinary,
  taintReachabilityLeads,
} from './opacidad-leads.js';
import {
  type Lead,
  type ScheduleState,
  countReachabilityProbes,
  replan,
  scheduleLeads,
  specKey,
  specsForClass,
} from './opacidad-plan.js';
import type { Service } from './providers/servicemap.js';
import type { SinkHit } from './providers/webtaint.js';
import type { HandlerAnalysis } from './providers/webtaint.js';

const lead = (target: string): Lead => ({ kind: 'decompile-binary', target, reason: `decompile ${target}` });

describe('replan + specKey', () => {
  it('maps a decompile-binary lead to a W5 spec tagged origin=replan', () => {
    const specs = replan(lead('usr/sbin/httpd'), new Set());
    expect(specs).toHaveLength(1);
    expect(specs[0]).toMatchObject({ provider: 'decompile', target: 'usr/sbin/httpd', origin: 'replan', built: true });
    expect(specs[0]?.worker).toContain('httpd');
  });

  it('drops a lead whose binary is already planned (idempotent)', () => {
    const planned = new Set(['decompile:usr/sbin/httpd']);
    expect(replan(lead('usr/sbin/httpd'), planned)).toHaveLength(0);
  });

  it('keys a decompile spec on its target, other specs on provider/worker', () => {
    expect(
      specKey({ worker: 'x', reason: '', needsRootfs: true, built: true, provider: 'decompile', target: 'a/b' }),
    ).toBe('decompile:a/b');
    expect(specKey({ worker: 'W2', reason: '', needsRootfs: true, built: true, provider: 'sbom' })).toBe('sbom');
  });
});

describe('scheduleLeads', () => {
  it('appends new specs, dedupes, and caps dynamic growth (surfacing the overflow)', () => {
    const state: ScheduleState = { planned: new Set(), dynamicCount: 0, capped: 0 };
    const leads = [lead('a'), lead('b'), lead('a'), lead('c')]; // 'a' twice
    const added = scheduleLeads(leads, state, 2);
    expect(added.map((s) => s.target)).toEqual(['a', 'b']); // 'a' deduped, cap 2 stops before 'c'
    expect(state.dynamicCount).toBe(2);
    expect(state.capped).toBe(1); // 'c' over the cap
  });

  it('does not re-schedule a binary already in the planned set', () => {
    const state: ScheduleState = { planned: new Set(['decompile:a']), dynamicCount: 0, capped: 0 };
    expect(scheduleLeads([lead('a')], state, 8)).toHaveLength(0);
  });
});

describe('lead resolution over a rootfs', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-replan-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));
  const touch = (rel: string): void => {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, '\x7fELF');
  };
  touch('usr/sbin/dropbear');
  touch('bin/httpd');
  touch('usr/sbin/oui-httpd');

  it('resolves absolute, bare, and missing daemon tokens', () => {
    expect(resolveDaemonBinary(root, '/usr/sbin/dropbear')).toBe('usr/sbin/dropbear');
    expect(resolveDaemonBinary(root, 'httpd')).toBe('bin/httpd');
    expect(resolveDaemonBinary(root, 'nonexistent')).toBeNull();
    expect(resolveDaemonBinary(root, 'internal')).toBeNull();
  });

  it('builds decompile leads only for autostart network daemons that resolve', () => {
    const services: Service[] = [
      { name: 'dropbear', binary: '/usr/sbin/dropbear', source: 'etc/inittab', network: true, autostart: true },
      { name: 'httpd', binary: 'httpd', source: 'etc/rc.local', network: true, autostart: true },
      { name: 'telnet', binary: 'internal', source: 'etc/inetd.conf', network: true, autostart: true },
      { name: 'ntpd', binary: '/usr/sbin/ntpd', source: 'x', network: false, autostart: true },
    ];
    expect(daemonLeads(services, root).map((l) => l.target)).toEqual(['usr/sbin/dropbear', 'bin/httpd']);
  });

  it('builds an httpd decompile lead only when a handler is tainted', () => {
    const base = { sinks: [], sources: [], fromUci: false, runsAsRoot: false };
    const tainted: HandlerAnalysis[] = [{ handler: 'x', object: 'tor', ...base, tainted: true }];
    const clean: HandlerAnalysis[] = [{ handler: 'x', object: 'diag', ...base, tainted: false }];
    expect(handlerLeads(tainted, root).map((l) => l.target)).toEqual(['usr/sbin/oui-httpd']);
    expect(handlerLeads(clean, root)).toHaveLength(0);
  });
});

describe('execTargetFromSnippet — the program a tainted handler actually runs', () => {
  const cases: [string, string | null][] = [
    ['os.execute("/usr/sbin/gl-tor " .. params.enable)', '/usr/sbin/gl-tor'],
    ['local f = io.popen("wg show " .. name)', 'wg'],
    ['os.execute("sh -c \'/usr/bin/setcfg " .. v)', '/usr/bin/setcfg'],
    ['os.execute("sudo /sbin/reload " .. x)', '/sbin/reload'],
    ['os.execute("busybox killall " .. proc)', 'killall'],
  ];
  for (const [snippet, expected] of cases) {
    it(`reads ${expected} out of ${snippet.slice(0, 42)}…`, () => {
      expect(execTargetFromSnippet(snippet)).toBe(expected);
    });
  }

  it('says nothing when the program name is itself interpolated — a guess would be fabrication', () => {
    expect(execTargetFromSnippet('os.execute(cmd .. " restart")')).toBeNull();
    expect(execTargetFromSnippet('os.execute(string.format("%s %s", prog, arg))')).toBeNull();
    expect(execTargetFromSnippet('os.execute("$TOOL " .. x)')).toBeNull();
    expect(execTargetFromSnippet('os.execute(v)')).toBeNull();
  });

  // The real GL.iNet BE3600 4.9.0 tor handler. `echo` is resolved by /bin/sh as a BUILTIN, so the coreutil ELF
  // never runs — and the injection is into the shell command line (the concat and the `>>`), not into any argv the
  // symbolic prober models. Naming bin/echo would be a reachability question about a program that did not execute.
  it('drops a bare shell builtin, but keeps it when an absolute path really names the binary', () => {
    expect(
      execTargetFromSnippet('os.execute("echo \\"ExitNodes " .. countries .. "\\" >> /etc/tor/torrc")'),
    ).toBeNull();
    expect(execTargetFromSnippet('os.execute("/bin/echo " .. v)')).toBe('/bin/echo');
  });
});

describe('taintReachabilityLeads — W4 chains become the reachability questions', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-taintlead-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (rel: string, bytes: string): void => {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, bytes);
  };
  write('usr/sbin/gl-tor', '\x7fELFstrcpy');
  write('etc/init.d/tor', '#!/bin/sh\nexit 0\n'); // a script: not a symbolic-execution target

  const sink = (snippet: string): SinkHit => ({
    sink: 'os.execute',
    line: 12,
    concat: true,
    argvArray: false,
    snippet,
  });
  const handler = (snippet: string): HandlerAnalysis => ({
    handler: 'usr/lib/oui-httpd/rpc/tor',
    object: 'tor',
    sinks: [sink(snippet)],
    sources: [{ kind: 'param', name: 'enable', line: 11 }],
    tainted: true,
    fromUci: true,
    runsAsRoot: true,
  });

  it('schedules the exec’d native helper with the source→sink→privilege chain as the reason', () => {
    const leads = taintReachabilityLeads([handler('os.execute("/usr/sbin/gl-tor " .. params.enable)')], root);
    expect(leads).toHaveLength(1);
    expect(leads[0]).toMatchObject({ kind: 'prove-reachability', target: 'usr/sbin/gl-tor', sinks: [] });
    // Empty sinks = derive them from the binary itself; the reason must carry the chain, not just a filename.
    expect(leads[0]?.reason).toContain('params.enable');
    expect(leads[0]?.reason).toContain('as root');
  });

  it('skips a shell script — angr loads executables, and pretending otherwise would fail later', () => {
    expect(taintReachabilityLeads([handler('os.execute("/etc/init.d/tor restart " .. p)')], root)).toHaveLength(0);
  });

  it('ignores an untainted handler and a hardened argv-array sink', () => {
    const clean = { ...handler('os.execute("/usr/sbin/gl-tor " .. params.enable)'), tainted: false };
    expect(taintReachabilityLeads([clean], root)).toHaveLength(0);
    const hardened = handler('os.execute("/usr/sbin/gl-tor " .. params.enable)');
    (hardened.sinks[0] as SinkHit).argvArray = true;
    expect(taintReachabilityLeads([hardened], root)).toHaveLength(0);
  });

  it('respects a spent budget rather than overrunning the run’s angr allowance', () => {
    expect(taintReachabilityLeads([handler('os.execute("/usr/sbin/gl-tor " .. params.enable)')], root, 0)).toEqual([]);
  });
});

describe('the reachability budget is global across lead sources', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-budget-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const rel of ['bin/a', 'bin/b', 'bin/c']) {
    fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(root, rel), '\x7fELF');
  }
  const candidate = (p: string): FindingDraft => ({
    kind: 'binary-pwnable-candidate',
    title: p,
    severity: 'medium',
    proofState: 'needs_runtime_reproduction',
    evidence: { path: p, unsafeFns: ['strcpy'] },
    rationale: '',
  });

  it('counts probes already on the agenda so W4 and the sweep share one allowance', () => {
    expect(countReachabilityProbes(new Set(['sbom', 'symreach:bin/a', 'decompile:bin/x', 'symreach:bin/b']))).toBe(2);
  });

  it('lets the sweep fill only what W4 left unspent', () => {
    const candidates = [candidate('bin/a'), candidate('bin/b'), candidate('bin/c')];
    expect(reachabilityLeads(candidates, root, 1).map((l) => l.target)).toEqual(['bin/a']);
    expect(reachabilityLeads(candidates, root, 0)).toEqual([]);
  });
});

describe('reachabilityLeads spends the probe budget smallest-first when no worker flagged anything', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-order-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
  for (const rel of ['bin/a', 'bin/b', 'bin/c', 'bin/d']) fs.writeFileSync(path.join(root, rel), '\x7fELF');

  const sized = (p: string, size: number): FindingDraft => ({
    kind: 'binary-pwnable-candidate',
    title: p,
    severity: 'medium',
    proofState: 'needs_runtime_reproduction',
    evidence: { path: p, size, unsafeFns: ['strcpy'] },
    rationale: '',
  });

  // The defect this pins, measured on the real DVRF rootfs: the sweep hands over candidates in walk order, so the
  // three probes a run can afford went to usr/sbin daemons and never reached the 7 KB pwnable that actually
  // crashes. Angr converges on small binaries and times out on large ones, so walk order spends the whole
  // allowance on the questions least likely to return an answer.
  it('asks about the smallest binaries, not the ones the walk happened to reach first', () => {
    const candidates = [sized('bin/d', 900_000), sized('bin/a', 7_016), sized('bin/c', 120_000), sized('bin/b', 42)];
    expect(reachabilityLeads(candidates, root, 3).map((l) => l.target)).toEqual(['bin/b', 'bin/a', 'bin/c']);
  });

  it('does not mutate the caller’s candidate list while ordering it', () => {
    const candidates = [sized('bin/d', 900_000), sized('bin/b', 42)];
    reachabilityLeads(candidates, root, 2);
    expect(candidates.map((f) => f.title)).toEqual(['bin/d', 'bin/b']);
  });

  // Caught by the first autonomous run: ranking by size promoted DVRF's ~6 KB iptables plugins to the front of the
  // queue, and a .so has no entry point to be reachable from and cannot be run under gdb either.
  it('skips a shared library, whose entry point the question presupposes and which has none', () => {
    const lib: FindingDraft = {
      ...sized('bin/b', 10),
      evidence: { path: 'bin/b', size: 10, runnable: false, unsafeFns: ['strcpy'] },
    };
    expect(reachabilityLeads([lib, sized('bin/a', 9000)], root, 3).map((l) => l.target)).toEqual(['bin/a']);
  });

  it('treats a candidate predating the runnable flag as askable rather than disqualifying it on silence', () => {
    const old: FindingDraft = { ...sized('bin/a', 5), evidence: { path: 'bin/a', size: 5, unsafeFns: ['strcpy'] } };
    expect(reachabilityLeads([old], root, 3).map((l) => l.target)).toEqual(['bin/a']);
  });

  it('sorts a candidate carrying no size last rather than letting it jump the queue', () => {
    const noSize: FindingDraft = { ...sized('bin/d', 0), evidence: { path: 'bin/d', unsafeFns: ['strcpy'] } };
    expect(reachabilityLeads([noSize, sized('bin/a', 500)], root, 2).map((l) => l.target)).toEqual(['bin/a', 'bin/d']);
  });
});

describe('reachabilityLeads weighs interest against answerability', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-interest-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));
  const write = (rel: string): void => {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, '\x7fELFstrcpy');
  };
  for (const rel of [
    'usr/sbin/httpd',
    'usr/sbin/gl-tor',
    'usr/bin/small',
    'usr/bin/store_domain_sid',
    'usr/bin/store_machine_password',
    'pwnable/Intro/stack_bof_01',
    'etc/init.d/quiet',
  ]) {
    write(rel);
  }

  const sized = (p: string, size: number): FindingDraft => ({
    kind: 'binary-pwnable-candidate',
    title: p,
    severity: 'medium',
    proofState: 'needs_runtime_reproduction',
    evidence: { path: p, size, unsafeFns: ['strcpy'] },
    rationale: '',
  });
  const daemon = (name: string, binary: string): Service => ({
    name,
    binary,
    source: 'etc/inittab',
    network: true,
    autostart: true,
  });
  const taintedHandler = (snippet: string): HandlerAnalysis => ({
    handler: 'usr/lib/oui-httpd/rpc/tor',
    object: 'tor',
    sinks: [{ sink: 'os.execute', line: 12, concat: true, argvArray: false, snippet }],
    sources: [{ kind: 'param', name: 'enable', line: 11 }],
    tainted: true,
    fromUci: true,
    runsAsRoot: true,
  });

  it('reads exposure off W3 and W4 rather than deciding it again', () => {
    const interest: ProbeInterest = {
      services: [
        daemon('httpd', '/usr/sbin/httpd'),
        { ...daemon('quiet', '/etc/init.d/quiet'), network: false }, // not a network daemon
        { ...daemon('later', '/usr/bin/small'), autostart: false }, // configured but never started
      ],
      handlers: [taintedHandler('os.execute("/usr/sbin/gl-tor " .. params.enable)')],
    };
    const why = interestingBinaries(root, interest);
    expect([...why.keys()].sort()).toEqual(['usr/sbin/gl-tor', 'usr/sbin/httpd']);
    expect(why.get('usr/sbin/gl-tor')).toContain('argv');
    expect(why.get('usr/sbin/httpd')).toContain('network daemon');
  });

  it('keeps W4’s clause when a binary is both — a resolved chain outranks a listening socket', () => {
    const why = interestingBinaries(root, {
      services: [daemon('gl-tor', '/usr/sbin/gl-tor')],
      handlers: [taintedHandler('os.execute("/usr/sbin/gl-tor " .. params.enable)')],
    });
    expect(why.get('usr/sbin/gl-tor')).toContain('argv');
  });

  it('asks the exposed binary before a smaller one nothing has flagged, and says why in the lead', () => {
    const candidates = [sized('usr/bin/small', 42), sized('usr/sbin/httpd', 60_000)];
    const interest: ProbeInterest = { services: [daemon('httpd', '/usr/sbin/httpd')] };
    const one = reachabilityLeads(candidates, root, 1, interest);
    expect(one.map((l) => l.target)).toEqual(['usr/sbin/httpd']);
    expect(one[0]?.reason).toContain('ranked ahead of smaller candidates');
    expect(one[0]?.reason).toContain('autostart network daemon (httpd)');
    // Round-robin, not a preference: the second slot goes back to the answerability queue.
    expect(reachabilityLeads(candidates, root, 2, interest).map((l) => l.target)).toEqual([
      'usr/sbin/httpd',
      'usr/bin/small',
    ]);
  });

  it('asks the binary a tainted handler execs — the probe seeds argv, which is that exact channel', () => {
    const candidates = [sized('usr/bin/small', 42), sized('usr/sbin/gl-tor', 30_000)];
    const interest: ProbeInterest = { handlers: [taintedHandler('os.execute("/usr/sbin/gl-tor " .. params.enable)')] };
    const leads = reachabilityLeads(candidates, root, 1, interest);
    expect(leads.map((l) => l.target)).toEqual(['usr/sbin/gl-tor']);
    expect(leads[0]?.reason).toContain('web input in its argv');
  });

  /**
   * The DVRF shape the backlog measured: the two smallest candidates were 4 KB samba helpers that both came back
   * inconclusive, and `stack_bof_01` — the one binary in that rootfs known to crash — sat at 7 KB behind them, so
   * a two-probe allowance never reached it. Reproduced synthetically, and deliberately so: on the REAL DVRF the
   * exposure signal is empty for all three (no Lua handlers for W4 to taint, and the pwnable is in no init script
   * for W3 to call a daemon), so this rule alone does not reorder that image. What it pins is the rank — an
   * exposed candidate is asked before smaller unflagged ones — not a claim about DVRF, which still needs a signal
   * neither W3 nor W4 produces.
   */
  it('spends a probe on the flagged pwnable instead of two inconclusive helpers ahead of it', () => {
    const candidates = [
      sized('usr/bin/store_domain_sid', 4_096),
      sized('usr/bin/store_machine_password', 4_096),
      sized('pwnable/Intro/stack_bof_01', 7_016),
    ];
    // What the old rule did with the same two probes.
    expect(reachabilityLeads(candidates, root, 2).map((l) => l.target)).toEqual([
      'usr/bin/store_domain_sid',
      'usr/bin/store_machine_password',
    ]);
    const interest: ProbeInterest = { services: [daemon('bof', '/pwnable/Intro/stack_bof_01')] };
    expect(reachabilityLeads(candidates, root, 2, interest).map((l) => l.target)).toEqual([
      'pwnable/Intro/stack_bof_01',
      'usr/bin/store_domain_sid',
    ]);
  });

  it('ranks the candidates no worker flagged rather than disqualifying them on that silence', () => {
    const candidates = [
      sized('usr/bin/small', 42),
      sized('usr/bin/store_domain_sid', 100),
      sized('usr/sbin/httpd', 9_000),
    ];
    const interest: ProbeInterest = { services: [daemon('httpd', '/usr/sbin/httpd')] };
    expect(reachabilityLeads(candidates, root, 3, interest).map((l) => l.target)).toEqual([
      'usr/sbin/httpd',
      'usr/bin/small',
      'usr/bin/store_domain_sid',
    ]);
  });

  it('asks an unflagged candidate carrying no size or runnable flag at all', () => {
    const bare: FindingDraft = {
      kind: 'binary-pwnable-candidate',
      title: 'usr/bin/store_domain_sid',
      severity: 'medium',
      proofState: 'needs_runtime_reproduction',
      evidence: { path: 'usr/bin/store_domain_sid', unsafeFns: ['strcpy'] },
      rationale: '',
    };
    const interest: ProbeInterest = { services: [daemon('httpd', '/usr/sbin/httpd')] };
    expect(reachabilityLeads([bare, sized('usr/sbin/httpd', 9_000)], root, 2, interest).map((l) => l.target)).toEqual([
      'usr/sbin/httpd',
      'usr/bin/store_domain_sid',
    ]);
  });

  it('does not re-ask a binary W4 already put on the agenda — that slot would buy nothing', () => {
    const candidates = [sized('usr/sbin/gl-tor', 10), sized('usr/bin/small', 42)];
    const interest: ProbeInterest = {
      handlers: [taintedHandler('os.execute("/usr/sbin/gl-tor " .. params.enable)')],
      planned: new Set(['symreach:usr/sbin/gl-tor']),
    };
    expect(reachabilityLeads(candidates, root, 1, interest).map((l) => l.target)).toEqual(['usr/bin/small']);
  });

  it('spends nothing on a zero budget and everything askable on a budget larger than the list', () => {
    const candidates = [sized('usr/bin/small', 42), sized('usr/sbin/httpd', 9_000)];
    const interest: ProbeInterest = { services: [daemon('httpd', '/usr/sbin/httpd')] };
    expect(reachabilityLeads(candidates, root, 0, interest)).toEqual([]);
    expect(reachabilityLeads(candidates, root, 99, interest).map((l) => l.target)).toEqual([
      'usr/sbin/httpd',
      'usr/bin/small',
    ]);
  });
});

describe('specsForClass — rootfs-free recon reaches every class', () => {
  // The third experimental pass caught this: driving the providers directly over an eCos `rtos` image, the U-Boot
  // worker flagged `bootcmd` booting over tftp — a real exposure the fixed class plan could not reach, on an image
  // whose own coverage report called it fully covered. Those workers read the raw image and need no rootfs.
  const ROOTFS_FREE = ['certs', 'uboot', 'fcc'];

  for (const cls of ['rtos', 'baremetal', 'esp-soc', 'encrypted', 'uefi-bios', 'something-unknown']) {
    it(`routes ${cls} to the rootfs-free recon workers`, () => {
      const providers = specsForClass(cls).map((s) => s.provider);
      for (const p of ROOTFS_FREE) expect(providers).toContain(p);
    });
  }

  it('keeps each class its own deep worker rather than replacing it', () => {
    expect(specsForClass('esp-soc').map((s) => s.provider)).toContain('esp');
    expect(specsForClass('encrypted').map((s) => s.provider)).toContain('encrypted');
    expect(specsForClass('rtos').map((s) => s.provider)).toContain('rtos');
    expect(specsForClass('uefi-bios').map((s) => s.provider)).toContain('fwhunt');
  });

  it('does not duplicate them in the Linux chain, which already had them', () => {
    const providers = specsForClass('embedded-linux').map((s) => s.provider);
    for (const p of ROOTFS_FREE) expect(providers.filter((x) => x === p)).toHaveLength(1);
  });
});

describe('reproductionLeads — a proven-reachable sink is the one worth running', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-repro-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'pwnable'), { recursive: true });
  fs.writeFileSync(path.join(root, 'pwnable/bof'), '\x7fELF');

  const reached = (binary: string, sink: string, addresses: string[]): FindingDraft => ({
    kind: 'sink-reachable',
    title: `${sink} in ${binary} is reachable`,
    severity: 'high',
    proofState: 'static_confirmed',
    evidence: { binary, sink, addresses },
    rationale: '',
  });

  it('turns a reached sink into a reproduction lead carrying the call-site addresses', () => {
    const leads = reproductionLeads([reached('pwnable/bof', 'strcpy', ['0x400a30'])], root);
    expect(leads).toHaveLength(1);
    expect(leads[0]).toMatchObject({
      kind: 'reproduce-crash',
      target: 'pwnable/bof',
      sink: 'strcpy',
      addresses: ['0x400a30'],
    });
  });

  // An inconclusive has no address to break on and no reason to expect the path is taken.
  it('ignores anything that is not a proven-reachable sink', () => {
    const inconclusive: FindingDraft = {
      kind: 'sink-reachability-inconclusive',
      title: 'x',
      severity: 'info',
      proofState: 'needs_runtime_reproduction',
      evidence: { binary: 'pwnable/bof', sinks: ['gets'] },
      rationale: '',
    };
    expect(reproductionLeads([inconclusive], root)).toEqual([]);
  });

  it('drops a reached sink with no usable address rather than guessing one', () => {
    expect(reproductionLeads([reached('pwnable/bof', 'strcpy', [])], root)).toEqual([]);
  });

  it('respects the per-run budget', () => {
    const many = [reached('pwnable/bof', 'strcpy', ['0x1']), reached('pwnable/bof', 'gets', ['0x2'])];
    expect(reproductionLeads(many, root, 1)).toHaveLength(1);
    expect(reproductionLeads(many, root, 0)).toEqual([]);
  });

  it('keys the follow-up spec per binary AND sink, so two sinks are two probes', () => {
    const a = replan(reproductionLeads([reached('pwnable/bof', 'strcpy', ['0x1'])], root)[0] as Lead, new Set());
    const b = replan(reproductionLeads([reached('pwnable/bof', 'gets', ['0x2'])], root)[0] as Lead, new Set());
    expect(specKey(a[0] as never)).not.toBe(specKey(b[0] as never));
    expect(specKey(a[0] as never)).toBe('dynprobe:pwnable/bof#strcpy');
  });
});

describe('the nvram store reaches every class, because it needs no rootfs', () => {
  /**
   * Nine of the sixteen images in the corpus carry a flash key-value store, and they span routers, cameras and
   * both eCos Xiaomis. It reads the RAW upload rather than extraction output — which is why no rootfs-walking
   * provider had ever seen one — so withholding it from any class would be withholding it for no reason, and it
   * can never be reported `skipped` for want of a rootfs.
   */
  for (const cls of ['embedded-linux', 'rtos', 'baremetal', 'esp-soc', 'encrypted', 'unknown']) {
    it(`routes ${cls} to the nvram store scan`, () => {
      const spec = specsForClass(cls).find((s) => s.provider === 'nvram');
      expect(spec).toBeDefined();
      expect(spec?.needsRootfs).toBe(false);
      expect(spec?.built).toBe(true);
    });
  }
});
