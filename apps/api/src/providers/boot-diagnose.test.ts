import { describe, expect, it } from 'vitest';
import { diagnoseUnreachable, rankExits, readDaemonTrace, signalOf } from './boot-diagnose.js';

/**
 * The two cases in the middle of this file are transcribed from real consoles, because they are the pair that
 * justifies the module: the MR3220 and the WR940N both report `open: []` and need opposite work.
 */

const trace = (lines: string[]): string => lines.map((l) => `[    3.000000] ${l}`).join('\n');

const wire = (o: Partial<{ synsToGuest: number; synAcksFromGuest: number; resetsFromGuest: number }> = {}) => ({
  synsToGuest: 0,
  synAcksFromGuest: 0,
  resetsFromGuest: 0,
  ...o,
});

describe('signalOf', () => {
  it('reads a signal only where the code encodes one', () => {
    expect(signalOf(139)).toBe(11); // 128 + SIGSEGV
    expect(signalOf(134)).toBe(6);
    // Below 128 is an ordinary exit status, and dressing `1` up as a signal would invent a crash.
    expect(signalOf(1)).toBeNull();
    expect(signalOf(0)).toBeNull();
    expect(signalOf(255)).toBeNull();
  });
});

describe('readDaemonTrace', () => {
  it('follows a daemon from execve to exit, keeping the last file it opened', () => {
    const t = trace([
      'firmadyne: do_execve[PID: 103 (rcS)]: argv: /usr/bin/httpd, envp: USER=root',
      'firmadyne: do_sys_open[PID: 103 (httpd)]: file:/lib/libc.so.0',
      'firmadyne: do_sys_open[PID: 103 (httpd)]: file:/proc/simple_config/system_mode',
      'firmadyne: do_exit[PID: 103 (httpd)]: code:139',
    ]);
    const { started, exited } = readDaemonTrace(t);
    expect(started).toEqual(['httpd']);
    expect(exited).toEqual([
      { binary: 'httpd', pid: '103', code: 139, signal: 11, lastOpen: '/proc/simple_config/system_mode' },
    ]);
  });

  it('ignores a process that is not a network daemon, however loudly it dies', () => {
    const t = trace([
      'firmadyne: do_execve[PID: 42 (rcS)]: argv: /bin/mount, envp: USER=root',
      'firmadyne: do_exit[PID: 42 (mount)]: code:139',
    ]);
    expect(readDaemonTrace(t)).toEqual({ started: [], exited: [] });
  });

  it('does not blame a daemon for the exit of a pid that has since become something else', () => {
    // pids are reused across a boot; attributing the second program's death to the first is a fabricated crash.
    const t = trace([
      'firmadyne: do_execve[PID: 7 (rcS)]: argv: /usr/sbin/dropbear, envp: X=1',
      'firmadyne: do_execve[PID: 7 (dropbear)]: argv: /bin/sh, envp: X=1',
      'firmadyne: do_exit[PID: 7 (sh)]: code:139',
    ]);
    expect(readDaemonTrace(t).exited).toEqual([]);
  });

  it('reports a daemon that started and never exited as started', () => {
    const t = trace(['firmadyne: do_execve[PID: 9 (rcS)]: argv: /usr/bin/httpd, envp: X=1']);
    expect(readDaemonTrace(t)).toEqual({ started: ['httpd'], exited: [] });
  });
});

describe('diagnoseUnreachable', () => {
  it('says nothing when something answered', () => {
    const d = diagnoseUnreachable({ consoleOutput: '', forwards: 2, open: 1, wire: wire() });
    expect(d.cause).toBe('answered');
  });

  /** The MR3220, verbatim: 116 SYNs, 116 RSTs, and an httpd that segfaults on a missing `/proc` entry. */
  it('names the dead daemon and the file it died on, over the RSTs that would also explain it', () => {
    const d = diagnoseUnreachable({
      consoleOutput: trace([
        'firmadyne: do_execve[PID: 103 (rcS)]: argv: /usr/bin/httpd, envp: USER=root',
        'firmadyne: do_sys_open[PID: 103 (httpd)]: file:/proc/simple_config/system_mode',
        'firmadyne: do_exit[PID: 103 (httpd)]: code:139',
      ]),
      forwards: 2,
      open: 0,
      wire: wire({ synsToGuest: 116, resetsFromGuest: 116 }),
    });
    expect(d.cause).toBe('service-died');
    expect(d.summary).toContain('httpd');
    expect(d.summary).toContain('SIGSEGV');
    expect(d.summary).toContain('/proc/simple_config/system_mode');
    // The actionable half: it says what NOT to do, because widening the probe is the obvious wrong move here.
    expect(d.summary).toMatch(/forwarding more ports cannot reach/i);
  });

  /** The WR940N, verbatim: 158 SYNs in, nothing back, and an httpd that is provably still serving TLS. */
  it('separates a guest that DROPS the packets from one that refuses them', () => {
    const d = diagnoseUnreachable({
      consoleOutput: trace(['firmadyne: do_execve[PID: 104 (rcS)]: argv: /usr/bin/httpd, envp: USER=root']),
      forwards: 2,
      open: 0,
      wire: wire({ synsToGuest: 158 }),
    });
    expect(d.cause).toBe('guest-dropped');
    expect(d.summary).toContain('158');
    expect(d.summary).toMatch(/dropped inside the guest/i);
    // The claim it must never let a reader make.
    expect(d.summary).toMatch(/not "no service"/i);
    expect(d.evidence).toContain('running: httpd');
  });

  it('calls a RST what it is: the stack is up and the port is closed', () => {
    const d = diagnoseUnreachable({
      consoleOutput: '',
      forwards: 2,
      open: 0,
      wire: wire({ synsToGuest: 10, resetsFromGuest: 10 }),
    });
    expect(d.cause).toBe('nothing-listening');
    expect(d.summary).toMatch(/TCP stack is up and reachable/i);
  });

  /**
   * The WDR3600: 159 SYNs in and FOUR RSTs. The first version of this rule called that "nothing is bound" and
   * threw away the 155 that vanished, which is the more interesting half — and it was caught by running the
   * module against the real console rather than by any of the cases above.
   */
  it('does not let a handful of RSTs hide the packets that vanished', () => {
    const d = diagnoseUnreachable({
      consoleOutput: '',
      forwards: 2,
      open: 0,
      wire: wire({ synsToGuest: 159, resetsFromGuest: 4 }),
    });
    expect(d.cause).toBe('guest-dropped');
    expect(d.summary).toMatch(/155 of them got no answer at all/);
    expect(d.summary).toMatch(/part-way through the boot/);
  });

  it('puts the silence on the host side when no SYN ever arrived', () => {
    const d = diagnoseUnreachable({ consoleOutput: '', forwards: 2, open: 0, wire: wire() });
    expect(d.cause).toBe('no-syns');
    expect(d.summary).toMatch(/never asked/i);
  });

  it('says a run that forwarded nothing asked nothing, rather than blaming the firmware', () => {
    const d = diagnoseUnreachable({ consoleOutput: '', forwards: 0, open: 0, wire: null });
    expect(d.cause).toBe('no-syns');
    expect(d.summary).toMatch(/forwarded no ports/i);
  });

  it('refuses to guess with no capture, instead of picking the likeliest story', () => {
    const d = diagnoseUnreachable({ consoleOutput: '', forwards: 2, open: 0, wire: null });
    expect(d.cause).toBe('unknown');
    expect(d.summary).toMatch(/not something this deployment can say/i);
  });

  it('reports an ordinary exit as an exit, never as a crash', () => {
    const d = diagnoseUnreachable({
      consoleOutput: trace([
        'firmadyne: do_execve[PID: 5 (rcS)]: argv: /usr/sbin/telnetd, envp: X=1',
        'firmadyne: do_exit[PID: 5 (telnetd)]: code:1',
      ]),
      forwards: 1,
      open: 0,
      wire: wire({ synsToGuest: 3, resetsFromGuest: 3 }),
    });
    expect(d.summary).toContain('exited with status 1');
    expect(d.summary).not.toMatch(/signal|SIG/);
  });
});

/**
 * More than one daemon can die on a boot, and the first version led with `exited[0]` — making the choice an
 * artifact of the order init happened to start them in, and dropping the rest with no statement that they
 * existed. That is the rule `selectFindings` was fixed for, repeated in a new module.
 */
describe('more than one daemon dies', () => {
  const exit = (binary: string, code: number) => ({
    binary,
    pid: '1',
    code,
    signal: signalOf(code),
    lastOpen: null,
  });

  it('leads with the SIGNAL death, not with whichever init started first', () => {
    // A daemon that returned status 1 chose to stop; one that took SIGSEGV was stopped. The second says more.
    const ranked = rankExits([exit('telnetd', 1), exit('httpd', 139)]);
    expect(ranked[0]?.binary).toBe('httpd');
  });

  it('keeps trace order between two deaths of the same kind, rather than reordering on nothing', () => {
    const ranked = rankExits([exit('a', 139), exit('b', 139)]);
    expect(ranked.map((x) => x.binary)).toEqual(['a', 'b']);
  });

  it('states how many others also exited instead of silently reporting one of them', () => {
    const d = diagnoseUnreachable({
      consoleOutput: trace([
        'firmadyne: do_execve[PID: 1 (rcS)]: argv: /usr/sbin/telnetd, envp: X=1',
        'firmadyne: do_exit[PID: 1 (telnetd)]: code:1',
        'firmadyne: do_execve[PID: 2 (rcS)]: argv: /usr/bin/httpd, envp: X=1',
        'firmadyne: do_exit[PID: 2 (httpd)]: code:139',
      ]),
      forwards: 2,
      open: 0,
      wire: wire({ synsToGuest: 5, resetsFromGuest: 5 }),
    });
    // Led with the crash…
    expect(d.summary).toContain('httpd');
    expect(d.summary).toContain('SIGSEGV');
    // …and the other one is neither led with nor lost.
    expect(d.summary).toMatch(/1 other network daemon\(s\) also exited/);
    expect(d.evidence).toContain('2 daemon(s) exited in total');
    expect(d.daemonsExited.map((x) => x.binary).sort()).toEqual(['httpd', 'telnetd']);
  });

  it('says nothing about "others" when there is only one', () => {
    const d = diagnoseUnreachable({
      consoleOutput: trace([
        'firmadyne: do_execve[PID: 1 (rcS)]: argv: /usr/bin/httpd, envp: X=1',
        'firmadyne: do_exit[PID: 1 (httpd)]: code:139',
      ]),
      forwards: 1,
      open: 0,
      wire: wire({ synsToGuest: 1, resetsFromGuest: 1 }),
    });
    expect(d.summary).not.toMatch(/other network daemon/);
    expect(d.evidence).not.toContain('1 daemon(s) exited in total');
  });
});
