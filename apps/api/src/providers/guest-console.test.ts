import { describe, expect, it } from 'vitest';
import {
  CONSOLE_FLAG,
  type ConsolePassGate,
  GUEST_SHELL_CMDLINE,
  MARK,
  classifyConsolePass,
  consoleInterventions,
  consoleScript,
  consoleScriptDurationMs,
  describeConsole,
  planConsolePass,
  readConsoleOutcome,
} from './guest-console.js';

const inputs = (over: Partial<Parameters<typeof consoleScript>[0]> = {}) => ({
  hasRcS: true,
  hasIptablesStop: true,
  hasIptables: true,
  intervene: true,
  ...over,
});

/** A console transcript as the serial port delivers it: CRLF, and every typed line echoed before its output. */
function transcript(o: {
  shell?: boolean;
  rcs?: boolean;
  before?: string | null;
  teardown?: boolean | 'control';
  after?: string | null;
  listeners?: string[] | null;
}): string {
  const L: string[] = ['[    0.000000] Linux version 4.1.17+'];
  if (o.shell !== false) L.push(`# echo ${MARK.shell}`, MARK.shell);
  if (o.rcs !== false) L.push(`# /etc/rc.d/rcS >/dev/null 2>&1; echo ${MARK.rcsDone}`, MARK.rcsDone);
  if (o.before !== null && o.before !== undefined) {
    L.push(`# echo ${MARK.polBefore}; iptables -L INPUT -n`, MARK.polBefore, `Chain INPUT (policy ${o.before})`);
  }
  if (o.teardown === 'control') L.push(`# echo ${MARK.noStop}`, MARK.noStop);
  else if (o.teardown !== false) L.push(`# /etc/rc.d/iptables-stop; echo ${MARK.stopDone}`, MARK.stopDone);
  if (o.after !== null && o.after !== undefined) {
    L.push(`# echo ${MARK.polAfter}; iptables -L INPUT -n`, MARK.polAfter, `Chain INPUT (policy ${o.after})`);
  }
  if (o.listeners !== null && o.listeners !== undefined) {
    L.push(`# echo ${MARK.listeners}; cat /proc/net/tcp`, MARK.listeners, '  sl  local_address rem_address   st');
    L.push(...o.listeners);
  }
  return `${L.join('\r\n')}\r\n`;
}

/** The real shape of a `/proc/net/tcp` row, big-endian MIPS, as this corpus's WR940N prints it. */
const listenRow = (hexPort: string, st = '0A') => `   0: 00000000:${hexPort} 00000000:0000 ${st} 00000000:00000000`;

describe('consoleScript', () => {
  it('gives rcS a long enough wait for the daemons to bind', () => {
    // The confound that nearly invalidated this experiment: httpd bound 80/443/22 roughly 30 s after rcS
    // returned, so a probe fired straight after rcS measures the wrong thing.
    const rcs = consoleScript(inputs()).find((s) => s.send.includes('rcS'));
    expect(rcs?.waitMs).toBeGreaterThanOrEqual(60_000);
  });

  it('spends the same wall-clock in the control arm as in the intervened one', () => {
    const total = (i: Parameters<typeof consoleScript>[0]) => consoleScript(i).reduce((n, s) => n + s.waitMs, 0);
    expect(total(inputs({ intervene: false }))).toBe(total(inputs({ intervene: true })));
  });

  it('reads the policy before it changes anything, and again after', () => {
    const sends = consoleScript(inputs()).map((s) => s.send);
    const before = sends.findIndex((s) => s.includes(MARK.polBefore));
    const stop = sends.findIndex((s) => s.includes('iptables-stop'));
    const after = sends.findIndex((s) => s.includes(MARK.polAfter));
    expect(before).toBeGreaterThanOrEqual(0);
    expect(before).toBeLessThan(stop);
    expect(stop).toBeLessThan(after);
  });

  it('never runs the teardown in the control arm', () => {
    expect(consoleScript(inputs({ intervene: false })).some((s) => s.send.includes('iptables-stop'))).toBe(false);
  });

  it('never runs a teardown the image does not ship', () => {
    expect(consoleScript(inputs({ hasIptablesStop: false })).some((s) => s.send.includes('iptables-stop'))).toBe(false);
  });

  it('silences rcS, because the daemon floods the console it inherits', () => {
    // `open device ar7100_gpio_chrdev failed`, thousands of times, is what drowned the first read of the ruleset.
    expect(consoleScript(inputs()).find((s) => s.send.includes('rcS'))?.send).toContain('>/dev/null 2>&1');
  });

  it('skips the rcS step entirely when the image ships no init script', () => {
    expect(consoleScript(inputs({ hasRcS: false })).some((s) => s.send.includes('rcS'))).toBe(false);
  });
});

describe('readConsoleOutcome', () => {
  it('reads a DROP → ACCEPT flush from the two dumps in one stream', () => {
    const o = readConsoleOutcome(transcript({ before: 'DROP', after: 'ACCEPT', listeners: [listenRow('0050')] }));
    expect(o.shellAnswered).toBe(true);
    expect(o.rcsCompleted).toBe(true);
    expect(o.policyBefore).toBe('DROP');
    expect(o.policyAfter).toBe('ACCEPT');
    expect(o.teardownRan).toBe(true);
  });

  it('does not report the first dump twice — the two are scoped by their own markers', () => {
    // A global match returns the BEFORE policy for both and reports a flush that never happened.
    const o = readConsoleOutcome(transcript({ before: 'DROP', after: 'DROP' }));
    expect(o.policyBefore).toBe('DROP');
    expect(o.policyAfter).toBe('DROP');
  });

  it('counts a marker as run only when the guest echoed it, not when it was typed', () => {
    // The typed line contains the marker. Treating presence as proof reports every step as done the instant it
    // is sent, which is the shape of the result this rung had to retract in 3cc413d.
    const typedOnly = `# /etc/rc.d/iptables-stop; echo ${MARK.stopDone}\r\n`;
    expect(readConsoleOutcome(typedOnly).teardownRan).toBe(false);
  });

  it('reads listening ports as decimal and ignores sockets that are not in LISTEN', () => {
    const o = readConsoleOutcome(
      transcript({
        before: 'DROP',
        after: 'ACCEPT',
        listeners: [listenRow('0050'), listenRow('01BB'), listenRow('076C'), listenRow('0016', '01')],
      }),
    );
    expect(o.listening).toEqual([80, 443, 1900]);
    expect(o.listenersRead).toBe(true);
  });

  it('separates "the table was read and was empty" from "the table was never read"', () => {
    expect(readConsoleOutcome(transcript({ before: 'DROP', listeners: [] })).listenersRead).toBe(true);
    expect(readConsoleOutcome(transcript({ before: 'DROP', listeners: null })).listenersRead).toBe(false);
  });

  it('reports nothing at all when no shell ever answered', () => {
    const o = readConsoleOutcome('[    0.000000] Linux version 4.1.17+\r\nkernel panic\r\n');
    expect(o.shellAnswered).toBe(false);
    expect(o.policyBefore).toBeNull();
    expect(o.listening).toEqual([]);
  });

  it('boots with a cmdline that asks for a shell', () => {
    expect(GUEST_SHELL_CMDLINE).toBe('init=/bin/sh');
  });
});

describe('consoleInterventions', () => {
  it('names the replaced init first, because it is the modification a reader will not think of', () => {
    const out = consoleInterventions(
      readConsoleOutcome(transcript({ before: 'DROP', after: 'ACCEPT', listeners: [listenRow('0050')] })),
    );
    expect(out[0]).toContain('init=/bin/sh');
    expect(out[0]).toContain('inittab');
  });

  it('records the flush with the policy change that evidences it', () => {
    const out = consoleInterventions(readConsoleOutcome(transcript({ before: 'DROP', after: 'ACCEPT' })));
    expect(out.some((s) => s.includes('DROP → ACCEPT'))).toBe(true);
    expect(out.some((s) => s.includes('its boot path never calls'))).toBe(true);
  });

  it('lists no intervention at all when no shell answered', () => {
    expect(consoleInterventions(readConsoleOutcome('kernel panic'))).toEqual([]);
  });

  it('claims NO teardown in the control arm — the branch that must find nothing', () => {
    // Found by running the real control boot, not by a fixture: both arms echoed the same marker, so the control
    // reported `teardownRan: true` and listed "the firmware's own /etc/rc.d/iptables-stop was run" on the arm
    // that ran nothing. Second false intervention claim on this rung; the first one was retracted in 3cc413d.
    const o = readConsoleOutcome(transcript({ before: 'DROP', after: 'DROP', teardown: 'control' }));
    expect(o.teardownRan).toBe(false);
    expect(o.policyBefore).toBe('DROP');
    expect(o.policyAfter).toBe('DROP');
    expect(consoleInterventions(o).some((x) => x.includes('iptables-stop'))).toBe(false);
  });

  it('does not claim a teardown whose marker never came back', () => {
    const out = consoleInterventions(readConsoleOutcome(transcript({ before: 'DROP', teardown: false })));
    expect(out.some((s) => s.includes('iptables-stop'))).toBe(false);
  });
});

describe('describeConsole', () => {
  it('says a DROP policy is exactly the symptom the rung reported', () => {
    const s = describeConsole(readConsoleOutcome(transcript({ before: 'DROP', after: 'ACCEPT' })));
    expect(s).toContain('without a reset');
  });

  it('says the firewall was NOT the cause when the policy was already ACCEPT', () => {
    // A repair that cannot tell you it was unnecessary is not a diagnosis.
    const s = describeConsole(readConsoleOutcome(transcript({ before: 'ACCEPT', after: 'ACCEPT' })));
    expect(s).toContain('NOT what silences this firmware');
    expect(s).toContain('still open');
  });

  it('claims nothing about a guest that never gave a shell', () => {
    expect(describeConsole(readConsoleOutcome('kernel panic'))).toContain('nothing about it is claimed');
  });

  it('says outright when nothing was listening, whatever the policy', () => {
    const s = describeConsole(readConsoleOutcome(transcript({ before: 'DROP', after: 'ACCEPT', listeners: [] })));
    expect(s).toContain('no listening TCP port at all');
  });
});

describe('consoleScriptDurationMs', () => {
  it('is the sum of the script the caller is about to run, not a number beside it', () => {
    const steps = consoleScript(inputs());
    expect(consoleScriptDurationMs(steps)).toBe(steps.reduce((n, s) => n + s.waitMs, 0));
  });

  /**
   * The reason this function exists rather than a constant: the schedule is longer than `BOOT_TIMEOUT_MS`, so a
   * driven pass sized by the un-driven pass's box would be killed before the two reads the outcome comes from.
   */
  it('exceeds the 120 s box the un-driven passes use, which is why the deadline is derived', () => {
    expect(consoleScriptDurationMs(consoleScript(inputs()))).toBeGreaterThan(120_000 - 45_000);
  });

  it('is zero for an empty script rather than undefined', () => {
    expect(consoleScriptDurationMs([])).toBe(0);
  });
});

describe('planConsolePass — six gates, and the branch that runs is only one of them', () => {
  const gate = (over: Partial<ConsolePassGate> = {}): ConsolePassGate => ({
    enabled: true,
    answered: 0,
    booted: true,
    panicked: false,
    rootfsAvailable: true,
    alreadyIntervened: false,
    ...over,
  });

  it('runs when nothing answered on a guest that booted', () => {
    const p = planConsolePass(gate());
    expect(p.run).toBe(true);
    expect(p.reason).toContain('asked directly');
  });

  it('does not run with the flag off, and says the question was not put — never that there was nothing to say', () => {
    const p = planConsolePass(gate({ enabled: false }));
    expect(p.run).toBe(false);
    expect(p.reason).toContain(CONSOLE_FLAG);
    expect(p.reason).toContain('the question was not put');
  });

  it('never touches a firmware that already answers', () => {
    const p = planConsolePass(gate({ answered: 2 }));
    expect(p.run).toBe(false);
    expect(p.reason).toContain('as shipped');
  });

  it('declines on a panic before it declines on a missing boot marker — a panic is the more specific fact', () => {
    // Both are true of a panicked guest (`booted` is false whenever `panicked` is true), and the reader deserves
    // the cause rather than its consequence.
    const p = planConsolePass(gate({ booted: false, panicked: true }));
    expect(p.reason).toContain('panicked');
  });

  it('declines when no pass printed a boot', () => {
    expect(planConsolePass(gate({ booted: false })).reason).toContain('no evidence a shell could exist');
  });

  it('declines without a rootfs rather than assembling the script from assumptions', () => {
    const p = planConsolePass(gate({ rootfsAvailable: false }));
    expect(p.run).toBe(false);
    expect(p.reason).toContain('nobody looked at');
  });

  /**
   * The gate that is about correctness rather than cost. The appended-line repair runs the vendor teardown from
   * inside `rcS`, and this script runs `rcS` and THEN reads the policy — so the "before" read would show the flush
   * this workbench caused, and `describeConsole` would report the firewall exonerated on that evidence.
   */
  it('declines when the repair already flushed this image, because the before-read would measure our own flush', () => {
    const p = planConsolePass(gate({ alreadyIntervened: true }));
    expect(p.run).toBe(false);
    expect(p.reason).toContain('FIRMLAB_EMU_REPAIR');
    expect(p.reason).toContain('cannot attribute');
  });
});

describe('classifyConsolePass', () => {
  const outcome = (t: Parameters<typeof transcript>[0], open = 0) =>
    classifyConsolePass(readConsoleOutcome(transcript(t)), open);

  it('keeps confirmed_full_system when a port answered, and says in the TITLE that it was not as shipped', () => {
    const v = outcome({ before: 'DROP', after: 'ACCEPT', listeners: [listenRow('0050')] }, 1);
    expect(v.proofState).toBe('confirmed_full_system');
    expect(v.kind).toBe('system-console-answered');
    // The census is the number people quote, so the qualification cannot live only in `interventions`.
    expect(v.title).toContain('not as shipped');
    expect(v.reason).toContain('says nothing about the physical device');
  });

  it('grades a read policy as confirmed_in_emulation when nothing answered even so', () => {
    const v = outcome({ before: 'DROP', after: 'ACCEPT', listeners: [listenRow('0050')] }, 0);
    expect(v.proofState).toBe('confirmed_in_emulation');
    expect(v.kind).toBe('system-console-diagnosed');
    expect(v.title).toContain('DROP → ACCEPT');
  });

  it('does not print an arrow when the policy did not move', () => {
    expect(outcome({ before: 'ACCEPT', after: 'ACCEPT' }).title).not.toContain('→');
  });

  /** A shell that never answered is the question failing, not the firmware answering it. */
  it('blocks by platform when no shell answered, and refuses to read that as a negative', () => {
    const v = classifyConsolePass(readConsoleOutcome('[ 0.0] Linux version 4.1.17+'), 0);
    expect(v.proofState).toBe('blocked_by_platform');
    expect(v.kind).toBe('system-console-blocked');
    expect(v.reason).toContain('in either direction');
  });

  it('reports a shell that answered and read nothing as a lead, not as a measurement', () => {
    const v = outcome({ before: null, after: null, listeners: null });
    expect(v.proofState).toBe('needs_runtime_reproduction');
    expect(v.kind).toBe('system-console-inconclusive');
  });

  it('gives every branch its own kind, so the ledger can separate them', () => {
    const kinds = [
      outcome({ before: 'DROP', after: 'ACCEPT' }, 1).kind,
      outcome({ before: 'DROP', after: 'ACCEPT' }, 0).kind,
      classifyConsolePass(readConsoleOutcome('nothing'), 0).kind,
      outcome({ before: null, after: null, listeners: null }).kind,
    ];
    expect(new Set(kinds).size).toBe(4);
  });
});
