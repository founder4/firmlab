import { describe, expect, it } from 'vitest';
import {
  GUEST_SHELL_CMDLINE,
  MARK,
  consoleInterventions,
  consoleScript,
  describeConsole,
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
