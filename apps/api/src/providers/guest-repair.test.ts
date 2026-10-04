import { describe, expect, it } from 'vitest';
import {
  FLUSHED,
  type GuestRepairInputs,
  INITTAB_LINE_MAX,
  INIT_EXEC_GUARD,
  REPAIR_FLAG,
  REPAIR_REPORT_MAX,
  RULES_BEGIN,
  RULES_END,
  chooseRepairPlacement,
  createRepairReportTap,
  describeRepairDisposition,
  describeRuleset,
  findSysinitInsertion,
  insertAfterShebang,
  planGuestRepair,
  readGuestRuleset,
} from './guest-repair.js';

const RCS = '#!/bin/sh\nifconfig lo 127.0.0.1 up\n/usr/bin/httpd\n';
const INITTAB = '# vendor\n::sysinit:/etc/rc.d/rcS\n::askfirst:-/bin/sh\n::ctrlaltdel:/sbin/reboot\n';

const inputs = (o: Partial<GuestRepairInputs> = {}): GuestRepairInputs => ({
  initScript: 'etc/rc.d/rcS',
  initScriptText: RCS,
  inittab: INITTAB,
  hasIptablesStop: true,
  hasIptablesSave: true,
  hasPing: true,
  ...o,
});

describe('planGuestRepair', () => {
  it('runs the firmware’s OWN teardown, and injects no file of its own', () => {
    const p = planGuestRepair(inputs());
    const line = p.line ?? '';
    expect(line).toContain('/etc/rc.d/iptables-stop');
    // Everything this EXECUTES has to already be in the image: a repair that ships a binary into the guest could
    // introduce behaviour the firmware does not contain, and the intervention sentence could not stay true. Every
    // absolute path in the line is checked, rather than grepping for a name — the `FIRMLAB_` markers are echoed
    // strings and are supposed to be there, since they are how our output is found in the vendor's console.
    for (const p of line.match(/\/[\w./-]+/g) ?? []) {
      expect(p).toMatch(/^\/(etc\/rc\.d\/iptables-stop|dev\/null)$/);
    }
  });

  it('reads the ruleset BEFORE flushing it, because a repair that cannot say it was pointless is not a diagnosis', () => {
    const p = planGuestRepair(inputs());
    const line = p.line ?? '';
    expect(line.indexOf('iptables-save')).toBeLessThan(line.indexOf('iptables-stop'));
    expect(line).toContain(RULES_BEGIN);
    expect(line).toContain(RULES_END);
  });

  it('waits with ping, because this busybox has no sleep', () => {
    // BusyBox 1.01 on the WR940N and the MR3220 ships no `sleep` applet at all. Firing immediately would read an
    // empty ruleset before httpd had installed one.
    expect(planGuestRepair(inputs()).line).toMatch(/ping -c \d+ 127\.0\.0\.1/);
  });

  /**
   * The timer's precondition moved with the placement, and it would have failed silently. Appended at the END of
   * `rcS` the wait could assume `lo` was already up; executed BEFORE `rcS` it cannot, and `ping` against a down
   * loopback exits in milliseconds — so a bare `ping -c 20` would have elapsed the entire wait at t≈0, read an
   * empty ruleset and flushed rules httpd had not installed yet. A measurement-shaped nothing.
   */
  it('retries the ping, because it now runs before the vendor brings `lo` up', () => {
    const line = planGuestRepair(inputs()).line ?? '';
    // Bounded by nested loops over ten positional parameters — 100 tries — so a guest whose `lo` never comes up stops
    // forking instead of spinning for the whole boot.
    expect(line).toMatch(/set 0 1 2 3 4 5 6 7 8 9;for a do for b do ping -c \d+ 127\.0\.0\.1 [^;]*&&break 2;done;done/);
  });

  it('reads and flushes NOTHING when the timer runs out, rather than reading a ruleset at t≈0', () => {
    const line = planGuestRepair(inputs()).line ?? '';
    // `break 2` leaves the loops with status 0; exhausting them leaves ping's failure, and `|| exit` ends the subshell
    // before the first marker. Measured on the WR940N's msh: the exhausted run printed nothing at all.
    expect(line).toMatch(/done;done\|\|exit;echo FIRMLAB_RULES_BEGIN/);
  });

  /**
   * The first inittab-first line was a syntax error on the real WR940N console and never ran. Each of these is a
   * construct the guest's BusyBox 1.01 msh was measured rejecting; none of them may come back.
   */
  it('uses nothing the guest’s BusyBox 1.01 msh cannot parse', () => {
    const line = planGuestRepair(inputs()).line ?? '';
    expect(line).not.toContain('$((');
    expect(line).not.toMatch(/\bexec\b/);
    // A quoted `sh -c '…'` wrapper is useless here: msh's `exec` re-splits quoted arguments.
    expect(line).not.toMatch(/sh -c/);
  });

  it('survives the `exec ` busybox init prepends to an inittab entry', () => {
    const p = planGuestRepair(inputs());
    const entry = (p.placement?.content ?? '').split('\n').find((l) => l.includes(FLUSHED)) ?? '';
    // init runs `/bin/sh -c "exec <entry>"`. `exec (` is a syntax error in every shell — it is what the WR940N console
    // printed — so the entry must open with a redirection-only command that makes that exec a no-op.
    expect(entry.startsWith(`::sysinit:${INIT_EXEC_GUARD}(`)).toBe(true);
    expect(`exec ${entry.slice('::sysinit:'.length)}`).toMatch(/^exec 2>&1;\(/);
  });

  it('backgrounds itself so the vendor boot is not held up by the wait', () => {
    expect(planGuestRepair(inputs()).line?.trim().endsWith('&')).toBe(true);
  });

  it('states the intervention in words that will travel on every finding from the boot', () => {
    const p = planGuestRepair(inputs());
    expect(p.interventions).toHaveLength(1);
    expect(p.interventions[0]).toMatch(/iptables-stop/);
    // The half a reader needs: what it means for anything that then answered.
    expect(p.interventions[0]).toMatch(/may have answered only because/i);
  });

  describe('refuses rather than improvises', () => {
    it('does nothing when there is no init layout at all, and says the guest booted as shipped', () => {
      const p = planGuestRepair(inputs({ initScript: null, initScriptText: null, inittab: null }));
      expect(p.line).toBeNull();
      expect(p.placement).toBeNull();
      expect(p.interventions).toEqual([]);
      expect(p.skipped[0]).toMatch(/boots exactly as shipped/);
    });

    it('refuses when the inittab is unreadable and there is no init script to fall back to', () => {
      const p = planGuestRepair(inputs({ initScript: null, initScriptText: null, inittab: 'garbage\n' }));
      expect(p.line).toBeNull();
      expect(p.placement).toBeNull();
      expect(p.interventions).toEqual([]);
      // The refusal names what it could not read AND why appending anyway would have been worse than nothing.
      expect(p.skipped[0]).toMatch(/not id:runlevels:action:process/);
      expect(p.skipped[0]).toMatch(/no CPU executed/);
    });

    it('does NOT inject a flush of its own when the firmware ships none', () => {
      const p = planGuestRepair(inputs({ hasIptablesStop: false }));
      expect(p.line).toBeNull();
      expect(p.interventions).toEqual([]);
      expect(p.skipped[0]).toMatch(/runs only what the image already contains/);
    });

    it('refuses when there is no timer, rather than reading a ruleset that does not exist yet', () => {
      const p = planGuestRepair(inputs({ hasPing: false }));
      expect(p.line).toBeNull();
      expect(p.skipped[0]).toMatch(/reads as a measurement and is not one/);
    });

    it('still repairs without iptables-save, and says what is then missing', () => {
      const p = planGuestRepair(inputs({ hasIptablesSave: false }));
      expect(p.line).toContain('iptables-stop');
      expect(p.line).not.toContain('iptables-save');
      expect(p.interventions).toHaveLength(1);
      expect(p.skipped[0]).toMatch(/whether it was the thing that mattered/);
    });
  });
});

describe('readGuestRuleset', () => {
  const console_ = (rules: string, flushed = true): string =>
    `[ 1.0] boot\n${RULES_BEGIN}\n${rules}\n${RULES_END}\n${flushed ? `${FLUSHED}\n` : ''}[ 30.0] more`;

  it('reads the ruleset back verbatim', () => {
    const r = readGuestRuleset(console_('-P INPUT DROP\n-A INPUT -j ACCEPT'));
    expect(r.ran).toBe(true);
    expect(r.rules).toBe('-P INPUT DROP\n-A INPUT -j ACCEPT');
    expect(r.flushed).toBe(true);
  });

  /** The whole reason the read happens before the flush. */
  it('treats an EMPTY ruleset as a real answer, not as the line never running', () => {
    const r = readGuestRuleset(console_(''));
    expect(r.ran).toBe(true);
    expect(r.rules).toBe('');
    expect(describeRuleset(r)).toMatch(/NO iptables rules/);
    // …and it names what to look at instead, rather than leaving the reader with a negative.
    expect(describeRuleset(r)).toMatch(/bridge\/VLAN modules/);
  });

  it('says the line never reported when the markers are absent', () => {
    const r = readGuestRuleset('[ 1.0] boot\n[ 30.0] more');
    expect(r.ran).toBe(false);
    expect(describeRuleset(r)).toMatch(/never reported back/);
  });

  it('counts the rules it found', () => {
    const r = readGuestRuleset(console_('-P INPUT DROP\n-A INPUT -j X\n-A FORWARD -j Y'));
    expect(describeRuleset(r)).toMatch(/2 iptables rule\(s\)/);
  });

  /**
   * Verbatim shape of the real WR940N console (2026-10-04) for the first inittab-first line: firmadyne logs the
   * execve WITH its argv, the argv contains every marker, and the line itself died on `syntax error`. The substring
   * reader returned `ran: true`, rules "; iptables-save 2>&1; echo" and "0 rules, flush ran" — a fabricated
   * measurement of a line that never executed.
   */
  it('does not mistake the kernel’s echo of the command for the command running', () => {
    const argv =
      '(n=0; until ping -c 20 127.0.0.1 >/dev/null 2>&1 || [ $n -ge 600 ]; do n=$((n+1)); done; echo FIRMLAB_RULES_BEGIN; iptables-save 2>&1; echo FIRMLAB_RULES_END; /etc/rc.d/iptables-stop >/dev/null 2>&1; echo FIRMLAB_FLUSHED) &';
    const real = [
      'init started:  BusyBox v1.01 (2026.05.28-02:39+0000) multi-call binary',
      `[    0.776593] firmadyne: do_execve[PID: 50 (init)]: argv: /bin/sh -c exec ${argv}, envp: HOME=/ TERM=vt102`,
      `[ANALYZE] [PID: 50 (init)]: /bin/sh -c exec ${argv}`,
      '[    0.793759] firmadyne: vfs_ioctl[PID: 50 (sh)]: cmd:0x0 arg:0x540d',
      'syntax error',
      '[    0.795148] firmadyne: do_exit[PID: 50 (sh)]: code:65280',
    ].join('\r\n');
    const r = readGuestRuleset(real);
    expect(r).toEqual({ ran: false, rules: '', read: false, flushed: false });
    expect(describeRuleset(r)).toMatch(/no evidence it executed/);
  });

  it('reads markers on a serial console’s CRLF lines, and drops kernel lines interleaved into the block', () => {
    const r = readGuestRuleset(
      [
        'boot',
        RULES_BEGIN,
        '*filter',
        '[   21.5] firmadyne: do_execve[PID: 9]',
        '-A INPUT -j DROP',
        'COMMIT',
        RULES_END,
        FLUSHED,
      ].join('\r\n'),
    );
    expect(r).toEqual({ ran: true, rules: '*filter\n-A INPUT -j DROP\nCOMMIT', read: true, flushed: true });
  });

  it('never calls a ruleset EMPTY when it was not read at all', () => {
    // A flush with no read block — no iptables-save, or a console that lost the block — is not an empty filter.
    const r = readGuestRuleset(`boot\n${FLUSHED}\n`);
    expect(r).toMatchObject({ ran: true, read: false, flushed: true });
    expect(describeRuleset(r)).toMatch(/never read back/);
    expect(describeRuleset(r)).not.toMatch(/NO iptables rules/);
  });
});

describe('createRepairReportTap — the report survives the console cap', () => {
  it('reassembles markers split across chunks and keeps only the report', () => {
    const tap = createRepairReportTap();
    for (const c of [
      'noise\r\nFIRMLAB_RU',
      'LES_BEGIN\r\n-A INPUT -j DROP\r',
      '\nFIRMLAB_RULES_END\r\nmore\r\nFIRMLAB_FLUSHED',
    ]) {
      tap.push(c);
    }
    expect(tap.text()).toBe(`${RULES_BEGIN}\n-A INPUT -j DROP\n${RULES_END}\n${FLUSHED}\n`);
    expect(readGuestRuleset(tap.text())).toEqual({ ran: true, rules: '-A INPUT -j DROP', read: true, flushed: true });
  });

  it('ignores a marker that only appears inside a longer line', () => {
    const tap = createRepairReportTap();
    tap.push(`[ 0.7] firmadyne: do_execve argv: /bin/sh -c exec (echo ${RULES_BEGIN}; echo ${FLUSHED}) &\n`);
    expect(tap.text()).toBe('');
  });

  it('keeps the report even when it lands in the middle the 256 KB cap elides', () => {
    const tap = createRepairReportTap();
    const filler = `${'[ 1.0] firmadyne: close[PID: 50 (sh)]: fd:3\n'.repeat(4000)}`;
    tap.push(filler);
    tap.push(`${RULES_BEGIN}\n-A INPUT -j DROP\n${RULES_END}\n${FLUSHED}\n`);
    tap.push(filler);
    expect(readGuestRuleset(tap.text())).toMatchObject({ ran: true, read: true, rules: '-A INPUT -j DROP' });
  });

  it('closes a truncated block and says so inside it, rather than losing the read', () => {
    const tap = createRepairReportTap(128);
    tap.push(`${RULES_BEGIN}\n${'-A INPUT -j DROP\n'.repeat(20)}${RULES_END}\n${FLUSHED}\n`);
    expect(tap.text().length).toBeLessThanOrEqual(128);
    const r = readGuestRuleset(tap.text());
    expect(r).toMatchObject({ ran: true, read: true, flushed: true });
    // A prefix of the ruleset, then the note: the bound shortens the block, it does not punch holes in it.
    expect(r.rules).toBe('-A INPUT -j DROP\n# FirmLab: ruleset truncated at 128 bytes');
  });

  /**
   * `max` is a bound on `text()` for EVERY input. The first tap bounded only the lines between the markers, so each
   * of these grew it without limit: a marker printed in a loop, and a console that never sends another newline.
   */
  describe('bounds text() under hostile input', () => {
    const MAX = 256;

    it('keeps one report however often the markers repeat', () => {
      const tap = createRepairReportTap(MAX);
      const report = `${RULES_BEGIN}\n-A INPUT -j DROP\n${RULES_END}\n${FLUSHED}\n`;
      tap.push(report);
      for (let i = 0; i < 10_000; i++) tap.push(`${RULES_END}\r\n${FLUSHED}\n${RULES_BEGIN}\n-A X\n`);
      tap.push(`${RULES_END}\n`);
      expect(tap.text()).toBe(report);
      expect(readGuestRuleset(tap.text())).toEqual({ ran: true, rules: '-A INPUT -j DROP', read: true, flushed: true });
    });

    it('stays bounded under repeated end and flush markers with no block at all', () => {
      const tap = createRepairReportTap(MAX);
      for (let i = 0; i < 10_000; i++) tap.push(`${RULES_END}\n${FLUSHED}\n`);
      tap.push(RULES_END);
      expect(tap.text()).toBe(`${FLUSHED}\n`);
      // A stray end marker is not a read; the reader ignores it on the raw console too.
      expect(readGuestRuleset(tap.text())).toMatchObject({ ran: true, read: false, flushed: true });
    });

    it('does not buffer a newline-free line whole, and does not mistake it for a marker', () => {
      const tap = createRepairReportTap(MAX);
      for (let i = 0; i < 1000; i++) tap.push(FLUSHED.repeat(100));
      expect(tap.text()).toBe('');
      tap.push(`\n${RULES_BEGIN}\n-A INPUT -j DROP\n${RULES_END}\n`);
      expect(readGuestRuleset(tap.text())).toMatchObject({
        ran: true,
        read: true,
        flushed: false,
        rules: '-A INPUT -j DROP',
      });
    });

    it('truncates at an arbitrarily long rule line inside the block, and still closes it', () => {
      const tap = createRepairReportTap(MAX);
      tap.push(`${RULES_BEGIN}\n-A INPUT -j DROP\n`);
      for (let i = 0; i < 1000; i++) tap.push('-A INPUT -m comment --comment x'.repeat(50));
      tap.push(`\n-A AFTER -j ACCEPT\n${RULES_END}\n${FLUSHED}\n`);
      expect(tap.text().length).toBeLessThanOrEqual(MAX);
      const r = readGuestRuleset(tap.text());
      expect(r).toMatchObject({ ran: true, read: true, flushed: true });
      expect(r.rules).toBe(`-A INPUT -j DROP\n# FirmLab: ruleset truncated at ${MAX} bytes`);
    });

    it('drops an over-long kernel line inside the block without calling the ruleset truncated', () => {
      const tap = createRepairReportTap(MAX);
      tap.push(
        `${RULES_BEGIN}\n[   21.5] firmadyne: do_execve[PID: 9]: argv: ${'x'.repeat(10 * MAX)}\n-A INPUT -j DROP\n`,
      );
      tap.push(`${RULES_END}\n`);
      expect(readGuestRuleset(tap.text()).rules).toBe('-A INPUT -j DROP');
    });

    it('bounds an oversized ruleset, reserving room for both closing markers', () => {
      const tap = createRepairReportTap(MAX);
      tap.push(`${RULES_BEGIN}\n`);
      for (let i = 0; i < 100_000; i++) tap.push(`-A INPUT -s 10.0.${i % 256}.0/24 -j DROP\n`);
      expect(tap.text().length).toBeLessThanOrEqual(MAX);
      // Killed before the end marker: the block was never closed, so it is not a read, however much was kept.
      expect(readGuestRuleset(tap.text())).toMatchObject({ ran: true, read: false });
      tap.push(`${RULES_END}\n${FLUSHED}`);
      expect(tap.text().length).toBeLessThanOrEqual(MAX);
      const r = readGuestRuleset(tap.text());
      expect(r).toMatchObject({ ran: true, read: true, flushed: true });
      expect(r.rules).toMatch(
        /^-A INPUT -s 10\.0\.0\.0\/24 -j DROP\n[\s\S]*# FirmLab: ruleset truncated at 256 bytes$/,
      );
    });

    it('holds the default bound too', () => {
      const tap = createRepairReportTap();
      tap.push(`${RULES_BEGIN}\n`);
      for (let i = 0; i < 20_000; i++) tap.push(`-A INPUT -s 10.0.${i % 256}.0/24 -j DROP\n${FLUSHED}\n`);
      tap.push(`${RULES_END}\n`);
      expect(tap.text().length).toBeLessThanOrEqual(REPAIR_REPORT_MAX);
      expect(readGuestRuleset(tap.text())).toMatchObject({ read: true, flushed: true });
    });

    it('refuses a bound too small to hold its own markers rather than reporting a line that never ran', () => {
      expect(() => createRepairReportTap(64)).toThrow(RangeError);
    });
  });

  it('keeps a split end marker that is still pending when the guest is killed', () => {
    const tap = createRepairReportTap();
    tap.push(`${RULES_BEGIN}\r\n-A INPUT -j DROP\r\nFIRMLAB_RU`);
    tap.push('LES_END\r');
    expect(readGuestRuleset(tap.text())).toEqual({ ran: true, rules: '-A INPUT -j DROP', read: true, flushed: false });
  });
});

/**
 * `interventions: []` is a load-bearing empty value — the design reads it as "the image as shipped" — and that
 * reading is only true if the firmware was actually examined. With the flag off nothing was looked at, so the same
 * empty list would be a claim about a look that never happened. This is that distinction, and it is the reason
 * `attempted` exists at all.
 */
describe('describeRepairDisposition — "nobody asked" is not "asked and changed nothing"', () => {
  const plannable: GuestRepairInputs = inputs();

  it('reports the flag being off as silence, and refuses to say the image was as shipped', () => {
    const d = describeRepairDisposition(false, null);
    expect(d.attempted).toBe(false);
    expect(d.interventions).toEqual([]);
    expect(d.note).toMatch(/the question was not asked/);
    expect(d.note).not.toMatch(/as shipped/);
  });

  it('reports an examined-and-untouched firmware as exactly that, with the same empty list', () => {
    // No iptables-stop: the plan declines, and declining is a measurement.
    const plan = planGuestRepair({ ...plannable, hasIptablesStop: false });
    const d = describeRepairDisposition(true, plan);
    expect(d.attempted).toBe(true);
    expect(d.interventions).toEqual([]);
    expect(d.note).toMatch(/booted as shipped/);
    // The pair: identical `interventions`, opposite meanings, and the discriminator is not the list.
    expect(describeRepairDisposition(false, null).interventions).toEqual(d.interventions);
    expect(describeRepairDisposition(false, null).attempted).not.toBe(d.attempted);
  });

  it('carries the skip reason so an unattempted repair is never mistaken for a failed one', () => {
    const d = describeRepairDisposition(true, planGuestRepair({ ...plannable, hasPing: false }));
    expect(d.skipped.join(' ')).toMatch(/no `ping` applet/);
    expect(d.note).toMatch(/booted as shipped/);
  });

  it('says the image was MODIFIED when a line was appended, and names what ran', () => {
    const d = describeRepairDisposition(true, planGuestRepair(plannable));
    expect(d.attempted).toBe(true);
    expect(d.interventions).toHaveLength(1);
    expect(d.note).toMatch(/was MODIFIED for the boot/);
    expect(d.interventions[0]).toMatch(/iptables-stop/);
    expect(d.interventions[0]).toMatch(/may have answered only because/);
  });

  it('distinguishes "no rootfs to examine" from both of the above', () => {
    const d = describeRepairDisposition(true, null);
    expect(d.attempted).toBe(true);
    expect(d.interventions).toEqual([]);
    expect(d.note).toMatch(/no rootfs was available to examine/);
    expect(d.note).not.toMatch(/as shipped/);
  });

  it('names the flag in every branch, so a reader knows which switch produced the state', () => {
    for (const d of [
      describeRepairDisposition(false, null),
      describeRepairDisposition(true, null),
      describeRepairDisposition(true, planGuestRepair({ ...plannable, hasIptablesStop: false })),
      describeRepairDisposition(true, planGuestRepair(plannable)),
    ]) {
      expect(d.note).toContain(REPAIR_FLAG);
    }
  });
});

/**
 * The defect this replaced: the repair was APPENDED to the end of `/etc/rc.d/rcS`, which is the one point of the
 * boot that is never reached — the vendor's `rcS` ends by starting the daemons that keep the system up and does not
 * return. So `interventions: [1]` was reported for a line no CPU ever executed, and nothing short of reading the
 * guest's console could tell the two apart. These fixtures are about WHERE the line lands, because that is the
 * entire difference between a repair and a note in a file.
 */
describe('where the repair lands', () => {
  const VENDOR_SYSINIT = '::sysinit:/etc/rc.d/rcS';

  it('takes the inittab route, as the FIRST sysinit entry — above the vendor’s own', () => {
    const p = planGuestRepair(inputs());
    expect(p.placement?.kind).toBe('inittab-sysinit');
    expect(p.placement?.file).toBe('etc/inittab');
    const content = p.placement?.content ?? '';
    const entry = `::sysinit:${INIT_EXEC_GUARD}${p.line}`;
    expect(content.indexOf(entry)).toBeGreaterThanOrEqual(0);
    // Ordering IS the fix: busybox init runs sysinit entries in file order and waits for each, so ours executes
    // before rcS starts and stops depending on whether rcS ever returns.
    expect(content.indexOf(entry)).toBeLessThan(content.indexOf(VENDOR_SYSINIT));
  });

  it('adds exactly one line and leaves every other byte of the inittab alone', () => {
    const content = planGuestRepair(inputs()).placement?.content ?? '';
    const lines = content.split('\n');
    const ours = lines.findIndex((l) => l.startsWith(`::sysinit:${INIT_EXEC_GUARD}(`));
    expect(ours).toBeGreaterThanOrEqual(0);
    lines.splice(ours, 1);
    // Byte-identical once our line is taken back out: the restore in rootfs-image puts the original buffer back,
    // and this is the same promise made where the content is composed.
    expect(lines.join('\n')).toBe(INITTAB);
  });

  it('leaves the vendor’s own init script untouched when it can use the inittab', () => {
    const p = planGuestRepair(inputs());
    expect(p.placement?.file).not.toBe('etc/rc.d/rcS');
    expect(p.interventions[0]).toMatch(/No vendor script was edited/);
    // Nothing was degraded, so nothing is reported as skipped.
    expect(p.skipped).toEqual([]);
  });

  describe('degrades to the head of the init script, explicitly, and never to its end', () => {
    const cases: Array<[string, string | null, RegExp]> = [
      ['no inittab at all', null, /ships no \/etc\/inittab/],
      ['an empty inittab', '   \n', /is empty/],
      ['a line it cannot parse', '# c\nnot:enough\n::sysinit:/etc/rc.d/rcS\n', /not id:runlevels:action:process/],
      ['no sysinit entry', '::askfirst:-/bin/sh\n::ctrlaltdel:/sbin/reboot\n', /declares no sysinit entry/],
      ['a SysV-style id on the sysinit entry', 'si::sysinit:/etc/init.d/rcS\n', /attaches such an entry to \/dev\/si/],
    ];

    for (const [name, inittab, reason] of cases) {
      it(`falls back on ${name}, and the reason travels onto the intervention`, () => {
        const p = planGuestRepair(inputs({ inittab }));
        expect(p.placement?.kind).toBe('init-script-head');
        expect(p.placement?.file).toBe('etc/rc.d/rcS');
        expect(p.interventions[0]).toMatch(reason);
        // A degradation is a skip: the preferred placement was available in principle and was not used.
        expect(p.skipped.join(' ')).toMatch(/The preferred placement/);
        expect(p.skipped.join(' ')).toMatch(reason);
      });
    }

    it('puts the line after the shebang and BEFORE the vendor body, never at the end', () => {
      const content = planGuestRepair(inputs({ inittab: null })).placement?.content ?? '';
      // No exec guard here: a script line is not handed to `exec`, and the line opens directly with its subshell.
      expect(content.startsWith('#!/bin/sh\n(')).toBe(true);
      expect(content.indexOf('iptables-stop')).toBeLessThan(content.indexOf('/usr/bin/httpd'));
      expect(content.endsWith(RCS.slice(RCS.indexOf('\n') + 1))).toBe(true);
    });

    it('refuses the inittab line busybox init would silently truncate into a different command', () => {
      // busybox reads an inittab line into a fixed 256-byte buffer: over the limit it does not fail, it becomes an
      // unterminated subshell handed to `/bin/sh -c`. The ceiling is checked before the entry is composed.
      const long = `(${'x'.repeat(INITTAB_LINE_MAX)}) &`;
      const chosen = chooseRepairPlacement(inputs(), long);
      expect(chosen.placement?.kind).toBe('init-script-head');
      expect(chosen.degraded).toMatch(new RegExp(`truncates an inittab line at ${INITTAB_LINE_MAX}`));
    });

    it('fits the real line inside that ceiling, which is the only reason the preferred route is available', () => {
      const p = planGuestRepair(inputs());
      expect(`::sysinit:${INIT_EXEC_GUARD}${p.line}`.length).toBeLessThanOrEqual(INITTAB_LINE_MAX);
    });
  });
});

describe('findSysinitInsertion', () => {
  it('finds the first sysinit entry, skipping comments and blank lines', () => {
    const v = findSysinitInsertion('# a\n\n::respawn:/sbin/getty\n::sysinit:/etc/rc.d/rcS\n::sysinit:/etc/rc.d/rcS2\n');
    expect(v).toEqual({ usable: true, index: 3 });
  });

  it('tolerates CRLF, which is a line ending rather than a malformed entry', () => {
    expect(findSysinitInsertion('# a\r\n::sysinit:/etc/rc.d/rcS\r\n')).toEqual({ usable: true, index: 1 });
  });

  /** Three refusals with three different meanings — the same discipline as `stampVerdict`. */
  it('separates "cannot read it" from "no such stage" from "not busybox’s convention"', () => {
    expect(findSysinitInsertion('hello\n').usable).toBe(false);
    expect(findSysinitInsertion('::respawn:/sbin/getty\n').usable).toBe(false);
    expect(findSysinitInsertion('si::sysinit:/etc/init.d/rcS\n').usable).toBe(false);
    // …and each says which one it is, in a sentence a reader can act on.
    expect(findSysinitInsertion('hello\n')).toMatchObject({ reason: expect.stringContaining('line 1') });
    expect(findSysinitInsertion('::respawn:/sbin/getty\n')).toMatchObject({
      reason: expect.stringContaining('inventing a stage'),
    });
    expect(findSysinitInsertion('si::sysinit:/etc/init.d/rcS\n')).toMatchObject({
      reason: expect.stringContaining('no evidence it ran'),
    });
  });
});

describe('insertAfterShebang', () => {
  it('goes after the shebang, not before it', () => {
    expect(insertAfterShebang('#!/bin/sh\nbody\n', 'X')).toBe('#!/bin/sh\nX\nbody\n');
  });

  it('goes at the top when there is no shebang, because there is nothing to preserve', () => {
    expect(insertAfterShebang('body\n', 'X')).toBe('X\nbody\n');
  });

  it('still lands after a file that is nothing but a shebang', () => {
    // `indexOf('\n') + 1` would be 0 here and would put the line ahead of `#!`, breaking the script.
    expect(insertAfterShebang('#!/bin/sh', 'X')).toBe('#!/bin/sh\nX\n');
  });
});
