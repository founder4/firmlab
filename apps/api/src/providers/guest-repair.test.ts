import { describe, expect, it } from 'vitest';
import {
  FLUSHED,
  type GuestRepairInputs,
  REPAIR_FLAG,
  RULES_BEGIN,
  RULES_END,
  describeRepairDisposition,
  describeRuleset,
  planGuestRepair,
  readGuestRuleset,
} from './guest-repair.js';

const inputs = (o: Partial<Parameters<typeof planGuestRepair>[0]> = {}) => ({
  initScript: 'etc/rc.d/rcS',
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
    // BusyBox 1.01 on the WR940N and the MR3220 ships no `sleep` applet at all, and `rcS` brings `lo` up a few
    // lines earlier. Firing immediately would read an empty ruleset before httpd had installed one.
    expect(planGuestRepair(inputs()).line).toMatch(/ping -c \d+ 127\.0\.0\.1/);
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
    it('does nothing when there is no init script, and says the guest booted as shipped', () => {
      const p = planGuestRepair(inputs({ initScript: null }));
      expect(p.line).toBeNull();
      expect(p.interventions).toEqual([]);
      expect(p.skipped[0]).toMatch(/boots exactly as shipped/);
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
});

/**
 * `interventions: []` is a load-bearing empty value — the design reads it as "the image as shipped" — and that
 * reading is only true if the firmware was actually examined. With the flag off nothing was looked at, so the same
 * empty list would be a claim about a look that never happened. This is that distinction, and it is the reason
 * `attempted` exists at all.
 */
describe('describeRepairDisposition — "nobody asked" is not "asked and changed nothing"', () => {
  const plannable: GuestRepairInputs = {
    initScript: 'etc/rc.d/rcS',
    hasIptablesStop: true,
    hasIptablesSave: true,
    hasPing: true,
  };

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
