import { describe, expect, it } from 'vitest';
import { armPositioning, buildBettercapArgs } from './spoof.js';

describe('buildBettercapArgs', () => {
  it('scopes the ARP spoof to a single target and pins the interface when given', () => {
    const args = buildBettercapArgs('eth0', '192.168.1.42');
    expect(args.slice(0, 2)).toEqual(['-iface', 'eth0']);
    const caplet = args[args.length - 1] as string;
    expect(caplet).toContain('set arp.spoof.targets 192.168.1.42');
    expect(caplet).toContain('set arp.spoof.internal false');
    expect(caplet).toContain('arp.spoof on');
  });
  it('omits -iface when none is given (bettercap auto-selects)', () => {
    const args = buildBettercapArgs(null, '10.0.0.5');
    expect(args).not.toContain('-iface');
    expect(args[0]).toBe('-no-colors');
  });
});

describe('armPositioning — honest degradation', () => {
  it('falls back to manual positioning when neither a gateway nor spoof capability is available', () => {
    // On the test host there is no bettercap + NET_ADMIN/NET_RAW and no declared gateway, so it must not pretend
    // to be on-path — it reports `manual` with what to do instead, and spawns nothing.
    const r = armPositioning('sess-test', '192.168.1.42');
    expect(r.strategy).toBe('manual');
    expect(r.active).toBe(false);
    expect(r.reason).toMatch(/manually|gateway|agent/i);
  });
});
