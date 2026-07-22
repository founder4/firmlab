import { describe, expect, it } from 'vitest';
import { planEntries, specsForClass } from './opacidad-plan.js';

describe('specsForClass — class-routed worker plan', () => {
  it('routes a Linux rootfs to the full provider chain, extraction first', () => {
    const specs = specsForClass('embedded-linux');
    expect(specs[0]?.worker).toContain('Extraction');
    const workers = specs.map((s) => s.worker);
    expect(workers.some((w) => w.includes('SBOM'))).toBe(true);
    expect(workers.some((w) => w.includes('Credentials'))).toBe(true);
    expect(workers.some((w) => w.includes('Service enumeration'))).toBe(true);
    // The web-taint deep worker is honestly marked not-built (not silently omitted).
    const w4 = specs.find((s) => s.worker.includes('Web attack-surface'));
    expect(w4?.built).toBe(false);
  });

  it('routes a FIT/UBI container through the same Linux chain (its rootfs appears after the W1 carve)', () => {
    expect(specsForClass('openwrt-fit-ubi').map((s) => s.worker)).toEqual(
      specsForClass('embedded-linux').map((s) => s.worker),
    );
  });

  it('routes each non-Linux class to its own worker', () => {
    expect(specsForClass('uefi-bios')[0]?.worker).toContain('chipsec');
    expect(specsForClass('baremetal')[0]?.worker).toContain('Bare-metal');
    expect(specsForClass('rtos')[0]?.worker).toContain('Bare-metal');
    // The ESP (W6) and encrypted (W8) deep workers are built.
    expect(specsForClass('esp-soc')[0]?.built).toBe(true);
    expect(specsForClass('esp-soc')[0]?.provider).toBe('esp');
    expect(specsForClass('encrypted')[0]?.built).toBe(true);
    expect(specsForClass('encrypted')[0]?.provider).toBe('encrypted');
  });

  it('falls back to an extraction probe for an unknown class', () => {
    const specs = specsForClass('unknown');
    expect(specs).toHaveLength(1);
    expect(specs[0]?.worker).toContain('Extraction');
  });

  it('planEntries exposes worker + reason for the pre-run plan', () => {
    const plan = planEntries(specsForClass('uefi-bios'));
    expect(plan[0]).toEqual({ worker: expect.stringContaining('chipsec'), reason: expect.any(String) });
  });
});
