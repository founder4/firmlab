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
    // The web-taint deep worker (W4) is built.
    const w4 = specs.find((s) => s.worker.includes('Web attack-surface'));
    expect(w4?.built).toBe(true);
    expect(w4?.provider).toBe('webtaint');
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

  it('falls back to extraction plus the rootfs-free recon for an unknown class', () => {
    const specs = specsForClass('unknown');
    expect(specs[0]?.worker).toContain('Extraction');
    // An unrecognised class still gets the workers that read the raw image — they need no rootfs, so there is no
    // reason to withhold them from the one class we know least about.
    expect(specs.map((s) => s.provider)).toEqual([
      'extract',
      'certs',
      'uboot',
      'devicetree',
      'bootcmdline',
      'fcc',
      'nvram',
    ]);
  });

  /**
   * The cross-check is the one stage that consumes two others' output, so its position is not cosmetic — and its
   * existence in the plan is what gives `coverage.ts` a "was this question asked" row for it. Both properties are
   * asserted structurally rather than by re-pinning a list, because a re-baselined list would have accepted the
   * spec landing anywhere.
   */
  describe('the kernel-command-line cross-check needs both halves, so it is planned after them', () => {
    const CLASSES = [
      'embedded-linux',
      'openwrt-fit-ubi',
      'uefi-bios',
      'baremetal',
      'rtos',
      'esp-soc',
      'encrypted',
      'unknown',
    ];

    it('is routed to by every class, since both halves read the raw image and need no rootfs', () => {
      for (const cls of CLASSES) {
        const spec = specsForClass(cls).find((s) => s.provider === 'bootcmdline');
        expect(spec, cls).toBeDefined();
        expect(spec?.built, cls).toBe(true);
        expect(spec?.needsRootfs, cls).toBe(false);
      }
    });

    it('is ordered after the U-Boot and device-tree stages that feed it, in every class', () => {
      for (const cls of CLASSES) {
        const providers = specsForClass(cls).map((s) => s.provider);
        const cross = providers.indexOf('bootcmdline');
        expect(providers.indexOf('uboot'), cls).toBeGreaterThanOrEqual(0);
        expect(providers.indexOf('devicetree'), cls).toBeGreaterThanOrEqual(0);
        expect(cross, cls).toBeGreaterThan(providers.indexOf('uboot'));
        expect(cross, cls).toBeGreaterThan(providers.indexOf('devicetree'));
      }
    });

    it('appears exactly once per class — one question, one coverage row', () => {
      for (const cls of CLASSES) {
        expect(
          specsForClass(cls).filter((s) => s.provider === 'bootcmdline'),
          cls,
        ).toHaveLength(1);
      }
    });
  });

  it('planEntries exposes worker + reason for the pre-run plan', () => {
    const plan = planEntries(specsForClass('uefi-bios'));
    expect(plan[0]).toEqual({ worker: expect.stringContaining('chipsec'), reason: expect.any(String) });
  });
});
