import { describe, expect, it } from 'vitest';
import { PLAN_REASON_IDS, planEntries, specsForClass } from './opacidad-plan.js';

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

  it('includes the agent-facing depth stages after the evidence they depend on', () => {
    const providers = specsForClass('embedded-linux').map((spec) => spec.provider);
    expect(providers).toContain('credmatch');
    expect(providers).toContain('yarascan');
    expect(providers).toContain('exportreach');
    expect(providers.indexOf('credmatch')).toBeGreaterThan(providers.indexOf('fsaudit'));
    expect(providers.indexOf('yarascan')).toBeGreaterThan(providers.indexOf('compcve'));
    expect(providers.indexOf('exportreach')).toBeGreaterThan(providers.indexOf('kmod'));
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

/**
 * The plan's "why this stage" column, once it became a parameter rather than a literal.
 *
 * The column sits directly under the coverage verdict in the same table, and for a while the verdict was Spanish
 * and this column was English — a seam in the one panel whose whole job is to be read carefully. What has to hold
 * afterwards is narrow and easy to lose: the ROUTING may not move between languages (a worker id, a provider tag
 * and a rootfs requirement are what the scan, the stored run and the stage table all key on), and an absent locale
 * must still produce byte-for-byte what every caller before the parameter got — because `opacidad.ts` stores its
 * plan on the job row, and a stored plan is a record.
 */
describe('the plan reason is composed per request; the routing is not', () => {
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

  /** What must be identical in every language: everything except the sentence. */
  const routing = (cls: string, locale?: 'en' | 'es'): unknown =>
    (locale ? specsForClass(cls, locale) : specsForClass(cls)).map((s) => ({
      worker: s.worker,
      provider: s.provider,
      needsRootfs: s.needsRootfs,
      built: s.built,
    }));

  it('answers an absent locale in English, exactly as it did before the parameter existed', () => {
    for (const cls of CLASSES) expect(specsForClass(cls), cls).toEqual(specsForClass(cls, 'en'));
    expect(specsForClass('embedded-linux')[0]?.reason).toBe(
      'recover the rootfs (recursive FIT→UBI→SquashFS carve when the container needs it)',
    );
  });

  it('keeps the worker ids, provider tags and rootfs requirements identical in Spanish, class by class', () => {
    for (const cls of CLASSES) expect(routing(cls, 'es'), cls).toEqual(routing(cls));
  });

  it('translates every reason, and leaves none of them empty or still in English', () => {
    for (const cls of CLASSES) {
      const english = specsForClass(cls);
      const spanish = specsForClass(cls, 'es');
      expect(spanish.length, cls).toBe(english.length);
      spanish.forEach((s, i) => {
        expect(s.reason.length, `${cls}[${i}]`).toBeGreaterThan(0);
        expect(s.reason, `${cls}[${i}] — ${s.worker}`).not.toBe(english[i]?.reason);
      });
    }
  });

  /**
   * `certs` and `uboot` are each reached from two places, and the rootfs-free recon copy says outright that it
   * reads the raw image. Collapsing the pair into one gloss would drop that clause from the classes — rtos,
   * esp-soc, encrypted, uefi-bios — where it is the entire reason the stage is planned at all.
   */
  it('keeps the raw-image recon wording distinct from the Linux-chain wording, in Spanish too', () => {
    const linuxCerts = specsForClass('embedded-linux', 'es').find((s) => s.provider === 'certs')?.reason;
    const reconCerts = specsForClass('rtos', 'es').find((s) => s.provider === 'certs')?.reason;
    expect(reconCerts).not.toBe(linuxCerts);
    expect(reconCerts).toContain('imagen en bruto');

    const linuxUboot = specsForClass('embedded-linux', 'es').find((s) => s.provider === 'uboot')?.reason;
    const reconUboot = specsForClass('rtos', 'es').find((s) => s.provider === 'uboot')?.reason;
    expect(reconUboot).not.toBe(linuxUboot);
    // Net-boot is the exposure the third experimental pass found on an eCos monolith — it must survive in Spanish.
    expect(reconUboot).toContain('arranque por red');
  });

  it('never translates a path, a flag or a symbol name inside a Spanish reason', () => {
    const spanish = new Map(specsForClass('embedded-linux', 'es').map((s) => [s.provider, s.reason]));
    expect(spanish.get('uboot')).toContain('init=/bin/sh');
    expect(spanish.get('devicetree')).toContain('/chosen bootargs');
    expect(spanish.get('kernel')).toContain('/dev/kmem');
    expect(spanish.get('kernel')).toContain('KASLR/RWX');
    expect(spanish.get('webtaint')).toContain('os.execute/io.popen');
    expect(spanish.get('compcve')).toContain('pppd, openssl');
  });

  it('carries the composed reason through planEntries, in whichever language it was asked for', () => {
    const plan = planEntries(specsForClass('uefi-bios', 'es'));
    expect(plan[0]?.worker).toContain('chipsec');
    expect(plan[0]?.reason).toBe(specsForClass('uefi-bios', 'es')[0]?.reason);
    expect(plan[0]?.reason).not.toBe(specsForClass('uefi-bios')[0]?.reason);
  });

  /**
   * The exported id list is what `catalogue.test.ts` checks the two glosses against, so it has to stay honest in
   * both directions: a duplicate would let an unglossed id hide behind a sibling, and an id the routing never
   * reaches would be dead prose that both languages are nonetheless required to carry.
   */
  it('exports each reason id once, and the routing reaches every one of them', () => {
    expect(new Set(PLAN_REASON_IDS).size).toBe(PLAN_REASON_IDS.length);
    const distinctReasons = new Set(CLASSES.flatMap((cls) => specsForClass(cls).map((s) => s.reason)));
    expect(distinctReasons.size).toBe(PLAN_REASON_IDS.length);
  });
});
