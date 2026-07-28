import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { auditBootEnv, findEnvBlock, parseUbootEnv, readBootScript, runUbootAnalysis } from './uboot.js';

/**
 * The Tenda camera's environment, copied verbatim out of the deployed corpus
 * (`/data/images/75976cfa/Tenda-Camera.bin`, 53 variables, 0 malformed entries). It is the board that forced this
 * whole feature: `bootcmd` runs `boot_normal`, which re-sets `bootargs` to a line the stored variable does not
 * carry — and it does it with `env set` rather than `setenv`, and through a `${mtdparts1}` the board does not have.
 */
const TENDA_VARS: Record<string, string> = {
  bootdelay: '1',
  loadaddr: '0x81000000',
  sf_hz: '66000000',
  console: 'ttySAK0,115200n8',
  mtd_root: '/dev/mtdblock3',
  rootfstype: 'jffs2',
  init: '/sbin/init',
  mem: 'mem=64M',
  memsize: 'memsize=64M',
  mtdparts:
    'mtdparts=spi0.0:320k(boot),2112k(kernel),64k(dtb),5120k(rootfs),7616k(user),320K(custom),768K(config),64K(encrypt),16384K@0(all)',
  bootargs: 'console=${console} root=${mtd_root} rootfstype=${rootfstype} init=${init} ',
  read_kernel: 'sf probe 0:0 ${sf_hz} 0; sf read ${loadaddr} 0x00050000 0x00210000',
  read_dtb: 'sf probe 0:0 ${sf_hz} 0; sf read 0x81008000 0x00260000 0x00010000;fdt addr ${fdtcontroladdr}',
  boot_normal:
    'env set bootargs console=${console} root=${mtd_root} rootfstype=${rootfstype} init=${init} ${mtdparts}${mtdparts1} ${mem} ${memsize};run read_dtb; run read_kernel; bootm ${loadaddr} - 0x81008000',
  bootcmd: 'run boot_normal',
  // Real, and the reason this is a WALK rather than a scan for `setenv bootargs`: this board also stores a second
  // assignment (note the `ro` and the different `mem`) in a variable nothing runs. Grepping the environment would
  // have reported it as a reachable command line.
  setcmd: 'setenv bootargs console=${console} root=${mtd_root} rootfstype=${rootfstype} ro init=${init} mem=${memsize}',
};

/** Build a NUL-separated `key=value` entry region ending in the terminating double-NUL. */
function entries(...kv: string[]): Buffer {
  return Buffer.from(`${kv.join('\0')}\0\0`, 'ascii');
}

// A realistic env: a bad kernel command line (drops to a root shell + exposes a serial console), an interruptible
// autoboot, and a plain (non-network) bootcmd.
const ENV_ENTRIES = entries(
  'bootcmd=bootm 0x8000',
  'bootargs=console=ttyS0,115200 root=/dev/mtdblock2 init=/bin/sh',
  'bootdelay=3',
);

// A plain-store env blob: 4 zero CRC bytes + the entries (the canonical shape from the task).
const ENV_BLOB = Buffer.concat([Buffer.alloc(4, 0), ENV_ENTRIES]);

describe('parseUbootEnv', () => {
  it('extracts every key=value entry past the 4-byte CRC header', () => {
    const { vars, entryCount } = parseUbootEnv(ENV_BLOB);
    expect(entryCount).toBe(3);
    expect(vars.bootcmd).toBe('bootm 0x8000');
    expect(vars.bootargs).toBe('console=ttyS0,115200 root=/dev/mtdblock2 init=/bin/sh');
    expect(vars.bootdelay).toBe('3');
  });

  it('handles a redundant-env store (one flags byte after the CRC) via the offset-5 path', () => {
    // Non-zero binary CRC (0x12345678) + a 0x01 flags byte, then the entries.
    const redundant = Buffer.concat([Buffer.from([0x12, 0x34, 0x56, 0x78, 0x01]), ENV_ENTRIES]);
    const { vars, entryCount } = parseUbootEnv(redundant);
    expect(entryCount).toBe(3);
    expect(vars.bootcmd).toBe('bootm 0x8000');
    expect(vars.bootdelay).toBe('3');
  });

  it('tolerates a header-less ASCII block (offset-0 path)', () => {
    const { vars } = parseUbootEnv(ENV_ENTRIES);
    expect(vars.bootargs).toContain('init=/bin/sh');
  });

  // The count is what licenses reading an ABSENT variable as "the board does not have it" rather than "we could
  // not read it" — a distinction the assembled Tenda line depends on, since it references a `mtdparts1` that
  // genuinely is not there.
  it('counts the entries it refused, so a clean decode can be told from a lossy one', () => {
    expect(parseUbootEnv(ENV_BLOB).malformedEntries).toBe(0);
    const lossy = Buffer.concat([Buffer.alloc(4, 0), Buffer.from('bootcmd=bootm\0not-an-entry\0\0', 'ascii')]);
    expect(parseUbootEnv(lossy).malformedEntries).toBe(1);
  });
});

describe('auditBootEnv', () => {
  it('flags an init=/bin/sh boot-args root shell as HIGH / needs_runtime_reproduction', () => {
    const { vars } = parseUbootEnv(ENV_BLOB);
    const f = auditBootEnv(vars).find((d) => d.kind === 'uboot-root-shell');
    expect(f?.severity).toBe('high');
    expect(f?.proofState).toBe('needs_runtime_reproduction');
    expect((f?.evidence as { markers: string[] }).markers).toContain('init=/bin/sh');
  });

  it('flags an interruptible autoboot as MEDIUM / static_confirmed', () => {
    const { vars } = parseUbootEnv(ENV_BLOB);
    const f = auditBootEnv(vars).find((d) => d.kind === 'uboot-autoboot-interruptible');
    expect(f?.severity).toBe('medium');
    expect(f?.proofState).toBe('static_confirmed');
    expect(f?.title).toContain('bootdelay=3');
  });

  it('surfaces an exposed serial console as INFO / static_confirmed', () => {
    const { vars } = parseUbootEnv(ENV_BLOB);
    const f = auditBootEnv(vars).find((d) => d.kind === 'uboot-serial-console');
    expect(f?.severity).toBe('info');
    expect(f?.proofState).toBe('static_confirmed');
  });

  it('flags a network boot path in bootcmd as MEDIUM / needs_runtime_reproduction', () => {
    const f = auditBootEnv({ bootcmd: 'tftpboot 0x8000 uImage; bootm 0x8000' }).find((d) => d.kind === 'uboot-netboot');
    expect(f?.severity).toBe('medium');
    expect(f?.proofState).toBe('needs_runtime_reproduction');
    expect((f?.evidence as { scheme: string }).scheme.toLowerCase()).toBe('tftp');
  });

  it('does not over-claim: a safe env (bootdelay=0, no risky args) yields no findings', () => {
    expect(auditBootEnv({ bootcmd: 'bootm 0x8000', bootdelay: '0' })).toHaveLength(0);
  });
});

describe('readBootScript — the line a bootcmd assembles, read as text and never as an execution', () => {
  it('follows bootcmd → boot_normal on the real Tenda env and reconstructs the assignment it performs', () => {
    const r = readBootScript(TENDA_VARS);
    expect(r.present).toBe(true);
    expect(r.roots).toEqual(['bootcmd']);
    expect(r.variants).toHaveLength(1);
    const only = r.variants[0];
    expect(only?.via).toEqual(['bootcmd', 'boot_normal']);
    // The value is the right-hand side as WRITTEN — still a template, because expansion belongs to the comparison.
    expect(only?.value).toBe(
      'console=${console} root=${mtd_root} rootfstype=${rootfstype} init=${init} ${mtdparts}${mtdparts1} ${mem} ${memsize}',
    );
    expect(only?.conditional).toBe(false);
    // `run read_dtb` / `run read_kernel` both resolve, so nothing was left unfollowed and one line is reachable.
    expect(r.unfollowed).toEqual([]);
    expect(r.ambiguous).toBe(false);
    expect(r.reason).toContain('STATIC read');
  });

  it('does not pick up a `setenv bootargs` sitting in a variable nothing runs', () => {
    // `setcmd` is real and unreachable on this board; only `bootcmd → boot_normal` is walked.
    const values = readBootScript(TENDA_VARS).variants.map((v) => v.value);
    expect(values).toHaveLength(1);
    expect(values[0]).not.toContain(' ro ');
  });

  it('accepts `env set` as well as `setenv`, which is the spelling the Tenda actually uses', () => {
    expect(readBootScript({ bootcmd: 'env set bootargs ro' }).variants[0]?.value).toBe('ro');
    expect(readBootScript({ bootcmd: 'setenv bootargs ro' }).variants[0]?.value).toBe('ro');
    expect(readBootScript({ bootcmd: 'setenv -f bootargs ro' }).variants[0]?.value).toBe('ro');
  });

  it('ignores a setenv of any other variable — only bootargs is a kernel command line', () => {
    expect(readBootScript({ bootcmd: 'setenv bootargs_extra ro; setenv foo bar' }).variants).toEqual([]);
  });

  it('strips the quotes U-Boot strips, so a quoted value is the value', () => {
    expect(readBootScript({ bootcmd: 'setenv bootargs "console=ttyS0 root=/dev/sda1"' }).variants[0]?.value).toBe(
      'console=ttyS0 root=/dev/sda1',
    );
  });

  it('walks preboot as well as bootcmd, because U-Boot runs it first', () => {
    const r = readBootScript({ preboot: 'setenv bootargs ro', bootcmd: 'bootm 0x8000' });
    expect(r.roots).toEqual(['preboot', 'bootcmd']);
    expect(r.variants[0]?.via).toEqual(['preboot']);
  });

  describe('what it refuses to decide', () => {
    it('reports BOTH branches of a conditional rather than picking one', () => {
      const r = readBootScript({
        bootcmd: 'if test ${flag} = 1; then setenv bootargs root=/dev/mtdblock2; else setenv bootargs single; fi',
      });
      expect(r.variants.map((v) => v.value)).toEqual(['root=/dev/mtdblock2', 'single']);
      expect(r.variants.every((v) => v.conditional)).toBe(true);
      expect(r.ambiguous).toBe(true);
      expect(r.reason).toContain('not decidable from these bytes');
      expect(r.reason).toContain('none is presented as the boot');
    });

    it('propagates conditionality through a `run` made inside the conditional', () => {
      const r = readBootScript({
        bootcmd: 'if test ${x} = 1; then run alt; fi',
        alt: 'setenv bootargs ro',
      });
      expect(r.variants[0]?.conditional).toBe(true);
      expect(r.ambiguous).toBe(true);
    });

    it('names a `run` target this environment does not carry instead of assuming it sets nothing', () => {
      const r = readBootScript({ bootcmd: 'run boot_missing' });
      expect(r.unfollowed).toEqual([{ name: 'boot_missing', why: 'undefined' }]);
      expect(r.ambiguous).toBe(true);
      expect(r.reason).toContain('may exist');
    });

    it('terminates on a cycle instead of recursing, and says the walk stopped there', () => {
      const r = readBootScript({ bootcmd: 'run a', a: 'setenv bootargs ro; run b', b: 'run a' });
      expect(r.variants.map((v) => v.value)).toEqual(['ro']);
      expect(r.unfollowed).toEqual([{ name: 'a', why: 'cycle' }]);
      // A cycle re-enters text already read, so nothing was missed — it must NOT read as an incomplete walk.
      expect(r.reason).toContain('no text was missed');
    });

    it('states what the variant bound dropped rather than presenting the first eight as the set', () => {
      const script = Array.from({ length: 11 }, (_, i) => `setenv bootargs root=/dev/mtdblock${i}`).join('; ');
      const r = readBootScript({ bootcmd: script });
      expect(r.variants).toHaveLength(8);
      expect(r.variantsCapped).toBe(true);
      expect(r.reason).toContain('dropped by that bound, not absent');
    });
  });

  describe('no boot script at all behaves exactly as before the reader existed', () => {
    it('reports no script when neither bootcmd nor preboot is set', () => {
      const r = readBootScript({ bootargs: 'console=ttyS0' });
      expect(r.present).toBe(false);
      expect(r.variants).toEqual([]);
      expect(r.ambiguous).toBe(false);
      expect(r.reason).toContain('no `bootcmd` or `preboot`');
    });

    it('reports a bootcmd that sets nothing as exactly that, not as an unread script', () => {
      const r = readBootScript({ bootcmd: 'bootm 0x8000', bootargs: 'console=ttyS0' });
      expect(r.present).toBe(true);
      expect(r.variants).toEqual([]);
      expect(r.ambiguous).toBe(false);
      expect(r.reason).toContain('nothing in the script re-sets the stored command line');
    });
  });
});

describe('auditBootEnv — the assembled line is audited too, without minting the same fact twice', () => {
  it('flags a root shell that exists ONLY in the line the script assembles', () => {
    const f = auditBootEnv({
      bootargs: 'console=ttyS0 root=/dev/mtdblock2',
      bootcmd: 'run boot_rescue',
      boot_rescue: 'setenv bootargs console=ttyS0 init=/bin/sh; bootm',
    }).find((d) => d.kind === 'uboot-root-shell');
    expect(f?.proofState).toBe('needs_runtime_reproduction');
    expect((f?.evidence as { via: string[] }).via).toEqual(['bootcmd', 'boot_rescue']);
    expect(f?.rationale).toContain('not that this board ran it');
  });

  it('does not report the same finding kind twice when both lines answer the same question', () => {
    const kinds = auditBootEnv(TENDA_VARS).map((d) => d.kind);
    expect(kinds.filter((k) => k === 'uboot-serial-console')).toHaveLength(1);
    // The stored line is the one that carried it, so the finding keeps the stored provenance.
    const console = auditBootEnv(TENDA_VARS).find((d) => d.kind === 'uboot-serial-console');
    expect((console?.evidence as { var?: string }).var).toBe('bootargs');
  });

  it('says so when a conditional variant is the one that carries the fact', () => {
    const f = auditBootEnv({
      bootcmd: 'if test ${mode} = rescue; then setenv bootargs init=/bin/sh; fi',
    }).find((d) => d.kind === 'uboot-root-shell');
    expect((f?.evidence as { conditional?: boolean }).conditional).toBe(true);
    expect(f?.rationale).toContain('sits inside a conditional');
  });
});

describe('findEnvBlock', () => {
  it('locates the env block inside a larger image with padding around it', () => {
    const pad = Buffer.alloc(32, 0xff);
    const image = Buffer.concat([pad, ENV_BLOB, pad]);
    const block = findEnvBlock(image);
    expect(block).not.toBeNull();
    const { vars } = parseUbootEnv(block as Uint8Array);
    expect(vars.bootcmd).toBe('bootm 0x8000');
    expect(vars.bootargs).toContain('init=/bin/sh');
    expect(vars.bootdelay).toBe('3');
  });

  it('returns null when the image has no U-Boot env marker', () => {
    expect(findEnvBlock(Buffer.alloc(4096, 0xff))).toBeNull();
  });
});

describe('runUbootAnalysis', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-uboot-test-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('returns found:false honestly on an image with no env', () => {
    const p = path.join(tmp, 'no-env.bin');
    fs.writeFileSync(p, Buffer.alloc(8192, 0xff));
    const res = runUbootAnalysis(p);
    expect(res.available).toBe(true);
    expect(res.found).toBe(false);
    expect(res.varCount).toBe(0);
    expect(res.findings).toHaveLength(0);
    expect(res.reason).toMatch(/No U-Boot environment/i);
  });

  it('finds and audits an env embedded in an image', () => {
    const p = path.join(tmp, 'with-env.bin');
    fs.writeFileSync(p, Buffer.concat([Buffer.alloc(64, 0xff), ENV_BLOB, Buffer.alloc(64, 0xff)]));
    const res = runUbootAnalysis(p);
    expect(res.found).toBe(true);
    expect(res.varCount).toBe(3);
    expect(res.vars.bootargs).toContain('init=/bin/sh');
    expect(res.findings.map((f) => f.kind)).toContain('uboot-root-shell');
    // Nothing was capped and nothing failed to decode, so an absent variable is the board's answer, not ours.
    expect(res.varsComplete).toBe(true);
    // This env's bootcmd sets no bootargs — the reading says that, rather than being absent.
    expect(res.bootScript?.present).toBe(true);
    expect(res.bootScript?.variants).toEqual([]);
  });

  it('surfaces the assembled command line on an image whose bootcmd re-sets bootargs', () => {
    const p = path.join(tmp, 'assembling-env.bin');
    const blob = Buffer.concat([
      Buffer.alloc(4, 0),
      entries(
        'bootcmd=run boot_normal',
        'boot_normal=env set bootargs ${base} ${mem}; bootm',
        'base=ro',
        'mem=mem=64M',
      ),
    ]);
    fs.writeFileSync(p, blob);
    const res = runUbootAnalysis(p);
    expect(res.bootScript?.variants[0]?.via).toEqual(['bootcmd', 'boot_normal']);
    expect(res.bootScript?.variants[0]?.value).toBe('${base} ${mem}');
    expect(res.reason).toContain('re-sets bootargs');
  });
});
