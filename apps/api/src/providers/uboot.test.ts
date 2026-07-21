import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { auditBootEnv, findEnvBlock, parseUbootEnv, runUbootAnalysis } from './uboot.js';

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
  });
});
