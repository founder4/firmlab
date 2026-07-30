import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { planGuestRepair } from './guest-repair.js';
import {
  buildMkfsArgs,
  collectGuestRepairInputs,
  ensureRootfsImage,
  imageIsCurrent,
  imageReusable,
  planImageSize,
  stageGuestRepair,
  unstageFirmadyneShim,
  unstageGuestRepair,
} from './rootfs-image.js';

describe('planImageSize', () => {
  it('leaves room for ext2 metadata and the guest’s own writes', () => {
    // A filesystem sized to exactly its contents fills the moment the guest boots, and a full filesystem fails
    // in ways that read as firmware misbehaviour rather than as a sizing mistake.
    expect(planImageSize(100 * 1024)).toBe(Math.ceil(100 * 1024 * 1024 * 2.5));
  });

  it('never builds an image too small to boot into, however small the rootfs', () => {
    // DVRF extracts to a few hundred KB; an image that size has no room for /var, /tmp or a pid file.
    expect(planImageSize(200)).toBe(32 * 1024 * 1024);
    expect(planImageSize(0)).toBe(32 * 1024 * 1024);
  });

  it('caps a pathological extraction rather than filling the data volume', () => {
    expect(planImageSize(50 * 1024 * 1024)).toBe(2 * 1024 * 1024 * 1024);
  });
});

describe('buildMkfsArgs', () => {
  it('populates from the directory, which is what makes this work without root', () => {
    const args = buildMkfsArgs('/data/rootfs.img', '/data/rootfs');
    expect(args).toContain('-d');
    expect(args[args.indexOf('-d') + 1]).toBe('/data/rootfs');
    // -F: the target is a plain file, not a block device. Without it mke2fs refuses.
    expect(args).toContain('-F');
    // 1 KiB blocks: firmware rootfs are small and a 4 KiB block wastes a large fraction of them.
    expect(args.join(' ')).toContain('-b 1024');
    expect(args[args.length - 1]).toBe('/data/rootfs.img');
  });
});

describe('imageIsCurrent', () => {
  it('reuses an image built after its rootfs, and rebuilds one built before it', () => {
    expect(imageIsCurrent(2000, 1000)).toBe(true);
    expect(imageIsCurrent(1000, 2000)).toBe(false);
  });

  it('treats an equal timestamp as current — a rebuild on every boot costs minutes for nothing', () => {
    expect(imageIsCurrent(1000, 1000)).toBe(true);
  });
});

/**
 * The extraction has to come back out of a boot as the firmware it went in as.
 *
 * `stageFirmadyneShim` writes `/firmadyne/libnvram.so` into the rootfs so `mkfs.ext2 -d` picks it up, and its
 * own header used to claim it wrote into a copy. It never did — both TP-Link extractions on the deployment were
 * found carrying a shim that is part of no firmware. Every other provider walks that same tree as evidence, so
 * this asserts the whole round trip: after `ensureRootfsImage`, nothing this workbench added is left behind.
 */
describe('ensureRootfsImage leaves the extraction as it found it', () => {
  const tmp = (): string => fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-rootfs-test-'));

  /**
   * The unstage on its own, because the round trip through `ensureRootfsImage` CANNOT be asserted here: this
   * suite runs on a host with no `mkfs.ext2`, so that function returns before it stages anything and a green
   * test would prove only that nothing happened. That is the shape this repo has been burned by — a guard whose
   * success path is the one nobody runs — so the real behaviour is exercised directly and the integration case
   * below is honest about being a smoke test.
   */
  it('removes a staged shim, and the directory it came in', () => {
    const dir = tmp();
    const rootfs = path.join(dir, 'squashfs-root');
    fs.mkdirSync(path.join(rootfs, 'firmadyne'), { recursive: true });
    fs.writeFileSync(path.join(rootfs, 'firmadyne', 'libnvram.so'), 'shim');
    fs.mkdirSync(path.join(rootfs, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(rootfs, 'bin', 'busybox'), 'not really busybox');

    unstageFirmadyneShim(rootfs, () => undefined);

    expect(fs.existsSync(path.join(rootfs, 'firmadyne'))).toBe(false);
    // …and nothing of the firmware's with it.
    expect(fs.readdirSync(rootfs)).toEqual(['bin']);
    expect(fs.existsSync(path.join(rootfs, 'bin', 'busybox'))).toBe(true);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('is a no-op on a tree that was never staged, rather than throwing', () => {
    const dir = tmp();
    fs.mkdirSync(path.join(dir, 'rootfs'), { recursive: true });
    expect(() => unstageFirmadyneShim(path.join(dir, 'rootfs'), () => undefined)).not.toThrow();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('smoke: a boot attempt adds nothing to the extraction (mkfs absent here, so this proves only that)', async () => {
    const dir = tmp();
    const rootfs = path.join(dir, 'squashfs-root');
    fs.mkdirSync(path.join(rootfs, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(rootfs, 'bin', 'busybox'), 'not really busybox');

    const before = fs.readdirSync(rootfs).sort();
    await ensureRootfsImage(rootfs, 'mips');
    expect(fs.readdirSync(rootfs).sort()).toEqual(before);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('reports a missing rootfs rather than creating one', async () => {
    const dir = tmp();
    const result = await ensureRootfsImage(path.join(dir, 'nope'), 'mips');
    expect(result.available).toBe(false);
    expect(result.reason).toMatch(/No extracted rootfs directory/);
    expect(fs.existsSync(path.join(dir, 'nope'))).toBe(false);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

/**
 * The staging discipline `stageFirmadyneShim` had to learn the hard way, applied to a file that is far worse to
 * leave behind: the vendor's OWN init script. Whatever sits in the extraction is read as the firmware by every
 * provider that walks it afterwards, so the bytes have to come back exactly.
 */
describe('the boot-time repair is staged into the extraction and taken back out', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'repair-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  const rootfs = (name: string, files: Record<string, string>): string => {
    const root = path.join(tmp, name);
    for (const [rel, body] of Object.entries(files)) {
      const abs = path.join(root, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, body);
    }
    return root;
  };

  it('restores the init script BYTE FOR BYTE, not by stripping the line back out', () => {
    const original = '#!/bin/sh\nmount -t proc none /proc\nexec /sbin/init\n';
    const root = rootfs('restore', { 'etc/rc.d/rcS': original });
    const abs = path.join(root, 'etc/rc.d/rcS');

    const staged = stageGuestRepair(root, '(echo hi) &', 'etc/rc.d/rcS', () => {});
    expect(fs.readFileSync(abs, 'utf8')).toContain('(echo hi) &');
    unstageGuestRepair(staged, () => {});
    // Byte-exact, which stripping could not guarantee for a script that already ended without a newline.
    expect(fs.readFileSync(abs, 'utf8')).toBe(original);
  });

  it('is a no-op when nothing was staged, so the not-repaired path cannot corrupt anything', () => {
    const original = '#!/bin/sh\n';
    const root = rootfs('noop', { 'etc/rc.d/rcS': original });
    unstageGuestRepair(null, () => {});
    expect(fs.readFileSync(path.join(root, 'etc/rc.d/rcS'), 'utf8')).toBe(original);
  });

  it('reports the failure and stages nothing when the init script cannot be read', () => {
    const logs: string[] = [];
    const staged = stageGuestRepair(path.join(tmp, 'absent'), 'x', 'etc/rc.d/rcS', (m) => logs.push(m));
    expect(staged).toBeNull();
    expect(logs.join(' ')).toMatch(/The image is as shipped/);
  });
});

describe('collectGuestRepairInputs reads the rootfs, and reads it honestly', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'repair-in-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('finds what the corpus routers ship', () => {
    const root = path.join(tmp, 'tplink');
    fs.mkdirSync(path.join(root, 'etc/rc.d'), { recursive: true });
    fs.mkdirSync(path.join(root, 'sbin'), { recursive: true });
    fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(root, 'etc/rc.d/rcS'), '#!/bin/sh\n');
    fs.writeFileSync(path.join(root, 'etc/rc.d/iptables-stop'), 'iptables -F\n');
    fs.writeFileSync(path.join(root, 'sbin/iptables-save'), 'x');
    fs.writeFileSync(path.join(root, 'bin/busybox'), 'junk\u0000ping\u0000sleep\u0000more');

    expect(collectGuestRepairInputs(root)).toEqual({
      initScript: 'etc/rc.d/rcS',
      hasIptablesStop: true,
      hasIptablesSave: true,
      hasPing: true,
    });
  });

  /**
   * A path the extractor cut to `/dev/null` passes `existsSync` and is unrunnable, which would have produced a
   * plan that appends a line invoking a script that is not there — the extract-neutered defect arriving in a new
   * place. `lstat` first is what keeps the two apart.
   */
  it('treats a path the extractor neutered as absent, not as present', () => {
    const root = path.join(tmp, 'cut');
    fs.mkdirSync(path.join(root, 'etc/rc.d'), { recursive: true });
    fs.writeFileSync(path.join(root, 'etc/rc.d/rcS'), '#!/bin/sh\n');
    fs.symlinkSync('/dev/null', path.join(root, 'etc/rc.d/iptables-stop'));
    const i = collectGuestRepairInputs(root);
    expect(i.initScript).toBe('etc/rc.d/rcS');
    expect(i.hasIptablesStop).toBe(false);
    // And the plan then declines, rather than appending a line that calls nothing.
    expect(planGuestRepair(i).line).toBeNull();
  });

  it('reports a busybox with no ping applet as having none, rather than assuming one', () => {
    const root = path.join(tmp, 'noping');
    fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(root, 'bin/busybox'), 'junk\u0000mapping\u0000pinging\u0000more');
    expect(collectGuestRepairInputs(root).hasPing).toBe(false);
  });
});

/**
 * The defect a real boot exposed one commit after the wiring landed, and the third instance this session of "a
 * guard is only as good as its SUCCESS path". Reuse compared mtimes alone, so with the repair armed a real WR940N
 * boot was served an image built WITHOUT one and returned `repair: undefined` — the operator asked for an
 * intervention and silently did not get it.
 */
describe('imageReusable — freshness was necessary and not sufficient', () => {
  const base = { imageMtimeMs: 2000, rootfsMtimeMs: 1000 };

  it('reuses a fresh image when the disposition matches, in both directions', () => {
    expect(imageReusable({ ...base, builtRepaired: false, wantRepaired: false }).reusable).toBe(true);
    expect(imageReusable({ ...base, builtRepaired: true, wantRepaired: true }).reusable).toBe(true);
  });

  it('refuses an unrepaired image for a run that asks for a repair, and says which way round', () => {
    const v = imageReusable({ ...base, builtRepaired: false, wantRepaired: true });
    expect(v.reusable).toBe(false);
    expect(v.reason).toMatch(/built WITHOUT the boot-time repair and this run asks for one/);
  });

  it('also refuses a REPAIRED image for a run that wants the firmware as shipped', () => {
    // The other direction matters just as much: the verdict would never mention a line the image carries.
    const v = imageReusable({ ...base, builtRepaired: true, wantRepaired: false });
    expect(v.reusable).toBe(false);
    expect(v.reason).toMatch(/asks for the firmware as shipped/);
  });

  it('still refuses a stale image whatever the disposition, and reports staleness first', () => {
    for (const [builtRepaired, wantRepaired] of [
      [false, false],
      [true, true],
      [false, true],
    ] as const) {
      const v = imageReusable({ imageMtimeMs: 1000, rootfsMtimeMs: 2000, builtRepaired, wantRepaired });
      expect(v.reusable).toBe(false);
      expect(v.reason).toMatch(/rootfs is newer/);
    }
  });

  it('treats equal mtimes as current, which is what imageIsCurrent already promised', () => {
    expect(
      imageReusable({ imageMtimeMs: 1000, rootfsMtimeMs: 1000, builtRepaired: false, wantRepaired: false }).reusable,
    ).toBe(true);
  });
});
