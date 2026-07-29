import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildMkfsArgs,
  ensureRootfsImage,
  imageIsCurrent,
  planImageSize,
  unstageFirmadyneShim,
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
