import { describe, expect, it } from 'vitest';
import { buildMkfsArgs, imageIsCurrent, planImageSize } from './rootfs-image.js';

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
