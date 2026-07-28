/**
 * Assemble the raw disk image the full-system rung boots from an already-extracted rootfs.
 *
 * The rung has always been passed `${rootfsPath}.img` and nothing in the codebase ever created it — the guided
 * recipe's own note said "assemble a rootfs image (mkfs) first", i.e. the operator was expected to do by hand the
 * one step that stood between a working emulation ladder and a rung that could not complete. So every full-system
 * run died on `Could not open '…​.img'` before qemu reached a guest instruction.
 *
 * `mkfs.ext2 -d <dir>` populates a filesystem from a directory WITHOUT root, which is what makes this possible
 * inside an unprivileged container. No partition table: a whole-disk ext2 booted as `root=/dev/sda` avoids loop
 * devices and the privileges partitioning would need, and the kernel is happy with it.
 *
 * **What this image is NOT.** A filesystem rebuilt from an extraction is not the vendor's filesystem. `unsquashfs`
 * run unprivileged cannot recreate device nodes, setuid bits or ownership, so `/dev` arrives thin and everything
 * is owned by the building user. A guest that then fails for want of `/dev/console` is failing on an artefact of
 * extraction, not on the firmware — which is exactly the distinction the boot classifier was taught to make, and
 * why the caveat travels with the result rather than living only here.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import type { Architecture } from '@firmlab/core';
import { isToolAvailable } from '../tools.js';
import type { JobHandle } from './jobs.js';
import { LIBNVRAM_DIR } from './preflight.js';

const execFileAsync = promisify(execFile);

/** Smallest image worth building: a rootfs of a few hundred KB still needs room for the guest to write. */
const MIN_IMAGE_BYTES = 32 * 1024 * 1024;
/** Ceiling, so a pathological extraction cannot fill the data volume. */
const MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024;

/**
 * Pure: how big to make the image, from the rootfs's own size in KiB.
 *
 * Generous on purpose. ext2 metadata, inode tables and the guest's own runtime writes all come out of this, and
 * a full filesystem fails in ways that look like firmware misbehaviour rather than like a sizing mistake.
 */
export function planImageSize(rootfsKb: number): number {
  const wanted = Math.ceil(rootfsKb * 1024 * 2.5);
  return Math.min(MAX_IMAGE_BYTES, Math.max(MIN_IMAGE_BYTES, wanted));
}

/**
 * Pure: the mke2fs invocation.
 *
 * `-F` because the target is a plain file rather than a block device; `-b 1024` because firmware rootfs are small
 * and a 4 KiB block wastes a large fraction of them; `-d` is the whole point — populate from the directory.
 */
export function buildMkfsArgs(imagePath: string, rootfsPath: string): string[] {
  return ['-F', '-b', '1024', '-t', 'ext2', '-d', rootfsPath, imagePath];
}

export interface RootfsImageResult {
  available: boolean;
  /** The image path, present whenever one exists to boot — freshly built or already current. */
  imagePath: string | null;
  built: boolean;
  reason: string;
  sizeBytes: number;
  /** Stated with every result: this is a REBUILT filesystem, not the vendor's. */
  caveat: string;
}

const CAVEAT =
  'This image was rebuilt from the extracted files, so it is not byte-for-byte the vendor filesystem: an ' +
  'unprivileged extraction cannot restore device nodes, setuid bits or ownership. A guest that fails for want of ' +
  '/dev/console is failing on the extraction, not on the firmware.';

/** Pure: is an existing image still current for this rootfs? Older than the rootfs means the extraction moved on. */
export function imageIsCurrent(imageMtimeMs: number, rootfsMtimeMs: number): boolean {
  return imageMtimeMs >= rootfsMtimeMs;
}

/**
 * Build (or reuse) the raw image for a rootfs. Never throws: a missing tool or a failed mkfs is reported as an
 * unavailable result, so the caller blocks honestly instead of booting something that is not there.
 */
/**
 * Stage the NVRAM shim inside the tree that is about to become the image.
 *
 * The firmadyne kernels are patched to preload `/firmadyne/libnvram.so` into every process, and a rootfs that
 * does not carry it kills init immediately: the real WR940N boot reached userspace, printed
 * `/sbin/init: can't load library '/firmadyne/libnvram.so'` and panicked with `Attempted to kill init`. The shim
 * ships with this deployment already — the chroot rung uses it — so the only thing missing was putting it where
 * the kernel looks. Copied into a COPY of the extraction, never into the extraction itself: the rootfs is
 * evidence and other providers read it.
 */
async function stageFirmadyneShim(rootfsPath: string, arch: Architecture, log: (m: string) => void): Promise<void> {
  const shim = `${LIBNVRAM_DIR}/libnvram-${arch}.so`;
  if (!fs.existsSync(shim)) {
    log(
      `No libnvram shim for ${arch} at ${shim}. The firmadyne kernel preloads /firmadyne/libnvram.so into every process, so init will fail to start — the boot will report that honestly rather than look like a firmware fault.`,
    );
    return;
  }
  const dir = path.join(rootfsPath, 'firmadyne');
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.copyFileSync(shim, path.join(dir, 'libnvram.so'));
    log(`Staged the ${arch} NVRAM shim at /firmadyne/libnvram.so, which the firmadyne kernel preloads.`);
  } catch (err) {
    log(`Could not stage the NVRAM shim: ${(err as Error).message}. init will very likely fail to start.`);
  }
}

export async function ensureRootfsImage(
  rootfsPath: string,
  arch: Architecture,
  handle?: JobHandle,
): Promise<RootfsImageResult> {
  const log = (m: string): void => handle?.log(m);
  const imagePath = `${rootfsPath}.img`;

  if (!fs.existsSync(rootfsPath) || !fs.statSync(rootfsPath).isDirectory()) {
    return {
      available: false,
      imagePath: null,
      built: false,
      sizeBytes: 0,
      reason: `No extracted rootfs directory at ${rootfsPath} — extraction has to succeed before a system can be booted from it.`,
      caveat: CAVEAT,
    };
  }

  // Reuse a current image: rebuilding a 100 MB filesystem on every boot is minutes of nothing.
  try {
    const img = fs.statSync(imagePath);
    if (imageIsCurrent(img.mtimeMs, fs.statSync(rootfsPath).mtimeMs)) {
      log(`Reusing the existing disk image (${(img.size / 1024 / 1024).toFixed(1)} MB) — it is newer than the rootfs.`);
      return {
        available: true,
        imagePath,
        built: false,
        sizeBytes: img.size,
        reason: 'Existing image is current.',
        caveat: CAVEAT,
      };
    }
    log('The rootfs is newer than its disk image — rebuilding.');
  } catch {
    // no image yet, which is the normal first run
  }

  if (!(await isToolAvailable('mkfs.ext2'))) {
    return {
      available: false,
      imagePath: null,
      built: false,
      sizeBytes: 0,
      reason:
        'mkfs.ext2 (e2fsprogs) is not installed in this deployment, so the raw disk image the full-system rung ' +
        'boots cannot be assembled. This is a missing capability, not a result about the firmware.',
      caveat: CAVEAT,
    };
  }

  let kb = 0;
  try {
    const { stdout } = await execFileAsync('du', ['-sk', rootfsPath], { timeout: 60_000 });
    kb = Number.parseInt(stdout.trim().split(/\s+/)[0] ?? '0', 10) || 0;
  } catch {
    kb = 0;
  }
  const sizeBytes = planImageSize(kb);
  log(`Assembling a ${(sizeBytes / 1024 / 1024).toFixed(0)} MB ext2 image from ${kb} KiB of extracted files.`);
  await stageFirmadyneShim(rootfsPath, arch, log);

  try {
    // Sparse: the file reports its full size while occupying only what is written.
    const fd = fs.openSync(imagePath, 'w');
    fs.ftruncateSync(fd, sizeBytes);
    fs.closeSync(fd);
    const { stderr } = await execFileAsync('mkfs.ext2', buildMkfsArgs(imagePath, rootfsPath), {
      timeout: 300_000,
      maxBuffer: 4 * 1024 * 1024,
    });
    if (stderr.trim()) log(`mke2fs: ${stderr.trim().split('\n').slice(-3).join(' | ')}`);
    log(CAVEAT);
    return {
      available: true,
      imagePath,
      built: true,
      sizeBytes,
      reason: `Built a ${(sizeBytes / 1024 / 1024).toFixed(0)} MB ext2 image from the extracted rootfs.`,
      caveat: CAVEAT,
    };
  } catch (err) {
    // A half-written image is worse than none: it would boot into something arbitrary.
    try {
      fs.rmSync(imagePath, { force: true });
    } catch {}
    const e = err as { stderr?: string; message?: string };
    return {
      available: false,
      imagePath: null,
      built: false,
      sizeBytes: 0,
      reason: `mkfs.ext2 could not assemble the image: ${(e.stderr || e.message || 'unknown failure').slice(0, 300)}`,
      caveat: CAVEAT,
    };
  }
}
