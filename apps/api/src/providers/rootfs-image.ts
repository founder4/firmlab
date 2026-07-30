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
import { decideFlag, effectiveEnv } from '../flags.js';
import { isToolAvailable } from '../tools.js';
import {
  type GuestRepairInputs,
  REPAIR_FLAG,
  type RepairDisposition,
  describeRepairDisposition,
  planGuestRepair,
} from './guest-repair.js';
import type { JobHandle } from './jobs.js';
import { LIBNVRAM_DIR } from './preflight.js';

const execFileAsync = promisify(execFile);

/**
 * The delimiter busybox uses between applet names in its own table. Written as an escape, never as the byte: a
 * literal NUL passes tsc, biome and vitest and makes grep skip the whole file without saying so.
 */
const APPLET_DELIM = '\u0000';

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
  /**
   * Whether this image was repaired for the boot, and whether the question was asked. Optional forever: a result
   * stored before the repair existed carries none, and a `RepairDisposition` with `attempted: false` is a different
   * claim from an absent field — the first says the flag was off on that run, the second that the build predates
   * the feature.
   */
  repair?: RepairDisposition;
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
 * the kernel looks.
 *
 * **It writes into the extraction, and it must be taken back out.** The header of this function used to claim it
 * copied into "a COPY of the extraction, never into the extraction itself" — it never did, and both TP-Link
 * rootfs on this deployment were carrying a `/firmadyne/libnvram.so` that is not part of any firmware. Nothing
 * had surfaced it yet only because their stored extraction results predate the first full-system boot; any
 * provider re-run after one would have walked a tree containing a file this workbench put there and reported it
 * as the firmware's. Copying a whole rootfs per boot is the expensive fix; the cheap and correct one is that the
 * file only has to exist for the length of the `mkfs` call, so `unstage` removes it in a `finally`.
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

/**
 * Read what the repair needs to know off the rootfs. Thin: every decision is in `planGuestRepair`.
 *
 * `hasPing` is read out of busybox's own strings because these images have no separate `ping` binary — the applet
 * table inside busybox is the only place the answer exists. Verified on the corpus: all three TP-Link busybox
 * carry `ping`, and two of the three carry no `sleep` at all, which is why the repair's timer is a ping.
 */
export function collectGuestRepairInputs(rootfsPath: string): GuestRepairInputs {
  const has = (rel: string): boolean => {
    try {
      // `existsSync` follows symlinks, and a symlink the extractor neutered to /dev/null WOULD pass it while being
      // unrunnable. `lstat` + a size test is the honest check for "the firmware ships a usable file here".
      const abs = path.join(rootfsPath, rel);
      const st = fs.lstatSync(abs);
      if (st.isSymbolicLink()) return fs.readlinkSync(abs) !== '/dev/null' && fs.existsSync(abs);
      return st.size > 0;
    } catch {
      return false;
    }
  };
  let hasPing = false;
  try {
    const bb = fs.readFileSync(path.join(rootfsPath, 'bin/busybox'));
    // Applet names sit NUL-delimited in busybox's own table, so the delimiter IS the exact-token test: it is what
    // separates the `ping` applet from `ping` inside `mapping`. MEASURED on all three corpus routers: `ping` is
    // NUL-delimited in every one, and `sleep` is NUL-delimited only in the WDR3600 — which matches what those
    // applet lists actually contain, while a SPACE-delimited search finds `ping` in all three by coincidence and
    // misses the WDR3600's `sleep` entirely. A search that is accidentally right about the common case is worse
    // than one that is right, because nothing tells you which of the two you have.
    //
    // `includes` rather than a regex: a NUL in a regex literal is a control character biome rightly refuses, and
    // the raw byte must never be written into a source file here — it makes grep skip the file in silence, which
    // is exactly how this line was first written and how the entire edit appeared never to have been made.
    hasPing = bb.toString('latin1').includes(`${APPLET_DELIM}ping${APPLET_DELIM}`);
  } catch {
    hasPing = false;
  }
  return {
    initScript: has('etc/rc.d/rcS') ? 'etc/rc.d/rcS' : null,
    hasIptablesStop: has('etc/rc.d/iptables-stop'),
    hasIptablesSave: has('sbin/iptables-save'),
    hasPing,
  };
}

/**
 * Append the repair line to the init script, for the length of the `mkfs` call only.
 *
 * The original bytes are returned so `unstageGuestRepair` can put them back EXACTLY. This is the same discipline
 * `stageFirmadyneShim` had to learn the hard way: whatever is written into the extraction is read as the firmware by
 * every provider that walks it afterwards, and here what would be read is a vendor init script carrying a line this
 * workbench wrote. Restoring the bytes — rather than trying to strip the line back out — is the only version of this
 * that cannot drift.
 */
export function stageGuestRepair(
  rootfsPath: string,
  line: string,
  initScript: string,
  log: (m: string) => void,
): { original: Buffer; path: string } | null {
  const abs = path.join(rootfsPath, initScript);
  try {
    const original = fs.readFileSync(abs);
    fs.writeFileSync(abs, Buffer.concat([original, Buffer.from(`\n${line}\n`, 'utf8')]));
    log(`Appended the boot-time repair to /${initScript} for the length of the mkfs call.`);
    return { original, path: abs };
  } catch (err) {
    log(`Could not append the boot-time repair to /${initScript}: ${(err as Error).message}. The image is as shipped.`);
    return null;
  }
}

/** Put the init script's original bytes back. Best-effort and loud, for the same reason as `unstageFirmadyneShim`. */
export function unstageGuestRepair(staged: { original: Buffer; path: string } | null, log: (m: string) => void): void {
  if (!staged) return;
  try {
    fs.writeFileSync(staged.path, staged.original);
  } catch (err) {
    log(
      `The repaired init script could NOT be restored (${(err as Error).message}). ${staged.path} now carries a line this workbench appended and is no longer the firmware — treat any later reading of it as an artefact of this boot.`,
    );
  }
}

/**
 * Take back out everything staged above, so the extraction is the firmware again.
 *
 * Best-effort and silent on failure: a leftover shim degrades the honesty of a later file listing, while throwing
 * here would fail a boot that has already succeeded. It says so in the log instead.
 */
export function unstageFirmadyneShim(rootfsPath: string, log: (m: string) => void): void {
  const dir = path.join(rootfsPath, 'firmadyne');
  try {
    if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  } catch (err) {
    log(
      `The staged /firmadyne directory could not be removed from the extraction (${(err as Error).message}). It is NOT part of the firmware — treat it as an artefact of this boot if a later listing shows it.`,
    );
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

  // The boot-time repair, armed only by the operator. `decideFlag` rather than `=== '1'`, so an unset flag is off
  // and the disposition can say nobody asked — which is the difference between "the image booted as shipped" and
  // "we never looked at whether it needed to".
  const repairEnabled = decideFlag(REPAIR_FLAG, effectiveEnv()).enabled;
  const repairInputs = repairEnabled ? collectGuestRepairInputs(rootfsPath) : null;
  const repairPlan = repairInputs ? planGuestRepair(repairInputs) : null;
  const repair = describeRepairDisposition(repairEnabled, repairPlan);
  log(repair.note);
  const stagedRepair =
    repairPlan?.line && repairInputs?.initScript
      ? stageGuestRepair(rootfsPath, repairPlan.line, repairInputs.initScript, log)
      : null;

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
      repair,
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
      repair,
    };
  } finally {
    // The image now holds a copy; the extraction goes back to being the firmware. On BOTH paths, because a
    // failed mkfs leaves the staged file behind just as surely as a successful one — and the init script is
    // restored FIRST, since it is the vendor's own file rather than a directory of ours: leaving our line in it
    // would make every later provider read a firmware that includes our edit.
    unstageGuestRepair(stagedRepair, log);
    unstageFirmadyneShim(rootfsPath, log);
  }
}
