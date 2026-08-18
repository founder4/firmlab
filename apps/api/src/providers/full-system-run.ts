/**
 * The single entry point for booting an extracted rootfs under full-system emulation.
 *
 * A rootfs directory is not a QEMU disk. Keeping the conversion next to the boot call makes that distinction a
 * type-level/API boundary shared by operator-driven and agent-driven runs, rather than a convention each caller
 * has to remember independently.
 */
import type { Architecture } from '@firmlab/core';
import type { BootOutcome } from './boot-reproducibility.js';
import { type SystemEmulationResult, runFullSystem } from './emulate-system.js';
import type { JobHandle } from './jobs.js';
import { type RootfsImageResult, ensureRootfsImage } from './rootfs-image.js';

interface FullSystemRunDependencies {
  ensureImage: (rootfsPath: string, arch: Architecture, handle?: JobHandle) => Promise<RootfsImageResult>;
  boot: typeof runFullSystem;
}

const DEFAULT_DEPENDENCIES: FullSystemRunDependencies = {
  ensureImage: ensureRootfsImage,
  boot: runFullSystem,
};

/**
 * Assemble (or reuse) the raw filesystem image and only then hand it to QEMU.
 *
 * `dependencies` is deliberately injectable so the directory/image boundary can be tested without building a
 * real ext2 filesystem or starting QEMU. Production callers should omit it.
 */
export async function runFullSystemFromRootfs(
  arch: Architecture,
  rootfsPath: string,
  hostPort: number,
  handle: JobHandle,
  priorBoots?: readonly BootOutcome[],
  dependencies: FullSystemRunDependencies = DEFAULT_DEPENDENCIES,
): Promise<SystemEmulationResult> {
  const image = await dependencies.ensureImage(rootfsPath, arch, handle);
  if (!image.available || !image.imagePath) {
    return {
      ran: false,
      strategy: 'full-system',
      proofState: 'blocked_by_platform',
      reason: image.reason,
      command: '',
      stdout: '',
      stderr: '',
      timedOut: false,
    };
  }

  return dependencies.boot(arch, image.imagePath, hostPort, handle, rootfsPath, image.repair, priorBoots);
}
