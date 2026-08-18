import type { Architecture } from '@firmlab/core';
import { describe, expect, it, vi } from 'vitest';
import type { SystemEmulationResult } from './emulate-system.js';
import { runFullSystemFromRootfs } from './full-system-run.js';
import type { JobHandle } from './jobs.js';
import type { RootfsImageResult } from './rootfs-image.js';

const handle: JobHandle = { id: 'job', log: vi.fn() };

function imageResult(overrides: Partial<RootfsImageResult> = {}): RootfsImageResult {
  return {
    available: true,
    imagePath: '/work/extracted-root.img',
    built: true,
    reason: 'assembled',
    sizeBytes: 1024,
    caveat: 'rebuilt filesystem',
    ...overrides,
  };
}

const bootResult: SystemEmulationResult = {
  ran: true,
  strategy: 'full-system',
  proofState: 'confirmed_in_emulation',
  reason: 'boot attempted',
  command: 'qemu-system',
  stdout: '',
  stderr: '',
  timedOut: false,
};

describe('runFullSystemFromRootfs', () => {
  it('passes the assembled disk image to QEMU, never the extracted rootfs directory', async () => {
    const ensureImage = vi.fn(async () => imageResult());
    const boot = vi.fn(async () => bootResult);
    const priorBoots = [{ verdict: 'observed_in_emulation', openPorts: 0, panic: false }];

    const result = await runFullSystemFromRootfs(
      'mips' as Architecture,
      '/work/extracted-root',
      8080,
      handle,
      priorBoots,
      {
        ensureImage,
        boot,
      },
    );

    expect(result).toBe(bootResult);
    expect(ensureImage).toHaveBeenCalledWith('/work/extracted-root', 'mips', handle);
    expect(boot).toHaveBeenCalledWith(
      'mips',
      '/work/extracted-root.img',
      8080,
      handle,
      '/work/extracted-root',
      undefined,
      priorBoots,
    );
    expect(boot).not.toHaveBeenCalledWith(
      'mips',
      '/work/extracted-root',
      8080,
      handle,
      '/work/extracted-root',
      undefined,
      priorBoots,
    );
  });

  it('returns an honest platform block and never starts QEMU when the disk cannot be assembled', async () => {
    const ensureImage = vi.fn(async () =>
      imageResult({ available: false, imagePath: null, built: false, reason: 'mkfs.ext2 is unavailable' }),
    );
    const boot = vi.fn(async () => bootResult);

    const result = await runFullSystemFromRootfs('mips' as Architecture, '/work/extracted-root', 8080, handle, [], {
      ensureImage,
      boot,
    });

    expect(boot).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      ran: false,
      strategy: 'full-system',
      proofState: 'blocked_by_platform',
      reason: 'mkfs.ext2 is unavailable',
    });
  });
});
