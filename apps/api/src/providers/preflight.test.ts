import { describe, expect, it } from 'vitest';
import {
  FIRMADYNE_KERNEL_NAMES,
  type PreflightInputs,
  QEMU_MACHINE_BY_ARCH,
  QEMU_SYSTEM_BY_ARCH,
  QEMU_USER_BY_ARCH,
  chooseRuntimeStrategy,
  firmadyneKernelFor,
} from './preflight.js';

const base: PreflightInputs = {
  arch: 'mipsel',
  firmwareClass: 'embedded-linux',
  hasRootfs: true,
  userEmulatorAvailable: true,
  systemEmulatorAvailable: false,
  renodeAvailable: false,
  chipsecAvailable: false,
  hasNvramShim: false,
  hasSystemKernel: false,
};

describe('chooseRuntimeStrategy', () => {
  it('an unmapped arch is unsupported → blocked_by_platform (never fabricated)', () => {
    const out = chooseRuntimeStrategy({ ...base, arch: 'sparc' });
    expect(out.strategy).toBe('unsupported-arch');
    expect(out.proofCeiling).toBe('blocked_by_platform');
  });

  it('no rootfs → static-only, ceiling static_confirmed', () => {
    const out = chooseRuntimeStrategy({ ...base, hasRootfs: false });
    expect(out.strategy).toBe('static-only');
    expect(out.proofCeiling).toBe('static_confirmed');
  });

  it('mapped arch but emulator not installed → static-only', () => {
    const out = chooseRuntimeStrategy({ ...base, userEmulatorAvailable: false });
    expect(out.strategy).toBe('static-only');
  });

  it('rootfs + qemu-user only → qemu-user, ceiling confirmed_in_emulation', () => {
    const out = chooseRuntimeStrategy(base);
    expect(out.strategy).toBe('qemu-user');
    expect(out.proofCeiling).toBe('confirmed_in_emulation');
  });

  it('libnvram shim present → chroot-service', () => {
    const out = chooseRuntimeStrategy({ ...base, hasNvramShim: true });
    expect(out.strategy).toBe('chroot-service');
    expect(out.proofCeiling).toBe('confirmed_in_emulation');
  });

  it('system emulator + kernel wins over chroot → full-system, ceiling confirmed_full_system', () => {
    const out = chooseRuntimeStrategy({
      ...base,
      systemEmulatorAvailable: true,
      hasSystemKernel: true,
      hasNvramShim: true,
    });
    expect(out.strategy).toBe('full-system');
    expect(out.proofCeiling).toBe('confirmed_full_system');
  });

  it('RTOS with Renode → rtos-renode; without → static-only', () => {
    expect(chooseRuntimeStrategy({ ...base, firmwareClass: 'rtos', renodeAvailable: true }).strategy).toBe(
      'rtos-renode',
    );
    expect(chooseRuntimeStrategy({ ...base, firmwareClass: 'rtos', renodeAvailable: false }).strategy).toBe(
      'static-only',
    );
  });

  it('UEFI/BIOS with chipsec → uefi-chipsec (static ceiling); without → static-only', () => {
    const withChipsec = chooseRuntimeStrategy({ ...base, firmwareClass: 'uefi-bios', chipsecAvailable: true });
    expect(withChipsec.strategy).toBe('uefi-chipsec');
    expect(withChipsec.proofCeiling).toBe('static_confirmed');
    expect(chooseRuntimeStrategy({ ...base, firmwareClass: 'uefi-bios', chipsecAvailable: false }).strategy).toBe(
      'static-only',
    );
  });

  it('UEFI/BIOS never fabricates an emulation path even with emulators present', () => {
    const out = chooseRuntimeStrategy({
      ...base,
      firmwareClass: 'uefi-bios',
      chipsecAvailable: true,
      systemEmulatorAvailable: true,
      hasSystemKernel: true,
    });
    // A UEFI image must not be routed to a qemu rung; chipsec's offline decode is the only track.
    expect(out.strategy).toBe('uefi-chipsec');
  });

  it('ESP-SoC / bare-metal / encrypted classes degrade to static-only (honest ceiling), never a qemu rung', () => {
    for (const fc of ['esp-soc', 'baremetal', 'encrypted'] as const) {
      const out = chooseRuntimeStrategy({
        ...base,
        firmwareClass: fc,
        systemEmulatorAvailable: true,
        hasSystemKernel: true,
        hasNvramShim: true,
      });
      expect(out.strategy).toBe('static-only');
      expect(out.proofCeiling).toBe('static_confirmed');
    }
  });

  it('openwrt-fit-ubi routes like a Linux image once a rootfs is present (arm64 → qemu-user)', () => {
    const out = chooseRuntimeStrategy({ ...base, firmwareClass: 'openwrt-fit-ubi', arch: 'arm64' });
    expect(out.strategy).toBe('qemu-user');
    expect(out.proofCeiling).toBe('confirmed_in_emulation');
  });

  it('an emulator without a kernel for that arch does not promise a full-system proof', () => {
    // The pair (emulator installed, kernels directory present) used to be enough, because `hasSystemKernel` was a
    // bare directory check. Mapping arm64 to qemu-system-aarch64 made that reachable: firmadyne ships no arm64
    // kernel, so this plan would have advertised a `confirmed_full_system` ceiling the runner then blocked on.
    const out = chooseRuntimeStrategy({
      ...base,
      arch: 'arm64',
      systemEmulatorAvailable: true,
      hasSystemKernel: false,
    });
    expect(out.strategy).not.toBe('full-system');
    expect(out.proofCeiling).not.toBe('confirmed_full_system');
  });
});

describe('the architecture → emulator maps', () => {
  it('big-endian MIPS gets a big-endian emulator in BOTH modes, never the mipsel one', () => {
    // Three instances of this one shape have been paid for in this file: mips→mipsel in system mode (fixed, and
    // its comment is the warning), mips→mipsel in user mode, and arm64 unmapped. Neither map was pinned by any
    // test, which is how the second survived the fix for the first.
    expect(QEMU_USER_BY_ARCH.mips).toBe('qemu-mips-static');
    expect(QEMU_SYSTEM_BY_ARCH.mips).toBe('qemu-system-mips');
    for (const emulator of [QEMU_USER_BY_ARCH.mips, QEMU_SYSTEM_BY_ARCH.mips]) {
      expect(emulator).not.toContain('mipsel');
    }
  });

  it('little-endian MIPS keeps the little-endian emulator', () => {
    expect(QEMU_USER_BY_ARCH.mipsel).toBe('qemu-mipsel-static');
    expect(QEMU_SYSTEM_BY_ARCH.mipsel).toBe('qemu-system-mipsel');
  });

  it('every architecture with a user-mode emulator also has a system one, so a block names a real limit', () => {
    // arm64 had a user-mode emulator, a machine (`virt`) and no system emulator, so the full-system rung refused
    // it with "no emulator in this deployment" about a deployment that had shipped qemu-system-aarch64 all along.
    for (const arch of Object.keys(QEMU_USER_BY_ARCH) as (keyof typeof QEMU_USER_BY_ARCH)[]) {
      expect(QEMU_SYSTEM_BY_ARCH[arch]).toBeDefined();
      expect(QEMU_MACHINE_BY_ARCH[arch]).toBeDefined();
    }
  });

  it('an architecture firmadyne ships no kernel for is absent, not guessed', () => {
    expect(FIRMADYNE_KERNEL_NAMES.arm64).toBeUndefined();
    expect(firmadyneKernelFor('arm64', '/nonexistent')).toBeNull();
  });
});
