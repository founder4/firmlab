import { describe, expect, it } from 'vitest';
import { type PreflightInputs, chooseRuntimeStrategy } from './preflight.js';

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
});
