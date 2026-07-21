/**
 * Deterministic runtime-capability preflight — the honest floor under the emulation ladder and the proof-state
 * machine. Before any emulation is attempted, this inspects the image's arch, whether a rootfs was extracted,
 * which qemu emulators are installed, and whether the chroot/full-system assets (libnvram shim, firmadyne
 * kernels) are present — and decides the best strategy the deployment can actually run. No LLM, no guessing:
 * if the arch/blob cannot be emulated here, a dynamic claim is capped at `blocked_by_platform` / `static_confirmed`
 * rather than fabricated.
 *
 * The arch→emulator maps live here (upstream of emulate.ts) so the planner and runners share one source.
 */
import fs from 'node:fs';
import type { Architecture, FirmwareClass, ProofState } from '@firmlab/core';
import { type ToolId, detectTools } from '../tools.js';
import type { ExtractResult } from './extract.js';

/** Map an architecture to its qemu-user-static binary. */
export const QEMU_USER_BY_ARCH: Partial<Record<Architecture, ToolId>> = {
  mipsel: 'qemu-mipsel-static',
  mips: 'qemu-mipsel-static',
  arm: 'qemu-arm-static',
  arm64: 'qemu-aarch64-static',
};

export const QEMU_SYSTEM_BY_ARCH: Partial<Record<Architecture, ToolId>> = {
  mipsel: 'qemu-system-mipsel',
  mips: 'qemu-system-mipsel',
  arm: 'qemu-system-arm',
};

/** A sensible default qemu-system `-M` machine per arch for the guided full-system boot command. */
export const QEMU_MACHINE_BY_ARCH: Partial<Record<Architecture, string>> = {
  mips: 'malta',
  mipsel: 'malta',
  arm: 'virt',
  arm64: 'virt',
};

/** Where the on-image emulation assets live (populated by Dockerfile.firmware, Phase-0 task 4). */
export const LIBNVRAM_DIR = '/opt/libnvram';
export const FIRMADYNE_KERNELS_DIR = '/opt/firmae/kernels';

/** The dynamic-execution strategy the deployment can run for this image, cheapest-viable first. */
export type RuntimeStrategy =
  | 'qemu-user' // run a single binary under qemu-<arch>-static
  | 'chroot-service' // start a network service in a chroot with libnvram + /dev shims
  | 'full-system' // boot the rootfs under qemu-system + a firmadyne kernel
  | 'rtos-renode' // emulate an RTOS/Cortex-M blob under Renode
  | 'uefi-chipsec' // decode + scan a UEFI/BIOS image offline with chipsec (no emulation)
  | 'static-only' // nothing can run here — analyze from the bytes only
  | 'unsupported-arch'; // no emulator maps this arch at all

export interface RuntimeCapabilities {
  arch: Architecture;
  firmwareClass: FirmwareClass;
  hasRootfs: boolean;
  userEmulator: ToolId | null;
  systemEmulator: ToolId | null;
  strategy: RuntimeStrategy;
  /** The best proof state achievable given the strategy — the honest ceiling the proof-state machine enforces. */
  proofCeiling: ProofState;
  reason: string;
}

/** Inputs to the pure decision — everything the strategy depends on, so the tree is unit-testable. */
export interface PreflightInputs {
  arch: Architecture;
  firmwareClass: FirmwareClass;
  hasRootfs: boolean;
  userEmulatorAvailable: boolean;
  systemEmulatorAvailable: boolean;
  renodeAvailable: boolean;
  chipsecAvailable: boolean;
  hasNvramShim: boolean;
  hasSystemKernel: boolean;
}

/**
 * Pure decision tree: given the facts, pick the strategy and its honest proof ceiling. No I/O.
 */
export function chooseRuntimeStrategy(i: PreflightInputs): {
  strategy: RuntimeStrategy;
  proofCeiling: ProofState;
  reason: string;
} {
  // UEFI/BIOS has no Linux rootfs and no MCU to emulate; its analysis path is chipsec's offline decode + scan.
  // That is static analysis (facts about the bytes), so the honest ceiling is static_confirmed, not an emulation
  // proof — no device claim is ever made from a decode.
  if (i.firmwareClass === 'uefi-bios') {
    return i.chipsecAvailable
      ? {
          strategy: 'uefi-chipsec',
          proofCeiling: 'static_confirmed',
          reason: 'UEFI/BIOS image — chipsec can decode the firmware volumes and scan modules offline.',
        }
      : {
          strategy: 'static-only',
          proofCeiling: 'static_confirmed',
          reason: 'UEFI/BIOS: chipsec not installed — static analysis only.',
        };
  }

  // RTOS / baremetal never has a Linux rootfs; its only dynamic path is Renode.
  if (i.firmwareClass === 'rtos') {
    return i.renodeAvailable
      ? { strategy: 'rtos-renode', proofCeiling: 'confirmed_in_emulation', reason: 'RTOS blob emulable under Renode.' }
      : {
          strategy: 'static-only',
          proofCeiling: 'static_confirmed',
          reason: 'RTOS: Renode not installed — static only.',
        };
  }

  // ESP SoC dumps and bare-metal MCU images have no Linux rootfs and no qemu-user path; their analysis is static
  // (partition table / NVS for ESP, ISA-aware disassembly for bare-metal). Honest ceiling = static_confirmed.
  if (i.firmwareClass === 'esp-soc') {
    return {
      strategy: 'static-only',
      proofCeiling: 'static_confirmed',
      reason: 'ESP SoC flash dump — partition table / app / NVS analysis is offline; no Linux emulation applies.',
    };
  }
  if (i.firmwareClass === 'baremetal') {
    return {
      strategy: 'static-only',
      proofCeiling: 'static_confirmed',
      reason: 'Bare-metal MCU image — no filesystem to emulate; ISA-aware static analysis only (dynamic = W7).',
    };
  }

  // An encrypted whole-image blob cannot be extracted or emulated without the key; the honest output is the
  // cipher diagnosis, not an empty result. Cap at static_confirmed (facts about the bytes: entropy/header).
  if (i.firmwareClass === 'encrypted') {
    return {
      strategy: 'static-only',
      proofCeiling: 'static_confirmed',
      reason: 'Encrypted image — extraction needs the key; only the entropy/cipher diagnosis is available (W8).',
    };
  }

  if (!hasUserEmulatorMapping(i.arch)) {
    return {
      strategy: 'unsupported-arch',
      proofCeiling: 'blocked_by_platform',
      reason: `No qemu-user emulator maps arch "${i.arch}"; dynamic reproduction needs hardware.`,
    };
  }
  if (!i.hasRootfs) {
    return { strategy: 'static-only', proofCeiling: 'static_confirmed', reason: 'No rootfs extracted yet.' };
  }
  if (!i.userEmulatorAvailable) {
    return {
      strategy: 'static-only',
      proofCeiling: 'static_confirmed',
      reason: 'The qemu-user emulator for this arch is not installed in this deployment.',
    };
  }

  // A rootfs plus a matched qemu-user emulator: at least rung-1 runs. Climb if the assets are present.
  if (i.systemEmulatorAvailable && i.hasSystemKernel) {
    return {
      strategy: 'full-system',
      proofCeiling: 'confirmed_full_system',
      reason: 'qemu-system + firmadyne kernel present — full-system boot is viable.',
    };
  }
  if (i.hasNvramShim) {
    return {
      strategy: 'chroot-service',
      proofCeiling: 'confirmed_in_emulation',
      reason: 'libnvram shim present — a network service can run in a chroot.',
    };
  }
  return {
    strategy: 'qemu-user',
    proofCeiling: 'confirmed_in_emulation',
    reason: 'Single-binary qemu-user execution is viable; chroot/full-system assets not present.',
  };
}

/** Whether some qemu-user-static binary maps this arch at all (independent of whether it is installed). */
function hasUserEmulatorMapping(arch: Architecture): boolean {
  return QEMU_USER_BY_ARCH[arch] !== undefined;
}

/**
 * Gather the real inputs (identity, rootfs, installed tools, on-image assets) and compute the capabilities.
 * Returns null if the image has no cached identity yet. Store access is lazily imported so the pure decision
 * tree above stays unit-testable without loading node:sqlite (same pattern as providers/diff.ts).
 */
export async function computeRuntimeCapabilities(imageId: string): Promise<RuntimeCapabilities | null> {
  const { getImage, listJobs } = await import('../store.js');
  const row = getImage(imageId);
  if (!row?.identityJson) return null;
  const identity = JSON.parse(row.identityJson) as { arch: Architecture; firmwareClass: FirmwareClass };
  const arch = identity.arch;

  const tools = await detectTools();
  const available = (id: ToolId | undefined): boolean =>
    id !== undefined && (tools.find((t) => t.id === id)?.available ?? false);

  const userEmulator = QEMU_USER_BY_ARCH[arch] ?? null;
  const systemEmulator = QEMU_SYSTEM_BY_ARCH[arch] ?? null;
  const extractJob = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  const hasRootfs = extractJob?.resultJson
    ? (JSON.parse(extractJob.resultJson) as ExtractResult).rootfsPath !== null
    : false;

  const inputs: PreflightInputs = {
    arch,
    firmwareClass: identity.firmwareClass,
    hasRootfs,
    userEmulatorAvailable: available(userEmulator ?? undefined),
    systemEmulatorAvailable: available(systemEmulator ?? undefined),
    renodeAvailable: available('renode'),
    chipsecAvailable: available('chipsec'),
    hasNvramShim: userEmulator ? fs.existsSync(`${LIBNVRAM_DIR}/libnvram-${arch}.so`) : false,
    hasSystemKernel: fs.existsSync(FIRMADYNE_KERNELS_DIR),
  };

  const { strategy, proofCeiling, reason } = chooseRuntimeStrategy(inputs);
  return {
    arch,
    firmwareClass: identity.firmwareClass,
    hasRootfs,
    userEmulator,
    systemEmulator,
    strategy,
    proofCeiling,
    reason,
  };
}
