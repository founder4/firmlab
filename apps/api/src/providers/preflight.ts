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

/**
 * Map an architecture to its qemu-user-static binary.
 *
 * `mips` means BIG-endian here — `structure.ts` demotes a little-endian MIPS ELF to `mipsel` when it decodes the
 * EI_DATA byte, so a `mips` value can only ever have come from a big-endian header (or from a uImage arch code,
 * which carries no endianness at all and is never little-endian-specific either). This entry pointed at
 * `qemu-mipsel-static` until 2026-08-03, which is the little-endian emulator: it exits 255 with "Invalid ELF
 * image for this architecture" without executing an instruction, and it destroyed the user-mode rung on every
 * big-endian image in the corpus — WR940N, WDR3600, MR3220 — while the ledger row for the very same binary read
 * `mips · 32 · big`, measured from the ELF header.
 */
export const QEMU_USER_BY_ARCH: Partial<Record<Architecture, ToolId>> = {
  mipsel: 'qemu-mipsel-static',
  mips: 'qemu-mips-static',
  arm: 'qemu-arm-static',
  arm64: 'qemu-aarch64-static',
};

export const QEMU_SYSTEM_BY_ARCH: Partial<Record<Architecture, ToolId>> = {
  mipsel: 'qemu-system-mipsel',
  // Big-endian MIPS gets the big-endian emulator. It used to point at `qemu-system-mipsel`, which refuses a
  // big-endian kernel outright — "The image has incorrect endianness" — so every full-system boot of a
  // big-endian image (a TP-Link WR940N among them) died before executing one instruction, on a machine where
  // qemu-system-mips was installed the whole time.
  mips: 'qemu-system-mips',
  arm: 'qemu-system-arm',
  // arm64 was absent until 2026-08-03, and its absence did not read as an absence: the rung answered
  // `blocked_by_platform` — "No qemu-system emulator/machine for arch arm64 in this deployment" — about a
  // deployment that has shipped qemu-system-aarch64 all along, on the corpus's flagship modern image. The
  // machine was already mapped (`arm64: 'virt'` below); only the emulator key was missing. A block that names
  // the wrong cause is worse than no block, because it closes the question.
  arm64: 'qemu-system-aarch64',
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

/**
 * firmadyne's kernel filenames, which are NOT the architecture names this codebase uses.
 *
 * The path was built as `vmlinux.${arch}.4`, and that is right for exactly one architecture. firmadyne ships
 * `vmlinux.mipseb.4` for big-endian MIPS and `vmlinux.armel` (no `.4`) for ARM, so a TP-Link WR940N — plain
 * `mips` — was refused with "No firmadyne kernel at …/vmlinux.mips.4" while the kernel it needed sat in the same
 * directory under a different name. `mipsel` matched by coincidence, which is why this went unnoticed.
 *
 * Candidates are ordered most-specific first and every one is a real filename observed in the deployed image.
 * It lives here, beside the emulator maps and upstream of the runner, because the preflight has to answer
 * "can this deployment boot THIS architecture?" and a kernel is half of that answer — see `hasSystemKernel`.
 * An architecture firmadyne ships nothing for is absent rather than guessed: `arm64` has no entry, and the
 * runner's block then names the missing kernel instead of inventing a filename.
 */
export const FIRMADYNE_KERNEL_NAMES: Partial<Record<Architecture, string[]>> = {
  mipsel: ['vmlinux.mipsel.4', 'vmlinux.mipsel'],
  mips: ['vmlinux.mipseb.4', 'vmlinux.mipseb'],
  arm: ['vmlinux.armel', 'zImage.armel'],
};

/** The first firmadyne kernel that exists for an architecture, or null when this deployment ships none. */
export function firmadyneKernelFor(arch: Architecture, dir: string = FIRMADYNE_KERNELS_DIR): string | null {
  for (const name of FIRMADYNE_KERNEL_NAMES[arch] ?? []) {
    const p = `${dir}/${name}`;
    if (fs.existsSync(p)) return p;
  }
  return null;
}

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
    // Per ARCHITECTURE, not per directory. This used to be `fs.existsSync(FIRMADYNE_KERNELS_DIR)` — true for
    // every image the moment the deployment shipped any kernel at all — which was harmless only for as long as
    // no unbootable architecture had an emulator. Mapping arm64 to qemu-system-aarch64 ended that: the pair
    // (emulator available, kernels directory present) would have planned `full-system` and promised a
    // `confirmed_full_system` ceiling for an architecture firmadyne ships no kernel for, and the runner would
    // then have blocked. A ceiling is a claim about what this deployment can prove; it has to be measured.
    hasSystemKernel: firmadyneKernelFor(arch) !== null,
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
