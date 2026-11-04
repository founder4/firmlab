/**
 * Pure RP2350/Hazard3 runtime-plan scaffold. It turns a validated executable PICOBIN definition into an explicit
 * local-only Renode contract, but never claims a boot: the plan stays blocked until the operator supplies a boot
 * ROM, an RP2350 platform description, a sufficiently new Renode, and every required peripheral model. Unknown
 * MMIO is always a stop condition rather than a fabricated zero read.
 */
import type { PicobinInfo, ProofState } from '@firmlab/core';
import { type PicobinFlashMapping, picobinFlashMapping } from './picobin-riscv.js';

export const RP2350_RENODE_MINIMUM = '1.17.0';
export const RP2350_RISCV_ISA = 'rv32ima_zicsr_zifencei_zba_zbb_zbs_zbkb_zca_zcb_zcmp';
export const RP2350_REQUIRED_MODELS = ['resets', 'xosc', 'clocks', 'timer', 'uart'] as const;

/**
 * RP2350 APB slots are 0x8000 bytes. These ranges come from Raspberry Pi's RP2350 address map; adjacent timer and
 * UART instances share one required model name because the runtime capability is about model coverage, not a
 * particular SDK instance. Keeping the ranges here makes an MMIO decision pure and reviewable before an executor
 * is allowed to use it.
 */
export const RP2350_REQUIRED_MODEL_RANGES = [
  { model: 'clocks', start: 0x4001_0000, endExclusive: 0x4001_8000 },
  { model: 'resets', start: 0x4002_0000, endExclusive: 0x4002_8000 },
  { model: 'xosc', start: 0x4004_8000, endExclusive: 0x4005_0000 },
  { model: 'uart', start: 0x4007_0000, endExclusive: 0x4008_0000 },
  { model: 'timer', start: 0x400b_0000, endExclusive: 0x400c_0000 },
] as const;

export interface Rp2350MmioAccess {
  address: number;
  size: 1 | 2 | 4;
  operation: 'read' | 'write';
}

export type Rp2350MmioDecision =
  | {
      action: 'continue';
      access: Rp2350MmioAccess;
      model: (typeof RP2350_REQUIRED_MODELS)[number];
      range: { start: number; endExclusive: number };
    }
  | {
      action: 'stop';
      access: Rp2350MmioAccess;
      proofState: 'blocked_by_platform';
      reason: string;
    };

const RP2350_MMIO_WINDOWS = [
  { name: 'APB', start: 0x4000_0000, endExclusive: 0x5000_0000 },
  { name: 'AHB', start: 0x5000_0000, endExclusive: 0x6000_0000 },
  { name: 'SIO', start: 0xd000_0000, endExclusive: 0xe000_0000 },
] as const;

/**
 * Decide whether an observed access may reach a declared model. Unknown, invalid, or boundary-straddling accesses
 * always stop with `blocked_by_platform`; this function never synthesizes a read value (especially not zero).
 */
export function classifyRp2350MmioAccess(
  access: Rp2350MmioAccess,
  modeledPeripherals: readonly string[],
): Rp2350MmioDecision {
  const endExclusive = access.address + access.size;
  if (
    !Number.isSafeInteger(access.address) ||
    access.address < 0 ||
    access.address > 0xffff_ffff ||
    ![1, 2, 4].includes(access.size) ||
    endExclusive > 0x1_0000_0000
  ) {
    return {
      action: 'stop',
      access,
      proofState: 'blocked_by_platform',
      reason: `invalid RP2350 MMIO ${access.operation} at ${String(access.address)} (${access.size} byte(s))`,
    };
  }

  const range = RP2350_REQUIRED_MODEL_RANGES.find(
    (candidate) => access.address >= candidate.start && endExclusive <= candidate.endExclusive,
  );
  if (range) {
    if (modeledPeripherals.includes(range.model)) {
      return {
        action: 'continue',
        access,
        model: range.model,
        range: { start: range.start, endExclusive: range.endExclusive },
      };
    }
    return {
      action: 'stop',
      access,
      proofState: 'blocked_by_platform',
      reason: `${range.model} MMIO is not backed by a declared local model`,
    };
  }

  const window = RP2350_MMIO_WINDOWS.find(
    (candidate) => access.address >= candidate.start && endExclusive <= candidate.endExclusive,
  );
  return {
    action: 'stop',
    access,
    proofState: 'blocked_by_platform',
    reason: window
      ? `unknown RP2350 ${window.name} MMIO access has no declared local model`
      : 'access is outside the documented RP2350 MMIO windows',
  };
}

export interface Rp2350RuntimeCapabilities {
  renodeVersion?: string;
  bootRomPath?: string;
  platformDescriptionPath?: string;
  modeledPeripherals?: string[];
}

export interface Rp2350RuntimePlan {
  target: 'rp2350-hazard3';
  status: 'ready' | 'blocked';
  proofState: ProofState;
  reason: string;
  isa: typeof RP2350_RISCV_ISA;
  minimumRenodeVersion: typeof RP2350_RENODE_MINIMUM;
  bootMode: 'operator-supplied-rom';
  network: 'isolated';
  unknownMmio: 'stop-and-report';
  mapping: PicobinFlashMapping | null;
  requiredModels: string[];
  missingModels: string[];
  blockers: string[];
}

function versionTuple(version: string | undefined): [number, number, number] | null {
  const match = version?.match(/(?:^|\s)(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3] ?? 0)];
}

export function supportsRp2350Isa(version: string | undefined): boolean {
  const actual = versionTuple(version);
  const minimum = versionTuple(RP2350_RENODE_MINIMUM);
  if (!actual || !minimum) return false;
  for (let i = 0; i < minimum.length; i++) {
    const difference = (actual[i] ?? 0) - (minimum[i] ?? 0);
    if (difference !== 0) return difference > 0;
  }
  return true;
}

export function buildRp2350RuntimePlan(
  picobin: Pick<PicobinInfo, 'cpuMode' | 'isExecutable' | 'entryPoint' | 'rollingWindowDelta'> &
    Partial<Pick<PicobinInfo, 'loadMap'>>,
  fileSize: number,
  capabilities: Rp2350RuntimeCapabilities = {},
): Rp2350RuntimePlan | null {
  if (picobin.cpuMode !== 'riscv' || !picobin.isExecutable) return null;
  const mapping = picobinFlashMapping(picobin, fileSize);
  const modeled = new Set(capabilities.modeledPeripherals ?? []);
  const missingModels = RP2350_REQUIRED_MODELS.filter((model) => !modeled.has(model));
  const blockers: string[] = [];
  if (!mapping) blockers.push('PICOBIN entrypoint has no unique file-backed runtime mapping');
  if (!supportsRp2350Isa(capabilities.renodeVersion)) {
    blockers.push(`Renode ${RP2350_RENODE_MINIMUM} or newer has not been verified for this run`);
  }
  if (!capabilities.bootRomPath) blockers.push('operator-supplied RP2350 boot ROM is missing');
  if (!capabilities.platformDescriptionPath) blockers.push('local RP2350 Renode platform description is missing');
  if (missingModels.length > 0) blockers.push(`required peripheral models are missing: ${missingModels.join(', ')}`);
  const status = blockers.length === 0 ? 'ready' : 'blocked';
  return {
    target: 'rp2350-hazard3',
    status,
    proofState: status === 'ready' ? 'needs_runtime_reproduction' : 'blocked_by_platform',
    reason:
      status === 'ready'
        ? 'The bounded local-only runtime prerequisites are declared; no boot has been executed yet.'
        : `Runtime plan is blocked: ${blockers.join('; ')}.`,
    isa: RP2350_RISCV_ISA,
    minimumRenodeVersion: RP2350_RENODE_MINIMUM,
    bootMode: 'operator-supplied-rom',
    network: 'isolated',
    unknownMmio: 'stop-and-report',
    mapping,
    requiredModels: [...RP2350_REQUIRED_MODELS],
    missingModels,
    blockers,
  };
}
