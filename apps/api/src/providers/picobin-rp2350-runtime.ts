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
