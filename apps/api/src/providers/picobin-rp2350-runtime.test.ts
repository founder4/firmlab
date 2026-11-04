import { describe, expect, it } from 'vitest';
import {
  RP2350_RISCV_ISA,
  RP2350_REQUIRED_MODELS,
  buildRp2350RuntimePlan,
  classifyRp2350MmioAccess,
  supportsRp2350Isa,
} from './picobin-rp2350-runtime.js';

const picobin = {
  cpuMode: 'riscv' as const,
  isExecutable: true,
  entryPoint: 0x2000_0250,
  rollingWindowDelta: null,
  loadMap: {
    itemOffset: 0x6000,
    relative: true,
    entries: [{ storageAddress: -0x2000, runtimeAddress: 0x2000_0000, size: 0x1fac }],
  },
};

describe('RP2350 runtime plan', () => {
  it('stays explicitly blocked when local runtime prerequisites are absent', () => {
    expect(buildRp2350RuntimePlan(picobin, 0x7000)).toMatchObject({
      target: 'rp2350-hazard3',
      status: 'blocked',
      proofState: 'blocked_by_platform',
      isa: RP2350_RISCV_ISA,
      network: 'isolated',
      unknownMmio: 'stop-and-report',
      mapping: {
        entryPoint: 0x2000_0250,
        entryFileOffset: 0x4250,
        mappingKind: 'relative-load-map',
      },
      missingModels: ['resets', 'xosc', 'clocks', 'timer', 'uart'],
    });
  });

  it('becomes runnable in contract only after every declared prerequisite is supplied', () => {
    expect(
      buildRp2350RuntimePlan(picobin, 0x7000, {
        renodeVersion: 'Renode 1.17.1',
        bootRomPath: '/local/rp2350-a2.rom',
        platformDescriptionPath: '/local/rp2350.repl',
        modeledPeripherals: ['resets', 'xosc', 'clocks', 'timer', 'uart'],
      }),
    ).toMatchObject({
      status: 'ready',
      proofState: 'needs_runtime_reproduction',
      blockers: [],
      missingModels: [],
    });
  });

  it('parses Renode versions conservatively and ignores non-RISC-V definitions', () => {
    expect(supportsRp2350Isa('Renode, version 1.17.0')).toBe(true);
    expect(supportsRp2350Isa('1.16.2')).toBe(false);
    expect(supportsRp2350Isa('development')).toBe(false);
    expect(buildRp2350RuntimePlan({ ...picobin, cpuMode: 'arm' }, 0x7000)).toBeNull();
  });

  it('continues only when the complete access is covered by a declared local model', () => {
    expect(classifyRp2350MmioAccess({ address: 0x4001_0010, size: 4, operation: 'read' }, ['clocks'])).toEqual({
      action: 'continue',
      access: { address: 0x4001_0010, size: 4, operation: 'read' },
      model: 'clocks',
      range: { start: 0x4001_0000, endExclusive: 0x4001_8000 },
    });
    expect(classifyRp2350MmioAccess({ address: 0x4007_8000, size: 4, operation: 'write' }, ['uart'])).toMatchObject({
      action: 'continue',
      model: 'uart',
    });
  });

  it('stops and reports missing, unknown, invalid, and boundary-straddling MMIO without fabricating a value', () => {
    const decisions = [
      classifyRp2350MmioAccess({ address: 0x4002_0000, size: 4, operation: 'read' }, []),
      classifyRp2350MmioAccess({ address: 0x4009_0000, size: 4, operation: 'read' }, RP2350_REQUIRED_MODELS),
      classifyRp2350MmioAccess({ address: 0xd000_0000, size: 4, operation: 'read' }, RP2350_REQUIRED_MODELS),
      classifyRp2350MmioAccess({ address: 0x4001_7fff, size: 4, operation: 'write' }, ['clocks']),
      classifyRp2350MmioAccess({ address: 0xffff_ffff, size: 4, operation: 'read' }, RP2350_REQUIRED_MODELS),
    ];
    for (const decision of decisions) {
      expect(decision).toMatchObject({ action: 'stop', proofState: 'blocked_by_platform' });
      expect(decision).not.toHaveProperty('value');
    }
    expect(decisions.map((decision) => ('reason' in decision ? decision.reason : ''))).toEqual([
      'resets MMIO is not backed by a declared local model',
      'unknown RP2350 APB MMIO access has no declared local model',
      'unknown RP2350 SIO MMIO access has no declared local model',
      'unknown RP2350 APB MMIO access has no declared local model',
      'invalid RP2350 MMIO read at 4294967295 (4 byte(s))',
    ]);
  });
});
