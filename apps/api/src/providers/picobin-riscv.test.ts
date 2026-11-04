import { describe, expect, it } from 'vitest';
import { parsePicobinRadare2Output, picobinFlashMapping, runPicobinRiscvDisassembly } from './picobin-riscv.js';

const ENTRY = 0x1000_0036;
const FILE_SIZE = 0x1000;
const mapping = {
  baseAddress: 0x1000_0000,
  entryPoint: ENTRY,
  entryFileOffset: 0x36,
  mappingKind: 'direct-xip' as const,
  mappedRuntimeStart: 0x1000_0000,
  mappedRuntimeEnd: 0x1000_1000,
};

function r2Output(): string {
  return `${JSON.stringify([
    { addr: ENTRY, size: 8, ninstr: 2, jump: ENTRY + 12, fail: ENTRY + 8 },
    { addr: ENTRY + 8, size: 4, ninstr: 1 },
  ])}\n__FIRMLAB_PICOBIN_RISCV_SPLIT__\n${JSON.stringify({
    name: 'entry0',
    ops: [
      { addr: ENTRY, size: 4, opcode: 'auipc gp, 0x1003c', type: 'lea' },
      { addr: ENTRY + 4, size: 4, opcode: 'addi gp, gp, 1755', type: 'add' },
      { addr: ENTRY + 8, size: 4, opcode: 'j 0x10000042', type: 'jmp', jump: ENTRY + 12 },
    ],
  })}`;
}

function r2SingleFunction(address: number, ops: object[]): string {
  return `${JSON.stringify([{ addr: address, size: 8, ninstr: ops.length }])}\n__FIRMLAB_PICOBIN_RISCV_SPLIT__\n${JSON.stringify(
    {
      name: `fcn.${address.toString(16)}`,
      ops,
    },
  )}`;
}

describe('picobinFlashMapping', () => {
  it('maps an RP2350 XIP entrypoint to its raw flash offset', () => {
    expect(picobinFlashMapping({ entryPoint: ENTRY, rollingWindowDelta: null }, FILE_SIZE)).toEqual(mapping);
  });

  it('maps a sector-aligned rolling XIP window to the stored file bytes', () => {
    expect(picobinFlashMapping({ entryPoint: ENTRY, rollingWindowDelta: 0x1000 }, 0x2000)).toEqual({
      baseAddress: 0x0fff_f000,
      entryPoint: ENTRY,
      entryFileOffset: 0x1036,
      mappingKind: 'rolling-xip',
      mappedRuntimeStart: 0x0fff_f000,
      mappedRuntimeEnd: 0x1000_1000,
    });
  });

  it('maps relative and absolute LOAD_MAP regions into their runtime addresses', () => {
    expect(
      picobinFlashMapping(
        {
          entryPoint: 0x2000_0008,
          rollingWindowDelta: null,
          loadMap: {
            itemOffset: 0x18,
            relative: true,
            entries: [{ storageAddress: 0x40, runtimeAddress: 0x2000_0000, size: 0x20 }],
          },
        },
        FILE_SIZE,
      ),
    ).toEqual({
      baseAddress: 0x1fff_ffa8,
      entryPoint: 0x2000_0008,
      entryFileOffset: 0x60,
      mappingKind: 'relative-load-map',
      mappedRuntimeStart: 0x2000_0000,
      mappedRuntimeEnd: 0x2000_0020,
    });
    expect(
      picobinFlashMapping(
        {
          entryPoint: 0x2000_0008,
          rollingWindowDelta: null,
          loadMap: {
            itemOffset: 0x18,
            relative: false,
            entries: [{ storageAddress: 0x1000_0100, runtimeAddress: 0x2000_0000, size: 0x20 }],
          },
        },
        FILE_SIZE,
      ),
    ).toEqual({
      baseAddress: 0x1fff_ff00,
      entryPoint: 0x2000_0008,
      entryFileOffset: 0x108,
      mappingKind: 'absolute-load-map',
      mappedRuntimeStart: 0x2000_0000,
      mappedRuntimeEnd: 0x2000_0020,
    });
  });

  it('refuses RAM/out-of-range entries, malformed rolls and zero-fill LOAD_MAP regions', () => {
    expect(picobinFlashMapping({ entryPoint: 0x2000_0036, rollingWindowDelta: null }, FILE_SIZE)).toBeNull();
    expect(picobinFlashMapping({ entryPoint: 0x1000_2000, rollingWindowDelta: null }, FILE_SIZE)).toBeNull();
    expect(picobinFlashMapping({ entryPoint: ENTRY, rollingWindowDelta: 2 }, FILE_SIZE)).toBeNull();
    expect(
      picobinFlashMapping(
        {
          entryPoint: 0x2000_0008,
          rollingWindowDelta: null,
          loadMap: {
            itemOffset: 0x18,
            relative: true,
            entries: [{ storageAddress: 0, runtimeAddress: 0x2000_0000, size: 0x20 }],
          },
        },
        FILE_SIZE,
      ),
    ).toBeNull();
  });
});

describe('parsePicobinRadare2Output', () => {
  it('normalizes bounded entry-function blocks and instructions', () => {
    expect(parsePicobinRadare2Output(r2Output(), mapping, FILE_SIZE)).toEqual({
      basicBlocksTotal: 2,
      instructionsTotal: 3,
      basicBlocks: [
        { address: ENTRY, size: 8, instructionCount: 2, jump: ENTRY + 12, fail: ENTRY + 8 },
        { address: ENTRY + 8, size: 4, instructionCount: 1 },
      ],
      instructions: [
        { address: ENTRY, size: 4, opcode: 'auipc gp, 0x1003c', type: 'lea' },
        { address: ENTRY + 4, size: 4, opcode: 'addi gp, gp, 1755', type: 'add' },
        { address: ENTRY + 8, size: 4, opcode: 'j 0x10000042', type: 'jmp', jump: ENTRY + 12 },
      ],
    });
  });

  it('rejects malformed JSON and decoder addresses outside the mapped image', () => {
    expect(parsePicobinRadare2Output('not json', mapping, FILE_SIZE)).toBeNull();
    const outside = r2Output().replace(String(ENTRY), String(0x2000_0000));
    expect(parsePicobinRadare2Output(outside, mapping, FILE_SIZE)).toBeNull();
  });

  it('accepts a reachable call target that radare2 folds into a function beginning before the target', () => {
    const target = ENTRY + 8;
    expect(parsePicobinRadare2Output(r2Output(), { ...mapping, entryPoint: target }, FILE_SIZE)).not.toBeNull();
  });
});

describe('runPicobinRiscvDisassembly', () => {
  const picobin = { cpuMode: 'riscv' as const, isExecutable: true, entryPoint: ENTRY, rollingWindowDelta: null };

  it('pins raw RISC-V/base/entry arguments and emits a bounded static finding', () => {
    let args: string[] = [];
    const result = runPicobinRiscvDisassembly('/firmware/pico.bin', picobin, FILE_SIZE, (received) => {
      args = received;
      return r2Output();
    });
    expect(args).toEqual([
      '-q',
      '-2',
      '-a',
      'riscv',
      '-b',
      '32',
      '-m',
      '0x10000000',
      '-c',
      expect.stringContaining('s 0x10000036;af firmlab_10000036;'),
      '/firmware/pico.bin',
    ]);
    expect(result).toMatchObject({
      available: true,
      scope: 'reachable-call-graph',
      instructionsTotal: 3,
      reachableFunctions: [{ address: ENTRY, depth: 0 }],
      callEdges: [],
      callGraphTruncated: false,
    });
    expect(result?.findings[0]).toMatchObject({ kind: 'rtos-picobin-entry-cfg', proofState: 'static_confirmed' });
  });

  it('follows only bounded direct call targets and records unresolved calls separately', () => {
    const target = ENTRY + 0x100;
    const scripts: string[] = [];
    const result = runPicobinRiscvDisassembly('/firmware/pico.bin', picobin, FILE_SIZE, (received) => {
      const script = received[received.indexOf('-c') + 1] ?? '';
      scripts.push(script);
      if (script.includes(`s 0x${target.toString(16)};`)) {
        return r2SingleFunction(target, [
          { addr: target, size: 4, opcode: 'ret', type: 'ret' },
          { addr: target + 4, size: 4, opcode: 'nop', type: 'nop' },
        ]);
      }
      return r2SingleFunction(ENTRY, [
        { addr: ENTRY, size: 4, opcode: `jal 0x${target.toString(16)}`, type: 'call', jump: target },
        { addr: ENTRY + 4, size: 4, opcode: 'jalr t0', type: 'ucall' },
      ]);
    });

    expect(scripts).toHaveLength(2);
    expect(scripts.every((script) => !script.includes('aaa') && !script.includes('aac'))).toBe(true);
    expect(result).toMatchObject({
      available: true,
      reachableFunctions: [
        { address: ENTRY, depth: 0, instructionsTotal: 2 },
        { address: target, depth: 1, instructionsTotal: 2 },
      ],
      callEdges: [{ caller: ENTRY, callsite: ENTRY, target }],
      unresolvedCallsitesTotal: 1,
      callGraphTruncated: false,
    });
  });

  it('degrades explicitly when radare2 is absent', () => {
    const result = runPicobinRiscvDisassembly('/firmware/pico.bin', picobin, FILE_SIZE, () => {
      throw Object.assign(new Error('spawn radare2 ENOENT'), { code: 'ENOENT' });
    });
    expect(result).toMatchObject({ attempted: true, available: false, reason: 'radare2 is not installed' });
    expect(result?.findings).toEqual([]);
  });

  it('degrades explicitly when a RISC-V entrypoint cannot be mapped to raw file bytes', () => {
    const result = runPicobinRiscvDisassembly(
      '/firmware/pico.bin',
      { ...picobin, rollingWindowDelta: 2 },
      FILE_SIZE,
      () => r2Output(),
    );
    expect(result).toMatchObject({
      attempted: false,
      available: false,
      baseAddress: null,
      entryPoint: ENTRY,
      entryFileOffset: null,
    });
    expect(result?.reason).toMatch(/not flash-sector aligned/);
  });

  it('does not attempt an Arm or non-executable PICOBIN image', () => {
    expect(
      runPicobinRiscvDisassembly('/firmware/pico.bin', { ...picobin, cpuMode: 'arm' }, FILE_SIZE, () => r2Output()),
    ).toBeNull();
    expect(
      runPicobinRiscvDisassembly('/firmware/pico.bin', { ...picobin, isExecutable: false }, FILE_SIZE, () =>
        r2Output(),
      ),
    ).toBeNull();
  });
});
