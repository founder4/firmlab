import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  parsePicobinRadare2Output,
  picobinFlashMapping,
  picobinRuntimeMapping,
  resolveRiscvPcRelativeCalls,
  runPicobinRiscvDisassembly,
} from './picobin-riscv.js';

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

describe('picobinRuntimeMapping', () => {
  it('maps an address copied from flash into a startup-table runtime region', () => {
    expect(
      picobinRuntimeMapping(
        0x2000_0008,
        4,
        mapping,
        {
          tableAddress: 0x1000_0060,
          tableFileOffset: 0x60,
          bytesExamined: 16,
          regions: [
            {
              sourceAddress: 0x1000_0100,
              sourceFileOffset: 0x100,
              runtimeAddress: 0x2000_0000,
              size: 0x20,
            },
          ],
        },
        FILE_SIZE,
      ),
    ).toEqual({
      baseAddress: 0x1fff_ff00,
      entryPoint: 0x2000_0008,
      entryFileOffset: 0x108,
      mappingKind: 'startup-copy',
      mappedRuntimeStart: 0x2000_0000,
      mappedRuntimeEnd: 0x2000_0020,
    });
  });

  it('does not invent a mapping outside the declared copied regions', () => {
    expect(picobinRuntimeMapping(0x2000_0008, 4, mapping, null, FILE_SIZE)).toBeNull();
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

describe('resolveRiscvPcRelativeCalls', () => {
  it('resolves adjacent AUIPC/JALR pairs from instruction bytes without guessing register state', () => {
    const resolved = resolveRiscvPcRelativeCalls([
      { address: 0x1000_008a, size: 4, opcode: 'auipc ra, 0x1000c', type: 'lea', bytes: '97c00010' },
      { address: 0x1000_008e, size: 4, opcode: 'jalr 1954(ra)', type: 'ucall', bytes: 'e780207a' },
      { address: 0x1000_0092, size: 4, opcode: 'auipc ra, 0x10003', type: 'lea', bytes: '97300010' },
      { address: 0x1000_0096, size: 4, opcode: 'jalr -1778(ra)', type: 'ucall', bytes: 'e780e090' },
      { address: 0x1000_009a, size: 4, opcode: 'auipc ra, 0x1000c', type: 'lea', bytes: '97c00010' },
      { address: 0x1000_009e, size: 4, opcode: 'jalr 1820(ra)', type: 'ucall', bytes: 'e780c071' },
    ]);
    expect(
      resolved.filter((instruction) => instruction.type === 'ucall').map((instruction) => instruction.jump),
    ).toEqual([0x2000_c82c, 0x2000_29a0, 0x2000_c7b6]);
  });

  it('leaves a JALR unresolved when the producer is missing or writes a different register', () => {
    const instructions = [
      { address: ENTRY, size: 4, opcode: 'auipc t0, 1', type: 'lea', bytes: '97120000' },
      { address: ENTRY + 4, size: 4, opcode: 'jalr 0(ra)', type: 'ucall', bytes: 'e7800000' },
    ];
    expect(resolveRiscvPcRelativeCalls(instructions)).toEqual(instructions);
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

  it('records an undecodable reachable target and continues with independent queued branches', () => {
    const bad = ENTRY + 0x100;
    const good = ENTRY + 0x200;
    const image = new Uint8Array(FILE_SIZE);
    image.set([0xb3, 0x16, 0xa0, 0x28, 0xb3, 0x47, 0xf5, 0x20], bad - mapping.baseAddress);
    const result = runPicobinRiscvDisassembly(
      '/firmware/pico.bin',
      picobin,
      FILE_SIZE,
      (received) => {
        const script = received[received.indexOf('-c') + 1] ?? '';
        if (script.includes(`s 0x${bad.toString(16)};`)) return '[]\n__FIRMLAB_PICOBIN_RISCV_SPLIT__\n{}';
        if (script.includes(`s 0x${good.toString(16)};`))
          return r2SingleFunction(good, [{ addr: good, size: 4, opcode: 'ret', type: 'ret' }]);
        return r2SingleFunction(ENTRY, [
          { addr: ENTRY, size: 4, opcode: `jal 0x${bad.toString(16)}`, type: 'call', jump: bad },
          { addr: ENTRY + 4, size: 4, opcode: `jal 0x${good.toString(16)}`, type: 'call', jump: good },
        ]);
      },
      image,
    );

    expect(result).toMatchObject({
      reachableFunctions: [{ address: ENTRY }, { address: good }],
      callEdges: [
        { caller: ENTRY, callsite: ENTRY, target: bad },
        { caller: ENTRY, callsite: ENTRY + 4, target: good },
      ],
      callGraphTruncated: true,
      decodeFailuresTotal: 1,
      decodeFailures: [
        {
          address: bad,
          fileOffset: bad - mapping.baseAddress,
          classification: 'unsupported-instruction',
          bytesHex: 'b316a028b347f520',
        },
      ],
    });
    expect(result?.reason).toContain('1 reachable target decode failure(s)');
    expect(result?.findings[0]?.evidence).toMatchObject({ decodeFailuresTotal: 1, decodeFailuresListed: 1 });
  });

  it('recovers an exact BSET/SH2ADD target through a temporary decoder view and restores source bytes', () => {
    const target = ENTRY + 0x100;
    const image = new Uint8Array(FILE_SIZE);
    image.set([0xb3, 0x16, 0xa0, 0x28, 0xb3, 0x47, 0xf5, 0x20], target - mapping.baseAddress);
    let temporaryView = '';
    const result = runPicobinRiscvDisassembly(
      '/firmware/pico.bin',
      picobin,
      FILE_SIZE,
      (received) => {
        const script = received[received.indexOf('-c') + 1] ?? '';
        const inputPath = received.at(-1) ?? '';
        if (!script.includes(`s 0x${target.toString(16)};`) && inputPath === '/firmware/pico.bin') {
          return r2SingleFunction(ENTRY, [
            { addr: ENTRY, size: 4, opcode: `jal 0x${target.toString(16)}`, type: 'call', jump: target },
          ]);
        }
        if (inputPath === '/firmware/pico.bin') return '[]\n__FIRMLAB_PICOBIN_RISCV_SPLIT__\n{}';
        temporaryView = inputPath;
        const patched = readFileSync(inputPath);
        expect(Array.from(patched.subarray(target - mapping.baseAddress, target - mapping.baseAddress + 8))).toEqual([
          0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00,
        ]);
        return r2SingleFunction(target + 8, [{ addr: target + 8, size: 4, opcode: 'ret', type: 'ret' }]);
      },
      image,
    );

    expect(temporaryView).toContain('firmlab-picobin-');
    expect(result).toMatchObject({
      reachableFunctions: [{ address: ENTRY }, { address: target }],
      callGraphTruncated: false,
      decodeFailuresTotal: 0,
      decoderSubstitutionsTotal: 2,
      decoderSubstitutions: [
        { address: target, instruction: 'bset', originalBytesHex: 'b316a028' },
        { address: target + 4, instruction: 'sh2add', originalBytesHex: 'b347f520' },
      ],
    });
    expect(result?.reason).toContain('2 exact Zba/Zbs decoder-view substitution(s)');
    expect(result?.findings[0]?.evidence).toMatchObject({
      decoderSubstitutionsTotal: 2,
      decoderSubstitutionsListed: 2,
    });
  });

  it('recovers the CRT0 copy table and follows a flash-backed SRAM target', () => {
    const entry = 0x1000_0020;
    const target = 0x2000_0008;
    const image = new Uint8Array(0x200);
    const view = new DataView(image.buffer);
    view.setUint32(0x20, 0x0000_0717, true); // auipc a4, 0
    view.setUint32(0x24, 0x0407_0713, true); // addi a4, a4, 0x40 -> table at 0x60
    view.setUint32(0x60, 0x1000_0100, true);
    view.setUint32(0x64, 0x2000_0000, true);
    view.setUint32(0x68, 0x2000_0020, true);
    view.setUint32(0x6c, 0, true);

    const scripts: string[] = [];
    const result = runPicobinRiscvDisassembly(
      '/firmware/pico.bin',
      { ...picobin, entryPoint: entry },
      image.byteLength,
      (received) => {
        const script = received[received.indexOf('-c') + 1] ?? '';
        scripts.push(script);
        return script.includes(`s 0x${target.toString(16)};`)
          ? r2SingleFunction(target, [{ addr: target, size: 2, opcode: 'ret', type: 'ret' }])
          : r2SingleFunction(entry, [
              { addr: entry, size: 4, opcode: 'auipc a4, 0', type: 'lea' },
              { addr: entry + 4, size: 4, opcode: 'addi a4, a4, 0x40', type: 'add' },
              { addr: entry + 8, size: 4, opcode: `jal 0x${target.toString(16)}`, type: 'call', jump: target },
            ]);
      },
      image,
    );

    expect(scripts).toHaveLength(2);
    expect(result).toMatchObject({
      available: true,
      startupCopyTableAttempted: true,
      startupCopyTable: {
        tableAddress: 0x1000_0060,
        regions: [{ sourceFileOffset: 0x100, runtimeAddress: 0x2000_0000, size: 0x20 }],
      },
      reachableFunctions: [
        { address: entry, depth: 0 },
        { address: target, depth: 1 },
      ],
      callEdges: [{ caller: entry, callsite: entry + 8, target }],
      outOfMapCallsitesTotal: 0,
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
