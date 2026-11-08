import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  parsePicobinRadare2Output,
  picobinDecodeStops,
  picobinDecoderSourceEvidence,
  picobinFailureBytes,
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
    { addr: ENTRY + 8, size: 4, ninstr: 1, jump: ENTRY + 12 },
    { addr: ENTRY + 12, size: 4, ninstr: 1 },
  ])}\n__FIRMLAB_PICOBIN_RISCV_SPLIT__\n${JSON.stringify({
    name: 'entry0',
    ops: [
      { addr: ENTRY, size: 4, opcode: 'auipc gp, 0x1003c', type: 'lea' },
      { addr: ENTRY + 4, size: 4, opcode: 'addi gp, gp, 1755', type: 'add' },
      { addr: ENTRY + 8, size: 4, opcode: 'j 0x10000042', type: 'jmp', jump: ENTRY + 12 },
      { addr: ENTRY + 12, size: 4, opcode: 'ret', type: 'ret' },
    ],
  })}`;
}

function r2Graph(blocks: object[], ops: object[]): string {
  return `${JSON.stringify(blocks)}\n__FIRMLAB_PICOBIN_RISCV_SPLIT__\n${JSON.stringify({ ops })}`;
}

function r2SingleFunction(address: number, ops: object[]): string {
  return `${JSON.stringify([{ addr: address, size: ops.reduce<number>((total, op) => total + (op as { size: number }).size, 0), ninstr: ops.length }])}\n__FIRMLAB_PICOBIN_RISCV_SPLIT__\n${JSON.stringify(
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
      mappedRuntimeStart: 0x1000_0000,
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

describe('mapping bounds regressions', () => {
  it('requires an aligned entry with two file-backed bytes', () => {
    expect(picobinFlashMapping({ entryPoint: ENTRY + 1, rollingWindowDelta: null }, FILE_SIZE)).toBeNull();
    expect(picobinFlashMapping({ entryPoint: ENTRY, rollingWindowDelta: null }, 0x37)).toBeNull();
    expect(picobinFlashMapping({ entryPoint: ENTRY, rollingWindowDelta: null }, 0x38)).not.toBeNull();
  });

  it('intersects positive and negative rolling windows with XIP and the actual file', () => {
    const positive = picobinFlashMapping({ entryPoint: ENTRY, rollingWindowDelta: 0x1000 }, 0x2000);
    expect(positive).toMatchObject({ mappedRuntimeStart: 0x10000000, mappedRuntimeEnd: 0x10001000 });
    const negative = picobinFlashMapping({ entryPoint: ENTRY + 0x1000, rollingWindowDelta: -0x1000 }, 0x2000);
    expect(negative).toMatchObject({
      entryFileOffset: 0x36,
      mappedRuntimeStart: 0x10001000,
      mappedRuntimeEnd: 0x10003000,
    });
    expect(picobinFlashMapping({ entryPoint: ENTRY + 0x1000, rollingWindowDelta: 0xfffff000 }, 0x2000)).toEqual(
      negative,
    );
    if (!positive) throw new Error('expected positive rolling mapping');
    expect(picobinRuntimeMapping(0x0ffffff0, 2, positive, null, 0x2000)).toBeNull();
    expect(picobinFlashMapping({ entryPoint: 0x10fffffe, rollingWindowDelta: null }, 0x1001000)).toMatchObject({
      mappedRuntimeEnd: 0x11000000,
    });
  });

  it('rejects absolute storage extending beyond XIP and selected LOAD_MAP overlaps away from entry', () => {
    const candidate = {
      entryPoint: 0x20000000,
      rollingWindowDelta: null,
      loadMap: {
        itemOffset: 0,
        relative: false,
        entries: [{ storageAddress: 0x10fffff0, runtimeAddress: 0x20000000, size: 0x20 }],
      },
    };
    expect(picobinFlashMapping(candidate, 0x1000020)).toBeNull();
    expect(
      picobinFlashMapping(
        {
          ...candidate,
          loadMap: {
            ...candidate.loadMap,
            entries: [{ storageAddress: 0x10000000, runtimeAddress: 0x20000000, size: 1 }],
          },
        },
        FILE_SIZE,
      ),
    ).toBeNull();
    candidate.loadMap.entries = [
      { storageAddress: 0x10000000, runtimeAddress: 0x20000000, size: 0x40 },
      { storageAddress: 0x10000080, runtimeAddress: 0x20000020, size: 0x40 },
    ];
    expect(picobinFlashMapping(candidate, FILE_SIZE)).toBeNull();
  });

  it('rejects a selected startup-copy region that overlaps later or leaves its source mapping', () => {
    const region = { sourceAddress: 0x10000100, sourceFileOffset: 0x100, runtimeAddress: 0x20000000, size: 0x40 };
    const table = {
      tableAddress: 0x10000060,
      tableFileOffset: 0x60,
      bytesExamined: 28,
      regions: [region, { ...region, sourceAddress: 0x10000200, sourceFileOffset: 0x200, runtimeAddress: 0x20000020 }],
    };
    expect(picobinRuntimeMapping(0x20000000, 2, mapping, table, FILE_SIZE)).toBeNull();
    expect(picobinRuntimeMapping(0x20000001, 2, mapping, { ...table, regions: [region] }, FILE_SIZE)).toBeNull();
    expect(
      picobinRuntimeMapping(0x20000000, 2, mapping, { ...table, regions: [{ ...region, size: FILE_SIZE }] }, FILE_SIZE),
    ).toBeNull();
  });
});

describe('parsePicobinRadare2Output', () => {
  it('normalizes bounded entry-function blocks and instructions', () => {
    expect(parsePicobinRadare2Output(r2Output(), mapping, FILE_SIZE)).toEqual({
      basicBlocksTotal: 3,
      instructionsTotal: 4,
      basicBlocks: [
        { address: ENTRY, size: 8, instructionCount: 2, jump: ENTRY + 12, fail: ENTRY + 8 },
        { address: ENTRY + 8, size: 4, instructionCount: 1, jump: ENTRY + 12 },
        { address: ENTRY + 12, size: 4, instructionCount: 1 },
      ],
      instructions: [
        { address: ENTRY, size: 4, opcode: 'auipc gp, 0x1003c', type: 'lea' },
        { address: ENTRY + 4, size: 4, opcode: 'addi gp, gp, 1755', type: 'add' },
        { address: ENTRY + 8, size: 4, opcode: 'j 0x10000042', type: 'jmp', jump: ENTRY + 12 },
        { address: ENTRY + 12, size: 4, opcode: 'ret', type: 'ret' },
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
      instructionsTotal: 4,
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
          { addr: target, size: 4, opcode: 'nop', type: 'nop' },
          { addr: target + 4, size: 4, opcode: 'ret', type: 'ret' },
        ]);
      }
      return r2SingleFunction(ENTRY, [
        { addr: ENTRY, size: 4, opcode: `jal 0x${target.toString(16)}`, type: 'call', jump: target },
        { addr: ENTRY + 4, size: 4, opcode: 'jalr t0', type: 'ucall' },
        { addr: ENTRY + 8, size: 4, opcode: 'ret', type: 'ret' },
      ]);
    });

    expect(scripts).toHaveLength(2);
    expect(scripts.every((script) => !script.includes('aaa') && !script.includes('aac'))).toBe(true);
    expect(result).toMatchObject({
      available: true,
      reachableFunctions: [
        { address: ENTRY, depth: 0, instructionsTotal: 3 },
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
          { addr: ENTRY + 8, size: 4, opcode: 'ret', type: 'ret' },
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
          classification: 'incomplete-decode',
          bytesHex: 'b316a028b347f520',
        },
      ],
    });
    expect(result?.reason).toContain('1 decode failure(s)/stopped continuation(s)');
    expect(result?.findings[0]?.evidence).toMatchObject({ decodeFailuresTotal: 1, decodeFailuresListed: 1 });
  });

  it('recovers an exact BSET/SH2ADD target through a temporary decoder view and restores source bytes', () => {
    const target = ENTRY + 0x100;
    const image = new Uint8Array(FILE_SIZE);
    image.set([0xb3, 0x16, 0xa0, 0x28, 0xb3, 0x47, 0xf5, 0x20, 0x67, 0x80, 0x00, 0x00], target - mapping.baseAddress);
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
            { addr: ENTRY + 4, size: 4, opcode: 'ret', type: 'ret' },
          ]);
        }
        if (inputPath === '/firmware/pico.bin') return '[]\n__FIRMLAB_PICOBIN_RISCV_SPLIT__\n{}';
        temporaryView = inputPath;
        const patched = readFileSync(inputPath);
        expect(Array.from(patched.subarray(target - mapping.baseAddress, target - mapping.baseAddress + 8))).toEqual([
          0x13, 0x80, 0x00, 0x00, 0x13, 0x80, 0x00, 0x00,
        ]);
        return r2Graph(
          [{ addr: target, size: 12, ninstr: 3 }],
          [
            { addr: target, size: 4, opcode: 'mv zero, ra', type: 'mov', bytes: '13800000' },
            { addr: target + 4, size: 4, opcode: 'mv zero, ra', type: 'mov', bytes: '13800000' },
            { addr: target + 8, size: 4, opcode: 'ret', type: 'ret', bytes: '67800000' },
          ],
        );
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
    expect(result?.findings[0]?.rationale).toContain('control-flow structure only after whole-result source agreement');
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
              { addr: entry + 12, size: 4, opcode: 'ret', type: 'ret' },
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

describe('bounded graph scheduling and failure accounting', () => {
  const entry = 0x10000000;
  const picobin = { cpuMode: 'riscv' as const, isExecutable: true, entryPoint: entry, rollingWindowDelta: null };
  const addressOf = (args: string[]): number =>
    Number((args[args.indexOf('-c') + 1] ?? '').match(/;s (0x[0-9a-f]+);/)?.[1]);
  const ret = (address: number) => ({ addr: address, size: 2, opcode: 'ret', type: 'ret' });
  const calls = (targets: number[]) =>
    r2SingleFunction(entry, [
      ...targets.map((jump, index) => ({ addr: entry + index * 4, size: 4, opcode: 'jal', type: 'call', jump })),
      ret(entry + targets.length * 4),
    ]);

  it('discovers distinct targets after repeated displayed edges and selects edges deterministically', () => {
    const a = entry + 0x200;
    const b = entry + 0x300;
    const result = runPicobinRiscvDisassembly('/synthetic.bin', picobin, FILE_SIZE, (args) => {
      const address = addressOf(args);
      return address === entry ? calls([...Array<number>(32).fill(a), b]) : r2SingleFunction(address, [ret(address)]);
    });
    expect(result).toMatchObject({
      reachableFunctions: [{ address: entry }, { address: a }, { address: b }],
      callEdgesTotal: 33,
      droppedCallEdgesTotal: 1,
      callGraphTruncated: true,
      functionsAttemptedTotal: 3,
      functionsCompletedTotal: 3,
      functionTargetsQueuedTotal: 3,
    });
    expect(result?.callEdges).toHaveLength(32);
    expect(result?.graphStopReasons).toContain('call-edge-display-cap');
    expect(result?.callEdgeSelection).toContain('caller');
  });

  it('retains a hard eight-target attempt cap even when every queued helper fails', () => {
    let attempts = 0;
    const targets = Array.from({ length: 12 }, (_, index) => entry + 0x200 + index * 2);
    const result = runPicobinRiscvDisassembly('/synthetic.bin', picobin, FILE_SIZE, (args) => {
      attempts++;
      return addressOf(args) === entry ? calls(targets) : 'malformed';
    });
    expect(attempts).toBe(8);
    expect(result).toMatchObject({
      functionsAttemptedTotal: 8,
      functionsCompletedTotal: 1,
      functionTargetsQueuedTotal: 8,
      functionsDecodedTotal: 1,
      decodeFailuresTotal: 7,
      droppedFunctionTargetsTotal: 5,
    });
    expect(result?.graphStopReasons).toEqual(expect.arrayContaining(['function-attempt-cap', 'unparsed-output']));
    expect(result?.reason).toContain('by configured limits');
    expect(result?.reason).toContain('coverage incomplete');
    expect(result?.decodeFailures?.every((failure) => failure.classification === 'incomplete-decode')).toBe(true);
  });

  it('bounds subprocess attempts at sixteen with recovery attempted on every admitted target', () => {
    const image = new Uint8Array(FILE_SIZE);
    const targets = Array.from({ length: 12 }, (_, index) => entry + 0x200 + index * 0x40);
    for (const address of [entry, ...targets]) image.set([0xb3, 0x16, 0xa0, 0x28], address - entry);
    targets.forEach((_, index) => image.set([0xef, 0x00, 0x00, 0x00], 4 + index * 4));
    image.set([0x67, 0x80, 0x00, 0x00], 4 + targets.length * 4);
    let attempts = 0;
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      FILE_SIZE,
      (args) => {
        attempts++;
        if (args.at(-1) === '/synthetic.bin' || addressOf(args) !== entry) return 'malformed';
        return r2SingleFunction(entry, [
          { addr: entry, size: 4, opcode: 'mv zero, ra', type: 'mov', bytes: '13800000' },
          ...targets.map((jump, index) => ({
            addr: entry + 4 + index * 4,
            size: 4,
            opcode: 'jal',
            type: 'call',
            bytes: 'ef000000',
            jump,
          })),
          { ...ret(entry + 4 + targets.length * 4), size: 4, bytes: '67800000' },
        ]);
      },
      image,
    );
    expect(attempts).toBe(16);
    expect(result).toMatchObject({
      functionAttemptCap: 8,
      decoderAttemptCap: 16,
      decoderAttemptsTotal: 16,
      functionsAttemptedTotal: 8,
      functionsDecodedTotal: 1,
      functionsCompletedTotal: 1,
      functionTargetsQueuedTotal: 8,
      functionTargetsPendingTotal: 0,
      decodeFailuresTotal: 7,
      droppedFunctionTargetsTotal: 5,
    });
  });

  it('selects target and edge subsets independently of decoder instruction arrival order', () => {
    const targets = Array.from({ length: 40 }, (_, index) => entry + 0x200 + index * 2);
    const ops = [
      ...targets.map((jump, index) => ({ addr: entry + index * 4, size: 4, opcode: 'jal', type: 'call', jump })),
      ret(entry + targets.length * 4),
    ];
    const run = (reverse: boolean) =>
      runPicobinRiscvDisassembly('/synthetic.bin', picobin, FILE_SIZE, (args) => {
        const address = addressOf(args);
        return address === entry
          ? r2SingleFunction(entry, reverse ? [...ops].reverse() : ops)
          : r2SingleFunction(address, [ret(address)]);
      });
    const forward = run(false);
    const backward = run(true);
    expect(forward?.callEdges).toEqual(backward?.callEdges);
    expect(forward?.reachableFunctions).toEqual(backward?.reachableFunctions);
    expect(forward).toMatchObject({ callEdgesTotal: 40, droppedCallEdgesTotal: 8, droppedFunctionTargetsTotal: 33 });
    expect(forward?.functionTargetSelection).toContain('ascending distinct targets');
  });

  it('keeps depth, instruction, and failure reasons together without calling partial decodes complete', () => {
    const result = runPicobinRiscvDisassembly('/synthetic.bin', picobin, FILE_SIZE, (args) => {
      const address = addressOf(args);
      if (address === entry)
        return r2SingleFunction(entry, [
          { addr: entry, size: 4, opcode: 'jal', type: 'call', jump: entry + 0x500 },
          ...Array.from({ length: 256 }, (_, index) => ({
            addr: entry + 4 + index * 2,
            size: 2,
            opcode: 'ret',
            type: 'ret',
          })),
        ]);
      return r2SingleFunction(address, [{ addr: address, size: 2, opcode: 'addi a0, a0, 1', type: 'add' }]);
    });
    expect(result).toMatchObject({
      functionsAttemptedTotal: 2,
      functionsDecodedTotal: 2,
      functionsCompletedTotal: 0,
      decodeFailuresTotal: 1,
    });
    expect(result?.graphStopReasons).toEqual(expect.arrayContaining(['instruction-cap', 'incomplete-decode']));
    expect(result?.reason).toContain('by configured limits');
    expect(result?.reason).toContain('coverage incomplete');
    const chain = runPicobinRiscvDisassembly('/synthetic.bin', picobin, FILE_SIZE, (args) => {
      const address = addressOf(args);
      return r2SingleFunction(address, [
        { addr: address, size: 4, opcode: 'jal', type: 'call', jump: address + 0x40 },
        ret(address + 4),
      ]);
    });
    expect(chain).toMatchObject({
      functionsAttemptedTotal: 5,
      droppedFunctionTargetsTotal: 1,
      graphStopReasons: ['call-depth-cap'],
    });
  });

  it('never samples before the selected mapping or past a short supplied byte array', () => {
    const selected = { ...mapping, mappedRuntimeStart: ENTRY, mappedRuntimeEnd: ENTRY + 8 };
    expect(picobinFailureBytes(ENTRY - 2, selected, FILE_SIZE, new Uint8Array(FILE_SIZE))).toBeUndefined();
    expect(picobinFailureBytes(ENTRY + 8, selected, FILE_SIZE, new Uint8Array(FILE_SIZE))).toBeUndefined();
    expect(picobinFailureBytes(ENTRY, selected, FILE_SIZE, new Uint8Array(0x37).fill(0xbb))).toBe('bb');
  });

  it.each(['null', 'malformed', 'boundary', 'tool'])(
    'does not claim unsupported instructions from %s failure and clamps samples',
    (mode) => {
      const target = entry + 0x3e;
      const image = new Uint8Array(FILE_SIZE).fill(0xaa);
      const result = runPicobinRiscvDisassembly(
        '/synthetic.bin',
        {
          ...picobin,
          loadMap: {
            itemOffset: 0,
            relative: false,
            entries: [{ storageAddress: entry, runtimeAddress: entry, size: 0x40 }],
          },
        },
        FILE_SIZE,
        (args) => {
          const address = addressOf(args);
          if (address === entry) return calls([target]);
          if (mode === 'tool') throw new Error('synthetic tool failure');
          if (mode === 'boundary')
            return r2SingleFunction(target, [{ addr: target, size: 4, opcode: 'ret', type: 'ret' }]);
          return mode === 'null' ? '[]\n__FIRMLAB_PICOBIN_RISCV_SPLIT__\n{}' : 'bad output';
        },
        image,
      );
      expect(result?.decodeFailures?.[0]).toMatchObject({
        address: target,
        bytesHex: 'aaaa',
        classification: mode === 'tool' ? 'tool-error' : 'incomplete-decode',
      });
      // The same sampler must respect the physical file end on a direct mapping.
      const fileResult = runPicobinRiscvDisassembly(
        '/synthetic.bin',
        picobin,
        0x40,
        (args) => (addressOf(args) === entry ? calls([target]) : 'bad output'),
        image,
      );
      expect(fileResult?.decodeFailures?.[0]?.bytesHex).toBe('aaaa');
    },
  );

  it('passes the selected window to startup copy parsing for table, source and code bounds', () => {
    const entryPoint = entry + 0x20;
    const image = new Uint8Array(0x200);
    const view = new DataView(image.buffer);
    view.setUint32(0x20, 0x00000013, true); // nop
    view.setUint32(0x24, 0x00000717, true); // auipc a4, 0
    view.setUint32(0x28, 0x03c70713, true); // table at 0x60
    view.setUint32(0x60, entry + 0x100, true);
    view.setUint32(0x64, 0x20000000, true);
    view.setUint32(0x68, 0x20000020, true);
    for (const size of [4, 0x40, 0x80, 0x1e0]) {
      const result = runPicobinRiscvDisassembly(
        '/synthetic.bin',
        {
          ...picobin,
          entryPoint,
          loadMap: {
            itemOffset: 0,
            relative: false,
            entries: [{ storageAddress: entryPoint, runtimeAddress: entryPoint, size }],
          },
        },
        image.length,
        () => r2SingleFunction(entryPoint, [ret(entryPoint)]),
        image,
      );
      if (size === 0x1e0)
        expect(result?.startupCopyTable).toMatchObject({
          sourceBounds: { start: entryPoint, endExclusive: entry + 0x200 },
        });
      else expect(result?.startupCopyTable).toBeNull();
    }
  });
});

describe('silent decoder truncation and recovery wiring', () => {
  const entry = 0x1000_0000;
  const picobin = { cpuMode: 'riscv' as const, isExecutable: true, entryPoint: entry, rollingWindowDelta: null };
  const normal = { addr: entry, size: 4, opcode: 'addi sp, sp, -16', type: 'add', bytes: '130101ff' };
  const replacement = { addr: entry + 4, size: 4, opcode: 'mv zero, ra', type: 'mov', bytes: '13800000' };
  const ret = { addr: entry + 8, size: 4, opcode: 'ret', type: 'ret', bytes: '67800000' };

  it('recognizes a successful nonterminal prefix as incomplete at the actual parser boundary', () => {
    // afbj/pdfj shape measured with radare2 6.2.4 on addi; bset; jal; ret.
    const parsed = parsePicobinRadare2Output(
      r2Graph([{ addr: entry, size: 4, ninstr: 1 }], [normal]),
      { ...mapping, entryPoint: entry, entryFileOffset: 0 },
      FILE_SIZE,
    );
    expect(parsed).not.toBeNull();
    if (!parsed) return;
    expect(picobinDecodeStops(parsed, mapping)).toEqual([entry + 4]);
  });

  it('detects a missing conditional continuation without treating out-of-map targets as local evidence', () => {
    const parsed = parsePicobinRadare2Output(
      r2Graph(
        [
          { addr: entry, size: 4, ninstr: 1, jump: entry + 8, fail: entry + 4 },
          { addr: entry + 4, size: 4, ninstr: 1 },
        ],
        [
          { addr: entry, size: 4, opcode: 'bnez a0, 0x10000008', type: 'cjmp', jump: entry + 8, fail: entry + 4 },
          { addr: entry + 4, size: 4, opcode: 'ret', type: 'ret' },
        ],
      ),
      { ...mapping, entryPoint: entry, entryFileOffset: 0 },
      FILE_SIZE,
    );
    expect(parsed).not.toBeNull();
    if (!parsed) return;
    expect(picobinDecodeStops(parsed, mapping)).toEqual([entry + 8]);
    expect(picobinDecodeStops(parsed, { mappedRuntimeStart: entry, mappedRuntimeEnd: entry + 8 })).toEqual([entry + 8]);
  });

  it('recovers a non-null mid-block prefix at depth zero and reports only decoded replacements', () => {
    const image = Buffer.from('130101ffb316a02867800000b347f520', 'hex');
    const paths: string[] = [];
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      (args) => {
        const input = args.at(-1) ?? '';
        paths.push(input);
        if (input === '/synthetic.bin') return r2Graph([{ addr: entry, size: 4, ninstr: 1 }], [normal]);
        expect(readFileSync(input).toString('hex')).toBe('130101ff138000006780000013800000');
        expect(args[args.indexOf('-c') + 1]).toContain('s 0x10000000;af ');
        return r2Graph([{ addr: entry, size: 12, ninstr: 3 }], [normal, replacement, ret]);
      },
      image,
    );
    expect(paths).toHaveLength(2);
    expect(result).toMatchObject({
      available: true,
      basicBlocksTotal: 1,
      instructionsTotal: 3,
      callGraphTruncated: false,
      decodeFailuresTotal: 0,
      decoderSubstitutionsTotal: 1,
      decoderSubstitutions: [{ address: entry + 4, originalBytesHex: 'b316a028', mnemonic: 'bset x13, x0, x10' }],
    });
    expect(result?.instructions[1]).toMatchObject({ opcode: 'bset x13, x0, x10', bytes: 'b316a028', type: 'bitmanip' });
    expect(result?.decoderSubstitutions?.some((row) => row.address === entry + 12)).toBe(false);
    expect(() => readFileSync(paths[1] ?? '')).toThrow();
  });

  it('retains a decoded prefix with explicit incomplete coverage when recovery cannot decode its tail', () => {
    const image = Buffer.from('130101ffb316a02aef00800167800000', 'hex');
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      () => r2Graph([{ addr: entry, size: 4, ninstr: 1 }], [normal]),
      image,
    );
    expect(result).toMatchObject({
      available: true,
      instructionsTotal: 1,
      callGraphTruncated: true,
      decodeFailuresTotal: 1,
      decodeFailures: [{ address: entry + 4, classification: 'incomplete-decode' }],
      decoderSubstitutionsTotal: 0,
    });
    expect(result?.reason).toContain('coverage incomplete');
  });

  it('describes a stopped mapping boundary without sampling adjacent unmapped bytes', () => {
    const image = Buffer.from('130101ffb316a02867800000', 'hex');
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      {
        ...picobin,
        loadMap: {
          itemOffset: 0,
          relative: false,
          entries: [{ storageAddress: entry, runtimeAddress: entry, size: 4 }],
        },
      },
      image.length,
      () => r2Graph([{ addr: entry, size: 4, ninstr: 1 }], [normal]),
      image,
    );
    expect(result).toMatchObject({ callGraphTruncated: true, decoderSubstitutionsTotal: 0, decodeFailuresTotal: 1 });
    expect(result?.decodeFailures?.[0]).toMatchObject({ address: entry + 4, classification: 'incomplete-decode' });
    expect(result?.decodeFailures?.[0]).not.toHaveProperty('bytesHex');
  });

  it('does not turn a still-truncated recovery into complete coverage', () => {
    const image = Buffer.from('b316a028b316a02a67800000', 'hex');
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      (args) =>
        args.at(-1) === '/synthetic.bin'
          ? '[]\n__FIRMLAB_PICOBIN_RISCV_SPLIT__\n{}'
          : r2Graph([{ addr: entry, size: 4, ninstr: 1 }], [{ ...replacement, addr: entry }]),
      image,
    );
    expect(result).toMatchObject({ callGraphTruncated: true, decodeFailuresTotal: 1, decoderSubstitutionsTotal: 1 });
    expect(result?.instructions[0]).toMatchObject({ opcode: 'bset x13, x0, x10', bytes: 'b316a028' });
  });
});

// Opt-in real-tool acceptance: each process gets only its synthetic input directory, no network or live data.
// Pin the image ID in FIRMLAB_TEST_RADARE2_IMAGE; ordinary unit tests do not require Docker/radare2.
describe.skipIf(!process.env.FIRMLAB_TEST_RADARE2_IMAGE)('offline real radare2 decoder recovery', () => {
  const entry = 0x1000_0000;
  const picobin = { cpuMode: 'riscv' as const, isExecutable: true, entryPoint: entry, rollingWindowDelta: null };
  const execute = (args: string[]): string => {
    const input = args.at(-1);
    if (!input) throw new Error('missing synthetic file');
    return execFileSync(
      'docker',
      [
        'run',
        '--rm',
        '--network',
        'none',
        '--read-only',
        '--tmpfs',
        '/tmp',
        '--mount',
        `type=bind,source=${path.dirname(input)},target=${path.dirname(input)},readonly`,
        '--entrypoint',
        'radare2',
        process.env.FIRMLAB_TEST_RADARE2_IMAGE ?? '',
        ...args,
      ],
      { encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] },
    );
  };
  const withImage = (hex: string, test: (image: Buffer, imagePath: string) => void, size = 128): void => {
    const directory = mkdtempSync(path.join(tmpdir(), 'firmlab-r2-synthetic-'));
    try {
      const image = Buffer.alloc(size);
      Buffer.from(hex, 'hex').copy(image);
      const imagePath = path.join(directory, 'synthetic.bin');
      writeFileSync(imagePath, image, { mode: 0o600 });
      test(image, imagePath);
      expect(readFileSync(imagePath)).toEqual(image);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  };

  it('preserves original instructions and the compressed call after jumping over inline data', () => {
    withImage(
      '11a00300130533100128b316a0288280',
      (image, imagePath) => {
        image.set(Buffer.from('8280', 'hex'), 0x28);
        writeFileSync(imagePath, image);
        const result = runPicobinRiscvDisassembly(imagePath, picobin, 64, execute, image);
        expect(result?.instructions.find((op) => op.address === entry + 4)).toMatchObject({ bytes: '13053310' });
        expect(result?.instructions.find((op) => op.address === entry + 8)).toMatchObject({
          bytes: '0128',
          jump: entry + 0x18,
        });
        expect(result?.callEdges).toContainEqual({ caller: entry, callsite: entry + 8, target: entry + 0x18 });
        expect(result?.instructions.some((op) => ['13051380', '00001380'].includes(op.bytes ?? ''))).toBe(false);
        // Source-anchored selection withholds offset 6 (it overlaps the decoded ADDI) before the retry, so the
        // separately corroborated BSET stop at 0x0a is recovered. Before that, the whole view was refused here.
        expect(result?.decoderCandidateExclusions).toEqual([
          {
            functionAddress: entry,
            address: entry + 6,
            fileOffset: 6,
            instruction: 'bset',
            originalBytesHex: '33100128',
            reason: 'known-instruction-overlap',
            conflictAddress: entry + 4,
          },
        ]);
        expect(result?.decoderSubstitutions).toEqual([
          {
            address: entry + 10,
            fileOffset: 10,
            instruction: 'bset',
            originalBytesHex: 'b316a028',
            candidateBasis: 'corroborated-boundary',
            mnemonic: 'bset x13, x0, x10',
          },
        ]);
        expect(result?.instructions.map((op) => [op.address - entry, op.bytes])).toEqual([
          [0, '11a0'],
          [4, '13053310'],
          [8, '0128'],
          [10, 'b316a028'],
          [14, '8280'],
        ]);
        // Only the entry function completes this static scope. The actual c.jal target is 0x18 (zero bytes, no
        // RET), not the RET at 0x28: the helper stays a decode failure and the graph stays incomplete.
        expect(result?.functionsCompletedTotal).toBe(1);
        expect(result?.reachableFunctions?.map((row) => row.address)).toEqual([entry]);
        expect(result?.decodeFailures?.map((row) => row.address)).toEqual([entry + 0x18]);
        expect(result?.callGraphTruncated).toBe(true);
        expect(result?.reason).toContain('coverage incomplete');
      },
      64,
    );
  });

  it('labelled synthetic variant: completes the helper only when 0x18 actually holds a RET', () => {
    withImage(
      '11a00300130533100128b316a0288280',
      (image, imagePath) => {
        image.set(Buffer.from('8280', 'hex'), 0x28);
        image.set(Buffer.from('8280', 'hex'), 0x18); // synthetic addition, not part of the Finding 1A fixture
        writeFileSync(imagePath, image);
        const result = runPicobinRiscvDisassembly(imagePath, picobin, 64, execute, image);
        expect(result).toMatchObject({
          functionsCompletedTotal: 2,
          callGraphTruncated: false,
          decodeFailuresTotal: 0,
          decoderSubstitutionsTotal: 1,
          decoderCandidateExclusionsTotal: 1,
        });
        expect(result?.reachableFunctions?.map((row) => row.address)).toEqual([entry, entry + 0x18]);
        expect(result?.instructions.find((op) => op.address === entry + 4)?.bytes).toBe('13053310');
      },
      64,
    );
  });

  for (const [instruction, hex] of [
    ['bset', 'b316a028'],
    ['sh1add', 'b327f520'],
    ['sh2add', 'b347f520'],
    ['sh3add', '3365c520'],
  ]) {
    for (const position of ['entry', 'mid-block']) {
      it(`recovers ${instruction} at ${position}, follows the tail call and preserves exact evidence`, () => {
        const prefix = position === 'entry' ? '' : '130101ff';
        const call = position === 'entry' ? 'ef00c001' : 'ef008001'; // JAL ra, entry+0x20
        withImage(`${prefix}${hex}${call}67800000`, (image, imagePath) => {
          image.set(Buffer.from('67800000', 'hex'), 0x20);
          // This extra bitmanip match is unreachable after helper RET and must not become graph evidence.
          image.set(Buffer.from('b316a028', 'hex'), 0x24);
          writeFileSync(imagePath, image);
          const raw = execute([
            '-q',
            '-2',
            '-a',
            'riscv',
            '-b',
            '32',
            '-m',
            '0x10000000',
            '-c',
            'e anal.bb.maxsize=4096;s 0x10000000;af test;afbj;?e __FIRMLAB_PICOBIN_RISCV_SPLIT__;pdfj',
            imagePath,
          ]);
          const parsed = parsePicobinRadare2Output(
            raw,
            { ...mapping, entryPoint: entry, entryFileOffset: 0 },
            image.length,
          );
          if (position === 'entry') expect(parsed).toBeNull();
          else expect(parsed).toMatchObject({ basicBlocksTotal: 1, instructionsTotal: 1 });
          const result = runPicobinRiscvDisassembly(imagePath, picobin, image.length, execute, image);
          expect(result).toMatchObject({
            available: true,
            basicBlocksTotal: 1,
            instructionsTotal: position === 'entry' ? 3 : 4,
            reachableFunctions: [{ address: entry }, { address: entry + 0x20, instructionsTotal: 1 }],
            callEdges: [{ caller: entry, callsite: entry + prefix.length / 2 + 4, target: entry + 0x20 }],
            callGraphTruncated: false,
            decodeFailuresTotal: 0,
            decoderSubstitutionsTotal: 1,
            decoderSubstitutions: [
              {
                address: entry + prefix.length / 2,
                instruction,
                originalBytesHex: hex,
                mnemonic: expect.stringContaining(`${instruction} `),
              },
            ],
          });
          expect(result?.instructions.find((row) => row.address === entry + prefix.length / 2)?.bytes).toBe(hex);
          expect(result?.basicBlocks).toEqual([
            { address: entry, size: position === 'entry' ? 12 : 16, instructionCount: position === 'entry' ? 3 : 4 },
          ]);
          expect(result?.instructions).toHaveLength(position === 'entry' ? 3 : 4);
          expect(new Set(result?.instructions.map((row) => row.address)).size).toBe(result?.instructions.length);
        });
      });
    }
  }

  it('recovers an omitted direct branch target or fallthrough block', () => {
    for (const hex of [
      '6314050067800000b316a02867800000',
      '63140500b316a02867800000',
      '6f00800067800000b316a02867800000',
    ]) {
      withImage(hex, (image, imagePath) => {
        const result = runPicobinRiscvDisassembly(imagePath, picobin, image.length, execute, image);
        expect(result).toMatchObject({
          available: true,
          callGraphTruncated: false,
          decodeFailuresTotal: 0,
          decoderSubstitutionsTotal: 1,
        });
        expect(result?.instructions.map((row) => row.address)).toContain(
          entry + (hex.includes('67800000b316a028') ? 8 : 4),
        );
        expect(result?.decoderSubstitutions?.[0]?.mnemonic).toBe('bset x13, x0, x10');
      });
    }
  });

  it('keeps a reachable helper with a backward edge to its substituted entry unique', () => {
    withImage('ef00000267800000', (image, imagePath) => {
      image.set(Buffer.from('b316a028e31e05fe67800000', 'hex'), 0x20);
      image.set(Buffer.from('b347f520', 'hex'), 0x2c);
      writeFileSync(imagePath, image);
      // Reproduce the former shifted NOP view: r2 already returns the back-edge entry.
      const legacyView = Buffer.from(image);
      legacyView.set(Buffer.from('13000000', 'hex'), 0x20);
      const legacyPath = path.join(path.dirname(imagePath), 'legacy-nop-view.bin');
      writeFileSync(legacyPath, legacyView, { mode: 0o600 });
      const legacyRaw = execute([
        '-q',
        '-2',
        '-a',
        'riscv',
        '-b',
        '32',
        '-m',
        '0x10000000',
        '-c',
        'e anal.bb.maxsize=4096;s 0x10000024;af test;afbj;?e __FIRMLAB_PICOBIN_RISCV_SPLIT__;pdfj',
        legacyPath,
      ]);
      const legacy = parsePicobinRadare2Output(
        legacyRaw,
        { ...mapping, entryPoint: entry + 0x24, entryFileOffset: 0x24 },
        image.length,
      );
      expect(legacy?.basicBlocks.map((block) => block.address)).toContain(entry + 0x20);
      expect(legacy?.instructions.map((instruction) => instruction.address)).toContain(entry + 0x20);
      const result = runPicobinRiscvDisassembly(imagePath, picobin, image.length, execute, image);
      expect(result).toMatchObject({
        reachableFunctions: [
          { address: entry, instructionsTotal: 2 },
          { address: entry + 0x20, basicBlocksTotal: 2, instructionsTotal: 3 },
        ],
        callGraphTruncated: false,
        decoderSubstitutionsTotal: 1,
        decoderSubstitutions: [{ address: entry + 0x20, originalBytesHex: 'b316a028', mnemonic: 'bset x13, x0, x10' }],
      });
      // Also inspect the helper as the selected entry so exact returned graph rows are observable.
      const helper = runPicobinRiscvDisassembly(
        imagePath,
        { ...picobin, entryPoint: entry + 0x20 },
        image.length,
        execute,
        image,
      );
      expect(helper?.basicBlocks).toEqual([
        { address: entry + 0x20, size: 8, instructionCount: 2, jump: entry + 0x20, fail: entry + 0x28 },
        { address: entry + 0x28, size: 4, instructionCount: 1 },
      ]);
      expect(helper?.instructions.map((row) => row.address)).toEqual([entry + 0x20, entry + 0x24, entry + 0x28]);
      expect(helper?.instructions[0]).toMatchObject({ bytes: 'b316a028', opcode: 'bset x13, x0, x10' });
    });
  });

  it('keeps coverage incomplete when the replacement cap leaves a supported tail undecoded', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'firmlab-r2-synthetic-cap-'));
    try {
      const image = Buffer.from(`${'b316a028'.repeat(65)}67800000`, 'hex');
      const imagePath = path.join(directory, 'synthetic.bin');
      writeFileSync(imagePath, image, { mode: 0o600 });
      const result = runPicobinRiscvDisassembly(imagePath, picobin, image.length, execute, image);
      expect(result).toMatchObject({
        available: true,
        callGraphTruncated: true,
        instructionsTotal: 64,
        decoderSubstitutionsTotal: 64,
        decodeFailuresTotal: 1,
      });
      expect(result?.decodeFailures?.[0]?.address).toBe(entry + 256);
      expect(result?.reason).toContain('coverage incomplete');
      expect(readFileSync(imagePath)).toEqual(image);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('reports unsupported entry and discarded mid-block tails as incomplete', () => {
    for (const prefix of ['', '130101ff']) {
      withImage(`${prefix}b316a02aef00800167800000`, (image, imagePath) => {
        const result = runPicobinRiscvDisassembly(imagePath, picobin, image.length, execute, image);
        expect(result?.callGraphTruncated).toBe(true);
        expect(result?.reason).toContain('coverage incomplete');
        if (prefix) expect(result).toMatchObject({ available: true, instructionsTotal: 1, decodeFailuresTotal: 1 });
        else expect(result?.available).toBe(false);
      });
    }
  });
});

describe('decoder evidence safety regressions', () => {
  const entry = 0x1000_0000;
  const picobin = { cpuMode: 'riscv' as const, isExecutable: true, entryPoint: entry, rollingWindowDelta: null };
  const localMapping = { ...mapping, entryPoint: entry, entryFileOffset: 0 };
  const normal = { addr: entry, size: 4, opcode: 'addi sp, sp, -16', type: 'add', bytes: '130101ff' };
  const replacement = { addr: entry + 4, size: 4, opcode: 'mv zero, ra', type: 'mov', bytes: '13800000' };
  const ret = { addr: entry + 8, size: 4, opcode: 'ret', type: 'ret', bytes: '67800000' };

  it.each(['jmp', 'cjmp', 'ujmp', 'ijmp', 'rjmp'])('never completes an unresolved %s continuation', (type) => {
    const indirect = type.endsWith('jmp') && !['jmp', 'cjmp'].includes(type);
    const jump = indirect ? {} : { jump: entry + 0x1000 };
    const fail = type === 'cjmp' ? { fail: entry + 4 } : {};
    const result = runPicobinRiscvDisassembly('/synthetic.bin', picobin, 4, () =>
      r2Graph(
        [{ addr: entry, size: 4, ninstr: 1, ...jump, ...fail }],
        [{ addr: entry, size: 4, opcode: 'jump', type, ...jump, ...fail }],
      ),
    );
    expect(result).toMatchObject({ functionsCompletedTotal: 0, callGraphTruncated: true });
    expect(result?.graphStopReasons).toContain('incomplete-decode');
    expect(result?.reason).toContain('stopped continuation(s)');
  });

  it.each([
    { name: 'missing tail', ops: [normal] },
    { name: 'internal gap', ops: [normal, { ...ret, addr: entry + 6, size: 2 }] },
    { name: 'invalid op', ops: [normal, { ...replacement, type: 'ill', opcode: 'illegal' }] },
    {
      name: 'unknown op',
      ops: [
        { ...normal, type: 'unk' },
        { ...ret, addr: entry + 4 },
      ],
    },
    {
      name: 'instruction count mismatch',
      ops: [normal, { ...ret, addr: entry + 4, size: 2 }, { ...ret, addr: entry + 6, size: 2 }],
    },
    {
      name: 'operation outside blocks',
      ops: [
        { ...ret, addr: entry, size: 8 },
        { ...ret, addr: entry + 12 },
      ],
    },
  ])('does not complete $name', ({ ops }) => {
    const result = runPicobinRiscvDisassembly('/synthetic.bin', picobin, 32, () =>
      r2Graph([{ addr: entry, size: 8, ninstr: 2 }], ops),
    );
    expect(result?.available).toBe(true);
    expect(result).toMatchObject({ functionsCompletedTotal: 0, callGraphTruncated: true });
    expect(result?.decodeFailuresTotal).toBeGreaterThan(0);
  });

  it('examines a fully listed stopped block even when another path has capped operations', () => {
    const ops = [
      normal,
      ...Array.from({ length: 256 }, (_, i) => ({ addr: entry + 16 + i * 2, size: 2, opcode: 'ret', type: 'ret' })),
    ];
    const parsed = parsePicobinRadare2Output(
      r2Graph(
        [
          { addr: entry, size: 4, ninstr: 1 },
          { addr: entry + 16, size: 512, ninstr: 256 },
        ],
        ops,
      ),
      localMapping,
      FILE_SIZE,
    );
    expect(parsed).not.toBeNull();
    if (parsed) expect(picobinDecodeStops(parsed, localMapping)).toContain(entry + 4);
  });

  it('restores listed substitutions in block 129 despite the block display cap', () => {
    const image = Buffer.from(`${'6f004000'.repeat(128)}b316a02867800000`, 'hex');
    const blocks = Array.from({ length: 129 }, (_, i) => ({
      addr: entry + i * 4,
      size: i === 128 ? 8 : 4,
      ninstr: i === 128 ? 2 : 1,
      ...(i < 128 ? { jump: entry + (i + 1) * 4 } : {}),
    }));
    const ops = Array.from({ length: 128 }, (_, i) => ({
      addr: entry + i * 4,
      size: 4,
      opcode: `j 0x${(entry + (i + 1) * 4).toString(16)}`,
      type: 'jmp',
      jump: entry + (i + 1) * 4,
      bytes: '6f004000',
    }));
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      (args) =>
        args.at(-1) === '/synthetic.bin'
          ? r2Graph(blocks.slice(0, 128), ops)
          : r2Graph(blocks, [...ops, { ...replacement, addr: entry + 512 }, { ...ret, addr: entry + 516 }]),
      image,
    );
    expect(result?.instructions[128]).toMatchObject({
      bytes: 'b316a028',
      type: 'bitmanip',
      opcode: 'bset x13, x0, x10',
    });
    expect(result?.decoderSubstitutionsTotal).toBe(1);
    expect(result?.graphStopReasons).toContain('basic-block-cap');
    expect(result?.functionsCompletedTotal).toBe(0);
  });

  it.each([
    'partial-overlap',
    'source-mismatch',
    'missing-bytes',
    'block-boundary',
    'width-mismatch',
    'lost-call',
    'no-progress',
    'irrelevant',
  ])('rejects %s recovery and retains the valid original call', (mode) => {
    const image = Buffer.from('ef000001b316a02867800000b316a02867800000', 'hex');
    const call = {
      addr: entry,
      size: 4,
      opcode: 'jal 0x10000010',
      type: 'call',
      bytes: 'ef000001',
      jump: entry + 16,
    };
    const original = r2Graph([{ addr: entry, size: 4, ninstr: 1 }], [call]);
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      (args) => {
        const script = args[args.indexOf('-c') + 1] ?? '';
        if (script.includes('s 0x10000010;')) return r2SingleFunction(entry + 16, [{ ...ret, addr: entry + 16 }]);
        if (args.at(-1) === '/synthetic.bin' || mode === 'no-progress') return original;
        if (mode === 'irrelevant')
          return r2Graph(
            [
              { addr: entry, size: 4, ninstr: 1 },
              { addr: entry + 12, size: 8, ninstr: 2 },
            ],
            [call, { ...replacement, addr: entry + 12 }, { ...ret, addr: entry + 16 }],
          );
        return r2Graph(
          [{ addr: entry, size: mode === 'block-boundary' ? 6 : mode === 'width-mismatch' ? 10 : 12, ninstr: 3 }],
          [
            mode === 'lost-call'
              ? { ...call, type: 'mov', opcode: 'mv zero, ra', jump: undefined }
              : mode === 'source-mismatch'
                ? { ...call, bytes: '13000000' }
                : call,
            mode === 'partial-overlap'
              ? { ...replacement, addr: entry + 6 }
              : mode === 'missing-bytes'
                ? { ...replacement, bytes: undefined }
                : replacement,
            mode === 'width-mismatch' ? { ...ret, size: 2, bytes: '6780' } : ret,
          ],
        );
      },
      image,
    );
    expect(result?.instructions).toEqual([
      { address: entry, size: 4, opcode: call.opcode, type: 'call', bytes: call.bytes, jump: call.jump },
    ]);
    expect(result?.callEdges).toContainEqual({ caller: entry, callsite: entry, target: entry + 16 });
    expect(result?.decoderSubstitutionsTotal).toBe(0);
    expect(result?.callGraphTruncated).toBe(true);
  });

  it('does not retry a stop with no relevant substitution', () => {
    const image = Buffer.from('130101ff130101ffb316a028', 'hex');
    let attempts = 0;
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      () => {
        attempts++;
        return r2Graph([{ addr: entry, size: 4, ninstr: 1 }], [normal]);
      },
      image,
    );
    expect(attempts).toBe(1);
    expect(result?.functionsCompletedTotal).toBe(0);
  });

  it.each([12, 16, 64])('bounds supplied bytes of length %s against the declared file', (length) => {
    const image = Buffer.alloc(length);
    Buffer.from('130101ffb316a02867800000', 'hex').copy(image);
    const fileSize = length === 12 ? 64 : 12;
    let attempts = 0;
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      fileSize,
      (args) => {
        attempts++;
        if (args.at(-1) === '/synthetic.bin') return r2Graph([{ addr: entry, size: 4, ninstr: 1 }], [normal]);
        expect(readFileSync(args.at(-1) ?? '')).toHaveLength(fileSize);
        return r2Graph([{ addr: entry, size: 12, ninstr: 3 }], [normal, replacement, ret]);
      },
      image,
    );
    expect(result?.sourceBytesAvailable).toBe(Math.min(length, fileSize));
    expect(result?.sourceBytesDeclared).toBe(fileSize);
    if (length < fileSize) {
      expect(attempts).toBe(1);
      expect(result?.instructions).toHaveLength(1);
      expect(result?.reason).toContain('source bytes available 12/64');
      expect(result?.decoderRecoveryUnavailableReason).toContain('complete file bytes unavailable');
      expect(result?.functionsCompletedTotal).toBe(0);
    } else {
      expect(attempts).toBe(2);
      expect(result?.decoderSubstitutionsTotal).toBe(1);
      expect(result?.instructions[1]?.bytes).toBe('b316a028');
      expect(result?.functionsCompletedTotal).toBe(1);
    }
  });

  it('retains the original prefix when the recovery subprocess fails', () => {
    const image = Buffer.from('130101ffb316a02867800000', 'hex');
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      (args) => {
        if (args.at(-1) === '/synthetic.bin') return r2Graph([{ addr: entry, size: 4, ninstr: 1 }], [normal]);
        throw new Error('synthetic retry failure');
      },
      image,
    );
    expect(result?.available).toBe(true);
    expect(result?.instructions).toHaveLength(1);
    expect(result?.graphStopReasons).toEqual(expect.arrayContaining(['tool-error', 'incomplete-decode']));
    expect(result?.decodeFailures).toEqual(
      expect.arrayContaining([expect.objectContaining({ classification: 'tool-error' })]),
    );
  });

  it('keeps an unavailable entry explicit when only a short byte prefix was supplied', () => {
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      64,
      () => 'malformed',
      Buffer.from('b316a028', 'hex'),
    );
    expect(result).toMatchObject({
      available: false,
      sourceBytesAvailable: 4,
      sourceBytesDeclared: 64,
      functionsCompletedTotal: 0,
    });
    expect(result?.reason).toContain('source bytes available 4/64');
  });

  it('refuses recovery that drops original branch graph attribution', () => {
    const image = Buffer.from('63140500b316a02867800000', 'hex');
    const branch = {
      addr: entry,
      size: 4,
      opcode: 'bnez a0, 0x10000008',
      type: 'cjmp',
      bytes: '63140500',
      jump: entry + 8,
      fail: entry + 4,
    };
    const originalBlocks = [
      { addr: entry, size: 4, ninstr: 1, jump: entry + 8, fail: entry + 4 },
      { addr: entry + 8, size: 4, ninstr: 1 },
    ];
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      (args) =>
        args.at(-1) === '/synthetic.bin'
          ? r2Graph(originalBlocks, [branch, ret])
          : r2Graph(
              [
                { addr: entry, size: 4, ninstr: 1, jump: entry + 8 },
                { addr: entry + 4, size: 8, ninstr: 2 },
              ],
              [branch, replacement, ret],
            ),
      image,
    );
    expect(result?.instructions).toHaveLength(2);
    expect(result?.basicBlocks[0]).toMatchObject({ jump: entry + 8, fail: entry + 4 });
    expect(result?.decoderSubstitutionsTotal).toBe(0);
    expect(result?.functionsCompletedTotal).toBe(0);
  });

  it('keeps an actual in-map stop and an out-of-map continuation alongside the operation cap', () => {
    const ops = [
      normal,
      ...Array.from({ length: 256 }, (_, i) => ({ addr: entry + 16 + i * 2, size: 2, opcode: 'ret', type: 'ret' })),
    ];
    const result = runPicobinRiscvDisassembly('/synthetic.bin', picobin, FILE_SIZE, () =>
      r2Graph(
        [
          { addr: entry, size: 4, ninstr: 1 },
          { addr: entry + 16, size: 512, ninstr: 256, jump: entry + FILE_SIZE },
        ],
        ops,
      ),
    );
    expect(result?.graphStopReasons).toEqual(
      expect.arrayContaining(['instruction-cap', 'out-of-map-continuation', 'incomplete-decode']),
    );
    expect(result?.decodeFailures).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ address: entry + 4 }),
        expect.objectContaining({ address: entry + FILE_SIZE }),
      ]),
    );
    expect(result?.functionsCompletedTotal).toBe(0);
  });

  it('distinguishes a decoded target omitted by the operation cap from a missing continuation', () => {
    const target = entry + 514;
    const ops = [
      { addr: entry, size: 4, opcode: 'bnez', type: 'cjmp', jump: target, fail: entry + 4 },
      ...Array.from({ length: 256 }, (_, i) => ({ addr: entry + 4 + i * 2, size: 2, opcode: 'ret', type: 'ret' })),
    ];
    const result = runPicobinRiscvDisassembly('/synthetic.bin', picobin, FILE_SIZE, () =>
      r2Graph(
        [
          { addr: entry, size: 4, ninstr: 1, jump: target, fail: entry + 4 },
          { addr: entry + 4, size: 512, ninstr: 256 },
        ],
        ops,
      ),
    );
    expect(result?.instructions).toHaveLength(256);
    expect(result?.instructionDisplayOmissions).toContain(target);
    expect(result?.graphStopReasons).toEqual(['instruction-cap']);
    expect(result?.decodeFailuresTotal).toBe(0);
    expect(result?.functionsCompletedTotal).toBe(0);
  });

  it('uses corroborated block targets when the terminal operation omits its jump attribute', () => {
    const result = runPicobinRiscvDisassembly('/synthetic.bin', picobin, 8, () =>
      r2Graph(
        [
          { addr: entry, size: 4, ninstr: 1, jump: entry + 4 },
          { addr: entry + 4, size: 4, ninstr: 1 },
        ],
        [
          { addr: entry, size: 4, opcode: 'j 0x10000004', type: 'jmp' },
          { ...ret, addr: entry + 4 },
        ],
      ),
    );
    expect(result).toMatchObject({ functionsCompletedTotal: 1, callGraphTruncated: false, decodeFailuresTotal: 0 });
  });
});

describe('source-anchored decoder candidate selection', () => {
  const entry = 0x1000_0000;
  const picobin = { cpuMode: 'riscv' as const, isExecutable: true, entryPoint: entry, rollingWindowDelta: null };
  const localMapping = { ...mapping, entryPoint: entry, entryFileOffset: 0, mappedRuntimeEnd: entry + 64 };
  // Rows exactly as the pinned radare2 reports the Finding 1A fixture and its offset-10-only view.
  const cj = { addr: entry, size: 2, opcode: 'j 0x10000004', type: 'jmp', bytes: '11a0', jump: entry + 4 };
  const addi = { addr: entry + 4, size: 4, opcode: 'addi a0, t1, 259', type: 'add', bytes: '13053310' };
  const cjal = { addr: entry + 8, size: 2, opcode: 'jal 0x10000018', type: 'call', bytes: '0128', jump: entry + 0x18 };
  const inlineData = (): Buffer => {
    const image = Buffer.alloc(64);
    Buffer.from('11a00300130533100128b316a0288280', 'hex').copy(image);
    image.set(Buffer.from('8280', 'hex'), 0x28);
    return image;
  };
  const originalRows = r2Graph(
    [
      { addr: entry, size: 2, ninstr: 1, jump: entry + 4 },
      { addr: entry + 4, size: 6, ninstr: 2 },
    ],
    [cj, addi, cjal],
  );

  it('withholds the conflicting offset before the retry and recovers the corroborated BSET stop', () => {
    const image = inlineData();
    const views: Buffer[] = [];
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      (args) => {
        const input = args.at(-1) ?? '';
        if (args.at(-2)?.includes('s 0x10000018;')) return 'not json';
        if (input === '/synthetic.bin') return originalRows;
        const view = readFileSync(input);
        views.push(view);
        // The view must leave ADDI and the compressed call untouched and replace only the stop at 0x0a.
        if (view.subarray(0, 10).toString('hex') !== image.subarray(0, 10).toString('hex')) return originalRows;
        return r2Graph(
          [
            { addr: entry, size: 2, ninstr: 1, jump: entry + 4 },
            { addr: entry + 4, size: 12, ninstr: 4 },
          ],
          [
            cj,
            addi,
            cjal,
            { addr: entry + 10, size: 4, opcode: 'mv zero, ra', type: 'mov', bytes: '13800000' },
            { addr: entry + 14, size: 2, opcode: 'ret', type: 'ret', bytes: '8280' },
          ],
        );
      },
      image,
    );
    expect(views).toHaveLength(1);
    expect(views[0]?.subarray(10, 14).toString('hex')).toBe('13800000');
    expect(result).toMatchObject({
      decoderSubstitutionsTotal: 1,
      decoderSubstitutions: [{ address: entry + 10, candidateBasis: 'corroborated-boundary' }],
      decoderCandidateExclusionsTotal: 1,
      decoderCandidateExclusions: [
        { functionAddress: entry, fileOffset: 6, reason: 'known-instruction-overlap', conflictAddress: entry + 4 },
      ],
      functionsCompletedTotal: 1,
      callGraphTruncated: true,
    });
    expect(result?.instructions.find((op) => op.address === entry + 8)).toMatchObject({
      bytes: '0128',
      jump: entry + 0x18,
    });
    expect(result?.callEdges).toEqual([{ caller: entry, callsite: entry + 8, target: entry + 0x18 }]);
    expect(result?.decodeFailures?.map((row) => row.address)).toEqual([entry + 0x18]);
  });

  it('builds anchoring evidence only from source-consistent rows and reported boundaries', () => {
    const image = inlineData();
    const parsed = parsePicobinRadare2Output(originalRows, localMapping, image.length);
    expect(parsed).not.toBeNull();
    if (!parsed) return;
    expect(picobinDecoderSourceEvidence(parsed, localMapping, image)).toEqual({
      knownInstructions: [
        { address: entry, size: 2 },
        { address: entry + 4, size: 4 },
        { address: entry + 8, size: 2 },
      ],
      boundaries: [entry, entry + 2, entry + 4, entry + 10, entry + 0x18],
    });
    expect(picobinDecoderSourceEvidence(null, localMapping, image)).toEqual({
      knownInstructions: [],
      boundaries: [entry],
    });
    const contradicted = Buffer.from(image);
    contradicted.set([0x13, 0x06], 4); // the reported ADDI bytes no longer match the source
    expect(picobinDecoderSourceEvidence(parsed, localMapping, contradicted)).toBeNull();
  });

  it('does not retry when the only stop candidate is bisected by a reported branch target', () => {
    // beqz a0 -> 0x06 and fallthrough 0x04 claim instruction starts two bytes apart: the BSET-looking word at
    // 0x04 cannot be substituted without corrupting the branch target. Both stay incomplete.
    const image = Buffer.from('63030500b316a02867800000', 'hex');
    let attempts = 0;
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      () => {
        attempts++;
        return r2Graph(
          [{ addr: entry, size: 4, ninstr: 1, jump: entry + 6, fail: entry + 4 }],
          [{ addr: entry, size: 4, opcode: 'beqz a0, 0x10000006', type: 'cjmp', bytes: '63030500' }],
        );
      },
      image,
    );
    expect(attempts).toBe(1);
    expect(result).toMatchObject({
      decoderSubstitutionsTotal: 0,
      decoderCandidateExclusions: [{ fileOffset: 4, reason: 'known-boundary-bisected', conflictAddress: entry + 6 }],
      functionsCompletedTotal: 0,
      callGraphTruncated: true,
    });
    expect(result?.instructions).toHaveLength(1);
  });

  it('does not retry when a valid original row contradicts the source instruction width', () => {
    // Two C.NOP parcels reported as one four-byte instruction: no candidate view could preserve that row.
    const image = Buffer.from('01000100b316a02867800000', 'hex');
    let attempts = 0;
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      () => {
        attempts++;
        return r2Graph([{ addr: entry, size: 4, ninstr: 1 }], [{ ...addi, addr: entry, bytes: '01000100' }]);
      },
      image,
    );
    expect(attempts).toBe(1);
    expect(result).toMatchObject({
      decoderSubstitutionsTotal: 0,
      functionsCompletedTotal: 0,
      callGraphTruncated: true,
    });
    expect(result?.decoderCandidateExclusionsTotal).toBeUndefined();
    expect(result?.instructions).toEqual([expect.objectContaining({ address: entry, bytes: '01000100' })]);
  });

  it('still recovers an entry BSET with no source decode, anchored only at the declared entry', () => {
    const image = Buffer.from('b316a02867800000', 'hex');
    const result = runPicobinRiscvDisassembly(
      '/synthetic.bin',
      picobin,
      image.length,
      (args) =>
        args.at(-1) === '/synthetic.bin'
          ? 'not json'
          : r2Graph(
              [{ addr: entry, size: 8, ninstr: 2 }],
              [
                { addr: entry, size: 4, opcode: 'mv zero, ra', type: 'mov', bytes: '13800000' },
                { addr: entry + 4, size: 4, opcode: 'ret', type: 'ret', bytes: '67800000' },
              ],
            ),
      image,
    );
    expect(result).toMatchObject({
      decoderSubstitutions: [
        { address: entry, candidateBasis: 'corroborated-boundary', mnemonic: 'bset x13, x0, x10' },
      ],
      functionsCompletedTotal: 1,
    });
    expect(result?.decoderCandidateExclusionsTotal).toBeUndefined();
  });
});
