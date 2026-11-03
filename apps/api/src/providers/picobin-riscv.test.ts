import { describe, expect, it } from 'vitest';
import { parsePicobinRadare2Output, picobinFlashMapping, runPicobinRiscvDisassembly } from './picobin-riscv.js';

const ENTRY = 0x1000_0036;
const FILE_SIZE = 0x1000;
const mapping = { baseAddress: 0x1000_0000, entryPoint: ENTRY, entryFileOffset: 0x36 };

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

describe('picobinFlashMapping', () => {
  it('maps an RP2350 XIP entrypoint to its raw flash offset', () => {
    expect(picobinFlashMapping({ entryPoint: ENTRY, rollingWindowDelta: null }, FILE_SIZE)).toEqual(mapping);
  });

  it('refuses RAM/out-of-range entries and unresolved rolling windows', () => {
    expect(picobinFlashMapping({ entryPoint: 0x2000_0036, rollingWindowDelta: null }, FILE_SIZE)).toBeNull();
    expect(picobinFlashMapping({ entryPoint: 0x1000_2000, rollingWindowDelta: null }, FILE_SIZE)).toBeNull();
    expect(picobinFlashMapping({ entryPoint: ENTRY, rollingWindowDelta: 0x1000 }, FILE_SIZE)).toBeNull();
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
      expect.stringContaining('s 0x10000036;af entry0;'),
      '/firmware/pico.bin',
    ]);
    expect(result).toMatchObject({ available: true, scope: 'entry-function-only', instructionsTotal: 3 });
    expect(result?.findings[0]).toMatchObject({ kind: 'rtos-picobin-entry-cfg', proofState: 'static_confirmed' });
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
      { ...picobin, rollingWindowDelta: 0x1000 },
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
    expect(result?.reason).toMatch(/rolling XIP window/);
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
