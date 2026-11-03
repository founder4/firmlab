/**
 * Focused, tool-backed RISC-V entrypoint recovery for a structurally validated PICOBIN image.
 *
 * This deliberately analyzes one declared entry function. It does not run whole-file auto-analysis (which can
 * manufacture thousands of functions from data in a raw image), and it never upgrades static disassembly into a
 * runtime claim. The PICOBIN parser remains the authority for CPU, entrypoint and block structure; radare2 only
 * decodes the mapped bytes and recovers the entry function's local control-flow graph.
 */
import { execFileSync } from 'node:child_process';
import type { FindingDraft, PicobinInfo } from '@firmlab/core';

const XIP_BASE = 0x1000_0000;
const XIP_END = 0x1200_0000;
const SPLIT = '__FIRMLAB_PICOBIN_RISCV_SPLIT__';
const BASIC_BLOCK_CAP = 128;
const INSTRUCTION_CAP = 256;

export interface PicobinBasicBlock {
  address: number;
  size: number;
  instructionCount: number;
  jump?: number;
  fail?: number;
}

export interface PicobinInstruction {
  address: number;
  size: number;
  opcode: string;
  type: string;
  jump?: number;
  fail?: number;
}

export interface PicobinRiscvDisassembly {
  attempted: boolean;
  available: boolean;
  tool: 'radare2';
  scope: 'entry-function-only';
  reason: string;
  baseAddress: number | null;
  entryPoint: number | null;
  entryFileOffset: number | null;
  basicBlocksTotal?: number;
  instructionsTotal?: number;
  basicBlocks: PicobinBasicBlock[];
  instructions: PicobinInstruction[];
  findings: FindingDraft[];
}

interface R2Block {
  addr?: unknown;
  size?: unknown;
  ninstr?: unknown;
  jump?: unknown;
  fail?: unknown;
}

interface R2Instruction {
  addr?: unknown;
  size?: unknown;
  opcode?: unknown;
  type?: unknown;
  jump?: unknown;
  fail?: unknown;
}

interface R2Function {
  ops?: unknown;
}

export type Radare2Executor = (args: string[]) => string;

function defaultRadare2Executor(args: string[]): string {
  return execFileSync('radare2', args, {
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 8 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function finiteInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) ? value : null;
}

function parseArrayBlock<T>(text: string): T[] | null {
  const start = text.indexOf('[');
  const end = text.lastIndexOf(']');
  if (start < 0 || end < start) return null;
  try {
    const parsed: unknown = JSON.parse(text.slice(start, end + 1));
    return Array.isArray(parsed) ? (parsed as T[]) : null;
  } catch {
    return null;
  }
}

function parseObjectBlock<T>(text: string): T | null {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start < 0 || end < start) return null;
  try {
    const parsed: unknown = JSON.parse(text.slice(start, end + 1));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as T) : null;
  } catch {
    return null;
  }
}

function optionalAddress(value: unknown): number | undefined {
  const parsed = finiteInteger(value);
  return parsed === null || parsed < 0 ? undefined : parsed;
}

function inMappedImage(address: number, size: number, baseAddress: number, fileSize: number): boolean {
  return address >= baseAddress && size > 0 && address + size <= baseAddress + fileSize;
}

export function picobinFlashMapping(
  picobin: Pick<PicobinInfo, 'entryPoint' | 'rollingWindowDelta'>,
  fileSize: number,
): { baseAddress: number; entryPoint: number; entryFileOffset: number } | null {
  const entryPoint = picobin.entryPoint;
  // A rolling delta means the runtime and stored XIP windows differ. Until the load/roll relation is parsed, do
  // not guess a file offset from the runtime entrypoint.
  if (entryPoint === null || picobin.rollingWindowDelta !== null) return null;
  if (entryPoint < XIP_BASE || entryPoint >= XIP_END) return null;
  const entryFileOffset = entryPoint - XIP_BASE;
  if (entryFileOffset < 0 || entryFileOffset >= fileSize) return null;
  return { baseAddress: XIP_BASE, entryPoint, entryFileOffset };
}

export function parsePicobinRadare2Output(
  stdout: string,
  mapping: { baseAddress: number; entryPoint: number; entryFileOffset: number },
  fileSize: number,
): Pick<PicobinRiscvDisassembly, 'basicBlocksTotal' | 'instructionsTotal' | 'basicBlocks' | 'instructions'> | null {
  const [blocksText, functionText] = stdout.split(SPLIT);
  if (blocksText === undefined || functionText === undefined) return null;
  const rawBlocks = parseArrayBlock<R2Block>(blocksText);
  const rawFunction = parseObjectBlock<R2Function>(functionText);
  if (!rawBlocks || !rawFunction || !Array.isArray(rawFunction.ops)) return null;

  const basicBlocks: PicobinBasicBlock[] = [];
  for (const raw of rawBlocks.slice(0, BASIC_BLOCK_CAP)) {
    const address = finiteInteger(raw.addr);
    const size = finiteInteger(raw.size);
    const instructionCount = finiteInteger(raw.ninstr);
    if (
      address === null ||
      size === null ||
      instructionCount === null ||
      instructionCount < 0 ||
      !inMappedImage(address, size, mapping.baseAddress, fileSize)
    ) {
      return null;
    }
    const jump = optionalAddress(raw.jump);
    const fail = optionalAddress(raw.fail);
    basicBlocks.push({
      address,
      size,
      instructionCount,
      ...(jump !== undefined ? { jump } : {}),
      ...(fail !== undefined ? { fail } : {}),
    });
  }

  const instructions: PicobinInstruction[] = [];
  for (const raw of (rawFunction.ops as R2Instruction[]).slice(0, INSTRUCTION_CAP)) {
    const address = finiteInteger(raw.addr);
    const size = finiteInteger(raw.size);
    if (
      address === null ||
      size === null ||
      typeof raw.opcode !== 'string' ||
      typeof raw.type !== 'string' ||
      !inMappedImage(address, size, mapping.baseAddress, fileSize)
    ) {
      return null;
    }
    const jump = optionalAddress(raw.jump);
    const fail = optionalAddress(raw.fail);
    instructions.push({
      address,
      size,
      opcode: raw.opcode,
      type: raw.type,
      ...(jump !== undefined ? { jump } : {}),
      ...(fail !== undefined ? { fail } : {}),
    });
  }

  if (basicBlocks.length === 0 || instructions.length === 0 || instructions[0]?.address !== mapping.entryPoint) {
    return null;
  }
  return {
    basicBlocksTotal: rawBlocks.length,
    instructionsTotal: rawFunction.ops.length,
    basicBlocks,
    instructions,
  };
}

function unavailable(
  mapping: { baseAddress: number; entryPoint: number; entryFileOffset: number },
  reason: string,
): PicobinRiscvDisassembly {
  return {
    attempted: true,
    available: false,
    tool: 'radare2',
    scope: 'entry-function-only',
    reason,
    ...mapping,
    basicBlocks: [],
    instructions: [],
    findings: [],
  };
}

function unmapped(
  picobin: Pick<PicobinInfo, 'entryPoint' | 'rollingWindowDelta'>,
  fileSize: number,
): PicobinRiscvDisassembly {
  const reason =
    picobin.entryPoint === null
      ? 'PICOBIN has no ENTRY_POINT item to decode'
      : picobin.rollingWindowDelta !== null
        ? 'PICOBIN uses a rolling XIP window whose runtime-to-file mapping is not yet resolved'
        : picobin.entryPoint < XIP_BASE || picobin.entryPoint >= XIP_END
          ? 'PICOBIN entrypoint is outside the directly mapped RP2350 XIP window'
          : `PICOBIN entrypoint maps beyond the ${fileSize}-byte image`;
  return {
    attempted: false,
    available: false,
    tool: 'radare2',
    scope: 'entry-function-only',
    reason,
    baseAddress: null,
    entryPoint: picobin.entryPoint,
    entryFileOffset: null,
    basicBlocks: [],
    instructions: [],
    findings: [],
  };
}

export function runPicobinRiscvDisassembly(
  imagePath: string,
  picobin: Pick<PicobinInfo, 'cpuMode' | 'isExecutable' | 'entryPoint' | 'rollingWindowDelta'>,
  fileSize: number,
  execute: Radare2Executor = defaultRadare2Executor,
): PicobinRiscvDisassembly | null {
  if (picobin.cpuMode !== 'riscv' || !picobin.isExecutable) return null;
  const mapping = picobinFlashMapping(picobin, fileSize);
  if (!mapping) return unmapped(picobin, fileSize);

  const entryHex = `0x${mapping.entryPoint.toString(16)}`;
  const baseHex = `0x${mapping.baseAddress.toString(16)}`;
  const script = `s ${entryHex};af entry0;afbj @ ${entryHex};?e ${SPLIT};pdfj @ ${entryHex}`;
  let stdout: string;
  try {
    stdout = execute(['-q', '-2', '-a', 'riscv', '-b', '32', '-m', baseHex, '-c', script, imagePath]);
  } catch (err) {
    const code = err && typeof err === 'object' && 'code' in err ? String(err.code) : '';
    const reason =
      code === 'ENOENT'
        ? 'radare2 is not installed'
        : `radare2 failed: ${err instanceof Error ? err.message : String(err)}`;
    return unavailable(mapping, reason);
  }

  const parsed = parsePicobinRadare2Output(stdout, mapping, fileSize);
  if (!parsed) return unavailable(mapping, 'radare2 output was missing, malformed or outside the mapped image');
  const complete =
    parsed.basicBlocks.length === parsed.basicBlocksTotal && parsed.instructions.length === parsed.instructionsTotal;
  const reason = `Decoded the declared RISC-V entry function: ${parsed.instructionsTotal} instruction(s), ${parsed.basicBlocksTotal} basic block(s)${complete ? '' : ' (stored lists capped)'}.`;
  const finding: FindingDraft = {
    kind: 'rtos-picobin-entry-cfg',
    title: `RISC-V PICOBIN entrypoint decoded: ${parsed.instructionsTotal} instructions across ${parsed.basicBlocksTotal} basic blocks`,
    severity: 'info',
    proofState: 'static_confirmed',
    evidence: {
      tool: 'radare2',
      scope: 'entry-function-only',
      baseAddress: baseHex,
      entryPoint: entryHex,
      entryFileOffset: mapping.entryFileOffset,
      basicBlocksTotal: parsed.basicBlocksTotal,
      basicBlocksListed: parsed.basicBlocks.length,
      instructionsTotal: parsed.instructionsTotal,
      instructionsListed: parsed.instructions.length,
    },
    rationale:
      'radare2 decoded instructions and local control-flow blocks from the entrypoint declared by a structurally ' +
      'validated PICOBIN image. This is bounded static decoder evidence for one function; it does not prove ' +
      'execution, whole-image function coverage or peripheral behavior.',
  };
  return {
    attempted: true,
    available: true,
    tool: 'radare2',
    scope: 'entry-function-only',
    reason,
    ...mapping,
    ...parsed,
    findings: [finding],
  };
}
