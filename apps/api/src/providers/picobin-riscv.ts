/**
 * Focused, tool-backed RISC-V entrypoint recovery for a structurally validated PICOBIN image.
 *
 * This deliberately starts at the declared entry function and follows only bounded direct calls. It does not run
 * whole-file auto-analysis (which can manufacture thousands of functions from data in a raw image), and it never
 * upgrades static disassembly into a runtime claim. The PICOBIN parser remains the authority for CPU, entrypoint
 * and mapping; radare2 only decodes explicitly selected, mapped functions.
 */
import { execFileSync } from 'node:child_process';
import {
  parseRiscvStartupCopyTable,
  type FindingDraft,
  type PicobinInfo,
  type RiscvStartupCopyTable,
} from '@firmlab/core';

const XIP_BASE = 0x1000_0000;
const XIP_END = 0x1100_0000;
const SPLIT = '__FIRMLAB_PICOBIN_RISCV_SPLIT__';
const BASIC_BLOCK_CAP = 128;
const INSTRUCTION_CAP = 256;
const REACHABLE_FUNCTION_CAP = 8;
const CALL_DEPTH_CAP = 4;
const CALL_EDGE_CAP = 32;

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
  bytes?: string;
  jump?: number;
  fail?: number;
}

export interface PicobinReachableFunction {
  address: number;
  depth: number;
  basicBlocksTotal: number;
  instructionsTotal: number;
}

export interface PicobinCallEdge {
  caller: number;
  callsite: number;
  target: number;
}

export interface PicobinRiscvDisassembly {
  attempted: boolean;
  available: boolean;
  tool: 'radare2';
  /** Historical results used entry-function-only; persisted provider output may retain that value forever. */
  scope: 'entry-function-only' | 'reachable-call-graph';
  reason: string;
  baseAddress: number | null;
  entryPoint: number | null;
  entryFileOffset: number | null;
  mappingKind?: PicobinMappingKind | null;
  mappedRuntimeStart?: number | null;
  mappedRuntimeEnd?: number | null;
  basicBlocksTotal?: number;
  instructionsTotal?: number;
  basicBlocks: PicobinBasicBlock[];
  instructions: PicobinInstruction[];
  reachableFunctions?: PicobinReachableFunction[];
  callEdges?: PicobinCallEdge[];
  outOfMapCalls?: PicobinCallEdge[];
  unresolvedCallsitesTotal?: number;
  outOfMapCallsitesTotal?: number;
  callGraphTruncated?: boolean;
  startupCopyTable?: RiscvStartupCopyTable | null;
  startupCopyTableAttempted?: boolean;
  findings: FindingDraft[];
}

export type PicobinMappingKind =
  | 'direct-xip'
  | 'rolling-xip'
  | 'relative-load-map'
  | 'absolute-load-map'
  | 'startup-copy';

export interface PicobinFlashMapping {
  baseAddress: number;
  entryPoint: number;
  entryFileOffset: number;
  mappingKind: PicobinMappingKind;
  mappedRuntimeStart: number;
  mappedRuntimeEnd: number;
}

type PicobinMappingInput = Pick<PicobinInfo, 'entryPoint' | 'rollingWindowDelta'> &
  Partial<Pick<PicobinInfo, 'loadMap'>>;

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
  bytes?: unknown;
  jump?: unknown;
  fail?: unknown;
}

interface R2Function {
  ops?: unknown;
}

interface ParsedPicobinFunction {
  basicBlocksTotal: number;
  instructionsTotal: number;
  basicBlocks: PicobinBasicBlock[];
  instructions: PicobinInstruction[];
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

function littleEndianWord(bytes: string | undefined): number | null {
  if (!bytes || !/^[0-9a-fA-F]{8}$/.test(bytes)) return null;
  const octets = bytes.match(/../g)?.map((octet) => Number.parseInt(octet, 16));
  if (!octets || octets.length !== 4) return null;
  return ((octets[0] ?? 0) | ((octets[1] ?? 0) << 8) | ((octets[2] ?? 0) << 16) | ((octets[3] ?? 0) << 24)) >>> 0;
}

/** Resolve the linker-generated AUIPC/JALR direct-call pair when radare2 leaves it typed as an unknown call. */
export function resolveRiscvPcRelativeCalls(instructions: PicobinInstruction[]): PicobinInstruction[] {
  return instructions.map((instruction, index) => {
    if (!instruction.type.includes('call') || instruction.jump !== undefined) return instruction;
    const previous = instructions[index - 1];
    if (!previous || previous.address + previous.size !== instruction.address) return instruction;
    const auipc = littleEndianWord(previous.bytes);
    const jalr = littleEndianWord(instruction.bytes);
    if (auipc === null || jalr === null || (auipc & 0x7f) !== 0x17 || (jalr & 0x7f) !== 0x67) {
      return instruction;
    }
    const auipcDestination = (auipc >>> 7) & 0x1f;
    const jalrSource = (jalr >>> 15) & 0x1f;
    const jalrFunction = (jalr >>> 12) & 0x7;
    if (auipcDestination === 0 || auipcDestination !== jalrSource || jalrFunction !== 0) return instruction;
    const pcRelativeBase = (previous.address + (auipc & 0xffff_f000)) >>> 0;
    const jalrImmediate = jalr >> 20;
    const jump = ((pcRelativeBase + jalrImmediate) & 0xffff_fffe) >>> 0;
    return { ...instruction, jump };
  });
}

function inMappedImage(address: number, size: number, mapping: PicobinFlashMapping, fileSize: number): boolean {
  const fileOffset = address - mapping.baseAddress;
  return (
    size > 0 &&
    address >= mapping.mappedRuntimeStart &&
    address + size <= mapping.mappedRuntimeEnd &&
    fileOffset >= 0 &&
    fileOffset + size <= fileSize
  );
}

export function picobinRuntimeMapping(
  address: number,
  size: number,
  primary: PicobinFlashMapping,
  startupCopyTable: RiscvStartupCopyTable | null,
  fileSize: number,
): PicobinFlashMapping | null {
  if (inMappedImage(address, size, primary, fileSize)) return functionMapping(primary, address);
  if (!startupCopyTable) return null;
  const matches = startupCopyTable.regions.filter(
    (region) =>
      address >= region.runtimeAddress && address + size <= region.runtimeAddress + region.size && region.size > 0,
  );
  if (matches.length !== 1) return null;
  const region = matches[0];
  if (!region) return null;
  const entryFileOffset = region.sourceFileOffset + (address - region.runtimeAddress);
  const baseAddress = region.runtimeAddress - region.sourceFileOffset;
  if (entryFileOffset < 0 || entryFileOffset + size > fileSize || baseAddress < 0) return null;
  return {
    baseAddress,
    entryPoint: address,
    entryFileOffset,
    mappingKind: 'startup-copy',
    mappedRuntimeStart: region.runtimeAddress,
    mappedRuntimeEnd: region.runtimeAddress + region.size,
  };
}

function resolvePicobinFlashMapping(
  picobin: PicobinMappingInput,
  fileSize: number,
): { mapping: PicobinFlashMapping | null; reason: string } {
  const entryPoint = picobin.entryPoint;
  if (entryPoint === null) return { mapping: null, reason: 'PICOBIN has no ENTRY_POINT item to decode' };
  const rollingDelta = picobin.rollingWindowDelta === null ? 0 : picobin.rollingWindowDelta | 0;
  if (picobin.rollingWindowDelta !== null && rollingDelta % 0x1000 !== 0) {
    return { mapping: null, reason: 'PICOBIN rolling-window delta is not flash-sector aligned' };
  }

  if (picobin.loadMap) {
    const matches = picobin.loadMap.entries.filter(
      (entry) => entryPoint >= entry.runtimeAddress && entryPoint < entry.runtimeAddress + entry.size,
    );
    if (matches.length === 0) {
      return { mapping: null, reason: 'PICOBIN entrypoint is not covered by its LOAD_MAP regions' };
    }
    if (matches.length > 1) {
      return { mapping: null, reason: 'PICOBIN entrypoint is covered by overlapping LOAD_MAP regions' };
    }
    const entry = matches[0];
    if (!entry || entry.storageAddress === 0) {
      return { mapping: null, reason: 'PICOBIN entrypoint lies in a zero-filled LOAD_MAP region' };
    }

    let sourceFileOffset: number;
    let mappingKind: PicobinMappingKind;
    if (picobin.loadMap.relative) {
      sourceFileOffset = picobin.loadMap.itemOffset + (entry.storageAddress | 0);
      mappingKind = 'relative-load-map';
    } else {
      if (entry.storageAddress < XIP_BASE || entry.storageAddress >= XIP_END) {
        return { mapping: null, reason: 'PICOBIN absolute LOAD_MAP source is outside flash-backed XIP storage' };
      }
      sourceFileOffset = entry.storageAddress - XIP_BASE + rollingDelta;
      mappingKind = 'absolute-load-map';
    }

    const entryFileOffset = sourceFileOffset + (entryPoint - entry.runtimeAddress);
    const baseAddress = entry.runtimeAddress - sourceFileOffset;
    if (
      !Number.isSafeInteger(sourceFileOffset) ||
      !Number.isSafeInteger(baseAddress) ||
      baseAddress < 0 ||
      sourceFileOffset < 0 ||
      sourceFileOffset + entry.size > fileSize ||
      entryFileOffset < 0 ||
      entryFileOffset >= fileSize
    ) {
      return { mapping: null, reason: `PICOBIN LOAD_MAP source lies beyond the ${fileSize}-byte image` };
    }
    return {
      mapping: {
        baseAddress,
        entryPoint,
        entryFileOffset,
        mappingKind,
        mappedRuntimeStart: entry.runtimeAddress,
        mappedRuntimeEnd: entry.runtimeAddress + entry.size,
      },
      reason: '',
    };
  }

  if (entryPoint < XIP_BASE || entryPoint >= XIP_END) {
    return { mapping: null, reason: 'PICOBIN entrypoint is outside the RP2350 XIP window and no LOAD_MAP resolves it' };
  }
  const entryFileOffset = entryPoint - XIP_BASE + rollingDelta;
  if (entryFileOffset < 0 || entryFileOffset >= fileSize) {
    return { mapping: null, reason: `PICOBIN entrypoint maps beyond the ${fileSize}-byte image` };
  }
  const baseAddress = XIP_BASE - rollingDelta;
  return {
    mapping: {
      baseAddress,
      entryPoint,
      entryFileOffset,
      mappingKind: rollingDelta === 0 ? 'direct-xip' : 'rolling-xip',
      mappedRuntimeStart: baseAddress,
      mappedRuntimeEnd: baseAddress + fileSize,
    },
    reason: '',
  };
}

export function picobinFlashMapping(picobin: PicobinMappingInput, fileSize: number): PicobinFlashMapping | null {
  return resolvePicobinFlashMapping(picobin, fileSize).mapping;
}

export function parsePicobinRadare2Output(
  stdout: string,
  mapping: PicobinFlashMapping,
  fileSize: number,
): ParsedPicobinFunction | null {
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
      !inMappedImage(address, size, mapping, fileSize)
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
      !inMappedImage(address, size, mapping, fileSize)
    ) {
      return null;
    }
    const bytes =
      typeof raw.bytes === 'string' && /^[0-9a-fA-F]+$/.test(raw.bytes) ? raw.bytes.toLowerCase() : undefined;
    const jump = optionalAddress(raw.jump);
    const fail = optionalAddress(raw.fail);
    instructions.push({
      address,
      size,
      opcode: raw.opcode,
      type: raw.type,
      ...(bytes !== undefined ? { bytes } : {}),
      ...(jump !== undefined ? { jump } : {}),
      ...(fail !== undefined ? { fail } : {}),
    });
  }

  const resolvedInstructions = resolveRiscvPcRelativeCalls(instructions);
  if (
    basicBlocks.length === 0 ||
    resolvedInstructions.length === 0 ||
    !resolvedInstructions.some((instruction) => instruction.address === mapping.entryPoint)
  ) {
    return null;
  }
  return {
    basicBlocksTotal: rawBlocks.length,
    instructionsTotal: rawFunction.ops.length,
    basicBlocks,
    instructions: resolvedInstructions,
  };
}

function unavailable(mapping: PicobinFlashMapping, reason: string): PicobinRiscvDisassembly {
  return {
    attempted: true,
    available: false,
    tool: 'radare2',
    scope: 'reachable-call-graph',
    reason,
    ...mapping,
    basicBlocks: [],
    instructions: [],
    findings: [],
  };
}

function unmapped(picobin: PicobinMappingInput, reason: string): PicobinRiscvDisassembly {
  return {
    attempted: false,
    available: false,
    tool: 'radare2',
    scope: 'reachable-call-graph',
    reason,
    baseAddress: null,
    entryPoint: picobin.entryPoint,
    entryFileOffset: null,
    mappingKind: null,
    mappedRuntimeStart: null,
    mappedRuntimeEnd: null,
    basicBlocks: [],
    instructions: [],
    findings: [],
  };
}

function radareFailureReason(err: unknown): string {
  const code = err && typeof err === 'object' && 'code' in err ? String(err.code) : '';
  return code === 'ENOENT'
    ? 'radare2 is not installed'
    : `radare2 failed: ${err instanceof Error ? err.message : String(err)}`;
}

function functionMapping(mapping: PicobinFlashMapping, address: number): PicobinFlashMapping {
  return { ...mapping, entryPoint: address, entryFileOffset: address - mapping.baseAddress };
}

function decodeFunction(
  imagePath: string,
  mapping: PicobinFlashMapping,
  fileSize: number,
  execute: Radare2Executor,
): ParsedPicobinFunction | null {
  const entryHex = `0x${mapping.entryPoint.toString(16)}`;
  const baseHex = `0x${mapping.baseAddress.toString(16)}`;
  const name = `firmlab_${mapping.entryPoint.toString(16)}`;
  const script = `e anal.bb.maxsize=4096;s ${entryHex};af ${name};afbj @ ${entryHex};?e ${SPLIT};pdfj @ ${entryHex}`;
  const stdout = execute(['-q', '-2', '-a', 'riscv', '-b', '32', '-m', baseHex, '-c', script, imagePath]);
  return parsePicobinRadare2Output(stdout, mapping, fileSize);
}

export function runPicobinRiscvDisassembly(
  imagePath: string,
  picobin: Pick<PicobinInfo, 'cpuMode' | 'isExecutable' | 'entryPoint' | 'rollingWindowDelta'> &
    Partial<Pick<PicobinInfo, 'loadMap'>>,
  fileSize: number,
  execute: Radare2Executor = defaultRadare2Executor,
  imageBytes?: Uint8Array,
): PicobinRiscvDisassembly | null {
  if (picobin.cpuMode !== 'riscv' || !picobin.isExecutable) return null;
  const resolved = resolvePicobinFlashMapping(picobin, fileSize);
  const mapping = resolved.mapping;
  if (!mapping) return unmapped(picobin, resolved.reason);

  const baseHex = `0x${mapping.baseAddress.toString(16)}`;
  const entryHex = `0x${mapping.entryPoint.toString(16)}`;
  let parsed: ParsedPicobinFunction | null;
  try {
    parsed = decodeFunction(imagePath, mapping, fileSize, execute);
  } catch (err) {
    return unavailable(mapping, radareFailureReason(err));
  }
  if (!parsed) return unavailable(mapping, 'radare2 output was missing, malformed or outside the mapped image');

  const startupCopyTable = imageBytes
    ? parseRiscvStartupCopyTable(imageBytes, mapping.entryPoint, mapping.entryFileOffset, mapping.baseAddress)
    : null;

  const reachableFunctions: PicobinReachableFunction[] = [
    {
      address: mapping.entryPoint,
      depth: 0,
      basicBlocksTotal: parsed.basicBlocksTotal,
      instructionsTotal: parsed.instructionsTotal,
    },
  ];
  const callEdges: PicobinCallEdge[] = [];
  const outOfMapCalls: PicobinCallEdge[] = [];
  const queued = new Set<number>([mapping.entryPoint]);
  const queue: { address: number; depth: number; mapping: PicobinFlashMapping }[] = [];
  let unresolvedCallsitesTotal = 0;
  let outOfMapCallsitesTotal = 0;
  let callGraphTruncated =
    parsed.basicBlocks.length !== parsed.basicBlocksTotal || parsed.instructions.length !== parsed.instructionsTotal;
  let graphStopReason = '';

  const enqueueCalls = (caller: number, depth: number, instructions: PicobinInstruction[]): void => {
    for (const instruction of instructions) {
      if (!instruction.type.includes('call')) continue;
      if (instruction.jump === undefined) {
        unresolvedCallsitesTotal++;
        continue;
      }
      const targetMapping = picobinRuntimeMapping(instruction.jump, 2, mapping, startupCopyTable, fileSize);
      if (!targetMapping) {
        outOfMapCallsitesTotal++;
        if (outOfMapCalls.length < CALL_EDGE_CAP) {
          outOfMapCalls.push({ caller, callsite: instruction.address, target: instruction.jump });
        } else {
          callGraphTruncated = true;
        }
        continue;
      }
      if (callEdges.length >= CALL_EDGE_CAP) {
        callGraphTruncated = true;
        continue;
      }
      callEdges.push({ caller, callsite: instruction.address, target: instruction.jump });
      if (queued.has(instruction.jump)) continue;
      if (depth >= CALL_DEPTH_CAP || queued.size >= REACHABLE_FUNCTION_CAP) {
        callGraphTruncated = true;
        continue;
      }
      queued.add(instruction.jump);
      queue.push({ address: instruction.jump, depth: depth + 1, mapping: targetMapping });
    }
  };

  enqueueCalls(mapping.entryPoint, 0, parsed.instructions);
  while (queue.length > 0 && reachableFunctions.length < REACHABLE_FUNCTION_CAP) {
    const next = queue.shift();
    if (!next) break;
    const nextMapping = functionMapping(next.mapping, next.address);
    let decoded: ParsedPicobinFunction | null;
    try {
      decoded = decodeFunction(imagePath, nextMapping, fileSize, execute);
    } catch (err) {
      callGraphTruncated = true;
      graphStopReason = radareFailureReason(err);
      break;
    }
    if (!decoded) {
      callGraphTruncated = true;
      graphStopReason = `radare2 could not decode the reachable target 0x${next.address.toString(16)}`;
      break;
    }
    reachableFunctions.push({
      address: next.address,
      depth: next.depth,
      basicBlocksTotal: decoded.basicBlocksTotal,
      instructionsTotal: decoded.instructionsTotal,
    });
    if (
      decoded.basicBlocks.length !== decoded.basicBlocksTotal ||
      decoded.instructions.length !== decoded.instructionsTotal
    ) {
      callGraphTruncated = true;
    }
    enqueueCalls(next.address, next.depth, decoded.instructions);
  }

  const reason =
    `Decoded a bounded RISC-V call graph from the declared entrypoint: ${reachableFunctions.length} function(s), ` +
    `${callEdges.length} followed direct edge(s), ${outOfMapCallsitesTotal} resolved target(s) outside mapped bytes, ` +
    `${unresolvedCallsitesTotal} unresolved/indirect callsite(s)` +
    `${callGraphTruncated ? `; coverage truncated${graphStopReason ? ` (${graphStopReason})` : ' by configured limits'}` : ''}.`;
  const finding: FindingDraft = {
    kind: 'rtos-picobin-entry-cfg',
    title: `RISC-V PICOBIN entry graph decoded: ${reachableFunctions.length} reachable function(s), ${callEdges.length} direct edge(s)`,
    severity: 'info',
    proofState: 'static_confirmed',
    evidence: {
      tool: 'radare2',
      scope: 'reachable-call-graph',
      functionCap: REACHABLE_FUNCTION_CAP,
      callDepthCap: CALL_DEPTH_CAP,
      callEdgeCap: CALL_EDGE_CAP,
      baseAddress: baseHex,
      entryPoint: entryHex,
      entryFileOffset: mapping.entryFileOffset,
      mappingKind: mapping.mappingKind,
      mappedRuntimeStart: `0x${mapping.mappedRuntimeStart.toString(16)}`,
      mappedRuntimeEnd: `0x${mapping.mappedRuntimeEnd.toString(16)}`,
      basicBlocksTotal: parsed.basicBlocksTotal,
      basicBlocksListed: parsed.basicBlocks.length,
      instructionsTotal: parsed.instructionsTotal,
      instructionsListed: parsed.instructions.length,
      reachableFunctions: reachableFunctions.length,
      directCallEdges: callEdges.length,
      outOfMapCallsListed: outOfMapCalls.length,
      unresolvedCallsitesTotal,
      outOfMapCallsitesTotal,
      callGraphTruncated,
      startupCopyRegions: startupCopyTable?.regions.length ?? 0,
    },
    rationale:
      'radare2 decoded instructions and local control-flow blocks from the entrypoint declared by a structurally ' +
      'validated PICOBIN image, then followed only direct call targets under explicit function/depth/edge caps. ' +
      'This is bounded static decoder evidence; it does not prove execution, resolve indirect calls, establish ' +
      'whole-image function coverage or demonstrate peripheral behavior.',
  };
  return {
    attempted: true,
    available: true,
    tool: 'radare2',
    scope: 'reachable-call-graph',
    reason,
    ...mapping,
    ...parsed,
    reachableFunctions,
    callEdges,
    outOfMapCalls,
    unresolvedCallsitesTotal,
    outOfMapCallsitesTotal,
    callGraphTruncated,
    startupCopyTable,
    startupCopyTableAttempted: imageBytes !== undefined,
    findings: [finding],
  };
}
