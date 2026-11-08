/**
 * Focused, tool-backed RISC-V entrypoint recovery for a structurally validated PICOBIN image.
 *
 * This deliberately starts at the declared entry function and follows only bounded direct calls. It does not run
 * whole-file auto-analysis (which can manufacture thousands of functions from data in a raw image), and it never
 * upgrades static disassembly into a runtime claim. The PICOBIN parser remains the authority for CPU, entrypoint
 * and mapping; radare2 only decodes explicitly selected, mapped functions.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  type FindingDraft,
  type PicobinInfo,
  type RiscvStartupCopyTable,
  parseRiscvStartupCopyTable,
} from '@firmlab/core';
import {
  type PicobinDecoderCandidateExclusion,
  type PicobinDecoderSourceEvidence,
  type PicobinDecoderSubstitution,
  type PicobinDecoderView,
  buildPicobinRiscvDecoderView,
  restoredPicobinOpcode,
  selectPicobinDecoderCandidates,
} from './picobin-riscv-decoder-view.js';

const XIP_BASE = 0x1000_0000;
const XIP_END = 0x1100_0000;
const SPLIT = '__FIRMLAB_PICOBIN_RISCV_SPLIT__';
const BASIC_BLOCK_CAP = 128;
const INSTRUCTION_CAP = 256;
const REACHABLE_FUNCTION_CAP = 8;
// Failed targets consume the same finite admission budget as successful functions.
const FUNCTION_ATTEMPT_CAP = 8;
// Each target gets at most one original decode and one bounded decoder-view retry.
const DECODER_ATTEMPT_CAP = FUNCTION_ATTEMPT_CAP * 2;
const CALL_DEPTH_CAP = 4;
const CALL_EDGE_CAP = 32;
const DECODE_FAILURE_CAP = 16;
const DECODER_SUBSTITUTION_EVIDENCE_CAP = 64;

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

export interface PicobinDecodeFailure {
  address: number;
  fileOffset: number;
  classification: 'unsupported-instruction' | 'tool-error' | 'incomplete-decode';
  reason: string;
  /** At most the first eight mapped bytes, for bounded reproducibility. */
  bytesHex?: string;
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
  /** Bounded continuation addresses seen only in omitted tool rows; never listed instruction evidence. */
  instructionDisplayOmissions?: number[];
  basicBlocks: PicobinBasicBlock[];
  instructions: PicobinInstruction[];
  reachableFunctions?: PicobinReachableFunction[];
  callEdges?: PicobinCallEdge[];
  outOfMapCalls?: PicobinCallEdge[];
  unresolvedCallsitesTotal?: number;
  outOfMapCallsitesTotal?: number;
  callGraphTruncated?: boolean;
  /** Scheduler accounting is optional forever for older persisted output. Queued includes the entry. */
  functionTargetsQueuedTotal?: number;
  functionsAttemptedTotal?: number;
  functionsDecodedTotal?: number;
  functionsCompletedTotal?: number;
  functionTargetsPendingTotal?: number;
  decoderAttemptsTotal?: number;
  functionAttemptCap?: number;
  decoderAttemptCap?: number;
  droppedFunctionTargetsTotal?: number;
  callEdgesTotal?: number;
  droppedCallEdgesTotal?: number;
  droppedOutOfMapCallEdgesTotal?: number;
  callEdgeSelection?: string;
  functionTargetSelection?: string;
  graphStopReasons?: PicobinGraphStopReason[];
  decodeFailuresTotal?: number;
  decodeFailures?: PicobinDecodeFailure[];
  /** Exact non-control-flow instructions replaced only in a temporary decoder view; optional for persisted data. */
  decoderSubstitutionsTotal?: number;
  decoderSubstitutions?: PicobinDecoderSubstitution[];
  /**
   * Linear-scan proposals withheld from the temporary view before any retry, optional forever. Proved conflicts
   * with source decoder output are labelled separately from merely unanchored phase; neither is a code/data proof.
   */
  decoderCandidateExclusionsTotal?: number;
  decoderCandidateExclusions?: PicobinDecoderCandidateExclusion[];
  startupCopyTable?: RiscvStartupCopyTable | null;
  startupCopyTableAttempted?: boolean;
  /** Actual supplied source prefix, bounded by declared file size; optional forever. */
  sourceBytesAvailable?: number;
  sourceBytesDeclared?: number;
  decoderRecoveryUnavailableReason?: string;
  findings: FindingDraft[];
}

export type PicobinGraphStopReason =
  | 'function-attempt-cap'
  | 'call-depth-cap'
  | 'call-edge-display-cap'
  | 'out-of-map-display-cap'
  | 'basic-block-cap'
  | 'instruction-cap'
  | 'incomplete-decode'
  | 'out-of-map-continuation'
  | 'unresolved-continuation'
  | 'inconsistent-decode'
  | 'unparsed-output'
  | 'tool-error';

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
  instructionDisplayOmissions?: number[];
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
    Number.isSafeInteger(address) &&
    Number.isSafeInteger(size) &&
    size > 0 &&
    address >= mapping.mappedRuntimeStart &&
    address + size <= mapping.mappedRuntimeEnd &&
    fileOffset >= 0 &&
    fileOffset + size <= fileSize
  );
}

function spansOverlap(start: number, size: number, otherStart: number, otherSize: number): boolean {
  return size > 0 && otherSize > 0 && start < otherStart + otherSize && otherStart < start + size;
}

export function picobinRuntimeMapping(
  address: number,
  size: number,
  primary: PicobinFlashMapping,
  startupCopyTable: RiscvStartupCopyTable | null,
  fileSize: number,
): PicobinFlashMapping | null {
  if (!Number.isSafeInteger(address) || address % 2 !== 0 || !Number.isSafeInteger(size) || size < 2) return null;
  const regions = startupCopyTable?.regions ?? [];
  if (inMappedImage(address, size, primary, fileSize)) {
    // A secondary destination overlapping anywhere in the selected primary span is ambiguous too.
    if (
      regions.some((region) =>
        spansOverlap(
          primary.mappedRuntimeStart,
          primary.mappedRuntimeEnd - primary.mappedRuntimeStart,
          region.runtimeAddress,
          region.size,
        ),
      )
    )
      return null;
    return functionMapping(primary, address);
  }
  const matches = regions.filter(
    (region) =>
      address >= region.runtimeAddress && address + size <= region.runtimeAddress + region.size && region.size > 0,
  );
  if (matches.length !== 1) return null;
  const region = matches[0];
  if (
    !region ||
    !Number.isSafeInteger(region.runtimeAddress) ||
    !Number.isSafeInteger(region.size) ||
    region.runtimeAddress < 0 ||
    region.runtimeAddress + region.size > 0x1_0000_0000 ||
    regions.some(
      (other) => other !== region && spansOverlap(region.runtimeAddress, region.size, other.runtimeAddress, other.size),
    ) ||
    spansOverlap(
      region.runtimeAddress,
      region.size,
      primary.mappedRuntimeStart,
      primary.mappedRuntimeEnd - primary.mappedRuntimeStart,
    ) ||
    region.sourceFileOffset !== region.sourceAddress - primary.baseAddress ||
    !inMappedImage(region.sourceAddress, region.size, primary, fileSize)
  )
    return null;
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
  if (
    !Number.isSafeInteger(entryPoint) ||
    entryPoint < 0 ||
    entryPoint > 0xffff_ffff ||
    entryPoint % 2 !== 0 ||
    !Number.isSafeInteger(fileSize) ||
    fileSize < 2
  ) {
    return { mapping: null, reason: 'PICOBIN requires an aligned entrypoint and at least two mapped bytes' };
  }
  const rawDelta = picobin.rollingWindowDelta ?? 0;
  if (!Number.isSafeInteger(rawDelta) || rawDelta < -0x8000_0000 || rawDelta > 0xffff_ffff) {
    return { mapping: null, reason: 'PICOBIN rolling-window delta is not a signed or stored unsigned 32-bit word' };
  }
  const rollingDelta = rawDelta | 0;
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
    if (
      entry &&
      (!Number.isSafeInteger(entry.runtimeAddress) ||
        !Number.isSafeInteger(entry.size) ||
        entry.runtimeAddress < 0 ||
        entry.size < 2 ||
        entry.runtimeAddress + entry.size > 0x1_0000_0000 ||
        entryPoint + 2 > entry.runtimeAddress + entry.size ||
        picobin.loadMap.entries.some(
          (other) =>
            other !== entry && spansOverlap(entry.runtimeAddress, entry.size, other.runtimeAddress, other.size),
        ))
    ) {
      return {
        mapping: null,
        reason: 'PICOBIN selected LOAD_MAP region is invalid or overlaps another runtime region',
      };
    }
    if (!entry || entry.storageAddress === 0) {
      return { mapping: null, reason: 'PICOBIN entrypoint lies in a zero-filled LOAD_MAP region' };
    }

    if (
      !Number.isSafeInteger(entry.storageAddress) ||
      entry.storageAddress < -0x8000_0000 ||
      entry.storageAddress > 0xffff_ffff ||
      !Number.isSafeInteger(picobin.loadMap.itemOffset) ||
      picobin.loadMap.itemOffset < 0
    ) {
      return { mapping: null, reason: 'PICOBIN LOAD_MAP storage coordinates are invalid' };
    }
    let sourceFileOffset: number;
    let mappingKind: PicobinMappingKind;
    if (picobin.loadMap.relative) {
      sourceFileOffset = picobin.loadMap.itemOffset + (entry.storageAddress | 0);
      mappingKind = 'relative-load-map';
    } else {
      if (entry.storageAddress < XIP_BASE || entry.storageAddress + entry.size > XIP_END) {
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
      entryFileOffset + 2 > fileSize
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
  if (entryFileOffset < 0 || entryFileOffset + 2 > fileSize || entryPoint + 2 > XIP_END) {
    return { mapping: null, reason: `PICOBIN entrypoint maps beyond the ${fileSize}-byte image` };
  }
  const baseAddress = XIP_BASE - rollingDelta;
  if (baseAddress < 0) return { mapping: null, reason: 'PICOBIN rolling mapping has a negative affine base' };
  return {
    mapping: {
      baseAddress,
      entryPoint,
      entryFileOffset,
      mappingKind: rollingDelta === 0 ? 'direct-xip' : 'rolling-xip',
      mappedRuntimeStart: Math.max(XIP_BASE, baseAddress),
      mappedRuntimeEnd: Math.min(XIP_END, baseAddress + fileSize),
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

  // Retain only membership for bounded continuation queries, not extra decoded instructions. Without this,
  // an existing target omitted by the op display cap is indistinguishable from an actual decoder stop.
  const continuationQueries = new Set<number>();
  if (rawFunction.ops.length > instructions.length) {
    for (const block of basicBlocks) {
      for (const address of [block.address, block.address + block.size, block.jump, block.fail]) {
        if (address !== undefined) continuationQueries.add(address);
      }
    }
    for (const instruction of instructions) {
      for (const address of [instruction.address + instruction.size, instruction.jump, instruction.fail]) {
        if (address !== undefined) continuationQueries.add(address);
      }
    }
  }
  const omittedContinuations = new Set<number>();
  for (let index = instructions.length; continuationQueries.size > 0 && index < rawFunction.ops.length; index++) {
    const raw: R2Instruction | null = rawFunction.ops[index];
    if (!raw || typeof raw !== 'object') continue;
    const address = finiteInteger(raw.addr);
    const size = finiteInteger(raw.size);
    if (
      address === null ||
      size === null ||
      !continuationQueries.has(address) ||
      !inMappedImage(address, size, mapping, fileSize) ||
      typeof raw.type !== 'string' ||
      typeof raw.opcode !== 'string'
    )
      continue;
    if (!invalidPicobinInstruction({ address, size, type: raw.type, opcode: raw.opcode }))
      omittedContinuations.add(address);
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
    ...(omittedContinuations.size > 0
      ? { instructionDisplayOmissions: [...omittedContinuations].sort((a, b) => a - b) }
      : {}),
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

function invalidPicobinInstruction(instruction: PicobinInstruction): boolean {
  return (
    ['invalid', 'ill', 'unk'].includes(instruction.type) || /^(invalid|illegal|unimp)(?:\s|$)/i.test(instruction.opcode)
  );
}

/** A stopped static continuation is separate from an in-map, exact bitmanip recovery candidate. */
export interface PicobinDecodeStop {
  address: number;
  kind: 'missing-continuation' | 'out-of-map-continuation' | 'unresolved-continuation' | 'inconsistent-decode';
}

/** Inspect each listed block independently: an operation display cap on one path cannot hide another stop. */
export function picobinDecodeCoverage(
  parsed: ParsedPicobinFunction,
  mapping: Pick<PicobinFlashMapping, 'mappedRuntimeStart' | 'mappedRuntimeEnd'>,
): PicobinDecodeStop[] {
  const stops = new Map<string, PicobinDecodeStop>();
  const add = (address: number, kind: PicobinDecodeStop['kind']): void => {
    stops.set(`${address}:${kind}`, { address, kind });
  };
  const instructions = [...parsed.instructions].sort((a, b) => a.address - b.address);
  const addresses = new Set(instructions.map((instruction) => instruction.address));
  const capped = parsed.instructions.length !== parsed.instructionsTotal;
  const omitted = new Set(capped ? parsed.instructionDisplayOmissions : []);
  const continuation = (address: number): void => {
    if (address < mapping.mappedRuntimeStart || address >= mapping.mappedRuntimeEnd) {
      add(address, 'out-of-map-continuation');
    } else if (!addresses.has(address) && !omitted.has(address)) add(address, 'missing-continuation');
  };
  for (const instruction of instructions) {
    if (['jmp', 'cjmp', 'ujmp', 'rjmp', 'ijmp'].includes(instruction.type)) {
      const terminalBlock = parsed.basicBlocks.find(
        (block) =>
          block.address <= instruction.address && block.address + block.size === instruction.address + instruction.size,
      );
      const jump = instruction.jump ?? terminalBlock?.jump;
      const fail = instruction.fail ?? terminalBlock?.fail;
      if (jump !== undefined) continuation(jump);
      else add(instruction.address, 'unresolved-continuation');
      if (fail !== undefined) continuation(fail);
      if (instruction.type === 'cjmp' && fail === undefined) continuation(instruction.address + instruction.size);
      if (
        parsed.basicBlocks.some(
          (block) =>
            instruction.address >= block.address && instruction.address + instruction.size < block.address + block.size,
        )
      )
        add(instruction.address, 'inconsistent-decode');
    }
    if (invalidPicobinInstruction(instruction)) add(instruction.address, 'missing-continuation');
    if (
      parsed.basicBlocks.length === parsed.basicBlocksTotal &&
      !parsed.basicBlocks.some(
        (block) =>
          instruction.address >= block.address && instruction.address + instruction.size <= block.address + block.size,
      )
    )
      add(instruction.address, 'inconsistent-decode');
  }
  for (const block of parsed.basicBlocks) {
    for (const target of [block.jump, block.fail]) if (target !== undefined) continuation(target);
    const end = block.address + block.size;
    const members = instructions.filter(
      (instruction) => instruction.address >= block.address && instruction.address < end,
    );
    let cursor = block.address;
    let gap = false;
    for (const instruction of members) {
      if (instruction.address !== cursor || instruction.address + instruction.size > end) {
        add(Math.min(cursor, instruction.address), 'inconsistent-decode');
        gap = true;
      }
      cursor = instruction.address + instruction.size;
    }
    // A missing suffix may be only a display omission. Fully listed blocks still get all continuation checks.
    const omittedSuffix =
      capped && !gap && members.length < block.instructionCount && cursor < end && omitted.has(cursor);
    if (cursor !== end && !omittedSuffix) add(cursor, 'inconsistent-decode');
    if (members.length !== block.instructionCount && !omittedSuffix) add(cursor, 'inconsistent-decode');
    const last = members.at(-1);
    if (!last || last.address + last.size !== end) continue;
    if (block.jump !== undefined && last.jump !== undefined && block.jump !== last.jump)
      add(last.address, 'inconsistent-decode');
    if (block.fail !== undefined && last.fail !== undefined && block.fail !== last.fail)
      add(last.address, 'inconsistent-decode');
    const jump = block.jump ?? last.jump;
    const fail = block.fail ?? last.fail;
    // A call's jump is a separately scheduled function, not an intra-function continuation.
    if (block.jump !== undefined || (!last.type.includes('call') && jump !== undefined)) continuation(jump ?? end);
    if (fail !== undefined) continuation(fail);
    if (['ujmp', 'rjmp', 'ijmp', 'jmp', 'cjmp'].includes(last.type) && jump === undefined) {
      add(last.address, 'unresolved-continuation');
    }
    if (last.type === 'cjmp' && fail === undefined) continuation(end);
    if (block.jump !== undefined || fail !== undefined || (!last.type.includes('call') && jump !== undefined)) continue;
    if (!['ret', 'jmp', 'ujmp', 'rjmp', 'ijmp', 'trap', 'swi'].includes(last.type)) continuation(end);
  }
  return [...stops.values()].sort((a, b) => a.address - b.address || a.kind.localeCompare(b.kind));
}

/** Compatibility helper: all observed incomplete locations, including unknown/out-of-map continuations. */
export function picobinDecodeStops(
  parsed: ParsedPicobinFunction,
  mapping: Pick<PicobinFlashMapping, 'mappedRuntimeStart' | 'mappedRuntimeEnd'>,
): number[] {
  return [...new Set(picobinDecodeCoverage(parsed, mapping).map((stop) => stop.address))];
}

/**
 * Accept the whole view or refuse it. Every listed instruction must agree with the actual view bytes and
 * source bytes, with only exact whole-instruction substitutions allowed. Displayed block containment is not
 * required for restoring instructions beyond the block cap. Graph endpoints may never bisect a replacement.
 * Valid original instructions (including call attribution) must survive unchanged; invalid rows may improve.
 */
export function acceptPicobinDecoderRecovery(
  candidate: ParsedPicobinFunction,
  original: ParsedPicobinFunction | null,
  view: PicobinDecoderView,
  source: Uint8Array,
  mapping: PicobinFlashMapping,
): { parsed: ParsedPicobinFunction; substitutions: PicobinDecoderSubstitution[] } | null {
  const substitutions: PicobinDecoderSubstitution[] = [];
  const ordered = [...candidate.instructions].sort((a, b) => a.address - b.address);
  let previousEnd = -1;
  for (const instruction of ordered) {
    const offset = instruction.address - mapping.baseAddress;
    if (offset < 0 || offset + instruction.size > source.length || instruction.address < previousEnd) return null;
    const parcel = (source[offset] ?? 0) | ((source[offset + 1] ?? 0) << 8);
    if (instruction.address % 2 !== 0 || (parcel & 0x1f) === 0x1f || instruction.size !== ((parcel & 3) === 3 ? 4 : 2))
      return null;
    previousEnd = instruction.address + instruction.size;
    const overlaps = view.substitutions.filter((row) =>
      spansOverlap(row.address, 4, instruction.address, instruction.size),
    );
    if (overlaps.some((row) => row.address !== instruction.address || instruction.size !== 4)) return null;
    const expectedView = Buffer.from(view.bytes.subarray(offset, offset + instruction.size)).toString('hex');
    if (instruction.bytes !== expectedView) return null;
    const sourceHex = Buffer.from(source.subarray(offset, offset + instruction.size)).toString('hex');
    const substitution = overlaps[0];
    if (substitution) {
      if (
        substitution.fileOffset !== offset ||
        substitution.originalBytesHex !== sourceHex ||
        instruction.jump !== undefined ||
        instruction.fail !== undefined
      )
        return null;
      substitutions.push({ ...substitution, mnemonic: restoredPicobinOpcode(substitution) });
    } else if (expectedView !== sourceHex) return null;
  }
  if (substitutions.length === 0) return null;
  for (const block of candidate.basicBlocks) {
    for (const boundary of [block.address, block.address + block.size, block.jump, block.fail]) {
      if (
        boundary !== undefined &&
        (view.substitutions.some((row) => boundary > row.address && boundary < row.address + 4) ||
          candidate.instructions.some((row) => boundary > row.address && boundary < row.address + row.size))
      )
        return null;
    }
  }
  const byAddress = new Map(substitutions.map((row) => [row.address, row]));
  const restored = candidate.instructions.map((instruction) => {
    const substitution = byAddress.get(instruction.address);
    return substitution
      ? {
          ...instruction,
          opcode: restoredPicobinOpcode(substitution),
          type: 'bitmanip',
          bytes: substitution.originalBytesHex,
        }
      : instruction;
  });
  if (original) {
    for (const block of original.basicBlocks) {
      if (
        (block.jump !== undefined || block.fail !== undefined) &&
        !candidate.basicBlocks.some(
          (next) =>
            next.address + next.size === block.address + block.size &&
            next.jump === block.jump &&
            next.fail === block.fail,
        )
      )
        return null;
    }
    for (const instruction of original.instructions) {
      if (invalidPicobinInstruction(instruction)) continue;
      const next = restored.find((row) => row.address === instruction.address);
      if (
        !next ||
        next.size !== instruction.size ||
        next.type !== instruction.type ||
        next.opcode !== instruction.opcode ||
        next.jump !== instruction.jump ||
        next.fail !== instruction.fail ||
        (instruction.bytes !== undefined && next.bytes !== instruction.bytes)
      )
        return null;
    }
    const stops = picobinDecodeCoverage(original, mapping).filter((stop) => stop.kind === 'missing-continuation');
    if (!substitutions.some((row) => stops.some((stop) => stop.address === row.address))) return null;
    // Replacing an invalid row is progress; retaining only the original prefix is not.
    if (
      !substitutions.some(
        (row) => !original.instructions.some((op) => op.address === row.address && !invalidPicobinInstruction(op)),
      )
    )
      return null;
  } else if (!byAddress.has(mapping.entryPoint)) return null;
  return { parsed: { ...candidate, instructions: restored }, substitutions };
}

/**
 * Source evidence for anchoring candidate selection: valid original instruction spans, plus every boundary
 * the unpatched decode reported (block edges, branch/call targets and stopped continuations). Reported bytes
 * must agree when present; absent bytes remain unrecorded, not a byte agreement claim. A contradiction returns
 * null. The selection also checks source width, and whole-result acceptance still requires candidate bytes.
 */
export function picobinDecoderSourceEvidence(
  original: ParsedPicobinFunction | null,
  mapping: PicobinFlashMapping,
  source: Uint8Array,
): PicobinDecoderSourceEvidence | null {
  if (!original) return { knownInstructions: [], boundaries: [mapping.entryPoint] };
  const knownInstructions: PicobinDecoderSourceEvidence['knownInstructions'] = [];
  const boundaries = new Set<number>([mapping.entryPoint]);
  for (const instruction of original.instructions) {
    for (const target of [instruction.jump, instruction.fail]) if (target !== undefined) boundaries.add(target);
    if (invalidPicobinInstruction(instruction)) continue;
    const offset = instruction.address - mapping.baseAddress;
    if (
      instruction.bytes !== undefined &&
      (offset < 0 ||
        instruction.bytes !== Buffer.from(source.subarray(offset, offset + instruction.size)).toString('hex'))
    )
      return null;
    knownInstructions.push({ address: instruction.address, size: instruction.size });
  }
  for (const block of original.basicBlocks) {
    for (const boundary of [block.address, block.address + block.size, block.jump, block.fail]) {
      if (boundary !== undefined) boundaries.add(boundary);
    }
  }
  for (const stop of picobinDecodeCoverage(original, mapping)) {
    if (stop.kind === 'missing-continuation') boundaries.add(stop.address);
  }
  return { knownInstructions, boundaries: [...boundaries].sort((a, b) => a - b) };
}

function decodeWithRecovery(
  imagePath: string,
  mapping: PicobinFlashMapping,
  fileSize: number,
  execute: Radare2Executor,
  imageBytes: Uint8Array | undefined,
): {
  parsed: ParsedPicobinFunction | null;
  substitutions: PicobinDecoderSubstitution[];
  exclusions?: PicobinDecoderCandidateExclusion[];
  recoveryFailure?: string;
} {
  const parsed = decodeFunction(imagePath, mapping, fileSize, execute);
  const unchanged = { parsed, substitutions: [] };
  const stops = parsed
    ? picobinDecodeCoverage(parsed, mapping)
    : [{ address: mapping.entryPoint, kind: 'missing-continuation' }];
  const eligible = stops.filter(
    (stop) => stop.kind === 'missing-continuation' && inMappedImage(stop.address, 4, mapping, fileSize),
  );
  if (!imageBytes || eligible.length === 0) return unchanged;
  const evidence = picobinDecoderSourceEvidence(parsed, mapping, imageBytes.subarray(0, fileSize));
  if (!evidence) return unchanged;
  const selection = selectPicobinDecoderCandidates(imageBytes, fileSize, mapping, evidence);
  const exclusions = selection?.exclusions ?? [];
  const withheld = exclusions.length > 0 ? { ...unchanged, exclusions } : unchanged;
  // Proved-conflicting proposals are withheld here, before any external retry.
  const view = buildPicobinRiscvDecoderView(imageBytes, fileSize, mapping, evidence);
  if (!view || !view.substitutions.some((row) => eligible.some((stop) => stop.address === row.address)))
    return withheld;
  try {
    const directory = mkdtempSync(path.join(tmpdir(), 'firmlab-picobin-'));
    const viewPath = path.join(directory, 'decoder-view.bin');
    try {
      writeFileSync(viewPath, view.bytes, { mode: 0o600 });
      const candidate = decodeFunction(viewPath, mapping, fileSize, execute);
      if (!candidate) return withheld;
      const accepted = acceptPicobinDecoderRecovery(candidate, parsed, view, imageBytes.subarray(0, fileSize), mapping);
      return accepted ? { ...accepted, ...(exclusions.length > 0 ? { exclusions } : {}) } : withheld;
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  } catch (err) {
    // A failed compatibility retry or temporary-file operation must retain the source prefix and call edges.
    if (!parsed) throw err;
    return { ...withheld, recoveryFailure: radareFailureReason(err) };
  }
}

/** Sample only bytes proved file-backed by this selected mapping. A boundary stop has no instruction sample. */
export function picobinFailureBytes(
  address: number,
  mapping: PicobinFlashMapping,
  fileSize: number,
  imageBytes: Uint8Array | undefined,
): string | undefined {
  const offset = address - mapping.baseAddress;
  if (!imageBytes || !inMappedImage(address, 1, mapping, fileSize)) return undefined;
  const length = Math.min(8, mapping.mappedRuntimeEnd - address, fileSize - offset, imageBytes.length - offset);
  return length > 0 ? Buffer.from(imageBytes.subarray(offset, offset + length)).toString('hex') : undefined;
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

  const sourceEvidence = imageBytes
    ? {
        sourceBytesAvailable: Math.min(imageBytes.length, fileSize),
        sourceBytesDeclared: fileSize,
        ...(imageBytes.length < fileSize
          ? { decoderRecoveryUnavailableReason: 'complete file bytes unavailable' }
          : {}),
      }
    : {};
  const sourceAvailabilityReason =
    imageBytes && imageBytes.length < fileSize
      ? `; source bytes available ${imageBytes.length}/${fileSize}; decoder-view recovery unavailable without complete file bytes`
      : '';
  const baseHex = `0x${mapping.baseAddress.toString(16)}`;
  const entryHex = `0x${mapping.entryPoint.toString(16)}`;
  let decoderAttemptsTotal = 0;
  const boundedExecute: Radare2Executor = (args) => {
    if (decoderAttemptsTotal >= DECODER_ATTEMPT_CAP) throw new Error('PICOBIN decoder attempt cap reached');
    decoderAttemptsTotal++;
    return execute(args);
  };
  const entryFailure = (
    classification: PicobinDecodeFailure['classification'],
    reason: string,
  ): PicobinRiscvDisassembly => {
    const bytesHex = picobinFailureBytes(mapping.entryPoint, mapping, fileSize, imageBytes);
    return {
      ...unavailable(mapping, reason + sourceAvailabilityReason),
      ...sourceEvidence,
      callGraphTruncated: true,
      functionTargetsQueuedTotal: 1,
      functionsAttemptedTotal: 1,
      functionsDecodedTotal: 0,
      functionsCompletedTotal: 0,
      functionTargetsPendingTotal: 0,
      functionAttemptCap: FUNCTION_ATTEMPT_CAP,
      decoderAttemptCap: DECODER_ATTEMPT_CAP,
      decoderAttemptsTotal,
      graphStopReasons: [classification === 'tool-error' ? 'tool-error' : 'unparsed-output'],
      decodeFailuresTotal: 1,
      decodeFailures: [
        {
          address: mapping.entryPoint,
          fileOffset: mapping.entryFileOffset,
          classification,
          reason,
          ...(bytesHex ? { bytesHex } : {}),
        },
      ],
    };
  };
  let parsed: ParsedPicobinFunction | null;
  let entrySubstitutions: PicobinDecoderSubstitution[];
  let entryExclusions: PicobinDecoderCandidateExclusion[];
  let entryRecoveryFailure: string | undefined;
  try {
    const decoded = decodeWithRecovery(imagePath, mapping, fileSize, boundedExecute, imageBytes);
    parsed = decoded.parsed;
    entrySubstitutions = decoded.substitutions;
    entryExclusions = decoded.exclusions ?? [];
    entryRecoveryFailure = decoded.recoveryFailure;
  } catch (err) {
    return entryFailure('tool-error', radareFailureReason(err));
  }
  if (!parsed)
    return entryFailure(
      'incomplete-decode',
      'radare2 output was missing, malformed, unsupported or outside the mapped image; coverage incomplete',
    );

  const startupCopyTable = imageBytes
    ? parseRiscvStartupCopyTable(
        imageBytes.subarray(0, fileSize),
        mapping.entryPoint,
        mapping.entryFileOffset,
        mapping.baseAddress,
        {
          start: mapping.mappedRuntimeStart,
          endExclusive: mapping.mappedRuntimeEnd,
        },
      )
    : null;

  const reachableFunctions: PicobinReachableFunction[] = [
    {
      address: mapping.entryPoint,
      depth: 0,
      basicBlocksTotal: parsed.basicBlocksTotal,
      instructionsTotal: parsed.instructionsTotal,
    },
  ];
  // At most 8 functions x 256 listed instructions; display selection cannot suppress target discovery.
  const allCallEdges: PicobinCallEdge[] = [];
  const allOutOfMapCalls: PicobinCallEdge[] = [];
  const queued = new Set<number>([mapping.entryPoint]);
  const droppedFunctionTargets = new Set<number>();
  const queue: { address: number; depth: number; mapping: PicobinFlashMapping }[] = [];
  let functionsAttemptedTotal = 1;
  let functionsCompletedTotal = 0;
  let unresolvedCallsitesTotal = 0;
  let outOfMapCallsitesTotal = 0;
  const graphStopReasons = new Set<PicobinGraphStopReason>();
  let decodeFailuresTotal = 0;
  const decodeFailures: PicobinDecodeFailure[] = [];
  const decoderSubstitutionsByOffset = new Map<number, PicobinDecoderSubstitution>(
    entrySubstitutions.map((substitution) => [substitution.fileOffset, substitution]),
  );
  // Keyed per function: the same bytes can conflict with one function's evidence and not another's.
  const candidateExclusions = new Map<string, PicobinDecoderCandidateExclusion>();
  const recordExclusions = (functionAddress: number, rows: PicobinDecoderCandidateExclusion[] | undefined): void => {
    for (const row of rows ?? [])
      candidateExclusions.set(`${functionAddress}:${row.fileOffset}`, { ...row, functionAddress });
  };
  recordExclusions(mapping.entryPoint, entryExclusions);
  const recordDecodeFailure = (
    next: { address: number; mapping: PicobinFlashMapping },
    classification: PicobinDecodeFailure['classification'],
    reason: string,
    sampleBytes = true,
  ): void => {
    decodeFailuresTotal++;
    if (decodeFailures.length >= DECODE_FAILURE_CAP) return;
    const bytesHex = sampleBytes ? picobinFailureBytes(next.address, next.mapping, fileSize, imageBytes) : undefined;
    decodeFailures.push({
      address: next.address,
      fileOffset: next.address - next.mapping.baseAddress,
      classification,
      reason,
      ...(bytesHex ? { bytesHex } : {}),
    });
  };

  const enqueueCalls = (caller: number, depth: number, instructions: PicobinInstruction[]): void => {
    const targets = new Map<number, PicobinFlashMapping>();
    for (const instruction of instructions) {
      if (!instruction.type.includes('call')) continue;
      if (instruction.jump === undefined) {
        unresolvedCallsitesTotal++;
        continue;
      }
      const edge = { caller, callsite: instruction.address, target: instruction.jump };
      const targetMapping = picobinRuntimeMapping(instruction.jump, 2, mapping, startupCopyTable, fileSize);
      if (!targetMapping) {
        outOfMapCallsitesTotal++;
        allOutOfMapCalls.push(edge);
        continue;
      }
      allCallEdges.push(edge);
      targets.set(instruction.jump, targetMapping);
    }
    // Stable breadth-first admission, numeric targets within each decoded caller. Failed targets retain slots.
    for (const [address, targetMapping] of [...targets].sort(([a], [b]) => a - b)) {
      if (queued.has(address)) continue;
      if (depth >= CALL_DEPTH_CAP || queued.size >= FUNCTION_ATTEMPT_CAP) {
        graphStopReasons.add(depth >= CALL_DEPTH_CAP ? 'call-depth-cap' : 'function-attempt-cap');
        droppedFunctionTargets.add(address);
        continue;
      }
      queued.add(address);
      queue.push({ address, depth: depth + 1, mapping: targetMapping });
    }
  };

  const recordFunctionCoverage = (decoded: ParsedPicobinFunction, currentMapping: PicobinFlashMapping): void => {
    const stops = picobinDecodeCoverage(decoded, currentMapping);
    const blocksCapped = decoded.basicBlocks.length !== decoded.basicBlocksTotal;
    const instructionsCapped = decoded.instructions.length !== decoded.instructionsTotal;
    if (blocksCapped) graphStopReasons.add('basic-block-cap');
    if (instructionsCapped) graphStopReasons.add('instruction-cap');
    for (const { address, kind } of stops) {
      if (kind !== 'missing-continuation') graphStopReasons.add(kind);
      graphStopReasons.add('incomplete-decode');
      recordDecodeFailure(
        { address, mapping: functionMapping(currentMapping, address) },
        'incomplete-decode',
        `radare2 ${kind} at 0x${address.toString(16)}; coverage incomplete`,
        false,
      );
    }
    if (stops.length === 0 && !blocksCapped && !instructionsCapped) functionsCompletedTotal++;
  };
  if (entryRecoveryFailure) {
    graphStopReasons.add('tool-error');
    recordDecodeFailure({ address: mapping.entryPoint, mapping }, 'tool-error', entryRecoveryFailure);
  }
  recordFunctionCoverage(parsed, mapping);
  enqueueCalls(mapping.entryPoint, 0, parsed.instructions);
  while (
    queue.length > 0 &&
    functionsAttemptedTotal < FUNCTION_ATTEMPT_CAP &&
    reachableFunctions.length < REACHABLE_FUNCTION_CAP
  ) {
    queue.sort((a, b) => a.depth - b.depth || a.address - b.address);
    const next = queue.shift();
    if (!next) break;
    const nextMapping = functionMapping(next.mapping, next.address);
    functionsAttemptedTotal++;
    let decoded: ParsedPicobinFunction | null;
    try {
      const recovered = decodeWithRecovery(imagePath, nextMapping, fileSize, boundedExecute, imageBytes);
      decoded = recovered.parsed;
      if (recovered.recoveryFailure) {
        graphStopReasons.add('tool-error');
        recordDecodeFailure(next, 'tool-error', recovered.recoveryFailure);
      }
      for (const substitution of recovered.substitutions) {
        decoderSubstitutionsByOffset.set(substitution.fileOffset, substitution);
      }
      recordExclusions(next.address, recovered.exclusions);
    } catch (err) {
      graphStopReasons.add('tool-error');
      recordDecodeFailure(next, 'tool-error', radareFailureReason(err));
      continue;
    }
    if (!decoded) {
      graphStopReasons.add('unparsed-output');
      recordDecodeFailure(
        next,
        'incomplete-decode',
        `radare2 output for reachable target 0x${next.address.toString(16)} was missing, malformed, unsupported or outside the mapped image; coverage incomplete`,
      );
      continue;
    }
    recordFunctionCoverage(decoded, nextMapping);
    reachableFunctions.push({
      address: next.address,
      depth: next.depth,
      basicBlocksTotal: decoded.basicBlocksTotal,
      instructionsTotal: decoded.instructionsTotal,
    });
    enqueueCalls(next.address, next.depth, decoded.instructions);
  }
  if (queue.length > 0) graphStopReasons.add('function-attempt-cap');
  const edgeOrder = (a: PicobinCallEdge, b: PicobinCallEdge): number =>
    a.caller - b.caller || a.callsite - b.callsite || a.target - b.target;
  const callEdges = allCallEdges.sort(edgeOrder).slice(0, CALL_EDGE_CAP);
  const outOfMapCalls = allOutOfMapCalls.sort(edgeOrder).slice(0, CALL_EDGE_CAP);
  const callEdgesTotal = allCallEdges.length;
  const droppedCallEdgesTotal = callEdgesTotal - callEdges.length;
  const droppedOutOfMapCallEdgesTotal = allOutOfMapCalls.length - outOfMapCalls.length;
  const functionTargetSelection =
    'breadth-first callers by depth then runtime address; ascending distinct targets per caller; failed targets retain attempt slots';
  const callEdgeSelection =
    'lowest caller, callsite, then target runtime addresses; discovery independent of display cap';
  if (droppedCallEdgesTotal > 0) graphStopReasons.add('call-edge-display-cap');
  if (droppedOutOfMapCallEdgesTotal > 0) graphStopReasons.add('out-of-map-display-cap');
  const callGraphTruncated = graphStopReasons.size > 0;
  const truncatedByLimits = [...graphStopReasons].some((reason) => reason.endsWith('-cap'));
  const decoderSubstitutions = Array.from(decoderSubstitutionsByOffset.values()).slice(
    0,
    DECODER_SUBSTITUTION_EVIDENCE_CAP,
  );
  const decoderSubstitutionsTotal = decoderSubstitutionsByOffset.size;
  const candidateExclusionEvidence =
    candidateExclusions.size > 0
      ? {
          decoderCandidateExclusionsTotal: candidateExclusions.size,
          decoderCandidateExclusions: [...candidateExclusions.values()].slice(0, DECODER_SUBSTITUTION_EVIDENCE_CAP),
        }
      : {};

  const reason =
    `Decoded a bounded RISC-V call graph from the declared entrypoint: ${reachableFunctions.length} function(s), ` +
    `${callEdges.length} listed direct edge(s) of ${callEdgesTotal} observed (${droppedCallEdgesTotal} dropped by display cap), ` +
    `${functionsAttemptedTotal} target(s) attempted, ${functionsCompletedTotal} decode(s) completed, ${queued.size} target(s) queued, ` +
    `${droppedFunctionTargets.size} distinct target(s) excluded by function/depth budgets, ` +
    `${outOfMapCallsitesTotal} resolved target(s) outside mapped bytes, ` +
    `${unresolvedCallsitesTotal} unresolved/indirect callsite(s), ${decodeFailuresTotal} decode failure(s)/stopped continuation(s), ` +
    `${decoderSubstitutionsTotal} exact Zba/Zbs decoder-view substitution(s)` +
    `${callGraphTruncated ? `; coverage truncated${truncatedByLimits ? ' by configured limits' : ''} (${[...graphStopReasons].sort().join(', ')})` : ''}` +
    `${decodeFailuresTotal > 0 ? '; coverage incomplete' : ''}` +
    `${sourceAvailabilityReason}.`;
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
      functionAttemptCap: FUNCTION_ATTEMPT_CAP,
      decoderAttemptCap: DECODER_ATTEMPT_CAP,
      decoderAttemptsTotal,
      functionTargetsQueuedTotal: queued.size,
      functionsAttemptedTotal,
      functionsDecodedTotal: reachableFunctions.length,
      functionsCompletedTotal,
      functionTargetsPendingTotal: queue.length,
      droppedFunctionTargetsTotal: droppedFunctionTargets.size,
      callEdgesTotal,
      droppedCallEdgesTotal,
      droppedOutOfMapCallEdgesTotal,
      callEdgeSelection,
      functionTargetSelection,
      graphStopReasons: [...graphStopReasons].sort(),
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
      decodeFailuresTotal,
      decodeFailuresListed: decodeFailures.length,
      decoderSubstitutionsTotal,
      decoderSubstitutionsListed: decoderSubstitutions.length,
      startupCopyRegions: startupCopyTable?.regions.length ?? 0,
    },
    rationale:
      'radare2 decoded instructions and local control-flow blocks from the entrypoint declared by a structurally ' +
      'validated PICOBIN image, then followed only direct call targets under explicit function/depth/attempt budgets and a separate edge display cap. ' +
      'Where the installed decoder rejected exact BSET/SH1ADD/SH2ADD/SH3ADD encodings, a bounded same-length ' +
      'discarded-destination MOV view (linear candidates overlapping a valid original instruction or straddling a ' +
      'reported boundary are withheld before any retry) recovered ' +
      'control-flow structure only after whole-result source agreement and preservation of valid original instructions; ' +
      'exact substitutions retain original bytes and source mnemonics, including instructions beyond the block display cap. This is bounded static ' +
      'decoder evidence; it does not prove execution, instruction semantics, indirect calls, whole-image function ' +
      'coverage or peripheral behavior.',
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
    functionTargetsQueuedTotal: queued.size,
    functionsAttemptedTotal,
    functionsDecodedTotal: reachableFunctions.length,
    functionsCompletedTotal,
    functionTargetsPendingTotal: queue.length,
    functionAttemptCap: FUNCTION_ATTEMPT_CAP,
    decoderAttemptCap: DECODER_ATTEMPT_CAP,
    decoderAttemptsTotal,
    droppedFunctionTargetsTotal: droppedFunctionTargets.size,
    callEdgesTotal,
    droppedCallEdgesTotal,
    droppedOutOfMapCallEdgesTotal,
    callEdgeSelection,
    functionTargetSelection,
    graphStopReasons: [...graphStopReasons].sort(),
    decodeFailuresTotal,
    decodeFailures,
    decoderSubstitutionsTotal,
    decoderSubstitutions,
    ...candidateExclusionEvidence,
    startupCopyTable,
    startupCopyTableAttempted: imageBytes !== undefined,
    ...sourceEvidence,
    findings: [finding],
  };
}
