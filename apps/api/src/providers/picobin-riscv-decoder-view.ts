/**
 * Build a bounded, same-length decoder view for exact ratified RV32 Zba/Zbs instructions that older
 * radare2 releases reject. The view is analysis-only: it replaces exact non-control-flow encodings with 32-bit
 * discarded-destination MOVs so the external decoder can recover block boundaries. Callers retain every original
 * byte and validate the entire recovered result before restoring mnemonics. Its linear length walk can lose phase
 * across inline data or jumps: scanned matches are only candidates, never evidence. It stops at unsupported longer encodings and does not
 * establish instruction semantics or distinguish embedded data from code. It never mutates the firmware image.
 *
 * Candidate selection may be anchored in source evidence from the unpatched decode: valid, source-consistent
 * instructions are authoritative (never re-proposed, never overlapped) and tool-reported boundaries (block
 * edges, branch/call targets, stopped continuations) resynchronize the width walk instead of being bisected.
 * A dropped proposal is labelled either a proved conflict with that evidence or merely an unanchored phase;
 * neither label, nor the corroborated-boundary basis of a kept proposal, is a code/data or global region proof.
 */

const DECODER_WINDOW_BYTES = 4096;
const SUBSTITUTION_CAP = 64;
const OPCODE_MASK = 0xfe00_707f;
// Unlike NOP, this instruction is accepted by radare2 as a function entry.
// x0 discards the value; this view is never executed or used for data-flow claims.
const RISCV_DECODER_ANCHOR = 0x0000_8013;

const supported = [
  { instruction: 'bset' as const, match: 0x2800_1033 },
  { instruction: 'sh1add' as const, match: 0x2000_2033 },
  { instruction: 'sh2add' as const, match: 0x2000_4033 },
  { instruction: 'sh3add' as const, match: 0x2000_6033 },
];

export interface PicobinDecoderSubstitution {
  address: number;
  fileOffset: number;
  instruction: 'bset' | 'sh1add' | 'sh2add' | 'sh3add';
  originalBytesHex: string;
  /** Exact source mnemonic; optional forever for previously persisted evidence. */
  mnemonic?: string;
  /**
   * Optional forever. `corroborated-boundary`: the start is the declared entry or a boundary the source decode
   * reported. `linear-scan`: reached only by width stepping from such a boundary. Neither proves code.
   */
  candidateBasis?: 'corroborated-boundary' | 'linear-scan';
}

/** Evidence from the unpatched decode of the same function, in runtime addresses. */
export interface PicobinDecoderSourceEvidence {
  /** Valid instructions whose width and bytes the caller checked against the source. */
  knownInstructions: { address: number; size: number }[];
  /** Tool-reported instruction boundaries: block edges, branch/call targets and stopped continuations. */
  boundaries: number[];
}

/** A legacy linear-scan proposal the evidence-anchored walk did not keep, and why. Optional evidence forever. */
export interface PicobinDecoderCandidateExclusion {
  address: number;
  fileOffset: number;
  instruction: PicobinDecoderSubstitution['instruction'];
  originalBytesHex: string;
  /**
   * `known-instruction-overlap` and `known-boundary-bisected` are proved conflicts with source decoder output.
   * `unanchored-phase` is not a conflict: the legacy walk reached it only after losing phase at such a conflict.
   */
  reason: 'known-instruction-overlap' | 'known-boundary-bisected' | 'unanchored-phase';
  conflictAddress?: number;
}

export type PicobinDecoderSelectionStop =
  | 'window-end'
  | 'substitution-cap'
  | 'unsupported-encoding'
  | 'inconsistent-source-evidence';

export interface PicobinDecoderCandidateSelection {
  substitutions: PicobinDecoderSubstitution[];
  exclusions: PicobinDecoderCandidateExclusion[];
  bytesExamined: number;
  stop: PicobinDecoderSelectionStop;
  /** Times the walk jumped to a boundary rather than bisect it or stop at an unsupported non-boundary parcel. */
  resynchronizations: number;
}

export interface PicobinDecoderView {
  bytes: Uint8Array;
  substitutions: PicobinDecoderSubstitution[];
  bytesExamined: number;
  /** Present only for an evidence-anchored view. */
  exclusions?: PicobinDecoderCandidateExclusion[];
  stop?: PicobinDecoderSelectionStop;
}

export interface PicobinDecoderViewMapping {
  entryPoint: number;
  entryFileOffset: number;
  mappedRuntimeEnd: number;
}

function readWord(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] ?? 0) |
      ((bytes[offset + 1] ?? 0) << 8) |
      ((bytes[offset + 2] ?? 0) << 16) |
      ((bytes[offset + 3] ?? 0) << 24)) >>>
    0
  );
}

function writeWord(bytes: Uint8Array, offset: number, word: number): void {
  bytes[offset] = word & 0xff;
  bytes[offset + 1] = (word >>> 8) & 0xff;
  bytes[offset + 2] = (word >>> 16) & 0xff;
  bytes[offset + 3] = (word >>> 24) & 0xff;
}

function wordHex(bytes: Uint8Array, offset: number): string {
  return Array.from(bytes.subarray(offset, offset + 4), (octet) => octet.toString(16).padStart(2, '0')).join('');
}

function validInput(imageBytes: Uint8Array, fileSize: number, mapping: PicobinDecoderViewMapping): boolean {
  return !(
    !Number.isSafeInteger(fileSize) ||
    fileSize <= 0 ||
    imageBytes.byteLength < fileSize ||
    !Number.isSafeInteger(mapping.entryFileOffset) ||
    !Number.isSafeInteger(mapping.entryPoint) ||
    !Number.isSafeInteger(mapping.mappedRuntimeEnd) ||
    mapping.entryPoint < 0 ||
    mapping.entryPoint > 0xffff_ffff ||
    mapping.entryPoint % 2 !== 0 ||
    mapping.mappedRuntimeEnd > 0x1_0000_0000 ||
    mapping.entryFileOffset < 0 ||
    mapping.entryFileOffset >= fileSize ||
    mapping.mappedRuntimeEnd <= mapping.entryPoint
  );
}

function windowEnd(fileSize: number, mapping: PicobinDecoderViewMapping): number {
  return Math.min(
    fileSize,
    mapping.entryFileOffset + DECODER_WINDOW_BYTES,
    mapping.entryFileOffset + (mapping.mappedRuntimeEnd - mapping.entryPoint),
  );
}

// RISC-V base instruction-length encoding, ratified unprivileged ISA table 1: low bits != 11 mark a 16-bit
// parcel; bbb11 with bbb != 111 marks 32 bits. A longer/reserved prefix (null) is outside this RV32 view.
function encodedWidth(bytes: Uint8Array, offset: number): 2 | 4 | null {
  const parcel = (bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8);
  if ((parcel & 0x1f) === 0x1f) return null;
  return (parcel & 0x3) === 0x3 ? 4 : 2;
}

function supportedAt(bytes: Uint8Array, offset: number): (typeof supported)[number] | undefined {
  const word = readWord(bytes, offset);
  return supported.find((candidate) => (word & OPCODE_MASK) >>> 0 === candidate.match);
}

/** The evidence-free walk: every exact match on one linear width phase from the entry. */
function legacyScan(
  imageBytes: Uint8Array,
  end: number,
  mapping: PicobinDecoderViewMapping,
): { substitutions: PicobinDecoderSubstitution[]; bytesExamined: number; stop: PicobinDecoderSelectionStop } {
  const substitutions: PicobinDecoderSubstitution[] = [];
  let offset = mapping.entryFileOffset;
  let stop: PicobinDecoderSelectionStop = 'window-end';
  // Stop at a longer/reserved prefix rather than interpreting its trailing parcels as instructions.
  while (offset + 2 <= end) {
    if (substitutions.length >= SUBSTITUTION_CAP) {
      stop = 'substitution-cap';
      break;
    }
    const instructionBytes = encodedWidth(imageBytes, offset);
    if (instructionBytes === null) {
      stop = 'unsupported-encoding';
      break;
    }
    if (offset + instructionBytes > end) break;
    const definition = instructionBytes === 4 ? supportedAt(imageBytes, offset) : undefined;
    if (definition) {
      substitutions.push({
        address: mapping.entryPoint + (offset - mapping.entryFileOffset),
        fileOffset: offset,
        instruction: definition.instruction,
        originalBytesHex: wordHex(imageBytes, offset),
      });
    }
    offset += instructionBytes;
  }
  return { substitutions, bytesExamined: offset - mapping.entryFileOffset, stop };
}

/**
 * Pure candidate selection. Without evidence it is exactly the legacy linear walk. With evidence it never
 * proposes inside or over a known valid instruction, never lets a 32-bit proposal straddle a reported boundary
 * (it jumps to that boundary instead), and resumes at the next reported boundary after an unsupported parcel that
 * is not itself a boundary. Known instructions that disagree with the source width refuse every candidate,
 * because the whole-result acceptor could not preserve them anyway. Budgets are the legacy ones.
 */
export function selectPicobinDecoderCandidates(
  imageBytes: Uint8Array,
  fileSize: number,
  mapping: PicobinDecoderViewMapping,
  evidence?: PicobinDecoderSourceEvidence,
): PicobinDecoderCandidateSelection | null {
  if (!validInput(imageBytes, fileSize, mapping)) return null;
  const end = windowEnd(fileSize, mapping);
  const legacy = legacyScan(imageBytes, end, mapping);
  if (!evidence) return { ...legacy, exclusions: [], resynchronizations: 0 };
  const toOffset = (address: number): number => mapping.entryFileOffset + (address - mapping.entryPoint);
  const toAddress = (offset: number): number => mapping.entryPoint + (offset - mapping.entryFileOffset);
  const refused = (): PicobinDecoderCandidateSelection => ({
    substitutions: [],
    exclusions: [],
    bytesExamined: 0,
    stop: 'inconsistent-source-evidence',
    resynchronizations: 0,
  });
  const known = new Map<number, number>();
  const ordered = [...evidence.knownInstructions].sort((a, b) => a.address - b.address);
  let previousEnd = Number.NEGATIVE_INFINITY;
  for (const instruction of ordered) {
    const offset = toOffset(instruction.address);
    if (
      !Number.isSafeInteger(instruction.address) ||
      instruction.address % 2 !== 0 ||
      instruction.address < previousEnd ||
      offset < 0 ||
      offset + instruction.size > fileSize ||
      encodedWidth(imageBytes, offset) !== instruction.size
    )
      return refused();
    previousEnd = instruction.address + instruction.size;
    known.set(offset, instruction.size);
  }
  const boundaries = new Set<number>([mapping.entryFileOffset]);
  for (const address of evidence.boundaries) {
    if (Number.isSafeInteger(address) && address % 2 === 0) boundaries.add(toOffset(address));
  }
  for (const [offset, size] of known) boundaries.add(offset).add(offset + size);
  const sortedBoundaries = [...boundaries].sort((a, b) => a - b);
  const knownCovering = (offset: number): [number, number] | undefined =>
    [...known].find(([start, size]) => offset > start && offset < start + size);

  const substitutions: PicobinDecoderSubstitution[] = [];
  const exclusions = new Map<number, PicobinDecoderCandidateExclusion>();
  const exclude = (offset: number, reason: PicobinDecoderCandidateExclusion['reason'], conflict?: number): void => {
    const definition = supportedAt(imageBytes, offset);
    if (!definition || exclusions.has(offset)) return;
    exclusions.set(offset, {
      address: toAddress(offset),
      fileOffset: offset,
      instruction: definition.instruction,
      originalBytesHex: wordHex(imageBytes, offset),
      reason,
      ...(conflict === undefined ? {} : { conflictAddress: toAddress(conflict) }),
    });
  };
  let offset = mapping.entryFileOffset;
  let stop: PicobinDecoderSelectionStop = 'window-end';
  let resynchronizations = 0;
  while (offset + 2 <= end) {
    if (substitutions.length >= SUBSTITUTION_CAP) {
      stop = 'substitution-cap';
      break;
    }
    const covering = knownCovering(offset);
    if (covering) {
      // Only contradictory evidence (a boundary inside a known instruction) lands here: keep the known one.
      offset = covering[0] + covering[1];
      resynchronizations++;
      continue;
    }
    const knownSize = known.get(offset);
    if (knownSize !== undefined) {
      offset += knownSize;
      continue;
    }
    const width = encodedWidth(imageBytes, offset);
    if (width === null) {
      const next = sortedBoundaries.find((boundary) => boundary > offset);
      if (boundaries.has(offset) || next === undefined || next + 2 > end) {
        stop = 'unsupported-encoding';
        break;
      }
      offset = next;
      resynchronizations++;
      continue;
    }
    if (offset + width > end) break;
    if (width === 4 && boundaries.has(offset + 2)) {
      exclude(offset, known.has(offset + 2) ? 'known-instruction-overlap' : 'known-boundary-bisected', offset + 2);
      offset += 2;
      resynchronizations++;
      continue;
    }
    const definition = width === 4 ? supportedAt(imageBytes, offset) : undefined;
    if (definition) {
      substitutions.push({
        address: toAddress(offset),
        fileOffset: offset,
        instruction: definition.instruction,
        originalBytesHex: wordHex(imageBytes, offset),
        candidateBasis: boundaries.has(offset) ? 'corroborated-boundary' : 'linear-scan',
      });
    }
    offset += width;
  }
  const selected = new Set(substitutions.map((row) => row.fileOffset));
  for (const row of legacy.substitutions) {
    if (selected.has(row.fileOffset) || exclusions.has(row.fileOffset)) continue;
    const overlap = [...known].find(([start, size]) => row.fileOffset < start + size && start < row.fileOffset + 4);
    if (overlap) exclude(row.fileOffset, 'known-instruction-overlap', overlap[0]);
    else if (boundaries.has(row.fileOffset + 2)) exclude(row.fileOffset, 'known-boundary-bisected', row.fileOffset + 2);
    else exclude(row.fileOffset, 'unanchored-phase');
  }
  return {
    substitutions,
    exclusions: [...exclusions.values()].sort((a, b) => a.fileOffset - b.fileOffset),
    bytesExamined: Math.max(0, offset - mapping.entryFileOffset),
    stop,
    resynchronizations,
  };
}

/** Return null unless the caller supplied the complete file and at least one exact supported encoding was selected. */
export function buildPicobinRiscvDecoderView(
  imageBytes: Uint8Array,
  fileSize: number,
  mapping: PicobinDecoderViewMapping,
  evidence?: PicobinDecoderSourceEvidence,
): PicobinDecoderView | null {
  const selection = selectPicobinDecoderCandidates(imageBytes, fileSize, mapping, evidence);
  if (!selection || selection.substitutions.length === 0) return null;
  const patched = Uint8Array.from(imageBytes.subarray(0, fileSize));
  for (const row of selection.substitutions) writeWord(patched, row.fileOffset, RISCV_DECODER_ANCHOR);
  return {
    bytes: patched,
    substitutions: selection.substitutions,
    bytesExamined: selection.bytesExamined,
    ...(evidence ? { exclusions: selection.exclusions, stop: selection.stop } : {}),
  };
}

/** Restore an exact source mnemonic without pretending to recover register values from radare2's replacement view. */
export function restoredPicobinOpcode(substitution: PicobinDecoderSubstitution): string {
  const word = Number.parseInt(substitution.originalBytesHex.match(/../g)?.reverse().join('') ?? '', 16);
  const rd = (word >>> 7) & 0x1f;
  const rs1 = (word >>> 15) & 0x1f;
  const rs2 = (word >>> 20) & 0x1f;
  return `${substitution.instruction} x${rd}, x${rs1}, x${rs2}`;
}
