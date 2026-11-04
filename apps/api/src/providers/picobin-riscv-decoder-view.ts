/**
 * Build a bounded, same-length decoder view for exact ratified RV32 Zba/Zbs instructions that older
 * radare2 releases reject. The view is analysis-only: it replaces exact non-control-flow encodings with 32-bit
 * NOPs so the external decoder can recover block boundaries, while callers retain every original byte and restore
 * the mnemonic in reported instructions. It never mutates the firmware image.
 */

const DECODER_WINDOW_BYTES = 4096;
const SUBSTITUTION_CAP = 64;
const OPCODE_MASK = 0xfe00_707f;
const RISCV_NOP = 0x0000_0013;

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
}

export interface PicobinDecoderView {
  bytes: Uint8Array;
  substitutions: PicobinDecoderSubstitution[];
  bytesExamined: number;
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

/** Return null unless the caller supplied the complete file and at least one exact supported encoding was found. */
export function buildPicobinRiscvDecoderView(
  imageBytes: Uint8Array,
  fileSize: number,
  mapping: PicobinDecoderViewMapping,
): PicobinDecoderView | null {
  if (
    imageBytes.byteLength !== fileSize ||
    mapping.entryFileOffset < 0 ||
    mapping.entryFileOffset >= fileSize ||
    mapping.mappedRuntimeEnd <= mapping.entryPoint
  ) {
    return null;
  }
  const runtimeBytes = mapping.mappedRuntimeEnd - mapping.entryPoint;
  const end = Math.min(
    fileSize,
    mapping.entryFileOffset + DECODER_WINDOW_BYTES,
    mapping.entryFileOffset + runtimeBytes,
  );
  const patched = Uint8Array.from(imageBytes);
  const substitutions: PicobinDecoderSubstitution[] = [];
  let offset = mapping.entryFileOffset;
  for (; offset + 4 <= end && substitutions.length < SUBSTITUTION_CAP; offset += 2) {
    const word = readWord(imageBytes, offset);
    const definition = supported.find((candidate) => (word & OPCODE_MASK) >>> 0 === candidate.match);
    if (!definition) continue;
    substitutions.push({
      address: mapping.entryPoint + (offset - mapping.entryFileOffset),
      fileOffset: offset,
      instruction: definition.instruction,
      originalBytesHex: wordHex(imageBytes, offset),
    });
    writeWord(patched, offset, RISCV_NOP);
    offset += 2;
  }
  if (substitutions.length === 0) return null;
  return { bytes: patched, substitutions, bytesExamined: end - mapping.entryFileOffset };
}

/** Restore an exact source mnemonic without pretending to recover register values from radare2's NOP view. */
export function restoredPicobinOpcode(substitution: PicobinDecoderSubstitution): string {
  const word = Number.parseInt(substitution.originalBytesHex.match(/../g)?.reverse().join('') ?? '', 16);
  const rd = (word >>> 7) & 0x1f;
  const rs1 = (word >>> 15) & 0x1f;
  const rs2 = (word >>> 20) & 0x1f;
  return `${substitution.instruction} x${rd}, x${rs1}, x${rs2}`;
}
