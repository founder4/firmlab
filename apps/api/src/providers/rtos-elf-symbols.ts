/**
 * FreeRTOS kernel symbols from the image's own ELF — the address source the RAM-snapshot walk (`rtos-tasks.ts`) was
 * missing. It reads the image's static symbol table with core's `readElfSymbols`, resolves the `tasks.c` globals with
 * `resolveFreeRtosKernelSymbols`, and hands the snapshot form a PRE-FILL built by `freeRtosSnapshotSymbols`, which
 * carries a field only when its symbol resolved to exactly one absolute address.
 *
 * What it refuses to claim, and why it syncs no findings:
 *
 *  - **A symbol is a link-time fact, not runtime proof.** An address says where the linker placed `pxCurrentTCB` in
 *    this build. It does not say the kernel ran, that the operator's RAM snapshot came from this build, or what the
 *    object holds. So nothing here is a finding at any proof state; the walk that consumes it stays
 *    `needs_runtime_reproduction`, and the operator still supplies the RAM.
 *  - **A non-ELF or stripped image is not "no FreeRTOS".** Most MCU images in the corpus are raw `.bin` blobs that
 *    carry no symbol table at all, and a stripped ELF has none either. Both are stated as what they are: a reason the
 *    addresses must come from somewhere else, never a negative about the kernel.
 *  - **No ready list is derived here.** Turning `pxReadyTasksLists`' `st_size` into per-priority addresses needs
 *    `sizeof(List_t)` and `configMAX_PRIORITIES`, and the first depends on a `TickType_t` width and integrity-check
 *    bytes the symbol table cannot show. The pre-fill carries the array's address and raw size only; the operator
 *    declares the two numbers, and the snapshot walk checks the size against them. The reason travels in `notCarried`.
 *
 * The image is read whole or not at all: above `MAX_ELF_FILE_BYTES` the run is refused with the size, because a
 * section table at the end of a file a truncated read never reached would turn "not read" into "stripped".
 */
import fs from 'node:fs';
import {
  DEFAULT_ELF_MAX_PROGRAM_HEADERS,
  DEFAULT_ELF_MAX_SECTIONS,
  DEFAULT_ELF_MAX_SYMBOLS,
  type ElfIdentity,
  type ElfRefusalCode,
  type ElfSymbolTable,
  type ElfSymbolsCoverage,
  type ElfSymbolsVerdict,
  type FreeRtosKernelSymbolName,
  type FreeRtosSnapshotSymbols,
  type FreeRtosSymbolResolution,
  freeRtosSnapshotSymbols,
  readElfSymbols,
  resolveFreeRtosKernelSymbols,
} from '@firmlab/core';

/** Whole-file read cap. MCU ELFs are kilobytes to a few MiB; this bounds a mis-routed multi-GB image. */
export const MAX_ELF_FILE_BYTES = 64 * 1024 * 1024;

export type RtosElfSymbolsVerdict = ElfSymbolsVerdict | 'refused' | 'file-too-large' | 'file-unreadable';

export interface RtosElfSymbolsResult {
  verdict: RtosElfSymbolsVerdict;
  /** One sentence stating what the verdict means and what it does not. */
  summary: string;
  file: { bytes: number | null; maxBytes: number; read: boolean; error?: string };
  /** Core's refusal, when the bytes are not a readable ELF. */
  refusal?: { code: ElfRefusalCode; detail: string };
  identity?: ElfIdentity;
  /** The symbol tables core found, with their own refusal reasons and caps. Symbols themselves are not persisted. */
  tables?: ElfSymbolTable[];
  coverage?: ElfSymbolsCoverage;
  /** True when every static symbol was examined with a readable name, so a missing name may be called `absent`. */
  complete: boolean;
  smpVariantPresent: boolean;
  /** One resolution per kernel name, always all of them, each with its status and reason. */
  symbols: FreeRtosSymbolResolution[];
  /** The snapshot form's fields; null fields are names that did not resolve to one absolute address. */
  prefill: FreeRtosSnapshotSymbols | null;
  notCarried: { name: FreeRtosKernelSymbolName; reason: string }[];
  bounds: { maxFileBytes: number; maxSections: number; maxSymbols: number; maxProgramHeaders: number };
}

const BOUNDS = {
  maxFileBytes: MAX_ELF_FILE_BYTES,
  maxSections: DEFAULT_ELF_MAX_SECTIONS,
  maxSymbols: DEFAULT_ELF_MAX_SYMBOLS,
  maxProgramHeaders: DEFAULT_ELF_MAX_PROGRAM_HEADERS,
};

const LINK_TIME =
  'These are link-time addresses, not runtime proof; the RAM snapshot still has to come from the operator.';
const NOT_A_NEGATIVE = 'This says nothing about whether the image runs FreeRTOS; supply the addresses by hand.';

/** Pure: resolve the FreeRTOS kernel symbols from an image's bytes, and say what the result does and does not mean. */
export function rtosElfSymbolsFromBytes(bytes: Uint8Array, maxFileBytes = MAX_ELF_FILE_BYTES): RtosElfSymbolsResult {
  const elf = readElfSymbols(bytes);
  const kernel = resolveFreeRtosKernelSymbols(elf);
  const snapshot = freeRtosSnapshotSymbols(kernel);
  const file = { bytes: bytes.length, maxBytes: maxFileBytes, read: true };
  const common = {
    file,
    complete: kernel.complete,
    smpVariantPresent: kernel.smpVariantPresent,
    symbols: kernel.symbols,
    notCarried: snapshot.notCarried,
    bounds: { ...BOUNDS, maxFileBytes },
  };
  if (elf.status === 'refused') {
    return {
      ...common,
      verdict: 'refused',
      summary:
        elf.code === 'not-elf'
          ? `The image is not an ELF file, so it carries no symbol table to read. ${NOT_A_NEGATIVE}`
          : `The image could not be read as an ELF (${elf.code}): ${elf.detail} ${NOT_A_NEGATIVE}`,
      refusal: { code: elf.code, detail: elf.detail },
      prefill: null,
    };
  }
  const parsed = {
    ...common,
    verdict: elf.verdict,
    identity: elf.identity,
    tables: elf.tables,
    coverage: elf.coverage,
  };
  if (elf.verdict !== 'symbols-read') {
    return { ...parsed, summary: `${elf.coverage.statement} ${NOT_A_NEGATIVE}`, prefill: null };
  }
  const resolved = kernel.symbols.filter((s) => s.status === 'resolved').length;
  const ambiguous = kernel.symbols.filter((s) => s.status === 'ambiguous').length;
  const basisNote =
    elf.identity.addressBasis === 'absolute'
      ? ''
      : ` Its values are ${elf.identity.addressBasis}, so none is a target address and nothing is pre-filled.`;
  return {
    ...parsed,
    summary: `${resolved} of ${kernel.symbols.length} FreeRTOS kernel name(s) resolved from the static symbol table${ambiguous > 0 ? `, ${ambiguous} ambiguous` : ''}.${basisNote} ${LINK_TIME}`,
    prefill: snapshot.symbols,
  };
}

/** Runner: read the whole image under the cap (refusing above it, never truncating) and resolve. */
export function runRtosElfSymbols(imagePath: string, maxBytes = MAX_ELF_FILE_BYTES): RtosElfSymbolsResult {
  const refusedFile = (
    verdict: 'file-too-large' | 'file-unreadable',
    size: number | null,
    summary: string,
    error?: string,
  ) => {
    const kernel = resolveFreeRtosKernelSymbols({ status: 'refused', code: 'not-elf', detail: summary });
    return {
      verdict,
      summary: `${summary} ${NOT_A_NEGATIVE}`,
      file: { bytes: size, maxBytes, read: false, ...(error === undefined ? {} : { error }) },
      complete: false,
      smpVariantPresent: false,
      symbols: kernel.symbols.map((s) => ({ ...s, note: summary })),
      prefill: null,
      notCarried: freeRtosSnapshotSymbols(kernel).notCarried,
      bounds: { ...BOUNDS, maxFileBytes: maxBytes },
    } satisfies RtosElfSymbolsResult;
  };
  let size: number;
  try {
    size = fs.statSync(imagePath).size;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return refusedFile('file-unreadable', null, 'The image file could not be opened.', msg);
  }
  if (size > maxBytes) {
    return refusedFile(
      'file-too-large',
      size,
      `The image is ${size} bytes, above the ${maxBytes}-byte cap; it was not read, rather than read in part.`,
    );
  }
  let bytes: Uint8Array;
  try {
    bytes = fs.readFileSync(imagePath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return refusedFile('file-unreadable', size, 'The image file could not be read.', msg);
  }
  return rtosElfSymbolsFromBytes(bytes, maxBytes);
}
