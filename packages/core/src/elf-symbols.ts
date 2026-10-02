/**
 * Bounded, byte-only ELF static symbol reader — the real symbol source the FreeRTOS task snapshot has been missing.
 *
 * `rtos-tasks.ts` walks kernel lists only from addresses it is handed, and the API's snapshot contract takes those
 * addresses from the operator. This module reads them out of the firmware's own ELF: header identity (class →
 * pointer width, `EI_DATA` → byte order, `e_machine`), the section header table, every `SHT_SYMTAB` with the string
 * table its `sh_link` names, and — labelled separately, never mixed into resolution — any `SHT_DYNSYM`. Local
 * (`STB_LOCAL`) symbols are kept on purpose: `tasks.c` declares its kernel lists `static`, so a reader that kept only
 * globals would report the lists missing from every image that has them.
 *
 * What it refuses to claim:
 *
 *  - **A symbol is a link-time fact, not a runtime one.** An address here says where the linker placed an object in
 *    an `ET_EXEC` image. It is not proof the kernel ran, that a RAM snapshot was taken from this build, or that the
 *    object holds anything. Nothing in this module is runtime proof. For `ET_REL` the value is an offset inside its
 *    section and for `ET_DYN` it is relative to an unknown load base, so neither is reported as an address.
 *  - **Absence of a symbol is not absence of the kernel.** A stripped image has no `SHT_SYMTAB`, and that is reported
 *    as its own verdict (`no-static-symbol-table`) — not as "not FreeRTOS". A name not found while a cap dropped
 *    symbols, a table was unreadable or a name could not be read is `not-examined`, never `absent`.
 *  - **No layout is inferred from a size.** `pxReadyTasksLists`' `st_size` is `configMAX_PRIORITIES × sizeof(List_t)`
 *    on the build that produced it, but `sizeof(List_t)` depends on `TickType_t` width and integrity-check bytes this
 *    module cannot see, so it reports the raw size and derives no stride, no priority count and no per-priority
 *    address. The snapshot's per-priority `readyLists` are deliberately NOT produced here; the pre-fill carries only
 *    the array's address and raw `st_size`, for the operator to pair with the two numbers they declare, and the
 *    snapshot API then uses `st_size` as a cross-check of that declaration, never as its source.
 *  - **Duplicate names are not resolved by order.** Two `static` objects with one name in two units are two
 *    definitions; the result is `ambiguous` with every candidate, never the first one in table order.
 *  - **The SMP kernel is not the single-core kernel.** `pxCurrentTCBs` (an array, one per core) is reported as its
 *    own SMP variant and never mapped onto `pxCurrentTCB`.
 *
 * Malformed input never throws: an unreadable header or section table is a structured refusal naming the reason; an
 * unreadable symbol table is refused on its own while the others are still read. Bounds are explicit — sections,
 * symbols and program headers are examined in their table index order up to a cap, and every cap reports how many
 * entries it dropped. Values above 2^53 are kept exactly as hex and given no lossy number. Pure: no I/O, no deps.
 */

// === Public shapes ========================================================================================

export type ElfRefusalCode =
  | 'invalid-options'
  | 'not-elf'
  | 'unsupported-class'
  | 'unsupported-encoding'
  | 'truncated-header'
  | 'bad-section-entry-size'
  | 'section-table-out-of-range';

export interface ElfRefusal {
  status: 'refused';
  code: ElfRefusalCode;
  detail: string;
}

/** How a symbol value relates to a target address, from `e_type`. Only `absolute` values are addresses. */
export type ElfAddressBasis = 'absolute' | 'load-base-relative' | 'section-relative' | 'unknown';

export interface ElfIdentity {
  elfClass: 'elf32' | 'elf64';
  pointerWidth: 4 | 8;
  endian: 'little' | 'big';
  machine: number;
  /** A label for a few well-known `e_machine` values; absent when the number is not in the small table. */
  machineName?: string;
  /** Raw `e_type`. */
  type: number;
  addressBasis: ElfAddressBasis;
}

export type ElfSymbolTableKind = 'symtab' | 'dynsym';

export type ElfTableRefusalCode =
  | 'symbol-table-out-of-range'
  | 'bad-symbol-entry-size'
  | 'string-table-index-out-of-range'
  | 'string-table-wrong-type'
  | 'string-table-out-of-range';

export interface ElfSymbolTable {
  kind: ElfSymbolTableKind;
  sectionIndex: number;
  sectionName: string | null;
  stringTableIndex: number;
  status: 'read' | 'refused';
  refusal?: { code: ElfTableRefusalCode; detail: string };
  /** Entries the table declares, excluding the reserved null symbol at index 0. */
  entries: number;
  examined: number;
  /** Entries not examined because the symbol cap was reached (table index order). */
  dropped: number;
  /** Symbols whose `st_name` points outside the string table or reaches its end without a terminator. */
  unreadableNames: number;
  /** Bytes after the last whole entry, when `sh_size` is not a multiple of `sh_entsize`. */
  trailingBytes: number;
}

export type ElfSymbolBinding = 'local' | 'global' | 'weak' | 'other';
export type ElfSymbolType = 'notype' | 'object' | 'func' | 'section' | 'file' | 'common' | 'tls' | 'other';
export type ElfSectionRef = 'undefined' | 'absolute' | 'common' | 'xindex' | 'reserved' | 'regular';

export interface ElfSymbol {
  table: ElfSymbolTableKind;
  tableSectionIndex: number;
  /** Index inside its table. */
  index: number;
  name: string;
  /** `st_value` as a number when it is at most 2^53 - 1, otherwise null; `valueHex` is always exact. */
  value: number | null;
  valueHex: string;
  size: number | null;
  sizeHex: string;
  binding: ElfSymbolBinding;
  bindingRaw: number;
  type: ElfSymbolType;
  typeRaw: number;
  /** Raw `st_shndx`. */
  sectionIndex: number;
  sectionRef: ElfSectionRef;
}

export interface ElfSegment {
  /** Index in the program header table. */
  index: number;
  vaddr: number;
  vaddrHex: string;
  memsz: number;
  filesz: number;
  offset: number;
  flags: { read: boolean; write: boolean; execute: boolean };
}

export type ElfSymbolsVerdict =
  | 'symbols-read'
  | 'no-section-headers'
  | 'no-static-symbol-table'
  | 'sections-not-examined'
  | 'static-symbol-table-unreadable';

export interface ElfSymbolsCoverage {
  sectionsDeclared: number;
  sectionsExamined: number;
  sectionsDropped: number;
  symbolsDeclared: number;
  symbolsExamined: number;
  symbolsDropped: number;
  programHeaders: 'read' | 'absent' | 'out-of-range' | 'bad-entry-size';
  programHeadersDeclared: number;
  programHeadersDropped: number;
  maxSections: number;
  maxSymbols: number;
  maxProgramHeaders: number;
  statement: string;
}

export interface ElfSymbolsParsed {
  status: 'parsed';
  identity: ElfIdentity;
  verdict: ElfSymbolsVerdict;
  tables: ElfSymbolTable[];
  /** Static (`symtab`) symbols first, then `dynsym`, each in section order and then table index order. */
  symbols: ElfSymbol[];
  /** `PT_LOAD` segments only. */
  segments: ElfSegment[];
  coverage: ElfSymbolsCoverage;
}

export type ElfSymbolsResult = ElfSymbolsParsed | ElfRefusal;

export interface ElfSymbolOptions {
  /** Section headers examined, in index order. Default 4096. */
  maxSections?: number;
  /** Symbols examined across all tables (static tables first). Default 100000. */
  maxSymbols?: number;
  /** Program headers examined, in index order. Default 256. */
  maxProgramHeaders?: number;
}

export const DEFAULT_ELF_MAX_SECTIONS = 4096;
export const DEFAULT_ELF_MAX_SYMBOLS = 100_000;
export const DEFAULT_ELF_MAX_PROGRAM_HEADERS = 256;

// === Constants from the ELF specification =================================================================

const SHT_SYMTAB = 2;
const SHT_STRTAB = 3;
const SHT_DYNSYM = 11;
const PT_LOAD = 1;
const SHN_UNDEF = 0;
const SHN_LORESERVE = 0xff00;
const SHN_ABS = 0xfff1;
const SHN_COMMON = 0xfff2;
const SHN_XINDEX = 0xffff;
const PN_XNUM = 0xffff;
const ET_REL = 1;
const ET_EXEC = 2;
const ET_DYN = 3;

const MACHINE_NAMES: ReadonlyMap<number, string> = new Map([
  [3, 'x86'],
  [8, 'MIPS'],
  [20, 'PowerPC'],
  [40, 'ARM'],
  [62, 'x86-64'],
  [94, 'Xtensa'],
  [183, 'AArch64'],
  [243, 'RISC-V'],
]);

const BINDINGS: readonly ElfSymbolBinding[] = ['local', 'global', 'weak'];
const TYPES: readonly ElfSymbolType[] = ['notype', 'object', 'func', 'section', 'file', 'common', 'tls'];

interface ClassLayout {
  ehsize: number;
  shentsize: number;
  phentsize: number;
  symsize: number;
}

const ELF32: ClassLayout = { ehsize: 52, shentsize: 40, phentsize: 32, symsize: 16 };
const ELF64: ClassLayout = { ehsize: 64, shentsize: 64, phentsize: 56, symsize: 24 };

// === Reading ==============================================================================================

interface Word {
  /** Null when the value exceeds Number.MAX_SAFE_INTEGER. */
  num: number | null;
  hex: string;
}

/** Every read is range-checked by its caller first; these helpers assume the bytes exist. */
class Reader {
  private readonly view: DataView;
  constructor(
    readonly bytes: Uint8Array,
    private readonly little: boolean,
    readonly wide: boolean,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  u8(o: number): number {
    return this.view.getUint8(o);
  }
  u16(o: number): number {
    return this.view.getUint16(o, this.little);
  }
  u32(o: number): number {
    return this.view.getUint32(o, this.little);
  }
  u64(o: number): Word {
    const lo = this.little ? this.u32(o) : this.u32(o + 4);
    const hi = this.little ? this.u32(o + 4) : this.u32(o);
    const num = hi < 0x200000 ? hi * 0x100000000 + lo : null;
    const hex = hi === 0 ? `0x${lo.toString(16)}` : `0x${hi.toString(16)}${lo.toString(16).padStart(8, '0')}`;
    return { num, hex };
  }
  /** A class-width word: `Elf32_Addr`/`Elf32_Off`/`Elf32_Word` or their 64-bit counterparts. */
  word(o: number): Word {
    if (this.wide) return this.u64(o);
    const v = this.u32(o);
    return { num: v, hex: `0x${v.toString(16)}` };
  }
}

/** Whether `[offset, offset + size)` lies inside a buffer of `length` bytes. Null operands are never in range. */
function inRange(offset: number | null, size: number | null, length: number): boolean {
  return offset !== null && size !== null && offset >= 0 && size >= 0 && offset + size <= length;
}

interface SectionHeader {
  index: number;
  name: number;
  type: number;
  offset: number | null;
  size: number | null;
  link: number;
  info: number;
  entsize: number | null;
}

function readSection(r: Reader, tableOffset: number, entsize: number, index: number): SectionHeader {
  const o = tableOffset + index * entsize;
  if (r.wide) {
    return {
      index,
      name: r.u32(o),
      type: r.u32(o + 4),
      offset: r.u64(o + 24).num,
      size: r.u64(o + 32).num,
      link: r.u32(o + 40),
      info: r.u32(o + 44),
      entsize: r.u64(o + 56).num,
    };
  }
  return {
    index,
    name: r.u32(o),
    type: r.u32(o + 4),
    offset: r.u32(o + 16),
    size: r.u32(o + 20),
    link: r.u32(o + 24),
    info: r.u32(o + 28),
    entsize: r.u32(o + 36),
  };
}

/** A NUL-terminated string inside `[start, end)`, or null when the offset or terminator falls outside it. */
function readCString(bytes: Uint8Array, start: number, end: number, offset: number): string | null {
  const from = start + offset;
  if (offset < 0 || from >= end) return null;
  let s = '';
  for (let i = from; i < end; i++) {
    const b = bytes[i] as number;
    if (b === 0) return s;
    s += String.fromCharCode(b);
  }
  return null;
}

function positiveInt(value: number | undefined, fallback: number): number | null {
  if (value === undefined) return fallback;
  return Number.isInteger(value) && value >= 1 ? value : null;
}

function refuse(code: ElfRefusalCode, detail: string): ElfRefusal {
  return { status: 'refused', code, detail };
}

function addressBasis(type: number): ElfAddressBasis {
  if (type === ET_EXEC) return 'absolute';
  if (type === ET_DYN) return 'load-base-relative';
  if (type === ET_REL) return 'section-relative';
  return 'unknown';
}

function sectionRef(shndx: number): ElfSectionRef {
  if (shndx === SHN_UNDEF) return 'undefined';
  if (shndx === SHN_ABS) return 'absolute';
  if (shndx === SHN_COMMON) return 'common';
  if (shndx === SHN_XINDEX) return 'xindex';
  if (shndx >= SHN_LORESERVE) return 'reserved';
  return 'regular';
}

// === The reader ===========================================================================================

/** Pure: read the identity, symbol tables and loadable segments of an ELF image, under the stated bounds. */
export function readElfSymbols(bytes: Uint8Array, options: ElfSymbolOptions = {}): ElfSymbolsResult {
  const maxSections = positiveInt(options.maxSections, DEFAULT_ELF_MAX_SECTIONS);
  const maxSymbols = positiveInt(options.maxSymbols, DEFAULT_ELF_MAX_SYMBOLS);
  const maxProgramHeaders = positiveInt(options.maxProgramHeaders, DEFAULT_ELF_MAX_PROGRAM_HEADERS);
  if (maxSections === null || maxSymbols === null || maxProgramHeaders === null) {
    return refuse('invalid-options', 'maxSections, maxSymbols and maxProgramHeaders must be positive integers.');
  }

  if (bytes.length < 16 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    return refuse('not-elf', 'The input does not start with the ELF magic 7f 45 4c 46 followed by an identity block.');
  }
  const cls = bytes[4];
  if (cls !== 1 && cls !== 2) return refuse('unsupported-class', `EI_CLASS is ${cls}; only 1 (ELF32) and 2 (ELF64).`);
  const data = bytes[5];
  if (data !== 1 && data !== 2) {
    return refuse('unsupported-encoding', `EI_DATA is ${data}; only 1 (little-endian) and 2 (big-endian).`);
  }
  const wide = cls === 2;
  const layout = wide ? ELF64 : ELF32;
  if (bytes.length < layout.ehsize) {
    return refuse(
      'truncated-header',
      `An ${wide ? 'ELF64' : 'ELF32'} header is ${layout.ehsize} bytes; the input has ${bytes.length}.`,
    );
  }
  const r = new Reader(bytes, data === 1, wide);

  const type = r.u16(16);
  const machine = r.u16(18);
  const phoff = r.word(wide ? 32 : 28).num;
  const shoff = r.word(wide ? 40 : 32).num;
  const phentsize = r.u16(wide ? 54 : 42);
  let phnum = r.u16(wide ? 56 : 44);
  const shentsize = r.u16(wide ? 58 : 46);
  let shnum = r.u16(wide ? 60 : 48);
  let shstrndx = r.u16(wide ? 62 : 50);

  const machineName = MACHINE_NAMES.get(machine);
  const identity: ElfIdentity = {
    elfClass: wide ? 'elf64' : 'elf32',
    pointerWidth: wide ? 8 : 4,
    endian: data === 1 ? 'little' : 'big',
    machine,
    ...(machineName === undefined ? {} : { machineName }),
    type,
    addressBasis: addressBasis(type),
  };

  // --- Section header table ---
  if (shoff === null) return refuse('section-table-out-of-range', 'e_shoff exceeds 2^53 and lies outside any input.');
  const hasSectionTable = shoff !== 0;
  if (hasSectionTable) {
    if (shentsize < layout.shentsize) {
      return refuse(
        'bad-section-entry-size',
        `e_shentsize is ${shentsize}; an ${identity.elfClass} section header is ${layout.shentsize} bytes.`,
      );
    }
    if (!inRange(shoff, shentsize, bytes.length)) {
      return refuse('section-table-out-of-range', `The section header table at ${shoff} lies outside the input.`);
    }
    // Extended numbering: the real counts live in section 0 when the header fields overflow.
    const s0 = readSection(r, shoff, shentsize, 0);
    if (shnum === 0) shnum = s0.size ?? Number.POSITIVE_INFINITY;
    if (shstrndx === SHN_XINDEX) shstrndx = s0.link;
    if (phnum === PN_XNUM) phnum = s0.info;
    if (!inRange(shoff, shnum * shentsize, bytes.length)) {
      return refuse(
        'section-table-out-of-range',
        `${shnum} section header(s) of ${shentsize} bytes at offset ${shoff} run past the ${bytes.length}-byte input.`,
      );
    }
  } else {
    shnum = 0;
  }

  const sectionsExamined = Math.min(shnum, maxSections);
  const sectionsDropped = shnum - sectionsExamined;
  const tableOffset = shoff ?? 0;

  let names: { start: number; end: number } | null = null;
  if (hasSectionTable && shstrndx !== SHN_UNDEF && shstrndx < shnum) {
    const strs = readSection(r, tableOffset, shentsize, shstrndx);
    if (strs.type === SHT_STRTAB && inRange(strs.offset, strs.size, bytes.length)) {
      names = { start: strs.offset as number, end: (strs.offset as number) + (strs.size as number) };
    }
  }
  const sectionName = (s: SectionHeader): string | null =>
    names === null ? null : readCString(bytes, names.start, names.end, s.name);

  const symtabs: SectionHeader[] = [];
  const dynsyms: SectionHeader[] = [];
  for (let i = 0; i < sectionsExamined; i++) {
    const s = readSection(r, tableOffset, shentsize, i);
    if (s.type === SHT_SYMTAB) symtabs.push(s);
    else if (s.type === SHT_DYNSYM) dynsyms.push(s);
  }

  // --- Symbol tables: static first, so the cap never spends its budget on dynsym before the kernel's tables ---
  const tables: ElfSymbolTable[] = [];
  const symbols: ElfSymbol[] = [];
  let budget = maxSymbols;
  let symbolsDeclared = 0;
  for (const [kind, list] of [
    ['symtab', symtabs],
    ['dynsym', dynsyms],
  ] as const) {
    for (const s of list) {
      const table = readTable(r, kind, s, shnum, tableOffset, shentsize, layout, sectionName(s), budget, symbols);
      budget -= table.examined;
      symbolsDeclared += table.entries;
      tables.push(table);
    }
  }
  const symbolsExamined = maxSymbols - budget;

  // --- Program headers (PT_LOAD only) ---
  const segments: ElfSegment[] = [];
  let programHeaders: ElfSymbolsCoverage['programHeaders'] = 'absent';
  let programHeadersDropped = 0;
  if (phoff !== null && phoff !== 0 && phnum > 0) {
    if (phentsize < layout.phentsize) programHeaders = 'bad-entry-size';
    else if (!inRange(phoff, phnum * phentsize, bytes.length)) programHeaders = 'out-of-range';
    else {
      programHeaders = 'read';
      const examined = Math.min(phnum, maxProgramHeaders);
      programHeadersDropped = phnum - examined;
      for (let i = 0; i < examined; i++) {
        const seg = readSegment(r, phoff + i * phentsize, i);
        if (seg !== null) segments.push(seg);
      }
    }
  } else if (phoff === null) {
    programHeaders = 'out-of-range';
  }

  const readable = tables.filter((t) => t.kind === 'symtab' && t.status === 'read');
  let verdict: ElfSymbolsVerdict;
  if (!hasSectionTable) verdict = 'no-section-headers';
  else if (readable.length > 0) verdict = 'symbols-read';
  else if (symtabs.length > 0) verdict = 'static-symbol-table-unreadable';
  else if (sectionsDropped > 0) verdict = 'sections-not-examined';
  else verdict = 'no-static-symbol-table';

  const coverage: ElfSymbolsCoverage = {
    sectionsDeclared: shnum,
    sectionsExamined,
    sectionsDropped,
    symbolsDeclared,
    symbolsExamined,
    symbolsDropped: symbolsDeclared - symbolsExamined,
    programHeaders,
    programHeadersDeclared: phoff !== null && phoff !== 0 ? phnum : 0,
    programHeadersDropped,
    maxSections,
    maxSymbols,
    maxProgramHeaders,
    statement: '',
  };
  coverage.statement = coverageStatement(verdict, coverage, tables);
  return { status: 'parsed', identity, verdict, tables, symbols, segments, coverage };
}

function readTable(
  r: Reader,
  kind: ElfSymbolTableKind,
  s: SectionHeader,
  shnum: number,
  tableOffset: number,
  shentsize: number,
  layout: ClassLayout,
  name: string | null,
  budget: number,
  out: ElfSymbol[],
): ElfSymbolTable {
  const base = { kind, sectionIndex: s.index, sectionName: name, stringTableIndex: s.link };
  const refused = (code: ElfTableRefusalCode, detail: string): ElfSymbolTable => ({
    ...base,
    status: 'refused',
    refusal: { code, detail },
    entries: 0,
    examined: 0,
    dropped: 0,
    unreadableNames: 0,
    trailingBytes: 0,
  });
  const bytes = r.bytes;
  if (s.entsize === null || s.entsize < layout.symsize) {
    return refused('bad-symbol-entry-size', `sh_entsize is ${s.entsize}; a symbol is ${layout.symsize} bytes.`);
  }
  if (!inRange(s.offset, s.size, bytes.length)) {
    return refused(
      'symbol-table-out-of-range',
      `The table's ${s.size} bytes at offset ${s.offset} lie outside the input.`,
    );
  }
  if (s.link === 0 || s.link >= shnum) {
    return refused('string-table-index-out-of-range', `sh_link ${s.link} names no section (there are ${shnum}).`);
  }
  const strs = readSection(r, tableOffset, shentsize, s.link);
  if (strs.type !== SHT_STRTAB) {
    return refused('string-table-wrong-type', `sh_link ${s.link} is section type ${strs.type}, not SHT_STRTAB.`);
  }
  if (!inRange(strs.offset, strs.size, bytes.length)) {
    return refused('string-table-out-of-range', `String table section ${s.link} lies outside the input.`);
  }
  const strStart = strs.offset as number;
  const strEnd = strStart + (strs.size as number);
  const tableStart = s.offset as number;
  const count = Math.floor((s.size as number) / s.entsize);
  const entries = Math.max(0, count - 1);
  const examined = Math.min(entries, Math.max(0, budget));
  let unreadableNames = 0;
  for (let i = 1; i <= examined; i++) {
    const o = tableStart + i * s.entsize;
    const stName = r.u32(o);
    const info = r.wide ? r.u8(o + 4) : r.u8(o + 12);
    const shndx = r.wide ? r.u16(o + 6) : r.u16(o + 14);
    const value = r.wide ? r.u64(o + 8) : r.word(o + 4);
    const size = r.wide ? r.u64(o + 16) : r.word(o + 8);
    const symName = readCString(bytes, strStart, strEnd, stName);
    if (symName === null) {
      unreadableNames++;
      continue;
    }
    const bindingRaw = info >> 4;
    const typeRaw = info & 0xf;
    out.push({
      table: kind,
      tableSectionIndex: s.index,
      index: i,
      name: symName,
      value: value.num,
      valueHex: value.hex,
      size: size.num,
      sizeHex: size.hex,
      binding: BINDINGS[bindingRaw] ?? 'other',
      bindingRaw,
      type: TYPES[typeRaw] ?? 'other',
      typeRaw,
      sectionIndex: shndx,
      sectionRef: sectionRef(shndx),
    });
  }
  return {
    ...base,
    status: 'read',
    entries,
    examined,
    dropped: entries - examined,
    unreadableNames,
    trailingBytes: (s.size as number) - count * s.entsize,
  };
}

function readSegment(r: Reader, o: number, index: number): ElfSegment | null {
  if (r.u32(o) !== PT_LOAD) return null;
  const flagsAt = r.wide ? o + 4 : o + 24;
  const offset = r.wide ? r.u64(o + 8) : r.word(o + 4);
  const vaddr = r.wide ? r.u64(o + 16) : r.word(o + 8);
  const filesz = r.wide ? r.u64(o + 32) : r.word(o + 16);
  const memsz = r.wide ? r.u64(o + 40) : r.word(o + 20);
  if (vaddr.num === null || memsz.num === null || filesz.num === null || offset.num === null) return null;
  const flags = r.u32(flagsAt);
  return {
    index,
    vaddr: vaddr.num,
    vaddrHex: vaddr.hex,
    memsz: memsz.num,
    filesz: filesz.num,
    offset: offset.num,
    flags: { read: (flags & 4) !== 0, write: (flags & 2) !== 0, execute: (flags & 1) !== 0 },
  };
}

function coverageStatement(verdict: ElfSymbolsVerdict, c: ElfSymbolsCoverage, tables: readonly ElfSymbolTable[]) {
  const parts: string[] = [];
  switch (verdict) {
    case 'no-section-headers':
      parts.push('The image has no section header table, so no symbol table can be located.');
      break;
    case 'no-static-symbol-table':
      parts.push('No SHT_SYMTAB section is present: the image is stripped of static symbols.');
      break;
    case 'sections-not-examined':
      parts.push('No SHT_SYMTAB was found among the sections examined, but sections were dropped by the cap.');
      break;
    case 'static-symbol-table-unreadable':
      parts.push('An SHT_SYMTAB is present but could not be read; see each table for the reason.');
      break;
    case 'symbols-read':
      parts.push(`Read ${c.symbolsExamined} of ${c.symbolsDeclared} declared symbol(s).`);
      break;
  }
  if (verdict !== 'symbols-read') {
    parts.push('That is not absence of any kernel and not evidence the image is not FreeRTOS.');
  }
  if (c.sectionsDropped > 0) {
    parts.push(
      `${c.sectionsDropped} of ${c.sectionsDeclared} section header(s) were not examined (cap ${c.maxSections}, index order).`,
    );
  }
  if (c.symbolsDropped > 0) {
    parts.push(
      `${c.symbolsDropped} symbol(s) were not examined (cap ${c.maxSymbols}; static tables first, then table index order).`,
    );
  }
  const unreadable = tables.reduce((n, t) => n + t.unreadableNames, 0);
  if (unreadable > 0) parts.push(`${unreadable} symbol name(s) were unreadable and those symbols are omitted.`);
  if (c.programHeadersDropped > 0) {
    parts.push(`${c.programHeadersDropped} program header(s) were not examined (cap ${c.maxProgramHeaders}).`);
  }
  parts.push('Symbols are link-time facts, never runtime proof.');
  return parts.join(' ');
}

// === Address → segment ===================================================================================

/** Pure: every `PT_LOAD` segment whose memory range contains `address`, and whether the byte is file-backed. */
export function elfSegmentsContaining(
  segments: readonly ElfSegment[],
  address: number,
): { index: number; fileBacked: boolean }[] {
  return segments
    .filter((s) => address >= s.vaddr && address < s.vaddr + s.memsz)
    .map((s) => ({ index: s.index, fileBacked: address < s.vaddr + s.filesz }));
}

// === FreeRTOS kernel symbols =============================================================================

/** The single-core `tasks.c` globals the snapshot API consumes or that locate them. */
export const FREERTOS_KERNEL_SYMBOLS = [
  'pxCurrentTCB',
  'pxReadyTasksLists',
  'xDelayedTaskList1',
  'xDelayedTaskList2',
  'pxDelayedTaskList',
  'pxOverflowDelayedTaskList',
  'xSuspendedTaskList',
  'xPendingReadyList',
  'xTasksWaitingTermination',
  'uxTopReadyPriority',
] as const;

/** SMP-kernel names, reported as their own variant and never mapped onto a single-core name. */
export const FREERTOS_SMP_SYMBOLS = ['pxCurrentTCBs'] as const;

export type FreeRtosKernelSymbolName = (typeof FREERTOS_KERNEL_SYMBOLS)[number] | (typeof FREERTOS_SMP_SYMBOLS)[number];

export type FreeRtosSymbolStatus =
  | 'resolved'
  | 'ambiguous'
  | 'absent'
  | 'not-examined'
  | 'undefined-only'
  | 'unavailable';

export interface FreeRtosSymbolCandidate {
  /** The address, only when the image's address basis is `absolute` and the value fits a number. */
  address: number | null;
  valueHex: string;
  size: number | null;
  sizeHex: string;
  binding: ElfSymbolBinding;
  type: ElfSymbolType;
  sectionIndex: number;
  /** The `PT_LOAD` segments containing the address (empty when there is no address or no segment holds it). */
  segments: { index: number; fileBacked: boolean }[];
  /** Symbol-table entries carrying this same name and value (more than one is a duplicate, not a conflict). */
  entries: number;
}

export interface FreeRtosSymbolResolution {
  name: FreeRtosKernelSymbolName;
  variant: 'single-core' | 'smp';
  status: FreeRtosSymbolStatus;
  /** One candidate when resolved; every distinct definition when ambiguous; none otherwise. */
  candidates: FreeRtosSymbolCandidate[];
  note: string;
}

export interface FreeRtosKernelSymbolsResult {
  /** `refused` and the reader's non-`symbols-read` verdicts pass through unchanged. */
  verdict: 'refused' | ElfSymbolsVerdict;
  addressBasis: ElfAddressBasis | null;
  /** True when every static symbol was examined with a readable name, so a missing name may be called `absent`. */
  complete: boolean;
  symbols: FreeRtosSymbolResolution[];
  /** Whether any SMP-variant name resolved: the image may be an SMP kernel, which the snapshot API does not walk. */
  smpVariantPresent: boolean;
}

/** Pure: resolve the FreeRTOS kernel globals from a `readElfSymbols` result, using `SHT_SYMTAB` symbols only. */
export function resolveFreeRtosKernelSymbols(elf: ElfSymbolsResult): FreeRtosKernelSymbolsResult {
  const all: { name: FreeRtosKernelSymbolName; variant: 'single-core' | 'smp' }[] = [
    ...FREERTOS_KERNEL_SYMBOLS.map((name) => ({ name, variant: 'single-core' as const })),
    ...FREERTOS_SMP_SYMBOLS.map((name) => ({ name, variant: 'smp' as const })),
  ];
  if (elf.status === 'refused' || elf.verdict !== 'symbols-read') {
    const why =
      elf.status === 'refused'
        ? `The ELF was refused (${elf.code}): ${elf.detail}`
        : `No static symbol table could be read (${elf.verdict}).`;
    return {
      verdict: elf.status === 'refused' ? 'refused' : elf.verdict,
      addressBasis: elf.status === 'refused' ? null : elf.identity.addressBasis,
      complete: false,
      symbols: all.map(({ name, variant }) => ({
        name,
        variant,
        status: 'unavailable',
        candidates: [],
        note: `${why} This says nothing about whether the image runs FreeRTOS.`,
      })),
      smpVariantPresent: false,
    };
  }

  const basis = elf.identity.addressBasis;
  const symtabs = elf.tables.filter((t) => t.kind === 'symtab');
  const complete =
    elf.coverage.sectionsDropped === 0 &&
    symtabs.every((t) => t.status === 'read' && t.dropped === 0 && t.unreadableNames === 0);
  const byName = new Map<string, ElfSymbol[]>();
  for (const s of elf.symbols) {
    if (s.table !== 'symtab') continue;
    const list = byName.get(s.name);
    if (list) list.push(s);
    else byName.set(s.name, [s]);
  }

  const symbols = all.map(({ name, variant }): FreeRtosSymbolResolution => {
    const matches = byName.get(name) ?? [];
    const defs = matches.filter((s) => s.sectionRef !== 'undefined');
    if (defs.length === 0) {
      if (matches.length > 0) {
        return {
          name,
          variant,
          status: 'undefined-only',
          candidates: [],
          note: 'Only undefined references to this name are present; a reference is not a definition.',
        };
      }
      return complete
        ? {
            name,
            variant,
            status: 'absent',
            candidates: [],
            note: 'Not in any static symbol table. That is not evidence the kernel is absent: a build may rename or omit it.',
          }
        : {
            name,
            variant,
            status: 'not-examined',
            candidates: [],
            note: 'Not found, but some symbols were not examined or had unreadable names, so this is undecided.',
          };
    }
    const byValue = new Map<string, ElfSymbol[]>();
    for (const d of defs) {
      const list = byValue.get(d.valueHex);
      if (list) list.push(d);
      else byValue.set(d.valueHex, [d]);
    }
    const candidates = [...byValue.values()].map((group) => candidate(group, basis, elf.segments));
    if (candidates.length > 1) {
      return {
        name,
        variant,
        status: 'ambiguous',
        candidates,
        note: `${candidates.length} definitions at different values; none is chosen by table order.`,
      };
    }
    const note =
      basis === 'absolute'
        ? 'Link-time address from the static symbol table; not runtime proof.'
        : `The image's values are ${basis}, so no target address is given.`;
    return { name, variant, status: 'resolved', candidates, note };
  });

  return {
    verdict: 'symbols-read',
    addressBasis: basis,
    complete,
    symbols,
    smpVariantPresent: symbols.some(
      (s) => s.variant === 'smp' && (s.status === 'resolved' || s.status === 'ambiguous'),
    ),
  };
}

function candidate(group: readonly ElfSymbol[], basis: ElfAddressBasis, segments: readonly ElfSegment[]) {
  const first = group[0] as ElfSymbol;
  const address = basis === 'absolute' ? first.value : null;
  return {
    address,
    valueHex: first.valueHex,
    size: first.size,
    sizeHex: first.sizeHex,
    binding: first.binding,
    type: first.type,
    sectionIndex: first.sectionIndex,
    segments: address === null ? [] : elfSegmentsContaining(segments, address),
    entries: group.length,
  } satisfies FreeRtosSymbolCandidate;
}

// === Into the snapshot API's symbol contract =============================================================

/**
 * The subset of the API's `RtosTaskSnapshotInput.symbols` (apps/api/src/providers/rtos-tasks.ts) this module can
 * fill honestly. Core cannot import the API, so the shape is restated here; a null means "asked and not resolved",
 * which the API turns into a `missing_symbol` lane.
 */
export interface FreeRtosSnapshotSymbols {
  pxCurrentTCB: number | null;
  delayedLists: { name: 'xDelayedTaskList1' | 'xDelayedTaskList2'; address: number | null }[];
  suspendedList: number | null;
  pendingReadyList: number | null;
  terminatedList: number | null;
  /**
   * `pxReadyTasksLists`' address and raw `st_size` (each null unless the symbol resolved) — never `maxPriorities` or
   * `listSize`, which the operator declares. Optional: a pre-fill persisted by an older build does not carry it.
   */
  readyListArray?: { base: number | null; symbolSize: number | null };
}

export interface FreeRtosSnapshotSymbolsResult {
  symbols: FreeRtosSnapshotSymbols;
  /** Names deliberately not carried into the contract, each with the reason. */
  notCarried: { name: FreeRtosKernelSymbolName; reason: string }[];
}

const READY_LISTS_REASON =
  'Per-priority addresses need sizeof(List_t) and configMAX_PRIORITIES, which this module does not infer; only the ' +
  "array's address and raw st_size are pre-filled, beside the two numbers the operator declares";

/** Pure: the snapshot contract's fields, from resolved symbols only. Ambiguous or missing names become null. */
export function freeRtosSnapshotSymbols(res: FreeRtosKernelSymbolsResult): FreeRtosSnapshotSymbolsResult {
  const addr = (name: FreeRtosKernelSymbolName): number | null => {
    const s = res.symbols.find((x) => x.name === name);
    return s?.status === 'resolved' ? (s.candidates[0]?.address ?? null) : null;
  };
  const pxReady = res.symbols.find((x) => x.name === 'pxReadyTasksLists');
  const readyResolved = pxReady?.status === 'resolved' ? pxReady.candidates[0] : undefined;
  const readySize = readyResolved?.sizeHex;
  return {
    symbols: {
      pxCurrentTCB: addr('pxCurrentTCB'),
      delayedLists: [
        { name: 'xDelayedTaskList1', address: addr('xDelayedTaskList1') },
        { name: 'xDelayedTaskList2', address: addr('xDelayedTaskList2') },
      ],
      suspendedList: addr('xSuspendedTaskList'),
      pendingReadyList: addr('xPendingReadyList'),
      terminatedList: addr('xTasksWaitingTermination'),
      readyListArray: { base: addr('pxReadyTasksLists'), symbolSize: readyResolved?.size ?? null },
    },
    notCarried: [
      {
        name: 'pxReadyTasksLists',
        reason: `${READY_LISTS_REASON}${readySize === undefined ? '.' : `; the array's raw st_size is ${readySize}.`}`,
      },
      {
        name: 'pxDelayedTaskList',
        reason: 'A pointer variable, not a list; which delayed list it points at is a RAM fact.',
      },
      {
        name: 'pxOverflowDelayedTaskList',
        reason: 'A pointer variable, not a list; which delayed list it points at is a RAM fact.',
      },
      { name: 'uxTopReadyPriority', reason: 'A scalar in RAM, not a list; the snapshot contract has no field for it.' },
      {
        name: 'pxCurrentTCBs',
        reason: 'The SMP per-core array; the snapshot contract reads one pxCurrentTCB and has no SMP lane.',
      },
    ],
  };
}
