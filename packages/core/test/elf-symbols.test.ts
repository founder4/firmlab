import { describe, expect, it } from 'vitest';
import {
  type ElfSymbolsParsed,
  type ElfSymbolsResult,
  elfSegmentsContaining,
  freeRtosSnapshotSymbols,
  readElfSymbols,
  resolveFreeRtosKernelSymbols,
} from '../src/elf-symbols.js';

// === A minimal ELF writer: header, PT_LOAD headers, section data, section header table ====================

const STB_LOCAL = 0;
const STB_GLOBAL = 1;
const STB_WEAK = 2;
const STT_OBJECT = 1;
const STT_FUNC = 2;
const SHT_PROGBITS = 1;
const SHT_SYMTAB = 2;
const SHT_STRTAB = 3;
const SHT_DYNSYM = 11;

interface Sym {
  name: string;
  value: number | bigint;
  size?: number;
  bind?: number;
  type?: number;
  shndx?: number;
}

interface Seg {
  vaddr: number;
  memsz: number;
  filesz: number;
  flags: number;
}

interface ElfSpec {
  wide: boolean;
  little: boolean;
  machine: number;
  type?: number;
  symtabs?: Sym[][];
  dynsym?: Sym[];
  segments?: Seg[];
  /** Extra PROGBITS sections placed BEFORE the symbol tables. */
  padSections?: number;
}

interface Built {
  bytes: Uint8Array;
  shoff: number;
  shentsize: number;
  /** Section index of each symtab, in order. */
  symtabIndex: number[];
  /** File offset of each symtab's data, in order. */
  symtabDataOffset: number[];
}

function buildElf(spec: ElfSpec): Built {
  const { wide, little } = spec;
  const ehsize = wide ? 64 : 52;
  const phentsize = wide ? 56 : 32;
  const shentsize = wide ? 64 : 40;
  const symsize = wide ? 24 : 16;
  const segments = spec.segments ?? [];

  interface Sec {
    name: string;
    type: number;
    data: Uint8Array;
    link: number;
    entsize: number;
    info: number;
  }
  const sections: Sec[] = [{ name: '', type: 0, data: new Uint8Array(0), link: 0, entsize: 0, info: 0 }];
  const shstr: string[] = [''];
  const shstrOffset = (n: string) => {
    let off = 0;
    for (const s of shstr) {
      if (s === n) return off;
      off += s.length + 1;
    }
    shstr.push(n);
    return off;
  };

  const strtab = (names: string[]) => {
    const offsets: number[] = [];
    let text = '\u0000';
    for (const n of names) {
      offsets.push(text.length);
      text += `${n}\u0000`;
    }
    return { data: Uint8Array.from(text, (c) => c.charCodeAt(0)), offsets };
  };
  const symData = (syms: Sym[], nameOffsets: number[]) => {
    const buf = new Uint8Array(symsize * (syms.length + 1));
    const v = new DataView(buf.buffer);
    syms.forEach((s, k) => {
      const o = (k + 1) * symsize;
      const info = ((s.bind ?? STB_GLOBAL) << 4) | (s.type ?? STT_OBJECT);
      v.setUint32(o, nameOffsets[k] as number, little);
      if (wide) {
        v.setUint8(o + 4, info);
        v.setUint16(o + 6, s.shndx ?? 1, little);
        v.setBigUint64(o + 8, BigInt(s.value), little);
        v.setBigUint64(o + 16, BigInt(s.size ?? 4), little);
      } else {
        v.setUint32(o + 4, Number(s.value), little);
        v.setUint32(o + 8, s.size ?? 4, little);
        v.setUint8(o + 12, info);
        v.setUint16(o + 14, s.shndx ?? 1, little);
      }
    });
    return buf;
  };

  for (let k = 0; k < (spec.padSections ?? 0); k++) {
    sections.push({ name: `.pad${k}`, type: SHT_PROGBITS, data: new Uint8Array(4), link: 0, entsize: 0, info: 0 });
  }
  const symtabIndex: number[] = [];
  for (const [k, syms] of (spec.symtabs ?? []).entries()) {
    const st = strtab(syms.map((s) => s.name));
    sections.push({ name: `.strtab${k}`, type: SHT_STRTAB, data: st.data, link: 0, entsize: 0, info: 0 });
    symtabIndex.push(sections.length);
    sections.push({
      name: `.symtab${k}`,
      type: SHT_SYMTAB,
      data: symData(syms, st.offsets),
      link: sections.length - 1,
      entsize: symsize,
      info: 1,
    });
  }
  if (spec.dynsym) {
    const st = strtab(spec.dynsym.map((s) => s.name));
    sections.push({ name: '.dynstr', type: SHT_STRTAB, data: st.data, link: 0, entsize: 0, info: 0 });
    sections.push({
      name: '.dynsym',
      type: SHT_DYNSYM,
      data: symData(spec.dynsym, st.offsets),
      link: sections.length - 1,
      entsize: symsize,
      info: 1,
    });
  }
  const shstrndx = sections.length;
  for (const s of sections) shstrOffset(s.name);
  shstrOffset('.shstrtab');
  const shstrData = strtab(shstr.slice(1));
  sections.push({ name: '.shstrtab', type: SHT_STRTAB, data: shstrData.data, link: 0, entsize: 0, info: 0 });

  // Layout: header | phdrs | section data... | shdrs
  let cursor = ehsize + phentsize * segments.length;
  const dataOffsets = sections.map((s) => {
    const at = cursor;
    cursor += s.data.length;
    cursor = (cursor + 7) & ~7;
    return at;
  });
  const shoff = cursor;
  const total = shoff + shentsize * sections.length;
  const bytes = new Uint8Array(total);
  const v = new DataView(bytes.buffer);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, wide ? 2 : 1, little ? 1 : 2, 1]);
  v.setUint16(16, spec.type ?? 2, little);
  v.setUint16(18, spec.machine, little);
  v.setUint32(20, 1, little);
  const phoff = segments.length > 0 ? ehsize : 0;
  if (wide) {
    v.setBigUint64(32, BigInt(phoff), little);
    v.setBigUint64(40, BigInt(shoff), little);
    v.setUint16(52, ehsize, little);
    v.setUint16(54, phentsize, little);
    v.setUint16(56, segments.length, little);
    v.setUint16(58, shentsize, little);
    v.setUint16(60, sections.length, little);
    v.setUint16(62, shstrndx, little);
  } else {
    v.setUint32(28, phoff, little);
    v.setUint32(32, shoff, little);
    v.setUint16(40, ehsize, little);
    v.setUint16(42, phentsize, little);
    v.setUint16(44, segments.length, little);
    v.setUint16(46, shentsize, little);
    v.setUint16(48, sections.length, little);
    v.setUint16(50, shstrndx, little);
  }
  segments.forEach((s, k) => {
    const o = ehsize + k * phentsize;
    v.setUint32(o, 1, little);
    if (wide) {
      v.setUint32(o + 4, s.flags, little);
      v.setBigUint64(o + 16, BigInt(s.vaddr), little);
      v.setBigUint64(o + 32, BigInt(s.filesz), little);
      v.setBigUint64(o + 40, BigInt(s.memsz), little);
    } else {
      v.setUint32(o + 8, s.vaddr, little);
      v.setUint32(o + 16, s.filesz, little);
      v.setUint32(o + 20, s.memsz, little);
      v.setUint32(o + 24, s.flags, little);
    }
  });
  sections.forEach((s, k) => {
    bytes.set(s.data, dataOffsets[k] as number);
    const o = shoff + k * shentsize;
    v.setUint32(o, k === 0 ? 0 : shstrOffset(s.name), little);
    v.setUint32(o + 4, s.type, little);
    if (wide) {
      v.setBigUint64(o + 24, BigInt(dataOffsets[k] as number), little);
      v.setBigUint64(o + 32, BigInt(s.data.length), little);
      v.setUint32(o + 40, s.link, little);
      v.setUint32(o + 44, s.info, little);
      v.setBigUint64(o + 56, BigInt(s.entsize), little);
    } else {
      v.setUint32(o + 16, dataOffsets[k] as number, little);
      v.setUint32(o + 20, s.data.length, little);
      v.setUint32(o + 24, s.link, little);
      v.setUint32(o + 28, s.info, little);
      v.setUint32(o + 36, s.entsize, little);
    }
  });
  return {
    bytes,
    shoff,
    shentsize,
    symtabIndex,
    symtabDataOffset: symtabIndex.map((i) => dataOffsets[i] as number),
  };
}

/** Patch a section header field (offset within the header) with a 32-bit value. */
function patchShdr32(b: Built, index: number, field: number, value: number, little: boolean) {
  new DataView(b.bytes.buffer).setUint32(b.shoff + index * b.shentsize + field, value, little);
}

function parsed(r: ElfSymbolsResult): ElfSymbolsParsed {
  if (r.status !== 'parsed') throw new Error(`expected a parse, got ${r.code}: ${r.detail}`);
  return r;
}

/** The FreeRTOS globals a Cortex-M build places in RAM; the kernel lists are `static` (local) in tasks.c. */
const FREERTOS_SYMS: Sym[] = [
  { name: 'pxCurrentTCB', value: 0x20000010, size: 4, bind: STB_GLOBAL },
  { name: 'pxReadyTasksLists', value: 0x20000100, size: 0xa0, bind: STB_LOCAL },
  { name: 'xDelayedTaskList1', value: 0x200001a0, size: 0x14, bind: STB_LOCAL },
  { name: 'xDelayedTaskList2', value: 0x200001b4, size: 0x14, bind: STB_LOCAL },
  { name: 'pxDelayedTaskList', value: 0x200001c8, size: 4, bind: STB_LOCAL },
  { name: 'pxOverflowDelayedTaskList', value: 0x200001cc, size: 4, bind: STB_LOCAL },
  { name: 'xSuspendedTaskList', value: 0x200001d0, size: 0x14, bind: STB_LOCAL },
  { name: 'xPendingReadyList', value: 0x200001e4, size: 0x14, bind: STB_LOCAL },
  { name: 'xTasksWaitingTermination', value: 0x200001f8, size: 0x14, bind: STB_LOCAL },
  { name: 'uxTopReadyPriority', value: 0x2000020c, size: 4, bind: STB_LOCAL },
  { name: 'vTaskStartScheduler', value: 0x08000401, size: 0x80, bind: STB_GLOBAL, type: STT_FUNC },
  { name: 'vApplicationIdleHook', value: 0, size: 0, bind: STB_WEAK, shndx: 0 },
];

const CORTEX_M_SEGMENTS: Seg[] = [
  { vaddr: 0x08000000, memsz: 0x10000, filesz: 0x10000, flags: 5 },
  { vaddr: 0x20000000, memsz: 0x1000, filesz: 0x10, flags: 6 },
];

describe('readElfSymbols', () => {
  it('ELF32 LE ARM: identity, local and global symbols with exact values, segments', () => {
    const r = parsed(
      readElfSymbols(
        buildElf({ wide: false, little: true, machine: 40, symtabs: [FREERTOS_SYMS], segments: CORTEX_M_SEGMENTS })
          .bytes,
      ),
    );
    expect(r.identity).toEqual({
      elfClass: 'elf32',
      pointerWidth: 4,
      endian: 'little',
      machine: 40,
      machineName: 'ARM',
      type: 2,
      addressBasis: 'absolute',
    });
    expect(r.verdict).toBe('symbols-read');
    const by = (n: string) => r.symbols.find((s) => s.name === n);
    expect(by('pxCurrentTCB')).toMatchObject({
      table: 'symtab',
      value: 0x20000010,
      valueHex: '0x20000010',
      size: 4,
      binding: 'global',
      type: 'object',
      sectionIndex: 1,
      sectionRef: 'regular',
    });
    expect(by('pxReadyTasksLists')).toMatchObject({ value: 0x20000100, size: 0xa0, binding: 'local' });
    expect(by('vTaskStartScheduler')).toMatchObject({ value: 0x08000401, type: 'func' });
    expect(by('vApplicationIdleHook')).toMatchObject({ binding: 'weak', sectionRef: 'undefined' });
    expect(r.segments.map((s) => [s.vaddr, s.flags])).toEqual([
      [0x08000000, { read: true, write: false, execute: true }],
      [0x20000000, { read: true, write: true, execute: false }],
    ]);
    expect(r.tables).toEqual([
      expect.objectContaining({ kind: 'symtab', sectionName: '.symtab0', status: 'read', entries: 12, dropped: 0 }),
    ]);
    expect(r.coverage).toMatchObject({ symbolsDeclared: 12, symbolsExamined: 12, symbolsDropped: 0 });
    expect(r.coverage.statement).toMatch(/never runtime proof/);
  });

  it('ELF32 BE MIPS: big-endian fields decode to the same exact values', () => {
    const syms: Sym[] = [
      { name: 'pxCurrentTCB', value: 0x80401234, size: 4, bind: STB_GLOBAL },
      { name: 'xPendingReadyList', value: 0x80405678, size: 0x14, bind: STB_LOCAL },
    ];
    const r = parsed(readElfSymbols(buildElf({ wide: false, little: false, machine: 8, symtabs: [syms] }).bytes));
    expect(r.identity).toMatchObject({ elfClass: 'elf32', endian: 'big', machine: 8, machineName: 'MIPS' });
    expect(r.symbols.map((s) => [s.name, s.valueHex, s.binding])).toEqual([
      ['pxCurrentTCB', '0x80401234', 'global'],
      ['xPendingReadyList', '0x80405678', 'local'],
    ]);
  });

  it('ELF64 LE: 64-bit values are exact, and one above 2^53 keeps its hex and gets no lossy number', () => {
    const syms: Sym[] = [
      { name: 'pxCurrentTCB', value: 0x4000_0000_0010n, size: 8, bind: STB_GLOBAL },
      { name: 'xSuspendedTaskList', value: 0x4000_0000_0100n, size: 0x28, bind: STB_LOCAL },
      { name: 'huge', value: 0xffff_ffff_8000_0000n, size: 8 },
    ];
    const r = parsed(readElfSymbols(buildElf({ wide: true, little: true, machine: 183, symtabs: [syms] }).bytes));
    expect(r.identity).toMatchObject({ elfClass: 'elf64', pointerWidth: 8, endian: 'little', machineName: 'AArch64' });
    expect(r.symbols.map((s) => [s.name, s.value, s.valueHex, s.binding])).toEqual([
      ['pxCurrentTCB', 0x4000_0000_0010, '0x400000000010', 'global'],
      ['xSuspendedTaskList', 0x4000_0000_0100, '0x400000000100', 'local'],
      ['huge', null, '0xffffffff80000000', 'global'],
    ]);
  });

  it('stripped: no SHT_SYMTAB is its own verdict, never "not FreeRTOS"', () => {
    const r = parsed(readElfSymbols(buildElf({ wide: false, little: true, machine: 40, padSections: 2 }).bytes));
    expect(r.verdict).toBe('no-static-symbol-table');
    expect(r.symbols).toEqual([]);
    expect(r.coverage.statement).toMatch(/stripped of static symbols/);
    expect(r.coverage.statement).toMatch(/not evidence the image is not FreeRTOS/);
  });

  it('dynsym is read and labelled separately, and does not count as a static symbol table', () => {
    const r = parsed(
      readElfSymbols(
        buildElf({ wide: false, little: true, machine: 40, dynsym: [{ name: 'pxCurrentTCB', value: 0x1000 }] }).bytes,
      ),
    );
    expect(r.verdict).toBe('no-static-symbol-table');
    expect(r.tables.map((t) => [t.kind, t.sectionName, t.status])).toEqual([['dynsym', '.dynsym', 'read']]);
    expect(r.symbols[0]).toMatchObject({ table: 'dynsym', name: 'pxCurrentTCB' });
    expect(resolveFreeRtosKernelSymbols(r).symbols.find((s) => s.name === 'pxCurrentTCB')?.status).toBe('unavailable');
  });

  it('no section header table is reported as such', () => {
    const b = buildElf({ wide: false, little: true, machine: 40, symtabs: [FREERTOS_SYMS] });
    new DataView(b.bytes.buffer).setUint32(32, 0, true);
    const r = parsed(readElfSymbols(b.bytes));
    expect(r.verdict).toBe('no-section-headers');
    expect(r.coverage.statement).toMatch(/no section header table/);
  });

  it.each([
    ['not-elf', () => new Uint8Array(64)],
    ['not-elf', () => Uint8Array.from([0x7f, 0x45, 0x4c, 0x46])],
    [
      'unsupported-class',
      () => {
        const b = buildElf({ wide: false, little: true, machine: 40 }).bytes;
        b[4] = 3;
        return b;
      },
    ],
    [
      'unsupported-encoding',
      () => {
        const b = buildElf({ wide: false, little: true, machine: 40 }).bytes;
        b[5] = 0;
        return b;
      },
    ],
    ['truncated-header', () => buildElf({ wide: false, little: true, machine: 40 }).bytes.slice(0, 40)],
    ['truncated-header', () => buildElf({ wide: true, little: true, machine: 62 }).bytes.slice(0, 60)],
    [
      'section-table-out-of-range',
      () => {
        const b = buildElf({ wide: false, little: true, machine: 40, symtabs: [FREERTOS_SYMS] });
        return b.bytes.slice(0, b.shoff + b.shentsize * 2);
      },
    ],
    [
      'bad-section-entry-size',
      () => {
        const b = buildElf({ wide: false, little: true, machine: 40 }).bytes;
        new DataView(b.buffer).setUint16(46, 8, true);
        return b;
      },
    ],
  ])('refuses %s with a reason, without throwing', (code, make) => {
    const r = readElfSymbols(make());
    expect(r).toMatchObject({ status: 'refused', code });
    expect(r.status === 'refused' && r.detail.length).toBeGreaterThan(10);
  });

  it('refuses invalid bounds rather than throwing', () => {
    expect(readElfSymbols(new Uint8Array(0), { maxSymbols: 0 })).toMatchObject({ code: 'invalid-options' });
  });

  describe('a malformed symbol table is refused on its own, with the reason', () => {
    const SYMTAB_SH_OFFSET = 16;
    const SYMTAB_SH_LINK = 24;
    const SYMTAB_SH_ENTSIZE = 36;
    const make = () => buildElf({ wide: false, little: true, machine: 40, symtabs: [FREERTOS_SYMS] });

    it.each([
      ['string-table-wrong-type', SYMTAB_SH_LINK, (b: Built) => b.symtabIndex[0] as number],
      ['string-table-index-out-of-range', SYMTAB_SH_LINK, () => 999],
      ['symbol-table-out-of-range', SYMTAB_SH_OFFSET, () => 0x7fff0000],
      ['bad-symbol-entry-size', SYMTAB_SH_ENTSIZE, () => 0],
    ])('%s', (code, field, value) => {
      const b = make();
      patchShdr32(b, b.symtabIndex[0] as number, field, value(b), true);
      const r = parsed(readElfSymbols(b.bytes));
      expect(r.verdict).toBe('static-symbol-table-unreadable');
      expect(r.tables[0]).toMatchObject({ status: 'refused', refusal: { code } });
      const k = resolveFreeRtosKernelSymbols(r);
      expect(k.verdict).toBe('static-symbol-table-unreadable');
      expect(k.symbols.every((s) => s.status === 'unavailable')).toBe(true);
    });

    it('string-table-out-of-range', () => {
      const b = make();
      const strtabIndex = (b.symtabIndex[0] as number) - 1;
      patchShdr32(b, strtabIndex, SYMTAB_SH_OFFSET, 0x7fff0000, true);
      expect(parsed(readElfSymbols(b.bytes)).tables[0]?.refusal?.code).toBe('string-table-out-of-range');
    });

    it('an st_name outside the string table drops that symbol, counts it, and makes absence undecided', () => {
      const b = make();
      // Symbol index 1 is pxCurrentTCB; point its name far past the string table.
      new DataView(b.bytes.buffer).setUint32((b.symtabDataOffset[0] as number) + 16, 0x100000, true);
      const r = parsed(readElfSymbols(b.bytes));
      expect(r.verdict).toBe('symbols-read');
      expect(r.tables[0]?.unreadableNames).toBe(1);
      expect(r.coverage.statement).toMatch(/1 symbol name\(s\) were unreadable/);
      const k = resolveFreeRtosKernelSymbols(r);
      expect(k.complete).toBe(false);
      expect(k.symbols.find((s) => s.name === 'pxCurrentTCB')?.status).toBe('not-examined');
      expect(k.symbols.find((s) => s.name === 'xPendingReadyList')?.status).toBe('resolved');
    });
  });

  it('never throws on mutated or truncated bytes', () => {
    const good = buildElf({
      wide: false,
      little: true,
      machine: 40,
      symtabs: [FREERTOS_SYMS],
      segments: CORTEX_M_SEGMENTS,
    }).bytes;
    let seed = 0x1234;
    const rand = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed;
    };
    for (let n = 0; n < 2000; n++) {
      const b = good.slice(0, n % 3 === 0 ? rand() % good.length : good.length);
      for (let k = 0; k < 4; k++) if (b.length > 0) b[rand() % b.length] = rand() & 0xff;
      expect(() => resolveFreeRtosKernelSymbols(readElfSymbols(b))).not.toThrow();
    }
  });

  describe('caps state what they dropped', () => {
    it('symbols: static tables first, then index order; dropped names are not-examined, not absent', () => {
      const b = buildElf({
        wide: false,
        little: true,
        machine: 40,
        symtabs: [FREERTOS_SYMS],
        dynsym: [{ name: 'x', value: 1 }],
      });
      const r = parsed(readElfSymbols(b.bytes, { maxSymbols: 3 }));
      expect(r.symbols.map((s) => s.name)).toEqual(['pxCurrentTCB', 'pxReadyTasksLists', 'xDelayedTaskList1']);
      expect(r.coverage).toMatchObject({ symbolsDeclared: 13, symbolsExamined: 3, symbolsDropped: 10 });
      expect(r.tables.map((t) => [t.kind, t.examined, t.dropped])).toEqual([
        ['symtab', 3, 9],
        ['dynsym', 0, 1],
      ]);
      expect(r.coverage.statement).toMatch(/10 symbol\(s\) were not examined \(cap 3; static tables first/);
      const k = resolveFreeRtosKernelSymbols(r);
      expect(k.complete).toBe(false);
      expect(k.symbols.find((s) => s.name === 'pxCurrentTCB')?.status).toBe('resolved');
      expect(k.symbols.find((s) => s.name === 'xTasksWaitingTermination')?.status).toBe('not-examined');
    });

    it('sections: a symbol table beyond the cap is not reported as stripped', () => {
      const b = buildElf({ wide: false, little: true, machine: 40, padSections: 5, symtabs: [FREERTOS_SYMS] });
      const r = parsed(readElfSymbols(b.bytes, { maxSections: 4 }));
      expect(r.verdict).toBe('sections-not-examined');
      expect(r.coverage.sectionsDropped).toBe(r.coverage.sectionsDeclared - 4);
      expect(r.coverage.statement).toMatch(/section header\(s\) were not examined \(cap 4, index order\)/);
      expect(r.coverage.statement).toMatch(/not evidence the image is not FreeRTOS/);
    });

    it('program headers', () => {
      const b = buildElf({ wide: false, little: true, machine: 40, symtabs: [[]], segments: CORTEX_M_SEGMENTS });
      const r = parsed(readElfSymbols(b.bytes, { maxProgramHeaders: 1 }));
      expect(r.segments.map((s) => s.index)).toEqual([0]);
      expect(r.coverage).toMatchObject({ programHeadersDeclared: 2, programHeadersDropped: 1 });
      expect(r.coverage.statement).toMatch(/1 program header\(s\) were not examined \(cap 1\)/);
    });
  });
});

describe('elfSegmentsContaining', () => {
  it('separates file-backed bytes from zero-initialised memory, and misses outside every segment', () => {
    const r = parsed(
      readElfSymbols(buildElf({ wide: false, little: true, machine: 40, segments: CORTEX_M_SEGMENTS }).bytes),
    );
    expect(elfSegmentsContaining(r.segments, 0x20000004)).toEqual([{ index: 1, fileBacked: true }]);
    expect(elfSegmentsContaining(r.segments, 0x20000100)).toEqual([{ index: 1, fileBacked: false }]);
    expect(elfSegmentsContaining(r.segments, 0x30000000)).toEqual([]);
  });
});

describe('resolveFreeRtosKernelSymbols', () => {
  const cortexM = () =>
    parsed(
      readElfSymbols(
        buildElf({ wide: false, little: true, machine: 40, symtabs: [FREERTOS_SYMS], segments: CORTEX_M_SEGMENTS })
          .bytes,
      ),
    );

  it('resolves every single-core global with address, size, binding and segment', () => {
    const k = resolveFreeRtosKernelSymbols(cortexM());
    expect(k).toMatchObject({ verdict: 'symbols-read', addressBasis: 'absolute', complete: true });
    const one = (n: string) => k.symbols.find((s) => s.name === n);
    expect(one('pxCurrentTCB')).toMatchObject({
      status: 'resolved',
      variant: 'single-core',
      candidates: [
        {
          address: 0x20000010,
          size: 4,
          binding: 'global',
          type: 'object',
          segments: [{ index: 1, fileBacked: false }],
          entries: 1,
        },
      ],
    });
    expect(one('xTasksWaitingTermination')?.candidates[0]).toMatchObject({ address: 0x200001f8, binding: 'local' });
    // Raw size only: no stride, no priority count.
    expect(one('pxReadyTasksLists')?.candidates[0]).toMatchObject({ address: 0x20000100, size: 0xa0, sizeHex: '0xa0' });
    expect(one('pxCurrentTCBs')).toMatchObject({ variant: 'smp', status: 'absent' });
    expect(one('pxCurrentTCBs')?.note).toMatch(/not evidence the kernel is absent/);
    expect(k.smpVariantPresent).toBe(false);
  });

  it('an undefined reference is not a definition', () => {
    const r = parsed(
      readElfSymbols(
        buildElf({
          wide: false,
          little: true,
          machine: 40,
          symtabs: [[{ name: 'pxCurrentTCB', value: 0, shndx: 0 }]],
        }).bytes,
      ),
    );
    expect(resolveFreeRtosKernelSymbols(r).symbols[0]).toMatchObject({
      name: 'pxCurrentTCB',
      status: 'undefined-only',
    });
  });

  it('duplicates at different addresses are ambiguous with every candidate; same address is one definition', () => {
    const syms: Sym[] = [
      { name: 'xPendingReadyList', value: 0x20000300, bind: STB_LOCAL },
      { name: 'pxCurrentTCB', value: 0x20000010 },
      { name: 'xPendingReadyList', value: 0x20000200, bind: STB_LOCAL },
    ];
    const second: Sym[] = [{ name: 'pxCurrentTCB', value: 0x20000010 }];
    const r = parsed(
      readElfSymbols(buildElf({ wide: false, little: true, machine: 40, symtabs: [syms, second] }).bytes),
    );
    const k = resolveFreeRtosKernelSymbols(r);
    const pending = k.symbols.find((s) => s.name === 'xPendingReadyList');
    expect(pending?.status).toBe('ambiguous');
    expect(pending?.candidates.map((c) => c.address)).toEqual([0x20000300, 0x20000200]);
    expect(pending?.note).toMatch(/none is chosen by table order/);
    const cur = k.symbols.find((s) => s.name === 'pxCurrentTCB');
    expect(cur).toMatchObject({ status: 'resolved', candidates: [{ address: 0x20000010, entries: 2 }] });
    expect(freeRtosSnapshotSymbols(k).symbols.pendingReadyList).toBeNull();
  });

  it('the SMP array is its own variant and never fills pxCurrentTCB', () => {
    const r = parsed(
      readElfSymbols(
        buildElf({
          wide: false,
          little: true,
          machine: 40,
          symtabs: [[{ name: 'pxCurrentTCBs', value: 0x20000020, size: 8 }]],
        }).bytes,
      ),
    );
    const k = resolveFreeRtosKernelSymbols(r);
    expect(k.smpVariantPresent).toBe(true);
    expect(k.symbols.find((s) => s.name === 'pxCurrentTCBs')).toMatchObject({ variant: 'smp', status: 'resolved' });
    expect(k.symbols.find((s) => s.name === 'pxCurrentTCB')?.status).toBe('absent');
    expect(freeRtosSnapshotSymbols(k).symbols.pxCurrentTCB).toBeNull();
  });

  it('a relocatable object has values but no addresses', () => {
    const r = parsed(
      readElfSymbols(
        buildElf({
          wide: false,
          little: true,
          machine: 40,
          type: 1,
          symtabs: [[{ name: 'pxCurrentTCB', value: 0x10 }]],
        }).bytes,
      ),
    );
    const k = resolveFreeRtosKernelSymbols(r);
    expect(k.addressBasis).toBe('section-relative');
    expect(k.symbols[0]).toMatchObject({ status: 'resolved', candidates: [{ address: null, valueHex: '0x10' }] });
    expect(k.symbols[0]?.note).toMatch(/section-relative, so no target address/);
  });

  it('a refusal passes through and claims nothing about FreeRTOS', () => {
    const k = resolveFreeRtosKernelSymbols(readElfSymbols(new Uint8Array(8)));
    expect(k.verdict).toBe('refused');
    expect(k.symbols).toHaveLength(11);
    expect(k.symbols.every((s) => s.status === 'unavailable')).toBe(true);
    expect(k.symbols[0]?.note).toMatch(/says nothing about whether the image runs FreeRTOS/);
  });
});

describe('freeRtosSnapshotSymbols', () => {
  it('fills the snapshot contract from resolved lists, and states what it does not carry', () => {
    const k = resolveFreeRtosKernelSymbols(
      parsed(readElfSymbols(buildElf({ wide: false, little: true, machine: 40, symtabs: [FREERTOS_SYMS] }).bytes)),
    );
    const out = freeRtosSnapshotSymbols(k);
    expect(out.symbols).toEqual({
      pxCurrentTCB: 0x20000010,
      delayedLists: [
        { name: 'xDelayedTaskList1', address: 0x200001a0 },
        { name: 'xDelayedTaskList2', address: 0x200001b4 },
      ],
      suspendedList: 0x200001d0,
      pendingReadyList: 0x200001e4,
      terminatedList: 0x200001f8,
      readyListArray: { base: 0x20000100, symbolSize: 0xa0 },
    });
    expect(out.notCarried.map((n) => n.name)).toEqual([
      'pxReadyTasksLists',
      'pxDelayedTaskList',
      'pxOverflowDelayedTaskList',
      'uxTopReadyPriority',
      'pxCurrentTCBs',
    ]);
    expect(out.notCarried[0]?.reason).toMatch(/two numbers the operator declares; the array's raw st_size is 0xa0\./);
  });

  it('carries an st_size of 0 as null, because ELF defines 0 as no or unknown size', () => {
    const syms = FREERTOS_SYMS.map((s) => (s.name === 'pxReadyTasksLists' ? { ...s, size: 0 } : s));
    const k = resolveFreeRtosKernelSymbols(
      parsed(readElfSymbols(buildElf({ wide: false, little: true, machine: 40, symtabs: [syms] }).bytes)),
    );
    const out = freeRtosSnapshotSymbols(k);
    expect(out.symbols.readyListArray).toEqual({ base: 0x20000100, symbolSize: null });
    expect(out.notCarried[0]?.reason).toMatch(/st_size is 0x0, which ELF defines as no or unknown size/);
  });
});
