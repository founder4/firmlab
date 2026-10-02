import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { MAX_ELF_FILE_BYTES, rtosElfSymbolsFromBytes, runRtosElfSymbols } from './rtos-elf-symbols.js';

interface Sym {
  name: string;
  value: number;
  size?: number;
  /** STB_LOCAL 0, STB_GLOBAL 1. */
  bind?: number;
}

/**
 * A minimal little-endian ELF32 (ARM, e_machine 40) with one SHT_SYMTAB, its string table and a section-name table.
 * `type` is `e_type` (2 = ET_EXEC); `symtab: false` builds the same image stripped of its static symbols.
 */
function elf32(syms: Sym[], opts: { type?: number; symtab?: boolean } = {}): Uint8Array {
  const withSymtab = opts.symtab !== false;
  const strtab = ['', ...syms.map((s) => s.name)].join('\u0000').concat('\u0000');
  const nameOffsets: number[] = [];
  let at = 1;
  for (const s of syms) {
    nameOffsets.push(at);
    at += s.name.length + 1;
  }
  const shstr = '\u0000.strtab\u0000.symtab\u0000.shstrtab\u0000';
  const symtab = new Uint8Array(16 * (syms.length + 1));
  const sv = new DataView(symtab.buffer);
  syms.forEach((s, k) => {
    const o = 16 * (k + 1);
    sv.setUint32(o, nameOffsets[k] as number, true);
    sv.setUint32(o + 4, s.value, true);
    sv.setUint32(o + 8, s.size ?? 4, true);
    sv.setUint8(o + 12, ((s.bind ?? 1) << 4) | 1);
    sv.setUint16(o + 14, 1, true);
  });
  const ascii = (t: string) => Uint8Array.from(t, (c) => c.charCodeAt(0));
  const parts = [ascii(strtab), symtab, ascii(shstr)];
  let cursor = 52;
  const offsets = parts.map((p) => {
    const o = cursor;
    cursor += (p.length + 3) & ~3;
    return o;
  });
  const shoff = cursor;
  // Sections: 0 null, 1 .strtab, 2 .symtab (or a PROGBITS stand-in when stripped), 3 .shstrtab.
  const bytes = new Uint8Array(shoff + 40 * 4);
  const v = new DataView(bytes.buffer);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]);
  v.setUint16(16, opts.type ?? 2, true);
  v.setUint16(18, 40, true);
  v.setUint32(32, shoff, true);
  v.setUint16(46, 40, true);
  v.setUint16(48, 4, true);
  v.setUint16(50, 3, true);
  parts.forEach((p, k) => bytes.set(p, offsets[k] as number));
  const shdr = (i: number, name: number, type: number, k: number, link: number, entsize: number) => {
    const o = shoff + 40 * i;
    v.setUint32(o, name, true);
    v.setUint32(o + 4, type, true);
    v.setUint32(o + 16, offsets[k] as number, true);
    v.setUint32(o + 20, (parts[k] as Uint8Array).length, true);
    v.setUint32(o + 24, link, true);
    v.setUint32(o + 36, entsize, true);
  };
  shdr(1, 1, 3, 0, 0, 0);
  shdr(2, 9, withSymtab ? 2 : 1, 1, 1, 16);
  shdr(3, 17, 3, 2, 0, 0);
  return bytes;
}

const KERNEL: Sym[] = [
  { name: 'pxCurrentTCB', value: 0x20000010, bind: 1 },
  { name: 'pxReadyTasksLists', value: 0x20000100, size: 0xa0, bind: 0 },
  { name: 'xDelayedTaskList1', value: 0x200001a0, size: 0x14, bind: 0 },
  { name: 'xDelayedTaskList2', value: 0x200001b4, size: 0x14, bind: 0 },
  { name: 'xSuspendedTaskList', value: 0x200001d0, size: 0x14, bind: 0 },
  { name: 'xTasksWaitingTermination', value: 0x200001f8, size: 0x14, bind: 0 },
];

describe('rtosElfSymbolsFromBytes', () => {
  it('resolves the kernel globals and pre-fills only resolved fields', () => {
    const r = rtosElfSymbolsFromBytes(elf32(KERNEL));
    expect(r.verdict).toBe('symbols-read');
    expect(r.identity).toMatchObject({ elfClass: 'elf32', endian: 'little', machine: 40, addressBasis: 'absolute' });
    expect(r.complete).toBe(true);
    expect(r.prefill).toEqual({
      pxCurrentTCB: 0x20000010,
      delayedLists: [
        { name: 'xDelayedTaskList1', address: 0x200001a0 },
        { name: 'xDelayedTaskList2', address: 0x200001b4 },
      ],
      suspendedList: 0x200001d0,
      pendingReadyList: null,
      terminatedList: 0x200001f8,
      readyListArray: { base: 0x20000100, symbolSize: 0xa0 },
    });
    expect(r.symbols.find((s) => s.name === 'xPendingReadyList')?.status).toBe('absent');
    expect(r.symbols.find((s) => s.name === 'pxCurrentTCB')?.candidates[0]).toMatchObject({ binding: 'global' });
    expect(r.symbols.find((s) => s.name === 'xSuspendedTaskList')?.candidates[0]).toMatchObject({ binding: 'local' });
    expect(r.notCarried.map((n) => n.name)).toContain('pxReadyTasksLists');
    expect(r.notCarried.find((n) => n.name === 'pxReadyTasksLists')?.reason).toMatch(/raw st_size is 0xa0/);
    expect(r.summary).toMatch(/link-time addresses, not runtime proof/);
    expect(r.bounds).toEqual({
      maxFileBytes: MAX_ELF_FILE_BYTES,
      maxSections: 4096,
      maxSymbols: 100_000,
      maxProgramHeaders: 256,
    });
    // Only the kernel resolutions are persisted on the job row, never the whole symbol table.
    expect(r.symbols).toHaveLength(11);
  });

  it('a duplicate name at two addresses is ambiguous and never pre-filled', () => {
    const r = rtosElfSymbolsFromBytes(
      elf32([
        { name: 'xSuspendedTaskList', value: 0x20000300, bind: 0 },
        { name: 'xSuspendedTaskList', value: 0x20000400, bind: 0 },
      ]),
    );
    const s = r.symbols.find((x) => x.name === 'xSuspendedTaskList');
    expect(s?.status).toBe('ambiguous');
    expect(s?.candidates.map((c) => c.address)).toEqual([0x20000300, 0x20000400]);
    expect(r.prefill?.suspendedList).toBeNull();
    expect(r.summary).toMatch(/1 ambiguous/);
  });

  it('a raw binary is not an ELF, and that is never "no FreeRTOS"', () => {
    const r = rtosElfSymbolsFromBytes(new Uint8Array(4096).fill(0xaa));
    expect(r.verdict).toBe('refused');
    expect(r.refusal?.code).toBe('not-elf');
    expect(r.prefill).toBeNull();
    expect(r.summary).toMatch(/not an ELF file/);
    expect(r.summary).toMatch(/says nothing about whether the image runs FreeRTOS/);
    expect(r.symbols.every((s) => s.status === 'unavailable')).toBe(true);
    expect(r.symbols).toHaveLength(11);
  });

  it('a stripped ELF states its verdict and pre-fills nothing', () => {
    const r = rtosElfSymbolsFromBytes(elf32(KERNEL, { symtab: false }));
    expect(r.verdict).toBe('no-static-symbol-table');
    expect(r.prefill).toBeNull();
    expect(r.summary).toMatch(/stripped of static symbols/);
    expect(r.summary).toMatch(/says nothing about whether the image runs FreeRTOS/);
  });

  it('a relocatable object resolves values but pre-fills no address', () => {
    const r = rtosElfSymbolsFromBytes(elf32(KERNEL, { type: 1 }));
    expect(r.identity?.addressBasis).toBe('section-relative');
    expect(r.prefill?.pxCurrentTCB).toBeNull();
    expect(r.summary).toMatch(/section-relative, so none is a target address and nothing is pre-filled/);
  });
});

describe('runRtosElfSymbols', () => {
  const dirs: string[] = [];
  const write = (bytes: Uint8Array) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rtos-elf-'));
    dirs.push(dir);
    const p = path.join(dir, 'fw.elf');
    fs.writeFileSync(p, bytes);
    return p;
  };
  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  it('reads the whole file under the cap', () => {
    const r = runRtosElfSymbols(write(elf32(KERNEL)));
    expect(r.verdict).toBe('symbols-read');
    expect(r.file).toMatchObject({ read: true, maxBytes: MAX_ELF_FILE_BYTES });
  });

  it('refuses a file above the cap instead of reading part of it', () => {
    const bytes = elf32(KERNEL);
    const r = runRtosElfSymbols(write(bytes), 64);
    expect(r.verdict).toBe('file-too-large');
    expect(r.file).toEqual({ bytes: bytes.length, maxBytes: 64, read: false });
    expect(r.bounds.maxFileBytes).toBe(64);
    expect(r.summary).toMatch(/above the 64-byte cap; it was not read, rather than read in part/);
    expect(r.prefill).toBeNull();
    expect(r.symbols.every((s) => s.status === 'unavailable')).toBe(true);
  });

  it('a missing file is unreadable, with the error', () => {
    const r = runRtosElfSymbols(path.join(os.tmpdir(), 'firmlab-no-such-image.elf'));
    expect(r.verdict).toBe('file-unreadable');
    expect(r.file.read).toBe(false);
    expect(r.file.error).toMatch(/ENOENT/);
  });
});
