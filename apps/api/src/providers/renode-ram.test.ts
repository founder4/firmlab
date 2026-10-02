import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { ElfRefusal, ElfSymbolsParsed } from '@firmlab/core';
import { afterAll, describe, expect, it } from 'vitest';

import {
  DEFAULT_RAM_CAPTURE_SECONDS,
  MAX_RAM_CAPTURE_SECONDS,
  MIN_RAM_CAPTURE_SECONDS,
  type MappedMemoryRegion,
  buildRenodeRamCaptureScript,
  buildRenodeRamInvocation,
  parsePlatformMemory,
  parseReplMemoryText,
  runRenodeRamCapture,
  selectRamRegion,
} from './renode-ram.js';
import { MAX_SNAPSHOT_BYTES } from './rtos-tasks.js';

function makeMockElf(opts: {
  symbols?: { name: string; value: number }[];
  segments?: { vaddr: number; memsz: number; write: boolean }[];
  endian?: 'little' | 'big';
  bitness?: 32 | 64;
}): ElfSymbolsParsed {
  return {
    status: 'parsed',
    identity: {
      elfClass: (opts.bitness ?? 32) === 64 ? 'elf64' : 'elf32',
      pointerWidth: ((opts.bitness ?? 32) === 64 ? 8 : 4) as 4 | 8,
      endian: opts.endian ?? 'little',
      machine: 40,
      machineName: 'ARM',
      type: 2,
      addressBasis: 'absolute',
    },
    verdict: 'symbols-read',
    tables: [
      {
        kind: 'symtab',
        sectionIndex: 1,
        sectionName: '.symtab',
        stringTableIndex: 2,
        status: 'read',
        entries: opts.symbols?.length ?? 0,
        examined: opts.symbols?.length ?? 0,
        dropped: 0,
        unreadableNames: 0,
        trailingBytes: 0,
      },
    ],
    symbols: (opts.symbols ?? []).map((s, idx) => ({
      table: 'symtab',
      tableSectionIndex: 1,
      index: idx,
      name: s.name,
      value: s.value,
      valueHex: `0x${s.value.toString(16)}`,
      size: 4,
      sizeHex: '0x4',
      binding: 'global',
      bindingRaw: 1,
      type: 'object',
      typeRaw: 1,
      sectionIndex: 1,
      sectionRef: 'regular',
    })),
    segments: (opts.segments ?? []).map((s, idx) => ({
      index: idx,
      vaddr: s.vaddr,
      vaddrHex: `0x${s.vaddr.toString(16)}`,
      memsz: s.memsz,
      filesz: s.memsz,
      offset: 0x1000 * (idx + 1),
      flags: { read: true, write: s.write, execute: !s.write },
    })),
    coverage: {
      sectionsDeclared: 2,
      sectionsExamined: 2,
      sectionsDropped: 0,
      symbolsDeclared: opts.symbols?.length ?? 0,
      symbolsExamined: opts.symbols?.length ?? 0,
      symbolsDropped: 0,
      programHeaders: 'read',
      programHeadersDeclared: opts.segments?.length ?? 0,
      programHeadersDropped: 0,
      maxSections: 4096,
      maxSymbols: 100000,
      maxProgramHeaders: 256,
      statement: 'coverage statement',
    },
  };
}

describe('parseReplMemoryText', () => {
  it('parses single declaration with @ sysbus and hex size', () => {
    const text = `
sram: Memory.MappedMemory @ sysbus 0x20000000
    size: 0x5000
flash: Memory.MappedMemory @ sysbus 0x08000000
    size: 0x30000
`;
    const map = parseReplMemoryText(text);
    expect(map.get('sram')).toEqual({ name: 'sram', base: 0x20000000, size: 0x5000 });
    expect(map.get('flash')).toEqual({ name: 'flash', base: 0x08000000, size: 0x30000 });
  });

  it('parses multi-registration block with @ { sysbus ... }', () => {
    const text = `
internal_sram: Memory.MappedMemory @ {
    sysbus 0x0;
    sysbus 0x40000000
}
    size: 0x10000
`;
    const map = parseReplMemoryText(text);
    expect(map.get('internal_sram')).toEqual({ name: 'internal_sram', base: 0x0, size: 0x10000 });
  });

  it('parses decimal size and strips comments', () => {
    const text = `
// A line comment
/* A block
   comment */
sram: Memory.MappedMemory @ sysbus 0x20000000
    size: 20480 // 20 KB
// ignored: Memory.MappedMemory @ sysbus 0x1000
`;
    const map = parseReplMemoryText(text);
    expect(map.size).toBe(1);
    expect(map.get('sram')).toEqual({ name: 'sram', base: 0x20000000, size: 20480 });
  });

  it('updates size when an existing peripheral is redefined', () => {
    const text1 = 'sram: Memory.MappedMemory @ sysbus 0x20000000\n    size: 0x4000\n';
    const map = parseReplMemoryText(text1);
    expect(map.get('sram')?.size).toBe(0x4000);

    const text2 = 'sram:\n    size: 0x8000\n';
    parseReplMemoryText(text2, map);
    expect(map.get('sram')).toEqual({ name: 'sram', base: 0x20000000, size: 0x8000 });
  });

  it('ignores peripherals without sysbus registration', () => {
    const text = 'flash_mem: Memory.MappedMemory\n    size: 0x800000\n';
    const map = parseReplMemoryText(text);
    expect(map.get('flash_mem')?.base).toBeUndefined();
  });
});

describe('parsePlatformMemory', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'renode-ram-repl-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

  it('follows include chain depth-first and applies board overrides', () => {
    fs.mkdirSync(path.join(root, 'platforms/cpus'), { recursive: true });
    fs.mkdirSync(path.join(root, 'platforms/boards'), { recursive: true });

    // CPU repl sets default SRAM size 0x4000
    fs.writeFileSync(
      path.join(root, 'platforms/cpus/soc.repl'),
      `
sram: Memory.MappedMemory @ sysbus 0x20000000
    size: 0x4000
flash: Memory.MappedMemory @ sysbus 0x08000000
    size: 0x20000
`,
    );

    // Board repl includes CPU repl and overrides sram size to 0x8000
    fs.writeFileSync(
      path.join(root, 'platforms/boards/board.repl'),
      `
using "platforms/cpus/soc.repl"
sram:
    size: 0x8000
`,
    );

    const regions = parsePlatformMemory(path.join(root, 'platforms/boards/board.repl'), root);
    const sram = regions.find((r) => r.name === 'sram');
    const flash = regions.find((r) => r.name === 'flash');

    expect(sram).toEqual({ name: 'sram', base: 0x20000000, size: 0x8000 });
    expect(flash).toEqual({ name: 'flash', base: 0x08000000, size: 0x20000 });
  });

  it('handles cyclic includes without looping indefinitely', () => {
    fs.writeFileSync(
      path.join(root, 'a.repl'),
      'using "./b.repl"\nsram: Memory.MappedMemory @ sysbus 0x20000000\n    size: 0x1000\n',
    );
    fs.writeFileSync(path.join(root, 'b.repl'), 'using "./a.repl"\n');

    const regions = parsePlatformMemory(path.join(root, 'a.repl'), root);
    expect(regions).toHaveLength(1);
    expect(regions[0]?.name).toBe('sram');
  });

  it('refuses includes outside the Renode root', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'outside-renode-'));
    try {
      fs.writeFileSync(
        path.join(outside, 'secret.repl'),
        'secret: Memory.MappedMemory @ sysbus 0x30000000\n    size: 0x1000\n',
      );
      fs.writeFileSync(path.join(root, 'traitor.repl'), `using "${path.join(outside, 'secret.repl')}"\n`);

      const regions = parsePlatformMemory(path.join(root, 'traitor.repl'), root);
      expect(regions).toEqual([]);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

describe('selectRamRegion', () => {
  const regions: MappedMemoryRegion[] = [
    { name: 'flash', base: 0x08000000, size: 0x40000 },
    { name: 'sram', base: 0x20000000, size: 0x8000 }, // 0x20000000 - 0x20008000
    { name: 'backup_sram', base: 0x40024000, size: 0x1000 },
  ];

  it('selects region by rule freertos-symbols when resolved kernel symbols are present', () => {
    const elf = makeMockElf({
      symbols: [
        { name: 'pxCurrentTCB', value: 0x20000100 },
        { name: 'pxReadyTasksLists', value: 0x20000200 },
      ],
      segments: [{ vaddr: 0x20000000, memsz: 0x1000, write: true }],
    });

    const res = selectRamRegion(regions, elf);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.selection.rule).toBe('freertos-symbols');
      expect(res.selection.region.name).toBe('sram');
      expect(res.selection.region.base).toBe(0x20000000);
      expect(res.selection.reason).toContain('contains all 2 resolved FreeRTOS kernel symbols');
    }
  });

  it('selects region by rule elf-writable-segment when FreeRTOS symbols are absent (e.g. Zephyr / stripped)', () => {
    const elf = makeMockElf({
      symbols: [], // No FreeRTOS symbols
      segments: [
        { vaddr: 0x08000000, memsz: 0x10000, write: false }, // Flash
        { vaddr: 0x20000000, memsz: 0x2000, write: true }, // SRAM
      ],
    });

    const res = selectRamRegion(regions, elf);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.selection.rule).toBe('elf-writable-segment');
      expect(res.selection.region.name).toBe('sram');
      expect(res.selection.reason).toContain('contains the ELF writable PT_LOAD segment(s)');
    }
  });

  it('refuses when writable segment does not match any platform region (never guesses 0x20000000)', () => {
    const elf = makeMockElf({
      segments: [{ vaddr: 0x60000000, memsz: 0x1000, write: true }],
    });

    const res = selectRamRegion(regions, elf);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toContain('None of the platform memory regions');
      expect(res.reason).not.toContain('guessing');
    }
  });

  it('refuses when resolved symbols span multiple regions (ambiguous match)', () => {
    const elf = makeMockElf({
      symbols: [
        { name: 'pxCurrentTCB', value: 0x20000100 }, // in sram
        { name: 'xSuspendedTaskList', value: 0x40024010 }, // in backup_sram
      ],
    });

    const res = selectRamRegion(regions, elf);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toContain('Ambiguous RAM match');
      expect(res.reason).toContain("'sram'");
      expect(res.reason).toContain("'backup_sram'");
    }
  });

  it('refuses when firmware is not an ELF file', () => {
    const refusal: ElfRefusal = { status: 'refused', code: 'not-elf', detail: 'Magic bytes do not match ELF' };
    const res = selectRamRegion(regions, refusal);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toContain('Firmware is not a readable ELF file');
      expect(res.reason).toContain('refusing to guess a default base address');
    }
  });

  it('refuses when platform defines no MappedMemory regions', () => {
    const elf = makeMockElf({ segments: [{ vaddr: 0x20000000, memsz: 0x1000, write: true }] });
    const res = selectRamRegion([], elf);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.reason).toContain('Platform declares no sysbus MappedMemory peripherals');
    }
  });
});

describe('buildRenodeRamCaptureScript', () => {
  it('generates the exact sequence: mach create -> load repl -> load elf -> start -> sleep -> pause -> DumpBinary -> quit', () => {
    const script = buildRenodeRamCaptureScript(
      '/opt/renode/platforms/cpus/stm32l072.repl',
      '/tmp/app.elf',
      'sram',
      0x5000,
      '/tmp/ram.bin',
      2,
    );

    const lines = script.split('\n');
    expect(lines[0]).toBe('mach create');
    expect(lines[1]).toBe('machine LoadPlatformDescription @/opt/renode/platforms/cpus/stm32l072.repl');
    expect(lines[2]).toBe('sysbus LoadELF @/tmp/app.elf');
    expect(lines[3]).toBe('start');
    expect(lines[4]).toBe('sleep 2');
    expect(lines[5]).toBe('pause');
    expect(lines[6]).toBe('sysbus.sram DumpBinary @/tmp/ram.bin 0 0x5000');
    expect(lines[7]).toBe('quit');
  });
});

describe('buildRenodeRamInvocation', () => {
  it('passes include script and offline proxy environment with bounded limits', () => {
    const inv = buildRenodeRamInvocation('/tmp/test.resc', 3, '/tmp/work');
    expect(inv.argv).toEqual(['renode', '--disable-xwt', '--console', '--plain', '-e', 'include @/tmp/test.resc']);
    expect(inv.options.env.HTTP_PROXY).toBe('http://127.0.0.1:9');
    expect(inv.options.env.NO_PROXY).toBeUndefined();
    expect(inv.options.env.HOME).toBe('/tmp/work');
    expect(inv.options.limits.addressSpaceBytes).toBe(0);
    expect(inv.options.limits.fileSizeBytes).toBe(0);
    expect(inv.options.limits.wallMs).toBe((3 + 45) * 1000);
  });
});

describe('runRenodeRamCapture — honest degradation when Renode is absent', () => {
  it('returns available:false and blocked_by_platform without throwing or requiring Renode', async () => {
    const res = await runRenodeRamCapture('/path/to/any.elf');
    // On systems where renode is not installed (e.g. host test environment)
    if (!res.available) {
      expect(res.available).toBe(false);
      expect(res.ran).toBe(false);
      expect(res.captured).toBe(false);
      expect(res.proofState).toBe('blocked_by_platform');
      expect(res.reason).toContain('Renode not installed');
      expect(res.bytesBase64).toBeNull();
      expect(res.bytes).toBeNull();
      expect(res.bytesCaptured).toBe(0);
    }
  });

  it('clamps seconds bounds between 1 and 30 (default 2)', () => {
    expect(DEFAULT_RAM_CAPTURE_SECONDS).toBe(2);
    expect(MIN_RAM_CAPTURE_SECONDS).toBe(1);
    expect(MAX_RAM_CAPTURE_SECONDS).toBe(30);
    expect(MAX_SNAPSHOT_BYTES).toBe(512 * 1024);
  });
});
