import { describe, expect, it } from 'vitest';
import {
  fingerprintMcu,
  parsePicobin,
  parsePicobinImages,
  parseRiscvStartupCopyTable,
  parseRp2040Flash,
  qmkFirmwareMarkers,
} from '../src/mcu.js';

/** Minimal ELF32 builder: header + N PT_LOAD program headers, little-endian, plus optional trailing strings. */
function elf32(machine: number, loads: { vaddr: number; paddr: number; filesz: number }[], trailer = ''): Uint8Array {
  const ehSize = 52;
  const phSize = 32;
  const trailerBytes = new TextEncoder().encode(trailer);
  const buf = new Uint8Array(ehSize + loads.length * phSize + trailerBytes.length);
  const dv = new DataView(buf.buffer);
  buf.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1]); // magic, class=32, data=LE, version
  dv.setUint16(16, 2, true); // e_type = ET_EXEC
  dv.setUint16(18, machine, true); // e_machine
  dv.setUint32(20, 1, true); // e_version
  dv.setUint32(28, ehSize, true); // e_phoff
  dv.setUint16(40, ehSize, true); // e_ehsize
  dv.setUint16(42, phSize, true); // e_phentsize
  dv.setUint16(44, loads.length, true); // e_phnum
  loads.forEach((l, i) => {
    const o = ehSize + i * phSize;
    dv.setUint32(o, 1, true); // p_type = PT_LOAD
    dv.setUint32(o + 8, l.vaddr, true);
    dv.setUint32(o + 12, l.paddr, true);
    dv.setUint32(o + 16, l.filesz, true);
    dv.setUint32(o + 20, l.filesz, true); // p_memsz
  });
  buf.set(trailerBytes, ehSize + loads.length * phSize);
  return buf;
}

function ascii(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe('fingerprintMcu — ELF memory layout', () => {
  it('reads arch and the flash/RAM bases from an ARM Cortex-M ELF (flash + a copy-to-RAM data segment)', () => {
    const fp = fingerprintMcu(
      elf32(40, [
        { vaddr: 0x0800_0000, paddr: 0x0800_0000, filesz: 0x200 }, // .text in flash
        { vaddr: 0x2000_0000, paddr: 0x0800_0200, filesz: 0x40 }, // .data: runs from RAM, stored in flash
      ]),
    );
    expect(fp.arch).toBe('arm');
    expect(fp.isElf).toBe(true);
    expect(fp.flashBase).toBe(0x0800_0000);
    expect(fp.ramBase).toBe(0x2000_0000);
  });

  it('maps a RISC-V ELF e_machine', () => {
    expect(fingerprintMcu(elf32(243, [{ vaddr: 0x2040_0000, paddr: 0x2040_0000, filesz: 0x10 }])).arch).toBe('riscv');
  });

  it('records the flash base as evidence but does NOT fabricate a vendor family without a string', () => {
    const fp = fingerprintMcu(elf32(40, [{ vaddr: 0x0800_0000, paddr: 0x0800_0000, filesz: 0x100 }]));
    expect(fp.arch).toBe('arm'); // ELF e_machine
    expect(fp.family).toBeNull(); // 0x08000000 alone is not proof of a specific family
    expect(fp.evidence.some((e) => e.includes('0x8000000'))).toBe(true);
  });
});

describe('fingerprintMcu — raw Cortex-M vector table', () => {
  it('fingerprints a raw .bin from a valid SP + reset vector', () => {
    const buf = new Uint8Array(0x40);
    new DataView(buf.buffer).setUint32(0, 0x2000_5000, true); // initial SP → SRAM
    new DataView(buf.buffer).setUint32(4, 0x0800_0abd, true); // reset handler (Thumb, bit 0 set) → flash
    const fp = fingerprintMcu(buf);
    expect(fp.isElf).toBe(false);
    expect(fp.arch).toBe('arm');
    expect(fp.flashBase).toBe(0x0800_0000);
    expect(fp.ramBase).toBe(0x2000_0000);
  });

  it('does not force a Cortex-M reading on random bytes', () => {
    const buf = new Uint8Array(0x40).fill(0xff);
    const fp = fingerprintMcu(buf);
    expect(fp.flashBase).toBeNull();
    expect(fp.arch).toBe('unknown');
  });
});

describe('parseRp2040Flash — boot2 CRC + XIP vector table', () => {
  // First 264 bytes of the hash-locked official Framework QMK ANSI v0.3.1 release. This covers the complete
  // checksummed boot2 block and the first two application vectors, without relying on its filename or strings.
  const frameworkQmkPrefix = () =>
    Uint8Array.from(
      Buffer.from(
        'ALUySyEgWGCYaAIhiEOYYNhgGGFYYS5LACGZYAQhWWEBIfAimVArSRlgASGZYDUgAPBE+AIikEIU0AYhGWYA8DT4GW4BIRlmACAYZhpmAPAs+BluGW4ZbgUgAPAv+AEhCEL50QAhmWAbSRlgACFZYBpJG0gBYAEhmWDrIRlmoCEZZgDwEvgAIZlgFkkUSAFgASGZYAG8ACgA0ABHEkgTSQhgA8iA8wiICEcDtZlqBCABQvvQASABQvjRA70CtRhmGGb/9/L/GG4YbgK9AAACQAAAABgAAAcAAANfACEiAAD0AAAYIiAAoAABABAI7QDgAAAAAAAAAAAAAAAABwuP1QAEBCDFAgAQ',
        'base64',
      ),
    );

  it('recognizes the official Framework QMK RP2040 image from binary structure', () => {
    const info = parseRp2040Flash(frameworkQmkPrefix());
    expect(info).toEqual({ vectorOffset: 0x100, initialSP: 0x2004_0400, resetHandler: 0x1000_02c5 });

    const fp = fingerprintMcu(frameworkQmkPrefix());
    expect(fp).toMatchObject({ arch: 'arm', cortexM: 'cortex-m0plus', family: 'rp2040', vendor: 'raspberrypi' });
    expect(fp.evidence).toContain('RP2040 boot2 CRC32 + Cortex-M0+ XIP vector table');
  });

  it('corroborates QMK with multiple internal markers and reports the RP2040 QMK runtime', () => {
    const base = frameworkQmkPrefix();
    const markers = ascii('eeconfig_update_rgb_matrix_default\0rgb_matrix_config EEPROM\0xkeyboard_report:');
    const buf = new Uint8Array(base.length + markers.length);
    buf.set(base);
    buf.set(markers, base.length);
    expect(qmkFirmwareMarkers(buf)).toHaveLength(3);
    expect(fingerprintMcu(buf).rtos).toBe('qmk');
  });

  it('does not identify QMK from a generic keyboard message alone', () => {
    const base = frameworkQmkPrefix();
    const marker = ascii('suspending keyboard');
    const buf = new Uint8Array(base.length + marker.length);
    buf.set(base);
    buf.set(marker, base.length);
    expect(qmkFirmwareMarkers(buf)).toEqual([]);
  });

  it('rejects a corrupted boot2 CRC even when the following vectors look valid', () => {
    const buf = frameworkQmkPrefix();
    buf[0] = (buf[0] ?? 0) ^ 1;
    expect(parseRp2040Flash(buf)).toBeNull();
  });

  it('rejects a valid boot2 block followed by a vector outside RP2040 XIP flash', () => {
    const buf = frameworkQmkPrefix();
    new DataView(buf.buffer).setUint32(0x104, 0x0800_02c5, true);
    expect(parseRp2040Flash(buf)).toBeNull();
  });
});

describe('fingerprintMcu — vendor/family string markers', () => {
  const cases: [string, Partial<ReturnType<typeof fingerprintMcu>>][] = [
    ['STM32F407VG rev A', { family: 'stm32f4', vendor: 'st', part: 'stm32f407vg', arch: 'arm' }],
    ['Nordic Semiconductor nRF52840 SoftDevice', { family: 'nrf52', vendor: 'nordic', part: 'nrf52840' }],
    ['Silicon Labs EFR32MG12 Gecko', { family: 'efr32mg', vendor: 'silabs' }],
    ['TI CC2538 SimpleLink', { family: 'cc2538', vendor: 'ti' }],
    ['Espressif ESP-IDF esp32 build', { family: 'esp32', vendor: 'espressif', arch: 'xtensa' }],
    ['built for esp32-c3 target', { family: 'esp32c3', vendor: 'espressif', arch: 'riscv' }],
    ['SiFive FE310-G002 HiFive', { family: 'fe310', vendor: 'sifive', arch: 'riscv' }],
    ['Microchip ATSAMD51J20', { family: 'samd51', vendor: 'microchip' }],
  ];
  for (const [marker, expected] of cases) {
    it(`detects ${marker}`, () => {
      const fp = fingerprintMcu(ascii(`\x00\x00padding ${marker} more padding`));
      for (const [k, v] of Object.entries(expected)) {
        expect(fp[k as keyof typeof fp]).toBe(v);
      }
    });
  }

  it('exposes the bare STM32 part core (prefix stripped) to match boards that drop it', () => {
    const fp = fingerprintMcu(ascii('STM32H753ZI on a Nucleo-144 board'));
    expect(fp.family).toBe('stm32h7');
    expect(fp.part).toBe('stm32h753zi');
    expect(fp.partCore).toBe('h753');
    expect(fp.tokens).toContain('h753');
  });

  it('normalizes the Cortex-M core and RTOS banner', () => {
    const fp = fingerprintMcu(ascii('Zephyr OS running on Cortex-M0+ core'));
    expect(fp.cortexM).toBe('cortex-m0plus');
    expect(fp.rtos).toBe('zephyr');
    expect(fp.arch).toBe('arm'); // inferred from the named core when no ELF/marker arch
  });

  it('requires RIOT and mbed runtime-specific banners', () => {
    expect(fingerprintMcu(ascii('RIOT_VERSION=2026.10')).rtos).toBe('riot');
    expect(fingerprintMcu(ascii('mbed_error_status')).rtos).toBe('mbed');
    expect(fingerprintMcu(ascii('random /riot bytes')).rtos).toBeNull();
    expect(fingerprintMcu(ascii('CONFIG_OF_EMBED')).rtos).toBeNull();
  });

  it('stays honest on an unrecognized MCU (no family → selector will block)', () => {
    const fp = fingerprintMcu(ascii('some proprietary blob with no known markers'));
    expect(fp.family).toBeNull();
    expect(fp.part).toBeNull();
    expect(fp.tokens).toEqual([]);
  });

  it('exposes tokens for catalog matching', () => {
    const fp = fingerprintMcu(ascii('nRF52840 Cortex-M4 Zephyr'));
    expect(fp.tokens).toContain('nrf52');
    expect(fp.tokens).toContain('nrf52840');
    expect(fp.tokens).toContain('nordic');
    expect(fp.tokens).toContain('cortex-m4');
  });
});

describe('parsePicobin — RP2350 boot block ISA', () => {
  /** A complete singleton PICOBIN IMAGE_DEF block with IMAGE_TYPE, LAST, link-to-self and end marker. */
  function picobinBlock(flags: number, markerAt = 0x10): Uint8Array {
    const buf = new Uint8Array(markerAt + 20);
    const dv = new DataView(buf.buffer);
    dv.setUint32(markerAt, 0xffff_ded3, true);
    dv.setUint32(markerAt + 4, ((flags & 0xffff) << 16) | 0x0142, true);
    dv.setUint32(markerAt + 8, 0x0000_01ff, true); // LAST: one preceding item word
    dv.setUint32(markerAt + 12, 0, true); // relative link to this block (singleton loop)
    dv.setUint32(markerAt + 16, 0xab12_3579, true);
    return buf;
  }

  function picobinLoadMapBlock(options: {
    absolute?: boolean;
    storageAddress: number;
    runtimeAddress: number;
    encodedSize: number;
    entryPoint: number;
  }): Uint8Array {
    const markerAt = 0x10;
    const buf = new Uint8Array(0x40);
    const dv = new DataView(buf.buffer);
    dv.setUint32(markerAt, 0xffff_ded3, true);
    dv.setUint32(markerAt + 4, 0x1101_0142, true);
    const loadMapFlags = options.absolute ? 0x81 : 0x01; // Entry count plus the absolute flag in bit 31.
    dv.setUint32(markerAt + 8, (loadMapFlags << 24) | 0x0406, true);
    dv.setUint32(markerAt + 12, options.storageAddress, true);
    dv.setUint32(markerAt + 16, options.runtimeAddress, true);
    dv.setUint32(markerAt + 20, options.encodedSize, true);
    dv.setUint32(markerAt + 24, 0x0000_0344, true);
    dv.setUint32(markerAt + 28, options.entryPoint, true);
    dv.setUint32(markerAt + 32, 0x2008_2000, true);
    dv.setUint32(markerAt + 36, 0x0000_08ff, true);
    dv.setUint32(markerAt + 40, 0, true);
    dv.setUint32(markerAt + 44, 0xab12_3579, true);
    return buf;
  }

  it('reads a RISC-V RP2350 executable image (CPU field, not the chip name)', () => {
    const info = parsePicobin(picobinBlock(0x1101)); // EXE | CPU_RISCV(0x100) | CHIP_RP2350(0x1000)
    expect(info).not.toBeNull();
    expect(info?.cpu).toBe('riscv');
    expect(info?.chip).toBe('rp2350');
    expect(info?.isExecutable).toBe(true);
    expect(info?.cpuMode).toBe('riscv');
    expect(info?.blockOffsets).toEqual([0x10]);
    expect(info?.loopComplete).toBe(true);
  });

  it('reads an Arm RP2350 image', () => {
    expect(parsePicobin(picobinBlock(0x1001))?.cpu).toBe('arm'); // CPU_ARM(0x0)
  });

  it('maps a varmulet image to Arm (emulated Arm code on the RISC-V core)', () => {
    const info = parsePicobin(picobinBlock(0x1201));
    expect(info?.cpu).toBe('arm'); // CPU_VARMULET(0x2) → the image is Arm code
    expect(info?.cpuMode).toBe('varmulet');
  });

  it('validates and follows the two-block loop shape used by real Pico SDK flash images', () => {
    const buf = new Uint8Array(0x70);
    const dv = new DataView(buf.buffer);
    const first = 0x14;
    const tail = 0x50;
    dv.setUint32(first, 0xffff_ded3, true);
    dv.setUint32(first + 4, 0x1101_0142, true); // IMAGE_TYPE: executable, RISC-V, RP2350
    dv.setUint32(first + 8, 0x0000_0344, true); // ENTRY_POINT, three words
    dv.setUint32(first + 12, 0x1000_0036, true);
    dv.setUint32(first + 16, 0x2008_2000, true);
    dv.setUint32(first + 20, 0x0000_04ff, true); // LAST: four preceding words
    dv.setInt32(first + 24, tail - first, true);
    dv.setUint32(first + 28, 0xab12_3579, true);
    dv.setUint32(tail, 0xffff_ded3, true);
    dv.setUint32(tail + 4, 0x0000_01fe, true); // one-word ignored item (16-bit size form)
    dv.setUint32(tail + 8, 0x0000_01ff, true);
    dv.setInt32(tail + 12, first - tail, true);
    dv.setUint32(tail + 16, 0xab12_3579, true);

    expect(parsePicobin(buf)).toMatchObject({
      markerOffset: first,
      entryPoint: 0x1000_0036,
      initialSP: 0x2008_2000,
      blockOffsets: [first, tail],
      loopComplete: true,
    });
  });

  it('enumerates each IMAGE_DEF in a universal block loop while preserving the primary reading', () => {
    const buf = new Uint8Array(0x50);
    const dv = new DataView(buf.buffer);
    const arm = 0x10;
    const riscv = 0x30;
    for (const [offset, flags, next] of [
      [arm, 0x1001, riscv],
      [riscv, 0x1101, arm],
    ] as const) {
      dv.setUint32(offset, 0xffff_ded3, true);
      dv.setUint32(offset + 4, (flags << 16) | 0x0142, true);
      dv.setUint32(offset + 8, 0x0000_01ff, true);
      dv.setInt32(offset + 12, next - offset, true);
      dv.setUint32(offset + 16, 0xab12_3579, true);
    }

    expect(parsePicobinImages(buf)).toMatchObject([
      { markerOffset: arm, cpuMode: 'arm', blockOffsets: [arm, riscv], loopComplete: true },
      { markerOffset: riscv, cpuMode: 'riscv', blockOffsets: [riscv, arm], loopComplete: true },
    ]);
    expect(parsePicobin(buf)?.markerOffset).toBe(arm);
  });

  it('decodes a relative LOAD_MAP and retains the item-relative storage offset', () => {
    const info = parsePicobin(
      picobinLoadMapBlock({
        storageAddress: 0x40,
        runtimeAddress: 0x2000_0000,
        encodedSize: 0x20,
        entryPoint: 0x2000_0008,
      }),
    );
    expect(info?.loadMap).toEqual({
      itemOffset: 0x18,
      relative: true,
      entries: [{ storageAddress: 0x40, runtimeAddress: 0x2000_0000, size: 0x20 }],
    });
  });

  it('sign-extends a backwards relative LOAD_MAP storage offset', () => {
    const info = parsePicobin(
      picobinLoadMapBlock({
        storageAddress: -0x20,
        runtimeAddress: 0x2000_0000,
        encodedSize: 0x20,
        entryPoint: 0x2000_0008,
      }),
    );
    expect(info?.loadMap?.entries[0]?.storageAddress).toBe(-0x20);
  });

  it('normalizes an absolute LOAD_MAP end address to a byte length', () => {
    const info = parsePicobin(
      picobinLoadMapBlock({
        absolute: true,
        storageAddress: 0x1000_1000,
        runtimeAddress: 0x2000_0000,
        encodedSize: 0x2000_0040,
        entryPoint: 0x2000_0008,
      }),
    );
    expect(info?.loadMap).toEqual({
      itemOffset: 0x18,
      relative: false,
      entries: [{ storageAddress: 0x1000_1000, runtimeAddress: 0x2000_0000, size: 0x40 }],
    });
  });

  it('rejects LOAD_MAP item sizes and spans that disagree with the encoded entry count', () => {
    const malformedSize = picobinLoadMapBlock({
      storageAddress: 0x40,
      runtimeAddress: 0x2000_0000,
      encodedSize: 0x20,
      entryPoint: 0x2000_0008,
    });
    new DataView(malformedSize.buffer).setUint32(0x18, 0x0100_0306, true);
    expect(parsePicobin(malformedSize)).toBeNull();

    const unaligned = picobinLoadMapBlock({
      storageAddress: 0x42,
      runtimeAddress: 0x2000_0000,
      encodedSize: 0x20,
      entryPoint: 0x2000_0008,
    });
    expect(parsePicobin(unaligned)).toBeNull();
  });

  it('rejects a marker plus IMAGE_TYPE when LAST/end-marker structure is missing', () => {
    const truncated = new Uint8Array(0x20);
    const dv = new DataView(truncated.buffer);
    dv.setUint32(0x10, 0xffff_ded3, true);
    dv.setUint32(0x14, 0x1101_0142, true);
    expect(parsePicobin(truncated)).toBeNull();
  });

  it('rejects LAST when its declared preceding-word count is inconsistent', () => {
    const malformed = picobinBlock(0x1101);
    new DataView(malformed.buffer).setUint32(0x18, 0x0000_02ff, true);
    expect(parsePicobin(malformed)).toBeNull();
  });

  it('keeps a valid image definition but reports an unresolved/truncated block loop honestly', () => {
    const linkedOutside = picobinBlock(0x1101);
    new DataView(linkedOutside.buffer).setUint32(0x1c, 0x100, true);
    expect(parsePicobin(linkedOutside)).toMatchObject({ blockOffsets: [0x10], loopComplete: false });
  });

  it('returns null when there is no PICOBIN block', () => {
    expect(parsePicobin(new Uint8Array(64))).toBeNull();
  });
});

describe('parseRiscvStartupCopyTable — bounded Pico SDK startup map', () => {
  function startupImage(sourceAddress = 0x1000_0100): Uint8Array {
    const buf = new Uint8Array(0x200);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0x20, 0x0000_0717, true); // auipc a4, 0
    dv.setUint32(0x24, 0x0407_0713, true); // addi a4, a4, 0x40 -> runtime/file offset 0x60
    dv.setUint32(0x60, sourceAddress, true);
    dv.setUint32(0x64, 0x2000_0000, true);
    dv.setUint32(0x68, 0x2000_0020, true);
    dv.setUint32(0x6c, 0, true);
    return buf;
  }

  it('recovers a terminated source/runtime table referenced by AUIPC plus ADDI', () => {
    expect(parseRiscvStartupCopyTable(startupImage(), 0x1000_0020, 0x20, 0x1000_0000)).toEqual({
      tableAddress: 0x1000_0060,
      tableFileOffset: 0x60,
      bytesExamined: 16,
      regions: [
        {
          sourceAddress: 0x1000_0100,
          sourceFileOffset: 0x100,
          runtimeAddress: 0x2000_0000,
          size: 0x20,
        },
      ],
    });
  });

  it('rejects a table whose declared source bytes are outside the image', () => {
    expect(parseRiscvStartupCopyTable(startupImage(0x1000_01f0), 0x1000_0020, 0x20, 0x1000_0000)).toBeNull();
  });
});

describe('fingerprintMcu — the string scan is bounded, and says so', () => {
  it('records the clip in the audit trail when the image exceeds the 4 MB marker cap', () => {
    const big = new Uint8Array(5 * 1024 * 1024);
    const fp = fingerprintMcu(big);
    expect(fp.evidence.some((e) => /scan bounded to the first 4 MB/.test(e))).toBe(true);
  });

  it('adds no scan-bound note when the image fits inside the cap', () => {
    const small = new Uint8Array(1024);
    const fp = fingerprintMcu(small);
    expect(fp.evidence.some((e) => /scan bounded/.test(e))).toBe(false);
  });
});
