import { describe, expect, it } from 'vitest';
import { fingerprintMcu } from '../src/mcu.js';

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

  it('normalizes the Cortex-M core and RTOS banner', () => {
    const fp = fingerprintMcu(ascii('Zephyr OS running on Cortex-M0+ core'));
    expect(fp.cortexM).toBe('cortex-m0plus');
    expect(fp.rtos).toBe('zephyr');
    expect(fp.arch).toBe('arm'); // inferred from the named core when no ELF/marker arch
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
