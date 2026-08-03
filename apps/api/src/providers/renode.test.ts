import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fingerprintMcu } from '@firmlab/core';
import { afterAll, describe, expect, it } from 'vitest';
import {
  type RenodeResult,
  buildRenodeFindings,
  buildRenodeScript,
  discoverUarts,
  listPlatformCatalog,
  selectPlatform,
} from './renode.js';

/** A stand-in Renode catalog covering common + less-common families, mirroring real `.repl` filenames. */
const CATALOG = [
  'boards/stm32f4_discovery-kit.repl',
  'boards/stm32f072b_discovery.repl',
  'boards/stm32l072.repl',
  'cpus/stm32f4.repl',
  'cpus/nrf52840.repl',
  'cpus/efr32mg.repl',
  'cpus/cc2538.repl',
  'boards/sifive_fe310.repl',
  'boards/nucleo_h753zi.repl',
  'cpus/stm32h743.repl',
  'cpus/samd51.repl',
];

/** Build a fingerprint straight from a marker string, the way the real firmware bytes would produce one. */
function fpFrom(marker: string) {
  return fingerprintMcu(new TextEncoder().encode(`padding ${marker} padding`));
}

describe('buildRenodeScript', () => {
  it('loads the platform + ELF and surfaces every discovered UART, ending on start', () => {
    const s = buildRenodeScript('/plat/stm32f4.repl', '/fw/app.elf', ['usart1', 'uart4']).split('\n');
    expect(s[0]).toBe('mach create');
    expect(s).toContain('machine LoadPlatformDescription @/plat/stm32f4.repl');
    expect(s).toContain('sysbus LoadELF @/fw/app.elf');
    expect(s).toContain('showAnalyzer sysbus.usart1');
    expect(s).toContain('showAnalyzer sysbus.uart4');
    expect(s[s.length - 1]).toBe('start');
  });

  it('falls back to uart0 when no UARTs are known', () => {
    expect(buildRenodeScript('/p.repl', '/f.elf', [])).toContain('showAnalyzer sysbus.uart0');
  });

  it('adds a file backend per UART when a capture dir is given', () => {
    const s = buildRenodeScript('/p.repl', '/f.elf', ['uart4'], '/tmp/cap');
    expect(s).toContain('sysbus.uart4 CreateFileBackend @/tmp/cap/uart_uart4.txt true');
  });
});

describe('discoverUarts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'renode-repl-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

  it('follows `using` includes (both ./relative and root-relative) to find the real UARTs', () => {
    // Mirror the STM32F4 board→SoC layout: a board repl that declares no UART, pulling them from an included SoC repl.
    fs.mkdirSync(path.join(root, 'platforms/boards'), { recursive: true });
    fs.mkdirSync(path.join(root, 'platforms/cpus'), { recursive: true });
    fs.writeFileSync(
      path.join(root, 'platforms/cpus/soc.repl'),
      'usart1: UART.STM32_UART @ sysbus <0x40011000, +0x100>\nuart4: UART.STM32_UART @ sysbus <0x40004C00, +0x100>\n',
    );
    fs.writeFileSync(
      path.join(root, 'platforms/boards/mid.repl'),
      'using "platforms/cpus/soc.repl"\nUserLED: Miscellaneous.LED @ gpioPortD\n',
    );
    fs.writeFileSync(path.join(root, 'platforms/boards/board.repl'), 'using "./mid.repl"\n');
    const uarts = discoverUarts(path.join(root, 'platforms/boards/board.repl'), root);
    expect(uarts.sort()).toEqual(['uart4', 'usart1']);
  });

  it('returns nothing for a missing platform (→ script falls back to uart0)', () => {
    expect(discoverUarts(path.join(root, 'nope.repl'), root)).toEqual([]);
  });
});

describe('selectPlatform', () => {
  it('steers a fingerprinted STM32F4 to the known-good Discovery board, not a bare cpu', () => {
    const sel = selectPlatform(fpFrom('STM32F407VG'), [], CATALOG);
    expect(sel?.repl).toBe('boards/stm32f4_discovery-kit.repl');
    expect(sel?.via).toBe('family');
  });

  it('matches families beyond the common three from the real catalog (RISC-V FE310, SAMD51)', () => {
    expect(selectPlatform(fpFrom('SiFive FE310-G002'), [], CATALOG)?.repl).toBe('boards/sifive_fe310.repl');
    expect(selectPlatform(fpFrom('Microchip ATSAMD51J20'), [], CATALOG)?.repl).toBe('cpus/samd51.repl');
  });

  it('prefers a part-specific board over a bare cpu (STM32H753 → nucleo_h753zi, not cpus/stm32h743)', () => {
    // The board names the exact part (via its stripped core `h753`) and carries the SoC peripherals.
    expect(selectPlatform(fpFrom('STM32H753ZI'), [], CATALOG)?.repl).toBe('boards/nucleo_h753zi.repl');
  });

  it('picks the exact part when the catalog names it (nRF52840 → cpus/nrf52840)', () => {
    const sel = selectPlatform(fpFrom('Nordic nRF52840 SoftDevice'), [], CATALOG);
    expect(sel?.repl).toBe('cpus/nrf52840.repl');
    expect(sel?.via).toBe('part');
  });

  it('blocks honestly on a bare Cortex-M with no vendor identity (real Renode ships no generic core .repl)', () => {
    // A raw vector table (valid Cortex-M memory map) but no vendor family string → cannot pick a real board.
    const buf = new Uint8Array(0x40);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, 0x2000_5000, true);
    dv.setUint32(4, 0x0800_0abd, true);
    buf.set(new TextEncoder().encode('Cortex-M0 bare metal'), 0x20);
    const fp = fingerprintMcu(buf);
    expect(fp.arch).toBe('arm'); // it IS recognized as Cortex-M…
    expect(selectPlatform(fp, [], CATALOG)).toBeNull(); // …but without a vendor family we honestly block
  });

  it('mines the free-text hints too (a "discovery" hint reinforces the board)', () => {
    expect(selectPlatform(fpFrom('STM32F072'), ['STM32F072B Discovery kit'], CATALOG)?.repl).toBe(
      'boards/stm32f072b_discovery.repl',
    );
  });

  it('returns null when nothing matches (→ honest blocked_by_platform)', () => {
    expect(selectPlatform(fpFrom('some x86 linux server'), [], CATALOG)).toBeNull();
    expect(selectPlatform(fingerprintMcu(new Uint8Array()), [], CATALOG)).toBeNull();
  });
});

describe('listPlatformCatalog', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'renode-cat-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

  it('recursively lists .repl files as paths relative to the platforms dir', () => {
    fs.mkdirSync(path.join(root, 'boards'), { recursive: true });
    fs.mkdirSync(path.join(root, 'cpus'), { recursive: true });
    fs.writeFileSync(path.join(root, 'boards/stm32f4_discovery-kit.repl'), '');
    fs.writeFileSync(path.join(root, 'cpus/nrf52840.repl'), '');
    fs.writeFileSync(path.join(root, 'cpus/notes.txt'), 'ignored');
    const cat = listPlatformCatalog(root).sort();
    expect(cat).toEqual(['boards/stm32f4_discovery-kit.repl', 'cpus/nrf52840.repl']);
  });

  it('returns [] for a missing platforms dir (→ selection blocks honestly)', () => {
    expect(listPlatformCatalog(path.join(root, 'nope'))).toEqual([]);
  });
});

describe('buildRenodeFindings', () => {
  const base: RenodeResult = {
    available: true,
    ran: true,
    booted: true,
    reason: 'Renode booted the firmware on stm32f4_discovery-kit and the UART printed a recognisable banner.',
    proofState: 'confirmed_in_emulation',
    platform: 'boards/stm32f4_discovery-kit.repl',
    uartExcerpt: 'Contiki 3.x started\n',
    command: 'renode --disable-xwt -e ...',
  };

  it('a boot names the platform and refuses the device in its own title', () => {
    const [d] = buildRenodeFindings(base);
    expect(d?.kind).toBe('renode-booted');
    expect(d?.proofState).toBe('confirmed_in_emulation');
    expect(d?.evidenceChannel).toBe('emulated_run');
    expect(d?.title).toContain('stm32f4_discovery-kit');
    expect(d?.title).toContain('not on the part');
    expect(d?.evidence?.uartExcerpt).toContain('Contiki 3.x started');
  });

  // Renode is an opt-in layer, so "not installed" is the common case — and it must not read as "nothing to find"
  // on images whose ONLY dynamic question this is.
  it('a blocked run earns a row that says it is not a negative, and carries no evidence channel', () => {
    const [d] = buildRenodeFindings({
      ...base,
      available: false,
      ran: false,
      booted: false,
      proofState: 'blocked_by_platform',
      platform: null,
      uartExcerpt: '',
      command: '',
      reason: 'Renode not installed (opt-in layer).',
    });
    expect(d?.kind).toBe('renode-blocked');
    expect(d?.proofState).toBe('blocked_by_platform');
    expect(d && 'evidenceChannel' in d).toBe(false);
    expect(d?.title).toContain('not a negative result');
    expect(d?.rationale).toContain('not evidence that there is nothing to find');
  });

  it('ran-but-never-booted is its own row, not a boot and not a block', () => {
    const [d] = buildRenodeFindings({ ...base, booted: false, proofState: 'needs_runtime_reproduction' });
    expect(d?.kind).toBe('renode-boot-unconfirmed');
    expect(d?.proofState).toBe('needs_runtime_reproduction');
    expect(d?.evidenceChannel).toBe('emulated_run');
    expect(d?.title).toContain('not a verdict about the firmware');
  });

  it('carries the proof state the runner decided, never one of its own', () => {
    // `booted` is read from real UART output; a composer that re-derived the state would be a second opinion on
    // evidence it never saw.
    const [d] = buildRenodeFindings({ ...base, proofState: 'blocked_by_security' });
    expect(d?.proofState).toBe('blocked_by_security');
  });

  it('bounds the UART excerpt so a chatty firmware cannot grow the row without limit', () => {
    const [d] = buildRenodeFindings({ ...base, uartExcerpt: 'A'.repeat(9000) });
    expect(String(d?.evidence?.uartExcerpt).length).toBe(4000);
  });
});
