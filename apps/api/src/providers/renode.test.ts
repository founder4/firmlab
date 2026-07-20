import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { buildRenodeScript, discoverUarts, selectPlatform } from './renode.js';

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
  it('maps MCU/vendor hints to a bundled board platform', () => {
    // A custom dir bypasses the on-disk existence check, so mapping is unit-testable without Renode.
    expect(selectPlatform(['STM32F407 Discovery'], '/plat')).toContain('stm32f4');
    expect(selectPlatform(['Nordic nRF52840 SoftDevice'], '/plat')).toContain('nrf52840');
    expect(selectPlatform(['generic cortex-m4 rtos'], '/plat')).toContain('cortex-m4');
  });

  it('returns null when nothing matches (→ honest blocked_by_platform)', () => {
    expect(selectPlatform(['some x86 linux server'], '/plat')).toBeNull();
  });
});
