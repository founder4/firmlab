import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { rtosElfSymbolsFromBytes } from './rtos-elf-symbols.js';

// A real FreeRTOS V11.1.0 build (see __fixtures__/freertos-stm32f4/PROVENANCE.md), not a hand-made ELF: the symbol
// pre-fill is checked against what an actual toolchain emits. The Renode half lives in scripts/rtos-freertos-e2e.mjs.
const here = path.dirname(fileURLToPath(import.meta.url));
const elf = fs.readFileSync(path.join(here, '__fixtures__/freertos-stm32f4/freertos-stm32f4.elf'));

describe('FreeRTOS fixture ELF symbol pre-fill', () => {
  const r = rtosElfSymbolsFromBytes(new Uint8Array(elf));

  it('pre-fills every list the fixture compiles in, inside its RAM', () => {
    expect(r.verdict).toBe('symbols-read');
    const p = r.prefill;
    if (!p) throw new Error('no prefill');
    const inRam = (a: number | null | undefined) => typeof a === 'number' && a >= 0x20000000 && a < 0x20020000;
    expect(inRam(p.pxCurrentTCB)).toBe(true);
    expect(inRam(p.suspendedList)).toBe(true);
    expect(inRam(p.pendingReadyList)).toBe(true);
    expect(p.delayedLists.map((d) => inRam(d.address))).toEqual([true, true]);
    expect(inRam(p.readyListArray?.base)).toBe(true);
    // configMAX_PRIORITIES (5) × sizeof(List_t) (20): the cross-check the operator's declaration is held to.
    expect(p.readyListArray?.symbolSize).toBe(100);
  });

  it('reports the list INCLUDE_vTaskDelete=0 leaves out as unresolved, not as an address', () => {
    expect(r.prefill?.terminatedList).toBeNull();
    expect(r.symbols.find((s) => s.name === 'xTasksWaitingTermination')?.status).not.toBe('resolved');
  });
});
