import { describe, expect, it } from 'vitest';
import { buildRenodeScript } from './renode.js';

describe('buildRenodeScript', () => {
  it('loads the platform then the firmware ELF and starts', () => {
    const s = buildRenodeScript('/plat/stm32f4.repl', '/fw/app.elf').split('\n');
    expect(s[0]).toBe('mach create');
    expect(s).toContain('machine LoadPlatformDescription @/plat/stm32f4.repl');
    expect(s).toContain('sysbus LoadELF @/fw/app.elf');
    expect(s[s.length - 1]).toBe('start');
  });
});
