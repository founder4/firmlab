import { describe, expect, it } from 'vitest';
import { buildFuzzCommand } from './fuzz.js';

describe('buildFuzzCommand', () => {
  it('builds an AFL++ qemu-mode, time-bounded invocation with file input', () => {
    const cmd = buildFuzzCommand('/rootfs/bin/parser', '/w/seeds', '/w/out', 60);
    expect(cmd[0]).toBe('afl-fuzz');
    expect(cmd).toContain('-Q'); // binary-only qemu mode
    expect(cmd).toContain('-V');
    expect(cmd[cmd.indexOf('-V') + 1]).toBe('60');
    expect(cmd.slice(-2)).toEqual(['/rootfs/bin/parser', '@@']);
  });

  it('includes a dictionary when supplied', () => {
    const cmd = buildFuzzCommand('/rootfs/bin/parser', '/w/seeds', '/w/out', 30, '/w/dict.txt');
    expect(cmd).toContain('-x');
    expect(cmd[cmd.indexOf('-x') + 1]).toBe('/w/dict.txt');
  });

  it('omits the dictionary flag when not supplied', () => {
    expect(buildFuzzCommand('/b', '/s', '/o', 10)).not.toContain('-x');
  });
});
