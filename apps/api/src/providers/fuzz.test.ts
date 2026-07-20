import { describe, expect, it } from 'vitest';
import { buildAflDict, buildFuzzCommand } from './fuzz.js';

describe('buildFuzzCommand', () => {
  it('builds an AFL++ qemu-mode, time-bounded invocation with file input', () => {
    const cmd = buildFuzzCommand('/rootfs/bin/parser', '/w/seeds', '/w/out', 60);
    expect(cmd[0]).toBe('afl-fuzz');
    expect(cmd).toContain('-Q'); // binary-only qemu mode
    expect(cmd).toContain('-V');
    expect(cmd[cmd.indexOf('-V') + 1]).toBe('60');
    expect(cmd.slice(-2)).toEqual(['/rootfs/bin/parser', '@@']);
  });

  it('disables the memory limit (qemu mode forks die under an AS cap)', () => {
    const cmd = buildFuzzCommand('/rootfs/bin/parser', '/w/seeds', '/w/out', 60);
    expect(cmd[cmd.indexOf('-m') + 1]).toBe('none');
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

describe('buildAflDict', () => {
  it('emits AFL dictionary entries for printable strings, deduped', () => {
    const d = buildAflDict(['admin', 'admin', 'password', 'ab']).split('\n');
    expect(d).toHaveLength(2); // 'ab' too short, 'admin' deduped
    expect(d[0]).toMatch(/^fw_0="admin"$/);
    expect(d[1]).toMatch(/^fw_1="password"$/);
  });

  it('strips non-printable bytes and escapes quotes/backslashes', () => {
    const d = buildAflDict(['a\x00b"c\\d']);
    expect(d).toBe('fw_0="ab\\"c\\\\d"');
  });
});
