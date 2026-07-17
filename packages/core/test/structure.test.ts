import { describe, expect, it } from 'vitest';
import { decodeElfArch, ubootArch } from '../src/structure.js';

describe('decodeElfArch', () => {
  it('maps common ELF machines with endianness', () => {
    expect(decodeElfArch(40, false, 32)).toEqual({ arch: 'arm', endianness: 'little' });
    expect(decodeElfArch(183, false, 64)).toEqual({ arch: 'arm64', endianness: 'little' });
    expect(decodeElfArch(62, false, 64)).toEqual({ arch: 'x86_64', endianness: 'little' });
  });

  it('distinguishes mips (BE) from mipsel (LE)', () => {
    expect(decodeElfArch(8, true, 32)).toEqual({ arch: 'mips', endianness: 'big' });
    expect(decodeElfArch(8, false, 32)).toEqual({ arch: 'mipsel', endianness: 'little' });
  });

  it('downgrades x86_64 machine to x86 when the class is 32-bit', () => {
    expect(decodeElfArch(62, false, 32).arch).toBe('x86');
  });

  it('returns unknown arch for an unmapped machine', () => {
    expect(decodeElfArch(9999, false, 32).arch).toBe('unknown');
  });
});

describe('ubootArch', () => {
  it('maps U-Boot ih_arch codes', () => {
    expect(ubootArch(2)).toBe('arm');
    expect(ubootArch(5)).toBe('mips');
    expect(ubootArch(22)).toBe('arm64');
    expect(ubootArch(26)).toBe('riscv');
  });

  it('returns unknown for an unmapped code', () => {
    expect(ubootArch(0)).toBe('unknown');
    expect(ubootArch(99)).toBe('unknown');
  });
});
