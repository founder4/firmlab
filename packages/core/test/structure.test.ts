import { describe, expect, it } from 'vitest';
import { decodeElfArch, inferIdentity, ubootArch } from '../src/structure.js';

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

describe('inferIdentity — eCos marker scan is bounded, and says so', () => {
  it('marks a fallback class provisional when the eCos scan was clipped by the 4 MB cap', () => {
    // 5 MB, no signature hits and no eCos marker in the first 4 MB → falls to the `unknown` fallback, which an
    // eCos monolith with markers past 4 MB could really have been. The verdict must declare it scanned under a bound.
    const big = new Uint8Array(5 * 1024 * 1024);
    const id = inferIdentity(big, []);
    expect(id.firmwareClass).toBe('unknown');
    expect(id.classRationale).toMatch(/bounded to the first 4 MB/);
    expect(id.classRationale).toMatch(/provisional/);
  });

  it('adds no such caveat when the image fits inside the cap (the common case)', () => {
    const small = new Uint8Array(64 * 1024);
    const id = inferIdentity(small, []);
    expect(id.firmwareClass).toBe('unknown');
    expect(id.classRationale).toBeUndefined();
  });

  it('a positive eCos identification within the prefix is not flagged provisional', () => {
    const buf = new TextEncoder().encode('redboot cyg_scheduler cyg_thread padding');
    const id = inferIdentity(buf, []);
    expect(id.firmwareClass).toBe('rtos');
    expect(id.classRationale ?? '').not.toMatch(/provisional/);
  });
});
