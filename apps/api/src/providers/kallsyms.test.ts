import { describe, expect, it } from 'vitest';
import { decodeKallsyms } from './kallsyms.js';

function absoluteKallsymsFixture(symbolCount = 2000): Buffer {
  const alphabet = ['T', ...'abcdefghijklmnopqrstuvwxyz', ...'0123456789', '_'];
  const tokenBytes: number[] = [];
  const offsets: number[] = [];
  const tokenFor = new Map<string, number>();
  for (let i = 0; i < 256; i++) {
    offsets.push(tokenBytes.length);
    const char = alphabet[i] ?? 'x';
    if (!tokenFor.has(char)) tokenFor.set(char, i);
    tokenBytes.push(char.charCodeAt(0), 0);
  }

  const core = ['commit_creds', 'prepare_kernel_cred', 'do_exit', 'kmalloc'];
  const names = Array.from({ length: symbolCount }, (_, i) => core[i] ?? `sym_${i}`);
  const encodedNames: number[] = [];
  for (const name of names) {
    const expanded = `T${name}`;
    encodedNames.push(expanded.length);
    for (const char of expanded) encodedNames.push(tokenFor.get(char) as number);
  }

  const addresses = Buffer.alloc(symbolCount * 4);
  for (let i = 0; i < symbolCount; i++) addresses.writeUInt32LE(0x80000000 + i * 4, i * 4);
  const count = Buffer.alloc(4);
  count.writeUInt32LE(symbolCount);
  const namesBuffer = Buffer.from(encodedNames);
  const padding = Buffer.alloc((addresses.length + count.length + namesBuffer.length) % 2);
  const tokenTable = Buffer.from(tokenBytes);
  const tokenIndex = Buffer.alloc(512);
  for (let i = 0; i < 256; i++) tokenIndex.writeUInt16LE(offsets[i] as number, i * 2);
  return Buffer.concat([addresses, count, namesBuffer, padding, tokenTable, tokenIndex]);
}

describe('decodeKallsyms', () => {
  it('recovers a complete compressed table from its address/count and token-table invariants', () => {
    const decoded = decodeKallsyms(absoluteKallsymsFixture());

    expect(decoded).not.toBeNull();
    expect(decoded).toMatchObject({ complete: true, symbolCount: 2000, uniqueNameCount: 2000, wordBytes: 4 });
    expect(decoded?.names).toEqual(
      expect.objectContaining({
        has: expect.any(Function),
      }),
    );
    expect(decoded?.names.has('commit_creds')).toBe(true);
    expect(decoded?.names.has('prepare_kernel_cred')).toBe(true);
    expect(decoded?.names.has('do_exit')).toBe(true);
    expect(decoded?.names.has('kmalloc')).toBe(true);
    expect(decoded?.names.has('sym_1999')).toBe(true);
  });

  it('fails closed when the declared count no longer matches the address run', () => {
    const fixture = absoluteKallsymsFixture();
    fixture.writeUInt32LE(1999, 2000 * 4);
    expect(decodeKallsyms(fixture)).toBeNull();
  });

  it('does not manufacture a table from arbitrary bytes', () => {
    const noise = Buffer.alloc(16 * 1024, 0xa5);
    expect(decodeKallsyms(noise)).toBeNull();
  });
});
