import { describe, expect, it } from 'vitest';
import { capDecompileItems, parseDecompileList } from './decompile.js';

describe('capDecompileItems', () => {
  it('keeps the true denominator when the persisted list is capped', () => {
    const result = capDecompileItems([1, 2, 3, 4, 5], 3);
    expect(result).toEqual({ items: [1, 2, 3], total: 5, complete: false });
  });

  it('calls an exact-bound list complete', () => {
    expect(capDecompileItems([1, 2, 3], 3)).toEqual({ items: [1, 2, 3], total: 3, complete: true });
  });
});

describe('parseDecompileList', () => {
  it('keeps a valid empty inventory distinct from an unparseable block', () => {
    expect(parseDecompileList('[]')).toEqual({ items: [], parsed: true });
    expect(parseDecompileList('radare2 warning, no json')).toEqual({ items: [], parsed: false });
  });
});
