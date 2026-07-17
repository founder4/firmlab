import { describe, expect, it } from 'vitest';
import { normalizeFunctions } from './ghidra.js';

describe('normalizeFunctions', () => {
  it('returns [] for non-array input', () => {
    expect(normalizeFunctions(null)).toEqual([]);
    expect(normalizeFunctions({})).toEqual([]);
    expect(normalizeFunctions('nope')).toEqual([]);
  });

  it('coerces fields and fills defaults', () => {
    expect(normalizeFunctions([{ name: 'main', signature: 'int main(void)', pseudocode: 'return 0;' }])).toEqual([
      { name: 'main', signature: 'int main(void)', pseudocode: 'return 0;' },
    ]);
    const [only] = normalizeFunctions([{}]);
    expect(only).toEqual({ name: '?', signature: '', pseudocode: '' });
  });

  it('caps at 40 functions', () => {
    const many = Array.from({ length: 100 }, (_, i) => ({ name: `f${i}`, signature: '', pseudocode: '' }));
    expect(normalizeFunctions(many)).toHaveLength(40);
  });

  it('truncates pseudocode to 8000 chars', () => {
    const [f] = normalizeFunctions([{ name: 'big', signature: '', pseudocode: 'x'.repeat(20000) }]);
    expect(f?.pseudocode.length).toBe(8000);
  });
});
