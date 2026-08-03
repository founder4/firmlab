import { describe, expect, it } from 'vitest';
import { buildGhidraFindings, normalizeFunctions } from './ghidra.js';

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

describe('buildGhidraFindings — a decompilation is a view, not a claim', () => {
  it('writes NO finding for a successful run, because pseudocode asserts nothing about the firmware', () => {
    expect(buildGhidraFindings({ available: true, binary: 'usr/bin/httpd', functionCount: 40, functions: [] })).toEqual(
      [],
    );
  });

  /**
   * Rule 2: absence of a tool is not absence of a problem. Ghidra is an opt-in layer the shipped image omits, so
   * without this row a dossier with no Ghidra findings cannot be told from one where the decompiler never ran.
   */
  it('writes a blocked row when it could not run, and calls it not a negative', () => {
    const [d] = buildGhidraFindings({
      available: false,
      reason: 'Ghidra (analyzeHeadless) not installed',
      binary: 'usr/bin/httpd',
      functionCount: 0,
      functions: [],
    });
    expect(d?.kind).toBe('decompilation-blocked');
    expect(d?.proofState).toBe('blocked_by_platform');
    expect(d?.severity).toBe('info');
    expect(d?.title).toContain('not a negative result');
    expect(d?.rationale).toContain('not installed');
    // Nothing was read, so nothing was learned through any channel.
    expect(d && 'evidenceChannel' in d).toBe(false);
  });
});
