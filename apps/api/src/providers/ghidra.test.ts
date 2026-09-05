import { describe, expect, it } from 'vitest';
import { allPseudocodeEmpty, buildGhidraFindings, normalizeFunctions, parseScriptOutput } from './ghidra.js';

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

/**
 * The post-script's output, and the total it used to have no way of reporting.
 *
 * The script `break`-ed out of its function walk at the cap, so nothing ever learned how many functions the
 * binary had; the provider then set `functionCount: functions.length` and the web coverage widget read that pair
 * as denominator over numerator, so it could only ever print "40 of 40". The walk now runs to the end and only
 * stops calling the decompiler.
 */
describe('parseScriptOutput — a total is read, never derived from the list', () => {
  const fn = (name: string) => ({ name, signature: 'int f(void)', pseudocode: 'return 0;' });

  it('reads the totals the script now reports', () => {
    const out = parseScriptOutput({ functionTotal: 913, eligible: 870, decompiled: 2, functions: [fn('a'), fn('b')] });
    expect(out.functions).toHaveLength(2);
    expect(out.functionTotal).toBe(913);
    expect(out.eligibleCount).toBe(870);
  });

  it('yields NO totals for the bare array an older script wrote, rather than inventing them', () => {
    const out = parseScriptOutput([fn('a'), fn('b')]);
    expect(out.functions).toHaveLength(2);
    // Deriving a total from the list is precisely the fabrication being removed.
    expect(out.functionTotal).toBeUndefined();
    expect(out.eligibleCount).toBeUndefined();
  });

  it('drops a total that is smaller than the list it claims to bound', () => {
    const out = parseScriptOutput({ functionTotal: 1, functions: [fn('a'), fn('b'), fn('c')] });
    expect(out.functions).toHaveLength(3);
    expect(out.functionTotal).toBeUndefined();
  });

  it('survives junk without claiming anything', () => {
    expect(parseScriptOutput(null).functions).toEqual([]);
    expect(parseScriptOutput('nope').functions).toEqual([]);
    expect(parseScriptOutput({ functions: 'not an array', functionTotal: 9 }).functionTotal).toBe(9);
    expect(parseScriptOutput({}).functions).toEqual([]);
  });

  it('accepts a total equal to the list — the uncapped run, where nothing was dropped', () => {
    const out = parseScriptOutput({ functionTotal: 2, eligible: 2, functions: [fn('a'), fn('b')] });
    expect(out.functionTotal).toBe(2);
    expect(out.eligibleCount).toBe(2);
  });
});

/**
 * `allPseudocodeEmpty` — the shape of a run that succeeded and decompiled nothing.
 *
 * Found by running the real thing in the deployed container, not by a test: `analyzeHeadless` is a Java launcher
 * and the decompiler it drives is a NATIVE binary Ghidra does not ship pre-built for arm64. On TP-Link
 * WR940Nv6's `usr/bin/httpd` the script walked 4 600 functions, listed 40, and every one of the 40 came back with
 * `pseudocode: ""`. Names and signatures come from the analyzer, so they were all present — the run looked fine.
 */
describe('a Ghidra run that produced no pseudocode is not a successful decompilation', () => {
  const fn = (name: string, pseudocode: string) => ({ name, signature: `undefined ${name}()`, pseudocode });

  it('treats every function coming back empty as the platform fact it is', () => {
    expect(allPseudocodeEmpty([fn('a', ''), fn('b', ''), fn('c', '')])).toBe(true);
  });

  it('does not condemn a run because ONE function failed to decompile', () => {
    // Normal and expected; a single stubborn function says nothing about the decompiler's presence.
    expect(allPseudocodeEmpty([fn('a', 'int a(void) { return 0; }'), fn('b', '')])).toBe(false);
  });

  it('says nothing about a run that listed no functions at all', () => {
    // An empty list is a different question (a stripped or tiny binary), and must not be read as a broken tool.
    expect(allPseudocodeEmpty([])).toBe(false);
  });

  it('accepts the healthy run — the branch nobody checks', () => {
    expect(allPseudocodeEmpty([fn('a', 'void a(void) {}'), fn('b', 'void b(void) {}')])).toBe(false);
  });
});
