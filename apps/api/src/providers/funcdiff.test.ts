import { describe, expect, it } from 'vitest';
import {
  type FuncSig,
  RECOMPILE_THRESHOLD,
  buildFuncDiffFindings,
  classifyDiff,
  formatRatio,
  isSyntheticName,
  matchFunctions,
  parseFunctions,
} from './funcdiff.js';

const fn = (name: string, o: Partial<FuncSig> = {}): FuncSig => ({
  name,
  offset: 0x400000,
  size: 100,
  nbbs: 5,
  cc: 3,
  ninstrs: 40,
  edges: 6,
  ...o,
});

/** N distinct name-matched functions with distinct shapes, identical on both sides. */
const stable = (n: number): FuncSig[] =>
  Array.from({ length: n }, (_, i) => fn(`sym.f${i}`, { nbbs: i + 2, cc: i + 1, ninstrs: 10 + i, edges: i + 3 }));

describe('isSyntheticName — an address is not an identity', () => {
  it('rejects radare2 placeholders, which encode the ADDRESS and move with any earlier change', () => {
    expect(isSyntheticName('fcn.00400abc')).toBe(true);
    expect(isSyntheticName('sub.400abc')).toBe(true);
    expect(isSyntheticName('loc.0x1234')).toBe(true);
    expect(isSyntheticName('0x400abc')).toBe(true);
  });
  it('keeps real symbols', () => {
    expect(isSyntheticName('sym.imp.strcpy')).toBe(false);
    expect(isSyntheticName('main')).toBe(false);
  });
});

describe('parseFunctions', () => {
  it('reads the aflj fields it compares on', () => {
    const fs = parseFunctions([{ name: 'main', offset: 4096, size: 120, nbbs: 7, cc: 4, ninstrs: 55, edges: 9 }]);
    expect(fs[0]).toMatchObject({ name: 'main', size: 120, nbbs: 7, cc: 4, ninstrs: 55, edges: 9 });
  });
  it('drops nameless or malformed entries rather than comparing garbage', () => {
    expect(parseFunctions([{ size: 10 }, null, 'x'])).toEqual([]);
    expect(parseFunctions('not an array')).toEqual([]);
  });
});

describe('matchFunctions', () => {
  it('matches real symbols by name across builds even when addresses moved', () => {
    const a = [fn('main', { offset: 0x400100 }), fn('sym.helper', { offset: 0x400200 })];
    const b = [fn('sym.helper', { offset: 0x500200 }), fn('main', { offset: 0x500100 })];
    const m = matchFunctions(a, b);
    expect(m.pairs).toHaveLength(2);
    expect(m.onlyA).toHaveLength(0);
    expect(m.onlyB).toHaveLength(0);
  });

  it('matches stripped functions structurally when the fingerprint is unique on both sides', () => {
    const a = [fn('fcn.00400100', { nbbs: 9, cc: 7, ninstrs: 81, edges: 12 })];
    const b = [fn('fcn.00500999', { nbbs: 9, cc: 7, ninstrs: 81, edges: 12 })];
    const m = matchFunctions(a, b);
    expect(m.pairs).toHaveLength(1);
    expect(m.ambiguous).toHaveLength(0);
  });

  // A binary is full of trivial identical-shaped stubs. Pairing those arbitrarily would manufacture "changes" out
  // of an ordering coincidence, so neither side is claimed.
  it('refuses to pair an ambiguous fingerprint instead of guessing', () => {
    const shape = { nbbs: 1, cc: 1, ninstrs: 4, edges: 0 };
    const a = [fn('fcn.0040a', shape), fn('fcn.0040b', shape)];
    const b = [fn('fcn.0050a', shape), fn('fcn.0050b', shape)];
    const m = matchFunctions(a, b);
    expect(m.pairs).toHaveLength(0);
    expect(m.ambiguous).toHaveLength(2);
  });

  it('reports functions present on only one side', () => {
    const m = matchFunctions([fn('sym.gone')], [fn('sym.fresh')]);
    expect(m.onlyA.map((f) => f.name)).toEqual(['sym.gone']);
    expect(m.onlyB.map((f) => f.name)).toEqual(['sym.fresh']);
  });
});

describe('classifyDiff — the verdict is the point', () => {
  it('calls a byte-stable build identical', () => {
    const d = classifyDiff('bin/x', matchFunctions(stable(12), stable(12)));
    expect(d.verdict).toBe('identical');
    expect(d.functions).toEqual([]);
  });

  it('localizes a small delta as patched, tightest change first', () => {
    const a = stable(20);
    const b = stable(20).map((f, i) =>
      i === 3 ? { ...f, ninstrs: f.ninstrs + 9, size: f.size + 20 } : i === 7 ? { ...f, ninstrs: f.ninstrs + 2 } : f,
    );
    const d = classifyDiff('bin/httpd', matchFunctions(a, b));
    expect(d.verdict).toBe('patched');
    expect(d.changed).toBe(2);
    // A bounds check is a couple of instructions; a rewritten function is many. Read the tight one first.
    expect(d.functions[0]?.name).toBe('sym.f7');
    expect(d.functions[0]?.delta?.ninstrs).toBe(2);
  });

  // The defining honesty case: a toolchain bump moves nearly every function, and a 400-entry "candidate list"
  // would be noise presented as analysis.
  it('calls a wholesale rewrite a REBUILD and withholds the candidate list', () => {
    const a = stable(20);
    const b = stable(20).map((f, i) => (i < 15 ? { ...f, ninstrs: f.ninstrs + 3, size: f.size + 8 } : f));
    const d = classifyDiff('bin/busybox', matchFunctions(a, b));
    expect(d.verdict).toBe('recompiled');
    expect(d.changed / d.matched).toBeGreaterThan(RECOMPILE_THRESHOLD);
    expect(d.functions).toEqual([]);
    expect(d.reason).toContain('REBUILD, not a patch');
    expect(d.reason).toContain('noise presented as analysis');
  });

  it('refuses to judge when too little surface matched', () => {
    const a = [fn('sym.a'), fn('sym.b', { nbbs: 9, cc: 8, ninstrs: 90, edges: 11 })];
    const b = [fn('sym.a', { ninstrs: 99 }), fn('sym.b', { nbbs: 9, cc: 8, ninstrs: 90, edges: 11 })];
    const d = classifyDiff('bin/tiny', matchFunctions(a, b));
    expect(d.verdict).toBe('incomparable');
    expect(d.reason).toContain('too little surface');
  });

  it('is incomparable, not identical, when nothing matched at all', () => {
    const d = classifyDiff('bin/x', matchFunctions([fn('sym.only_a')], []));
    expect(d.verdict).toBe('incomparable');
    expect(d.reason).toContain('nothing here is a comparison');
  });
});

describe('buildFuncDiffFindings — a changed function is a fact, not a fix', () => {
  it('emits the candidate list for a patched verdict, phrased as a code fact', () => {
    const a = stable(20);
    const b = stable(20).map((f, i) => (i === 3 ? { ...f, ninstrs: f.ninstrs + 2 } : f));
    const drafts = buildFuncDiffFindings(classifyDiff('bin/httpd', matchFunctions(a, b)), 'v1.0.bin', 'v1.1.bin');
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('function-diff-candidate');
    expect(drafts[0]?.proofState).toBe('static_confirmed');
    expect(drafts[0]?.rationale).toContain('an inference this does not make');
  });

  it('says nothing at all when the binaries are identical', () => {
    expect(buildFuncDiffFindings(classifyDiff('bin/x', matchFunctions(stable(12), stable(12))), 'a', 'b')).toEqual([]);
  });

  // "Compared and could not localize" and "no change found" are different results, and only one is reassuring.
  it('records a rebuild as inconclusive rather than staying silent', () => {
    const a = stable(20);
    const b = stable(20).map((f, i) => (i < 15 ? { ...f, ninstrs: f.ninstrs + 3 } : f));
    const drafts = buildFuncDiffFindings(classifyDiff('bin/busybox', matchFunctions(a, b)), 'v1', 'v2');
    expect(drafts[0]?.kind).toBe('function-diff-inconclusive');
    expect(drafts[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(drafts[0]?.rationale).toContain('rather than as "no change found"');
  });
});

describe('formatRatio — a percentage must not contradict the count beside it', () => {
  // Seen on a real build pair: "4 of 873 matched functions (0%) changed" — the 0% reads as "nothing changed"
  // standing next to the 4 that did, and a tiny fraction is exactly the interesting case here.
  it('renders a sub-1% change as <1%, never as 0%', () => {
    expect(formatRatio(4, 873)).toBe('<1%');
  });
  it('renders a genuine zero and ordinary fractions plainly', () => {
    expect(formatRatio(0, 873)).toBe('0%');
    expect(formatRatio(31, 39)).toBe('79%');
    expect(formatRatio(1, 0)).toBe('—');
  });
});
