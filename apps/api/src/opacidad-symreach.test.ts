import { describe, expect, it } from 'vitest';
import { summarizeLibraryReach } from './opacidad-symreach.js';
import type { LibrarySinkResult, SymReachResult } from './providers/symreach.js';

const sink = (o: Partial<LibrarySinkResult>): LibrarySinkResult => ({
  sink: 'strcpy',
  outcome: 'not_reached_in_budget',
  addresses: [],
  entryPointsAttempted: 16,
  entryPointsCompleted: 0,
  steps: 0,
  pruned: false,
  errors: 0,
  ...o,
});

const result = (o: Partial<SymReachResult>): SymReachResult => ({
  available: true,
  reason: 'bounded search',
  binary: 'lib/libfoo.so',
  sinks: [],
  findings: [],
  ...o,
});

const library = (sinks: LibrarySinkResult[]) => ({
  entryPointsTotal: 118,
  entryPointsConsidered: 16,
  maxEntryPoints: 16,
  sinks,
  budgetSeconds: 120,
});

describe('summarizeLibraryReach — the library rung as W9 states it', () => {
  it('names the reached sinks and the export bound, without degrading', () => {
    const s = summarizeLibraryReach(
      'lib/libfoo.so',
      result({ mode: 'library', library: library([sink({ outcome: 'reached' })]) }),
    );
    expect(s?.summary).toBe('reachability lib/libfoo.so (library): strcpy reachable from 16 of 118 export(s)');
    expect(s?.degraded).toBeUndefined();
  });

  it('keeps reaching nothing inconclusive, never clean, and names the remedy', () => {
    const s = summarizeLibraryReach('lib/libfoo.so', result({ mode: 'library', library: library([sink({})]) }));
    expect(s?.summary).toContain('inconclusive, not clean');
    expect(s?.degraded).toBe(true);
    expect(s?.remedy).toBe('unbounded-search');
    expect(s?.note).toBe('bounded search');
  });

  it('leaves an executable result, or a library result missing its block, to the entry-point path', () => {
    expect(summarizeLibraryReach('bin/x', result({}))).toBeNull();
    expect(summarizeLibraryReach('bin/x', result({ mode: 'executable' }))).toBeNull();
    expect(summarizeLibraryReach('lib/x.so', result({ mode: 'library' }))).toBeNull();
  });
});
