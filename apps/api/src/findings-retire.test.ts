import { describe, expect, it } from 'vitest';
import {
  MAX_LISTED_ROWS,
  type RetiredRowSummary,
  describeRetirement,
  retirementNote,
  validateRetirement,
} from './findings-retire.js';

const req = { source: 'symreach:lib/libutil-0.9.30.so', retiredBy: 'aaron', reason: 'the queue no longer asks it' };
const row = (over: Partial<RetiredRowSummary> = {}): RetiredRowSummary => ({
  kind: 'sink-reachability-inconclusive',
  title: 'Reachability of 1 sink(s) in lib/libutil-0.9.30.so is unresolved',
  proofState: 'needs_runtime_reproduction',
  ...over,
});

describe('validateRetirement — a deletion with no author and no reason is just a gap', () => {
  it('accepts a complete request and trims it', () => {
    const r = validateRetirement({ source: '  symreach:lib/x.so ', retiredBy: ' aaron ', reason: ' stale ' });
    expect(r).toEqual({ ok: true, value: { source: 'symreach:lib/x.so', retiredBy: 'aaron', reason: 'stale' } });
  });

  it('requires a source, and says what one looks like', () => {
    const r = validateRetirement({ retiredBy: 'aaron', reason: 'x' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('symreach:');
  });

  /**
   * The asymmetry this whole surface rests on. A provider row is a computation and is re-derivable; an assertion
   * is somebody's claim, and a ledger is far better off holding "this was wrong, and here is why" than a gap.
   * `deleteFindingsBySource` already refuses these in the SQL — this refuses them with the route they wanted.
   */
  it('refuses an operator source and names the surface that does handle it', () => {
    const r = validateRetirement({ source: 'operator:aaron', retiredBy: 'aaron', reason: 'mistake' });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error).toContain('withdraw');
      expect(r.error).toContain('retracted, never removed');
    }
  });

  it('requires an author', () => {
    expect(validateRetirement({ source: 'a', reason: 'b' }).ok).toBe(false);
  });

  it('requires a reason, because the reason is the only thing that outlives the rows', () => {
    const r = validateRetirement({ source: 'a', retiredBy: 'aaron' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('came back clean');
  });

  it('bounds the free text rather than storing whatever arrives', () => {
    expect(validateRetirement({ source: 'a', retiredBy: 'x'.repeat(200), reason: 'b' }).ok).toBe(false);
    expect(validateRetirement({ source: 'a', retiredBy: 'aaron', reason: 'b'.repeat(5000) }).ok).toBe(false);
  });
});

describe('retirementNote — what replaces the rows', () => {
  it('names the source, the author, the reason and every row, proof state first', () => {
    const note = retirementNote(req, [row(), row({ proofState: 'static_confirmed', kind: 'sink-reachable' })]);
    expect(note).toContain('Retired 2 computed finding(s)');
    expect(note).toContain('symreach:lib/libutil-0.9.30.so');
    expect(note).toContain('Reason given by aaron: the queue no longer asks it');
    expect(note).toContain('[static_confirmed] sink-reachable');
    expect(note).toContain('[needs_runtime_reproduction] sink-reachability-inconclusive');
  });

  it('states that the removal answered nothing — the one reading it must never license', () => {
    const note = retirementNote(req, [row()]);
    expect(note).toContain('came back clean');
    expect(note).toContain('covers no stage');
    // And why deleting a computed row was permissible in the first place.
    expect(note).toContain('re-running');
  });

  it('bounds the enumeration and says by what rule, keeping the count exact', () => {
    const many = Array.from({ length: MAX_LISTED_ROWS + 7 }, (_, i) => row({ title: `row ${i}` }));
    const note = retirementNote(req, many);
    expect(note).toContain(`Retired ${MAX_LISTED_ROWS + 7} computed finding(s)`);
    expect(note).toContain('7 further row(s) not listed individually');
    expect(note).toContain('the count above is exact');
  });
});

describe('describeRetirement — a mistyped source must not read as success', () => {
  it('reports a match of nothing as the typo it usually is', () => {
    const s = describeRetirement(req, [], false);
    expect(s).toContain('nothing was removed');
    expect(s).toContain('far more often a typo');
  });

  it('names the proof states removed, so retiring a confirmed row is legible as that', () => {
    const s = describeRetirement(req, [row(), row({ proofState: 'static_confirmed' })], false);
    expect(s).toContain('static_confirmed');
    expect(s).toContain('recomputable');
  });

  it('speaks in the conditional for a dry run', () => {
    expect(describeRetirement(req, [row()], true)).toContain('Would retire');
    expect(describeRetirement(req, [row()], false)).toContain('Retired');
  });
});
