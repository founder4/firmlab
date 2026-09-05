import { describe, expect, it } from 'vitest';
import {
  type CapabilityResultBase,
  capabilityState,
  coverageIsPartial,
  coverageNumbers,
  saysSomethingAboutFirmware,
} from './capabilities.js';

const ran = (o: Partial<CapabilityResultBase> & Record<string, unknown> = {}): CapabilityResultBase =>
  ({ available: true, reason: 'ran', findings: [], ...o }) as CapabilityResultBase;

describe('capabilityState — three kinds of nothing, and only one of them is about the firmware', () => {
  it('reads an absent result as not-run, which says nothing at all', () => {
    expect(capabilityState(null)).toEqual({ kind: 'not-run' });
    // `undefined` is the same fact for this screen: nothing has asked.
    expect(capabilityState(undefined)).toEqual({ kind: 'not-run' });
  });

  it('reads an unavailable tool as its OWN state, not as not-run and not as a clean result', () => {
    const s = capabilityState({ available: false, reason: 'yara is not installed in this deployment' });
    expect(s).toEqual({ kind: 'unavailable', reason: 'yara is not installed in this deployment' });
    // The pair the point missed: never-asked and asked-but-unanswerable are different, and neither is a result.
    expect(s.kind).not.toBe('not-run');
    expect(saysSomethingAboutFirmware(s)).toBe(false);
    expect(saysSomethingAboutFirmware(capabilityState(null))).toBe(false);
  });

  it('reads a stage that ran and found NOTHING as a real result — the only one that may be read', () => {
    const s = capabilityState(ran({ reason: '0 matches over 235 files' }));
    expect(s).toEqual({ kind: 'ran', findingCount: 0, reason: '0 matches over 235 files' });
    expect(saysSomethingAboutFirmware(s)).toBe(true);
  });

  it('distinguishes an empty run from a populated one without changing its kind', () => {
    expect(capabilityState(ran({ findings: [1, 2, 3] })).kind).toBe('ran');
    expect(capabilityState(ran({ findings: [] })).kind).toBe('ran');
  });

  it('survives a result stored by an older build that carries no findings array', () => {
    // A persisted result is data written by an OLDER build; a missing field must not become a crash or a wrong 0.
    const s = capabilityState({ available: true, reason: 'stored two commits ago' });
    expect(s).toEqual({ kind: 'ran', findingCount: 0, reason: 'stored two commits ago' });
  });
});

describe('coverageNumbers — an absent denominator is not a zero', () => {
  it('reads fwhunt’s rule denominator, which is the number the scan is about', () => {
    expect(coverageNumbers('fwhunt', ran({ rulesInCorpus: 108, rulesRun: 17, rulesNotApplicable: 91 }))).toEqual({
      denominator: 108,
      applied: 17,
      lost: 91,
      unit: 'rules',
    });
  });

  it('reads yarascan’s from its nested corpus summary', () => {
    expect(coverageNumbers('yarascan', ran({ corpus: { rulesDeclared: 5, rulesApplied: 4, rulesLost: 1 } }))).toEqual({
      denominator: 5,
      applied: 4,
      lost: 1,
      unit: 'rules',
    });
  });

  /**
   * The fixture this replaces was `{ functionCount: 900, functions: [{}, {}] }`, and the provider cannot produce
   * it: `runGhidra` sets `functionCount: functions.length`, so the pair the old code used as denominator and
   * numerator could never differ, and this widget could only ever print "40 of 40". The test passed because its
   * fixture was written from the same assumption as the code — the trap CLAUDE.md records elsewhere.
   */
  it('reads ghidra’s denominator from the eligible count, never from the length of its own list', () => {
    expect(
      coverageNumbers('ghidra', ran({ functionCount: 40, functions: Array(40).fill({}), eligibleCount: 913 })),
    ).toEqual({ denominator: 913, applied: 40, lost: null, unit: 'functions' });
  });

  it('falls back to the whole-program total when only that was recorded', () => {
    expect(coverageNumbers('ghidra', ran({ functionCount: 2, functions: [{}, {}], functionTotal: 900 }))).toEqual({
      denominator: 900,
      applied: 2,
      lost: null,
      unit: 'functions',
    });
  });

  it('reports NO denominator for a result stored before the script counted anything', () => {
    // `functionCount` is present and equals the list length. Reading it as a denominator is what invented a
    // 100%-covered claim, so its absence must produce null rather than a ratio of the list against itself.
    const c = coverageNumbers('ghidra', ran({ functionCount: 40, functions: Array(40).fill({}) }));
    expect(c.applied).toBe(40);
    expect(c.denominator).toBeNull();
  });

  it('returns nulls rather than zeros for a capability that carries no denominator', () => {
    const c = coverageNumbers('nvram', ran({ stores: [{}, {}] }));
    expect(c.applied).toBe(2);
    // Not 0: nvram has no notion of "stores offered", and printing 0 would invent a measurement.
    expect(c.denominator).toBeNull();
    expect(c.lost).toBeNull();
  });

  it('returns all-nulls for a stage that never ran or whose tool was absent', () => {
    for (const r of [null, { available: false, reason: 'absent' }]) {
      const c = coverageNumbers('fwhunt', r);
      expect([c.denominator, c.applied, c.lost]).toEqual([null, null, null]);
    }
  });

  it('does not invent numbers from a result whose fields are the wrong type', () => {
    const c = coverageNumbers('fwhunt', ran({ rulesInCorpus: '108', rulesRun: null }));
    expect(c.denominator).toBeNull();
    expect(c.applied).toBeNull();
  });
});

describe('coverageIsPartial', () => {
  it('is true only when both numbers are known and the applied count is short', () => {
    expect(coverageIsPartial({ denominator: 108, applied: 17, lost: 91, unit: 'rules' })).toBe(true);
    expect(coverageIsPartial({ denominator: 108, applied: 108, lost: 0, unit: 'rules' })).toBe(false);
  });

  it('is FALSE when the denominator is unknown — an absence cannot support either claim', () => {
    expect(coverageIsPartial({ denominator: null, applied: 4, lost: null, unit: 'stores' })).toBe(false);
    expect(coverageIsPartial({ denominator: 10, applied: null, lost: null, unit: 'rules' })).toBe(false);
  });
});
