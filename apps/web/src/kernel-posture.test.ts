import { describe, expect, it } from 'vitest';
import type { PostureAnswer } from './api';
import { answerClass, moduleSigning, orderAnswers, postureCensus, postureState } from './kernel-posture';

const a = (over: Partial<PostureAnswer>): PostureAnswer => ({
  id: 'q',
  option: 'CONFIG_X',
  question: 'Is X on?',
  verdict: 'unknown',
  bad: false,
  ...over,
});

describe('answerClass — `unknown` is not one state', () => {
  it('separates a question that cannot apply from one that went unanswered', () => {
    // The whole design centre. On the WR940N eight of nine answers are `unknown`, and rendering them alike would
    // invent eight hardening failures on an image that has one.
    expect(answerClass(a({ verdict: 'unknown', reason: 'option-postdates-kernel' }))).toBe('not-applicable');
    expect(answerClass(a({ verdict: 'unknown', reason: 'option-removed-upstream' }))).toBe('not-applicable');
    expect(answerClass(a({ verdict: 'unknown', reason: 'no-kernel-config-shipped' }))).toBe('unanswered');
    expect(answerClass(a({ verdict: 'unknown', reason: 'kernel-blob-not-readable' }))).toBe('unanswered');
  });

  it('treats an undetermined answer with no reason recorded as unanswered, never as inapplicable', () => {
    expect(answerClass(a({ verdict: 'unknown' }))).toBe('unanswered');
  });

  it('lets the provider decide what is dangerous, whatever the verdict says', () => {
    expect(answerClass(a({ verdict: 'on', bad: true }))).toBe('bad');
    expect(answerClass(a({ verdict: 'off', bad: true }))).toBe('bad');
    expect(answerClass(a({ verdict: 'unknown', reason: 'option-postdates-kernel', bad: true }))).toBe('bad');
  });

  it('counts a settled, not-dangerous answer as good whichever way the question is phrased', () => {
    // Some questions are inverted — `off` is the safe answer — so `good` cannot be read off the verdict word.
    expect(answerClass(a({ verdict: 'on', bad: false }))).toBe('good');
    expect(answerClass(a({ verdict: 'off', bad: false }))).toBe('good');
  });

  it('sends an unrecognised verdict to unanswered rather than letting it inherit "passed"', () => {
    expect(answerClass(a({ verdict: 'partially' as NonNullable<PostureAnswer['verdict']> }))).toBe('unanswered');
  });
});

describe('postureCensus', () => {
  it('gives the denominator a bare question count cannot', () => {
    const c = postureCensus([
      a({ bad: true }),
      a({ verdict: 'unknown', reason: 'no-kernel-config-shipped' }),
      a({ verdict: 'unknown', reason: 'option-postdates-kernel' }),
      a({ verdict: 'on' }),
    ]);
    expect(c).toEqual({ total: 4, bad: 1, unanswered: 1, good: 1, notApplicable: 1 });
  });

  it('is all zeroes for no answers rather than throwing', () => {
    expect(postureCensus([])).toEqual({ total: 0, bad: 0, unanswered: 0, good: 0, notApplicable: 0 });
  });
});

describe('orderAnswers', () => {
  it('puts what a reader must act on first and closed questions last', () => {
    const rows = orderAnswers([
      a({ option: 'C_APPLIES_NOT', verdict: 'unknown', reason: 'option-postdates-kernel' }),
      a({ option: 'B_GOOD', verdict: 'on' }),
      a({ option: 'A_BAD', bad: true }),
      a({ option: 'D_OPEN', verdict: 'unknown', reason: 'no-kernel-config-shipped' }),
    ]);
    expect(rows.map((r) => r.option)).toEqual(['A_BAD', 'D_OPEN', 'B_GOOD', 'C_APPLIES_NOT']);
  });

  it('is a total order — the option name breaks the tie, never arrival', () => {
    const one = orderAnswers([a({ option: 'Z', bad: true }), a({ option: 'A', bad: true })]);
    const other = orderAnswers([a({ option: 'A', bad: true }), a({ option: 'Z', bad: true })]);
    expect(one.map((r) => r.option)).toEqual(['A', 'Z']);
    expect(other.map((r) => r.option)).toEqual(['A', 'Z']);
  });

  it('does not mutate the array it was given', () => {
    const input = [a({ option: 'Z', bad: true }), a({ option: 'A', verdict: 'on' })];
    orderAnswers(input);
    expect(input.map((r) => r.option)).toEqual(['Z', 'A']);
  });
});

describe('postureState — four states, and none of them is an empty table', () => {
  it('reports nothing asked as not-run', () => {
    expect(postureState(null)).toEqual({ kind: 'not-run' });
    expect(postureState(undefined)).toEqual({ kind: 'not-run' });
  });

  it('separates a deployment that could not answer from an image with no kernel', () => {
    expect(postureState({ available: false, reason: 'no tool' })).toEqual({ kind: 'unavailable', reason: 'no tool' });
    const notLocated = postureState({ available: true, located: false, reason: 'nothing found', searched: ['/boot'] });
    expect(notLocated).toEqual({ kind: 'not-located', reason: 'nothing found', searched: ['/boot'] });
  });

  it('carries the places it looked, so "not located" is a coverage gap and not a verdict', () => {
    const s = postureState({ available: true, located: false, searched: ['rootfs', 'raw image'] });
    expect(s.kind === 'not-located' && s.searched).toEqual(['rootfs', 'raw image']);
  });

  it('reads a result with neither flag as located — an older row that predates them still renders', () => {
    expect(postureState({ version: '5.4.0' })).toEqual({ kind: 'located' });
  });
});

describe('moduleSigning', () => {
  it('counts signed against what was INSPECTED, not against the total', () => {
    // A walk that could not read every module must not have its silence counted as unsigned modules.
    const m = moduleSigning({ modules: { moduleCount: 73, inspectedCount: 40, signedCount: 0, vermagic: '2.6.31' } });
    expect(m).toEqual({ total: 73, inspected: 40, signed: 0, vermagic: '2.6.31' });
  });

  it('falls back to the total when no inspected count was recorded', () => {
    expect(moduleSigning({ modules: { moduleCount: 5, signedCount: 1 } })?.inspected).toBe(5);
  });

  it('returns null when no module set was inspected at all', () => {
    expect(moduleSigning({ modules: null })).toBeNull();
    expect(moduleSigning({})).toBeNull();
    expect(moduleSigning({ modules: { moduleCount: 0 } })).toBeNull();
  });
});
