import { describe, expect, it } from 'vitest';
import { normalizeRunBudget } from './run-budget.js';

const bounds = { defaultSeconds: 60, minSeconds: 5, maxSeconds: 180 };

describe('normalizeRunBudget', () => {
  it('records the effective default when seconds are omitted', () => {
    expect(normalizeRunBudget(undefined, bounds)).toEqual({
      seconds: 60,
      requestedSeconds: null,
      secondsClamped: false,
    });
  });

  it('preserves an in-range operator budget', () => {
    expect(normalizeRunBudget(45, bounds)).toEqual({
      seconds: 45,
      requestedSeconds: 45,
      secondsClamped: false,
    });
  });

  it.each([
    [0, 5],
    [999, 180],
  ])('retains a clamped request of %s seconds alongside the effective %s', (requested, seconds) => {
    expect(normalizeRunBudget(requested, bounds)).toEqual({
      seconds,
      requestedSeconds: requested,
      secondsClamped: true,
    });
  });

  it.each([null, '30', Number.NaN, Number.POSITIVE_INFINITY])('rejects invalid seconds value %s', (raw) => {
    expect(normalizeRunBudget(raw, bounds)).toBeNull();
  });
});
