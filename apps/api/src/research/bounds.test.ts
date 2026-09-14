import { describe, expect, it } from 'vitest';
import { rootfsKeyWalkWasBounded, selectSecurityDomains } from './bounds.js';

describe('research bounds', () => {
  it('marks a key count as a floor when either stopping condition leaves work unanswered', () => {
    expect(rootfsKeyWalkWasBounded({ keysFound: 20, keyCap: 20, entryBudgetExhausted: false })).toBe(true);
    expect(rootfsKeyWalkWasBounded({ keysFound: 2, keyCap: 20, entryBudgetExhausted: true })).toBe(true);
    expect(rootfsKeyWalkWasBounded({ keysFound: 2, keyCap: 20, entryBudgetExhausted: false })).toBe(false);
  });

  it('retains the provenance-domain denominator and names what the query cap did not ask', () => {
    expect(selectSecurityDomains(['a.test', 'b.test', 'c.test'], 2)).toEqual({
      selected: ['a.test', 'b.test'],
      total: 3,
      unchecked: 1,
    });
    expect(selectSecurityDomains(['a.test'], 5).unchecked).toBe(0);
  });
});
