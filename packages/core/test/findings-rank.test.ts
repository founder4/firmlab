import { describe, expect, it } from 'vitest';
import { compareFindings, findingCategory, findingRank, isEstablished, severityCensus } from '../src/findings-rank.js';
import type { Finding, FindingProvenance, FindingSeverity } from '../src/types.js';

let seq = 0;
function f(severity: FindingSeverity, proofState: FindingProvenance, title = `t${++seq}`): Finding {
  return { id: `id${++seq}`, imageId: 'img', source: 'test', kind: 'k', title, severity, proofState };
}

describe('isEstablished', () => {
  it('counts the three rungs that assert a property of the image', () => {
    expect(isEstablished('static_confirmed')).toBe(true);
    expect(isEstablished('confirmed_in_emulation')).toBe(true);
    expect(isEstablished('confirmed_full_system')).toBe(true);
  });

  it('does not count a lead — a precondition observed is not a property established', () => {
    expect(isEstablished('needs_runtime_reproduction')).toBe(false);
  });

  it('does not count a block: the question was asked and not answered, which is neither yes nor no', () => {
    expect(isEstablished('blocked_by_platform')).toBe(false);
    expect(isEstablished('blocked_by_security')).toBe(false);
  });

  it('does not count testimony or a dismissal', () => {
    expect(isEstablished('operator_assertion')).toBe(false);
    expect(isEstablished('false_positive')).toBe(false);
  });

  it('treats an unknown proof state as unestablished, so a new rung cannot inherit a claim', () => {
    expect(isEstablished('confirmed_on_physical_device')).toBe(false);
  });
});

describe('findingCategory', () => {
  it('keeps every proof-state meaning in its own exhaustive category', () => {
    expect(findingCategory('static_confirmed')).toBe('established');
    expect(findingCategory('confirmed_in_emulation')).toBe('established');
    expect(findingCategory('confirmed_full_system')).toBe('established');
    expect(findingCategory('needs_runtime_reproduction')).toBe('lead');
    expect(findingCategory('blocked_by_platform')).toBe('blocked');
    expect(findingCategory('blocked_by_security')).toBe('blocked');
    expect(findingCategory('false_positive')).toBe('dismissed');
    expect(findingCategory('operator_assertion')).toBe('asserted');
  });

  it('does not guess what an unfamiliar persisted state means', () => {
    expect(findingCategory('confirmed_on_physical_device')).toBe('other');
  });
});

describe('compareFindings', () => {
  it('orders by severity first — a critical lead still outranks a proven info row', () => {
    const lead = f('critical', 'needs_runtime_reproduction');
    const proven = f('info', 'confirmed_full_system');
    expect(compareFindings(lead, proven)).toBeLessThan(0);
  });

  it('breaks a severity tie by the ladder, not the alphabet', () => {
    // The defect this replaces: `a.proofState < b.proofState` put `blocked_by_platform` above
    // `confirmed_full_system` because 'b' precedes 'c'.
    const blocked = f('high', 'blocked_by_platform');
    const confirmed = f('high', 'confirmed_full_system');
    expect(compareFindings(blocked, confirmed)).toBeGreaterThan(0);
    expect([blocked, confirmed].sort(compareFindings)[0]).toBe(confirmed);
  });

  it('ranks a block below a lead and above a dismissal', () => {
    const lead = f('medium', 'needs_runtime_reproduction');
    const blocked = f('medium', 'blocked_by_security');
    const dismissed = f('medium', 'false_positive');
    expect([dismissed, blocked, lead].sort(compareFindings).map((x) => x.proofState)).toEqual([
      'needs_runtime_reproduction',
      'blocked_by_security',
      'false_positive',
    ]);
  });

  it('is a total order: title then id break the remaining ties, never arrival order', () => {
    const a = { ...f('high', 'static_confirmed', 'aaa'), id: 'z' };
    const b = { ...f('high', 'static_confirmed', 'aaa'), id: 'a' };
    expect([a, b].sort(compareFindings).map((x) => x.id)).toEqual(['a', 'z']);
    expect([b, a].sort(compareFindings).map((x) => x.id)).toEqual(['a', 'z']);
  });

  it('sorts an unknown severity below info rather than above critical', () => {
    const weird = { ...f('info', 'static_confirmed'), severity: 'catastrophic' as FindingSeverity };
    const info = f('info', 'static_confirmed');
    expect([weird, info].sort(compareFindings)[0]).toBe(info);
  });
});

describe('findingRank', () => {
  it('keeps severity dominant over proof state', () => {
    expect(findingRank({ severity: 'critical', proofState: 'needs_runtime_reproduction' })).toBeGreaterThan(
      findingRank({ severity: 'high', proofState: 'confirmed_full_system' }),
    );
  });

  it('separates two rows of equal severity by how far they were proven', () => {
    expect(findingRank({ severity: 'high', proofState: 'confirmed_in_emulation' })).toBeGreaterThan(
      findingRank({ severity: 'high', proofState: 'needs_runtime_reproduction' }),
    );
  });
});

describe('severityCensus', () => {
  it('splits each severity into what was established and what is still a reason to look', () => {
    const census = severityCensus([
      f('critical', 'needs_runtime_reproduction'),
      f('critical', 'needs_runtime_reproduction'),
      f('critical', 'static_confirmed'),
      f('low', 'confirmed_in_emulation'),
    ]);
    expect(census).toEqual([
      {
        severity: 'critical',
        total: 3,
        established: 1,
        leads: 2,
        blocked: 0,
        dismissed: 0,
        asserted: 0,
        other: 0,
        unproven: 2,
      },
      {
        severity: 'low',
        total: 1,
        established: 1,
        leads: 0,
        blocked: 0,
        dismissed: 0,
        asserted: 0,
        other: 0,
        unproven: 0,
      },
    ]);
  });

  it('returns highest severity first and omits severities with no rows', () => {
    const census = severityCensus([f('info', 'static_confirmed'), f('high', 'static_confirmed')]);
    expect(census.map((c) => c.severity)).toEqual(['high', 'info']);
  });

  it('separates leads, blocks, dismissals and assertions while retaining the compatibility sum', () => {
    const census = severityCensus([
      f('high', 'needs_runtime_reproduction'),
      f('high', 'blocked_by_platform'),
      f('high', 'blocked_by_security'),
      f('high', 'operator_assertion'),
      f('high', 'false_positive'),
    ]);
    expect(census[0]).toEqual({
      severity: 'high',
      total: 5,
      established: 0,
      leads: 1,
      blocked: 2,
      dismissed: 1,
      asserted: 1,
      other: 0,
      unproven: 5,
    });
  });

  it('is empty for an empty ledger rather than inventing zero rows', () => {
    expect(severityCensus([])).toEqual([]);
  });
});
