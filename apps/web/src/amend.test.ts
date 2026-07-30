import { describe, expect, it } from 'vitest';
import { type AmendableFields, amendmentIsSendable, describeChangedFields, diffAmendment } from './amend.js';

const base: AmendableFields = {
  title: 'The telnet daemon is compiled out of this build',
  claim: 'asserted_from_device',
  rationale: 'I read the applet table on the retail unit.',
  severity: 'medium',
};

describe('diffAmendment — a revision row must correspond to a real change of claim', () => {
  it('reports the fields that differ, in a stable order', () => {
    const d = diffAmendment(base, { ...base, severity: 'high', title: 'Something else' });
    // Field order comes from the module, not from object key order, so the report is a function of the edit.
    expect(d.changed).toEqual(['title', 'severity']);
    expect(d.substantive).toBe(true);
    expect(d.refusal).toBeNull();
    expect(describeChangedFields(d)).toBe('title, severity');
  });

  /**
   * The pair this module exists for. Both produce IDENTICAL values and they are not the same event: one is a form
   * submitted as it opened, the other is a person who considered the wording and arrived at the same claim.
   */
  it('separates a form nobody touched from one retyped to the same text', () => {
    const untouched = diffAmendment(base, { ...base });
    const retyped = diffAmendment(base, { ...base }, new Set(['rationale']));
    expect(untouched.changed).toEqual(retyped.changed);
    expect(untouched.substantive).toBe(retyped.substantive);
    // Same values, same verdict, DIFFERENT reason — which is what the operator is told.
    expect(untouched.refusal).toBe('untouched');
    expect(retyped.refusal).toBe('retyped');
    expect(untouched.refusal).not.toBe(retyped.refusal);
  });

  it('refuses both, because neither is a change the ledger should record', () => {
    expect(amendmentIsSendable(diffAmendment(base, { ...base }))).toBe(false);
    expect(amendmentIsSendable(diffAmendment(base, { ...base }, new Set(['title'])))).toBe(false);
  });

  it('allows an amendment that changes exactly one field', () => {
    const d = diffAmendment(base, { ...base, rationale: 'I re-read it and the applet is present.' });
    expect(d.changed).toEqual(['rationale']);
    expect(amendmentIsSendable(d)).toBe(true);
  });

  it('does not treat a whitespace edit as an amendment, and compares what will be stored', () => {
    const d = diffAmendment(base, { ...base, title: `  ${base.title}  ` }, new Set(['title']));
    expect(d.changed).toEqual([]);
    expect(d.refusal).toBe('retyped');
    expect(amendmentIsSendable(d)).toBe(false);
  });

  it('treats a field emptied to whitespace as a change, since it changes what is stored', () => {
    const d = diffAmendment(base, { ...base, rationale: '   ' });
    expect(d.changed).toEqual(['rationale']);
    expect(amendmentIsSendable(d)).toBe(true);
  });

  it('reports every field when every field changed', () => {
    const d = diffAmendment(base, {
      title: 'a',
      claim: 'asserted_unverified',
      rationale: 'b',
      severity: 'low',
    });
    expect(d.changed).toEqual(['title', 'claim', 'rationale', 'severity']);
  });

  it('describes an empty change as an empty string rather than inventing prose', () => {
    expect(describeChangedFields(diffAmendment(base, { ...base }))).toBe('');
  });
});
