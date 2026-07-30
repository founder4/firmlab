import { describe, expect, it } from 'vitest';
import {
  UNMEASURED_HARDENING,
  hardeningCoverage,
  hardeningFlag,
  hardeningIsInformative,
  hasAnyHardening,
  isTriaged,
} from './hardening.js';

describe('hardeningFlag — the one place where the blank points at the ALARMING conclusion', () => {
  /**
   * `nx: 0` is a measurement: this binary has no NX. `nx: null` is the absence of one. Rendering both as a blank
   * tells a reader that 2005 of the corpus's 2007 binaries are unhardened when nothing has looked at any of them —
   * which does not lose the fact, it inverts it.
   */
  it('separates measured-absent from never-measured, which are opposite claims here', () => {
    expect(hardeningFlag(0)).toBe('off');
    expect(hardeningFlag(null)).toBe('not-measured');
    expect(hardeningFlag(0)).not.toBe(hardeningFlag(null));
  });

  it('reads a measured protection as on', () => {
    expect(hardeningFlag(1)).toBe('on');
  });

  it('reads undefined as never-measured, not as absent', () => {
    // A field an older build did not write arrives as undefined, and it is silence.
    expect(hardeningFlag(undefined)).toBe('not-measured');
  });

  it('refuses to coerce anything else, in the direction that does NOT reassure', () => {
    // A string from an older build or a float must not become a hardening verdict.
    for (const v of ['1', '0', 1.5, true, false, {}, []]) {
      expect(hardeningFlag(v)).toBe('not-measured');
    }
  });
});

describe('the corpus denominator, which is what makes the columns readable', () => {
  const b = (o: Record<string, unknown> = {}) => ({ nx: null, canary: null, pic: null, triaged: 0, ...o });

  it('counts nothing measured as nothing measured, and says the table is not informative', () => {
    // The real DVRF: 218 binaries, every hardening field null.
    const c = hardeningCoverage(Array.from({ length: 218 }, () => b()));
    expect(c).toEqual({ total: 218, measured: 0, triaged: 0, triagedWithoutFlags: 0 });
    expect(hardeningIsInformative(c)).toBe(false);
  });

  it('counts a row with one measured flag as measured, even when the others are absent', () => {
    const c = hardeningCoverage([b({ nx: 1 }), b(), b()]);
    expect(c.measured).toBe(1);
    expect(hardeningIsInformative(c)).toBe(true);
  });

  it('counts a measured-OFF flag as measured — it is a reading, not a gap', () => {
    const c = hardeningCoverage([b({ canary: 0 })]);
    expect(c.measured).toBe(1);
  });

  /**
   * The third nothing, and it needs its own number: triage RAN and read nothing off the binary. That is not the same
   * as triage never having run, and radare2 on a stripped or packed target legitimately produces it.
   */
  it('separates "triage ran and recorded nothing" from "triage never ran"', () => {
    const c = hardeningCoverage([b({ triaged: 1 }), b(), b({ triaged: 1, nx: 1 })]);
    expect(c.total).toBe(3);
    expect(c.triaged).toBe(2);
    expect(c.measured).toBe(1);
    expect(c.triagedWithoutFlags).toBe(1);
  });

  it('reads the real corpus pair as measured', () => {
    // IMOU's two, the only triaged binaries in 2007: usr/bin/sonia and bin/busybox.
    const c = hardeningCoverage([
      b({ triaged: 1, nx: 1, canary: 1, pic: 0 }),
      b({ triaged: 1, nx: 1, canary: 0, pic: 0 }),
    ]);
    expect(c).toEqual({ total: 2, measured: 2, triaged: 2, triagedWithoutFlags: 0 });
  });

  it('handles an empty binary list without claiming anything', () => {
    const c = hardeningCoverage([]);
    expect(c).toEqual({ total: 0, measured: 0, triaged: 0, triagedWithoutFlags: 0 });
    expect(hardeningIsInformative(c)).toBe(false);
  });
});

describe('isTriaged / hasAnyHardening', () => {
  it('accepts the integer SQLite stores and the boolean a client might', () => {
    expect(isTriaged({ triaged: 1 })).toBe(true);
    expect(isTriaged({ triaged: true })).toBe(true);
    expect(isTriaged({ triaged: 0 })).toBe(false);
    expect(isTriaged({})).toBe(false);
  });

  it('reports no hardening when every flag is absent, and some when one is a zero', () => {
    expect(hasAnyHardening({ nx: null, canary: null, pic: null })).toBe(false);
    expect(hasAnyHardening({ nx: null, canary: 0, pic: null })).toBe(true);
  });
});

describe('UNMEASURED_HARDENING', () => {
  it('names RELRO, which the technique matrix advertises and no provider measures', () => {
    expect([...UNMEASURED_HARDENING]).toEqual(['RELRO']);
  });
});
