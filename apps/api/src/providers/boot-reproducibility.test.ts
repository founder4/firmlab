import { describe, expect, it } from 'vitest';
import { type BootOutcome, comparisonIsAttributable, reproducibility } from './boot-reproducibility.js';

const ok = (openPorts = 0): BootOutcome => ({ verdict: 'confirmed_full_system', openPorts, panic: false });
const panicked = (): BootOutcome => ({ verdict: 'blocked_by_platform', openPorts: 0, panic: true });

describe('reproducibility — n=1 supports no causal claim at all', () => {
  /**
   * The pair, applied to sample size: "nothing has booted this image" and "one boot happened" both leave a causal
   * claim unsupported, and they are not the same statement. The first is about the workbench; the second reports
   * what one run did.
   */
  it('separates nothing-observed from one-observed', () => {
    const none = reproducibility([]);
    const one = reproducibility([ok(2)]);
    expect(none.kind).toBe('unobserved');
    expect(one.kind).toBe('single');
    expect(none.supportsCausalClaim).toBe(false);
    expect(one.supportsCausalClaim).toBe(false);
    // Same licence, different fact — and only one of them mentions an outcome.
    expect(none.reason).toMatch(/statement about this workbench/);
    expect(one.reason).toMatch(/confirmed_full_system\/open=2/);
    expect(none.reason).not.toMatch(/open=/);
  });

  it('refuses a causal claim from one boot, and says a second boot is the next measurement', () => {
    const v = reproducibility([ok(2)]);
    expect(v.supportsCausalClaim).toBe(false);
    expect(v.reason).toMatch(/nothing about what the next one will do/);
    expect(v.reason).toMatch(/A second boot of the same configuration is the cheapest next measurement/);
  });

  it('calls agreeing boots stable, and still bounds the claim to N runs', () => {
    const v = reproducibility([ok(2), ok(2), ok(2)]);
    expect(v.kind).toBe('stable');
    expect(v.n).toBe(3);
    expect(v.supportsCausalClaim).toBe(true);
    // Stability licences comparing configurations. It does not licence attribution.
    expect(v.reason).toMatch(
      /does NOT licence attributing a difference to an intervention without showing the intervention executed/,
    );
  });

  it('calls disagreeing boots varies, and names the distribution', () => {
    // The measured corpus case: three boots of the WR940N gave three outcomes.
    const v = reproducibility([ok(2), ok(0), panicked()]);
    expect(v.kind).toBe('varies');
    expect(v.supportsCausalClaim).toBe(false);
    expect(v.distribution).toHaveLength(3);
    expect(v.reason).toMatch(/3 different outcomes/);
    expect(v.reason).toMatch(/cannot be read as a property of the firmware/);
  });

  it('orders the distribution by frequency, so the common outcome is not buried', () => {
    const v = reproducibility([ok(0), ok(0), ok(0), ok(2)]);
    expect(v.distribution[0]?.count).toBe(3);
    expect(v.distribution[0]?.signature).toMatch(/open=0/);
    expect(v.distribution[1]?.count).toBe(1);
  });

  it('treats a panic as its own outcome rather than folding it into the verdict', () => {
    // A kernel panic is an emulation failure, not a firmware result — two boots that both `blocked_by_platform`
    // are still different runs if only one panicked.
    const v = reproducibility([
      { verdict: 'blocked_by_platform', openPorts: 0, panic: true },
      { verdict: 'blocked_by_platform', openPorts: 0, panic: false },
    ]);
    expect(v.kind).toBe('varies');
  });
});

describe('comparisonIsAttributable — the third condition is the one that was missing', () => {
  const stableA = [ok(2), ok(2), ok(2)];
  const stableB = [ok(0), ok(0), ok(0)];

  it('refuses when either arm is not reproducible, and says which', () => {
    const v = comparisonIsAttributable({ armA: [ok(2)], armB: stableB, interventionExecuted: true });
    expect(v.attributable).toBe(false);
    expect(v.reason).toMatch(/A: single, n=1/);
    expect(v.reason).toMatch(/confounded by the rung's own variance/);
  });

  it('refuses when both arms are stable and agree — there is nothing to attribute', () => {
    const v = comparisonIsAttributable({ armA: stableA, armB: [ok(2), ok(2)], interventionExecuted: true });
    expect(v.attributable).toBe(false);
    expect(v.reason).toMatch(/nothing to attribute/);
  });

  /**
   * This is the retracted claim's exact shape: two arms, a real difference, right arithmetic — and nobody asked
   * whether the intervention ran. An unchecked mechanism is not a weaker attribution, it is none.
   */
  it('refuses when nobody checked that the intervention executed', () => {
    const v = comparisonIsAttributable({ armA: stableA, armB: stableB, interventionExecuted: null });
    expect(v.attributable).toBe(false);
    expect(v.reason).toMatch(/nobody checked whether the intervention EXECUTED/);
    expect(v.reason).toMatch(/an unchecked mechanism is not a weaker attribution, it is none/);
  });

  it('refuses, differently, when the intervention demonstrably did not execute', () => {
    const unchecked = comparisonIsAttributable({ armA: stableA, armB: stableB, interventionExecuted: null });
    const didNot = comparisonIsAttributable({ armA: stableA, armB: stableB, interventionExecuted: false });
    expect(didNot.attributable).toBe(false);
    expect(didNot.reason).toMatch(/demonstrably did NOT execute/);
    // Not asked and asked-and-no are different sentences here too.
    expect(didNot.reason).not.toBe(unchecked.reason);
  });

  it('attributes only when all three conditions hold', () => {
    const v = comparisonIsAttributable({ armA: stableA, armB: stableB, interventionExecuted: true });
    expect(v.attributable).toBe(true);
    expect(v.reason).toMatch(
      /Both arms are stable \(3 and 3 boots\), they differ, and the intervention was shown to execute/,
    );
  });
});

/**
 * The defect the module itself had for a few hours, found by running it on the real record.
 *
 * Applied to the WR940N's 17 stored boots it reported `varies` — but those 17 span the shim fix, the per-run port
 * allocation, the measured-arch fix and the build stamp. What varied was the CODEBASE. A reader would have concluded
 * the emulator is unstable from a record of it being repaired.
 */
describe('build filtering — boots from other builds are not repeats of one experiment', () => {
  const at = (rev: string | undefined, openPorts = 0): BootOutcome => ({
    verdict: 'confirmed_full_system',
    openPorts,
    panic: false,
    buildRev: rev,
  });

  it('counts only boots from this build, and reports how many it excluded', () => {
    const v = reproducibility([at('old', 2), at('old', 0), at('new'), at('new'), at('new')], 'new');
    expect(v.kind).toBe('stable');
    expect(v.n).toBe(3);
    expect(v.incomparable).toBe(2);
  });

  it('is the measured corpus case: five consecutive boots of one build are stable', () => {
    // The real series, 2026-07-30: confirmed_full_system / open=0 / no panic, five times.
    const v = reproducibility(
      Array.from({ length: 5 }, () => at('e67b503')),
      'e67b503',
    );
    expect(v.kind).toBe('stable');
    expect(v.n).toBe(5);
    expect(v.incomparable).toBe(0);
    expect(v.supportsCausalClaim).toBe(true);
  });

  /**
   * The pair, at build granularity: no boot from this build, and no boot at all. Both are `unobserved` and only one
   * of them is fixed by booting again — the other says a history exists and cannot be counted.
   */
  it('separates "no boot from this build" from "no boot at all"', () => {
    const excluded = reproducibility([at('old'), at('old')], 'new');
    const none = reproducibility([], 'new');
    expect(excluded.kind).toBe('unobserved');
    expect(none.kind).toBe('unobserved');
    expect(excluded.incomparable).toBe(2);
    expect(none.incomparable).toBe(0);
    expect(excluded.reason).toMatch(/2 earlier boot\(s\) exist and came from another build/);
    expect(excluded.reason).toMatch(/what varied across them may have been the codebase/);
    expect(none.reason).toMatch(/Nothing has booted this image/);
  });

  it('treats a boot that recorded no build as incomparable, not as this build’s', () => {
    // Stored before boots carried the revision: nothing is known about which build ran it.
    const v = reproducibility([at(undefined), at(undefined), at('new')], 'new');
    expect(v.n).toBe(1);
    expect(v.incomparable).toBe(2);
    expect(v.kind).toBe('single');
  });

  it('filters nothing when no build is given, which is what the first version did', () => {
    const v = reproducibility([at('a'), at('b'), at(undefined)]);
    expect(v.n).toBe(3);
    expect(v.incomparable).toBe(0);
  });
});
