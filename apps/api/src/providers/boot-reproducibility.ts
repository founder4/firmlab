/**
 * What a set of boots of one image supports, and what a single boot does not.
 *
 * This module exists because the same mistake was made three times on this rung, by the same author, each time with
 * real numbers and each time wrong:
 *
 *   - A repaired boot opened two ports and an unrepaired control opened none, so the repair was reported as the
 *     cause. **Retracted:** the kernel's `execve` trace shows the repair never ran.
 *   - The repaired boot's console tail ended at `rcS` line 45, so `rcS` was reported as stopping there.
 *     **Retracted:** the control reached line 46 and a third boot traced `rcS` not at all.
 *   - Three boots of one image then produced `confirmed_full_system` with two open ports,
 *     `confirmed_full_system` with none, and `blocked_by_platform` on a kernel panic.
 *
 * Every one of those conclusions was drawn from n=1 on a process whose variance had never been measured. The
 * arithmetic was right and the inference was not, and no gate in the codebase objected — because the codebase's
 * discipline is about what a MEASUREMENT may claim, and had nothing to say about how many measurements there were.
 *
 * So this is that rule, as code. Given the outcomes of N boots of one image it says what may be concluded, and its
 * first job is to refuse: **one boot of a rung with unmeasured variance supports no causal claim at all.** Not a
 * weaker claim, not a hedged one — none, because "it opened two ports because of X" and "it opened two ports" are
 * different sentences and only the second survives n=1.
 *
 * The distinction it turns on is the one this codebase keeps insisting on, applied to sample size:
 *
 *   - `unobserved`  nothing has booted this image. Says nothing about the rung.
 *   - `single`      one boot. Says what THAT boot did, and nothing about what the next one will do.
 *   - `stable`      every boot agreed. The strongest thing available, and still a statement about N runs.
 *   - `varies`      the boots disagreed, so the rung's own behaviour is a variable and any comparison across boots
 *                   is confounded by it until the variance is characterised.
 *
 * Pure and dependency-free: the caller reads the boots out of the job rows and hands them over.
 */

/** One boot's outcome, reduced to the facts a comparison across boots can actually use. */
export interface BootOutcome {
  /** The proof state the rung recorded. */
  verdict: string;
  /** How many forwarded ports answered. */
  openPorts: number;
  /** Whether the guest kernel panicked, which is an emulation failure and not a firmware result. */
  panic: boolean;
}

export type ReproducibilityKind = 'unobserved' | 'single' | 'stable' | 'varies';

export interface ReproducibilityVerdict {
  kind: ReproducibilityKind;
  /** How many boots this is derived from. */
  n: number;
  /** The distinct outcome signatures seen, most frequent first, as `verdict/openPorts/panic` counts. */
  distribution: { signature: string; count: number }[];
  /** Whether a claim of the form "X caused Y" may be made across boots at all. */
  supportsCausalClaim: boolean;
  /** The sentence a reader gets. Never implies more than `n` allows. */
  reason: string;
}

/** The signature two boots must share to be called the same outcome. Deliberately coarse: a verdict, a reachability, a panic. */
function signatureOf(b: BootOutcome): string {
  return `${b.verdict}/open=${b.openPorts}/panic=${b.panic}`;
}

/**
 * Pure: what N boots of one image support.
 *
 * `supportsCausalClaim` is FALSE for `single` and for `varies`, for different reasons that the prose keeps apart. It
 * is true only for `stable`, and even then it is a licence to compare ARMS, not a licence to attribute — two stable
 * arms that differ still need the intervention to be shown to have executed, which is the step that was missing when
 * the repair was credited with opening two ports.
 */
export function reproducibility(boots: readonly BootOutcome[]): ReproducibilityVerdict {
  const counts = new Map<string, number>();
  for (const b of boots) {
    const sig = signatureOf(b);
    counts.set(sig, (counts.get(sig) ?? 0) + 1);
  }
  const distribution = [...counts.entries()]
    .map(([signature, count]) => ({ signature, count }))
    .sort((a, b) => b.count - a.count || a.signature.localeCompare(b.signature));

  if (boots.length === 0) {
    return {
      kind: 'unobserved',
      n: 0,
      distribution,
      supportsCausalClaim: false,
      reason:
        'Nothing has booted this image on this rung, so there is nothing to be reproducible or otherwise. That is a statement about this workbench, not about the firmware.',
    };
  }
  if (boots.length === 1) {
    return {
      kind: 'single',
      n: 1,
      distribution,
      supportsCausalClaim: false,
      reason: `One boot. It reports what THAT run did (${distribution[0]?.signature}) and nothing about what the next one will do — this rung's variance is unmeasured, so no comparison against another boot can attribute a difference to anything. A second boot of the same configuration is the cheapest next measurement.`,
    };
  }
  if (distribution.length === 1) {
    return {
      kind: 'stable',
      n: boots.length,
      distribution,
      supportsCausalClaim: true,
      reason: `${boots.length} boots, all ${distribution[0]?.signature}. That licences comparing this configuration against another one — it does NOT licence attributing a difference to an intervention without showing the intervention executed.`,
    };
  }
  return {
    kind: 'varies',
    n: boots.length,
    distribution,
    supportsCausalClaim: false,
    reason: `${boots.length} boots produced ${distribution.length} different outcomes (${distribution
      .map((d) => `${d.count}× ${d.signature}`)
      .join(
        '; ',
      )}), so the rung's own behaviour is a variable. Any difference measured between two boots is confounded by it, and a single-boot result from this rung cannot be read as a property of the firmware.`,
  };
}

/**
 * Pure: may a difference between two SETS of boots be attributed to what distinguishes them?
 *
 * Three conditions, and the third is the one whose absence produced the retraction: both arms must be reproducible,
 * they must actually differ, and **the intervention must be shown to have executed**. A comparison that satisfies the
 * first two and not the third is exactly the shape of "the repair made the guest answer" — right arithmetic, absent
 * mechanism.
 */
export function comparisonIsAttributable(input: {
  armA: readonly BootOutcome[];
  armB: readonly BootOutcome[];
  /** Did the thing that distinguishes the arms demonstrably run? `null` means nobody checked. */
  interventionExecuted: boolean | null;
}): { attributable: boolean; reason: string } {
  const a = reproducibility(input.armA);
  const b = reproducibility(input.armB);
  if (!a.supportsCausalClaim || !b.supportsCausalClaim) {
    return {
      attributable: false,
      reason: `At least one arm is not reproducible (A: ${a.kind}, n=${a.n}; B: ${b.kind}, n=${b.n}), so a difference between them is confounded by the rung's own variance.`,
    };
  }
  if (a.distribution[0]?.signature === b.distribution[0]?.signature) {
    return {
      attributable: false,
      reason: 'Both arms are stable and produced the same outcome, so there is nothing to attribute.',
    };
  }
  if (input.interventionExecuted === null) {
    return {
      attributable: false,
      reason:
        'Both arms are stable and they differ, and nobody checked whether the intervention EXECUTED. That is the step whose absence produced this workbench’s one retracted causal claim — an unchecked mechanism is not a weaker attribution, it is none.',
    };
  }
  if (!input.interventionExecuted) {
    return {
      attributable: false,
      reason:
        'Both arms are stable and they differ, and the intervention demonstrably did NOT execute — so whatever separates the arms, it is not that.',
    };
  }
  return {
    attributable: true,
    reason: `Both arms are stable (${a.n} and ${b.n} boots), they differ, and the intervention was shown to execute.`,
  };
}
