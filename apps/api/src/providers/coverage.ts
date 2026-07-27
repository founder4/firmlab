/**
 * Analysis coverage — the answer to "does zero findings mean this firmware is clean?".
 *
 * It almost never does. A firmware can show an empty findings list because every applicable stage ran and found
 * nothing (a real, if narrow, negative result), OR because extraction never recovered a rootfs and eight of the
 * eleven stages were skipped, OR because the class routes to a worker that is not built yet. Those read identically
 * in a flat list of findings, and the difference is the whole difference between "audited" and "unexamined".
 *
 * This computes, for one image, which stages its device class routes to, which of them actually executed, and the
 * single sentence that says what the finding count does and does not cover. The class routing is NOT re-derived
 * here — it reads `specsForClass`, the same unit-tested plan W9 executes, so the banner and the autonomous scan can
 * never disagree. Execution status comes from the last completed opacidad run's per-worker outcomes; with no run
 * yet, every applicable stage is honestly `not-run` rather than being assumed fine.
 *
 * Pure: `buildCoverage` takes plain data and returns the report. The route binds it to the store.
 */
import type { OpacidadStep } from '../opacidad-narrative.js';
import type { PlanSpec } from '../opacidad-plan.js';

export type StageStatus =
  | 'found' // ran and recorded findings
  | 'ran-empty' // ran and recorded nothing — a real negative, for this stage only
  | 'no-input' // skipped: the input it needs (usually a rootfs) was never recovered
  | 'degraded' // ran but could not do its full job (tool absent, partial data)
  | 'not-built' // this class routes here, but the deep worker does not exist yet
  | 'not-run'; // applicable and buildable, but nothing has executed it yet

export interface CoverageStage {
  worker: string;
  /** Why the class routes to this stage — the "what could this even tell me" line. */
  reason: string;
  status: StageStatus;
  detail?: string;
  findingCount?: number;
}

export interface CoverageReport {
  firmwareClass: string;
  classRationale?: string;
  /** Stages this device class routes to at all. */
  applicable: number;
  /** Of those, how many actually executed (ran or degraded). */
  executed: number;
  findingCount: number;
  stages: CoverageStage[];
  /** The one honest sentence about what this image's finding count covers. */
  verdict: string;
  /** True when the finding count alone would mislead — the UI shows the banner prominently. */
  ambiguous: boolean;
}

/** Map one executed worker's opacidad outcome to a coverage status. */
function statusOfStep(step: OpacidadStep): StageStatus {
  switch (step.status) {
    case 'ran':
      return (step.findingCount ?? 0) > 0 ? 'found' : 'ran-empty';
    case 'degraded':
      return 'degraded';
    case 'skipped':
      return 'no-input';
    default:
      return 'not-built';
  }
}

/**
 * Compose the honest reading of the finding count. The cases are deliberately distinct: "nothing has run" and
 * "everything ran and found nothing" must never produce the same sentence, because they are opposite conclusions.
 */
function verdictFor(
  findingCount: number,
  executed: number,
  applicable: number,
  blocked: CoverageStage[],
  degraded: CoverageStage[] = [],
): string {
  const missing = applicable - executed;
  const blockedNote = blocked.length
    ? ` Not covered: ${blocked
        .slice(0, 4)
        .map((s) => s.worker)
        .join(', ')}${blocked.length > 4 ? `, +${blocked.length - 4} more` : ''}.`
    : '';
  // A degraded stage RAN, so it counts as executed — but saying "all applicable stages" while one of them only
  // half-worked lets the headline absorb the caveat its own table is showing. Seen on a real OVMF scan: FwHunt
  // ran 17 of 108 rules, and the verdict still read "across all 2 applicable stages".
  const degradedNote = degraded.length
    ? ` ${degraded.length} stage(s) ran DEGRADED and cover less than their name suggests: ${degraded
        .slice(0, 3)
        .map((s) => s.worker)
        .join(', ')}${degraded.length > 3 ? `, +${degraded.length - 3} more` : ''}.`
    : '';

  if (executed === 0) {
    // Coverage is measured off the autonomous scan's per-worker outcomes, so a stage run on its own from a manual
    // route is invisible here. Saying "nothing has analyzed this image" next to a non-zero finding count would be
    // contradicted by the very row it annotates — which is the same conflation this banner exists to prevent.
    if (findingCount > 0) {
      return `No autonomous scan has run, so coverage of the ${applicable} applicable stage(s) is UNKNOWN. The ${findingCount} finding(s) here come from individually-run stages — real results, but no basis for reading the rest as clean.`;
    }
    return `Nothing has analyzed this image yet — ${applicable} applicable stage(s) are unexecuted. An empty findings list here means UNEXAMINED, not clean.`;
  }
  if (findingCount === 0 && missing > 0) {
    return `${executed} of ${applicable} stages ran and recorded nothing; ${missing} never ran. Zero findings covers only the stages that ran — it is not a clean bill for this firmware.${blockedNote}${degradedNote}`;
  }
  if (findingCount === 0) {
    return `All ${applicable} applicable stages ran and recorded nothing. That is a real negative for what this deployment can check statically — it is not proof the firmware is secure.${degradedNote}`;
  }
  if (missing > 0) {
    return `${findingCount} finding(s) from ${executed} of ${applicable} stages; ${missing} never ran, so the picture is incomplete.${blockedNote}${degradedNote}`;
  }
  return `${findingCount} finding(s) across all ${applicable} applicable stages.${degradedNote}`;
}

/**
 * Pure: build the coverage report from the class plan, the last run's outcomes (if any) and the finding count.
 * Workers the run scheduled dynamically (W9 re-planning) are appended — they are real coverage that the static
 * class plan does not predict.
 */
export function buildCoverage(input: {
  firmwareClass: string;
  classRationale?: string;
  specs: PlanSpec[];
  steps: OpacidadStep[] | null;
  findingCount: number;
}): CoverageReport {
  const { firmwareClass, classRationale, specs, steps, findingCount } = input;
  const byWorker = new Map((steps ?? []).map((s) => [s.worker, s]));

  const stages: CoverageStage[] = specs.map((spec) => {
    const step = byWorker.get(spec.worker);
    if (!step) {
      // Planned for this class but absent from the run: either it was never built, or nothing has run it yet.
      return { worker: spec.worker, reason: spec.reason, status: spec.built ? 'not-run' : 'not-built' };
    }
    const status = statusOfStep(step);
    return {
      worker: spec.worker,
      reason: spec.reason,
      status,
      ...(step.note ? { detail: step.note } : { detail: step.summary }),
      ...(step.findingCount !== undefined ? { findingCount: step.findingCount } : {}),
    };
  });

  // Dynamically re-planned workers (targeted decompiles, reachability probes) are coverage the class DAG never
  // named — list them so the operator sees the whole of what was examined, not just the seed plan.
  for (const step of steps ?? []) {
    if (byWorker.has(step.worker) && specs.some((s) => s.worker === step.worker)) continue;
    stages.push({
      worker: step.worker,
      reason: step.trigger ?? 'scheduled dynamically from a lead',
      status: statusOfStep(step),
      detail: step.note ?? step.summary,
      ...(step.findingCount !== undefined ? { findingCount: step.findingCount } : {}),
    });
  }

  const applicable = stages.length;
  const executed = stages.filter(
    (s) => s.status === 'found' || s.status === 'ran-empty' || s.status === 'degraded',
  ).length;
  const blocked = stages.filter((s) => s.status === 'no-input' || s.status === 'not-built' || s.status === 'not-run');

  return {
    firmwareClass,
    ...(classRationale ? { classRationale } : {}),
    applicable,
    executed,
    findingCount,
    stages,
    verdict: verdictFor(
      findingCount,
      executed,
      applicable,
      blocked,
      stages.filter((s) => s.status === 'degraded'),
    ),
    // A degraded stage covers less than its name suggests, so the count alone still misleads even at full
    // execution — the banner must stay prominent.
    ambiguous: findingCount === 0 || executed < applicable || stages.some((s) => s.status === 'degraded'),
  };
}
