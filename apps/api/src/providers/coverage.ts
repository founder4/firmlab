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
 * Operator assertions are counted on their own axis and never enter the stage arithmetic. A hand-written row is
 * testimony, not execution: three of them on an image nothing has ever analyzed must still read UNEXAMINED, or the
 * banner becomes a way to launder a claim into the appearance of coverage. `findingCount` therefore means
 * *measured* findings throughout — the verdict names the assertions separately so the two numbers can never be
 * silently summed by a reader who sees more rows in the ledger than the count admits.
 *
 * **Why the verdict is localised and a finding's title is not.** Nothing in this sentence is written at measurement
 * time. It is recomposed from the stage table on every request, and what it describes is THE ANALYSIS RUN — which
 * stages this deployment routed to and which of them executed — not the firmware. It is interface copy that happens
 * to be built server-side, so it is composed in the caller's language from `i18n/`. A finding's title and rationale
 * are the opposite: a provider wrote them while measuring and they are stored with the image as evidence, so they
 * render as recorded. Worker names are ids and are interpolated verbatim in either language, because the reader
 * compares the verdict against the stage table printed directly underneath it.
 *
 * Pure: `buildCoverage` takes plain data and returns the report. The route binds it to the store.
 */
import { type Locale, messages } from '../i18n/index.js';
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
  /** MEASURED findings only. Operator assertions are deliberately excluded — they are not a stage's output. */
  findingCount: number;
  /**
   * Active operator assertions on this image. Reported beside the count, never inside it. Optional-shaped for
   * readers that predate it: absent means zero, which is what every image had before assertions existed.
   */
  operatorAssertions: number;
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

/** The first `limit` worker names, plus how many were left out — the list is a summary and must say so. */
function namesAndRest(stages: CoverageStage[], limit: number): { workers: string[]; more: number } {
  return { workers: stages.slice(0, limit).map((s) => s.worker), more: Math.max(0, stages.length - limit) };
}

/**
 * Compose the honest reading of the finding count. The cases are deliberately distinct: "nothing has run" and
 * "everything ran and found nothing" must never produce the same sentence, because they are opposite conclusions —
 * and that has to hold in every language, which is why each branch is its own catalogue entry rather than a
 * placeholder substituted into one shared sentence.
 */
function verdictFor(
  findingCount: number,
  executed: number,
  applicable: number,
  blocked: CoverageStage[],
  degraded: CoverageStage[] = [],
  operatorAssertions = 0,
  locale: Locale = 'en',
): string {
  const t = messages(locale).coverage;
  const missing = applicable - executed;
  // Appended to every branch rather than folded into one. The stage arithmetic above must read identically
  // whether or not anyone has written an assertion — that invariance IS the guarantee, and a clause that only
  // appears in some branches is a clause a reader learns to stop looking for.
  const assertedNote = operatorAssertions ? t.assertions(operatorAssertions) : '';
  const blockedNote = blocked.length ? t.notCovered(namesAndRest(blocked, 4)) : '';
  // A degraded stage RAN, so it counts as executed — but saying "all applicable stages" while one of them only
  // half-worked lets the headline absorb the caveat its own table is showing. Seen on a real OVMF scan: FwHunt
  // ran 17 of 108 rules, and the verdict still read "across all 2 applicable stages".
  const degradedNote = degraded.length ? t.degraded({ count: degraded.length, ...namesAndRest(degraded, 3) }) : '';
  // Joined rather than concatenated so the notes carry no leading space of their own — a catalogue entry that has
  // to remember to start with one is an entry the next language will get wrong.
  const sentence = (base: string, ...notes: string[]): string => [base, ...notes.filter((n) => n)].join(' ');

  if (executed === 0) {
    // Coverage is measured off the autonomous scan's per-worker outcomes, so a stage run on its own from a manual
    // route is invisible here. Saying "nothing has analyzed this image" next to a non-zero finding count would be
    // contradicted by the very row it annotates — which is the same conflation this banner exists to prevent.
    if (findingCount > 0) {
      return sentence(t.verdict.unknownWithFindings({ applicable, findingCount }), assertedNote);
    }
    // Reached when the only rows on the image are assertions. The sentence must stay UNEXAMINED: nothing was
    // analyzed, and a person writing three claims does not change that by one stage.
    return sentence(t.verdict.unexamined(applicable), assertedNote);
  }
  if (findingCount === 0 && missing > 0) {
    return sentence(t.verdict.partialEmpty({ executed, applicable, missing }), blockedNote, degradedNote, assertedNote);
  }
  if (findingCount === 0) {
    return sentence(t.verdict.allRanEmpty(applicable), degradedNote, assertedNote);
  }
  if (missing > 0) {
    return sentence(
      t.verdict.partialWithFindings({ findingCount, executed, applicable, missing }),
      blockedNote,
      degradedNote,
      assertedNote,
    );
  }
  return sentence(t.verdict.complete({ findingCount, applicable }), degradedNote, assertedNote);
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
  /** MEASURED findings only — the caller partitions operator rows out before counting. */
  findingCount: number;
  /** Active operator assertions. Defaults to 0 so every existing caller keeps its exact previous verdict. */
  operatorAssertions?: number;
  /**
   * The language the verdict is composed in. A parameter, never a module-level setting: two requests in two
   * languages can be in flight at once, and it defaults to English so a caller without one — or a request whose
   * `?lang` was absent or unrecognised — gets exactly what it always got.
   */
  locale?: Locale;
}): CoverageReport {
  const { firmwareClass, classRationale, specs, steps, findingCount, operatorAssertions = 0, locale = 'en' } = input;
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
      // `trigger` is the lead the re-plan fired on — recorded by the run and printed as it was recorded. Only the
      // fallback, which this build composes now, is localised.
      reason: step.trigger ?? messages(locale).coverage.scheduledFromLead,
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
    operatorAssertions,
    stages,
    verdict: verdictFor(
      findingCount,
      executed,
      applicable,
      blocked,
      stages.filter((s) => s.status === 'degraded'),
      operatorAssertions,
      locale,
    ),
    // A degraded stage covers less than its name suggests, so the count alone still misleads even at full
    // execution — the banner must stay prominent.
    ambiguous: findingCount === 0 || executed < applicable || stages.some((s) => s.status === 'degraded'),
  };
}
