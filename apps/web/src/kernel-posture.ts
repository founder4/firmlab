/**
 * Reading a kernel-posture result — the decisions, without a DOM.
 *
 * **Why this exists.** `providers/kernelposture.ts` is 1618 lines, produces 36 findings across this corpus, has a
 * route, and `api.kernelPosture` is declared in the client and called by **nothing**. The richest payload the
 * workbench computes about a device reaches no screen at all, which is the honest version of "I run a kernel
 * posture and I never find a results table".
 *
 * **The distinction the table is built around.** On the WR940N, eight of nine questions come back `unknown`, and
 * `unknown` is not one state. The provider records WHY, and two of its reasons mean opposite things to a reader:
 *
 *   - `option-postdates-kernel` / `option-removed-upstream` — **the question does not apply**. `CONFIG_RANDOMIZE_BASE`
 *     landed upstream in 3.14; asking a 2.6.31 kernel whether it has KASLR is asking about a feature that did not
 *     exist. Rendering that beside a real gap would invent eight hardening failures on an image that has one.
 *   - everything else (`no-kernel-config-shipped`, `no-kernel-blob`, `kernel-blob-not-readable`,
 *     `no-marker-evidence`, `kernel-version-unknown`) — **the question applies and this image did not answer it.**
 *     A gap in coverage, never a negative.
 *
 * Collapsing those two into "unknown" is the same conflation `ProofState` exists to prevent, one level down. So
 * `answerClass` returns four values and the table groups by them.
 *
 * **Ordering is by class, never by arrival.** The provider emits its questions in its own declaration order, which
 * puts the one dangerous answer wherever it happens to fall. Bad first, then the questions that went unanswered,
 * then the ones that passed, then the ones that do not apply — because that is descending order of what a reader
 * has to do about them.
 *
 * Pure and dependency-free.
 */
import type { KernelPostureResult, PostureAnswer } from './api';

/**
 * The four things an answer can be, from the reader's side.
 *
 * `not-applicable` is deliberately a peer of the others rather than a flavour of `unanswered`: an option that
 * postdates the kernel is a closed question, and grouping it with open ones would overstate the work outstanding.
 */
export type AnswerClass = 'bad' | 'unanswered' | 'good' | 'not-applicable';

/** The undetermined reasons that mean the question could not exist for this kernel, rather than went unanswered. */
const INAPPLICABLE: ReadonlySet<string> = new Set(['option-postdates-kernel', 'option-removed-upstream']);

/**
 * Pure: which class an answer falls in.
 *
 * `bad` wins over everything, including a verdict this reader does not recognise: the provider decided the row was
 * the dangerous one and that decision is not re-derived here. An unfamiliar verdict with `bad !== true` is
 * `unanswered` rather than `good` — the safe direction, since a future verdict inheriting "passed" would be a
 * silent claim about hardening nobody made.
 */
export function answerClass(a: PostureAnswer): AnswerClass {
  if (a.bad === true) return 'bad';
  if (a.verdict === 'unknown') return INAPPLICABLE.has(a.reason ?? '') ? 'not-applicable' : 'unanswered';
  return a.verdict === 'on' || a.verdict === 'off' ? 'good' : 'unanswered';
}

/** How many answers sit in each class. The denominator a bare "9 questions" cannot give. */
export interface PostureCensus {
  total: number;
  bad: number;
  unanswered: number;
  good: number;
  notApplicable: number;
}

export function postureCensus(answers: readonly PostureAnswer[]): PostureCensus {
  const c: PostureCensus = { total: answers.length, bad: 0, unanswered: 0, good: 0, notApplicable: 0 };
  for (const a of answers) {
    const k = answerClass(a);
    if (k === 'bad') c.bad += 1;
    else if (k === 'unanswered') c.unanswered += 1;
    else if (k === 'good') c.good += 1;
    else c.notApplicable += 1;
  }
  return c;
}

const CLASS_ORDER: Record<AnswerClass, number> = { bad: 0, unanswered: 1, good: 2, 'not-applicable': 3 };

/**
 * Pure: the display order — class first, then the option name.
 *
 * The second key is what makes it a total order. Ties broken by arrival would make the table an artifact of the
 * provider's declaration order, and any future cap's cut an artifact of the same thing.
 */
export function orderAnswers(answers: readonly PostureAnswer[]): PostureAnswer[] {
  return [...answers].sort((x, y) => {
    const d = CLASS_ORDER[answerClass(x)] - CLASS_ORDER[answerClass(y)];
    if (d !== 0) return d;
    const ox = x.option ?? x.id ?? '';
    const oy = y.option ?? y.id ?? '';
    return ox < oy ? -1 : ox > oy ? 1 : 0;
  });
}

/**
 * What state the whole stage is in — the four a reader must be able to tell apart.
 *
 * `not-located` is the one worth spelling out: the questions were asked and no kernel was found to ask them of, so
 * the result carries `searched`, the list of places it looked. That is a gap in this analysis, never a statement
 * that the image has no kernel, and it must not render as an empty table.
 */
export type PostureState =
  | { kind: 'not-run' }
  | { kind: 'unavailable'; reason: string }
  | { kind: 'not-located'; reason: string; searched: string[] }
  | { kind: 'located' };

export function postureState(result: KernelPostureResult | null | undefined): PostureState {
  if (!result) return { kind: 'not-run' };
  if (result.available === false) return { kind: 'unavailable', reason: result.reason ?? '' };
  if (result.located === false) {
    return { kind: 'not-located', reason: result.reason ?? '', searched: result.searched ?? [] };
  }
  return { kind: 'located' };
}

/**
 * Pure: the module-signing picture, or null when no module set was inspected.
 *
 * `signed` of `inspected` rather than of `total`: a walk that could not read every module must not have its
 * silence counted as unsigned modules. Returned as numbers so the caller can print the denominator it was given.
 */
export interface ModuleSigning {
  total: number;
  inspected: number;
  signed: number;
  vermagic: string | null;
}

export function moduleSigning(result: KernelPostureResult | null | undefined): ModuleSigning | null {
  const m = result?.modules as
    | { moduleCount?: number; inspectedCount?: number; signedCount?: number; vermagic?: string; total?: number }
    | null
    | undefined;
  if (!m) return null;
  const total = m.moduleCount ?? m.total ?? 0;
  if (total === 0) return null;
  return {
    total,
    inspected: m.inspectedCount ?? total,
    signed: m.signedCount ?? 0,
    vermagic: m.vermagic ?? null,
  };
}
