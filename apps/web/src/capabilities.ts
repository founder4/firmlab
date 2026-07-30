/**
 * The capabilities that run and cannot be read.
 *
 * Five providers ship a POST and a GET route, sync findings under their own source, and have ZERO references in this
 * app: `yarascan`, `funcdiff`, `fwhunt`, `nvram` and `ghidra`. Each one carries a coverage story that exists only to
 * be read — yarascan's `rulesDeclared`/`rulesApplied`/`rulesLost`, nvram's `capped` and `duplicateKeys`, fwhunt's
 * `rulesRun` against `rulesInCorpus`, funcdiff's `unmatchable` — and none of it reaches a screen. A stage that never
 * ran is therefore invisible rather than reported as not-run, which is the exact conflation the coverage banner
 * exists to prevent, arriving through the absence of a reader rather than through a wrong sentence.
 *
 * **Three states, not two.** The obvious reading is "no result versus a result", and it is wrong in the way this
 * codebase keeps having to correct: `available: false` is a third thing. The question WAS asked, the deployment
 * could not answer it, and the honest label is the one the API already uses for that — `blocked_by_platform`, never
 * a negative. Collapsing it into either neighbour loses the distinction the whole workbench is built on:
 *
 *   - `not-run`     nothing has asked. Says nothing about the firmware.
 *   - `unavailable` asked; the tool is absent from this deployment. Says nothing about the firmware either, and for
 *                   a different reason, which is why it cannot share a sentence with `not-run`.
 *   - `ran`         asked and answered. An EMPTY answer here is a real result, and it is the only one of the three
 *                   that the coverage story can qualify.
 *
 * Pure and dependency-free: every decision below is reachable from a unit test without a DOM or a client.
 */

/** The five capability ids, as they appear in their routes. */
export type CapabilityId = 'yarascan' | 'fwhunt' | 'nvram' | 'ghidra' | 'funcdiff' | 'dynprobe';

/** The shape every one of the five results shares. Anything beyond this is read per capability. */
export interface CapabilityResultBase {
  available: boolean;
  /**
   * Optional, and it has to be: `GhidraResult.reason` is declared optional on the client and a result persisted by
   * an older build may carry none. Requiring it here would make this module reject the very shapes it exists to read.
   */
  reason?: string;
  /** Present on all five; a stage that ran and produced none is a result, not a silence. */
  findings?: unknown[];
}

export type CapabilityState =
  | { kind: 'not-run' }
  | { kind: 'unavailable'; reason: string }
  | { kind: 'ran'; findingCount: number; reason: string };

/**
 * Pure: which of the three a stored result is.
 *
 * Takes `undefined` as well as `null` because a client that has not fetched yet and a route that answered `null` are
 * the same fact for this screen — nothing has been asked — while a fetch still in flight is the caller's own
 * loading state and never reaches here.
 */
export function capabilityState(result: CapabilityResultBase | null | undefined): CapabilityState {
  if (!result) return { kind: 'not-run' };
  if (!result.available) return { kind: 'unavailable', reason: result.reason ?? '' };
  return { kind: 'ran', findingCount: result.findings?.length ?? 0, reason: result.reason ?? '' };
}

/**
 * Whether this state may be read as saying anything at all about the firmware.
 *
 * Only `ran` may. It is a separate function rather than a field because it is the question a reader actually has,
 * and answering it in one place stops five panels from each deciding it differently.
 */
export function saysSomethingAboutFirmware(s: CapabilityState): boolean {
  return s.kind === 'ran';
}

/** One capability's own denominator, as numbers this screen can print beside its state. */
export interface CoverageNumbers {
  /** What was offered to the stage. */
  denominator: number | null;
  /** What the stage actually applied or examined. */
  applied: number | null;
  /** What it lost, dropped or could not read — the part a bare count hides. */
  lost: number | null;
  /** The unit, so a row reads "17 of 108 rules" rather than "17 of 108". */
  unit: string;
}

/**
 * Pure: pull the coverage numbers out of a result, per capability.
 *
 * `null` for a number means the result does not carry it — NOT zero. Printing 0 for an absent field would invent a
 * measurement, which is the same defect as an empty findings list read as clean; a caller renders an absent number
 * as an em-dash and says why in the row's own sentence.
 */
export function coverageNumbers(id: CapabilityId, result: CapabilityResultBase | null | undefined): CoverageNumbers {
  const none: CoverageNumbers = { denominator: null, applied: null, lost: null, unit: '' };
  if (!result || !result.available) return none;
  // Through `unknown`: the base type declares only the shared contract, and the per-capability fields below are
  // read off the same object without widening that contract for every caller.
  const r = result as unknown as Record<string, unknown>;
  const num = (v: unknown): number | null => (typeof v === 'number' ? v : null);
  switch (id) {
    case 'fwhunt':
      return {
        denominator: num(r.rulesInCorpus),
        applied: num(r.rulesRun),
        lost: num(r.rulesNotApplicable),
        unit: 'rules',
      };
    case 'yarascan': {
      const corpus = (r.corpus ?? {}) as Record<string, unknown>;
      return {
        denominator: num(corpus.rulesDeclared),
        applied: num(corpus.rulesApplied),
        lost: num(corpus.rulesLost),
        unit: 'rules',
      };
    }
    case 'nvram':
      return {
        denominator: null,
        applied: num((r.stores as unknown[] | undefined)?.length),
        lost: null,
        unit: 'stores',
      };
    case 'ghidra':
      // `functionCount` is the provider's own number and `functions` is the (possibly capped) list it returns, so the
      // count is the denominator and the list length is what actually arrived — the cap is legible from the pair.
      return {
        denominator: num(r.functionCount),
        applied: num((r.functions as unknown[] | undefined)?.length),
        lost: null,
        unit: 'functions',
      };
    case 'dynprobe':
      // The probe answers about ONE call site, so it has no denominator to report and pretending otherwise would
      // invent one. What it does carry is `sinkHits` — how many times the breakpoint was reached — which is the
      // closest thing to a measure of what the run examined.
      return { denominator: null, applied: num(r.sinkHits), lost: null, unit: 'sink hits' };
    case 'funcdiff':
      return {
        denominator: null,
        applied: num((r.binaries as unknown[] | undefined)?.length),
        lost: null,
        unit: 'binaries',
      };
    default:
      return none;
  }
}

/**
 * Pure: is this capability's coverage PARTIAL — i.e. did it run and leave part of its input unexamined?
 *
 * `false` when nothing is known, deliberately: a missing denominator cannot support a claim of completeness OR of
 * partiality, and the row says which of the two it is in prose rather than letting a badge imply it.
 */
export function coverageIsPartial(c: CoverageNumbers): boolean {
  if (c.denominator === null || c.applied === null) return false;
  return c.applied < c.denominator;
}
