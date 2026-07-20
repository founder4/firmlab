/**
 * The governor — hard budget caps for an agent session (Phase 3). Conscious autonomy needs a leash: an agent
 * that reasons within the deterministic skeleton still costs tokens, money and time, so every session runs
 * under a governor that halts it the moment any cap is reached. Steps, tokens, USD and wall-clock are all
 * enforced; the first ceiling hit stops the run and its reason is recorded on the session.
 *
 * The evaluation is a pure function of (budget, consumed) so it unit-tests without a clock or a provider; the
 * Governor class is the thin stateful wrapper the orchestrator uses.
 */

export interface GovernorBudget {
  maxSteps: number;
  maxTokens: number;
  /** USD ceiling; 0 disables the money cap (steps/tokens/time still apply). */
  maxUsd: number;
  maxWallMs: number;
}

export interface GovernorConsumed {
  steps: number;
  inputTokens: number;
  outputTokens: number;
  usd: number;
  elapsedMs: number;
}

/**
 * Rough per-1M-token USD prices, blended input/output, keyed by a case-insensitive model-name substring. Used
 * only to *estimate* spend for the transparency gauge and the optional USD cap — this is a safety net, not a
 * billing system. Unknown models fall back to a conservative default so the cap still bites.
 */
const PRICE_PER_1M: { match: string; input: number; output: number }[] = [
  { match: 'deepseek', input: 0.3, output: 0.5 },
  { match: 'opus', input: 15, output: 75 },
  { match: 'sonnet', input: 3, output: 15 },
  { match: 'haiku', input: 0.8, output: 4 },
  { match: 'gpt-4o-mini', input: 0.15, output: 0.6 },
  { match: 'gpt-4o', input: 2.5, output: 10 },
  { match: 'gpt', input: 5, output: 15 },
];
const DEFAULT_PRICE = { input: 2, output: 8 };

/** Estimate the USD cost of one model turn from its token counts. */
export function estimateUsd(model: string, inputTokens: number, outputTokens: number): number {
  const m = model.toLowerCase();
  const price = PRICE_PER_1M.find((p) => m.includes(p.match)) ?? DEFAULT_PRICE;
  return (inputTokens * price.input + outputTokens * price.output) / 1_000_000;
}

/** Resolve the governor budget from the environment. All caps are configurable; the defaults are conservative. */
export function loadGovernorBudget(env: NodeJS.ProcessEnv = process.env): GovernorBudget {
  return {
    maxSteps: Math.max(1, Number(env.FIRMLAB_AGENT_MAX_STEPS ?? 8)),
    maxTokens: Math.max(1, Number(env.FIRMLAB_AGENT_MAX_TOKENS ?? 120_000)),
    maxUsd: Math.max(0, Number(env.FIRMLAB_AGENT_MAX_USD ?? 0.5)),
    maxWallMs: Math.max(1, Number(env.FIRMLAB_AGENT_MAX_SECONDS ?? 300)) * 1000,
  };
}

export interface BudgetVerdict {
  ok: boolean;
  /** The cap that was hit, when ok is false — recorded verbatim as the session's haltReason. */
  reason: string | null;
}

/**
 * Pure: has this session already reached any ceiling? Called before each node so the run stops *before*
 * spending past a cap. The first exceeded cap wins, in a stable order (steps → tokens → usd → time).
 */
export function evaluateBudget(budget: GovernorBudget, consumed: GovernorConsumed): BudgetVerdict {
  if (consumed.steps >= budget.maxSteps) {
    return { ok: false, reason: `step budget reached (${consumed.steps}/${budget.maxSteps})` };
  }
  const totalTokens = consumed.inputTokens + consumed.outputTokens;
  if (totalTokens >= budget.maxTokens) {
    return { ok: false, reason: `token budget reached (${totalTokens}/${budget.maxTokens})` };
  }
  if (budget.maxUsd > 0 && consumed.usd >= budget.maxUsd) {
    return { ok: false, reason: `cost budget reached ($${consumed.usd.toFixed(4)}/$${budget.maxUsd})` };
  }
  if (consumed.elapsedMs >= budget.maxWallMs) {
    return {
      ok: false,
      reason: `time budget reached (${Math.round(consumed.elapsedMs / 1000)}s/${budget.maxWallMs / 1000}s)`,
    };
  }
  return { ok: true, reason: null };
}

export const ZERO_CONSUMED: GovernorConsumed = { steps: 0, inputTokens: 0, outputTokens: 0, usd: 0, elapsedMs: 0 };

/**
 * Stateful wrapper the orchestrator drives: it accrues consumption as nodes run and answers whether the budget
 * still allows another step. Wall-clock is measured from construction unless a start time is supplied (tests
 * pass a fixed one).
 */
export class Governor {
  private consumed: GovernorConsumed = { ...ZERO_CONSUMED };

  constructor(
    private readonly budget: GovernorBudget,
    private readonly startMs: number = Date.now(),
    private readonly now: () => number = Date.now,
  ) {}

  /** Fold one model turn's cost into the running tally (steps + tokens + estimated USD). */
  record(model: string, inputTokens: number, outputTokens: number): void {
    this.consumed.steps += 1;
    this.consumed.inputTokens += inputTokens;
    this.consumed.outputTokens += outputTokens;
    this.consumed.usd += estimateUsd(model, inputTokens, outputTokens);
  }

  /** Restore a persisted tally without counting a phantom step (for a governor resumed outside the main loop). */
  seed(consumed: GovernorConsumed): void {
    this.consumed = {
      steps: consumed.steps,
      inputTokens: consumed.inputTokens,
      outputTokens: consumed.outputTokens,
      usd: consumed.usd,
      elapsedMs: 0, // recomputed by snapshot() from the clock
    };
  }

  /** Snapshot of consumption, with wall-clock filled from the clock, for persisting or checking. */
  snapshot(): GovernorConsumed {
    return { ...this.consumed, elapsedMs: this.now() - this.startMs };
  }

  /** Whether the budget still permits another node to run. */
  check(): BudgetVerdict {
    return evaluateBudget(this.budget, this.snapshot());
  }

  getBudget(): GovernorBudget {
    return this.budget;
  }
}
