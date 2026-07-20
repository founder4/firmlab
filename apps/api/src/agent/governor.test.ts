import { describe, expect, it } from 'vitest';
import {
  Governor,
  type GovernorBudget,
  ZERO_CONSUMED,
  estimateUsd,
  evaluateBudget,
  loadGovernorBudget,
} from './governor.js';

const budget: GovernorBudget = { maxSteps: 4, maxTokens: 10_000, maxUsd: 0.1, maxWallMs: 60_000 };

describe('evaluateBudget', () => {
  it('permits a step while under every cap', () => {
    expect(evaluateBudget(budget, ZERO_CONSUMED).ok).toBe(true);
  });

  it('halts on the step ceiling first, in stable order', () => {
    const v = evaluateBudget(budget, { ...ZERO_CONSUMED, steps: 4, inputTokens: 999_999 });
    expect(v.ok).toBe(false);
    expect(v.reason).toContain('step budget');
  });

  it('halts on the token ceiling (input + output combined)', () => {
    const v = evaluateBudget(budget, { ...ZERO_CONSUMED, steps: 1, inputTokens: 6000, outputTokens: 4000 });
    expect(v.ok).toBe(false);
    expect(v.reason).toContain('token budget');
  });

  it('halts on the cost ceiling', () => {
    const v = evaluateBudget(budget, { ...ZERO_CONSUMED, steps: 1, usd: 0.1 });
    expect(v.ok).toBe(false);
    expect(v.reason).toContain('cost budget');
  });

  it('does not enforce the cost cap when maxUsd is 0', () => {
    const v = evaluateBudget({ ...budget, maxUsd: 0 }, { ...ZERO_CONSUMED, steps: 1, usd: 999 });
    expect(v.ok).toBe(true);
  });

  it('halts on the wall-clock ceiling', () => {
    const v = evaluateBudget(budget, { ...ZERO_CONSUMED, steps: 1, elapsedMs: 60_000 });
    expect(v.ok).toBe(false);
    expect(v.reason).toContain('time budget');
  });
});

describe('estimateUsd', () => {
  it('prices a known model from its name substring', () => {
    // deepseek: $0.3/1M in, $0.5/1M out → 1000*0.3/1e6 + 1000*0.5/1e6 = 0.0008
    expect(estimateUsd('deepseek-v4-flash', 1000, 1000)).toBeCloseTo(0.0008, 6);
  });

  it('falls back to a conservative default for an unknown model', () => {
    expect(estimateUsd('some-unknown-model', 1_000_000, 0)).toBeCloseTo(2, 6);
  });

  it('prices opus far above deepseek for the same tokens', () => {
    expect(estimateUsd('claude-opus-4-8', 1000, 1000)).toBeGreaterThan(estimateUsd('deepseek-v4-flash', 1000, 1000));
  });
});

describe('Governor', () => {
  it('accrues cost across turns and halts when a cap is crossed', () => {
    const t = 0;
    const gov = new Governor({ maxSteps: 2, maxTokens: 1_000_000, maxUsd: 0, maxWallMs: 1_000_000 }, 0, () => t);
    expect(gov.check().ok).toBe(true);
    gov.record('deepseek', 100, 100);
    expect(gov.check().ok).toBe(true);
    gov.record('deepseek', 100, 100);
    expect(gov.snapshot().steps).toBe(2);
    expect(gov.check().ok).toBe(false); // step budget reached
  });

  it('measures wall-clock from the injected clock', () => {
    let t = 0;
    const gov = new Governor({ maxSteps: 99, maxTokens: 1e9, maxUsd: 0, maxWallMs: 500 }, 0, () => t);
    expect(gov.check().ok).toBe(true);
    t = 500;
    expect(gov.check().ok).toBe(false);
    expect(gov.check().reason).toContain('time budget');
  });
});

describe('loadGovernorBudget', () => {
  it('uses conservative defaults with no env set', () => {
    const b = loadGovernorBudget({} as NodeJS.ProcessEnv);
    expect(b.maxSteps).toBe(8);
    expect(b.maxTokens).toBe(120_000);
    expect(b.maxWallMs).toBe(300_000);
  });

  it('reads overrides and converts seconds to ms', () => {
    const b = loadGovernorBudget({
      FIRMLAB_AGENT_MAX_STEPS: '3',
      FIRMLAB_AGENT_MAX_SECONDS: '30',
    } as unknown as NodeJS.ProcessEnv);
    expect(b.maxSteps).toBe(3);
    expect(b.maxWallMs).toBe(30_000);
  });
});
