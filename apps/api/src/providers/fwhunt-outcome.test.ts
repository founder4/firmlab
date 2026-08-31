import { describe, expect, it } from 'vitest';
import { FWHUNT_WORKER, fwhuntCoverageStep, fwhuntOutcome } from './fwhunt-outcome.js';
import type { FwHuntResult, ModulePass } from './fwhunt.js';

function result(scanned: number, failed: number, skipped: number): FwHuntResult {
  const module = (index: number) => ({ path: `/m/${index}.dxe`, name: `M${index}` });
  return {
    available: true,
    reason: 'fixture',
    rulesRun: 106,
    rulesNotApplicable: 2,
    rulesInCorpus: 108,
    matches: [],
    findings: [],
    modulePass: {
      ran: true,
      modulesCarved: scanned + failed + skipped,
      modulesScanned: Array.from({ length: scanned }, (_, index) => module(index)),
      modulesFailed: Array.from({ length: failed }, (_, index) => module(scanned + index)),
      modulesSkipped: Array.from({ length: skipped }, (_, index) => module(scanned + failed + index)),
      skipReason: skipped ? 'bounded' : '',
    } as ModulePass,
  };
}

describe('FwHunt coverage outcome', () => {
  it('keeps finalized analyzer failures degraded and names them as unknown', () => {
    const outcome = fwhuntOutcome(result(404, 5, 0), true);
    expect(outcome.degraded).toBe(true);
    expect(outcome.note).toContain('5 failed and remain unknown');
    expect(outcome.note).toContain('0 were not attempted');
  });

  it('reports a genuinely complete module pass as ran', () => {
    const step = fwhuntCoverageStep(result(409, 0, 0));
    expect(step).toMatchObject({ worker: FWHUNT_WORKER, status: 'ran', findingCount: 0 });
  });
});
