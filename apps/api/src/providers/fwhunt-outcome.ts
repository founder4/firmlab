import type { OpacidadStep } from '../opacidad-narrative.js';
import type { FwHuntResult } from './fwhunt.js';

export const FWHUNT_WORKER = 'UEFI · FwHunt implant scan';

export interface FwHuntStepOutcome {
  summary: string;
  findingCount: number;
  degraded?: boolean;
  note?: string;
}

/** Summarize one durable or freshly-run FwHunt result without hiding either coverage denominator. */
export function fwhuntOutcome(r: FwHuntResult, reusedDurableCampaign = false): FwHuntStepOutcome {
  if (!r.available) {
    return {
      summary: 'FwHunt implant scan: unavailable',
      findingCount: r.findings.length,
      degraded: true,
      note: r.reason,
    };
  }
  const mp = r.modulePass;
  const modulesScanned = mp?.modulesScanned.length ?? 0;
  const modulesFailed = mp?.modulesFailed.length ?? 0;
  const modulesSkipped = mp?.modulesSkipped.length ?? 0;
  const moduleCoverageThin = !!mp && mp.ran && mp.modulesCarved > 0 && modulesScanned * 2 < mp.modulesCarved;
  const modulePassBlocked = !mp || !mp.ran;
  const modulePassPartial = modulesFailed > 0 || modulesSkipped > 0;
  const moduleNote = mp?.ran
    ? `${modulesScanned}/${mp.modulesCarved} carved module(s) scanned; ${modulesFailed} failed and remain unknown; ${modulesSkipped} were not attempted${mp.skipReason ? ` (${mp.skipReason})` : ''}${reusedDurableCampaign ? '; reused the newest dedicated campaign without replacing it with an isolated batch zero' : ''}`
    : `the per-module pass did not run: ${mp?.reason || 'no module pass'} — only the whole-image rules were exercised`;
  return {
    summary: `FwHunt implant scan${reusedDurableCampaign ? ' (reused durable campaign)' : ''}: ${r.matches.length} match(es), ${r.rulesRun}/${r.rulesInCorpus} rule(s) over ${mp?.ran ? `${modulesScanned}/${mp.modulesCarved}` : '0'} carved module(s)`,
    findingCount: r.findings.length,
    ...(moduleCoverageThin || modulePassBlocked || modulePassPartial
      ? { degraded: true, note: moduleNote }
      : reusedDurableCampaign
        ? {
            note: 'Reused the newest dedicated, provenance-checked FwHunt campaign; this autonomous run did not replace it with an isolated batch zero.',
          }
        : {}),
  };
}

/** Convert a dedicated result into the exact step shape consumed by the coverage report. */
export function fwhuntCoverageStep(r: FwHuntResult): OpacidadStep {
  const outcome = fwhuntOutcome(r, true);
  return {
    worker: FWHUNT_WORKER,
    status: outcome.degraded ? 'degraded' : 'ran',
    summary: outcome.summary,
    findingCount: outcome.findingCount,
    ...(outcome.note ? { note: outcome.note } : {}),
  };
}
