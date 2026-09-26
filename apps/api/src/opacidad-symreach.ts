/**
 * Pure: how W9 states a `symreach` run that answered on the LIBRARY rung.
 *
 * It lives beside `opacidad.ts` rather than inside it because that module imports the store, and a test that must
 * reach this decision cannot load `node:sqlite`. The decision is worth pinning on its own: a shared object is
 * asked from its EXPORTS, and those outcomes deliberately do not live in `sinks` — counting them there would turn a
 * path under unconstrained arguments into the entry-point claim. No reproduction lead is scheduled either: those
 * key on `sink-reachable` rows, and qemu-user cannot run a `.so`. Reaching nothing is inconclusive, never clean.
 */
import type { SymReachResult } from './providers/symreach.js';

export interface LibraryReachSummary {
  summary: string;
  findingCount: number;
  degraded?: boolean;
  remedy?: 'unbounded-search';
  note?: string;
}

/** `null` when the result did not answer on the library rung — the caller keeps its entry-point path. */
export function summarizeLibraryReach(binary: string, r: SymReachResult): LibraryReachSummary | null {
  if (r.mode !== 'library' || !r.library) return null;
  const lib = r.library;
  const hit = lib.sinks.filter((s) => s.outcome === 'reached');
  const from = `${lib.entryPointsConsidered} of ${lib.entryPointsTotal} export(s)`;
  return {
    summary: hit.length
      ? `reachability ${binary} (library): ${hit.map((s) => s.sink).join('/')} reachable from ${from}`
      : `reachability ${binary} (library): no sink reached from ${from} (inconclusive, not clean)`,
    findingCount: r.findings.length,
    ...(hit.length === 0 ? { degraded: true, remedy: 'unbounded-search' as const, note: r.reason } : {}),
  };
}
