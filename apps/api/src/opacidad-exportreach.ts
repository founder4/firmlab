/** Pure, deterministic target selection for the autonomous export-reachability stage. */
export interface ExportReachCandidate {
  path: string;
  size: number;
  networkFacing: number;
  importsSummary: string | null;
}

const DANGEROUS_IMPORT = /\b(strcpy|strcat|sprintf|vsprintf|system|popen|execve|memcpy|copy_from_user|kmalloc)\b/i;

/**
 * Prefer objects for which the question is meaningful and consequential. Ties choose the smaller graph first so
 * a bounded run answers more questions; path is the stable final key, making re-runs select the same objects.
 */
export function selectExportReachTargets(candidates: ExportReachCandidate[], cap = 4): string[] {
  const boundedCap = Math.max(0, Math.floor(cap));
  return candidates
    .filter((candidate) => candidate.path.endsWith('.ko') || /\.so(?:\.|$)/.test(candidate.path))
    .map((candidate) => ({
      ...candidate,
      score:
        (candidate.networkFacing === 1 ? 30 : 0) +
        (candidate.path.endsWith('.ko') ? 20 : 0) +
        (DANGEROUS_IMPORT.test(candidate.importsSummary ?? '') ? 50 : 0),
    }))
    .sort((a, b) => b.score - a.score || a.size - b.size || a.path.localeCompare(b.path))
    .slice(0, boundedCap)
    .map((candidate) => candidate.path);
}
