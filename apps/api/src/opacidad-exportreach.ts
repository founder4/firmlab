/** Pure, deterministic target selection for the autonomous export-reachability stage. */
export interface ExportReachCandidate {
  path: string;
  size: number;
  networkFacing: number;
  importsSummary: string | null;
}

const DANGEROUS_IMPORT = /\b(strcpy|strcat|sprintf|vsprintf|system|popen|execve|memcpy|copy_from_user|kmalloc)\b/i;

export interface ExportReachSelection {
  /** The chosen targets, ranked, capped. */
  targets: string[];
  /** Objects that matched the .so/.ko filter — the real pool the cap is drawn from, not the whole inventory. */
  total: number;
  /** How many matching objects the cap left unexamined. */
  dropped: number;
  /** The sentence a summary states so the cap is a declared rule, never a silent gap. */
  rule: string;
}

/**
 * Prefer objects for which the question is meaningful and consequential. Ties choose the smaller graph first so
 * a bounded run answers more questions; path is the stable final key, making re-runs select the same objects.
 *
 * Returns the selection AND the size of the pool it was cut from: a rootfs can carry hundreds of `.so`/`.ko`
 * (896 in one corpus image), and reporting only the four chosen — the way this used to — made the *set* an
 * artifact of the cap without ever saying so. See the audit note beside `binvuln.selectFindings`.
 */
export function selectExportReachTargets(candidates: ExportReachCandidate[], cap = 4): ExportReachSelection {
  const boundedCap = Math.max(0, Math.floor(cap));
  const ranked = candidates
    .filter((candidate) => candidate.path.endsWith('.ko') || /\.so(?:\.|$)/.test(candidate.path))
    .map((candidate) => ({
      ...candidate,
      score:
        (candidate.networkFacing === 1 ? 30 : 0) +
        (candidate.path.endsWith('.ko') ? 20 : 0) +
        (DANGEROUS_IMPORT.test(candidate.importsSummary ?? '') ? 50 : 0),
    }))
    .sort((a, b) => b.score - a.score || a.size - b.size || a.path.localeCompare(b.path));
  const targets = ranked.slice(0, boundedCap).map((candidate) => candidate.path);
  const dropped = ranked.length - targets.length;
  const rule = [
    `Selected ${targets.length} of ${ranked.length} .so/.ko object(s), ranked:`,
    'network-facing first, then kernel modules, then objects importing an unbounded-copy or command sink,',
    'ties by smaller graph and then path — never by directory order.',
    dropped > 0
      ? `The ${dropped} not selected were not asked the reachability question; their absence from the result is the cap, not a clean answer.`
      : '',
  ]
    .filter((s) => s !== '')
    .join(' ');
  return { targets, total: ranked.length, dropped, rule };
}
