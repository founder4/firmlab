/**
 * Pure finding normalizers — turn each provider's structured output into `Finding` drafts with an explicit,
 * honest initial proof state. No persistence, no side effects (kept separate from findings.ts so they are
 * unit-testable without loading the SQLite store).
 *
 * Initial proof-state policy (deliberately conservative):
 *   - secrets / gitleaks  → `static_confirmed`  (the secret is literally present in the firmware bytes)
 *   - binary hardening    → `static_confirmed`  (an NX/canary/PIC flag is a fact about the binary)
 *   - SBOM CVEs           → `needs_runtime_reproduction`  (a vulnerable component is present, but reachability
 *                            and on-device exploitability are unproven — never overstated)
 */
import type { Finding, FindingSeverity, ProofState, StringHit } from '@firmlab/core';
import type { DecompileResult } from './providers/decompile.js';
import type { GitleaksResult } from './providers/gitleaks.js';
import type { SbomResult, Severity } from './providers/sbom.js';

/** A finding as produced by a normalizer, before it is stamped with id/imageId/source/createdAt. */
export type FindingDraft = Omit<Finding, 'id' | 'imageId' | 'source' | 'createdAt'>;

/** Hardcoded credentials / keys / tokens found by the static string classifier over the raw image. */
export function normalizeSecrets(secrets: StringHit[]): FindingDraft[] {
  return secrets
    .filter((s) => s.secretKind)
    .map((s) => ({
      kind: s.secretKind ?? 'secret',
      title: `${s.secretKind ?? 'secret'} at 0x${s.offset.toString(16)}`,
      severity: (s.severity ?? 'medium') as FindingSeverity,
      proofState: 'static_confirmed' as ProofState,
      evidence: { offset: s.offset, value: s.value },
    }));
}

const SBOM_SEVERITY: Record<Severity, FindingSeverity> = {
  Critical: 'critical',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
  Negligible: 'info',
  Unknown: 'info',
};

/** CVEs matched against the rootfs SBOM (syft + grype). Present ≠ reachable, hence needs_runtime_reproduction. */
export function normalizeSbom(result: SbomResult): FindingDraft[] {
  if (!result.available) return [];
  return result.vulnerabilities.map((v) => ({
    kind: 'cve',
    title: `${v.id} — ${v.packageName} ${v.packageVersion}`,
    severity: SBOM_SEVERITY[v.severity] ?? 'info',
    proofState: 'needs_runtime_reproduction' as ProofState,
    rationale: 'Vulnerable component present in the rootfs; reachability and exploitability not yet proven.',
    evidence: { id: v.id, packageName: v.packageName, packageVersion: v.packageVersion, fixedIn: v.fixedIn },
  }));
}

/** Deep secret scan of the extracted rootfs files (gitleaks). Matched in a real file → static_confirmed. */
export function normalizeGitleaks(result: GitleaksResult): FindingDraft[] {
  if (!result.available) return [];
  return result.findings.map((f) => ({
    kind: f.rule,
    title: `${f.description || f.rule} in ${f.file}`,
    severity: 'high' as FindingSeverity,
    proofState: 'static_confirmed' as ProofState,
    evidence: { file: f.file, line: f.line, match: f.match, rule: f.rule },
  }));
}

/** Missing exploit-mitigations on a triaged binary (radare2). A hardening flag is a fact → static_confirmed. */
export function normalizeBinaryHardening(result: DecompileResult): FindingDraft[] {
  if (!result.available) return [];
  const { info, binary } = result;
  const drafts: FindingDraft[] = [];
  const weak = (kind: string, label: string, severity: FindingSeverity): void => {
    drafts.push({
      kind,
      title: `${label}: ${binary}`,
      severity,
      proofState: 'static_confirmed',
      evidence: { binary, info },
    });
  };
  if (info.nx === false) weak('no-nx', 'Non-executable stack disabled (NX off)', 'low');
  if (info.canary === false) weak('no-canary', 'No stack canary', 'low');
  if (info.pic === false) weak('no-pic', 'No position-independent code (PIC off)', 'info');
  return drafts;
}
