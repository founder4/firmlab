/**
 * Finding persistence — stamps normalized drafts into the findings ledger and rehydrates them. The pure
 * normalizers live in findings-normalize.ts (re-exported here for convenience so callers have one import).
 *
 * Findings are the durable, cross-provider record the dossier renders and the corpus (Phase 1) will index.
 * Every finding is backed by the provider evidence that produced it; nothing here invents a claim.
 */
import { randomUUID } from 'node:crypto';
import type { Finding, FindingSeverity, ProofState } from '@firmlab/core';
import type { FindingDraft } from './findings-normalize.js';
import { type FindingRow, deleteFindingsBySource, insertFindings } from './store.js';

export {
  type FindingDraft,
  normalizeSecrets,
  normalizeSbom,
  normalizeGitleaks,
  normalizeBinaryHardening,
} from './findings-normalize.js';

/**
 * Replace the finding set contributed by one `source` for an image and insert the freshly normalized drafts.
 * Idempotent: re-running a provider re-syncs only its own findings, leaving other sources untouched. Per-binary
 * results use a `binary:<path>` source so distinct binaries don't clobber each other.
 */
export function syncFindings(imageId: string, source: string, drafts: FindingDraft[]): void {
  deleteFindingsBySource(imageId, source);
  const now = Date.now();
  const rows: FindingRow[] = drafts.map((d) => ({
    id: randomUUID().slice(0, 12),
    imageId,
    source,
    kind: d.kind,
    title: d.title,
    severity: d.severity,
    proofState: d.proofState,
    evidenceJson: d.evidence ? JSON.stringify(d.evidence) : null,
    rationale: d.rationale ?? null,
    createdAt: now,
  }));
  insertFindings(rows);
}

/** Parse a stored row back into the domain `Finding` (evidence rehydrated from JSON). */
export function rowToFinding(row: FindingRow): Finding {
  const finding: Finding = {
    id: row.id,
    imageId: row.imageId,
    source: row.source,
    kind: row.kind,
    title: row.title,
    severity: row.severity as FindingSeverity,
    proofState: row.proofState as ProofState,
    createdAt: row.createdAt,
  };
  if (row.evidenceJson) finding.evidence = JSON.parse(row.evidenceJson) as Record<string, unknown>;
  if (row.rationale) finding.rationale = row.rationale;
  return finding;
}
