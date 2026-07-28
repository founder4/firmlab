/**
 * Finding persistence — stamps normalized drafts into the findings ledger and rehydrates them. The pure
 * normalizers live in findings-normalize.ts (re-exported here for convenience so callers have one import), and
 * the pure operator-assertion rules live in operator-findings.ts for the same reason: this module imports the
 * store, so nothing a unit test needs to reach may live in it.
 *
 * Findings are the durable, cross-provider record the dossier renders and the corpus (Phase 1) will index.
 * Every finding is backed by the provider evidence that produced it; nothing here invents a claim.
 *
 * Two populations share the table and must never share a code path. Provider rows are computed and re-syncable;
 * operator rows are asserted by a named author, carry no proof state, and are never deleted — only withdrawn.
 * `syncFindings` refuses an operator source outright rather than trusting callers to pass the right one.
 */
import { randomUUID } from 'node:crypto';
import type { Finding, FindingProvenance, FindingSeverity, OperatorAssertion, OperatorAuthorKind } from '@firmlab/core';
import type { FindingDraft } from './findings-normalize.js';
import {
  type ValidatedAssertion,
  amendAssertion,
  assertionToDraft,
  isOperatorSource,
  operatorSourceFor,
  withdrawAssertion,
} from './operator-findings.js';
import {
  type FindingRow,
  deleteFindingsBySource,
  getFinding,
  insertFindings,
  updateFindingAssertion,
} from './store.js';

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
 *
 * Throws on an operator source. A provider that reached this line with one has confused a measurement for a
 * person's claim, and the loud failure is worth far more than the convenience of ignoring it — the store's
 * `deleteFindingsBySource` would already have refused the delete, so silently proceeding would leave the ledger
 * holding both the assertion and a duplicate of it.
 */
export function syncFindings(imageId: string, source: string, drafts: FindingDraft[]): void {
  if (isOperatorSource(source)) {
    throw new Error(
      `syncFindings refused source '${source}': the operator: namespace holds hand-authored assertions, which no provider may write, re-state or delete. Use recordOperatorFinding.`,
    );
  }
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
    // Always null on this path: a computed finding has no author, and `assertion` being absent is precisely what
    // tells every reader that code decided this row.
    assertionJson: null,
    createdAt: now,
  }));
  insertFindings(rows);
}

/** Parse a stored row back into the domain `Finding` (evidence and assertion rehydrated from JSON). */
export function rowToFinding(row: FindingRow): Finding {
  const finding: Finding = {
    id: row.id,
    imageId: row.imageId,
    source: row.source,
    kind: row.kind,
    title: row.title,
    severity: row.severity as FindingSeverity,
    proofState: row.proofState as FindingProvenance,
    createdAt: row.createdAt,
  };
  if (row.evidenceJson) finding.evidence = JSON.parse(row.evidenceJson) as Record<string, unknown>;
  if (row.rationale) finding.rationale = row.rationale;
  if (row.assertionJson) finding.assertion = JSON.parse(row.assertionJson) as OperatorAssertion;
  return finding;
}

/**
 * Record a new operator assertion. The row gets a fresh id and its own `operator:<who>` source, so two authors
 * never share a row set and no provider's sync can reach either.
 */
export function recordOperatorFinding(imageId: string, v: ValidatedAssertion, authorKind: OperatorAuthorKind): Finding {
  const now = Date.now();
  const draft = assertionToDraft(v, authorKind, now);
  const row: FindingRow = {
    id: randomUUID().slice(0, 12),
    imageId,
    source: operatorSourceFor(v.assertedBy),
    kind: draft.kind,
    title: draft.title,
    severity: draft.severity,
    proofState: draft.proofState,
    evidenceJson: draft.evidence ? JSON.stringify(draft.evidence) : null,
    rationale: draft.rationale ?? null,
    assertionJson: JSON.stringify(draft.assertion),
    createdAt: now,
  };
  insertFindings([row]);
  return rowToFinding(row);
}

/** Look up one operator row, or say which of the two ways it is not one. */
export function loadOperatorFinding(
  imageId: string,
  findingId: string,
): { ok: true; row: FindingRow; assertion: OperatorAssertion } | { ok: false; error: string; status: 404 | 409 } {
  const row = getFinding(findingId);
  if (!row || row.imageId !== imageId) return { ok: false, error: 'Finding not found on this image.', status: 404 };
  if (!row.assertionJson) {
    return {
      ok: false,
      error:
        'That finding was decided by code, not asserted by a person, so it cannot be edited or withdrawn here. To disagree with it, record an assertion with claim `disputes_finding` — both rows then stand and a reader decides.',
      status: 409,
    };
  }
  return { ok: true, row, assertion: JSON.parse(row.assertionJson) as OperatorAssertion };
}

/** Amend an active assertion. The original author and assertion time survive; `amendedAt` records the edit. */
export function amendOperatorFinding(row: FindingRow, existing: OperatorAssertion, v: ValidatedAssertion): Finding {
  const now = Date.now();
  const assertion = amendAssertion(existing, v, now);
  const draft = assertionToDraft({ ...v, assertedBy: existing.assertedBy }, existing.authorKind, existing.assertedAt);
  updateFindingAssertion(row.id, JSON.stringify(assertion), {
    title: v.title,
    severity: v.severity,
    rationale: v.rationale,
    evidenceJson: JSON.stringify(draft.evidence ?? {}),
  });
  return rowToFinding({
    ...row,
    title: v.title,
    severity: v.severity,
    rationale: v.rationale,
    evidenceJson: JSON.stringify(draft.evidence ?? {}),
    assertionJson: JSON.stringify(assertion),
  });
}

/**
 * Retract an assertion in place. Nothing is deleted: the claim, its author, its original rationale and the reason
 * for the retraction all stay readable, because "this was wrong, and here is why" is the row a ledger most needs
 * to be able to hold.
 */
export function withdrawOperatorFinding(
  row: FindingRow,
  existing: OperatorAssertion,
  who: string,
  reason: string,
): { ok: true; finding: Finding } | { ok: false; error: string } {
  const result = withdrawAssertion(existing, who, reason, Date.now());
  if (!result.ok) return result;
  updateFindingAssertion(row.id, JSON.stringify(result.value), {});
  return { ok: true, finding: rowToFinding({ ...row, assertionJson: JSON.stringify(result.value) }) };
}
