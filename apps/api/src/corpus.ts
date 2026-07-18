/**
 * The persistent corpus — FirmLab's structural edge over a stateless scanner. It accumulates cross-image
 * *occurrences* (which artifact/credential/component appears in which image) so that analysing a new firmware
 * can be enriched with priors from every firmware seen before.
 *
 * THE ONE RULE (Phase-1 guiding principle): the corpus records occurrences and returns priors / cross-refs —
 * NEVER conclusions. A credential seen before raises a flag to check; it does not assert a finding. Every
 * finding still stands on its own per-image evidence. If the corpus ever concluded, we'd reintroduce
 * hallucination at the database layer and lose reproducibility.
 *
 * Recording is additive (INSERT OR IGNORE): firmware images are immutable, so a given (key, imageId) either
 * exists or not, and re-running a provider produces identical rows. Deleting an image cascades its occurrences.
 */
import { createHash } from 'node:crypto';
import type { Architecture, FirmwareClass } from '@firmlab/core';
import { getDb } from './store.js';

/** Content hash of a secret value — the cross-image key for credential reuse. */
export function hashSecret(value: string): string {
  return createHash('sha1').update(value).digest('hex');
}

/**
 * A stable device-family key from an image's identity (vendor:class:arch; unknowns collapse). Pure — groups
 * images so cross-version diff and reachability priors can be scoped to "the same kind of device".
 */
export function deviceFamilyKey(identity: {
  vendor?: string | undefined;
  firmwareClass: FirmwareClass;
  arch: Architecture;
}): string {
  const vendor = (identity.vendor ?? 'unknown').toLowerCase().replace(/\s+/g, '-');
  return `${vendor}:${identity.firmwareClass}:${identity.arch}`;
}

// === Recording (Level 0, additive) ===

export function recordArtifacts(imageId: string, rows: { sha1: string; path: string; arch: string | null }[]): void {
  const stmt = getDb().prepare(
    'INSERT OR IGNORE INTO artifact_occurrence (sha1, imageId, path, arch) VALUES (?, ?, ?, ?)',
  );
  for (const r of rows) if (r.sha1) stmt.run(r.sha1, imageId, r.path, r.arch);
}

export function recordCredentials(
  imageId: string,
  creds: { value: string; kind: string | null; severity: string | null }[],
): void {
  const stmt = getDb().prepare(
    'INSERT OR IGNORE INTO credential_occurrence (hash, imageId, kind, severity) VALUES (?, ?, ?, ?)',
  );
  for (const c of creds) if (c.value) stmt.run(hashSecret(c.value), imageId, c.kind, c.severity);
}

export function recordComponents(imageId: string, comps: { name: string; version: string; cveCount: number }[]): void {
  const stmt = getDb().prepare(
    'INSERT OR IGNORE INTO component_occurrence (name, version, imageId, cveCount) VALUES (?, ?, ?, ?)',
  );
  for (const c of comps) if (c.name && c.version) stmt.run(c.name, c.version, imageId, c.cveCount);
}

/** Record that a subject (component or finding kind) was confirmed by emulation for a device family. */
export function recordReachabilityPrior(familyKey: string, subject: string, proofState: string, imageId: string): void {
  getDb()
    .prepare(
      `INSERT OR IGNORE INTO reachability_prior (familyKey, subject, proofState, imageId, createdAt)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .run(familyKey, subject, proofState, imageId, Date.now());
}
