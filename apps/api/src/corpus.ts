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
import { randomUUID } from 'node:crypto';
import type { Architecture, FirmwareClass, ImageIdentity, StaticAnalysis } from '@firmlab/core';
import {
  CORPUS_REINDEX_SOURCES,
  type CorpusReindexReport,
  type CorpusReindexSource,
  type ReindexImagePlan,
  type ReindexText,
  type UnreconciledTable,
  planImageReindex,
  summarizeReindex,
} from './corpus-reindex.js';
import type { GitleaksResult } from './providers/gitleaks.js';
import type { SbomResult } from './providers/sbom.js';
import { hashSecret } from './secret-hash.js';
import { type JobRow, elevateFinding, getDb, listBinaries, listFindings, listImages, listJobs } from './store.js';

// The cross-image credential key lives in a store-free module so the pure providers that produce credential
// material can compute the SAME hash without dragging SQLite into their unit tests. Re-exported for the callers
// (research/run.ts) that already import it from here.
export { hashSecret };

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
//
// Each recorder returns how many rows it actually INSERTED, which under `INSERT OR IGNORE` is the number that
// were missing rather than the number offered. The live call sites ignore it — they are writing what they just
// measured — but it is the whole measurement for `reindexCorpus`, which otherwise could only report how many
// times it called insert.

export function recordArtifacts(imageId: string, rows: { sha1: string; path: string; arch: string | null }[]): number {
  const stmt = getDb().prepare(
    'INSERT OR IGNORE INTO artifact_occurrence (sha1, imageId, path, arch) VALUES (?, ?, ?, ?)',
  );
  let inserted = 0;
  for (const r of rows) if (r.sha1) inserted += Number(stmt.run(r.sha1, imageId, r.path, r.arch).changes);
  return inserted;
}

export function recordCredentials(
  imageId: string,
  creds: { value: string; kind: string | null; severity: string | null }[],
): number {
  const stmt = getDb().prepare(
    'INSERT OR IGNORE INTO credential_occurrence (hash, imageId, kind, severity) VALUES (?, ?, ?, ?)',
  );
  let inserted = 0;
  for (const c of creds)
    if (c.value) inserted += Number(stmt.run(hashSecret(c.value), imageId, c.kind, c.severity).changes);
  return inserted;
}

/**
 * Record credential occurrences that arrive ALREADY HASHED — the redaction-safe path for sources whose secret
 * value must never leave its provider (`nvram`'s store values, the key material `fsaudit`/`auxsecrets` find). The
 * value-based `recordCredentials` hashes what it is handed; this stores the hash verbatim, so a source that
 * computed the matching fingerprint (`hashSecret` for a value, `keyFingerprint` for a key) lands in the very same
 * cross-image bucket. INSERT OR IGNORE, so the same key seen twice in one image is idempotent.
 */
export function recordCredentialHashes(
  imageId: string,
  creds: { hash: string; kind: string | null; severity: string | null }[],
): number {
  const stmt = getDb().prepare(
    'INSERT OR IGNORE INTO credential_occurrence (hash, imageId, kind, severity) VALUES (?, ?, ?, ?)',
  );
  let inserted = 0;
  for (const c of creds) if (c.hash) inserted += Number(stmt.run(c.hash, imageId, c.kind, c.severity).changes);
  return inserted;
}

export function recordComponents(
  imageId: string,
  comps: { name: string; version: string; cveCount: number }[],
): number {
  const stmt = getDb().prepare(
    'INSERT OR IGNORE INTO component_occurrence (name, version, imageId, cveCount) VALUES (?, ?, ?, ?)',
  );
  let inserted = 0;
  for (const c of comps)
    if (c.name && c.version) inserted += Number(stmt.run(c.name, c.version, imageId, c.cveCount).changes);
  return inserted;
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

// === Cross-reference queries (priors — enrich existing per-image data, never assert new claims) ===

/** Reachability priors recorded for a device family — subjects proven reachable before (Level-2 input to node ④). */
export function listReachabilityPriors(familyKey: string): { subject: string; proofState: string; imageId: string }[] {
  return getDb()
    .prepare(
      'SELECT subject, proofState, imageId FROM reachability_prior WHERE familyKey = ? ORDER BY createdAt DESC LIMIT 200',
    )
    .all(familyKey) as unknown as { subject: string; proofState: string; imageId: string }[];
}

/** A live image referenced by a corpus cross-reference. */
export interface ImageRef {
  id: string;
  filename: string;
}

/** Other images (never the given one) that contain the same credential hash. */
export function credentialOtherImages(hash: string, excludeId: string): ImageRef[] {
  return getDb()
    .prepare(
      `SELECT i.id, i.filename FROM credential_occurrence c JOIN images i ON i.id = c.imageId
       WHERE c.hash = ? AND c.imageId != ? ORDER BY i.uploadedAt DESC`,
    )
    .all(hash, excludeId) as unknown as ImageRef[];
}

/** Other images that contain the same binary (by sha1). */
export function artifactOtherImages(sha1: string, excludeId: string): ImageRef[] {
  return getDb()
    .prepare(
      `SELECT DISTINCT i.id, i.filename FROM artifact_occurrence a JOIN images i ON i.id = a.imageId
       WHERE a.sha1 = ? AND a.imageId != ? ORDER BY i.filename`,
    )
    .all(sha1, excludeId) as unknown as ImageRef[];
}

/** Other images that contain the same component version. */
export function componentOtherImages(name: string, version: string, excludeId: string): ImageRef[] {
  return getDb()
    .prepare(
      `SELECT i.id, i.filename FROM component_occurrence c JOIN images i ON i.id = c.imageId
       WHERE c.name = ? AND c.version = ? AND c.imageId != ? ORDER BY i.uploadedAt DESC`,
    )
    .all(name, version, excludeId) as unknown as ImageRef[];
}

// === Level 1: human-curated rule promotion (known-bad credential watchlist) ===

export interface CorpusRule {
  id: string;
  type: string;
  key: string;
  label: string;
  note: string | null;
  createdAt: number;
}

/** Promote something recurring to a first-class rule (e.g. a credential hash → known-bad watchlist entry). */
export function promoteRule(type: string, key: string, label: string, note: string | null): CorpusRule {
  const rule: CorpusRule = { id: randomUUID().slice(0, 12), type, key, label, note, createdAt: Date.now() };
  getDb()
    .prepare('INSERT OR REPLACE INTO corpus_rule (id, type, key, label, note, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
    .run(rule.id, rule.type, rule.key, rule.label, rule.note, rule.createdAt);
  return rule;
}

export function listRules(type?: string): CorpusRule[] {
  const db = getDb();
  const rows = type
    ? db.prepare('SELECT * FROM corpus_rule WHERE type = ? ORDER BY createdAt DESC').all(type)
    : db.prepare('SELECT * FROM corpus_rule ORDER BY createdAt DESC').all();
  return rows as unknown as CorpusRule[];
}

export function deleteRule(id: string): void {
  getDb().prepare('DELETE FROM corpus_rule WHERE id = ?').run(id);
}

/** The set of credential hashes currently on the known-bad watchlist, mapped to their label. */
export function knownCredentialRules(): Map<string, string> {
  const map = new Map<string, string>();
  for (const r of listRules('known-credential')) map.set(r.key, r.label);
  return map;
}

/**
 * Cross-check an image's credential findings against the known-bad watchlist and elevate any match to critical,
 * with a rationale that cites the rule and cross-image prevalence. Still deterministic and still evidence-backed:
 * the finding already proved the secret is in this image; the rule only re-prioritizes it. Returns the count.
 *
 * It USED to look only at `source === 'secrets'` and only at a raw `evidence.value` — so it could reach 3 of the
 * corpus's 38 secret findings and none of the redacted ones (nvram, key material), meaning the entire Level-1
 * watchlist was blind to 92% of secrets even once a rule existed. It now keys on the same identity the recorder
 * stored: a source's redaction-safe `evidence.secretHash`/`secretHashes` when it emitted one, or `hashSecret` of
 * a raw `evidence.value` for the string classifier that stores the value verbatim. A finding carrying neither is
 * not a credential and is skipped.
 */
export function flagKnownCredentials(imageId: string): number {
  const rules = knownCredentialRules();
  if (rules.size === 0) return 0;
  let flagged = 0;
  for (const f of listFindings(imageId)) {
    if (!f.evidenceJson) continue;
    const ev = JSON.parse(f.evidenceJson) as { value?: string; secretHash?: string; secretHashes?: string[] };
    const hashes = new Set<string>();
    if (ev.secretHash) hashes.add(ev.secretHash);
    for (const h of ev.secretHashes ?? []) if (h) hashes.add(h);
    if (hashes.size === 0 && ev.value) hashes.add(hashSecret(ev.value));
    const hit = [...hashes].find((h) => rules.has(h));
    if (!hit) continue;
    const label = rules.get(hit) as string;
    const seenIn = credentialOtherImages(hit, imageId).length;
    elevateFinding(
      f.id,
      'critical',
      `Known-bad credential on the watchlist ("${label}")${seenIn > 0 ? `; also seen in ${seenIn} other image(s)` : ''}.`,
    );
    flagged++;
  }
  return flagged;
}

export interface CorpusRefs {
  credentials: { hash: string; kind: string | null; otherImages: ImageRef[] }[];
  components: { name: string; version: string; cveCount: number; otherImages: ImageRef[] }[];
  artifacts: { sha1: string; path: string; otherImages: ImageRef[] }[];
}

// === Corpus overview (the cross-image knowledge base as a whole) ===

export interface CorpusOverview {
  imageCount: number;
  ruleCount: number;
  /** Credentials shared across more than one image (the reuse signal), watchlist label attached if promoted. */
  credentialReuse: { hash: string; kind: string | null; imageCount: number; watchlistLabel: string | null }[];
  /** Component versions carried by MORE THAN ONE image (the prevalence signal), with their known CVE count. */
  componentPrevalence: { name: string; version: string; cveCount: number; imageCount: number }[];
  /** How many images have an SBOM at all — the denominator the prevalence empty-state needs to say WHY it is empty. */
  sbomImageCount: number;
  /** Images grouped by device family (vendor:class:arch), each list ordered oldest→newest for a version timeline. */
  deviceFamilies: { familyKey: string; images: ImageRef[] }[];
}

export function corpusOverview(): CorpusOverview {
  const db = getDb();
  const watchlist = knownCredentialRules();

  const credentialReuse = (
    db
      .prepare(
        `SELECT hash, MAX(kind) AS kind, COUNT(*) AS imageCount FROM credential_occurrence
         GROUP BY hash HAVING imageCount > 1 ORDER BY imageCount DESC LIMIT 200`,
      )
      .all() as unknown as { hash: string; kind: string | null; imageCount: number }[]
  ).map((r) => ({ ...r, watchlistLabel: watchlist.get(r.hash) ?? null }));

  // HAVING imageCount > 1, exactly as credentialReuse does: this table is titled "which versions span the most
  // images", so a row present in one image spans nothing and is noise — without the clause the section rendered
  // 200 UNKNOWN-version kernel modules that each occur once. The empty result now carries its own reason below.
  const componentPrevalence = db
    .prepare(
      `SELECT name, version, MAX(cveCount) AS cveCount, COUNT(*) AS imageCount FROM component_occurrence
       GROUP BY name, version HAVING imageCount > 1 ORDER BY imageCount DESC, cveCount DESC LIMIT 200`,
    )
    .all() as unknown as { name: string; version: string; cveCount: number; imageCount: number }[];

  const sbomImageCount = (
    db.prepare('SELECT COUNT(DISTINCT imageId) AS n FROM component_occurrence').get() as { n: number }
  ).n;

  // Device families are computed from each image's identity (no stored family column — always fresh).
  const families = new Map<string, ImageRef[]>();
  for (const img of [...listImages()].reverse()) {
    if (!img.identityJson) continue;
    const key = deviceFamilyKey(JSON.parse(img.identityJson) as ImageIdentity);
    const list = families.get(key) ?? [];
    list.push({ id: img.id, filename: img.filename });
    families.set(key, list);
  }
  const deviceFamilies = [...families.entries()]
    .map(([familyKey, images]) => ({ familyKey, images }))
    .sort((a, b) => b.images.length - a.images.length);

  return {
    imageCount: listImages().length,
    ruleCount: listRules().length,
    credentialReuse,
    componentPrevalence,
    sbomImageCount,
    deviceFamilies,
  };
}

/**
 * For one image, the corpus cross-references worth surfacing: its credentials / components / binaries that ALSO
 * appear in other images. Only reused items are returned (the prior signal). These enrich existing findings;
 * they never create or assert a finding.
 */
export function corpusRefs(imageId: string): CorpusRefs {
  const db = getDb();
  const creds = db
    .prepare('SELECT hash, kind FROM credential_occurrence WHERE imageId = ?')
    .all(imageId) as unknown as { hash: string; kind: string | null }[];
  const comps = db
    .prepare('SELECT name, version, cveCount FROM component_occurrence WHERE imageId = ?')
    .all(imageId) as unknown as { name: string; version: string; cveCount: number }[];
  const arts = db.prepare('SELECT sha1, path FROM artifact_occurrence WHERE imageId = ?').all(imageId) as unknown as {
    sha1: string;
    path: string;
  }[];

  return {
    credentials: creds
      .map((c) => ({ hash: c.hash, kind: c.kind, otherImages: credentialOtherImages(c.hash, imageId) }))
      .filter((c) => c.otherImages.length > 0),
    components: comps
      .map((c) => ({ ...c, otherImages: componentOtherImages(c.name, c.version, imageId) }))
      .filter((c) => c.otherImages.length > 0),
    artifacts: arts
      .map((a) => ({ sha1: a.sha1, path: a.path, otherImages: artifactOtherImages(a.sha1, imageId) }))
      .filter((a) => a.otherImages.length > 0),
  };
}

// === Reconciliation (the reindex path) ===

/** The most recent COMPLETED job of a kind, rehydrated. Null means no such job ever finished — never "it was empty". */
function latestJobResult<T>(jobs: JobRow[], kind: string): T | null {
  const done = jobs.find((j) => j.kind === kind && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  try {
    return JSON.parse(done.resultJson) as T;
  } catch {
    return null;
  }
}

function parseAnalysis(json: string | null): StaticAnalysis | null {
  if (!json) return null;
  try {
    return JSON.parse(json) as StaticAnalysis;
  } catch {
    return null;
  }
}

/**
 * Reconcile the corpus against every image on the bench, from state already persisted.
 *
 * Binds the pure planner in `corpus-reindex.ts` to the store: it re-reads no firmware bytes, runs no tool and
 * opens no socket, so it costs a few SQLite reads per image and is safe to point at a live deployment. Every
 * insert is `INSERT OR IGNORE` over immutable data, so running it twice inserts nothing the second time.
 *
 * The caller supplies `text` and `notReconciled` already localised — this module composes no prose, for the
 * same reason `providers/coverage.ts` does not: the sentence is recomputed interface copy and belongs to the
 * request's locale, while the rows are measurements and belong to nobody's language.
 */
export function reindexCorpus(text: ReindexText, notReconciled: UnreconciledTable[]): CorpusReindexReport {
  const inserted = Object.fromEntries(CORPUS_REINDEX_SOURCES.map((s) => [s, 0])) as Record<CorpusReindexSource, number>;
  const plans: ReindexImagePlan[] = [];

  for (const img of listImages()) {
    const jobs = listJobs(img.id);
    const plan = planImageReindex({
      imageId: img.id,
      filename: img.filename,
      analysis: parseAnalysis(img.analysisJson),
      gitleaks: latestJobResult<GitleaksResult>(jobs, 'gitleaks'),
      sbom: latestJobResult<SbomResult>(jobs, 'sbom'),
      findings: listFindings(img.id),
      binaries: listBinaries(img.id),
    });
    plans.push(plan);

    inserted['static-secrets'] += recordCredentials(img.id, plan.staticCredentials);
    inserted.gitleaks += recordCredentials(img.id, plan.gitleaksCredentials);
    inserted['credential-hashes'] += recordCredentialHashes(img.id, plan.credentialHashes);
    inserted.components += recordComponents(img.id, plan.components);
    inserted.artifacts += recordArtifacts(img.id, plan.artifacts);
  }

  return summarizeReindex(plans, inserted, text, notReconciled);
}
