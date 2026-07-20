/**
 * SQLite persistence for the workbench (better-sqlite3, synchronous). One database under the data root holds
 * uploaded image metadata + cached static analysis, and long-running jobs (extraction, emulation, SBOM,
 * decompilation). Survives API restarts so an analysis session is durable.
 */
import { DatabaseSync } from 'node:sqlite';
import { DB_PATH, ensureDataDirs } from './paths.js';

export type JobKind =
  | 'extract'
  | 'binwalk'
  | 'sbom'
  | 'emulate'
  | 'decompile'
  | 'gitleaks'
  | 'diff'
  | 'ghidra'
  | 'copilot'
  | 'research'
  | 'fuzz';
export type JobStatus = 'queued' | 'running' | 'done' | 'error';

export interface ImageRow {
  id: string;
  filename: string;
  path: string;
  size: number;
  sha256: string;
  uploadedAt: number;
  status: 'analyzing' | 'ready' | 'error';
  identityJson: string | null;
  analysisJson: string | null;
  /** JSON array of user tags, or null. */
  tags: string | null;
}

export interface JobRow {
  id: string;
  imageId: string;
  kind: JobKind;
  status: JobStatus;
  createdAt: number;
  updatedAt: number;
  params: string | null;
  log: string;
  resultJson: string | null;
  error: string | null;
}

/**
 * A binary discovered in an extracted rootfs, persisted as a first-class entity. Identity fields (arch/sha1)
 * are filled at extraction from the ELF header; triage fields (nx/canary/pic/imports) are filled when radare2
 * runs over it. Boolean-ish columns are 0/1/null (SQLite has no bool).
 */
export interface BinaryRow {
  imageId: string;
  path: string;
  sha1: string | null;
  size: number;
  arch: string | null;
  bits: number | null;
  endianness: string | null;
  nx: number | null;
  canary: number | null;
  pic: number | null;
  networkFacing: number;
  importsSummary: string | null;
  triaged: number;
  emulationStatus: string | null;
  createdAt: number;
  updatedAt: number;
}

/** Storage shape of a normalized finding (evidence held as a JSON string). Mirrors the core `Finding` type. */
export interface FindingRow {
  id: string;
  imageId: string;
  source: string;
  kind: string;
  title: string;
  severity: string;
  proofState: string;
  evidenceJson: string | null;
  rationale: string | null;
  createdAt: number;
}

/** Lifecycle of an agent session. `running`/`awaiting_approval` are the *active* states that pin the image. */
export type AgentSessionStatus = 'running' | 'awaiting_approval' | 'done' | 'error' | 'halted';

/** A conscious-autonomy run over one image: its budget, what it has consumed, and its terminal reason. */
export interface AgentSessionRow {
  id: string;
  imageId: string;
  status: AgentSessionStatus;
  goal: string | null;
  /** Governor budget snapshot: { maxSteps, maxTokens, maxUsd, maxWallMs }. */
  budgetJson: string;
  /** Running tally: { steps, inputTokens, outputTokens, usd, elapsedMs }. */
  consumedJson: string;
  haltReason: string | null;
  createdAt: number;
  updatedAt: number;
}

/** One entry in the auditable transcript: a decision node's structured input, output, and rationale. */
export interface AgentStepRow {
  id: string;
  sessionId: string;
  seq: number;
  node: string;
  status: string;
  inputJson: string | null;
  outputJson: string | null;
  rationale: string | null;
  model: string | null;
  inputTokens: number;
  outputTokens: number;
  createdAt: number;
}

/** node:sqlite binds named parameters from a plain record; our typed rows are cast through this. */
type SqlParams = Record<string, string | number | null>;
function asParams(row: object): SqlParams {
  return row as unknown as SqlParams;
}

let db: DatabaseSync | null = null;

export function getDb(): DatabaseSync {
  if (db) return db;
  ensureDataDirs();
  db = new DatabaseSync(DB_PATH);
  db.exec('PRAGMA journal_mode = WAL');
  // Enforce the declared ON DELETE CASCADE so deleting an image also drops its jobs and findings.
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS images (
      id TEXT PRIMARY KEY,
      filename TEXT NOT NULL,
      path TEXT NOT NULL,
      size INTEGER NOT NULL,
      sha256 TEXT NOT NULL,
      uploadedAt INTEGER NOT NULL,
      status TEXT NOT NULL,
      identityJson TEXT,
      analysisJson TEXT
    );
    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY,
      imageId TEXT NOT NULL,
      kind TEXT NOT NULL,
      status TEXT NOT NULL,
      createdAt INTEGER NOT NULL,
      updatedAt INTEGER NOT NULL,
      params TEXT,
      log TEXT NOT NULL DEFAULT '',
      resultJson TEXT,
      error TEXT,
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_jobs_image ON jobs(imageId);
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      imageId TEXT NOT NULL,
      source TEXT NOT NULL,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      proofState TEXT NOT NULL,
      evidenceJson TEXT,
      rationale TEXT,
      createdAt INTEGER NOT NULL,
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_findings_image ON findings(imageId);
    CREATE TABLE IF NOT EXISTS binaries (
      imageId TEXT NOT NULL,
      path TEXT NOT NULL,
      sha1 TEXT,
      size INTEGER NOT NULL DEFAULT 0,
      arch TEXT,
      bits INTEGER,
      endianness TEXT,
      nx INTEGER,
      canary INTEGER,
      pic INTEGER,
      networkFacing INTEGER NOT NULL DEFAULT 0,
      importsSummary TEXT,
      triaged INTEGER NOT NULL DEFAULT 0,
      emulationStatus TEXT,
      createdAt INTEGER NOT NULL,
      updatedAt INTEGER NOT NULL,
      PRIMARY KEY (imageId, path),
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_binaries_image ON binaries(imageId);

    -- === Corpus: cross-image occurrence tables (Phase 1). They record WHERE things appear, never conclusions. ===
    CREATE TABLE IF NOT EXISTS artifact_occurrence (
      sha1 TEXT NOT NULL,
      imageId TEXT NOT NULL,
      path TEXT NOT NULL,
      arch TEXT,
      PRIMARY KEY (sha1, imageId, path),
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_artifact_sha1 ON artifact_occurrence(sha1);
    CREATE INDEX IF NOT EXISTS idx_artifact_image ON artifact_occurrence(imageId);

    CREATE TABLE IF NOT EXISTS credential_occurrence (
      hash TEXT NOT NULL,
      imageId TEXT NOT NULL,
      kind TEXT,
      severity TEXT,
      PRIMARY KEY (hash, imageId),
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_credential_hash ON credential_occurrence(hash);
    CREATE INDEX IF NOT EXISTS idx_credential_image ON credential_occurrence(imageId);

    CREATE TABLE IF NOT EXISTS component_occurrence (
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      imageId TEXT NOT NULL,
      cveCount INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (name, version, imageId),
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_component_nv ON component_occurrence(name, version);
    CREATE INDEX IF NOT EXISTS idx_component_image ON component_occurrence(imageId);

    -- Reachability priors: recorded only when a finding is actually confirmed by emulation (mostly empty until
    -- the emulation ladder is validated — the mechanism, not fabricated data).
    CREATE TABLE IF NOT EXISTS reachability_prior (
      familyKey TEXT NOT NULL,
      subject TEXT NOT NULL,
      proofState TEXT NOT NULL,
      imageId TEXT NOT NULL,
      createdAt INTEGER NOT NULL,
      PRIMARY KEY (familyKey, subject, imageId),
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_reach_family ON reachability_prior(familyKey, subject);

    -- Level 1: human-curated promoted rules (e.g. a known-bad credential watchlist).
    CREATE TABLE IF NOT EXISTS corpus_rule (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      key TEXT NOT NULL,
      label TEXT NOT NULL,
      note TEXT,
      createdAt INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_corpus_rule_key ON corpus_rule(type, key);

    -- === Phase 3: agent sessions. The auditable transcript of a conscious-autonomy run. The mechanics stay
    -- deterministic; each agent_step records the structured input a decision node saw, the decision it made, and
    -- its rationale, so every branch choice is reproducible and reviewable. An active session pins its image
    -- against retention eviction. ===
    CREATE TABLE IF NOT EXISTS agent_session (
      id TEXT PRIMARY KEY,
      imageId TEXT NOT NULL,
      status TEXT NOT NULL,
      goal TEXT,
      budgetJson TEXT NOT NULL,
      consumedJson TEXT NOT NULL,
      haltReason TEXT,
      createdAt INTEGER NOT NULL,
      updatedAt INTEGER NOT NULL,
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_session_image ON agent_session(imageId);

    CREATE TABLE IF NOT EXISTS agent_step (
      id TEXT PRIMARY KEY,
      sessionId TEXT NOT NULL,
      seq INTEGER NOT NULL,
      node TEXT NOT NULL,
      status TEXT NOT NULL,
      inputJson TEXT,
      outputJson TEXT,
      rationale TEXT,
      model TEXT,
      inputTokens INTEGER NOT NULL DEFAULT 0,
      outputTokens INTEGER NOT NULL DEFAULT 0,
      createdAt INTEGER NOT NULL,
      FOREIGN KEY (sessionId) REFERENCES agent_session(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_step_session ON agent_step(sessionId);
  `);
  // Migration: add the tags column to databases created before it existed.
  try {
    db.exec('ALTER TABLE images ADD COLUMN tags TEXT');
  } catch {
    // Column already present — nothing to do.
  }
  return db;
}

// === Images ===

export function insertImage(row: ImageRow): void {
  getDb()
    .prepare(
      `INSERT INTO images (id, filename, path, size, sha256, uploadedAt, status, identityJson, analysisJson, tags)
       VALUES (@id, @filename, @path, @size, @sha256, @uploadedAt, @status, @identityJson, @analysisJson, @tags)`,
    )
    .run(asParams(row));
}

export function updateImageAnalysis(
  id: string,
  status: ImageRow['status'],
  identityJson: string | null,
  analysisJson: string | null,
): void {
  getDb()
    .prepare('UPDATE images SET status = ?, identityJson = ?, analysisJson = ? WHERE id = ?')
    .run(status, identityJson, analysisJson, id);
}

/** Persist a refined identity (e.g. arch recovered post-extraction) without touching the cached analysis. */
export function updateImageIdentity(id: string, identityJson: string): void {
  getDb().prepare('UPDATE images SET identityJson = ? WHERE id = ?').run(identityJson, id);
}

/** Persist the user tags (a JSON array string, or null to clear). */
export function updateImageTags(id: string, tagsJson: string | null): void {
  getDb().prepare('UPDATE images SET tags = ? WHERE id = ?').run(tagsJson, id);
}

export function getImage(id: string): ImageRow | undefined {
  return getDb().prepare('SELECT * FROM images WHERE id = ?').get(id) as unknown as ImageRow | undefined;
}

export function listImages(): ImageRow[] {
  return getDb().prepare('SELECT * FROM images ORDER BY uploadedAt DESC').all() as unknown as ImageRow[];
}

export function deleteImage(id: string): void {
  getDb().prepare('DELETE FROM images WHERE id = ?').run(id);
}

// === Jobs ===

export function insertJob(row: JobRow): void {
  getDb()
    .prepare(
      `INSERT INTO jobs (id, imageId, kind, status, createdAt, updatedAt, params, log, resultJson, error)
       VALUES (@id, @imageId, @kind, @status, @createdAt, @updatedAt, @params, @log, @resultJson, @error)`,
    )
    .run(asParams(row));
}

export function appendJobLog(id: string, line: string): void {
  getDb().prepare('UPDATE jobs SET log = log || ?, updatedAt = ? WHERE id = ?').run(`${line}\n`, Date.now(), id);
}

export function updateJobStatus(id: string, status: JobStatus, resultJson: string | null, error: string | null): void {
  getDb()
    .prepare('UPDATE jobs SET status = ?, resultJson = ?, error = ?, updatedAt = ? WHERE id = ?')
    .run(status, resultJson, error, Date.now(), id);
}

export function getJob(id: string): JobRow | undefined {
  return getDb().prepare('SELECT * FROM jobs WHERE id = ?').get(id) as unknown as JobRow | undefined;
}

export function listJobs(imageId: string): JobRow[] {
  return getDb()
    .prepare('SELECT * FROM jobs WHERE imageId = ? ORDER BY createdAt DESC')
    .all(imageId) as unknown as JobRow[];
}

// === Findings ===

export function insertFindings(rows: FindingRow[]): void {
  if (rows.length === 0) return;
  const stmt = getDb().prepare(
    `INSERT OR REPLACE INTO findings
       (id, imageId, source, kind, title, severity, proofState, evidenceJson, rationale, createdAt)
     VALUES (@id, @imageId, @source, @kind, @title, @severity, @proofState, @evidenceJson, @rationale, @createdAt)`,
  );
  for (const row of rows) stmt.run(asParams(row));
}

/** Replace the finding set contributed by one source for an image (idempotent re-normalization). */
export function deleteFindingsBySource(imageId: string, source: string): void {
  getDb().prepare('DELETE FROM findings WHERE imageId = ? AND source = ?').run(imageId, source);
}

export function listFindings(imageId: string): FindingRow[] {
  return getDb()
    .prepare('SELECT * FROM findings WHERE imageId = ? ORDER BY createdAt DESC')
    .all(imageId) as unknown as FindingRow[];
}

/** Update a finding's proof state (and optional rationale) — used when emulation confirms or downgrades it. */
export function updateFindingProofState(id: string, proofState: string, rationale: string | null): void {
  getDb().prepare('UPDATE findings SET proofState = ?, rationale = ? WHERE id = ?').run(proofState, rationale, id);
}

/** Raise a finding's severity + rationale — used when a corpus watchlist rule matches (Phase 1, Level 1). */
export function elevateFinding(id: string, severity: string, rationale: string): void {
  getDb().prepare('UPDATE findings SET severity = ?, rationale = ? WHERE id = ?').run(severity, rationale, id);
}

// === Binaries ===

/** Identity fields set at extraction time (from the ELF header). Preserves triage fields on re-extraction. */
export interface BinaryIdentity {
  imageId: string;
  path: string;
  sha1: string | null;
  size: number;
  arch: string | null;
  bits: number | null;
  endianness: string | null;
  networkFacing: boolean;
}

export function registerBinary(b: BinaryIdentity): void {
  const now = Date.now();
  getDb()
    .prepare(
      `INSERT INTO binaries
         (imageId, path, sha1, size, arch, bits, endianness, networkFacing, triaged, createdAt, updatedAt)
       VALUES (@imageId, @path, @sha1, @size, @arch, @bits, @endianness, @networkFacing, 0, @now, @now)
       ON CONFLICT(imageId, path) DO UPDATE SET
         sha1 = excluded.sha1, size = excluded.size, arch = excluded.arch, bits = excluded.bits,
         endianness = excluded.endianness, networkFacing = excluded.networkFacing, updatedAt = excluded.updatedAt`,
    )
    .run({
      imageId: b.imageId,
      path: b.path,
      sha1: b.sha1,
      size: b.size,
      arch: b.arch,
      bits: b.bits,
      endianness: b.endianness,
      networkFacing: b.networkFacing ? 1 : 0,
      now,
    });
}

/** Triage fields set when radare2 runs over a binary. Upserts so a manually-triaged path still lands a row. */
export interface BinaryTriage {
  imageId: string;
  path: string;
  arch: string | null;
  bits: number | null;
  endianness: string | null;
  nx: number | null;
  canary: number | null;
  pic: number | null;
  importsSummary: string | null;
}

export function upsertBinaryTriage(t: BinaryTriage): void {
  const now = Date.now();
  getDb()
    .prepare(
      `INSERT INTO binaries
         (imageId, path, size, arch, bits, endianness, nx, canary, pic, importsSummary, triaged, createdAt, updatedAt)
       VALUES (@imageId, @path, 0, @arch, @bits, @endianness, @nx, @canary, @pic, @importsSummary, 1, @now, @now)
       ON CONFLICT(imageId, path) DO UPDATE SET
         arch = COALESCE(binaries.arch, excluded.arch), bits = COALESCE(binaries.bits, excluded.bits),
         endianness = COALESCE(binaries.endianness, excluded.endianness),
         nx = excluded.nx, canary = excluded.canary, pic = excluded.pic,
         importsSummary = excluded.importsSummary, triaged = 1, updatedAt = excluded.updatedAt`,
    )
    .run({ ...t, now });
}

/** Record the outcome of an emulation attempt against a binary (Phase-0 tasks 5/6 write this). */
export function updateBinaryEmulationStatus(imageId: string, path: string, status: string): void {
  getDb()
    .prepare('UPDATE binaries SET emulationStatus = ?, updatedAt = ? WHERE imageId = ? AND path = ?')
    .run(status, Date.now(), imageId, path);
}

export function listBinaries(imageId: string): BinaryRow[] {
  return getDb()
    .prepare('SELECT * FROM binaries WHERE imageId = ? ORDER BY networkFacing DESC, path ASC')
    .all(imageId) as unknown as BinaryRow[];
}

// === Agent sessions (Phase 3) ===

/** The active states — a session in one of these pins its image against retention eviction. */
const ACTIVE_SESSION_STATES = "('running', 'awaiting_approval')";

export function insertSession(row: AgentSessionRow): void {
  getDb()
    .prepare(
      `INSERT INTO agent_session (id, imageId, status, goal, budgetJson, consumedJson, haltReason, createdAt, updatedAt)
       VALUES (@id, @imageId, @status, @goal, @budgetJson, @consumedJson, @haltReason, @createdAt, @updatedAt)`,
    )
    .run(asParams(row));
}

export function updateSession(
  id: string,
  status: AgentSessionStatus,
  consumedJson: string,
  haltReason: string | null,
): void {
  getDb()
    .prepare('UPDATE agent_session SET status = ?, consumedJson = ?, haltReason = ?, updatedAt = ? WHERE id = ?')
    .run(status, consumedJson, haltReason, Date.now(), id);
}

export function getSession(id: string): AgentSessionRow | undefined {
  return getDb().prepare('SELECT * FROM agent_session WHERE id = ?').get(id) as unknown as AgentSessionRow | undefined;
}

export function listSessions(imageId: string): AgentSessionRow[] {
  return getDb()
    .prepare('SELECT * FROM agent_session WHERE imageId = ? ORDER BY createdAt DESC')
    .all(imageId) as unknown as AgentSessionRow[];
}

export function latestSession(imageId: string): AgentSessionRow | undefined {
  return getDb()
    .prepare('SELECT * FROM agent_session WHERE imageId = ? ORDER BY createdAt DESC LIMIT 1')
    .get(imageId) as unknown as AgentSessionRow | undefined;
}

/** Whether an image has a session that is still running or waiting for approval (used by the retention guard). */
export function hasActiveSession(imageId: string): boolean {
  const row = getDb()
    .prepare(`SELECT 1 FROM agent_session WHERE imageId = ? AND status IN ${ACTIVE_SESSION_STATES} LIMIT 1`)
    .get(imageId) as unknown as { 1: number } | undefined;
  return row !== undefined;
}

/** The set of image ids with an active session — retention consults this so it never evicts a pinned image. */
export function imagesWithActiveSessions(): Set<string> {
  const rows = getDb()
    .prepare(`SELECT DISTINCT imageId FROM agent_session WHERE status IN ${ACTIVE_SESSION_STATES}`)
    .all() as unknown as { imageId: string }[];
  return new Set(rows.map((r) => r.imageId));
}

export function insertStep(row: AgentStepRow): void {
  getDb()
    .prepare(
      `INSERT INTO agent_step
         (id, sessionId, seq, node, status, inputJson, outputJson, rationale, model, inputTokens, outputTokens, createdAt)
       VALUES (@id, @sessionId, @seq, @node, @status, @inputJson, @outputJson, @rationale, @model, @inputTokens, @outputTokens, @createdAt)`,
    )
    .run(asParams(row));
}

export function listSteps(sessionId: string): AgentStepRow[] {
  return getDb()
    .prepare('SELECT * FROM agent_step WHERE sessionId = ? ORDER BY seq ASC')
    .all(sessionId) as unknown as AgentStepRow[];
}
