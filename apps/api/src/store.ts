/**
 * SQLite persistence for the workbench (better-sqlite3, synchronous). One database under the data root holds
 * uploaded image metadata + cached static analysis, and long-running jobs (extraction, emulation, SBOM,
 * decompilation). Completed results survive API restarts; active in-process work is reconciled explicitly at
 * startup because its executable closure cannot be persisted.
 */
import { createRequire } from 'node:module';
import { OPERATOR_ASSERTION } from '@firmlab/core';
import { OPERATOR_SOURCE_PREFIX } from './operator-findings.js';
import { DB_PATH, ensureDataDirs } from './paths.js';

// Vite 5 predates `node:sqlite` and tries to resolve a static import as a package named `sqlite` in tests.
// Loading the same built-in through Node's require bridge keeps the production dependency native while allowing
// store integration tests to exercise the real database instead of a SQL mock.
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');
type FirmLabDatabase = InstanceType<typeof DatabaseSync>;

export type JobKind =
  | 'extract'
  // The binary-hardening sweep. It ran only inside the autonomous scan until it was given a route of its own,
  // which is why its kind arrives long after the providers around it.
  | 'binvuln'
  // The kernel-module sweep. `binvuln` excludes ET_REL objects by construction, so until this existed the `.ko`
  // files in a rootfs were counted by `component-map` and read by nothing.
  | 'kmod'
  // Export reachability — the question a `.so` or `.ko` admits, since neither has an entry point to explore
  // from. A distinct kind from `symreach`: the claim is a control-flow path, not a feasible one.
  | 'exportreach'
  | 'binwalk'
  | 'sbom'
  | 'emulate'
  | 'decompile'
  | 'gitleaks'
  | 'diff'
  | 'ghidra'
  | 'copilot'
  | 'research'
  | 'fuzz'
  | 'renode'
  | 'chipsec'
  | 'webprobe'
  | 'uboot'
  | 'devicetree'
  | 'fsaudit'
  | 'certs'
  | 'rtos'
  | 'compmap'
  | 'services'
  | 'fcc'
  | 'opacidad'
  | 'symreach'
  | 'fwhunt'
  | 'funcdiff'
  | 'dynprobe'
  | 'nvram'
  | 'kernel'
  | 'yarascan'
  | 'credmatch'
  | 'updatepath';
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
  /**
   * Set only on operator-authored rows: the serialized `OperatorAssertion` (who, when, on what basis, whether it
   * still stands). Nullable forever — every row written before this column existed is code-authored, and a null
   * here means exactly that.
   */
  assertionJson: string | null;
  /**
   * HOW this was known, alongside how far it was proven. Nullable forever, and a null means NOT RECORDED — a row
   * written before this column existed, or by a provider that has not been taught its channel. Reading a null as
   * "static" would invent provenance out of a missing field.
   */
  evidenceChannel: string | null;
  /** The serialized list of what was changed about the subject to obtain this. Null/empty = the image as shipped. */
  interventionsJson: string | null;
  createdAt: number;
}

/** A free-text working note on an image. Explicitly NOT a finding — see `routes/operator.ts`. */
export interface ImageNoteRow {
  id: string;
  imageId: string;
  author: string;
  body: string;
  createdAt: number;
  updatedAt: number;
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
  /** Subset of outputTokens spent in hidden provider reasoning; zero when absent/unreported. */
  reasoningTokens: number;
  /** SQLite boolean: the structured call needed its bounded non-thinking recovery attempt. */
  fallbackUsed: number;
  createdAt: number;
}

/** node:sqlite binds named parameters from a plain record; our typed rows are cast through this. */
type SqlParams = Record<string, string | number | null>;
function asParams(row: object): SqlParams {
  return row as unknown as SqlParams;
}

let db: FirmLabDatabase | null = null;

export function getDb(): FirmLabDatabase {
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
      assertionJson TEXT,
      createdAt INTEGER NOT NULL,
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_findings_image ON findings(imageId);
    -- Per-image working notes: reasoning that is not yet (and may never be) a finding. A separate table rather
    -- than a nullable finding kind, so nothing that reads findings can ever pick a note up by accident.
    CREATE TABLE IF NOT EXISTS image_note (
      id TEXT PRIMARY KEY,
      imageId TEXT NOT NULL,
      author TEXT NOT NULL,
      body TEXT NOT NULL,
      createdAt INTEGER NOT NULL,
      updatedAt INTEGER NOT NULL,
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_image_note_image ON image_note(imageId);
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
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updatedAt INTEGER NOT NULL
    );
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
      reasoningTokens INTEGER NOT NULL DEFAULT 0,
      fallbackUsed INTEGER NOT NULL DEFAULT 0,
      createdAt INTEGER NOT NULL,
      FOREIGN KEY (sessionId) REFERENCES agent_session(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_step_session ON agent_step(sessionId);

    CREATE TABLE IF NOT EXISTS emulation_preset (
      id TEXT PRIMARY KEY,
      imageId TEXT NOT NULL,
      name TEXT NOT NULL,
      mode TEXT NOT NULL,
      binary TEXT,
      argsJson TEXT,
      createdAt INTEGER NOT NULL,
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_preset_image ON emulation_preset(imageId);

    -- === Phase 6: capture & acquisition. Deliberately NOT image-scoped — a capture PRECEDES an image and may
    -- produce one, so these tables stand on their own (the first non-image-scoped state in the store). A
    -- capture_session is the auditable lifecycle anchor (armed to discovering to torn_down); the devices table is
    -- a persistent LAN inventory that accumulates across scans; capture_provenance links an ingested image back to
    -- how it was acquired — its schema lands now (a 6.0 deliverable), rows are written when interception ships. ===
    CREATE TABLE IF NOT EXISTS capture_sessions (
      id TEXT PRIMARY KEY,
      status TEXT NOT NULL,
      subnet TEXT,
      targetDeviceId TEXT,
      strategyJson TEXT,
      transcript TEXT NOT NULL DEFAULT '',
      deviceCount INTEGER NOT NULL DEFAULT 0,
      error TEXT,
      createdAt INTEGER NOT NULL,
      updatedAt INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_capture_sessions_created ON capture_sessions(createdAt);

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      mac TEXT NOT NULL UNIQUE,
      ouiVendor TEXT,
      ip TEXT,
      mdnsIdentity TEXT,
      openPorts TEXT,
      typeGuess TEXT,
      typeConfidence TEXT,
      firstSeen INTEGER NOT NULL,
      lastSeen INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_devices_lastseen ON devices(lastSeen);

    CREATE TABLE IF NOT EXISTS capture_provenance (
      id TEXT PRIMARY KEY,
      imageId TEXT NOT NULL,
      deviceId TEXT,
      sessionId TEXT,
      endpoint TEXT,
      version TEXT,
      transport TEXT,
      tlsPosture TEXT,
      capturedAt INTEGER NOT NULL,
      FOREIGN KEY (imageId) REFERENCES images(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_capture_provenance_image ON capture_provenance(imageId);

    -- Phase 6.1: the observed HTTP(S) flows of a capture session — the live flow feed, with each scored for
    -- "is this an OTA firmware blob?" (@firmlab/core signatures + entropy). Keyed by a deterministic flow id so
    -- re-reading the proxy's growing manifest is idempotent. Cascades with its session.
    CREATE TABLE IF NOT EXISTS capture_flows (
      id TEXT PRIMARY KEY,
      sessionId TEXT NOT NULL,
      host TEXT,
      url TEXT,
      method TEXT,
      contentType TEXT,
      size INTEGER NOT NULL DEFAULT 0,
      tlsPosture TEXT,
      firmwareScore INTEGER NOT NULL DEFAULT 0,
      carved INTEGER NOT NULL DEFAULT 0,
      bodyPath TEXT,
      createdAt INTEGER NOT NULL,
      FOREIGN KEY (sessionId) REFERENCES capture_sessions(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_capture_flows_session ON capture_flows(sessionId);
  `);
  // Migration: add the tags column to databases created before it existed.
  try {
    db.exec('ALTER TABLE images ADD COLUMN tags TEXT');
  } catch {
    // Column already present — nothing to do.
  }
  // Migration: operator assertions. Every pre-existing row gets NULL, which is the correct reading — everything
  // written before this column existed was authored by code.
  try {
    db.exec('ALTER TABLE findings ADD COLUMN assertionJson TEXT');
  } catch {
    // Column already present — nothing to do.
  }
  // Migration: the evidence channel and the intervention list. NULL on every pre-existing row, and NULL means
  // NOT RECORDED — deliberately not `static_bytes`. Backfilling a default here would manufacture provenance for
  // thousands of rows out of a column that did not exist when they were written.
  for (const column of ['evidenceChannel TEXT', 'interventionsJson TEXT']) {
    try {
      db.exec(`ALTER TABLE findings ADD COLUMN ${column}`);
    } catch {
      // Column already present — nothing to do.
    }
  }
  // Migration: provider reasoning telemetry. It is operational metadata, never chain-of-thought content. Older
  // steps correctly read as zero/not-used because the adapter did not preserve either measurement then.
  for (const column of ['reasoningTokens INTEGER NOT NULL DEFAULT 0', 'fallbackUsed INTEGER NOT NULL DEFAULT 0']) {
    try {
      db.exec(`ALTER TABLE agent_step ADD COLUMN ${column}`);
    } catch {
      // Column already present — nothing to do.
    }
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

/**
 * Close over the gap between durable job rows and the deliberately in-process runner. A queued/running row can
 * survive a process exit, but the `work` closure that could advance it cannot. On startup, turn every such row
 * into an explicit terminal failure instead of leaving the UI polling forever or pretending it can be resumed.
 *
 * Both statuses are reconciled: a queued job has not started, but its closure lived only in the old process just
 * like a running job's closure did. Completed/error rows are immutable here. Returns the number of rows changed
 * so startup can report recovery work. `now` is injectable only to make the persisted transition deterministic
 * under test.
 */
export function reconcileInterruptedJobs(now = Date.now()): number {
  const runningError =
    'interrupted by API restart while running; the in-memory job cannot be resumed — retry to start a new job';
  const queuedError =
    'discarded after API restart while queued; the in-memory job cannot be resumed — retry to start a new job';
  const result = getDb()
    .prepare(
      `UPDATE jobs
       SET status = 'error',
           updatedAt = ?,
           resultJson = NULL,
           error = CASE status WHEN 'running' THEN ? ELSE ? END,
           log = log || CASE status WHEN 'running' THEN ? ELSE ? END
       WHERE status IN ('queued', 'running')`,
    )
    .run(now, runningError, queuedError, `RECOVERY: ${runningError}\n`, `RECOVERY: ${queuedError}\n`);
  return Number(result.changes);
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
       (id, imageId, source, kind, title, severity, proofState, evidenceJson, rationale, assertionJson,
        evidenceChannel, interventionsJson, createdAt)
     VALUES (@id, @imageId, @source, @kind, @title, @severity, @proofState, @evidenceJson, @rationale,
             @assertionJson, @evidenceChannel, @interventionsJson, @createdAt)`,
  );
  for (const row of rows) stmt.run(asParams(row));
}

/**
 * Replace the finding set contributed by one source for an image (idempotent re-normalization).
 *
 * Operator-authored rows are excluded IN THE SQL, not by the caller checking first. That placement is the point:
 * `syncFindings` also refuses an operator source, but this is the layer a provider written next year — by someone
 * who never read that guard — still cannot get past. A hand-written record surviving every future re-run is a
 * property of the schema access path, not of anyone remembering.
 */
export function deleteFindingsBySource(imageId: string, source: string): void {
  getDb()
    .prepare(`DELETE FROM findings WHERE imageId = ? AND source = ? AND source NOT LIKE '${OPERATOR_SOURCE_PREFIX}%'`)
    .run(imageId, source);
}

/**
 * The rows one source contributed to an image. Excludes operator rows for the same reason the delete does, and in
 * the same place: this is what `retireFindings` reads to describe what it is about to remove, so a listing that
 * could return an assertion would let a retirement's note claim to be removing one.
 */
export function listFindingsBySource(imageId: string, source: string): FindingRow[] {
  return getDb()
    .prepare(
      `SELECT * FROM findings WHERE imageId = ? AND source = ? AND source NOT LIKE '${OPERATOR_SOURCE_PREFIX}%' ORDER BY createdAt DESC`,
    )
    .all(imageId, source) as unknown as FindingRow[];
}

export function listFindings(imageId: string): FindingRow[] {
  return getDb()
    .prepare('SELECT * FROM findings WHERE imageId = ? ORDER BY createdAt DESC')
    .all(imageId) as unknown as FindingRow[];
}

export function getFinding(id: string): FindingRow | null {
  const row = getDb().prepare('SELECT * FROM findings WHERE id = ?').get(id) as unknown as FindingRow | undefined;
  return row ?? null;
}

/**
 * Update a finding's proof state (and optional rationale) — used when emulation confirms or downgrades it.
 *
 * Refuses operator rows in the SQL. This is the promotion path: the agent's verdict node calls it to move a
 * finding up the ladder, and an assertion silently acquiring `static_confirmed` because an agent decided its own
 * note looked convincing is the single worst outcome this feature could have. An assertion is not on the ladder,
 * so nothing can move it along one.
 */
export function updateFindingProofState(id: string, proofState: string, rationale: string | null): void {
  getDb()
    .prepare(`UPDATE findings SET proofState = ?, rationale = ? WHERE id = ? AND proofState <> '${OPERATOR_ASSERTION}'`)
    .run(proofState, rationale, id);
}

/**
 * Raise a finding's severity + rationale — used when a corpus watchlist rule matches (Phase 1, Level 1).
 * Also refuses operator rows: the rationale it overwrites is the author's stated basis for the claim, and code
 * lending its own weight to a human's assertion is the same conflation from the other direction.
 */
export function elevateFinding(id: string, severity: string, rationale: string): void {
  getDb()
    .prepare(`UPDATE findings SET severity = ?, rationale = ? WHERE id = ? AND proofState <> '${OPERATOR_ASSERTION}'`)
    .run(severity, rationale, id);
}

/** Amend or withdraw an operator row's assertion in place. Only ever called for rows that carry one. */
export function updateFindingAssertion(
  id: string,
  assertionJson: string,
  patch: { title?: string; severity?: string; rationale?: string; evidenceJson?: string },
): void {
  const sets = ['assertionJson = @assertionJson'];
  if (patch.title !== undefined) sets.push('title = @title');
  if (patch.severity !== undefined) sets.push('severity = @severity');
  if (patch.rationale !== undefined) sets.push('rationale = @rationale');
  if (patch.evidenceJson !== undefined) sets.push('evidenceJson = @evidenceJson');
  getDb()
    .prepare(`UPDATE findings SET ${sets.join(', ')} WHERE id = @id AND proofState = '${OPERATOR_ASSERTION}'`)
    .run(asParams({ id, assertionJson, ...patch }));
}

// === Per-image working notes (not findings) ===

export function insertImageNote(row: ImageNoteRow): void {
  getDb()
    .prepare(
      `INSERT INTO image_note (id, imageId, author, body, createdAt, updatedAt)
       VALUES (@id, @imageId, @author, @body, @createdAt, @updatedAt)`,
    )
    .run(asParams(row));
}

export function listImageNotes(imageId: string): ImageNoteRow[] {
  return getDb()
    .prepare('SELECT * FROM image_note WHERE imageId = ? ORDER BY createdAt DESC')
    .all(imageId) as unknown as ImageNoteRow[];
}

export function getImageNote(id: string): ImageNoteRow | null {
  const row = getDb().prepare('SELECT * FROM image_note WHERE id = ?').get(id) as unknown as ImageNoteRow | undefined;
  return row ?? null;
}

export function updateImageNote(id: string, body: string, updatedAt: number): void {
  getDb().prepare('UPDATE image_note SET body = ?, updatedAt = ? WHERE id = ?').run(body, updatedAt, id);
}

export function deleteImageNote(id: string): void {
  getDb().prepare('DELETE FROM image_note WHERE id = ?').run(id);
}

// === Saved emulation presets ===

/** A stored emulation preset: a named, reusable recipe config (mode + optional binary/args) for an image. */
export interface PresetRow {
  id: string;
  imageId: string;
  name: string;
  mode: string;
  binary: string | null;
  argsJson: string | null;
  createdAt: number;
}

export function insertPreset(row: PresetRow): void {
  getDb()
    .prepare(
      `INSERT OR REPLACE INTO emulation_preset (id, imageId, name, mode, binary, argsJson, createdAt)
       VALUES (@id, @imageId, @name, @mode, @binary, @argsJson, @createdAt)`,
    )
    .run(asParams(row));
}

export function listPresets(imageId: string): PresetRow[] {
  return getDb()
    .prepare('SELECT * FROM emulation_preset WHERE imageId = ? ORDER BY createdAt DESC')
    .all(imageId) as unknown as PresetRow[];
}

export function deletePreset(id: string): void {
  getDb().prepare('DELETE FROM emulation_preset WHERE id = ?').run(id);
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
         (id, sessionId, seq, node, status, inputJson, outputJson, rationale, model, inputTokens, outputTokens,
          reasoningTokens, fallbackUsed, createdAt)
       VALUES (@id, @sessionId, @seq, @node, @status, @inputJson, @outputJson, @rationale, @model, @inputTokens,
               @outputTokens, @reasoningTokens, @fallbackUsed, @createdAt)`,
    )
    .run(asParams(row));
}

export function listSteps(sessionId: string): AgentStepRow[] {
  return getDb()
    .prepare('SELECT * FROM agent_step WHERE sessionId = ? ORDER BY seq ASC')
    .all(sessionId) as unknown as AgentStepRow[];
}

// === Phase 6: capture & acquisition ===

/**
 * A capture session's lifecycle (design §9). NOT image-scoped — a capture runs BEFORE any image exists and may
 * produce one. Phase 6.0 exercises only `armed → discovering → done | error`; the later states are the ladder the
 * interception phases (6.1+) drive the same row through.
 */
export type CaptureSessionStatus =
  | 'armed'
  | 'discovering'
  | 'target_selected'
  | 'preflight'
  | 'positioning'
  | 'watching'
  | 'carving'
  | 'captured'
  | 'ingested'
  | 'timed_out'
  | 'torn_down'
  | 'done'
  | 'error';

export interface CaptureSessionRow {
  id: string;
  status: CaptureSessionStatus;
  /** The subnet a discovery scan swept (CIDR), or null. */
  subnet: string | null;
  /** The device chosen for capture (6.1+), or null during discovery-only. */
  targetDeviceId: string | null;
  /** The chosen capture strategy as JSON (6.1+), or null. */
  strategyJson: string | null;
  /** Human-readable transcript, appended step by step (mirrors the agent transcript). */
  transcript: string;
  deviceCount: number;
  error: string | null;
  createdAt: number;
  updatedAt: number;
}

/**
 * A device seen on the LAN — a persistent inventory keyed by MAC that accumulates across scans (design §6/§11).
 * Nothing here is intercepted: discovery is passive. typeGuess/typeConfidence are heuristic, never asserted fact.
 */
export interface DeviceRow {
  id: string;
  mac: string;
  ouiVendor: string | null;
  ip: string | null;
  /** mDNS/SSDP identity (advertised service types / name) as a JSON string, or null. */
  mdnsIdentity: string | null;
  /** Observed open ports as a CSV string, or null. */
  openPorts: string | null;
  typeGuess: string | null;
  typeConfidence: string | null;
  firstSeen: number;
  lastSeen: number;
}

export function insertCaptureSession(row: CaptureSessionRow): void {
  getDb()
    .prepare(
      `INSERT INTO capture_sessions
         (id, status, subnet, targetDeviceId, strategyJson, transcript, deviceCount, error, createdAt, updatedAt)
       VALUES (@id, @status, @subnet, @targetDeviceId, @strategyJson, @transcript, @deviceCount, @error, @createdAt, @updatedAt)`,
    )
    .run(asParams(row));
}

export function updateCaptureSession(
  id: string,
  status: CaptureSessionStatus,
  transcript: string,
  deviceCount: number,
  error: string | null,
): void {
  getDb()
    .prepare(
      'UPDATE capture_sessions SET status = ?, transcript = ?, deviceCount = ?, error = ?, updatedAt = ? WHERE id = ?',
    )
    .run(status, transcript, deviceCount, error, Date.now(), id);
}

export function getCaptureSession(id: string): CaptureSessionRow | undefined {
  return getDb().prepare('SELECT * FROM capture_sessions WHERE id = ?').get(id) as unknown as
    | CaptureSessionRow
    | undefined;
}

/** Upsert a discovered device into the persistent inventory, keyed by MAC. Preserves firstSeen + the row id. */
export function upsertDevice(row: DeviceRow): void {
  getDb()
    .prepare(
      `INSERT INTO devices
         (id, mac, ouiVendor, ip, mdnsIdentity, openPorts, typeGuess, typeConfidence, firstSeen, lastSeen)
       VALUES (@id, @mac, @ouiVendor, @ip, @mdnsIdentity, @openPorts, @typeGuess, @typeConfidence, @firstSeen, @lastSeen)
       ON CONFLICT(mac) DO UPDATE SET
         ip = excluded.ip,
         ouiVendor = COALESCE(excluded.ouiVendor, devices.ouiVendor),
         mdnsIdentity = COALESCE(excluded.mdnsIdentity, devices.mdnsIdentity),
         openPorts = COALESCE(excluded.openPorts, devices.openPorts),
         typeGuess = COALESCE(excluded.typeGuess, devices.typeGuess),
         typeConfidence = COALESCE(excluded.typeConfidence, devices.typeConfidence),
         lastSeen = excluded.lastSeen`,
    )
    .run(asParams(row));
}

export function listDevices(): DeviceRow[] {
  return getDb().prepare('SELECT * FROM devices ORDER BY lastSeen DESC').all() as unknown as DeviceRow[];
}

export function getDevice(id: string): DeviceRow | undefined {
  return getDb().prepare('SELECT * FROM devices WHERE id = ?').get(id) as unknown as DeviceRow | undefined;
}

// === Phase 6.1: capture flows + provenance ===

/** One observed HTTP(S) flow in a capture session, scored for whether it carries an OTA firmware blob. */
export interface CaptureFlowRow {
  id: string;
  sessionId: string;
  host: string | null;
  url: string | null;
  method: string | null;
  contentType: string | null;
  size: number;
  /** 'plaintext' | 'tls-unpinned' | 'tls-pinned' | null. */
  tlsPosture: string | null;
  /** 0..100 firmware-likelihood from @firmlab/core signatures + entropy. */
  firmwareScore: number;
  /** 1 when the body was staged as an ingestable candidate. */
  carved: number;
  /** Absolute path to the saved body on disk (for carved flows), or null. */
  bodyPath: string | null;
  createdAt: number;
}

/** How an ingested image was acquired — links an `images` row back to the device/session/endpoint/transport. */
export interface CaptureProvenanceRow {
  id: string;
  imageId: string;
  deviceId: string | null;
  sessionId: string | null;
  endpoint: string | null;
  version: string | null;
  transport: string | null;
  tlsPosture: string | null;
  capturedAt: number;
}

/** Idempotent per flow id — re-reading the proxy's growing manifest upserts each flow without duplicating. */
export function upsertCaptureFlow(row: CaptureFlowRow): void {
  getDb()
    .prepare(
      `INSERT INTO capture_flows
         (id, sessionId, host, url, method, contentType, size, tlsPosture, firmwareScore, carved, bodyPath, createdAt)
       VALUES (@id, @sessionId, @host, @url, @method, @contentType, @size, @tlsPosture, @firmwareScore, @carved, @bodyPath, @createdAt)
       ON CONFLICT(id) DO UPDATE SET
         host = excluded.host, url = excluded.url, method = excluded.method, contentType = excluded.contentType,
         size = excluded.size, tlsPosture = excluded.tlsPosture, firmwareScore = excluded.firmwareScore,
         carved = excluded.carved, bodyPath = excluded.bodyPath`,
    )
    .run(asParams(row));
}

export function listCaptureFlows(sessionId: string): CaptureFlowRow[] {
  return getDb()
    .prepare('SELECT * FROM capture_flows WHERE sessionId = ? ORDER BY firmwareScore DESC, createdAt ASC')
    .all(sessionId) as unknown as CaptureFlowRow[];
}

export function getCaptureFlow(id: string): CaptureFlowRow | undefined {
  return getDb().prepare('SELECT * FROM capture_flows WHERE id = ?').get(id) as unknown as CaptureFlowRow | undefined;
}

export function insertCaptureProvenance(row: CaptureProvenanceRow): void {
  getDb()
    .prepare(
      `INSERT INTO capture_provenance
         (id, imageId, deviceId, sessionId, endpoint, version, transport, tlsPosture, capturedAt)
       VALUES (@id, @imageId, @deviceId, @sessionId, @endpoint, @version, @transport, @tlsPosture, @capturedAt)`,
    )
    .run(asParams(row));
}

/** All capture-provenance rows (the acquired-image history the learning surface aggregates). Newest first. */
export function listCaptureProvenance(): CaptureProvenanceRow[] {
  return getDb()
    .prepare('SELECT * FROM capture_provenance ORDER BY capturedAt DESC')
    .all() as unknown as CaptureProvenanceRow[];
}
