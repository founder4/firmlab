/**
 * SQLite persistence for the workbench (better-sqlite3, synchronous). One database under the data root holds
 * uploaded image metadata + cached static analysis, and long-running jobs (extraction, emulation, SBOM,
 * decompilation). Survives API restarts so an analysis session is durable.
 */
import { DatabaseSync } from 'node:sqlite';
import { DB_PATH, ensureDataDirs } from './paths.js';

export type JobKind = 'extract' | 'binwalk' | 'sbom' | 'emulate' | 'decompile' | 'gitleaks' | 'diff' | 'ghidra';
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
  `);
  return db;
}

// === Images ===

export function insertImage(row: ImageRow): void {
  getDb()
    .prepare(
      `INSERT INTO images (id, filename, path, size, sha256, uploadedAt, status, identityJson, analysisJson)
       VALUES (@id, @filename, @path, @size, @sha256, @uploadedAt, @status, @identityJson, @analysisJson)`,
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
