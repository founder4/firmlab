import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { MIGRATION, reconcileWebprobe } from '../apps/api/scripts/reconcile-webprobe.mjs';

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-webprobe-reconcile-'));
  const dbPath = path.join(dir, 'firmlab.db');
  const db = new DatabaseSync(dbPath);
  db.exec(`
    CREATE TABLE findings (id TEXT PRIMARY KEY, imageId TEXT, source TEXT, kind TEXT, title TEXT,
      severity TEXT, proofState TEXT, evidenceJson TEXT, rationale TEXT, assertionJson TEXT);
    CREATE TABLE jobs (id TEXT PRIMARY KEY, imageId TEXT, kind TEXT, status TEXT, createdAt INTEGER,
      updatedAt INTEGER, params TEXT, log TEXT, resultJson TEXT, error TEXT);
    CREATE TABLE image_note (id TEXT PRIMARY KEY, imageId TEXT, author TEXT, body TEXT,
      createdAt INTEGER, updatedAt INTEGER);
  `);
  const finding = db.prepare(`INSERT INTO findings
    (id,imageId,source,kind,title,severity,proofState,evidenceJson,rationale,assertionJson)
    VALUES (?,?,?,?,?,?,?,?,?,?)`);
  finding.run(
    'legacy',
    'image-1',
    'webprobe',
    'web-command-injection',
    'Original title',
    'critical',
    'confirmed_in_emulation',
    '{"payload":"old"}',
    'Original rationale',
    null,
  );
  finding.run(
    'current',
    'image-1',
    'webprobe',
    'web-path-traversal',
    'Current',
    'high',
    'confirmed_in_emulation',
    '{"probeVersion":2}',
    'Current rationale',
    null,
  );
  finding.run(
    'operator',
    'image-1',
    'operator:analyst',
    'web-command-injection',
    'Claim',
    'high',
    'operator_assertion',
    '{}',
    'Claim rationale',
    '{}',
  );
  const job = db.prepare(`INSERT INTO jobs
    (id,imageId,kind,status,createdAt,updatedAt,params,log,resultJson,error) VALUES (?,?,?,?,?,?,?,?,?,?)`);
  job.run('legacy-job', 'image-1', 'webprobe', 'done', 10, 20, '{}', '', '{"available":true,"findings":[]}', null);
  job.run(
    'current-job',
    'image-1',
    'webprobe',
    'done',
    30,
    40,
    '{}',
    '',
    '{"probeVersion":2,"available":true,"findings":[]}',
    null,
  );
  job.run(
    'legacy-emulate',
    'image-1',
    'emulate',
    'done',
    50,
    60,
    '{}',
    '',
    '{"proofState":"confirmed_full_system","webProbes":[{"result":{"findings":[]}}]}',
    null,
  );
  db.close();
  return { dir, dbPath };
}

test('dry run is read-only and reports only legacy computed evidence', () => {
  const f = fixture();
  try {
    const report = reconcileWebprobe(f.dbPath, { now: 100 });
    assert.equal(report.mode, 'dry-run');
    assert.deepEqual(
      report.findings.map((row) => row.id),
      ['legacy'],
    );
    assert.deepEqual(
      report.jobs.map((row) => row.id),
      ['legacy-job', 'legacy-emulate'],
    );
    const db = new DatabaseSync(f.dbPath, { readOnly: true });
    assert.equal(
      db.prepare("SELECT proofState FROM findings WHERE id='legacy'").get().proofState,
      'confirmed_in_emulation',
    );
    assert.throws(() => db.prepare('SELECT * FROM evidence_revalidation_archive').all());
    db.close();
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});

test('apply preserves originals, chronology and operator/current evidence and is idempotent', () => {
  const f = fixture();
  try {
    const report = reconcileWebprobe(f.dbPath, { apply: true, now: 100 });
    assert.equal(report.findings.length, 1);
    assert.equal(report.jobs.length, 2);
    const db = new DatabaseSync(f.dbPath, { readOnly: true });
    const legacy = db.prepare("SELECT * FROM findings WHERE id='legacy'").get();
    assert.equal(legacy.proofState, 'needs_runtime_reproduction');
    assert.equal(legacy.title, 'Original title');
    assert.match(legacy.rationale, /Original rationale/);
    const evidence = JSON.parse(legacy.evidenceJson);
    assert.equal(evidence.revalidation.migration, MIGRATION);
    assert.equal(evidence.revalidation.original.proofState, 'confirmed_in_emulation');
    assert.equal(
      db.prepare("SELECT proofState FROM findings WHERE id='current'").get().proofState,
      'confirmed_in_emulation',
    );
    assert.equal(
      db.prepare("SELECT proofState FROM findings WHERE id='operator'").get().proofState,
      'operator_assertion',
    );
    const migratedJob = db.prepare("SELECT resultJson,updatedAt FROM jobs WHERE id='legacy-job'").get();
    assert.equal(migratedJob.updatedAt, 20);
    assert.equal(JSON.parse(migratedJob.resultJson).revalidation.required, true);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM evidence_revalidation_archive').get().n, 2);
    const archived = db
      .prepare("SELECT originalResultJson FROM evidence_revalidation_archive WHERE jobId='legacy-job'")
      .get();
    assert.equal(JSON.parse(archived.originalResultJson).available, true);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM image_note').get().n, 1);
    db.close();
    const again = reconcileWebprobe(f.dbPath, { apply: true, now: 200 });
    assert.equal(again.findings.length, 0);
    assert.equal(again.jobs.length, 0);
    assert.equal(again.images, 0);
  } finally {
    fs.rmSync(f.dir, { recursive: true, force: true });
  }
});
