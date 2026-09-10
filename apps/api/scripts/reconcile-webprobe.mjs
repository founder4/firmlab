/** Explicit, transactional reconciliation of legacy web-probe evidence. Default: read-only dry run. */
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';

export const MIGRATION = 'webprobe-v2';
export const REASON =
  'Legacy web-probe detector lacked differential and anti-reflection controls. Its vulnerability conclusions and coverage require revalidation with probeVersion 2; historical output is preserved, not proof of absence or confirmation.';
const kinds = new Set(['web-command-injection', 'web-path-traversal']);
const confirmed = new Set([
  'confirmed_in_emulation',
  'confirmed_full_system',
  'static_confirmed',
  'confirmed_on_device',
]);

function object(json) {
  try {
    const value = JSON.parse(json);
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

export function reconcileWebprobe(dbPath, { apply = false, now = Date.now() } = {}) {
  const db = new DatabaseSync(dbPath, { readOnly: !apply });
  let transaction = false;
  try {
    // Hold the write lock before reading the plan so a provider cannot replace a row between review and update.
    if (apply) {
      db.exec('BEGIN IMMEDIATE');
      transaction = true;
    }
    const findings = [];
    const jobs = [];
    const invalidJobs = [];
    for (const row of db.prepare('SELECT * FROM findings').all()) {
      if (
        !kinds.has(row.kind) ||
        row.source.startsWith('operator:') ||
        row.proofState === 'operator_assertion' ||
        row.assertionJson
      )
        continue;
      const evidence = object(row.evidenceJson) ?? {};
      if (evidence.probeVersion === 2 || evidence.revalidation?.migration === MIGRATION) continue;
      findings.push({
        ...row,
        nextState: confirmed.has(row.proofState) ? 'needs_runtime_reproduction' : row.proofState,
        nextEvidence: {
          ...evidence,
          revalidation: {
            required: true,
            migration: MIGRATION,
            reason: REASON,
            appliedAt: now,
            original: {
              title: row.title,
              proofState: row.proofState,
              rationale: row.rationale,
              evidenceJson: row.evidenceJson,
            },
          },
        },
      });
    }
    for (const row of db
      .prepare("SELECT * FROM jobs WHERE kind IN ('webprobe', 'emulate') AND resultJson IS NOT NULL")
      .all()) {
      const result = object(row.resultJson);
      if (!result) {
        invalidJobs.push(row.id);
        continue;
      }
      if (result.revalidation?.migration === MIGRATION) continue;
      const legacy =
        row.kind === 'webprobe'
          ? result.probeVersion !== 2
          : Array.isArray(result.webProbes) && result.webProbes.some((probe) => probe?.result?.probeVersion !== 2);
      if (!legacy) continue;
      jobs.push({
        ...row,
        nextResult: {
          ...result,
          revalidation: {
            required: true,
            migration: MIGRATION,
            reason: REASON,
            appliedAt: now,
            archive: { table: 'evidence_revalidation_archive', migration: MIGRATION, jobId: row.id },
          },
        },
      });
    }
    const imageIds = [...new Set([...findings, ...jobs].map((row) => row.imageId))];
    const report = {
      mode: apply ? 'apply' : 'dry-run',
      migration: MIGRATION,
      reason: REASON,
      findings: findings.map((row) => ({
        id: row.id,
        imageId: row.imageId,
        source: row.source,
        from: row.proofState,
        to: row.nextState,
      })),
      jobs: jobs.map((row) => ({ id: row.id, imageId: row.imageId, kind: row.kind })),
      images: imageIds.length,
      invalidJobs,
    };
    if (apply) {
      db.exec(
        'CREATE TABLE IF NOT EXISTS evidence_revalidation_archive (migration TEXT NOT NULL, jobId TEXT NOT NULL, originalResultJson TEXT NOT NULL, archivedAt INTEGER NOT NULL, PRIMARY KEY (migration, jobId))',
      );
      const archive = db.prepare(
        'INSERT INTO evidence_revalidation_archive (migration, jobId, originalResultJson, archivedAt) VALUES (?, ?, ?, ?)',
      );
      for (const row of jobs) archive.run(MIGRATION, row.id, row.resultJson, now);
      const updateFinding = db.prepare(
        'UPDATE findings SET proofState = ?, rationale = ?, evidenceJson = ? WHERE id = ?',
      );
      for (const row of findings)
        updateFinding.run(
          row.nextState,
          `${REASON}\n\nOriginal rationale: ${row.rationale ?? ''}`,
          JSON.stringify(row.nextEvidence),
          row.id,
        );
      // This is evidence maintenance, not a new run. Preserve updatedAt so history ordering remains historical.
      const updateJob = db.prepare('UPDATE jobs SET resultJson = ? WHERE id = ?');
      for (const row of jobs) updateJob.run(JSON.stringify(row.nextResult), row.id);
      const note = db.prepare(
        'INSERT INTO image_note (id, imageId, author, body, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)',
      );
      for (const imageId of imageIds) {
        const changes = {
          migration: MIGRATION,
          reason: REASON,
          findings: report.findings.filter((row) => row.imageId === imageId),
          jobs: report.jobs.filter((row) => row.imageId === imageId),
        };
        note.run(
          randomUUID(),
          imageId,
          'system:webprobe-reconciliation',
          `Historical evidence reconciliation (no rows deleted). Original finding evidence is retained in revalidation metadata; original job results are in evidence_revalidation_archive.\n${JSON.stringify(changes, null, 2)}`,
          now,
          now,
        );
      }
      db.exec('COMMIT');
      transaction = false;
    }
    return report;
  } finally {
    if (transaction) db.exec('ROLLBACK');
    db.close();
  }
}

export function parseArgs(args) {
  let dbPath;
  let apply = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--db') dbPath = args[++i];
    else if (args[i] === '--apply') apply = true;
    else if (args[i] !== '--dry-run') throw new Error(`Unknown argument: ${args[i]}`);
  }
  if (!dbPath || dbPath.startsWith('--'))
    throw new Error('Usage: node reconcile-webprobe.mjs --db PATH [--apply] (default: read-only dry run)');
  return { dbPath: resolve(dbPath), apply };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { dbPath, apply } = parseArgs(process.argv.slice(2));
    console.log(JSON.stringify(reconcileWebprobe(dbPath, { apply }), null, 2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
