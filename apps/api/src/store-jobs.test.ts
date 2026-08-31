import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { JobRow } from './store.js';

let dataDir: string;
let store: typeof import('./store.js');
const previousDataDir = process.env.FIRMLAB_DATA_DIR;

function row(id: string, status: JobRow['status'], overrides: Partial<JobRow> = {}): JobRow {
  return {
    id,
    imageId: 'image-1',
    kind: 'extract',
    status,
    createdAt: 100,
    updatedAt: 100,
    params: '{}',
    log: '',
    resultJson: null,
    error: null,
    ...overrides,
  };
}

beforeAll(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-job-recovery-'));
  process.env.FIRMLAB_DATA_DIR = dataDir;
  vi.resetModules();
  store = await import('./store.js');
  store
    .getDb()
    .prepare(
      `INSERT INTO images (id, filename, path, size, sha256, uploadedAt, status, identityJson, analysisJson)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run('image-1', 'firmware.bin', '/firmware.bin', 1, 'sha256', 1, 'ready', null, null);
});

afterAll(() => {
  store.getDb().close();
  fs.rmSync(dataDir, { recursive: true, force: true });
  if (previousDataDir === undefined) Reflect.deleteProperty(process.env, 'FIRMLAB_DATA_DIR');
  else process.env.FIRMLAB_DATA_DIR = previousDataDir;
});

describe('reconcileInterruptedJobs', () => {
  it('terminates queued/running jobs honestly and leaves terminal jobs untouched', () => {
    store.insertJob(row('queued', 'queued', { log: 'accepted\n' }));
    store.insertJob(row('running', 'running', { log: 'started\n', resultJson: '{"partial":true}' }));
    store.insertJob(row('done', 'done', { resultJson: '{"ok":true}', updatedAt: 200 }));
    store.insertJob(row('error', 'error', { error: 'provider failed', updatedAt: 300 }));

    expect(store.reconcileInterruptedJobs(1_234)).toBe(2);

    const queued = store.getJob('queued');
    expect(queued).toMatchObject({ status: 'error', updatedAt: 1_234, resultJson: null });
    expect(queued?.error).toContain('while queued');
    expect(queued?.error).toContain('cannot be resumed');
    expect(queued?.log).toBe(`accepted\nRECOVERY: ${queued?.error}\n`);

    const running = store.getJob('running');
    expect(running).toMatchObject({ status: 'error', updatedAt: 1_234, resultJson: null });
    expect(running?.error).toContain('while running');
    expect(running?.error).toContain('cannot be resumed');
    expect(running?.log).toBe(`started\nRECOVERY: ${running?.error}\n`);

    expect(store.getJob('done')).toMatchObject({
      status: 'done',
      updatedAt: 200,
      resultJson: '{"ok":true}',
      error: null,
    });
    expect(store.getJob('error')).toMatchObject({ status: 'error', updatedAt: 300, error: 'provider failed' });

    // The transition is terminal and safe to invoke more than once at startup.
    expect(store.reconcileInterruptedJobs(9_999)).toBe(0);
    expect(store.getJob('running')?.updatedAt).toBe(1_234);
  });
});

describe('deleteSupersededJobSnapshots', () => {
  it('keeps the newest cumulative snapshot and failed attempts, but removes older successful snapshots', () => {
    store.insertJob(row('fwhunt-old-1', 'done', { kind: 'fwhunt', resultJson: '{"batch":1}', createdAt: 400 }));
    store.insertJob(row('fwhunt-error', 'error', { kind: 'fwhunt', error: 'scanner failed', createdAt: 500 }));
    store.insertJob(row('fwhunt-old-2', 'done', { kind: 'fwhunt', resultJson: '{"batch":2}', createdAt: 600 }));
    store.insertJob(row('fwhunt-current', 'done', { kind: 'fwhunt', resultJson: '{"batch":3}', createdAt: 700 }));
    store.insertJob(row('other-kind', 'done', { kind: 'kernel', resultJson: '{"ok":true}', createdAt: 800 }));

    expect(store.deleteSupersededJobSnapshots('image-1', 'fwhunt', 'fwhunt-current')).toBe(2);
    expect(store.getJob('fwhunt-old-1')).toBeUndefined();
    expect(store.getJob('fwhunt-old-2')).toBeUndefined();
    expect(store.getJob('fwhunt-current')?.resultJson).toBe('{"batch":3}');
    expect(store.getJob('fwhunt-error')).toMatchObject({ status: 'error', error: 'scanner failed' });
    expect(store.getJob('other-kind')?.resultJson).toBe('{"ok":true}');
  });
});
