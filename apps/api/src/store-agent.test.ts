import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

let dataDir: string;
let store: typeof import('./store.js');
const previousDataDir = process.env.FIRMLAB_DATA_DIR;

beforeAll(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-agent-telemetry-'));
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
  store.insertSession({
    id: 'session-1',
    imageId: 'image-1',
    status: 'running',
    goal: null,
    budgetJson: '{}',
    consumedJson: '{}',
    haltReason: null,
    createdAt: 1,
    updatedAt: 1,
  });
});

afterAll(() => {
  store.getDb().close();
  fs.rmSync(dataDir, { recursive: true, force: true });
  if (previousDataDir === undefined) Reflect.deleteProperty(process.env, 'FIRMLAB_DATA_DIR');
  else process.env.FIRMLAB_DATA_DIR = previousDataDir;
});

describe('agent step reasoning telemetry', () => {
  it('round-trips reasoning token counts and structured-output fallback use', () => {
    store.insertStep({
      id: 'step-1',
      sessionId: 'session-1',
      seq: 1,
      node: 'triage',
      status: 'ok',
      inputJson: '{}',
      outputJson: '{}',
      rationale: 'measured context',
      model: 'deepseek-reasoner',
      inputTokens: 100,
      outputTokens: 60,
      reasoningTokens: 48,
      fallbackUsed: 1,
      createdAt: 2,
    });

    expect(store.listSteps('session-1')[0]).toMatchObject({ reasoningTokens: 48, fallbackUsed: 1 });
  });

  it('defaults legacy-style inserts to no recorded telemetry', () => {
    store
      .getDb()
      .prepare(
        `INSERT INTO agent_step
           (id, sessionId, seq, node, status, inputJson, outputJson, rationale, model, inputTokens, outputTokens, createdAt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run('step-legacy', 'session-1', 2, 'preflight', 'ok', '{}', '{}', null, null, 0, 0, 3);

    expect(store.listSteps('session-1')[1]).toMatchObject({ reasoningTokens: 0, fallbackUsed: 0 });
  });
});
