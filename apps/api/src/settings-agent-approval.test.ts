import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

let dataDir: string;
let store: typeof import('./store.js');
let settings: typeof import('./settings.js');
const previousDataDir = process.env.FIRMLAB_DATA_DIR;

beforeAll(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-agent-approval-'));
  process.env.FIRMLAB_DATA_DIR = dataDir;
  vi.resetModules();
  store = await import('./store.js');
  settings = await import('./settings.js');
});

afterAll(() => {
  store.getDb().close();
  fs.rmSync(dataDir, { recursive: true, force: true });
  if (previousDataDir === undefined) Reflect.deleteProperty(process.env, 'FIRMLAB_DATA_DIR');
  else process.env.FIRMLAB_DATA_DIR = previousDataDir;
});

describe('persisted agent pre-approval', () => {
  it('round-trips an explicit choice and can return to following the environment', () => {
    expect(settings.getAgentPreapprovalOverride()).toBeUndefined();
    settings.setAgentPreapproval(true, 123);
    expect(settings.getAgentPreapprovalOverride()).toBe('1');
    expect(
      store.getDb().prepare('SELECT updatedAt FROM settings WHERE key = ?').get('FIRMLAB_AGENT_PREAPPROVE'),
    ).toEqual({ updatedAt: 123 });
    settings.clearAgentPreapproval();
    expect(settings.getAgentPreapprovalOverride()).toBeUndefined();
  });
});
