import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

let dataDir: string;
let store: typeof import('./store.js');
const previousDataDir = process.env.FIRMLAB_DATA_DIR;

beforeAll(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-binary-reconcile-'));
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

describe('deleteUnregisteredBinaries', () => {
  it('removes stale selection rows while retaining triage on paths that remain', () => {
    const identity = (binaryPath: string): void =>
      store.registerBinary({
        imageId: 'image-1',
        path: binaryPath,
        sha1: binaryPath,
        size: 10,
        arch: 'mips',
        bits: 32,
        endianness: 'big',
        networkFacing: binaryPath.endsWith('httpd'),
      });
    identity('sbin/httpd');
    identity('bin/busybox');
    identity('opt/stale');
    store.upsertBinaryTriage({
      imageId: 'image-1',
      path: 'sbin/httpd',
      arch: 'mips',
      bits: 32,
      endianness: 'big',
      nx: 1,
      canary: 0,
      pic: 1,
      importsSummary: 'system',
    });

    expect(store.deleteUnregisteredBinaries('image-1', new Set(['sbin/httpd', 'bin/busybox']))).toBe(1);
    const remaining = store.listBinaries('image-1');
    expect(remaining.map((binary) => binary.path).sort()).toEqual(['bin/busybox', 'sbin/httpd']);
    expect(remaining.find((binary) => binary.path === 'sbin/httpd')).toMatchObject({ triaged: 1, canary: 0 });
  });
});
