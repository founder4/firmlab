/** Real disposable process trees and sockets validate teardown, without firmware or a database. */
import type { ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';
import { JobCancellation, cancellationDecision, jobCancellation } from './job-cancellation.js';
import { execFile, spawn } from './job-process.js';

const listen = async (port = 0) => {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return server;
};

it('only active persisted statuses are cancellation candidates', () => {
  for (const status of ['done', 'error', 'cancelling', 'cancelled'])
    expect(cancellationDecision(status)).toBe('unchanged');
  for (const status of ['queued', 'running']) expect(cancellationDecision(status)).toBe('cancel');
});

describe.skipIf(process.platform === 'win32')('owned process groups', () => {
  it('kills child and grandchild, releases their socket, and rejects subsequent spawn', async () => {
    const reserved = await listen();
    const address = reserved.address();
    if (!address || typeof address === 'string') throw new Error('missing port');
    const port = address.port;
    await new Promise<void>((resolve) => reserved.close(() => resolve()));
    const leaf = `require('node:net').createServer().listen(${port}, '127.0.0.1', () => console.log('ready')); setInterval(() => {}, 1000)`;
    const middle = `require('node:child_process').spawn(process.execPath, ['-e', ${JSON.stringify(leaf)}], {stdio: 'inherit'}); setInterval(() => {}, 1000)`;
    const root = `require('node:child_process').spawn(process.execPath, ['-e', ${JSON.stringify(middle)}], {stdio: 'inherit'}); setInterval(() => {}, 1000)`;
    const cancellation = new JobCancellation();
    try {
      const child = jobCancellation.run(cancellation, () => spawn(process.execPath, ['-e', root]));
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('tree did not start')), 5000);
        child.stdout?.on('data', (chunk: Buffer) => {
          if (chunk.toString().includes('ready')) {
            clearTimeout(timer);
            resolve();
          }
        });
      });
      cancellation.cancel();
      cancellation.cancel();
      await cancellation.cleanup();
      const reused = await listen(port);
      await new Promise<void>((resolve) => reused.close(() => resolve()));
      expect(() => jobCancellation.run(cancellation, () => spawn(process.execPath, ['-e', '']))).toThrow(
        'Job cancelled',
      );
    } finally {
      cancellation.cancel();
      await cancellation.cleanup();
    }
  });

  it('cancels promisified execFile and waits for its process close', async () => {
    const cancellation = new JobCancellation();
    const promise = jobCancellation.run(cancellation, () =>
      promisify(execFile)(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {}),
    );
    const rejected = expect(promise).rejects.toThrow();
    cancellation.cancel();
    await cancellation.cleanup();
    await rejected;
  });
});

it('waits for close after a post-spawn error rather than treating the error as process exit', async () => {
  const child = new EventEmitter() as ChildProcess;
  child.on('error', () => undefined);
  const owner = new JobCancellation();
  owner.track(child);
  let settled = false;
  const cleanup = owner.cleanup().then(() => {
    settled = true;
  });
  child.emit('error', new Error('post-spawn failure'));
  await Promise.resolve();
  expect(settled).toBe(false);
  child.emit('close', 1, null);
  await cleanup;
  expect(settled).toBe(true);
});

it.skipIf(process.platform === 'win32')(
  'verifies ignored-stdio descendant teardown before declaring sockets reusable',
  async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'firmlab-ignored-tree-'));
    try {
      for (let attempt = 0; attempt < 5; attempt++) {
        const reserved = await listen();
        const port = (reserved.address() as { port: number }).port;
        await new Promise<void>((resolve) => reserved.close(() => resolve()));
        const ready = path.join(dir, String(attempt));
        const leaf = `require('node:net').createServer().listen(${port}, '127.0.0.1', () => require('node:fs').writeFileSync(${JSON.stringify(ready)}, 'ready')); setInterval(() => {}, 1000)`;
        const middle = `require('node:child_process').spawn(process.execPath, ['-e', ${JSON.stringify(leaf)}], {stdio:'ignore'}); setInterval(() => {}, 1000)`;
        const root = `require('node:child_process').spawn(process.execPath, ['-e', ${JSON.stringify(middle)}], {stdio:'ignore'}); setInterval(() => {if (require('node:fs').existsSync(${JSON.stringify(ready)})) process.exit(0)}, 5)`;
        const owner = new JobCancellation();
        try {
          await jobCancellation.run(owner, () =>
            promisify(execFile)(process.execPath, ['-e', root], { timeout: 3000 }),
          );
          await owner.cleanup();
          const reused = await listen(port);
          await new Promise<void>((resolve) => reused.close(() => resolve()));
        } finally {
          await owner.cleanup();
        }
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
  15000,
);
