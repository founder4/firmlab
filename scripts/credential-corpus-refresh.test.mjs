import assert from 'node:assert/strict';
import test from 'node:test';
import { parseArgs, runCredentialRefresh, summarizeRefresh } from './credential-corpus-refresh.mjs';

test('arguments are bounded and dry-run never starts a provider job', async () => {
  const args = parseArgs(['--dry-run', '--concurrency', '3'], {});
  assert.equal(args.base, 'http://127.0.0.1:8899');
  assert.equal(args.concurrency, 3);
  assert.throws(() => parseArgs(['--poll-ms', '0'], {}), /positive integer/);
  const calls = [];
  const report = await runCredentialRefresh(args, {}, async (url, init) => {
    calls.push({ url, method: init?.method ?? 'GET' });
    return new Response(JSON.stringify({ images: [{ id: 'one', filename: 'one.bin' }] }), { status: 200 });
  });
  assert.deepEqual(calls, [{ url: 'http://127.0.0.1:8899/api/images', method: 'GET' }]);
  assert.equal(report.stagesPlanned, 3);
  assert.equal(report.stagesDone, 0);
});

test('summary keeps unavailable inputs separate from completed scans', () => {
  const report = summarizeRefresh(
    [{ id: 'one' }],
    [
      [
        { status: 'done', findings: 2 },
        { status: 'done', findings: 0 },
        { status: 'no-input', reason: 'not extracted' },
      ],
    ],
  );
  assert.equal(report.stagesPlanned, 3);
  assert.equal(report.stagesDone, 2);
  assert.equal(report.stagesWithoutInput, 1);
  assert.equal(report.findings, 2);
});
