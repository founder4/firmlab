import assert from 'node:assert/strict';
import test from 'node:test';
import { campaignComplete, parseArgs, progressLine } from './fwhunt-campaign.mjs';

function pass(overrides = {}) {
  return {
    ran: true,
    modulesCarved: 4,
    batchCount: 2,
    batchesCompleted: [0, 1],
    batches: [
      { index: 0, complete: true },
      { index: 1, complete: true },
    ],
    modulesScanned: [{ name: 'A' }, { name: 'B' }, { name: 'C' }, { name: 'D' }],
    modulesFailed: [],
    ...overrides,
  };
}

test('a campaign finishes when every batch has a terminal, attributable disposition', () => {
  assert.equal(campaignComplete(pass()), true);
  assert.equal(campaignComplete(pass({ batches: [{ index: 0, complete: true }] })), false);
  assert.equal(campaignComplete(pass({ modulesScanned: [{ name: 'A' }] })), false);
  assert.equal(
    campaignComplete(
      pass({
        modulesScanned: [{ name: 'A' }, { name: 'B' }, { name: 'C' }],
        modulesFailed: [{ name: 'D' }],
        batches: [
          { index: 0, complete: true },
          { index: 1, complete: false, finalizedWithFailures: true },
        ],
      }),
    ),
    true,
  );
});

test('progress states all three campaign denominators', () => {
  assert.equal(progressLine(pass()), 'FwHunt: 4/4 modules scanned; 2/2 batches settled; 0 failed.');
});

test('arguments require an image and accept explicit resumability bounds', () => {
  assert.throws(() => parseArgs([], {}), /--image is required/);
  assert.deepEqual(parseArgs(['--image', 'abc', '--poll-ms', '10', '--max-retries', '4'], {}), {
    base: 'http://127.0.0.1:8899',
    image: 'abc',
    restart: false,
    pollMs: 10,
    jobTimeoutMs: 1_800_000,
    maxRetries: 4,
    failFast: false,
  });
});
