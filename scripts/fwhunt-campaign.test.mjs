import assert from 'node:assert/strict';
import test from 'node:test';
import { campaignComplete, parseArgs, progressLine } from './fwhunt-campaign.mjs';

function pass(overrides = {}) {
  return {
    ran: true,
    modulesCarved: 4,
    batchCount: 2,
    batchesCompleted: [0, 1],
    modulesScanned: [{ name: 'A' }, { name: 'B' }, { name: 'C' }, { name: 'D' }],
    modulesFailed: [],
    ...overrides,
  };
}

test('a campaign is complete only when every module and every batch completed without failures', () => {
  assert.equal(campaignComplete(pass()), true);
  assert.equal(campaignComplete(pass({ batchesCompleted: [0] })), false);
  assert.equal(campaignComplete(pass({ modulesScanned: [{ name: 'A' }] })), false);
  assert.equal(campaignComplete(pass({ modulesFailed: [{ name: 'D' }] })), false);
});

test('progress states all three campaign denominators', () => {
  assert.equal(progressLine(pass()), 'FwHunt: 4/4 modules; 2/2 batches complete; 0 failed.');
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
  });
});
