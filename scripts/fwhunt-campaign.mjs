/**
 * Resume a durable FwHunt campaign one server-owned batch at a time.
 *
 * Each batch is its own persisted job, so an API or client restart loses at most the active window. Re-running
 * this command asks the server for the newest cumulative snapshot and continues at the first incomplete window.
 */
import { pathToFileURL } from 'node:url';

const DEFAULT_BASE = 'http://127.0.0.1:8899';
const DEFAULT_POLL_MS = 5_000;
const DEFAULT_JOB_TIMEOUT_MS = 30 * 60 * 1_000;
const DEFAULT_MAX_RETRIES = 3;

export function campaignComplete(pass) {
  if (!pass?.ran || !Number.isSafeInteger(pass.batchCount) || pass.batchCount <= 0) return false;
  const settled = new Set(
    Array.isArray(pass.batches)
      ? pass.batches.filter((batch) => batch.complete || batch.finalizedWithFailures).map((batch) => batch.index)
      : [],
  );
  const failed = Array.isArray(pass.modulesFailed) ? pass.modulesFailed.length : Number.POSITIVE_INFINITY;
  const scanned = Array.isArray(pass.modulesScanned) ? pass.modulesScanned.length : 0;
  return settled.size === pass.batchCount && scanned + failed === pass.modulesCarved;
}

export function progressLine(pass) {
  if (!pass) return 'FwHunt has no module-pass result yet.';
  const scanned = Array.isArray(pass.modulesScanned) ? pass.modulesScanned.length : 0;
  const failed = Array.isArray(pass.modulesFailed) ? pass.modulesFailed.length : 0;
  const settled = Array.isArray(pass.batches)
    ? pass.batches.filter((batch) => batch.complete || batch.finalizedWithFailures).length
    : 0;
  return `FwHunt: ${scanned}/${pass.modulesCarved} modules scanned; ${settled}/${pass.batchCount} batches settled; ${failed} failed.`;
}

export function parseArgs(argv, env = process.env) {
  const args = {
    base: env.FIRMLAB_UI ?? DEFAULT_BASE,
    image: '',
    restart: false,
    pollMs: DEFAULT_POLL_MS,
    jobTimeoutMs: DEFAULT_JOB_TIMEOUT_MS,
    maxRetries: DEFAULT_MAX_RETRIES,
    failFast: false,
  };
  const take = (flag, index) => {
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${flag} requires a value`);
    return value;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--base') args.base = take(token, i++);
    else if (token === '--image') args.image = take(token, i++);
    else if (token === '--restart') args.restart = true;
    else if (token === '--poll-ms') args.pollMs = Number(take(token, i++));
    else if (token === '--job-timeout-ms') args.jobTimeoutMs = Number(take(token, i++));
    else if (token === '--max-retries') args.maxRetries = Number(take(token, i++));
    else if (token === '--fail-fast') args.failFast = true;
    else if (token === '--help') args.help = true;
    else throw new Error(`Unknown argument ${token}`);
  }
  if (!args.help && !args.image) throw new Error('--image is required');
  for (const [name, value] of [
    ['--poll-ms', args.pollMs],
    ['--job-timeout-ms', args.jobTimeoutMs],
    ['--max-retries', args.maxRetries],
  ]) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  }
  args.base = args.base.replace(/\/$/, '');
  return args;
}

function usage() {
  return [
    'Usage: node scripts/fwhunt-campaign.mjs --image ID [options]',
    '  --base URL             FirmLab origin (default FIRMLAB_UI or http://127.0.0.1:8899)',
    '  --restart              Discard the durable cursor and begin at batch 1',
    '  --poll-ms N            Job polling interval (default 5000)',
    '  --job-timeout-ms N     Maximum wait for one persisted batch (default 1800000)',
    '  --max-retries N        Finalize a fully attempted failed batch after N attempts (default 3)',
    '  --fail-fast            Stop instead of finalizing failures as explicit unknowns',
  ].join('\n');
}

function requestHeaders(env, json = false) {
  const headers = {};
  if (json) headers['content-type'] = 'application/json';
  if (env.FIRMLAB_UI_AUTH) {
    headers.authorization = `Basic ${Buffer.from(env.FIRMLAB_UI_AUTH).toString('base64')}`;
  }
  return headers;
}

async function fetchJson(url, init = {}) {
  const response = await fetch(url, init);
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`${response.status} ${response.statusText} from ${url}: non-JSON response`);
  }
  if (!response.ok) {
    const detail = body?.error ? `: ${body.error}` : '';
    throw new Error(`${response.status} ${response.statusText} from ${url}${detail}`);
  }
  return body;
}

async function waitForJob(base, jobId, args, env) {
  const deadline = Date.now() + args.jobTimeoutMs;
  while (Date.now() < deadline) {
    const { job } = await fetchJson(`${base}/api/jobs/${encodeURIComponent(jobId)}`, {
      headers: requestHeaders(env),
    });
    if (job.status === 'done') return job.result;
    if (job.status === 'error') throw new Error(`FwHunt job ${jobId} failed: ${job.error ?? 'unknown error'}`);
    await new Promise((resolve) => setTimeout(resolve, args.pollMs));
  }
  throw new Error(`FwHunt job ${jobId} did not finish within ${args.jobTimeoutMs} ms`);
}

export async function runCampaign(args, env = process.env) {
  const endpoint = `${args.base}/api/images/${encodeURIComponent(args.image)}/fwhunt`;
  let { result } = await fetchJson(endpoint, { headers: requestHeaders(env) });
  if (!args.restart && campaignComplete(result?.modulePass)) {
    process.stdout.write(`${progressLine(result.modulePass)} Campaign already complete.\n`);
    return result;
  }

  let restart = args.restart;
  let retryBatch = null;
  let retryCount = 0;
  for (;;) {
    const { jobId } = await fetchJson(endpoint, {
      method: 'POST',
      headers: requestHeaders(env, true),
      body: JSON.stringify(restart ? { restart: true } : {}),
    });
    restart = false;
    result = await waitForJob(args.base, jobId, args, env);
    const pass = result?.modulePass;
    process.stdout.write(`${progressLine(pass)}\n`);
    if (campaignComplete(pass)) return result;
    if (!pass?.ran) throw new Error(result?.reason ?? pass?.reason ?? 'FwHunt module pass did not run');

    if (pass.batchIndex === retryBatch) retryCount += 1;
    else {
      retryBatch = pass.batchIndex;
      retryCount = 1;
    }
    const currentBatch = pass.batches?.find((batch) => batch.index === pass.batchIndex);
    if (currentBatch?.complete) {
      retryBatch = null;
      retryCount = 0;
    } else if (retryCount >= args.maxRetries) {
      if (args.failFast) {
        throw new Error(
          `FwHunt batch ${pass.batchIndex + 1}/${pass.batchCount} remained incomplete after ${retryCount} attempts`,
        );
      }
      const currentBatchSize = currentBatch.rangeEnd - currentBatch.rangeStart;
      const attempted = (currentBatch.modulesScanned?.length ?? 0) + (currentBatch.modulesFailed?.length ?? 0);
      if (attempted !== currentBatchSize || !(currentBatch.modulesFailed?.length > 0)) {
        throw new Error(
          `FwHunt batch ${pass.batchIndex + 1}/${pass.batchCount} remained incomplete without a fully attributable failed window`,
        );
      }
      const { jobId } = await fetchJson(endpoint, {
        method: 'POST',
        headers: requestHeaders(env, true),
        body: JSON.stringify({ finalizeFailedBatch: true }),
      });
      result = await waitForJob(args.base, jobId, args, env);
      process.stdout.write(`${progressLine(result?.modulePass)} Finalized unresolved modules as unknown.\n`);
      retryBatch = null;
      retryCount = 0;
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  await runCampaign(args);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`fwhunt-campaign: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
