/** Refresh only the three redaction-safe credential sources, then leave corpus reindexing as an explicit step. */
import { pathToFileURL } from 'node:url';

const DEFAULT_BASE = 'http://127.0.0.1:8899';
const SOURCES = ['fsaudit', 'nvram', 'auxsecrets'];

export function parseArgs(argv, env = process.env) {
  const args = {
    base: env.FIRMLAB_UI ?? DEFAULT_BASE,
    pollMs: 1_000,
    jobTimeoutMs: 10 * 60 * 1_000,
    concurrency: 2,
    dryRun: false,
    help: false,
  };
  const take = (flag, index) => {
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${flag} requires a value`);
    return value;
  };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === '--base') args.base = take(token, i++);
    else if (token === '--poll-ms') args.pollMs = Number(take(token, i++));
    else if (token === '--job-timeout-ms') args.jobTimeoutMs = Number(take(token, i++));
    else if (token === '--concurrency') args.concurrency = Number(take(token, i++));
    else if (token === '--dry-run') args.dryRun = true;
    else if (token === '--help' || token === '-h') args.help = true;
    else throw new Error(`Unknown argument ${token}`);
  }
  for (const [flag, value] of [
    ['--poll-ms', args.pollMs],
    ['--job-timeout-ms', args.jobTimeoutMs],
    ['--concurrency', args.concurrency],
  ]) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${flag} must be a positive integer`);
  }
  args.base = args.base.replace(/\/$/, '');
  return args;
}

function usage() {
  return [
    'Usage: node scripts/credential-corpus-refresh.mjs [options]',
    '  --base URL             FirmLab origin (default FIRMLAB_UI or http://127.0.0.1:8899)',
    '  --poll-ms N            Job polling interval (default 1000)',
    '  --job-timeout-ms N     Maximum wait for one provider job (default 600000)',
    '  --concurrency N        Images refreshed concurrently (default 2)',
    '  --dry-run              List the image/source plan without starting jobs',
  ].join('\n');
}

function headers(env, json = false) {
  const result = {};
  if (json) result['content-type'] = 'application/json';
  if (env.FIRMLAB_UI_AUTH) {
    result.authorization = `Basic ${Buffer.from(env.FIRMLAB_UI_AUTH).toString('base64')}`;
  }
  return result;
}

async function responseJson(url, init, fetchImpl) {
  const response = await fetchImpl(url, init);
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`${response.status} ${response.statusText} from ${url}: non-JSON response`);
  }
  return { response, body };
}

async function waitForJob(base, jobId, args, env, fetchImpl) {
  const deadline = Date.now() + args.jobTimeoutMs;
  while (Date.now() < deadline) {
    const url = `${base}/api/jobs/${encodeURIComponent(jobId)}`;
    const { response, body } = await responseJson(url, { headers: headers(env) }, fetchImpl);
    if (!response.ok) throw new Error(`${response.status} ${response.statusText} from ${url}`);
    if (body?.job?.status === 'done') return body.job.result;
    if (body?.job?.status === 'error') {
      throw new Error(`${jobId} failed: ${body.job.error ?? 'unknown provider error'}`);
    }
    await new Promise((resolve) => setTimeout(resolve, args.pollMs));
  }
  throw new Error(`${jobId} did not finish within ${args.jobTimeoutMs} ms`);
}

async function refreshSource(image, source, args, env, fetchImpl) {
  const endpoint = `${args.base}/api/images/${encodeURIComponent(image.id)}/${source}`;
  const { response, body } = await responseJson(
    endpoint,
    { method: 'POST', headers: headers(env, true), body: '{}' },
    fetchImpl,
  );
  if (!response.ok) {
    if ([400, 409, 422].includes(response.status)) {
      return { imageId: image.id, filename: image.filename, source, status: 'no-input', reason: body?.error ?? '' };
    }
    throw new Error(`${response.status} ${response.statusText} from ${endpoint}: ${body?.error ?? 'request failed'}`);
  }
  if (typeof body?.jobId !== 'string') throw new Error(`${endpoint} returned no jobId`);
  const result = await waitForJob(args.base, body.jobId, args, env, fetchImpl);
  const findings = Array.isArray(result?.findings) ? result.findings.length : 0;
  return {
    imageId: image.id,
    filename: image.filename,
    source,
    status: result?.available === false ? 'no-input' : 'done',
    findings,
    reason: typeof result?.reason === 'string' ? result.reason : '',
  };
}

async function mapLimit(items, concurrency, work) {
  const results = new Array(items.length);
  let cursor = 0;
  const worker = async () => {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await work(items[index]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

export function summarizeRefresh(images, results) {
  const flat = results.flat();
  return {
    imageCount: images.length,
    stagesPlanned: images.length * SOURCES.length,
    stagesDone: flat.filter((row) => row.status === 'done').length,
    stagesWithoutInput: flat.filter((row) => row.status === 'no-input').length,
    findings: flat.reduce((sum, row) => sum + (row.findings ?? 0), 0),
    results: flat,
  };
}

export async function runCredentialRefresh(args, env = process.env, fetchImpl = fetch) {
  const url = `${args.base}/api/images`;
  const { response, body } = await responseJson(url, { headers: headers(env) }, fetchImpl);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText} from ${url}`);
  const images = Array.isArray(body?.images) ? body.images : [];
  if (args.dryRun)
    return summarizeRefresh(
      images,
      images.map(() => []),
    );
  const rows = await mapLimit(images, args.concurrency, async (image) => {
    const imageRows = [];
    for (const source of SOURCES) {
      const row = await refreshSource(image, source, args, env, fetchImpl);
      imageRows.push(row);
      process.stdout.write(
        `${image.id} ${source}: ${row.status}${row.findings === undefined ? '' : ` (${row.findings} finding(s))`}\n`,
      );
    }
    return imageRows;
  });
  return summarizeRefresh(images, rows);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(`${usage()}\n`);
  } else {
    runCredentialRefresh(args)
      .then((report) => {
        if (args.dryRun) {
          process.stdout.write(
            `Dry run: ${report.imageCount} image(s), ${report.stagesPlanned} provider job(s) would be started.\n`,
          );
        } else {
          process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
        }
      })
      .catch((error) => {
        process.stderr.write(`credential-corpus-refresh: ${error instanceof Error ? error.message : String(error)}\n`);
        process.exitCode = 1;
      });
  }
}
