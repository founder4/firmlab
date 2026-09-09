/**
 * Reconcile the persistent corpus against every image already on the bench.
 *
 * A thin client over `POST /api/corpus/reindex`. It deliberately holds no logic of its own: the reconciliation
 * reads SQLite and must run where SQLite is, which for the homelab deployment is inside a container that publishes
 * no host port — so this speaks to the same origin `corpus-matrix.mjs` does and stays usable from a laptop.
 *
 * What it prints is the report verbatim, and the report is built to be read rather than skimmed: rows INSERTED
 * separately from rows OFFERED (the reindex is idempotent, so a second run legitimately inserts nothing), images
 * WITHOUT input separately from images that had input and yielded nothing, and the tables a reconciliation
 * structurally cannot rebuild named rather than omitted.
 */
import { pathToFileURL } from 'node:url';

const DEFAULT_BASE = 'http://127.0.0.1:8899';

function usage() {
  return [
    'Usage: node scripts/corpus-reindex.mjs [options]',
    '  --base URL             FirmLab UI/API origin (default http://127.0.0.1:8899, or $FIRMLAB_UI)',
    '  --lang en|es           Language for the verdict (default es)',
    '  --format text|json     Output format (default text)',
    '  --dry-run              Print what would be called and exit without writing',
  ].join('\n');
}

export function parseArgs(argv) {
  const args = { base: process.env.FIRMLAB_UI ?? DEFAULT_BASE, lang: 'es', format: 'text', dryRun: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${token} needs a value`);
      return v;
    };
    if (token === '--base') args.base = value();
    else if (token === '--lang') args.lang = value();
    else if (token === '--format') args.format = value();
    else if (token === '--dry-run') args.dryRun = true;
    else if (token === '--help' || token === '-h') args.help = true;
    else throw new Error(`Unknown option: ${token}`);
  }
  if (!['en', 'es'].includes(args.lang)) throw new Error('--lang must be en or es');
  if (!['text', 'json'].includes(args.format)) throw new Error('--format must be text or json');
  return args;
}

function mb(bytes) {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Render the report.
 *
 * Pure and exported so a test reaches it: this is where a source that never ran could be made to look like a
 * source that ran clean, and that is the one thing the reindex exists to keep apart.
 */
export function renderReport(report) {
  const lines = [`Corpus reindex — ${report.imageCount} image(s)`, ''];
  const width = Math.max(...report.sources.map((s) => s.source.length));
  lines.push(`${'source'.padEnd(width)}   inserted / offered   images with input`);
  for (const s of report.sources) {
    const inputs =
      s.imagesWithoutInput > 0 ? `${s.imagesWithInput} (${s.imagesWithoutInput} never ran)` : `${s.imagesWithInput}`;
    lines.push(
      `${s.source.padEnd(width)}   ${String(s.rowsInserted).padStart(8)} / ${String(s.rowsOffered).padEnd(7)}  ${inputs}`,
    );
  }

  if (report.boundedInputs.length > 0) {
    lines.push('', 'Reconciled from a stored input that declares it was bounded:');
    for (const b of report.boundedInputs) {
      const pct = ((b.covered / b.total) * 100).toFixed(1);
      const amount = b.kind === 'static-scan' ? `${mb(b.covered)} of ${mb(b.total)}` : `${b.covered} of ${b.total}`;
      lines.push(`  ${b.imageId}  ${b.kind.padEnd(13)} ${amount} (${pct} %)  ${b.filename}`);
    }
  }

  if (report.unrecordedBounds.length > 0) {
    lines.push('', 'Bound NOT RECORDED — the stored result predates the field that would state it:');
    for (const u of report.unrecordedBounds) lines.push(`  ${u.kind.padEnd(13)} ${u.imageCount} image(s)`);
  }

  if (report.unstampedCredentials.length > 0) {
    lines.push('', 'Ledger rows from a credential-stamping provider that predate the stamping:');
    for (const u of report.unstampedCredentials) {
      lines.push(`  ${u.imageId}  ${String(u.rows).padStart(4)} row(s)  ${u.filename}`);
    }
  }

  lines.push('', 'Not reconciled (a reindex cannot rebuild these):');
  for (const t of report.notReconciled) lines.push(`  ${t.table} — ${t.reason}`);

  lines.push('', report.verdict);
  return `${lines.join('\n')}\n`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const base = args.base.replace(/\/$/, '');
  const url = `${base}/api/corpus/reindex?lang=${args.lang}`;
  if (args.dryRun) {
    process.stdout.write(`POST ${url}\n`);
    return;
  }
  const headers = { 'content-type': 'application/json' };
  if (process.env.FIRMLAB_UI_AUTH) {
    headers.authorization = `Basic ${Buffer.from(process.env.FIRMLAB_UI_AUTH).toString('base64')}`;
  }
  const response = await fetch(url, { method: 'POST', headers, body: '{}' });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText} from ${url}`);
  const { report } = await response.json();
  process.stdout.write(args.format === 'json' ? `${JSON.stringify(report, null, 2)}\n` : renderReport(report));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`corpus-reindex: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
