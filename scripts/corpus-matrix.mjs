/**
 * Live corpus validation matrix.
 *
 * The workbench already knows which stages apply to every firmware class and what the latest autonomous run did
 * with each one. This script reads that contract instead of maintaining a second provider map in a spreadsheet.
 * It can print Markdown for a review artifact, emit JSON for automation, and turn minimum class coverage or an
 * unwanted stage status into a non-zero exit code.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export const STATUS_META = {
  found: { symbol: '✓', label: 'ejecutada con hallazgos' },
  'ran-empty': { symbol: '○', label: 'ejecutada sin hallazgos para esta etapa' },
  degraded: { symbol: '△', label: 'ejecutada con cobertura reducida' },
  'no-input': { symbol: '⊘', label: 'aplicable, pero sin la entrada requerida' },
  'not-built': { symbol: '◇', label: 'aplicable, pero el proveedor no está construido' },
  'not-run': { symbol: '·', label: 'aplicable y no ejecutada' },
};

const STATUS_ORDER = Object.keys(STATUS_META);

/** Compare immutable image bytes + stage identity, never transient IDs, labels or row order. */
export function compareMatrices(current, baseline) {
  const index = (matrix, name) => {
    if (matrix?.schemaVersion !== 1 || !Array.isArray(matrix.samples)) {
      throw new Error(`${name}: expected corpus matrix schemaVersion 1 with samples`);
    }
    const samples = new Map();
    for (const sample of matrix.samples) {
      if (typeof sample.sha256 !== 'string' || !/^[a-f\d]{64}$/i.test(sample.sha256)) {
        throw new Error(`${name}: sample has missing or invalid SHA-256`);
      }
      const sha256 = sample.sha256.toLowerCase();
      if (samples.has(sha256)) throw new Error(`${name}: duplicate sample SHA-256 ${sha256}`);
      if (!Array.isArray(sample.coverage?.stages)) throw new Error(`${name}: missing stages for ${sha256}`);
      const stages = new Map();
      for (const stage of sample.coverage.stages) {
        if (typeof stage.worker !== 'string' || !stage.worker.trim() || !STATUS_ORDER.includes(stage.status)) {
          throw new Error(`${name}: invalid stage identity or status for ${sha256}`);
        }
        if (stages.has(stage.worker)) throw new Error(`${name}: duplicate stage ${stage.worker} for ${sha256}`);
        stages.set(stage.worker, stage);
      }
      samples.set(sha256, { filename: sample.filename, stages });
    }
    return samples;
  };
  const before = index(baseline, 'baseline');
  const after = index(current, 'current');
  const result = {
    comparedCells: 0,
    addedSamples: [],
    removedSamples: [],
    addedStages: [],
    removedStages: [],
    statusChanges: [],
    findingCountChanges: [],
    regressions: [],
  };
  for (const sha256 of [...new Set([...before.keys(), ...after.keys()])].sort()) {
    const oldSample = before.get(sha256);
    const newSample = after.get(sha256);
    if (!oldSample) {
      result.addedSamples.push({ sha256, filename: newSample.filename });
      continue;
    }
    if (!newSample) {
      result.removedSamples.push({ sha256, filename: oldSample.filename });
      continue;
    }
    for (const worker of [...new Set([...oldSample.stages.keys(), ...newSample.stages.keys()])].sort()) {
      const previous = oldSample.stages.get(worker);
      const next = newSample.stages.get(worker);
      const cell = { sha256, filename: newSample.filename, worker };
      if (!previous) {
        result.addedStages.push(cell);
        continue;
      }
      if (!next) {
        result.removedStages.push(cell);
        continue;
      }
      result.comparedCells++;
      if (previous.status !== next.status) {
        const change = { ...cell, before: previous.status, after: next.status };
        result.statusChanges.push(change);
        if (
          ['found', 'ran-empty'].includes(previous.status) &&
          ['degraded', 'no-input', 'not-run', 'not-built'].includes(next.status)
        ) {
          result.regressions.push(change);
        }
      }
      const oldCount =
        Number.isSafeInteger(previous.findingCount) && previous.findingCount >= 0 ? previous.findingCount : null;
      const newCount = Number.isSafeInteger(next.findingCount) && next.findingCount >= 0 ? next.findingCount : null;
      if (oldCount !== newCount) {
        result.findingCountChanges.push({ ...cell, before: oldCount, after: newCount });
      }
    }
  }
  return result;
}

export function evaluateRegressions(comparison) {
  return comparison.regressions.map(
    (change) => `regression ${change.sha256}/${change.worker}: ${change.before} -> ${change.after}`,
  );
}

function renderComparison(comparison) {
  const lines = [
    '',
    '## Comparación con baseline',
    '',
    `${comparison.comparedCells} celdas comparables · ${comparison.regressions.length} regresiones de ejecución.`,
    '',
    'Los cambios de recuento requieren revisión: más o menos hallazgos no implica mejora. Un recuento ausente es desconocido.',
    'Las muestras y etapas añadidas o retiradas se informan por separado; no se consideran regresiones de ejecución.',
  ];
  for (const [key, title] of [
    ['regressions', 'Regresiones de ejecución'],
    ['statusChanges', 'Cambios de estado'],
    ['findingCountChanges', 'Cambios de recuento'],
    ['addedSamples', 'Muestras añadidas'],
    ['removedSamples', 'Muestras retiradas'],
    ['addedStages', 'Etapas añadidas'],
    ['removedStages', 'Etapas retiradas'],
  ]) {
    lines.push('', `### ${title} (${comparison[key].length})`, '');
    for (const change of comparison[key]) {
      const transition =
        'before' in change ? `: ${change.before ?? 'desconocido'} → ${change.after ?? 'desconocido'}` : '';
      lines.push(
        `- ${escapeCell(change.filename)} (${change.sha256})${change.worker ? ` / ${escapeCell(change.worker)}` : ''}${transition}`,
      );
    }
  }
  return lines;
}

function escapeCell(value) {
  return String(value ?? '')
    .replaceAll('|', '\\|')
    .replaceAll('\n', ' ')
    .trim();
}

function compactName(filename) {
  const stem = filename
    .replace(/\.[^.]+$/, '')
    .replace(/[^a-zA-Z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
  return (stem || 'sample').slice(0, 20);
}

/** Assign compact, deterministic and collision-free labels for matrix columns. */
export function labelImages(images) {
  const used = new Set();
  return images.map((image) => {
    const base = compactName(image.filename);
    let label = base;
    if (used.has(label)) label = `${base.slice(0, 11)}-${image.id}`;
    used.add(label);
    return { ...image, label };
  });
}

/** Merge API responses and derive the status/class totals every renderer and gate reads. */
export function buildMatrix(images, coverageById) {
  const labelled = labelImages(images).map((image) => {
    const coverage = coverageById.get(image.id);
    if (!coverage) throw new Error(`Coverage response missing for image ${image.id}`);
    return { ...image, coverage };
  });
  const classes = new Map();
  const statusCounts = Object.fromEntries(STATUS_ORDER.map((status) => [status, 0]));

  for (const sample of labelled) {
    const firmwareClass = sample.identity?.firmwareClass ?? sample.coverage.firmwareClass ?? 'unknown';
    const group = classes.get(firmwareClass) ?? [];
    group.push(sample);
    classes.set(firmwareClass, group);
    for (const stage of sample.coverage.stages) {
      statusCounts[stage.status] = (statusCounts[stage.status] ?? 0) + 1;
    }
  }

  return {
    schemaVersion: 1,
    sampleCount: labelled.length,
    classCount: classes.size,
    stageCellCount: Object.values(statusCounts).reduce((sum, count) => sum + count, 0),
    statusCounts,
    samples: labelled,
    classes: [...classes.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([firmwareClass, samples]) => ({
        firmwareClass,
        samples: samples.sort((a, b) => a.filename.localeCompare(b.filename)),
      })),
  };
}

function stageCell(stage) {
  if (!stage) return '—';
  const symbol = STATUS_META[stage.status]?.symbol ?? '?';
  return stage.status === 'found' && stage.findingCount > 0 ? `${symbol}${stage.findingCount}` : symbol;
}

/** Stable Markdown: stage rows, sample columns, grouped by the firmware class that defines applicability. */
export function renderMarkdown(matrix, generatedAt = new Date().toISOString()) {
  const lines = [
    '# FirmLab — matriz de validación del corpus',
    '',
    `Generada: ${generatedAt}`,
    '',
    `${matrix.sampleCount} muestras · ${matrix.classCount} clases · ${matrix.stageCellCount} celdas de etapa aplicable.`,
    '',
    '## Leyenda',
    '',
    '| Marca | Estado | Significado |',
    '|---:|---|---|',
  ];
  for (const status of STATUS_ORDER) {
    const meta = STATUS_META[status];
    lines.push(`| ${meta.symbol} | \`${status}\` | ${meta.label} |`);
  }
  lines.push('', 'Un número tras `✓` es el recuento de hallazgos registrado por esa etapa.', '', '## Resumen', '');
  lines.push('| Estado | Celdas |', '|---|---:|');
  for (const status of STATUS_ORDER) {
    lines.push(`| \`${status}\` | ${matrix.statusCounts[status] ?? 0} |`);
  }

  for (const group of matrix.classes) {
    const workerNames = [];
    const seenWorkers = new Set();
    for (const sample of group.samples) {
      for (const stage of sample.coverage.stages) {
        if (seenWorkers.has(stage.worker)) continue;
        seenWorkers.add(stage.worker);
        workerNames.push(stage.worker);
      }
    }

    lines.push('', `## ${group.firmwareClass}`, '');
    lines.push(`Muestras: ${group.samples.map((sample) => `\`${sample.label}\``).join(', ')}.`, '');
    lines.push(`| Etapa | ${group.samples.map((sample) => escapeCell(sample.label)).join(' | ')} |`);
    lines.push(`|---|${group.samples.map(() => '---:').join('|')}|`);
    for (const worker of workerNames) {
      const cells = group.samples.map((sample) =>
        stageCell(sample.coverage.stages.find((stage) => stage.worker === worker)),
      );
      lines.push(`| ${escapeCell(worker)} | ${cells.join(' | ')} |`);
    }
    lines.push('', '| Etiqueta | ID | Arquitectura | Fichero | Cobertura |', '|---|---|---|---|---:|');
    for (const sample of group.samples) {
      lines.push(
        `| \`${sample.label}\` | \`${sample.id}\` | ${escapeCell(sample.identity?.arch ?? 'unknown')} | ${escapeCell(sample.filename)} | ${sample.coverage.executed}/${sample.coverage.applicable} |`,
      );
    }
  }
  if (matrix.comparison) lines.push(...renderComparison(matrix.comparison));
  lines.push('');
  return `${lines.join('\n')}\n`;
}

/** The gate is pure so CI can test policy without a running workbench. */
export function evaluateRequirements(matrix, requiredClasses = [], forbiddenStatuses = []) {
  const failures = [];
  const classCounts = new Map(matrix.classes.map((group) => [group.firmwareClass, group.samples.length]));
  for (const { firmwareClass, minimum } of requiredClasses) {
    const actual = classCounts.get(firmwareClass) ?? 0;
    if (actual < minimum) failures.push(`class ${firmwareClass}: required >= ${minimum}, found ${actual}`);
  }
  for (const status of forbiddenStatuses) {
    const count = matrix.statusCounts[status] ?? 0;
    if (count > 0) failures.push(`status ${status}: found ${count} forbidden stage cell(s)`);
  }
  return failures;
}

/** Validate that every locked artifact is present byte-for-byte and, when declared, classified as expected. */
export function evaluateManifest(matrix, manifest) {
  const failures = [];
  const bySha = new Map(matrix.samples.map((sample) => [sample.sha256, sample]));
  for (const locked of manifest.samples ?? []) {
    const sample = bySha.get(locked.sha256);
    if (!sample) {
      failures.push(`locked sample missing: ${locked.filename} (${locked.sha256})`);
      continue;
    }
    if (sample.size !== locked.size) {
      failures.push(`locked sample ${locked.filename}: expected ${locked.size} bytes, found ${sample.size}`);
    }
    const expectedClass = locked.expected?.firmwareClass;
    const actualClass = sample.identity?.firmwareClass ?? 'unknown';
    if (expectedClass && actualClass !== expectedClass) {
      failures.push(`locked sample ${locked.filename}: expected class ${expectedClass}, detected ${actualClass}`);
    }
    const expectedArch = locked.expected?.arch;
    const actualArch = sample.identity?.arch ?? 'unknown';
    if (expectedArch && actualArch !== expectedArch) {
      failures.push(`locked sample ${locked.filename}: expected arch ${expectedArch}, detected ${actualArch}`);
    }
  }
  return failures;
}

export function parseArgs(argv) {
  const args = {
    base: process.env.FIRMLAB_UI ?? 'http://127.0.0.1:8899',
    format: 'markdown',
    out: null,
    requiredClasses: [],
    forbiddenStatuses: [],
    manifest: null,
    baseline: null,
    failOnRegression: false,
  };
  const value = (flag, index) => {
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) throw new Error(`${flag} requires a value`);
    return next;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--base') args.base = value(token, i++);
    else if (token === '--format') args.format = value(token, i++);
    else if (token === '--out') args.out = value(token, i++);
    else if (token === '--manifest') args.manifest = value(token, i++);
    else if (token === '--baseline') args.baseline = value(token, i++);
    else if (token === '--fail-on-regression') args.failOnRegression = true;
    else if (token === '--require-class') {
      const requirement = value(token, i++);
      const match = /^([^=]+)=(\d+)$/.exec(requirement);
      if (!match) throw new Error(`Invalid --require-class ${requirement}; expected CLASS=MINIMUM`);
      args.requiredClasses.push({ firmwareClass: match[1], minimum: Number(match[2]) });
    } else if (token === '--forbid-status') {
      const status = value(token, i++);
      if (!STATUS_META[status]) throw new Error(`Unknown stage status ${status}`);
      args.forbiddenStatuses.push(status);
    } else if (token === '--help') {
      args.help = true;
    } else {
      throw new Error(`Unknown argument ${token}`);
    }
  }
  if (!['markdown', 'json'].includes(args.format)) throw new Error('--format must be markdown or json');
  if (args.failOnRegression && !args.baseline) throw new Error('--fail-on-regression requires --baseline');
  return args;
}

function usage() {
  return [
    'Usage: node scripts/corpus-matrix.mjs [options]',
    '  --base URL                  FirmLab UI/API origin (default http://127.0.0.1:8899)',
    '  --format markdown|json      Output format',
    '  --out FILE                  Write output to a file instead of stdout',
    '  --manifest FILE             Require every SHA-256 locked in this manifest',
    '  --baseline FILE             Compare with an earlier --format json matrix',
    '  --fail-on-regression        Fail on executed -> degraded/unavailable transitions (requires --baseline)',
    '  --require-class CLASS=N     Fail unless at least N samples of this class exist (repeatable)',
    '  --forbid-status STATUS      Fail if any applicable stage has this status (repeatable)',
  ].join('\n');
}

async function fetchJson(url, headers) {
  const response = await fetch(url, { headers });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText} from ${url}`);
  return response.json();
}

/** Basic-auth headers when the deployment is behind one, undefined otherwise — shared with the campaign planner. */
export function apiHeaders(env = process.env) {
  return env.FIRMLAB_UI_AUTH
    ? { authorization: `Basic ${Buffer.from(env.FIRMLAB_UI_AUTH).toString('base64')}` }
    : undefined;
}

/**
 * Read the live matrix from a running workbench. Exported so the coverage campaign plans against exactly the same
 * cells this command prints — a second reader with its own idea of what a stage is would be a second contract.
 */
export async function fetchMatrix(base, headers, lang = 'es') {
  const origin = base.replace(/\/$/, '');
  const { images } = await fetchJson(`${origin}/api/images`, headers);
  const coverageEntries = await Promise.all(
    images.map(async (image) => {
      const coverage = await fetchJson(
        `${origin}/api/images/${encodeURIComponent(image.id)}/coverage?lang=${encodeURIComponent(lang)}`,
        headers,
      );
      return [image.id, coverage];
    }),
  );
  return buildMatrix(images, new Map(coverageEntries));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const baseline = args.baseline ? JSON.parse(await readFile(args.baseline, 'utf8')) : null;
  if (args.baseline) compareMatrices(baseline, baseline);
  const base = args.base.replace(/\/$/, '');
  const matrix = await fetchMatrix(base, apiHeaders());
  if (args.baseline) matrix.comparison = compareMatrices(matrix, baseline);
  const output =
    args.format === 'json'
      ? `${JSON.stringify({ generatedAt: new Date().toISOString(), ...matrix }, null, 2)}\n`
      : renderMarkdown(matrix);
  if (args.out) await writeFile(args.out, output, 'utf8');
  else process.stdout.write(output);

  const manifest = args.manifest ? JSON.parse(await readFile(args.manifest, 'utf8')) : null;
  const failures = [
    ...evaluateRequirements(matrix, args.requiredClasses, args.forbiddenStatuses),
    ...(manifest ? evaluateManifest(matrix, manifest) : []),
    ...(args.failOnRegression ? evaluateRegressions(matrix.comparison) : []),
  ];
  if (failures.length > 0) {
    process.stderr.write(`Corpus validation failed:\n- ${failures.join('\n- ')}\n`);
    process.exitCode = 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`corpus-matrix: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
