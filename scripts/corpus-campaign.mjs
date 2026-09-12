/**
 * Coverage campaign over the VALIDATION corpus — which of its uncovered cells are worth scheduling, and which are
 * not debt at all. (Three unrelated things are called "corpus" here; see docs/ARCHITECTURE.md.)
 *
 * `corpus-matrix.mjs` measures the corpus; it does not prioritise it. Measured on the deployed workbench the
 * difference matters more than the total: of 411 applicable stage cells, 85 are `degraded`, and they are five
 * unrelated kinds of thing — an image that carries no device tree and was read everywhere one could be, a tool
 * this deployment lacks, a cap that truncated a walk that CAN finish, a harness that broke, and a symbolic search
 * that is inconclusive by construction. Re-running all 85 spends most of the budget re-answering answered
 * questions, and a campaign that reports "85 cells of debt" is reporting a number nobody can act on.
 *
 * So this reads what each degraded cell DECLARES about itself (`remedy`, from `apps/api/src/opacidad-remedy.ts`)
 * and never the English note beside it, partitions the corpus into work that a scan can do, work a deployment
 * change must precede, and cells no re-run can change, then orders the schedulable part by class and by measured
 * cost — the wall time that image's last autonomous scan actually took, not a guess.
 *
 * Three rules it holds to, all of them the same rule this codebase keeps paying for:
 *
 *  1. **An undeclared remedy is unknown, never settled.** Every result persisted before the field exists declares
 *     nothing. Such a cell is queued exactly once — a re-run is what MEASURES it — and a cell still undeclared
 *     after a run whose other cells do declare is reported as a site that cannot tell, which is a code question
 *     and not campaign debt.
 *  2. **A `no-input` cell is attributed, not counted.** All 33 of them sit downstream of extraction, and whether
 *     they are executable is entirely a fact about that image's extraction cell: three artifacts in this corpus
 *     yield no rootfs at all, and queueing their eleven stages apiece would manufacture 33 cells of debt that no
 *     scan on earth can retire.
 *  3. **The plan states its denominators.** Every bucket carries its cell count, its samples and the rule that put
 *     it there, because a campaign plan is read as "what is left", and a bucket without its rule is a number.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { apiHeaders, fetchMatrix } from './corpus-matrix.mjs';

/**
 * The remedy vocabulary, mirrored from `apps/api/src/opacidad-remedy.ts`. Mirrored rather than imported because
 * this script talks to a DEPLOYED workbench over HTTP and must read whatever build is running there — including
 * one older or newer than this checkout. An unrecognised value is therefore not an error: it is reported as
 * unrecognised, and never silently folded into a bucket it might not belong in.
 */
export const REMEDY_META = {
  retry: { disposition: 'scan', label: 'the run broke; the same question may settle it' },
  // NOT the scan queue, and the first live campaign is what showed why: every `raise-bound` cell in the corpus —
  // the W9 dynamic-step cap, a capped device-tree walk, FwHunt modules left unattempted — comes back identical
  // from a re-run with the same bound. Queueing it would put an image in the queue for ever and report the loop
  // as progress. It needs the bound raised (or, for FwHunt, its dedicated resumable campaign) first.
  'raise-bound': { disposition: 'raise', label: 'a cap truncated a search that can finish; raise it, then re-run' },
  'install-tool': { disposition: 'deploy', label: 'this deployment lacks the tool or rule corpus' },
  'reacquire-input': { disposition: 'reacquire', label: 'the input is not in these bytes' },
  settled: { disposition: 'settled', label: 'looked everywhere it can; this is the answer for this image' },
  'unbounded-search': { disposition: 'open-ended', label: 'inconclusive by construction; no budget completes it' },
  defect: { disposition: 'defect', label: "FirmLab's own defect, not the image's" },
};

/**
 * Dispositions a plain re-run can retire, and only those. Everything else is reported and never queued: a queue
 * whose entries survive their own execution is a loop with a progress bar.
 */
export const SCHEDULABLE = new Set(['scan', 'declare']);

const COVERED = new Set(['found', 'ran-empty']);

/**
 * One cell's disposition. `context` carries the two facts a cell cannot know about itself: whether its sample's
 * run declared remedies at all (so an undeclared cell can be told from a stale one), and what the sample's
 * extraction cell said (so a `no-input` cell is attributed to the thing that actually blocked it).
 */
export function classifyCell(stage, context = {}) {
  const { runDeclaresRemedies = false, extraction = null } = context;
  if (COVERED.has(stage.status)) return { disposition: 'covered', rule: 'the stage ran' };
  if (stage.status === 'not-run') {
    return { disposition: 'scan', rule: 'applicable and never executed' };
  }
  if (stage.status === 'not-built') {
    return { disposition: 'build', rule: 'the class routes here and the worker does not exist yet' };
  }
  if (stage.status === 'no-input') {
    // Downstream of extraction by construction: the stage was skipped for want of a rootfs. Its remedy is not its
    // own, it is whatever the extraction cell declared, and inheriting it is the only way this cell can be honest.
    if (!extraction) return { disposition: 'unknown', rule: 'no extraction cell to attribute this skip to' };
    if (SCHEDULABLE.has(extraction.disposition) || extraction.disposition === 'deploy') {
      return {
        disposition: 'blocked-upstream',
        rule: `blocked behind extraction, which is schedulable (${extraction.disposition})`,
        unlockedBy: extraction.disposition,
      };
    }
    return {
      disposition: 'blocked-upstream',
      rule: `blocked behind extraction, which no scan can change (${extraction.disposition})`,
      unlockedBy: null,
    };
  }
  if (stage.status !== 'degraded') {
    return { disposition: 'unknown', rule: `unrecognised stage status ${stage.status}` };
  }
  if (!stage.remedy) {
    return runDeclaresRemedies
      ? {
          disposition: 'undeclared',
          rule: 'this run declared remedies elsewhere, so the site itself cannot tell — a code question',
        }
      : { disposition: 'declare', rule: 'recorded by a build that declared no remedy; re-run to measure it' };
  }
  const meta = REMEDY_META[stage.remedy];
  if (!meta) return { disposition: 'unknown', rule: `unrecognised remedy ${stage.remedy}` };
  return { disposition: meta.disposition, rule: meta.label, remedy: stage.remedy };
}

/**
 * Per-sample pass: classify every cell, attributing the skips to the extraction cell of that same sample.
 *
 * Whether the run declares remedies is READ from the coverage report (`declaresRemedies`, stamped on the stored
 * result) and only inferred from the cells when a deployment too old to report it is being planned against. The
 * inference is not equivalent, and the first live run measured the gap: the FwHunt cell is recomposed from its own
 * durable campaign, so two UEFI images stored long before remedies existed showed exactly one declared cell each,
 * and the inference then read their stale device-tree cells as sites that cannot tell — dropping both images out
 * of the queue.
 */
export function classifySample(sample) {
  const stages = sample.coverage?.stages ?? [];
  const runDeclaresRemedies =
    sample.coverage?.declaresRemedies ?? stages.some((stage) => stage.status === 'degraded' && stage.remedy);
  // `provider` is a stable tag; the worker name is a display string and moves with the interface language.
  const extractionStage = stages.find((stage) => stage.provider === 'extract');
  const extraction = extractionStage ? classifyCell(extractionStage, { runDeclaresRemedies }) : null;
  const cells = stages.map((stage) => ({
    worker: stage.worker,
    ...(stage.provider ? { provider: stage.provider } : {}),
    status: stage.status,
    ...(stage.remedy ? { remedy: stage.remedy } : {}),
    ...classifyCell(stage, { runDeclaresRemedies, extraction }),
  }));
  return { runDeclaresRemedies, cells };
}

function tally(cells) {
  const counts = {};
  for (const cell of cells) counts[cell.disposition] = (counts[cell.disposition] ?? 0) + 1;
  return counts;
}

/**
 * Order the schedulable work. The backlog asks for class and cost, and the two are not interchangeable: class is
 * how the corpus is read (a campaign that unblocks every `uefi-bios` sample is a sentence about UEFI coverage),
 * cost is what the campaign spends. So classes are ordered by how much schedulable work they hold, and inside a
 * class the yield per image comes first, with measured wall time breaking ties — an image whose cost has never
 * been measured sorts last within its yield, because scheduling an unmeasured run ahead of a known-cheap one
 * spends an unknown budget first.
 */
export function rankQueue(entries) {
  const byClass = new Map();
  for (const entry of entries) {
    const group = byClass.get(entry.firmwareClass) ?? [];
    group.push(entry);
    byClass.set(entry.firmwareClass, group);
  }
  const groups = [...byClass.entries()].map(([firmwareClass, samples]) => ({
    firmwareClass,
    cells: samples.reduce((sum, sample) => sum + sample.cells, 0),
    samples: samples.sort(
      (a, b) =>
        b.cells - a.cells ||
        (a.costMs ?? Number.POSITIVE_INFINITY) - (b.costMs ?? Number.POSITIVE_INFINITY) ||
        a.id.localeCompare(b.id),
    ),
  }));
  return groups.sort((a, b) => b.cells - a.cells || a.firmwareClass.localeCompare(b.firmwareClass));
}

/**
 * Build the campaign from a matrix and whatever costs were measured. `costs` is a Map of image id → the wall time
 * that image's most recent completed autonomous scan took; an image with no measured cost keeps `null` rather
 * than an invented average, and the plan says how many of those it holds.
 */
export function planCampaign(matrix, costs = new Map()) {
  if (matrix?.schemaVersion !== 1 || !Array.isArray(matrix.samples)) {
    throw new Error('expected corpus matrix schemaVersion 1 with samples');
  }
  const totals = {};
  const queue = [];
  const deployment = [];
  const reacquire = [];
  const notExecutable = { settled: [], 'open-ended': [], defect: [], undeclared: [], unknown: [], build: [] };
  const raise = [];
  let blockedUpstreamUnlockable = 0;
  let blockedUpstreamDead = 0;

  for (const sample of matrix.samples) {
    const { cells } = classifySample(sample);
    for (const [disposition, count] of Object.entries(tally(cells))) {
      totals[disposition] = (totals[disposition] ?? 0) + count;
    }
    const firmwareClass = sample.identity?.firmwareClass ?? sample.coverage?.firmwareClass ?? 'unknown';
    const identity = { id: sample.id, filename: sample.filename, firmwareClass };
    const schedulable = cells.filter((cell) => SCHEDULABLE.has(cell.disposition));
    if (schedulable.length > 0) {
      queue.push({
        ...identity,
        cells: schedulable.length,
        costMs: costs.get(sample.id)?.lastScanMs ?? null,
        workers: schedulable.map((cell) => ({ worker: cell.worker, disposition: cell.disposition, rule: cell.rule })),
      });
    }
    const toRaise = cells.filter((cell) => cell.disposition === 'raise');
    if (toRaise.length > 0) {
      raise.push({ ...identity, workers: toRaise.map((cell) => cell.worker) });
    }
    const toDeploy = cells.filter((cell) => cell.disposition === 'deploy');
    if (toDeploy.length > 0) {
      deployment.push({ ...identity, workers: toDeploy.map((cell) => cell.worker) });
    }
    const toReacquire = cells.filter((cell) => cell.disposition === 'reacquire');
    if (toReacquire.length > 0) {
      const blocked = cells.filter((cell) => cell.disposition === 'blocked-upstream' && !cell.unlockedBy).length;
      reacquire.push({ ...identity, workers: toReacquire.map((cell) => cell.worker), blockedDownstream: blocked });
    }
    for (const cell of cells) {
      if (cell.disposition === 'blocked-upstream') {
        if (cell.unlockedBy) blockedUpstreamUnlockable += 1;
        else blockedUpstreamDead += 1;
      }
      if (notExecutable[cell.disposition]) {
        notExecutable[cell.disposition].push({ ...identity, worker: cell.worker, rule: cell.rule });
      }
    }
  }

  const measured = queue.filter((entry) => entry.costMs !== null);
  return {
    schemaVersion: 1,
    sampleCount: matrix.samples.length,
    stageCellCount: matrix.stageCellCount ?? 0,
    totals,
    // Two budgets, never summed: what the measured images are known to cost, and how many images would be run
    // with no idea what they cost. One number over both would read as a total and would not be one.
    budget: {
      measuredMs: measured.reduce((sum, entry) => sum + entry.costMs, 0),
      measuredImages: measured.length,
      unmeasuredImages: queue.length - measured.length,
    },
    classes: rankQueue(queue),
    queue: queue.sort((a, b) => b.cells - a.cells || a.id.localeCompare(b.id)),
    deployment,
    raise,
    reacquire,
    blockedUpstream: { unlockable: blockedUpstreamUnlockable, dead: blockedUpstreamDead },
    notExecutable,
  };
}

/** Flatten the ranked classes into the order the campaign actually executes: class by class, best yield first. */
export function executionOrder(plan) {
  return plan.classes.flatMap((group) => group.samples);
}

function ms(value) {
  if (value === null || value === undefined) return 'no medido';
  const seconds = Math.round(value / 1000);
  return seconds < 90 ? `${seconds} s` : `${Math.round(seconds / 60)} min`;
}

export function renderPlan(plan, generatedAt = new Date().toISOString()) {
  const t = plan.totals;
  const lines = [
    '# FirmLab — campaña de cobertura del corpus',
    '',
    `Generada: ${generatedAt}`,
    '',
    `${plan.sampleCount} muestras · ${plan.stageCellCount} celdas de etapa aplicable.`,
    '',
    'Cada celda sin cubrir declara qué la cambiaría; ninguna se clasifica leyendo su nota en prosa. Una celda que',
    'no declara remedio es DESCONOCIDA: se programa una vez, porque medirla es ejecutarla, y nunca se cuenta como',
    'resuelta.',
    '',
    '## Reparto',
    '',
    '| Disposición | Celdas | Qué significa |',
    '|---|---:|---|',
  ];
  const meaning = {
    covered: 'la etapa se ejecutó',
    scan: 'una corrida puede cambiarla — EJECUTABLE',
    declare: 'registrada por una build sin remedio declarado; re-ejecutar la mide — EJECUTABLE',
    raise: 'un tope la truncó: hay que subirlo (o correr su campaña dedicada) antes de re-ejecutar',
    deploy: 'falta la herramienta o el corpus de reglas en este despliegue',
    'blocked-upstream': 'omitida por falta de rootfs; hereda el estado de su extracción',
    settled: 'miró donde podía y ésa es la respuesta para esta imagen',
    reacquire: 'la entrada no está en estos bytes',
    'open-ended': 'inconcluyente por construcción; ningún presupuesto la termina',
    defect: 'defecto de FirmLab, no de la imagen',
    undeclared: 'el sitio no puede decirlo: cuestión de código',
    build: 'la clase enruta aquí y el worker no existe todavía',
    unknown: 'no reconocida por este planificador',
  };
  for (const [disposition, count] of Object.entries(t).sort((a, b) => b[1] - a[1])) {
    lines.push(`| \`${disposition}\` | ${count} | ${meaning[disposition] ?? '—'} |`);
  }

  const executable = (t.scan ?? 0) + (t.declare ?? 0);
  lines.push(
    '',
    '## Cola ejecutable',
    '',
    `${executable} celda(s) en ${plan.queue.length} imagen(es). Coste medido: ${ms(plan.budget.measuredMs)} sobre ${plan.budget.measuredImages} imagen(es); ${plan.budget.unmeasuredImages} sin coste medido.`,
    '',
    'La unidad de trabajo es una imagen: el escaneo autónomo recorre su cadena de etapas completa, así que una',
    'corrida resuelve todas las celdas ejecutables de esa muestra a la vez.',
    '',
  );
  for (const group of plan.classes) {
    lines.push(`### ${group.firmwareClass} — ${group.cells} celda(s)`, '');
    lines.push('| # | Imagen | Fichero | Celdas | Coste medido | Etapas |', '|---:|---|---|---:|---:|---|');
    group.samples.forEach((sample, index) => {
      const workers = sample.workers.map((w) => w.worker).join(', ');
      lines.push(
        `| ${index + 1} | \`${sample.id}\` | ${sample.filename} | ${sample.cells} | ${ms(sample.costMs)} | ${workers} |`,
      );
    });
    lines.push('');
  }

  lines.push('## No ejecutable por una corrida', '');
  lines.push(
    `- \`settled\` — ${plan.notExecutable.settled.length} celda(s): la etapa agotó lo que podía mirar.`,
    `- \`open-ended\` — ${plan.notExecutable['open-ended'].length} celda(s): búsqueda acotada por construcción.`,
    `- \`defect\` — ${plan.notExecutable.defect.length} celda(s): arreglo de código, no de cobertura.`,
    `- \`undeclared\` — ${plan.notExecutable.undeclared.length} celda(s): el sitio no puede declarar su remedio.`,
    `- \`build\` — ${plan.notExecutable.build.length} celda(s): worker no construido.`,
    `- \`unknown\` — ${plan.notExecutable.unknown.length} celda(s): estado o remedio no reconocido por este planificador.`,
    '',
    `Aguas abajo de la extracción: ${plan.blockedUpstream.dead} celda(s) que ninguna corrida recupera y ${plan.blockedUpstream.unlockable} que se desbloquean si su extracción lo hace.`,
    '',
  );

  if (plan.raise.length > 0) {
    lines.push('### Requiere subir un tope antes de re-ejecutar', '');
    lines.push(
      'Re-ejecutar tal cual devuelve la misma celda: el tope no depende de la corrida. Para FwHunt, la campaña',
      'dedicada (`pnpm fwhunt:campaign --image ID`) sí la retira.',
      '',
    );
    for (const entry of plan.raise) {
      lines.push(`- \`${entry.id}\` ${entry.filename} — ${entry.workers.join(', ')}`);
    }
    lines.push('');
  }
  if (plan.deployment.length > 0) {
    lines.push('### Requiere cambiar el despliegue antes de re-ejecutar', '');
    for (const entry of plan.deployment) {
      lines.push(`- \`${entry.id}\` ${entry.filename} — ${entry.workers.join(', ')}`);
    }
    lines.push('');
  }
  if (plan.reacquire.length > 0) {
    lines.push('### Requiere volver a obtener el artefacto', '');
    for (const entry of plan.reacquire) {
      const downstream = entry.blockedDownstream ? ` (+${entry.blockedDownstream} celda(s) aguas abajo)` : '';
      lines.push(`- \`${entry.id}\` ${entry.filename} — ${entry.workers.join(', ')}${downstream}`);
    }
    lines.push('');
  }
  return `${lines.join('\n')}\n`;
}

export function parseArgs(argv, env = process.env) {
  const args = {
    base: env.FIRMLAB_UI ?? 'http://127.0.0.1:8899',
    format: 'markdown',
    out: null,
    matrix: null,
    execute: false,
    limit: 0,
    pollMs: 5_000,
    jobTimeoutMs: 60 * 60 * 1_000,
    help: false,
  };
  const value = (flag, index) => {
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) throw new Error(`${flag} requires a value`);
    return next;
  };
  const positive = (flag, raw) => {
    const parsed = Number(raw);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${flag} must be a positive integer`);
    return parsed;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--base') args.base = value(token, i++);
    else if (token === '--format') args.format = value(token, i++);
    else if (token === '--out') args.out = value(token, i++);
    else if (token === '--matrix') args.matrix = value(token, i++);
    else if (token === '--execute') args.execute = true;
    else if (token === '--limit') args.limit = positive(token, value(token, i++));
    else if (token === '--poll-ms') args.pollMs = positive(token, value(token, i++));
    else if (token === '--job-timeout-ms') args.jobTimeoutMs = positive(token, value(token, i++));
    else if (token === '--help') args.help = true;
    else throw new Error(`Unknown argument ${token}`);
  }
  if (!['markdown', 'json'].includes(args.format)) throw new Error('--format must be markdown or json');
  if (args.execute && args.matrix) throw new Error('--execute plans against the live workbench, not a saved matrix');
  args.base = args.base.replace(/\/$/, '');
  return args;
}

function usage() {
  return [
    'Usage: node scripts/corpus-campaign.mjs [options]',
    '  --base URL             FirmLab origin (default FIRMLAB_UI or http://127.0.0.1:8899)',
    '  --matrix FILE          Plan against a saved --format json matrix instead of the live workbench',
    '  --format markdown|json Output format (default markdown)',
    '  --out FILE             Write the plan to a file instead of stdout',
    '  --execute              Run the queue, one autonomous scan at a time, in the printed order',
    '  --limit N              Execute at most N images (default: the whole queue)',
    '  --poll-ms N            Job polling interval (default 5000)',
    '  --job-timeout-ms N     Maximum wait for one scan (default 3600000)',
  ].join('\n');
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
    throw new Error(`${response.status} ${response.statusText} from ${url}${body?.error ? `: ${body.error}` : ''}`);
  }
  return body;
}

/**
 * What each image's last completed autonomous scan actually cost. Measured, never modelled: an image with no
 * completed scan on record gets no cost at all rather than the corpus average, because the whole use of this
 * number is to budget a campaign and an invented figure budgets nothing.
 */
export async function measureCosts(base, ids, headers) {
  const entries = await Promise.all(
    ids.map(async (id) => {
      try {
        const { jobs } = await fetchJson(`${base}/api/images/${encodeURIComponent(id)}/jobs`, { headers });
        const done = (jobs ?? []).filter((job) => job.kind === 'opacidad' && job.status === 'done');
        if (done.length === 0) return [id, null];
        const newest = done.reduce((best, job) => (job.updatedAt > best.updatedAt ? job : best), done[0]);
        return [id, { lastScanMs: Math.max(0, newest.updatedAt - newest.createdAt), lastScanAt: newest.updatedAt }];
      } catch {
        return [id, null];
      }
    }),
  );
  return new Map(entries.filter(([, cost]) => cost !== null));
}

async function waitForJob(base, jobId, args, headers) {
  const deadline = Date.now() + args.jobTimeoutMs;
  while (Date.now() < deadline) {
    const { job } = await fetchJson(`${base}/api/jobs/${encodeURIComponent(jobId)}`, { headers });
    if (job.status === 'done') return job;
    if (job.status === 'error') throw new Error(`scan ${jobId} failed: ${job.error ?? 'unknown error'}`);
    await new Promise((resolve) => setTimeout(resolve, args.pollMs));
  }
  throw new Error(`scan ${jobId} did not finish within ${args.jobTimeoutMs} ms`);
}

/**
 * Execute the queue one image at a time, in the ranked order. Sequential on purpose: the workbench already bounds
 * its own concurrency (`FIRMLAB_MAX_CONCURRENT_JOBS`), and a campaign that queues 20 scans at once would hand the
 * scheduler an ordering it did not choose — the ranking would stop meaning anything the moment it mattered.
 */
export async function executeCampaign(plan, args, env = process.env) {
  const headers = apiHeaders(env);
  const order = executionOrder(plan);
  const targets = args.limit > 0 ? order.slice(0, args.limit) : order;
  const ran = [];
  const failed = [];
  for (const [index, sample] of targets.entries()) {
    process.stdout.write(
      `[${index + 1}/${targets.length}] ${sample.firmwareClass} · ${sample.filename} (${sample.id}) — ${sample.cells} cell(s)\n`,
    );
    const started = Date.now();
    // One image failing is a result about that image, not about the campaign: a scan that throws is precisely the
    // `retry` case this plan exists to name, and aborting the queue would leave every image behind it unmeasured
    // for a reason that has nothing to do with them. Recorded, reported at the end, and the exit code says so.
    try {
      const { jobId } = await fetchJson(`${args.base}/api/images/${encodeURIComponent(sample.id)}/opacidad`, {
        method: 'POST',
        headers: { ...(headers ?? {}), 'content-type': 'application/json' },
        body: '{}',
      });
      await waitForJob(args.base, jobId, args, headers);
      const elapsed = Date.now() - started;
      ran.push({ id: sample.id, jobId, elapsedMs: elapsed });
      process.stdout.write(`      done in ${ms(elapsed)} (job ${jobId})\n`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      failed.push({ id: sample.id, filename: sample.filename, error: message });
      process.stdout.write(`      FAILED after ${ms(Date.now() - started)}: ${message}\n`);
    }
  }
  return { ran, failed };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const headers = apiHeaders();
  const matrix = args.matrix ? JSON.parse(await readFile(args.matrix, 'utf8')) : await fetchMatrix(args.base, headers);
  const costs = args.matrix
    ? new Map()
    : await measureCosts(
        args.base,
        matrix.samples.map((s) => s.id),
        headers,
      );
  const plan = planCampaign(matrix, costs);
  const output =
    args.format === 'json'
      ? `${JSON.stringify({ generatedAt: new Date().toISOString(), ...plan }, null, 2)}\n`
      : renderPlan(plan);
  if (args.out) await writeFile(args.out, output, 'utf8');
  else process.stdout.write(output);

  if (!args.execute) return;
  if (plan.queue.length === 0) {
    process.stdout.write('Nothing schedulable: every uncovered cell is reported above as not executable by a scan.\n');
    return;
  }
  const { ran, failed } = await executeCampaign(plan, args);
  process.stdout.write(`Campaign executed ${ran.length} scan(s). Re-run corpus-matrix.mjs to measure the result.\n`);
  if (failed.length > 0) {
    process.stderr.write(
      `${failed.length} scan(s) failed and their cells are unchanged:\n- ${failed
        .map((entry) => `${entry.filename} (${entry.id}): ${entry.error}`)
        .join('\n- ')}\n`,
    );
    process.exitCode = 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`corpus-campaign: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
