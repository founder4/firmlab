import assert from 'node:assert/strict';
import test from 'node:test';
import {
  classifyCell,
  classifySample,
  executionOrder,
  parseArgs,
  planCampaign,
  rankQueue,
  renderPlan,
} from './corpus-campaign.mjs';

const stage = (worker, status, extra = {}) => ({ worker, reason: `why ${worker}`, status, ...extra });

const sample = (id, firmwareClass, stages) => ({
  id,
  filename: `${id}.bin`,
  identity: { firmwareClass, arch: 'mips' },
  coverage: { firmwareClass, applicable: stages.length, executed: 0, stages },
});

const matrix = (samples) => ({
  schemaVersion: 1,
  samples,
  stageCellCount: samples.reduce((n, s) => n + s.coverage.stages.length, 0),
});

test('a covered cell is never work', () => {
  assert.equal(classifyCell(stage('W1', 'found')).disposition, 'covered');
  assert.equal(classifyCell(stage('W1', 'ran-empty')).disposition, 'covered');
});

test('a stage that has never executed is the cheapest thing a campaign can do', () => {
  assert.equal(classifyCell(stage('W1', 'not-run')).disposition, 'scan');
});

test('the remedy, not the note, decides what a degraded cell is', () => {
  const cases = [
    ['retry', 'scan'],
    ['raise-bound', 'scan'],
    ['install-tool', 'deploy'],
    ['reacquire-input', 'reacquire'],
    ['settled', 'settled'],
    ['unbounded-search', 'open-ended'],
    ['defect', 'defect'],
  ];
  for (const [remedy, disposition] of cases) {
    assert.equal(classifyCell(stage('W', 'degraded', { remedy })).disposition, disposition, remedy);
  }
});

test('a remedy this planner does not recognise is reported, never folded into a bucket', () => {
  // The workbench being planned against may run a build older or newer than this checkout.
  const cell = classifyCell(stage('W', 'degraded', { remedy: 'teleport' }));
  assert.equal(cell.disposition, 'unknown');
  assert.match(cell.rule, /teleport/);
});

test('an undeclared remedy is queued once when the run predates the field, and flagged when it does not', () => {
  const stale = classifyCell(stage('W', 'degraded'), { runDeclaresRemedies: false });
  assert.equal(stale.disposition, 'declare');
  const cannotTell = classifyCell(stage('W', 'degraded'), { runDeclaresRemedies: true });
  assert.equal(cannotTell.disposition, 'undeclared');
  assert.match(cannotTell.rule, /code question/);
});

test('a skipped stage inherits its executability from the extraction that blocked it', () => {
  const dead = classifySample(
    sample('dead', 'embedded-linux', [
      stage('W1 · Extraction', 'degraded', { provider: 'extract', remedy: 'reacquire-input' }),
      stage('W3 · Credentials', 'no-input'),
      stage('W4 · Web surface', 'no-input'),
    ]),
  );
  const blocked = dead.cells.filter((cell) => cell.disposition === 'blocked-upstream');
  assert.equal(blocked.length, 2);
  assert.equal(
    blocked.every((cell) => cell.unlockedBy === null),
    true,
  );

  const alive = classifySample(
    sample('alive', 'embedded-linux', [
      stage('W1 · Extraction', 'degraded', { provider: 'extract', remedy: 'install-tool' }),
      stage('W3 · Credentials', 'no-input'),
    ]),
  );
  assert.equal(alive.cells[1].disposition, 'blocked-upstream');
  assert.equal(alive.cells[1].unlockedBy, 'deploy');
});

test('a skip with no extraction cell to attribute it to is unknown, not dead', () => {
  const orphan = classifySample(sample('orphan', 'rtos', [stage('W3 · Credentials', 'no-input')]));
  assert.equal(orphan.cells[0].disposition, 'unknown');
});

test('the extraction cell is found by its provider tag, not by its display name', () => {
  // The worker column is localised interface copy; matching it would make the campaign language-dependent.
  const spanish = classifySample(
    sample('es', 'embedded-linux', [
      stage('W1 · Extracción', 'degraded', { provider: 'extract', remedy: 'reacquire-input' }),
      stage('W3 · Credenciales', 'no-input'),
    ]),
  );
  assert.equal(spanish.cells[1].unlockedBy, null);
});

test('a settled corpus queues nothing at all', () => {
  const plan = planCampaign(
    matrix([
      sample('a', 'rtos', [
        stage('Static · Device tree', 'degraded', { remedy: 'settled' }),
        stage('W0 · Identity', 'found'),
      ]),
    ]),
  );
  assert.equal(plan.queue.length, 0);
  assert.equal(plan.totals.settled, 1);
  assert.equal(plan.notExecutable.settled.length, 1);
});

test('the budget separates measured wall time from images whose cost is unknown', () => {
  const plan = planCampaign(
    matrix([sample('cheap', 'rtos', [stage('W', 'not-run')]), sample('unknown', 'rtos', [stage('W', 'not-run')])]),
    new Map([['cheap', { lastScanMs: 60_000, lastScanAt: 1 }]]),
  );
  assert.equal(plan.budget.measuredMs, 60_000);
  assert.equal(plan.budget.measuredImages, 1);
  assert.equal(plan.budget.unmeasuredImages, 1);
  // An unmeasured image must never be given an invented cost: the budget above is what the campaign KNOWS.
  assert.equal(plan.queue.find((entry) => entry.id === 'unknown').costMs, null);
});

test('ranking puts the busiest class first, then yield, then measured cost, then id', () => {
  const groups = rankQueue([
    { id: 'b', firmwareClass: 'rtos', cells: 1, costMs: 10 },
    { id: 'a', firmwareClass: 'embedded-linux', cells: 3, costMs: 900 },
    { id: 'c', firmwareClass: 'embedded-linux', cells: 3, costMs: 100 },
    { id: 'd', firmwareClass: 'embedded-linux', cells: 3, costMs: null },
  ]);
  assert.deepEqual(
    groups.map((group) => group.firmwareClass),
    ['embedded-linux', 'rtos'],
  );
  assert.deepEqual(
    groups[0].samples.map((entry) => entry.id),
    ['c', 'a', 'd'],
  );
});

test('execution follows the printed order exactly', () => {
  const plan = planCampaign(
    matrix([
      sample('small', 'rtos', [stage('W', 'not-run')]),
      sample('big', 'embedded-linux', [stage('W', 'not-run'), stage('X', 'not-run')]),
    ]),
  );
  assert.deepEqual(
    executionOrder(plan).map((entry) => entry.id),
    ['big', 'small'],
  );
});

test('the rendered plan names every bucket with its count and its rule', () => {
  const plan = planCampaign(
    matrix([
      sample('a', 'embedded-linux', [
        stage('W1 · Extraction', 'degraded', { provider: 'extract', remedy: 'reacquire-input' }),
        stage('W3 · Credentials', 'no-input'),
        stage('W5 · Reachability', 'degraded', { remedy: 'unbounded-search' }),
        stage('Static · YARA', 'degraded', { remedy: 'install-tool' }),
        stage('W2 · SBOM', 'not-run'),
      ]),
    ]),
  );
  const markdown = renderPlan(plan, '2026-09-12T00:00:00.000Z');
  assert.match(markdown, /`scan` \| 1/);
  assert.match(markdown, /Requiere cambiar el despliegue/);
  assert.match(markdown, /Requiere volver a obtener el artefacto/);
  assert.match(markdown, /1 celda\(s\) que ninguna corrida recupera/);
  assert.match(markdown, /open-end/);
});

test('a matrix of another schema is refused rather than half-read', () => {
  assert.throws(() => planCampaign({ schemaVersion: 2, samples: [] }), /schemaVersion 1/);
});

test('arguments', () => {
  const args = parseArgs(['--base', 'http://x/', '--limit', '3', '--execute'], {});
  assert.equal(args.base, 'http://x');
  assert.equal(args.limit, 3);
  assert.equal(args.execute, true);
  assert.throws(() => parseArgs(['--limit', '0'], {}), /positive integer/);
  assert.throws(() => parseArgs(['--format', 'xml'], {}), /markdown or json/);
  // Executing against a saved matrix would schedule work from a snapshot the workbench may have moved past.
  assert.throws(() => parseArgs(['--execute', '--matrix', 'm.json'], {}), /live workbench/);
});
