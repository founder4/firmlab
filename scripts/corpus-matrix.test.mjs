import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildMatrix,
  compareMatrices,
  evaluateManifest,
  evaluateRegressions,
  evaluateRequirements,
  labelImages,
  parseArgs,
  renderMarkdown,
} from './corpus-matrix.mjs';

const image = (id, filename, firmwareClass = 'rtos') => ({
  id,
  filename,
  identity: { firmwareClass, arch: 'arm' },
});

const coverage = (firmwareClass, stages) => ({
  firmwareClass,
  applicable: stages.length,
  executed: stages.filter((stage) => ['found', 'ran-empty', 'degraded'].includes(stage.status)).length,
  stages,
});

const snapshot = (samples) => ({ schemaVersion: 1, samples });
const sample = (digest, stages, id = 'id') => ({
  ...image(id, `${id}.bin`),
  sha256: digest.repeat(64),
  coverage: coverage('rtos', stages),
});
const stage = (worker, status, findingCount = 0) => ({ worker, status, findingCount });

test('baseline matches bytes and worker across changed IDs, filenames and ordering', () => {
  const baseline = snapshot([sample('a', [stage('B', 'found', 2), stage('A', 'ran-empty')], 'old')]);
  const current = snapshot([sample('a', [stage('A', 'degraded'), stage('B', 'found', 1)], 'new')]);
  const comparison = compareMatrices(current, baseline);
  assert.equal(comparison.comparedCells, 2);
  assert.equal(comparison.regressions.length, 1);
  assert.equal(comparison.regressions[0].worker, 'A');
  assert.equal(comparison.findingCountChanges.length, 1);
  assert.deepEqual(comparison.findingCountChanges[0], {
    sha256: 'a'.repeat(64),
    filename: 'new.bin',
    worker: 'B',
    before: 2,
    after: 1,
  });
  assert.equal(evaluateRegressions(comparison).length, 1);
});

test('each executed state becoming unavailable or degraded is a regression', () => {
  for (const before of ['found', 'ran-empty']) {
    for (const after of ['degraded', 'no-input', 'not-run', 'not-built']) {
      const comparison = compareMatrices(
        snapshot([sample('a', [stage('A', after)])]),
        snapshot([sample('a', [stage('A', before)])]),
      );
      assert.equal(comparison.regressions.length, 1, `${before} -> ${after}`);
    }
  }
});

test('count shifts and recovery are review changes, not automatic regression or improvement', () => {
  const comparison = compareMatrices(
    snapshot([sample('a', [stage('A', 'found', 10), stage('B', 'ran-empty'), { worker: 'C', status: 'found' }])]),
    snapshot([sample('a', [stage('A', 'degraded', 1), stage('B', 'found', 8), stage('C', 'found', 2)])]),
  );
  assert.equal(comparison.regressions.length, 0);
  assert.equal(comparison.statusChanges.length, 2);
  assert.equal(comparison.findingCountChanges.length, 3);
  assert.equal(comparison.findingCountChanges[2].after, null);
  assert.deepEqual(evaluateRegressions(comparison), []);
});

test('missing and new samples or stages are reported separately from execution regressions', () => {
  const comparison = compareMatrices(
    snapshot([sample('c', [stage('new-image-stage', 'not-run')]), sample('a', [stage('new', 'not-run')])]),
    snapshot([sample('b', [stage('removed-image-stage', 'found')]), sample('a', [stage('old', 'found')])]),
  );
  assert.equal(comparison.comparedCells, 0);
  assert.equal(comparison.regressions.length, 0);
  assert.equal(comparison.addedSamples.length, 1);
  assert.equal(comparison.removedSamples.length, 1);
  assert.deepEqual(
    comparison.addedStages.map((entry) => entry.worker),
    ['new'],
  );
  assert.deepEqual(
    comparison.removedStages.map((entry) => entry.worker),
    ['old'],
  );
});

test('invalid or ambiguous baseline schemas fail explicitly, while additive metadata is compatible', () => {
  const valid = snapshot([sample('a', [stage('A', 'found')])]);
  for (const invalid of [
    null,
    { ...valid, schemaVersion: 2 },
    {},
    snapshot([image('old', 'old.bin')]),
    snapshot([sample('a', []), sample('a', [])]),
    snapshot([sample('a', [stage('A', 'future-status')])]),
    snapshot([sample('a', [stage('A', 'found'), stage('A', 'found')])]),
  ]) {
    assert.throws(() => compareMatrices(valid, invalid));
  }
  assert.equal(compareMatrices(valid, { ...valid, futureMetadata: true }).comparedCells, 1);
});

test('regression flags are optional and gated comparison is rendered in review artifacts', () => {
  assert.equal(parseArgs([]).failOnRegression, false);
  assert.throws(() => parseArgs(['--fail-on-regression']), /requires --baseline/);
  assert.throws(() => parseArgs(['--baseline']), /requires a value/);
  assert.equal(parseArgs(['--baseline', 'old.json', '--fail-on-regression']).failOnRegression, true);
  const matrix = buildMatrix([sample('a', [])], new Map([['id', coverage('rtos', [])]]));
  assert.doesNotMatch(renderMarkdown(matrix, 'fixed'), /Comparación con baseline/);
  matrix.comparison = compareMatrices(matrix, matrix);
  assert.match(renderMarkdown(matrix, 'fixed'), /0 celdas comparables · 0 regresiones/);
  assert.match(renderMarkdown(matrix, 'fixed'), /más o menos hallazgos no implica mejora/);
});

test('labels remain compact and become unique when filenames share a stem', () => {
  const labels = labelImages([image('one', 'vendor-release.bin'), image('two', 'vendor-release.rom')]);
  assert.equal(labels[0].label, 'vendor-release');
  assert.equal(labels[1].label, 'vendor-rele-two');
});

test('builds class and status totals from the same coverage rows rendered in the matrix', () => {
  const images = [image('one', 'freertos.bin'), image('two', 'uefi.fd', 'uefi-bios')];
  const reports = new Map([
    ['one', coverage('rtos', [{ worker: 'RTOS detect', status: 'found', findingCount: 2 }])],
    ['two', coverage('uefi-bios', [{ worker: 'chipsec', status: 'degraded' }])],
  ]);
  const matrix = buildMatrix(images, reports);
  assert.equal(matrix.sampleCount, 2);
  assert.equal(matrix.classCount, 2);
  assert.equal(matrix.stageCellCount, 2);
  assert.equal(matrix.statusCounts.found, 1);
  assert.equal(matrix.statusCounts.degraded, 1);
  assert.match(renderMarkdown(matrix, '2026-08-23T00:00:00.000Z'), /\| RTOS detect \| ✓2 \|/);
});

test('requirements report missing classes and forbidden stage states without hiding either failure', () => {
  const matrix = buildMatrix(
    [image('one', 'sample.bin')],
    new Map([['one', coverage('rtos', [{ worker: 'RTOS detect', status: 'not-run' }])]]),
  );
  assert.deepEqual(
    evaluateRequirements(
      matrix,
      [
        { firmwareClass: 'rtos', minimum: 2 },
        { firmwareClass: 'uefi-bios', minimum: 1 },
      ],
      ['not-run'],
    ),
    [
      'class rtos: required >= 2, found 1',
      'class uefi-bios: required >= 1, found 0',
      'status not-run: found 1 forbidden stage cell(s)',
    ],
  );
});

test('a locked corpus artifact is matched by digest and checked against its declared identity', () => {
  const matrix = buildMatrix(
    [{ ...image('one', 'contiki.elf'), sha256: 'abc', size: 123 }],
    new Map([['one', coverage('rtos', [{ worker: 'RTOS detect', status: 'found' }])]]),
  );
  assert.deepEqual(
    evaluateManifest(matrix, {
      samples: [
        { filename: 'contiki.elf', sha256: 'abc', size: 124, expected: { firmwareClass: 'rtos', arch: 'riscv' } },
        { filename: 'missing.cap', sha256: 'missing', size: 1, expected: { firmwareClass: 'uefi-bios' } },
      ],
    }),
    [
      'locked sample contiki.elf: expected 124 bytes, found 123',
      'locked sample contiki.elf: expected arch riscv, detected arm',
      'locked sample missing: missing.cap (missing)',
    ],
  );
});
