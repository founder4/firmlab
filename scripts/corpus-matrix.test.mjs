import assert from 'node:assert/strict';
import test from 'node:test';
import { buildMatrix, evaluateManifest, evaluateRequirements, labelImages, renderMarkdown } from './corpus-matrix.mjs';

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
