import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseArgs, renderReport } from './corpus-reindex.mjs';

const report = (over = {}) => ({
  imageCount: 25,
  sources: [
    {
      source: 'credential-hashes',
      imagesWithInput: 25,
      imagesWithoutInput: 0,
      rowsOffered: 40,
      rowsInserted: 32,
    },
    { source: 'gitleaks', imagesWithInput: 8, imagesWithoutInput: 17, rowsOffered: 12, rowsInserted: 12 },
  ],
  boundedInputs: [],
  unrecordedBounds: [],
  unstampedCredentials: [],
  notReconciled: [{ table: 'reachability_prior', reason: 'only a live confirmation writes one' }],
  verdict: 'Reconciled 25 images…',
  ...over,
});

test('parseArgs defaults to the loopback sidecar and Spanish', () => {
  const args = parseArgs([]);
  assert.equal(args.lang, 'es');
  assert.equal(args.format, 'text');
  assert.equal(args.dryRun, false);
});

test('parseArgs rejects a language or format it cannot honour', () => {
  assert.throws(() => parseArgs(['--lang', 'fr']), /--lang must be en or es/);
  assert.throws(() => parseArgs(['--format', 'yaml']), /--format must be text or json/);
  assert.throws(() => parseArgs(['--base']), /--base needs a value/);
  assert.throws(() => parseArgs(['--wat']), /Unknown option/);
});

test('a source with images that never ran says so, and one with full coverage does not', () => {
  const out = renderReport(report());
  assert.match(out, /gitleaks\s+12 \/ 12\s+8 \(17 never ran\)/);
  assert.match(out, /credential-hashes\s+32 \/ 40\s+25$/m);
  // Nothing may render "17 images with input" as if the other 17 had been scanned clean.
  assert.doesNotMatch(out, /gitleaks.*\s25$/m);
});

test('the tables a reindex cannot rebuild are always printed, never omitted when empty elsewhere', () => {
  const out = renderReport(report());
  assert.match(out, /Not reconciled \(a reindex cannot rebuild these\):/);
  assert.match(out, /reachability_prior — only a live confirmation writes one/);
});

test('a bounded input is named with its own coverage, and absent otherwise', () => {
  const plain = renderReport(report());
  assert.doesNotMatch(plain, /bounded/);

  const bounded = renderReport(
    report({
      boundedInputs: [
        {
          imageId: 'ab12cd34',
          filename: 'glinet.bin',
          kind: 'static-scan',
          covered: 11 * 1024 * 1024,
          total: 106 * 1024 * 1024,
        },
        { imageId: 'ab12cd34', filename: 'glinet.bin', kind: 'sbom-packages', covered: 500, total: 2019 },
      ],
    }),
  );
  assert.match(bounded, /ab12cd34\s+static-scan\s+11\.0 MB of 106\.0 MB \(10\.4 %\)/);
  assert.match(bounded, /ab12cd34\s+sbom-packages\s+500 of 2019 \(24\.8 %\)/);
});

test('an unrecorded bound is printed as unrecorded, never folded into "covered everything"', () => {
  const out = renderReport(report({ unrecordedBounds: [{ kind: 'static-scan', imageCount: 20 }] }));
  assert.match(out, /Bound NOT RECORDED/);
  assert.match(out, /static-scan\s+20 image\(s\)/);
});

test('an unstamped ledger is named, so "0 offered" cannot read as "no key material"', () => {
  const out = renderReport(
    report({ unstampedCredentials: [{ imageId: 'ab12cd34', filename: 'tenda.bin', rows: 22 }] }),
  );
  assert.match(out, /predate the stamping/);
  assert.match(out, /ab12cd34\s+22 row\(s\)\s+tenda\.bin/);
});

test('the verdict is printed verbatim and last', () => {
  const out = renderReport(report({ verdict: 'THE VERDICT' }));
  assert.equal(out.trimEnd().split('\n').pop(), 'THE VERDICT');
});
