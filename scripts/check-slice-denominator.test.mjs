/**
 * Fixtures for the cap-as-denominator guard, positive and negative, because a guard is only as good as its SUCCESS
 * path and that is the path nobody runs. Four of this project's bugs were guards that reported "clean" from a
 * branch that had examined nothing, so the negatives here are not decoration: each one is a real shape from
 * `apps/api` that an earlier draft of the rule flagged, and each would have been "fixed" by weakening the rule
 * until it caught nothing at all.
 *
 * The fixtures are written to disk and compiled by the real checker rather than parsed from strings, for the same
 * reason `isCollection` exists: `text.slice(0, 6)` and `rows.slice(0, 6)` are the same syntax and a different
 * defect, and only a type tells them apart. That also means this file exercises the checker end to end — if the
 * default lib ever stopped resolving, the string fixtures would start failing here instead of quietly turning the
 * guard into a no-op in `pnpm biome`.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { analyzeFiles, listSources } from './check-slice-denominator.mjs';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-slice-denominator-'));

/** Write one fixture and analyse it on its own, so a defect can only come from the code under test. */
function analyze(name, source) {
  const file = path.join(dir, `${name}.ts`);
  fs.writeFileSync(file, source);
  return analyzeFiles([file]);
}

// --- positives: the cut is counted and nothing it came from is -------------------------------------------------

test('flags a prefix cap whose own length becomes the total', () => {
  const { defects, stats } = analyze(
    'prefix',
    `
    export function listing(all: string[], cap: number) {
      const shown = all.slice(0, cap);
      return { entries: shown, total: shown.length };
    }
  `,
  );
  assert.equal(stats.cappedSlices, 1);
  assert.equal(stats.overCollections, 1);
  assert.equal(defects.length, 1);
  assert.equal(defects[0].bound, 'shown');
  assert.ok(defects[0].lineage.includes('all'));
});

test('flags a suffix cap, which truncates just as hard', () => {
  const { defects } = analyze(
    'suffix',
    `
    export function recent(rows: number[], cap: number) {
      const tail = rows.slice(-cap);
      return { rows: tail, count: tail.length };
    }
  `,
  );
  assert.equal(defects.length, 1);
  assert.equal(defects[0].bound, 'tail');
});

test('flags a cap over a derived collection when no step of the lineage is measured', () => {
  const { defects } = analyze(
    'derived',
    `
    export function top(rows: { score: number }[]) {
      const ranked = rows.filter((r) => r.score > 0).sort((a, b) => b.score - a.score);
      const best = ranked.slice(0, 5);
      return { best, considered: best.length };
    }
  `,
  );
  assert.equal(defects.length, 1);
  assert.deepEqual(defects[0].lineage.includes('rows') && defects[0].lineage.includes('ranked'), true);
});

test('flags a count derived from the cut rather than read off it', () => {
  const { defects } = analyze(
    'derived-count',
    `
    export function summary(findings: { critical: boolean }[], cap: number) {
      const kept = findings.slice(0, cap);
      return { kept, criticals: kept.filter((f) => f.critical).length };
    }
  `,
  );
  assert.equal(defects.length, 1);
});

test('flags a total measured in a different function — one scope does not lend its denominator to another', () => {
  const { defects } = analyze(
    'other-scope',
    `
    export function elsewhere(all: string[]) {
      return all.length;
    }
    export function listing(all: string[], cap: number) {
      const shown = all.slice(0, cap);
      return { entries: shown, total: shown.length };
    }
  `,
  );
  assert.equal(defects.length, 1);
});

// --- negatives: every one of these is a real shape from apps/api ------------------------------------------------

test('accepts a cut whose original is measured beside it', () => {
  const { defects, stats } = analyze(
    'measured',
    `
    export function listing(all: string[], cap: number) {
      const shown = all.slice(0, cap);
      return { entries: shown, total: all.length, dropped: all.length - shown.length };
    }
  `,
  );
  assert.equal(stats.overCollections, 1);
  assert.deepEqual(defects, []);
});

test('accepts a cut over a derived collection when the collection it came from is measured', () => {
  // `report-assertions.ts` and `FindingsLedger.tsx`: contested rows first, the rest capped, `measured.length` the
  // denominator. The cut's own name is two derivations away from the one that carries the total.
  const { defects } = analyze(
    'lineage',
    `
    export function rows(measured: { id: string }[], contestedIds: Set<string>, cap: number) {
      const contested = measured.filter((f) => contestedIds.has(f.id));
      const rest = measured.filter((f) => !contestedIds.has(f.id));
      const room = Math.max(0, cap - contested.length);
      const shown = [...contested, ...rest.slice(0, room)];
      return { shown, omitted: measured.length - shown.length };
    }
  `,
  );
  assert.deepEqual(defects, []);
});

test('accepts a cut over the result of a ranking call, measured through its argument', () => {
  // `extract.ts` and `funcdiff-run.ts`: the collection never appears as the slice receiver at all, only inside the
  // call that ranked it. A rule keyed on the receiver's own name reports both of these and is useless.
  const { defects } = analyze(
    'ranked-call',
    `
    declare function rank(xs: string[]): string[];
    export function pick(candidates: string[], cap: number) {
      const selected = rank(candidates).slice(0, cap);
      return { selected, found: candidates.length, dropped: candidates.length - selected.length };
    }
  `,
  );
  assert.deepEqual(defects, []);
});

test('ignores a string, where length is an offset and not a population', () => {
  // `pem-scan.ts`, `kernelposture.ts`, `fuzz.ts`. Same syntax as the first positive; a different question entirely.
  const { defects, stats } = analyze(
    'string',
    `
    export function label(text: string, at: number) {
      const window = text.slice(at, at + 320);
      return { window, width: window.length };
    }
  `,
  );
  assert.equal(stats.cappedSlices, 1);
  assert.equal(stats.overCollections, 0, 'a string receiver is not a collection');
  assert.deepEqual(defects, []);
});

test('ignores a one-argument slice, which takes the rest rather than capping it', () => {
  // `nvd.ts` keeps the tail the cap dropped exactly this way, and `boot-cmdline.ts` splits on `--`. Counting the
  // REST is how a bound states what it dropped; flagging it would punish the correct pattern.
  const { defects, stats } = analyze(
    'rest',
    `
    export function split(ranked: string[], cap: number) {
      const dropped = ranked.slice(cap);
      return { queried: cap, droppedCount: dropped.length };
    }
  `,
  );
  assert.equal(stats.cappedSlices, 0, 'slice(n) is not a cap');
  assert.deepEqual(defects, []);
});

test('ignores a cut that is never counted — the number was not claimed', () => {
  const { defects, stats } = analyze(
    'uncounted',
    `
    export function listing(all: string[], cap: number) {
      const shown = all.slice(0, cap);
      return { entries: shown };
    }
  `,
  );
  assert.equal(stats.named, 1);
  assert.deepEqual(defects, []);
});

test('ignores an inline cut, which has no name for anything to count', () => {
  const { defects, stats } = analyze(
    'inline',
    `
    export function listing(all: string[], cap: number) {
      return { entries: all.slice(0, cap) };
    }
  `,
  );
  assert.equal(stats.overCollections, 1);
  assert.equal(stats.named, 0);
  assert.deepEqual(defects, []);
});

// --- the guard's own ability to look ----------------------------------------------------------------------------

test('a file the compiler cannot open is reported, never counted as clean', () => {
  const { stats, defects } = analyzeFiles([path.join(dir, 'does-not-exist.ts')]);
  assert.equal(stats.files, 0);
  assert.equal(stats.unreadable.length, 1);
  assert.deepEqual(defects, []);
});

test('listSources finds the workspace sources and leaves the test files out', () => {
  const sources = listSources(new URL('..', import.meta.url).pathname);
  assert.ok(sources.length > 100, `expected the workspace sources, got ${sources.length}`);
  assert.ok(sources.includes('apps/api/src/providers/credmatch.ts'));
  assert.equal(
    sources.filter((f) => /\.test\.tsx?$/.test(f)).length,
    0,
    'a test file asserting on a cap is not the cap',
  );
});

test.after(() => fs.rmSync(dir, { recursive: true, force: true }));
