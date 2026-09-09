import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { dirSize } from './retention-usage.js';

const made: string[] = [];

function tree(spec: Record<string, number>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-retention-'));
  made.push(root);
  for (const [rel, bytes] of Object.entries(spec)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, Buffer.alloc(bytes));
  }
  return root;
}

afterEach(() => {
  for (const dir of made.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('dirSize', () => {
  // The branch nobody runs: the walk finds nothing wrong. It must report `truncated: false`, because the sweep
  // reads that as licence to treat the sum as a total — and a guard that cries wolf on a healthy tree is a guard
  // that gets ignored on an unhealthy one.
  it('sums the whole tree and reports no truncation when the budget is not reached', () => {
    const root = tree({ 'a.bin': 100, 'sub/b.bin': 250, 'sub/deep/c.bin': 7 });
    expect(dirSize(root)).toEqual({ bytes: 357, truncated: false });
  });

  it('reports truncation when the walk stops with tree still unvisited', () => {
    const root = tree({ 'a.bin': 10, 'b.bin': 10, 'sub/c.bin': 10, 'sub/d.bin': 10 });
    const stopped = dirSize(root, 2);
    expect(stopped.truncated).toBe(true);
    // A floor, and strictly below the truth — which is the whole reason the flag has to travel with the number.
    expect(stopped.bytes).toBeLessThan(40);
  });

  // A tree holding exactly `budget` entries IS walked whole; deciding truncation from `visited >= budget` alone
  // would call that a floor and make the sweep warn about a directory it measured correctly.
  it('does not call a fully-walked tree truncated just because it used up the budget exactly', () => {
    const root = tree({ 'a.bin': 5, 'b.bin': 5 });
    expect(dirSize(root, 2)).toEqual({ bytes: 10, truncated: false });
  });

  it('returns zero rather than throwing for a directory that does not exist', () => {
    expect(dirSize(path.join(os.tmpdir(), 'firmlab-retention-absent-xyz'))).toEqual({ bytes: 0, truncated: false });
  });

  // A symlink is neither followed nor counted: `isFile()` is false for one, so a dangling link cannot throw and
  // a link into another image's directory cannot bill its bytes twice.
  it('does not count a symlink, dangling or otherwise', () => {
    const root = tree({ 'a.bin': 42 });
    fs.symlinkSync(path.join(root, 'nowhere'), path.join(root, 'dangling'));
    fs.symlinkSync(path.join(root, 'a.bin'), path.join(root, 'alias'));
    expect(dirSize(root)).toEqual({ bytes: 42, truncated: false });
  });
});
