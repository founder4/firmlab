import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { rankRootfsBinaryCandidates, walkRootfs } from './extract.js';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('walkRootfs coverage', () => {
  it('reports the exact-bound tree complete and a larger tree truncated', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-extract-walk-'));
    dirs.push(root);
    fs.writeFileSync(path.join(root, 'a'), 'a');
    fs.writeFileSync(path.join(root, 'b'), 'b');
    fs.writeFileSync(path.join(root, 'c'), 'c');

    expect(walkRootfs(root, 3).coverage).toEqual({ entriesWalked: 3, cap: 3, complete: true });
    expect(walkRootfs(root, 2).coverage).toEqual({ entriesWalked: 2, cap: 2, complete: false });
  });
});

describe('rankRootfsBinaryCandidates', () => {
  it('selects by security value and directory role, never traversal order', () => {
    const ranked = rankRootfsBinaryCandidates([
      { path: 'opt/first-from-walk', networkFacing: false },
      { path: 'bin/ash', networkFacing: false },
      { path: 'usr/sbin/httpd', networkFacing: true },
      { path: 'sbin/init', networkFacing: false },
    ]);
    expect(ranked.map((candidate) => candidate.path)).toEqual([
      'usr/sbin/httpd',
      'sbin/init',
      'bin/ash',
      'opt/first-from-walk',
    ]);
  });
});
