import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { LinuxKernelCveRecord } from '@firmlab/core';
import { afterEach, describe, expect, it } from 'vitest';
import { compareKernelBackports } from './kernel-backport.js';

const dirs: string[] = [];
const git = (repo: string, ...args: string[]) =>
  execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

function repo() {
  const path = mkdtempSync(join(tmpdir(), 'firmlab-kernel-backport-'));
  dirs.push(path);
  git(path, 'init', '-q');
  git(path, 'config', 'user.name', 'FirmLab Test');
  git(path, 'config', 'user.email', 'test@firmlab.invalid');
  writeFileSync(join(path, 'driver.c'), 'int value = 0;\n');
  git(path, 'add', 'driver.c');
  git(path, 'commit', '-q', '-m', 'base');
  return path;
}

function commit(repoPath: string, content: string, message: string) {
  writeFileSync(join(repoPath, 'driver.c'), content);
  git(repoPath, 'add', 'driver.c');
  git(repoPath, 'commit', '-q', '-m', message);
  return git(repoPath, 'rev-parse', 'HEAD');
}

function record(fixes: string[]): LinuxKernelCveRecord {
  return {
    cveId: 'CVE-2026-43286',
    repositories: ['https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git'],
    programFiles: ['driver.c'],
    gitRanges: fixes.map((fixed) => ({ introduced: '0'.repeat(40), fixed })),
    openGitIntroductions: [],
    fixCommits: fixes,
  };
}

afterEach(() => {
  for (const path of dirs.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe('compareKernelBackports', () => {
  it('reports an exact fix ancestor without claiming artifact binding', async () => {
    const path = repo();
    const fix = commit(path, 'int value = 1;\n', 'upstream fix');
    const result = await compareKernelBackports(path, record([fix]));
    expect(result).toMatchObject({
      artifactBinding: 'unverified',
      coverage: 'complete',
      matches: [{ upstreamCommit: fix, method: 'exact_ancestor', vendorCommit: fix }],
    });
  });

  it('recognizes an equivalent backport by stable patch-id despite a different commit hash', async () => {
    const path = repo();
    const base = git(path, 'rev-parse', 'HEAD');
    const fix = commit(path, 'int value = 1;\n', 'upstream fix');
    git(path, 'checkout', '-q', '-b', 'vendor', base);
    const vendor = commit(path, 'int value = 1;\n', 'vendor backport with different metadata');
    expect(vendor).not.toBe(fix);

    const result = await compareKernelBackports(path, record([fix]));
    expect(result.matches[0]).toMatchObject({
      upstreamCommit: fix,
      method: 'stable_patch_id',
      vendorCommit: vendor,
    });
    expect(result.matches[0]?.patchId).toMatch(/^[0-9a-f]{40}$/);
  });

  it('keeps a partially modified patch as not found, never as vulnerable', async () => {
    const path = repo();
    const base = git(path, 'rev-parse', 'HEAD');
    const fix = commit(path, 'int value = 1;\n', 'upstream fix');
    git(path, 'checkout', '-q', '-b', 'vendor', base);
    commit(path, 'int value = 2;\n', 'different vendor change');

    const result = await compareKernelBackports(path, record([fix]));
    expect(result.matches[0]).toMatchObject({ method: 'not_found' });
    expect(result.reason).toContain('artifact binding remains unverified');
  });

  it('refuses dirty and non-Git trees explicitly', async () => {
    const path = repo();
    const fix = commit(path, 'int value = 1;\n', 'upstream fix');
    writeFileSync(join(path, 'driver.c'), 'int value = 9;\n');
    const dirty = await compareKernelBackports(path, record([fix]));
    expect(dirty).toMatchObject({ coverage: 'none', commitsExamined: 0 });
    expect(dirty.reason).toContain('dirty');

    const plain = mkdtempSync(join(tmpdir(), 'firmlab-not-git-'));
    dirs.push(plain);
    const missing = await compareKernelBackports(plain, record([fix]));
    expect(missing).toMatchObject({ coverage: 'none', repoHead: null });
    expect(missing.reason).toContain('unavailable');
  });

  it('reports source objects missing from a shallow or unrelated mirror as incomplete evidence', async () => {
    const path = repo();
    const result = await compareKernelBackports(path, record(['f'.repeat(40)]), { maxCommits: 1 });
    expect(result.matches).toEqual([
      expect.objectContaining({ upstreamCommit: 'f'.repeat(40), method: 'source_commit_missing' }),
    ]);
    expect(result.coverage).toBe('none');
  });
});
