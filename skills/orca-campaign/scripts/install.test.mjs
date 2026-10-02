import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { install } from './install.mjs';
const exec = promisify(execFile);

test('installed launcher and suite run outside the source repository; update is idempotent', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'orca-install-'));
  const home = join(directory, "user's profile");
  const other = join(directory, 'other-project');
  try {
    await mkdir(other);
    const installed = await install({ home, codexHome: join(home, '.codex') });
    const help = await exec(installed.launcher, ['--help'], { cwd: other });
    assert.match(help.stdout, /--run RUN/);
    const guarded = await exec(installed.workerLauncher, ['--help'], { cwd: other });
    assert.match(guarded.stdout, /--policy <path>/);
    for (const name of ['policy.test.mjs', 'launch-worker.test.mjs']) {
      const run = await exec(process.execPath, ['--test', join(installed.skill, 'scripts', name)], {
        cwd: other,
        env: { ...process.env, NODE_TEST_CONTEXT: undefined },
      });
      assert.match(run.stdout, /fail 0/);
    }
    const suite = await exec(process.execPath, ['--test', join(installed.skill, 'scripts', 'watch.test.mjs')], {
      cwd: other,
      env: { ...process.env, NODE_TEST_CONTEXT: undefined },
    });
    assert.match(suite.stdout, /fail 0/);
    assert.deepEqual(await install({ home, codexHome: join(home, '.codex') }), installed);
    assert.match(
      await readFile(join(home, '.claude', 'skills', 'orca-campaign', 'SKILL.md'), 'utf8'),
      /name: orca-campaign/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('user modifications and unrelated commands are preserved and refused before mutation', async () => {
  const home = await mkdtemp(join(tmpdir(), 'orca-install-preserve-'));
  const options = { home, codexHome: join(home, '.codex') };
  try {
    const installed = await install(options);
    const script = join(installed.skill, 'scripts', 'watch.mjs');
    await writeFile(script, 'user edits');
    await assert.rejects(install(options), /Locally modified/);
    assert.equal(await readFile(script, 'utf8'), 'user edits');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
  const other = await mkdtemp(join(tmpdir(), 'orca-install-conflict-'));
  try {
    const launcher = join(other, '.local', 'bin', 'orca-campaign-watch');
    await mkdir(join(other, '.local', 'bin'), { recursive: true });
    await writeFile(launcher, 'unrelated command');
    await assert.rejects(install({ home: other, codexHome: join(other, '.codex') }), /Unmanaged launcher/);
    assert.equal(await readFile(launcher, 'utf8'), 'unrelated command');
    await assert.rejects(readFile(join(other, '.agents', 'skills', 'orca-campaign', 'SKILL.md')), /ENOENT/);
  } finally {
    await rm(other, { recursive: true, force: true });
  }
});
