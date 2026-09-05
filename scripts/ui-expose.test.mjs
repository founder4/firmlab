import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const script = path.join(root, 'scripts/ui-expose.sh');

async function fixture(dockerBody, curlBody = 'exit 1') {
  const dir = await mkdtemp(path.join(tmpdir(), 'firmlab-ui-expose-'));
  const log = path.join(dir, 'docker.log');
  const docker = path.join(dir, 'docker');
  const curl = path.join(dir, 'curl');
  await writeFile(docker, `#!/usr/bin/env bash\nprintf '%s\\n' "$*" >> "$DOCKER_LOG"\n${dockerBody}\n`);
  await writeFile(curl, `#!/usr/bin/env bash\n${curlBody}\n`);
  await chmod(docker, 0o755);
  await chmod(curl, 0o755);
  return {
    env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, DOCKER_LOG: log },
    log: async () => readFile(log, 'utf8').catch(() => ''),
  };
}

test('up reuses an existing healthy endpoint without touching Docker', async () => {
  const f = await fixture('exit 99', `printf '%s' '{"status":"ok"}'`);
  const { stdout } = await run('bash', [script, 'up'], { cwd: root, env: f.env });
  assert.match(stdout, /ya está disponible/);
  assert.equal(await f.log(), '');
});

test('down refuses to remove a Compose-managed container', async () => {
  const f = await fixture(`
case "$*" in
  *'--format {{index .Config.Labels "io.firmlab.ui-expose"}}'*) printf '' ;;
  *'--format {{index .Config.Labels "com.docker.compose.project"}}'*) printf 'firmlab' ;;
esac
exit 0`);
  await assert.rejects(run('bash', [script, 'down'], { cwd: root, env: f.env }), (error) => {
    assert.match(error.stderr, /se rechaza retirar/);
    return true;
  });
  assert.doesNotMatch(await f.log(), /rm -f/);
});

test('down removes only a sidecar carrying the ownership label', async () => {
  const f = await fixture(`
case "$*" in
  *'--format {{index .Config.Labels "io.firmlab.ui-expose"}}'*) printf '1' ;;
  *'--format {{index .Config.Labels "com.docker.compose.project"}}'*) printf '' ;;
esac
exit 0`);
  const { stdout } = await run('bash', [script, 'down'], { cwd: root, env: f.env });
  assert.match(stdout, /firmlab-ui-expose retirado/);
  assert.match(await f.log(), /rm -f firmlab-ui-expose/);
});

test('down succeeds when its fallback sidecar does not exist', async () => {
  const f = await fixture('exit 1');
  const { stdout } = await run('bash', [script, 'down'], { cwd: root, env: f.env });
  assert.match(stdout, /no estaba levantado/);
  assert.doesNotMatch(await f.log(), /rm -f/);
});
