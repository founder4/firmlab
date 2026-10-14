/**
 * The tools image is intentionally enormous, so refreshing Grype must invalidate only its final database layer.
 * These tests execute the real deploy script against a recording Docker shim: they pin both the command order and
 * the guard that prevents a firmware build after an explicit refresh produced an unusable offline database.
 */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceScript = path.join(root, 'scripts/deploy.sh');
const fixtures = [];

async function fixture({ toolsPresent = true, verificationExit = 0, currentLayer = 'sha256:old-layer' } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'firmlab-deploy-grype-'));
  fixtures.push(dir);
  const scriptsDir = path.join(dir, 'scripts');
  const binDir = path.join(dir, 'bin');
  const log = path.join(dir, 'docker.log');
  await mkdir(scriptsDir);
  await mkdir(binDir);
  await copyFile(sourceScript, path.join(scriptsDir, 'deploy.sh'));
  await chmod(path.join(scriptsDir, 'deploy.sh'), 0o755);
  await writeFile(path.join(dir, 'Dockerfile.tools'), 'FROM scratch\n');
  await writeFile(path.join(dir, 'Dockerfile.firmware'), 'FROM scratch\n');
  await writeFile(
    path.join(binDir, 'docker'),
    `#!/usr/bin/env bash
printf '%q ' "$@" >> "$DOCKER_LOG"
printf '\\n' >> "$DOCKER_LOG"
if [ "$1" = image ] && [ "$2" = inspect ]; then
  if [ "$3" = "$TOOLS_IMAGE_TAG" ]; then
    [ "$TOOLS_PRESENT" = 1 ] || exit 1
    if [ "$4" = --format ]; then printf '%s\\n' "$CURRENT_LAYER"; fi
    exit 0
  fi
  if [ "$3" = sha256:candidate ]; then
    if [ "$4" = --format ]; then printf '%s\\n' "$CANDIDATE_LAYER"; fi
    exit 0
  fi
  if [ "$3" = firmlab-firmware:latest ]; then
    printf 'sha256:firmware\\n'
    exit 0
  fi
fi
if [ "$1" = inspect ]; then
  exit 1
fi
if [ "$1" = build ]; then
  previous=''
  for argument in "$@"; do
    if [ "$previous" = --iidfile ]; then printf 'sha256:candidate\\n' > "$argument"; fi
    previous="$argument"
  done
  exit 0
fi
if [ "$1" = run ]; then
  exit "$VERIFICATION_EXIT"
fi
exit 0
`,
  );
  await writeFile(path.join(binDir, 'lsof'), '#!/usr/bin/env bash\nexit 1\n');
  await writeFile(path.join(binDir, 'date'), "#!/usr/bin/env bash\nprintf '2026-10-14T12:34:56Z\\n'\n");
  await Promise.all(['docker', 'lsof', 'date'].map((name) => chmod(path.join(binDir, name), 0o755)));

  await run('git', ['init', '-q'], { cwd: dir });
  await run('git', ['config', 'user.email', 'tests@firmlab.invalid'], { cwd: dir });
  await run('git', ['config', 'user.name', 'FirmLab tests'], { cwd: dir });
  await run('git', ['add', '.'], { cwd: dir });
  await run('git', ['commit', '-qm', 'test fixture'], { cwd: dir });

  const env = {
    ...Object.fromEntries(Object.entries(process.env).filter(([name]) => name !== 'GRYPE_DB_REFRESH')),
    PATH: `${binDir}:${process.env.PATH}`,
    DOCKER_LOG: log,
    TOOLS_PRESENT: toolsPresent ? '1' : '0',
    VERIFICATION_EXIT: String(verificationExit),
    TOOLS_IMAGE_TAG: 'firmlab-tools:latest',
    CURRENT_LAYER: currentLayer,
    CANDIDATE_LAYER: 'sha256:new-layer',
  };
  return {
    dir,
    env,
    log: async () => (await readFile(log, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean),
  };
}

function commandIndex(commands, pattern) {
  return commands.findIndex((command) => pattern.test(command));
}

test('Dockerfile consumes the refresh argument in the baked Grype database layer', async () => {
  const dockerfile = await readFile(path.join(root, 'Dockerfile.tools'), 'utf8');
  const argument = dockerfile.indexOf('ARG GRYPE_DB_REFRESH=initial');
  const databaseLayer = dockerfile.indexOf("RUN bash -c 'set -o pipefail; mkdir -p /opt/grype-db", argument);
  assert.ok(argument > 0, 'the refresh argument must be declared');
  assert.ok(databaseLayer > argument, 'the database layer must consume the refresh argument after its declaration');
  assert.equal(
    dockerfile.slice(argument, databaseLayer).trim(),
    'ARG GRYPE_DB_REFRESH=initial',
    'the argument belongs immediately before the final database layer',
  );
  assert.match(
    dockerfile.slice(databaseLayer),
    /printf "%s\\n" "\$\{GRYPE_DB_REFRESH\}" > \/opt\/grype-db\/\.firmlab-refresh/,
  );
  assert.equal(dockerfile.indexOf('\nRUN ', databaseLayer + 1), -1, 'the Grype database must remain the final layer');
});

test('firmware Dockerfile accepts the same tools image selected by deploy', async () => {
  const dockerfile = await readFile(path.join(root, 'Dockerfile.firmware'), 'utf8');
  assert.match(dockerfile, /ARG TOOLS_IMAGE=firmlab-tools:latest/);
  assert.match(dockerfile, /FROM \$\{TOOLS_IMAGE\} AS runtime/);
});

test('--tools passes an explicit refresh key and verifies offline before the firmware build', async () => {
  const f = await fixture();
  const env = { ...f.env, GRYPE_DB_REFRESH: 'release-42' };
  await run('bash', ['scripts/deploy.sh', '--tools', '--build-only'], { cwd: f.dir, env });
  const commands = await f.log();
  const toolsBuild = commandIndex(commands, /build .*GRYPE_DB_REFRESH=release-42 .*Dockerfile\.tools/);
  const offlineCheck = commandIndex(commands, /run --rm --network none .*GRYPE_DB_AUTO_UPDATE=false/);
  const promotion = commandIndex(commands, /tag sha256:candidate firmlab-tools:latest/);
  const firmwareBuild = commandIndex(commands, /build .*Dockerfile\.firmware/);
  assert.ok(toolsBuild >= 0, commands.join('\n'));
  assert.match(commands[toolsBuild], /--iidfile/);
  assert.doesNotMatch(commands[toolsBuild], /-t firmlab-tools:latest/);
  assert.ok(offlineCheck > toolsBuild, commands.join('\n'));
  assert.match(commands[offlineCheck], /sha256:candidate/);
  assert.ok(promotion > offlineCheck, commands.join('\n'));
  assert.ok(firmwareBuild > promotion, commands.join('\n'));
  assert.match(commands[offlineCheck], /GRYPE_CHECK_FOR_APP_UPDATE=false/);
  assert.match(commands[offlineCheck], /GRYPE_DB_VALIDATE_AGE=false/);
});

test('--tools generates a fresh refresh key when none is overridden', async () => {
  const f = await fixture();
  await run('bash', ['scripts/deploy.sh', '--tools', '--build-only'], { cwd: f.dir, env: f.env });
  const commands = await f.log();
  assert.ok(
    commandIndex(commands, /build .*GRYPE_DB_REFRESH=2026-10-14T12:34:56Z .*Dockerfile\.tools/) >= 0,
    commands.join('\n'),
  );
});

test('a failed explicit offline verification blocks the firmware build', async () => {
  const f = await fixture({ verificationExit: 19 });
  await assert.rejects(
    run('bash', ['scripts/deploy.sh', '--tools', '--build-only'], { cwd: f.dir, env: f.env }),
    (error) => error.code === 19,
  );
  const commands = await f.log();
  assert.ok(commandIndex(commands, /run --rm --network none/) >= 0, commands.join('\n'));
  assert.equal(commandIndex(commands, /tag sha256:candidate firmlab-tools:latest/), -1, commands.join('\n'));
  assert.equal(commandIndex(commands, /build .*Dockerfile\.firmware/), -1, commands.join('\n'));
});

test('an unchanged final layer is refused before promotion', async () => {
  const f = await fixture({ currentLayer: 'sha256:new-layer' });
  await assert.rejects(
    run('bash', ['scripts/deploy.sh', '--tools', '--build-only'], { cwd: f.dir, env: f.env }),
    (error) => error.code === 1,
  );
  const commands = await f.log();
  assert.ok(commandIndex(commands, /image inspect firmlab-tools:latest --format/) >= 0, commands.join('\n'));
  assert.ok(commandIndex(commands, /image inspect sha256:candidate --format/) >= 0, commands.join('\n'));
  assert.equal(commandIndex(commands, /tag sha256:candidate firmlab-tools:latest/), -1, commands.join('\n'));
  assert.equal(commandIndex(commands, /build .*Dockerfile\.firmware/), -1, commands.join('\n'));
});

test('normal deploy reuses an existing tools image without refresh or verification', async () => {
  const f = await fixture();
  await run('bash', ['scripts/deploy.sh', '--build-only'], { cwd: f.dir, env: f.env });
  const commands = await f.log();
  assert.equal(commandIndex(commands, /build .*Dockerfile\.tools/), -1, commands.join('\n'));
  assert.equal(commandIndex(commands, /run --rm --network none/), -1, commands.join('\n'));
  const firmwareBuild = commandIndex(commands, /build .*Dockerfile\.firmware/);
  assert.ok(firmwareBuild >= 0, commands.join('\n'));
  assert.match(commands[firmwareBuild], /TOOLS_IMAGE=firmlab-tools:latest/);
});

test('a TOOLS_IMAGE override is also the firmware runtime base', async () => {
  const f = await fixture();
  const env = {
    ...f.env,
    TOOLS_IMAGE: 'registry.invalid/firmlab-tools:test',
    TOOLS_IMAGE_TAG: 'registry.invalid/firmlab-tools:test',
  };
  await run('bash', ['scripts/deploy.sh', '--build-only'], { cwd: f.dir, env });
  const commands = await f.log();
  const firmwareBuild = commandIndex(commands, /build .*Dockerfile\.firmware/);
  assert.ok(firmwareBuild >= 0, commands.join('\n'));
  assert.match(commands[firmwareBuild], /TOOLS_IMAGE=registry\.invalid\/firmlab-tools:test/);
});

test('a missing tools image keeps the first-build degradation path without the strict refresh guard', async () => {
  const f = await fixture({ toolsPresent: false });
  await run('bash', ['scripts/deploy.sh', '--build-only'], { cwd: f.dir, env: f.env });
  const commands = await f.log();
  const toolsBuild = commandIndex(commands, /build .*Dockerfile\.tools/);
  assert.ok(toolsBuild >= 0, commands.join('\n'));
  assert.doesNotMatch(commands[toolsBuild], /GRYPE_DB_REFRESH=/);
  assert.equal(commandIndex(commands, /run --rm --network none/), -1, commands.join('\n'));
  assert.ok(commandIndex(commands, /build .*Dockerfile\.firmware/) > toolsBuild, commands.join('\n'));
});

test.after(async () => {
  await Promise.all(fixtures.map((dir) => rm(dir, { recursive: true, force: true })));
});
