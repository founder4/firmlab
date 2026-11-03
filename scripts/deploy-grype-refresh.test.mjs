/**
 * The tools image is intentionally enormous, so refreshing Grype must invalidate only its final database layer, and a
 * rebuild must never leave the deployment with less than it had. These tests execute the real deploy script against
 * a recording Docker shim: they pin the recipe chosen for each Debian release, the refusals that keep an older or
 * poorer candidate from being promoted, the local-only resolution of the Debian 13 recipe's private bases, and the
 * capability inventory — whose probe loop runs for real here, over stub tools, against the table in tools.ts.
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
const RETAINED = 'homelab-rollback/firmlab-tools:20261022-pre-trixie';
const RENODE = 'homelab-candidate/renode:trixie-20261022';
const fixtures = [];

/** The capability table the API probes, read from tools.ts itself so the deploy guard cannot drift from it. */
async function declaredProbes() {
  const source = await readFile(path.join(root, 'apps/api/src/tools.ts'), 'utf8');
  const defaultMs = Number(source.match(/const DEFAULT_PROBE_TIMEOUT_MS = (\d+);/)[1]);
  const start = source.indexOf('const TOOLS: readonly ToolSpec[] = [');
  const table = source.slice(start, source.indexOf('\n];', start));
  // The two Python-hosted probes take their interpreter from the image environment; the shim points each at a stub.
  const interpreterStub = { angrPython: 'angr-python', fwhuntPython: 'fwhunt-python' };
  return table
    .split(/\bid: '/)
    .slice(1)
    .map((chunk) => {
      const bin = chunk.match(/\bbin: (?:'([^']+)'|(\w+)\(\))/);
      return {
        id: chunk.slice(0, chunk.indexOf("'")),
        bin: bin[1] ?? interpreterStub[bin[2]],
        probe: [...chunk.match(/\bprobe: \[([^\]]*)\]/)[1].matchAll(/'([^']*)'/g)].map((m) => m[1]),
        budget: String(Math.ceil(Number(chunk.match(/\btimeoutMs: (\d+)/)?.[1] ?? defaultMs) / 1000)),
        presenceOnly: /\bdetectByExistence: true/.test(chunk),
      };
    });
}
const declared = await declaredProbes();

const FAKE_TIMEOUT = [
  '#!/bin/bash',
  '[ "$1" = -k ] && shift 2',
  'budget=$1',
  'shift',
  '{ printf "%s" "$budget"; printf "\\t%s" "${1##*/}" "${@:2}"; printf "\\n"; } >> "$TIMEOUT_LOG"',
  'while IFS= read -r slow; do [ "$slow" = "${1##*/}" ] && exit 124; done < "${0%/*}/slow"',
  'command -v "$1" >/dev/null 2>&1 || exit 127',
  'exec "$@"',
  '',
].join('\n');

/** One image's PATH: a stub per declared tool ('ok' | 'error' | 'slow' | 'missing'), plus a recording `timeout`. */
async function stubTools(dir, behaviour, withTimeout) {
  await mkdir(dir, { recursive: true });
  const slow = [];
  for (const { bin } of declared) {
    const mode = behaviour[bin] ?? 'ok';
    if (mode === 'missing') continue;
    if (mode === 'slow') slow.push(`${bin}\n`);
    await writeFile(path.join(dir, bin), `#!/bin/bash\nexit ${mode === 'error' ? 1 : 0}\n`, { mode: 0o755 });
  }
  await writeFile(path.join(dir, 'slow'), slow.join(''));
  if (withTimeout) await writeFile(path.join(dir, 'timeout'), FAKE_TIMEOUT, { mode: 0o755 });
}

const DOCKER_SHIM = [
  '#!/usr/bin/env bash',
  'printf "%q " "$@" >> "$DOCKER_LOG"',
  'printf "\\n" >> "$DOCKER_LOG"',
  'if [ "$1" = image ] && [ "$2" = inspect ]; then',
  '  case "$3" in',
  '    "$TOOLS_IMAGE_TAG")',
  '      [ "$SHIM_TOOLS_PRESENT" = 1 ] || exit 1',
  '      if [ "$4" = --format ]; then printf "%s\\n" "$CURRENT_LAYER"; fi',
  '      exit 0 ;;',
  '    sha256:candidate)',
  '      if [ "$4" = --format ]; then printf "%s\\n" "$CANDIDATE_LAYER"; fi',
  '      exit 0 ;;',
  '    firmlab-firmware:latest) printf "sha256:firmware\\n"; exit 0 ;;',
  '  esac',
  "  case $'\\n'\"$LOCAL_IMAGES\"$'\\n' in *$'\\n'\"$3\"$'\\n'*) exit 0 ;; esac",
  '  exit 1',
  'fi',
  'if [ "$1" = inspect ]; then',
  '  [ -n "$SHIM_RUNNING_IMAGE" ] && [[ "$*" == *"{{.Image}}"* ]] && { printf "%s\\n" "$SHIM_RUNNING_IMAGE"; exit 0; }',
  '  exit 1',
  'fi',
  'if [ "$1" = buildx ] && [ "$2" = inspect ]; then printf "Name: default\\nDriver: %s\\n" "$BUILDX_DRIVER"; exit 0; fi',
  'if [ "$1" = build ]; then',
  '  previous=""',
  '  for argument in "$@"; do',
  '    if [ "$previous" = --iidfile ]; then printf "sha256:candidate\\n" > "$argument"; fi',
  '    previous="$argument"',
  '  done',
  '  exit 0',
  'fi',
  'if [ "$1" = run ]; then',
  '  args=("$@"); which=""; entry=""; after=()',
  '  for ((i = 1; i < ${#args[@]}; i++)); do',
  '    case "${args[i]}" in',
  '      "$TOOLS_IMAGE_TAG") which=current ;;',
  '      sha256:candidate) which=candidate ;;',
  '      "${SHIM_RUNNING_IMAGE:-<none>}") which=running ;;',
  '      *) continue ;;',
  '    esac',
  '    after=("${args[@]:i+1}"); break',
  '  done',
  '  previous=""; for argument in "$@"; do [ "$previous" = --entrypoint ] && entry=$argument; previous=$argument; done',
  '  if [ "$entry" = cat ]; then',
  '    case "$which" in current) v=$SHIM_CURRENT_DEBIAN ;; candidate) v=$SHIM_CANDIDATE_DEBIAN ;; *) v=$SHIM_RUNNING_DEBIAN ;; esac',
  '    printf "PRETTY_NAME=\\"Debian\\"\\nID=debian\\nVERSION_ID=\\"%s\\"\\n" "$v"',
  '    exit 0',
  '  fi',
  '  if [ "$entry" = bash ]; then',
  '    stubs="$FIXTURE/stubs/$which"',
  '    exec env -i PATH="$stubs" TIMEOUT_LOG="$FIXTURE/timeout-$which.log" \\',
  '      FIRMLAB_ANGR_PYTHON="$stubs/angr-python" FIRMLAB_FWHUNT_PYTHON="$stubs/fwhunt-python" /bin/bash "${after[@]}"',
  '  fi',
  '  exit "$VERIFICATION_EXIT"',
  'fi',
  'exit 0',
  '',
].join('\n');

async function fixture({
  toolsPresent = true,
  verificationExit = 0,
  currentLayer = 'sha256:old-layer',
  currentDebian = '12',
  candidateDebian = currentDebian,
  localImages = [],
  buildxDriver = 'docker',
  running = null,
  current = {},
  candidate = {},
  candidateTimeout = true,
} = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'firmlab-deploy-grype-'));
  fixtures.push(dir);
  const binDir = path.join(dir, 'bin');
  const log = path.join(dir, 'docker.log');
  await mkdir(path.join(dir, 'scripts'));
  await mkdir(binDir);
  await copyFile(sourceScript, path.join(dir, 'scripts/deploy.sh'));
  await chmod(path.join(dir, 'scripts/deploy.sh'), 0o755);
  await copyFile(path.join(root, 'Dockerfile.trixie'), path.join(dir, 'Dockerfile.trixie'));
  await writeFile(path.join(dir, 'Dockerfile.tools'), 'FROM scratch\n');
  await writeFile(path.join(dir, 'Dockerfile.firmware'), 'FROM scratch\n');
  await writeFile(path.join(binDir, 'docker'), DOCKER_SHIM, { mode: 0o755 });
  await writeFile(path.join(binDir, 'lsof'), '#!/usr/bin/env bash\nexit 1\n', { mode: 0o755 });
  await writeFile(path.join(binDir, 'date'), "#!/usr/bin/env bash\nprintf '2026-10-14T12:34:56Z\\n'\n", {
    mode: 0o755,
  });
  await stubTools(path.join(dir, 'stubs/current'), current, true);
  await stubTools(path.join(dir, 'stubs/candidate'), candidate, candidateTimeout);
  // The stubs and logs are outside the repository the script inspects; only the copied sources are committed.
  await writeFile(path.join(dir, '.gitignore'), 'bin/\nstubs/\n*.log\n');

  await run('git', ['init', '-q'], { cwd: dir });
  await run('git', ['config', 'user.email', 'tests@firmlab.invalid'], { cwd: dir });
  await run('git', ['config', 'user.name', 'FirmLab tests'], { cwd: dir });
  await run('git', ['add', '.'], { cwd: dir });
  await run('git', ['commit', '-qm', 'test fixture'], { cwd: dir });

  const env = {
    ...Object.fromEntries(Object.entries(process.env).filter(([name]) => name !== 'GRYPE_DB_REFRESH')),
    PATH: `${binDir}:${process.env.PATH}`,
    FIXTURE: dir,
    DOCKER_LOG: log,
    SHIM_TOOLS_PRESENT: toolsPresent ? '1' : '0',
    VERIFICATION_EXIT: String(verificationExit),
    TOOLS_IMAGE_TAG: 'firmlab-tools:latest',
    CURRENT_LAYER: currentLayer,
    CANDIDATE_LAYER: 'sha256:new-layer',
    SHIM_CURRENT_DEBIAN: currentDebian,
    SHIM_CANDIDATE_DEBIAN: candidateDebian,
    LOCAL_IMAGES: localImages.join('\n'),
    BUILDX_DRIVER: buildxDriver,
    SHIM_RUNNING_IMAGE: running ? 'sha256:running' : '',
    SHIM_RUNNING_DEBIAN: running?.debian ?? '',
  };
  const lines = async (file) =>
    (await readFile(path.join(dir, file), 'utf8').catch(() => '')).trim().split('\n').filter(Boolean);
  return {
    env,
    deploy: (args, extraEnv = {}) =>
      run('bash', ['scripts/deploy.sh', ...args], { cwd: dir, env: { ...env, ...extraEnv } }),
    log: () => lines('docker.log'),
    timeouts: (which) => lines(`timeout-${which}.log`),
  };
}

function commandIndex(commands, pattern) {
  return commands.findIndex((command) => pattern.test(command));
}

const TOOLS_PROMOTION = /^tag sha256:candidate firmlab-tools:latest/;
const FIRMWARE_BUILD = /^build .*Dockerfile\.firmware/;
const GRYPE_CHECK = /^run --rm --network none .*db\\ status/;

/** A refusal must leave the current image tagged and build nothing on top of a candidate. */
function assertNothingPromoted(commands) {
  assert.equal(commandIndex(commands, TOOLS_PROMOTION), -1, commands.join('\n'));
  assert.equal(commandIndex(commands, FIRMWARE_BUILD), -1, commands.join('\n'));
}

for (const recipe of ['Dockerfile.tools', 'Dockerfile.trixie']) {
  test(`${recipe} bakes the Grype database as its final layer, keyed by the refresh argument`, async () => {
    const dockerfile = await readFile(path.join(root, recipe), 'utf8');
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
    assert.match(dockerfile.slice(databaseLayer), /grype db update/);
    // Any instruction after it (the old `COPY --from=retained /opt/grype-db`) would make the last layer static.
    assert.doesNotMatch(
      dockerfile.slice(dockerfile.indexOf('\n', databaseLayer)),
      /^[A-Z]+ /m,
      'the Grype database must be the final layer',
    );
    assert.doesNotMatch(dockerfile, /COPY --from=\S+ \/opt\/grype-db/);
  });
}

test('firmware Dockerfile accepts the same tools image selected by deploy', async () => {
  const dockerfile = await readFile(path.join(root, 'Dockerfile.firmware'), 'utf8');
  assert.match(dockerfile, /ARG TOOLS_IMAGE=firmlab-tools:latest/);
  assert.match(dockerfile, /FROM \$\{TOOLS_IMAGE\} AS runtime/);
});

test('the Debian 12 recipe selects a same-architecture JDK for Ghidra', async () => {
  const dockerfile = await readFile(path.join(root, 'Dockerfile.tools'), 'utf8');
  assert.match(dockerfile, /amd64\) jdk_arch=x64/);
  assert.match(dockerfile, /arm64\) jdk_arch=aarch64/);
  assert.match(dockerfile, /linux\/\$\{jdk_arch\}\/jdk\/hotspot/);
  assert.doesNotMatch(dockerfile, /linux\/aarch64\/jdk\/hotspot/);
});

test('the Debian 12 recipe pins AFL++, angr and the dependency APIs angr consumes', async () => {
  const dockerfile = await readFile(path.join(root, 'Dockerfile.tools'), 'utf8');
  assert.match(dockerfile, /ARG AFLPP_REF=dbaf11913c1b2702dee5b4d3dcfffd52f1defe50/);
  assert.match(dockerfile, /d5f4f72c830526654bebbc637f6164a93c22d7309ce8ba73979abadc42ce5974/);
  assert.doesNotMatch(dockerfile, /git clone --depth 1 https:\/\/github\.com\/AFLplusplus\/AFLplusplus/);
  assert.match(dockerfile, /make -C \/afl -j4 afl-fuzz afl-showmap afl-tmin NO_NYX=1/);
  assert.doesNotMatch(dockerfile, /make -C \/afl source-only/);
  assert.match(
    dockerfile,
    /pip install --no-cache-dir 'angr\[unicorn\]==9\.2\.211' bitstring==4\.3\.1 pycparser==3\.0/,
  );
  assert.match(dockerfile, /test "\$RULE_COUNT" -gt 0/);
});

test('the Debian 13 recipe takes exactly the retained and Renode images from local build arguments', async () => {
  const dockerfile = await readFile(path.join(root, 'Dockerfile.trixie'), 'utf8');
  assert.match(dockerfile, new RegExp(`^ARG RETAINED_IMAGE=${RETAINED}$`, 'm'));
  assert.match(dockerfile, new RegExp(`^ARG RENODE_IMAGE=${RENODE}$`, 'm'));
  assert.match(dockerfile, /angr\[unicorn\]==9\.2\.213 bitstring==4\.3\.1 pycparser==3\.0/);
  // Every other base is public and digest-pinned, so a remote resolution of it is content-addressed.
  for (const [, ref] of dockerfile.matchAll(/^FROM (\S+)/gm)) {
    assert.ok(/^\$\{[A-Z_]+\}$/.test(ref) || /@sha256:[0-9a-f]{64}$/.test(ref), ref);
  }
});

test('--tools on Debian 12 passes an explicit refresh key and verifies offline before the firmware build', async () => {
  const f = await fixture();
  await f.deploy(['--tools', '--build-only'], { GRYPE_DB_REFRESH: 'release-42' });
  const commands = await f.log();
  const toolsBuild = commandIndex(commands, /^build .*GRYPE_DB_REFRESH=release-42 .*-f Dockerfile\.tools /);
  const offlineCheck = commandIndex(commands, GRYPE_CHECK);
  const promotion = commandIndex(commands, TOOLS_PROMOTION);
  const firmwareBuild = commandIndex(commands, FIRMWARE_BUILD);
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
  await f.deploy(['--tools', '--build-only']);
  const commands = await f.log();
  assert.ok(
    commandIndex(commands, /^build .*GRYPE_DB_REFRESH=2026-10-14T12:34:56Z .*Dockerfile\.tools/) >= 0,
    commands.join('\n'),
  );
});

test('--tools on Debian 13 rebuilds with Dockerfile.trixie from local bases only, never a pull', async () => {
  const f = await fixture({ currentDebian: '13', localImages: [RETAINED, RENODE] });
  await f.deploy(['--tools', '--build-only']);
  const commands = await f.log();
  const toolsBuild = commandIndex(commands, /^build .*GRYPE_DB_REFRESH=2026-10-14T12:34:56Z .*-f Dockerfile\.trixie /);
  assert.ok(toolsBuild >= 0, commands.join('\n'));
  assert.equal(commandIndex(commands, /Dockerfile\.tools/), -1, 'a Debian 13 base is never rebuilt as Debian 12');
  for (const base of [RETAINED, RENODE]) {
    const inspected = commandIndex(commands, new RegExp(`^image inspect ${base.replace(/[.]/g, '\\.')} $`));
    assert.ok(inspected >= 0 && inspected < toolsBuild, `${base} must be found locally before the build`);
  }
  const driverCheck = commandIndex(commands, /^buildx inspect/);
  assert.ok(driverCheck >= 0 && driverCheck < toolsBuild, commands.join('\n'));
  assert.equal(commandIndex(commands, /^pull |--pull/), -1, commands.join('\n'));
  const promotion = commandIndex(commands, TOOLS_PROMOTION);
  assert.ok(promotion > commandIndex(commands, GRYPE_CHECK), commands.join('\n'));
  assert.ok(commandIndex(commands, FIRMWARE_BUILD) > promotion, commands.join('\n'));
});

test('a missing local base is refused before BuildKit could resolve it remotely', async () => {
  const f = await fixture({ currentDebian: '13', localImages: [RETAINED] });
  await assert.rejects(
    f.deploy(['--tools', '--build-only']),
    (error) => error.code === 1 && error.stderr.includes(RENODE) && /registro/.test(error.stderr),
  );
  const commands = await f.log();
  assert.equal(commandIndex(commands, /^build /), -1, commands.join('\n'));
  assert.equal(commandIndex(commands, /^pull |--pull/), -1, commands.join('\n'));
  assertNothingPromoted(commands);
});

test('a builder that cannot see local images is refused for the Debian 13 recipe', async () => {
  const f = await fixture({ currentDebian: '13', localImages: [RETAINED, RENODE], buildxDriver: 'docker-container' });
  await assert.rejects(
    f.deploy(['--tools', '--build-only']),
    (error) => error.code === 1 && /docker-container/.test(error.stderr),
  );
  assert.equal(commandIndex(await f.log(), /^build /), -1);
});

test('a Debian 12 candidate never replaces a Debian 13 tools image', async () => {
  const f = await fixture({ currentDebian: '13', candidateDebian: '12', localImages: [RETAINED, RENODE] });
  await assert.rejects(
    f.deploy(['--tools', '--build-only']),
    (error) => error.code === 1 && /Debian 12 .*Debian 13/.test(error.stderr),
  );
  const commands = await f.log();
  assert.equal(commandIndex(commands, GRYPE_CHECK), -1, commands.join('\n'));
  assertNothingPromoted(commands);
});

test('an unknown Debian release is refused instead of choosing a recipe blind', async () => {
  const f = await fixture({ currentDebian: '14' });
  await assert.rejects(f.deploy(['--tools', '--build-only']), (error) => /Debian 14/.test(error.stderr));
  assert.equal(commandIndex(await f.log(), /^build /), -1);
});

test('every declared capability is probed in both images, bounded by its own budget', async () => {
  assert.ok(declared.length >= 28, `parsed ${declared.length} probes from tools.ts`);
  const f = await fixture({ currentDebian: '13', localImages: [RETAINED, RENODE] });
  const { stdout } = await f.deploy(['--tools', '--build-only']);
  const commands = await f.log();
  const probes = commands.filter((command) => /^run .*--entrypoint bash/.test(command));
  assert.equal(probes.length, 2, commands.join('\n'));
  for (const probe of probes) {
    assert.match(probe, /^run --rm --network none /);
    for (const variable of ['GRYPE_DB_AUTO_UPDATE', 'GRYPE_CHECK_FOR_APP_UPDATE', 'SYFT_CHECK_FOR_APP_UPDATE']) {
      assert.match(probe, new RegExp(`-e ${variable}=false`));
    }
  }
  assert.ok(
    commandIndex(commands, /^run .*--entrypoint bash firmlab-tools:latest/) < commandIndex(commands, /^build /),
  );
  for (const which of ['current', 'candidate']) {
    const executed = (await f.timeouts(which)).map((line) => line.split('\t'));
    const expected = declared.filter((p) => !p.presenceOnly).map((p) => [p.budget, p.bin, ...p.probe]);
    assert.deepEqual(executed, expected, `${which}: every executed probe mirrors tools.ts`);
  }
  for (const { id, presenceOnly } of declared) {
    assert.match(stdout, new RegExp(`^ {4}${id.replace(/[.]/g, '\\.')} ${presenceOnly ? 'present' : 'ok'}`, 'm'));
  }
});

test('a capability the current image had and the candidate lost refuses promotion, naming why', async () => {
  const f = await fixture({ candidate: { 'angr-python': 'slow', analyzeHeadless: 'missing', yara: 'error' } });
  await assert.rejects(f.deploy(['--tools', '--build-only']), (error) => {
    assert.equal(error.code, 1);
    for (const reason of ['angr timeout 30s', 'analyzeHeadless missing', 'yara error exit=1']) {
      assert.ok(error.stderr.includes(reason), error.stderr);
    }
    return true;
  });
  const commands = await f.log();
  assert.equal(commandIndex(commands, GRYPE_CHECK), -1, commands.join('\n'));
  assertNothingPromoted(commands);
});

test('a tool missing from both images is a reported degradation, not a regression', async () => {
  const f = await fixture({ current: { 'angr-python': 'error' }, candidate: { 'angr-python': 'missing' } });
  const { stdout, stderr } = await f.deploy(['--tools', '--build-only']);
  assert.match(stdout, /^ {4}angr missing$/m);
  assert.match(stderr, /no que cada herramienta funcione/);
  assert.ok(commandIndex(await f.log(), TOOLS_PROMOTION) >= 0);
});

test('an image whose probes cannot be bounded is refused instead of reporting every tool missing', async () => {
  const f = await fixture({ candidateTimeout: false });
  await assert.rejects(
    f.deploy(['--tools', '--build-only']),
    (error) => error.code === 1 && /timeout/.test(error.stderr) && /inventariar/.test(error.stderr),
  );
  assertNothingPromoted(await f.log());
});

test('a failed explicit offline verification blocks the firmware build', async () => {
  const f = await fixture({ verificationExit: 19 });
  await assert.rejects(f.deploy(['--tools', '--build-only']), (error) => error.code === 19);
  const commands = await f.log();
  assert.ok(commandIndex(commands, GRYPE_CHECK) >= 0, commands.join('\n'));
  assertNothingPromoted(commands);
});

for (const currentDebian of ['12', '13']) {
  test(`an unchanged final layer is refused before promotion (Debian ${currentDebian})`, async () => {
    const f = await fixture({ currentDebian, currentLayer: 'sha256:new-layer', localImages: [RETAINED, RENODE] });
    await assert.rejects(
      f.deploy(['--tools', '--build-only']),
      (error) => error.code === 1 && /capa final de Grype no cambió/.test(error.stderr),
    );
    const commands = await f.log();
    assert.ok(commandIndex(commands, /^image inspect firmlab-tools:latest --format/) >= 0, commands.join('\n'));
    assert.ok(commandIndex(commands, /^image inspect sha256:candidate --format/) >= 0, commands.join('\n'));
    assertNothingPromoted(commands);
  });
}

test('normal deploy reuses an existing tools image without refresh or verification', async () => {
  const f = await fixture();
  await f.deploy(['--build-only']);
  const commands = await f.log();
  assert.equal(commandIndex(commands, /^build .*Dockerfile\.tools/), -1, commands.join('\n'));
  assert.equal(commandIndex(commands, /^run /), -1, commands.join('\n'));
  const firmwareBuild = commandIndex(commands, FIRMWARE_BUILD);
  assert.ok(firmwareBuild >= 0, commands.join('\n'));
  assert.match(commands[firmwareBuild], /TOOLS_IMAGE=firmlab-tools:latest/);
});

test('a TOOLS_IMAGE override is also the firmware runtime base', async () => {
  const f = await fixture();
  const tag = 'registry.invalid/firmlab-tools:test';
  await f.deploy(['--build-only'], { TOOLS_IMAGE: tag, TOOLS_IMAGE_TAG: tag });
  const commands = await f.log();
  const firmwareBuild = commandIndex(commands, FIRMWARE_BUILD);
  assert.ok(firmwareBuild >= 0, commands.join('\n'));
  assert.match(commands[firmwareBuild], /TOOLS_IMAGE=registry\.invalid\/firmlab-tools:test/);
});

test('a missing tools image keeps the first-build degradation path without the strict refresh guard', async () => {
  const f = await fixture({ toolsPresent: false });
  await f.deploy(['--build-only']);
  const commands = await f.log();
  const toolsBuild = commandIndex(commands, /^build .*Dockerfile\.tools/);
  assert.ok(toolsBuild >= 0, commands.join('\n'));
  assert.doesNotMatch(commands[toolsBuild], /GRYPE_DB_REFRESH=/);
  assert.equal(commandIndex(commands, /^run /), -1, commands.join('\n'));
  assert.ok(commandIndex(commands, FIRMWARE_BUILD) > toolsBuild, commands.join('\n'));
});

for (const args of [['--build-only'], ['--tools', '--build-only']]) {
  test(`a missing tools tag beside a Debian 13 container is not rebuilt as Debian 12 (${args.join(' ')})`, async () => {
    const f = await fixture({ toolsPresent: false, running: { debian: '13' } });
    await assert.rejects(f.deploy(args), (error) => error.code === 1 && /Debian 13/.test(error.stderr));
    const commands = await f.log();
    assert.equal(commandIndex(commands, /^build /), -1, commands.join('\n'));
  });
}

test('a missing tools tag beside a Debian 12 container keeps the first build', async () => {
  const f = await fixture({ toolsPresent: false, running: { debian: '12' } });
  await f.deploy(['--build-only']);
  assert.ok(commandIndex(await f.log(), /^build .*-t firmlab-tools:latest/) >= 0);
});

test.after(async () => {
  await Promise.all(fixtures.map((dir) => rm(dir, { recursive: true, force: true })));
});
