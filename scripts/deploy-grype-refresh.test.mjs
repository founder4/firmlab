/**
 * The tools image is intentionally enormous, so refreshing Grype must invalidate only its final database layer, and a
 * rebuild must never leave the deployment with less than it had. These tests execute the real deploy script against
 * a recording Docker shim: they pin the recipe chosen for each Debian release, the refusals that keep an older or
 * poorer candidate from being promoted, the local-only resolution of the Debian 13 recipe's private bases, and the
 * capability inventory — whose probe loop runs for real here, over stub tools, against the table in tools.ts.
 */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RETAINED = 'homelab-rollback/firmlab-tools:20261022-pre-trixie';
const RENODE = 'homelab-candidate/renode:trixie-20261022';
const fixtures = [];
const BASELINE_ID = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const inputId = (ref) => `sha256:${createHash('sha256').update(ref).digest('hex')}`;

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
  '  if [ "$5" = "{{.Id}}" ]; then',
  '    [ -f "$FIXTURE/ambiguous-alias" ] && [[ "$3" == firmlab-candidate-input/* ]] && exit 17',
  '    if [ "$3" = "$TOOLS_IMAGE_TAG" ] && [ "$SHIM_TOOLS_PRESENT" = 1 ]; then printf "%s\\n" "$BASELINE_ID"; exit 0; fi',
  '    if [ "$3" = "$CANDIDATE_TAG_REF" ] && [ -f "$FIXTURE/built" ]; then printf "%s\\n" "${SHIM_CANDIDATE_TAG_ID:-$CANDIDATE_ID}"; exit 0; fi',
  `    id=$(printf '%s\\n' "$LOCAL_IMAGE_IDS" | awk -F '\\t' -v ref="$3" '$1 == ref {print $2; exit}')`,
  `    [ -n "$id" ] || id=$(awk -F '\\t' -v ref="$3" '$1 == ref {print $2; exit}' "$FIXTURE/aliases" 2>/dev/null)`,
  '    [ -n "$id" ] && { printf "%s\\n" "$id"; exit 0; }',
  '  fi',
  '  case "$3" in',
  '    "$TOOLS_IMAGE_TAG"|"$BASELINE_ID")',
  '      [ "$SHIM_TOOLS_PRESENT" = 1 ] || exit 1',
  '      if [ "$4" = --format ]; then printf "%s\\n" "$CURRENT_LAYER"; fi',
  '      exit 0 ;;',
  '    sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc)',
  '      if [ "$4" = --format ]; then printf "%s\\n" "$SHIM_CANDIDATE_LAYER"; fi',
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
  'if [ "$1" = tag ]; then',
  '  [ -f "$FIXTURE/report/inputs.tsv" ] && cp "$FIXTURE/report/inputs.tsv" "$FIXTURE/manifest-before-${3##*:}"',
  '  [ "${SHIM_SECOND_TAG_FAIL:-0}" = 1 ] && [ -f "$FIXTURE/aliases" ] && exit 18',
  '  printf "%s\\t%s\\n" "$3" "$2" >> "$FIXTURE/aliases"',
  '  [ "${SHIM_ALIAS_RECEIPT_FAIL:-0}" = 1 ] && touch "$FIXTURE/ambiguous-alias"',
  '  exit 0',
  'fi',
  'if [ "$1" = build ]; then',
  '  touch "$FIXTURE/built"',
  '  [ "${SHIM_RECIPE_MUTATION_AT:-}" = build ] && printf "FROM evil/unpinned:latest\\n" >> "$SHIM_RECIPE_PATH"',
  '  [ "${SHIM_SOURCE_MUTATION:-0}" = 1 ] && printf "changed\\n" >> Dockerfile.tools',
  '  [ "${SHIM_ALIAS_DRIFT:-0}" = 1 ] && sed -i.bak \'s/sha256:/broken:/g\' "$FIXTURE/aliases"',
  '  previous=""',
  '  for argument in "$@"; do',
  '    if [ "$previous" = --iidfile ]; then [ "${SHIM_IID_MISSING:-0}" = 1 ] || printf "%s\\n" "${SHIM_IID:-$CANDIDATE_ID}" > "$argument"; fi',
  '    previous="$argument"',
  '  done',
  '  exit 0',
  'fi',
  'if [ "$1" = run ]; then',
  '  args=("$@"); which=""; entry=""; after=()',
  '  for ((i = 1; i < ${#args[@]}; i++)); do',
  '    case "${args[i]}" in',
  '      "$TOOLS_IMAGE_TAG"|"$BASELINE_ID") which=current ;;',
  '      sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc) which=candidate ;;',
  '      "${SHIM_RUNNING_IMAGE:-<none>}") which=running ;;',
  '      *) continue ;;',
  '    esac',
  '    after=("${args[@]:i+1}"); break',
  '  done',
  '  previous=""; for argument in "$@"; do [ "$previous" = --entrypoint ] && entry=$argument; previous=$argument; done',
  '  if [ "$entry" = cat ]; then',
  '    [ "$which" = candidate ] && [ "${SHIM_OS_FAILURE:-0}" = 1 ] && exit 19',
  '    case "$which" in current) v=$SHIM_CURRENT_DEBIAN ;; candidate) v=$SHIM_CANDIDATE_DEBIAN ;; *) v=$SHIM_RUNNING_DEBIAN ;; esac',
  '    printf "PRETTY_NAME=\\"Debian\\"\\nID=debian\\nVERSION_ID=\\"%s\\"\\n" "$v"',
  '    exit 0',
  '  fi',
  '  if [ "$entry" = timeout ]; then',
  '    if [ "$SHIM_REAL_GRYPE_CHECK" = 1 ]; then exec /bin/bash "${after[@]:4}"; fi',
  '    exit "$VERIFICATION_EXIT"',
  '  fi',
  '  if [ "$entry" = bash ]; then',
  '    [ "$which" = current ] && [ "${SHIM_RECIPE_MUTATION_AT:-}" = baseline ] && printf "# changed recipe bytes\\n" >> "$SHIM_RECIPE_PATH"',
  '    if [ "$which" = "${SHIM_INCOMPLETE:-none}" ]; then printf "binwalk ok\\n"; exit 0; fi',
  '    if [ "$which" = "${SHIM_UNKNOWN_STATUS:-none}" ]; then printf "%s\\n" "${after[3]}" | awk \'{print $1, "unknown"}\'; exit 0; fi',
  '    [ "$which" = candidate ] && [ "${SHIM_BASH_MISSING:-0}" = 1 ] && exit 127',
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
  currentLayer = 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  currentDebian = '12',
  candidateDebian = currentDebian,
  localImages = [],
  buildxDriver = 'docker',
  running = null,
  current = {},
  candidate = {},
  candidateTimeout = true,
  currentTimeout = true,
  grypeStatus = null,
  candidateLayer = 'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
} = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'firmlab-deploy-grype-'));
  fixtures.push(dir);
  const binDir = path.join(dir, 'bin');
  const log = path.join(dir, 'docker.log');
  await mkdir(path.join(dir, 'scripts'));
  await mkdir(binDir);
  for (const script of ['deploy.sh', 'tools-candidate.sh', 'tools-candidate-lib.sh']) {
    await copyFile(path.join(root, 'scripts', script), path.join(dir, 'scripts', script));
    await chmod(path.join(dir, 'scripts', script), 0o755);
  }
  await copyFile(path.join(root, 'Dockerfile.trixie'), path.join(dir, 'Dockerfile.trixie'));
  await writeFile(path.join(dir, 'Dockerfile.tools'), 'FROM scratch\n');
  await writeFile(path.join(dir, 'Dockerfile.firmware'), 'FROM scratch\n');
  await writeFile(path.join(binDir, 'docker'), DOCKER_SHIM, { mode: 0o755 });
  await writeFile(path.join(binDir, 'grype'), '#!/bin/bash\ncat "$FIXTURE/grype-status.json"\n', { mode: 0o755 });
  if (grypeStatus) {
    const database = path.join(dir, 'vulnerability.db');
    await writeFile(database, '');
    await truncate(database, 101 * 1024 * 1024);
    await writeFile(path.join(dir, 'grype-status.json'), JSON.stringify({ path: database, ...grypeStatus }));
  }
  await writeFile(path.join(binDir, 'lsof'), '#!/usr/bin/env bash\nexit 1\n', { mode: 0o755 });
  await writeFile(path.join(binDir, 'date'), "#!/usr/bin/env bash\nprintf '2026-10-14T12:34:56Z\\n'\n", {
    mode: 0o755,
  });
  await stubTools(path.join(dir, 'stubs/current'), current, currentTimeout);
  await stubTools(path.join(dir, 'stubs/candidate'), candidate, candidateTimeout);
  // The stubs and logs are outside the repository the script inspects; only the copied sources are committed.
  await writeFile(
    path.join(dir, '.gitignore'),
    'bin/\nstubs/\n*.log\nreport*/\naliases*\nbuilt\nmanifest-*\nambiguous-alias\ndata/\n',
  );

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
    SHIM_REAL_GRYPE_CHECK: grypeStatus ? '1' : '0',
    TOOLS_IMAGE_TAG: 'firmlab-tools:latest',
    CURRENT_LAYER: currentLayer,
    SHIM_CANDIDATE_LAYER: candidateLayer,
    SHIM_CURRENT_DEBIAN: currentDebian,
    SHIM_CANDIDATE_DEBIAN: candidateDebian,
    BASELINE_ID,
    CANDIDATE_ID: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    CANDIDATE_TAG_REF: CANDIDATE_TAG,
    LOCAL_IMAGE_IDS: localImages.map((ref) => `${ref}\t${inputId(ref)}`).join('\n'),
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
      run('/bin/bash', ['scripts/deploy.sh', ...args], { cwd: dir, env: { ...env, ...extraEnv } }),
    candidate: (args, extraEnv = {}) =>
      run('/bin/bash', ['scripts/tools-candidate.sh', '--report', path.join(dir, 'report'), ...args], {
        cwd: dir,
        env: { ...env, ...extraEnv },
      }),
    report: (file) => readFile(path.join(dir, 'report', file), 'utf8'),
    dir,
    log: () => lines('docker.log'),
    timeouts: (which) => lines(`timeout-${which}.log`),
  };
}

function commandIndex(commands, pattern) {
  return commands.findIndex((command) => pattern.test(command));
}

const TOOLS_PROMOTION =
  /^tag sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc firmlab-tools:latest/;
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
  assert.match(dockerfile, /amd64\) qemu_target=x86_64/);
  assert.match(dockerfile, /arm64\) qemu_target=aarch64/);
  assert.match(dockerfile, /CPU_TARGET="\$qemu_target"/);
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
  assert.match(
    dockerfile,
    /apt-get install -y --no-install-recommends[\s\S]*binutils-arm-none-eabi[\s\S]*rm -rf \/var\/lib\/apt\/lists\/\*/,
  );
  assert.match(dockerfile, /gcc-mipsel-linux-gnu libc6-dev-mipsel-cross/);
  assert.match(dockerfile, /for guest in mips mipsel; do[\s\S]*CPU_TARGET="\$guest"/);
  assert.match(
    dockerfile,
    /COPY --from=aflbuild \/out\/afl-qemu-trace-mips \/out\/afl-qemu-trace-mipsel \/usr\/local\/bin\//,
  );
  assert.match(
    dockerfile,
    /COPY --from=aflbuild \/out\/libaflppdesock-mipsel-uclibc\.so \/opt\/desock\/libaflppdesock-mipsel-uclibc\.so/,
  );
  assert.match(dockerfile, /Shared library: \\\[libdl\.so\.0\\\]/);
  assert.match(dockerfile, /grep -q 'libc\.so\.6'/);
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
  assert.match(commands[offlineCheck], /sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/);
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
    const f = await fixture({
      currentDebian,
      currentLayer: 'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
      localImages: [RETAINED, RENODE],
    });
    await assert.rejects(
      f.deploy(['--tools', '--build-only']),
      (error) => error.code === 1 && /capa final de Grype no cambió/.test(error.stderr),
    );
    const commands = await f.log();
    assert.ok(commandIndex(commands, /^image inspect firmlab-tools:latest --format/) >= 0, commands.join('\n'));
    assert.ok(
      commandIndex(
        commands,
        /^image inspect sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --format/,
      ) >= 0,
      commands.join('\n'),
    );
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

// --- scripts/tools-candidate.sh: the half of --tools that builds and validates but never promotes -------------------

const INPUTS = ['firmlab-campaign-test/retained-src:abc', 'firmlab-campaign-test/renode-src:abc'];
const CANDIDATE_TAG = 'firmlab-campaign-test/tools:trixie-t1';
const WITH_INPUTS = ['--retained', INPUTS[0], '--renode', INPUTS[1]];

/** Nothing a candidate run does may move a shared ref or reach a running service. */
function assertCandidateOnly(commands) {
  for (const command of commands.filter((c) => /^tag /.test(c))) {
    assert.match(command, /^tag sha256:[0-9a-f]{64} firmlab-candidate-input\//, command);
  }
  assert.equal(commandIndex(commands, /compose|^exec |^stop |^restart |^rm |^rmi |^push |Dockerfile\.firmware/), -1);
  for (const command of commands.filter((c) => /^run /.test(c))) {
    assert.match(command, /^run --rm --network none /, command);
    // Docker's own options end at the image; what follows is the probe script, which says `command -v`.
    assert.doesNotMatch(command.split(' --entrypoint ')[0], /(^| )(-v|--volume|--mount) /, command);
  }
  for (const command of commands.filter((c) => /^build /.test(c))) {
    assert.match(command, new RegExp(` -t ${CANDIDATE_TAG.replace(/[.]/g, '\\.')} `), command);
    assert.doesNotMatch(command, / -t (firmlab-tools|firmlab-firmware|firmlab):/, command);
  }
}

test('a candidate is built under its own tag from explicit local inputs, inventoried, and never promoted', async () => {
  const f = await fixture({ currentDebian: '13', localImages: INPUTS });
  const { stdout, stderr } = await f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS], { GRYPE_DB_REFRESH: 'k1' });
  const commands = await f.log();
  assertCandidateOnly(commands);
  const build = commands.find((c) => /^build /.test(c));
  for (const part of [
    'RETAINED_IMAGE=firmlab-candidate-input/',
    'RENODE_IMAGE=firmlab-candidate-input/',
    'GRYPE_DB_REFRESH=k1',
  ]) {
    assert.ok(build.includes(`--build-arg ${part}`), build);
  }
  assert.match(build, /-f Dockerfile\.trixie \.\s*$/);
  // The baseline is inventoried before the build, so a hung or broken baseline costs no build time.
  assert.ok(commandIndex(commands, /^run .*--entrypoint bash sha256:b{64}/) < commandIndex(commands, /^build /));
  for (const which of ['current', 'candidate']) {
    const executed = (await f.timeouts(which)).map((line) => line.split('\t'));
    const expected = declared.filter((p) => !p.presenceOnly).map((p) => [p.budget, p.bin, ...p.probe]);
    assert.deepEqual(executed, expected, `${which}: every executed probe mirrors tools.ts`);
  }
  assert.match(await f.report('verdict.txt'), /^accepted\n/);
  const inputs = await f.report('inputs.tsv');
  assert.match(inputs, new RegExp(`^RETAINED_IMAGE\t${INPUTS[0]}\t${inputId(INPUTS[0])}$`, 'm'));
  assert.match(inputs, new RegExp(`^RENODE_IMAGE\t${INPUTS[1]}\t${inputId(INPUTS[1])}$`, 'm'));
  assert.match(inputs, /^baseline\tfirmlab-tools:latest\tsha256:b{64}$/m);
  assert.match(
    inputs,
    new RegExp(
      `^candidate\t${CANDIDATE_TAG}\tsha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc$`,
      'm',
    ),
  );
  assert.equal((await f.report('inventory-candidate.txt')).trim().split('\n').length, declared.length);
  assert.match(stdout, /aceptada sin promoción/);
  assert.match(stderr, /no que cada herramienta funcione/);
});

test('without overrides a candidate freezes the recipe defaults locally', async () => {
  const f = await fixture({ currentDebian: '13', localImages: [RETAINED, RENODE] });
  await f.candidate(['--tag', CANDIDATE_TAG]);
  const build = (await f.log()).find((c) => /^build /.test(c));
  assert.match(build, /--build-arg RETAINED_IMAGE=firmlab-candidate-input\//);
  assert.match(build, /--build-arg RENODE_IMAGE=firmlab-candidate-input\//);

  const missing = await fixture({ currentDebian: '13', localImages: [RETAINED] });
  await assert.rejects(
    missing.candidate(['--tag', CANDIDATE_TAG]),
    (error) => error.code === 1 && error.stderr.includes(RENODE) && /registro/.test(error.stderr),
  );
  assert.equal(commandIndex(await missing.log(), /^build /), -1);
});

test('a candidate tag that names a shared, implicit or input ref is refused before Docker builds anything', async () => {
  const f = await fixture({ currentDebian: '13', localImages: INPUTS });
  for (const tag of [
    'firmlab-tools:latest',
    'firmlab-tools:trixie-candidate',
    'docker.io/library/firmlab-firmware:next',
    'firmlab:dev',
    'homelab-rollback/firmlab-tools:20261108',
    'homelab-candidate/renode:trixie-20261108',
    'firmlab-campaign-test/tools',
    'firmlab-campaign-test/tools:latest',
    `firmlab-campaign-test/tools@sha256:${'0'.repeat(64)}`,
    INPUTS[0],
  ]) {
    await assert.rejects(f.candidate(['--tag', tag, ...WITH_INPUTS]), (error) => error.code === 1, tag);
  }
  await assert.rejects(f.candidate(WITH_INPUTS), (error) => error.code === 1 && /--tag/.test(error.stderr));
  assert.equal(commandIndex(await f.log(), /^build |^run /), -1);
});

test('an existing candidate tag is never overwritten', async () => {
  const f = await fixture({ currentDebian: '13', localImages: [...INPUTS, CANDIDATE_TAG] });
  await assert.rejects(
    f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]),
    (error) => error.code === 1 && /ya existe/.test(error.stderr),
  );
  assert.equal(commandIndex(await f.log(), /^build /), -1);
});

test('an override for a base the recipe does not take, or a missing override image, is refused', async () => {
  const f = await fixture({ currentDebian: '13', localImages: INPUTS });
  await assert.rejects(
    f.candidate(['--tag', CANDIDATE_TAG, '--recipe', 'Dockerfile.tools', '--retained', INPUTS[0]]),
    (error) => error.code === 1 && /no toma ninguna base de RETAINED_IMAGE/.test(error.stderr),
  );
  await assert.rejects(
    f.candidate([
      '--tag',
      CANDIDATE_TAG,
      '--retained',
      INPUTS[0],
      '--renode',
      'firmlab-campaign-test/absent:1',
      '--report',
      path.join(f.dir, 'report-missing'),
    ]),
    (error) => error.code === 1 && error.stderr.includes('firmlab-campaign-test/absent:1'),
  );
  assert.equal(commandIndex(await f.log(), /^build /), -1);
});

test('a builder that cannot see local images is refused for a candidate too', async () => {
  const f = await fixture({ currentDebian: '13', localImages: INPUTS, buildxDriver: 'docker-container' });
  await assert.rejects(
    f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]),
    (error) => error.code === 1 && /docker-container/.test(error.stderr),
  );
  assert.equal(commandIndex(await f.log(), /^build /), -1);
});

test('a dirty tree needs --allow-dirty and is then stamped as dirty', async () => {
  const f = await fixture({ currentDebian: '13', localImages: INPUTS });
  await writeFile(path.join(f.dir, 'untracked.txt'), 'x\n');
  await assert.rejects(
    f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]),
    (error) => error.code === 1 && /sucio/.test(error.stderr),
  );
  assert.equal(commandIndex(await f.log(), /^build /), -1);
  await f.candidate([
    '--tag',
    CANDIDATE_TAG,
    ...WITH_INPUTS,
    '--allow-dirty',
    '--report',
    path.join(f.dir, 'report-dirty'),
  ]);
  assert.match(
    (await f.log()).find((c) => /^build /.test(c)),
    /revision=[0-9a-f]{40}-dirty-[0-9a-f]{64} /,
  );
});

for (const [name, options, reason] of [
  ['lost a capability', { candidate: { yara: 'error', 'angr-python': 'slow' } }, /angr timeout 30s;yara error exit=1/],
  ['failed the offline Grype check', { verificationExit: 1 }, /Grype no es válida offline/],
  [
    'kept the baseline final layer',
    {
      currentLayer: 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      candidateLayer: 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    },
    /capa final/,
  ],
  ['is an older Debian', { candidateDebian: '12' }, /Debian 12 y firmlab-tools:latest es Debian 13/],
]) {
  test(`a built candidate that ${name} is rejected with exit 4 and a written verdict, never promoted`, async () => {
    const f = await fixture({ currentDebian: '13', localImages: INPUTS, ...options });
    await assert.rejects(f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]), (error) => {
      assert.equal(error.code, 4, error.stderr);
      assert.match(error.stderr, reason);
      return true;
    });
    const verdict = await f.report('verdict.txt');
    assert.match(verdict, /^rejected\n/);
    assert.match(verdict, reason);
    assertCandidateOnly(await f.log());
  });
}

// Verified source defects: these assertions fail against the first-wave candidate script.
for (const [name, options] of [
  ['missing baseline', { toolsPresent: false }],
  ['unknown baseline Debian', { currentDebian: 'unknown' }],
  ['empty baseline layer', { currentLayer: '' }],
]) {
  test(`candidate refuses ${name} before building`, async () => {
    const f = await fixture({ localImages: INPUTS, ...options });
    await assert.rejects(f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]), (e) => e.code === 1);
    assert.equal(commandIndex(await f.log(), /^build /), -1);
  });
}

test('a candidate without timeout writes a rejected verdict and exits 4', async () => {
  const f = await fixture({ localImages: INPUTS, candidateTimeout: false });
  await assert.rejects(f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]), (e) => e.code === 4);
  assert.match(await f.report('verdict.txt'), /^rejected\n/);
});

for (const host of ['index.docker.io', 'registry-1.docker.io']) {
  test(`candidate refuses shared Docker Hub alias ${host}`, async () => {
    const f = await fixture({ localImages: INPUTS });
    await assert.rejects(f.candidate(['--tag', `${host}/library/firmlab-tools:next`, ...WITH_INPUTS]));
    assert.equal(commandIndex(await f.log(), /^build /), -1);
  });
}

test('a candidate refuses an unknown builder driver', async () => {
  const f = await fixture({ localImages: INPUTS, buildxDriver: '' });
  await assert.rejects(f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]));
  assert.equal(commandIndex(await f.log(), /^build /), -1);
});

test('candidate refuses reuse of an existing report directory and preserves its verdict', async () => {
  const f = await fixture({ localImages: INPUTS });
  await mkdir(path.join(f.dir, 'report'));
  await writeFile(path.join(f.dir, 'report/verdict.txt'), 'accepted\nold run\n');
  await assert.rejects(f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]), (e) =>
    /informe.*ya existe/.test(e.stderr),
  );
  assert.equal(await f.report('verdict.txt'), 'accepted\nold run\n');
  assert.equal(commandIndex(await f.log(), /^build /), -1);
});

for (const [name, options, env] of [
  ['without bash', {}, { SHIM_BASH_MISSING: '1' }],
  ['with unreadable os-release', {}, { SHIM_OS_FAILURE: '1' }],
  ['with unknown Debian', { candidateDebian: 'unknown' }, {}],
  ['with incomplete inventory', {}, { SHIM_INCOMPLETE: 'candidate' }],
  ['with unknown probe states', {}, { SHIM_UNKNOWN_STATUS: 'candidate' }],
  ['with missing iidfile', {}, { SHIM_IID_MISSING: '1' }],
  ['with malformed iidfile', {}, { SHIM_IID: 'sha256:fake' }],
  ['with empty layer metadata', { candidateLayer: '' }, {}],
  ['with malformed layer metadata', { candidateLayer: 'unknown' }, {}],
  ['with changed source', {}, { SHIM_SOURCE_MUTATION: '1' }],
  ['with changed input alias', {}, { SHIM_ALIAS_DRIFT: '1' }],
  ['with changed candidate tag', {}, { SHIM_CANDIDATE_TAG_ID: BASELINE_ID }],
]) {
  test(`built candidate ${name} records rejection and exit 4`, async () => {
    const f = await fixture({ localImages: INPUTS, ...options });
    await assert.rejects(f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS], env), (e) => e.code === 4);
    assert.match(await f.report('verdict.txt'), /^rejected\n/);
    assert.equal(commandIndex(await f.log(), /^build /) >= 0, true);
    assertCandidateOnly(await f.log());
  });
}

for (const [name, options, env] of [
  ['without timeout', { currentTimeout: false }, {}],
  ['with incomplete inventory', {}, { SHIM_INCOMPLETE: 'current' }],
  ['with unknown probe states', {}, { SHIM_UNKNOWN_STATUS: 'current' }],
  ['with malformed layer metadata', { currentLayer: 'unknown' }, {}],
  ['with unsupported Debian', { currentDebian: '14' }, {}],
]) {
  test(`baseline ${name} refuses before build`, async () => {
    const f = await fixture({ localImages: INPUTS, ...options });
    await assert.rejects(f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS], env), (e) => e.code === 1);
    assert.equal(commandIndex(await f.log(), /^build /), -1);
  });
}

test('source fingerprint distinguishes tracked and untracked content at the same HEAD', async () => {
  const f = await fixture();
  const fingerprint = async () =>
    (
      await run('/bin/bash', ['-c', '. scripts/tools-candidate-lib.sh; source_fingerprint'], { cwd: f.dir })
    ).stdout.trim();
  const clean = await fingerprint();
  await writeFile(path.join(f.dir, 'new source.txt'), 'first');
  const first = await fingerprint();
  await writeFile(path.join(f.dir, 'new source.txt'), 'second');
  const second = await fingerprint();
  await writeFile(path.join(f.dir, 'Dockerfile.tools'), 'FROM scratch\nLABEL changed=true\n');
  const tracked = await fingerprint();
  assert.equal(new Set([clean, first, second, tracked]).size, 4);
  assert.match(tracked, /^[0-9a-f]{64}$/);
});

for (const [name, fields, accepted] of [
  ['valid', {}, true],
  ['invalid', { valid: false }, false],
  ['unknown schema', { schemaVersion: null }, false],
  ['unknown build date', { built: '' }, false],
  ['missing database', { path: '/nonexistent/fixture.db' }, false],
]) {
  test(`offline Grype JSON ${name} is parsed by the actual validation shell`, async () => {
    const f = await fixture({
      grypeStatus: { valid: true, schemaVersion: 'v6.1.10', built: '2026-11-07T06:18:48Z', ...fields },
    });
    const command = run(
      '/bin/bash',
      ['-c', '. scripts/tools-candidate-lib.sh; verify_candidate_grype "$CANDIDATE_ID"'],
      { cwd: f.dir, env: f.env },
    );
    if (accepted) await command;
    else await assert.rejects(command);
    const check = (await f.log()).find((c) => /--entrypoint timeout/.test(c));
    assert.match(check, /-k 2 30 bash -c /);
    assert.match(check, /GRYPE_DB_AUTO_UPDATE=false/);
  });
}

test('baseline and original ARG tags are each resolved once; probes use their recorded IDs', async () => {
  const f = await fixture({ localImages: INPUTS });
  await f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]);
  const commands = await f.log();
  for (const ref of ['firmlab-tools:latest', ...INPUTS]) {
    assert.equal(commands.filter((c) => c.startsWith(`image inspect ${ref} --format `)).length, 1);
    assert.equal(
      commands.some((c) => c.startsWith('run ') && c.includes(` ${ref} `)),
      false,
    );
  }
  const build = commands.find((c) => c.startsWith('build '));
  assert.match(build, /--builder default --pull=false/);
  for (const ref of INPUTS) assert.equal(build.includes(ref), false);
  const rows = (await f.report('inputs.tsv'))
    .trim()
    .split('\n')
    .map((r) => r.split('\t'));
  for (const arg of ['RETAINED_IMAGE', 'RENODE_IMAGE']) {
    const original = rows.find((r) => r[0] === arg);
    const frozen = rows.find((r) => r[0] === `${arg}_build_ref`);
    assert.equal(original[2], frozen[2]);
    assert.ok(build.includes(`${arg}=${frozen[1]}`));
  }
});

for (const from of ['private/unexpected:local', '${UNKNOWN:-private/fallback:local}']) {
  test(`unrecognised recipe base ${from} cannot trigger an implicit registry fetch`, async () => {
    const f = await fixture();
    await writeFile(path.join(f.dir, 'Dockerfile.tools'), `FROM ${from}\n`);
    await assert.rejects(
      f.candidate(['--tag', CANDIDATE_TAG, '--recipe', 'Dockerfile.tools', '--allow-dirty']),
      (e) => e.code === 1 && /bases de forma verificable/.test(e.stderr),
    );
    assert.equal(commandIndex(await f.log(), /^build |^tag |^pull /), -1);
  });
}

// Provenance review regressions: tested red against 2046e15 before the implementation change.
for (const kind of ['external', 'ignored', 'symlink']) {
  for (const when of ['baseline', 'build']) {
    test(`provenance refuses ${kind} recipe before mutations (${when} mutation hook)`, async () => {
      const f = await fixture({ localImages: INPUTS });
      const externalDir = await mkdtemp(path.join(tmpdir(), 'firmlab-external-recipe-'));
      fixtures.push(externalDir);
      const target = kind === 'ignored' ? path.join(f.dir, 'data/recipe') : path.join(externalDir, 'recipe');
      await mkdir(path.dirname(target), { recursive: true });
      await copyFile(path.join(f.dir, 'Dockerfile.trixie'), target);
      let recipe = target;
      if (kind === 'symlink') {
        recipe = path.join(f.dir, 'Dockerfile.link');
        await symlink(target, recipe);
        await run('git', ['add', 'Dockerfile.link'], { cwd: f.dir });
        await run('git', ['commit', '-qm', 'tracked recipe symlink'], { cwd: f.dir });
      }
      await assert.rejects(
        f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS, '--recipe', recipe, '--allow-dirty'], {
          SHIM_RECIPE_MUTATION_AT: when,
          SHIM_RECIPE_PATH: target,
        }),
        (e) => e.code === 1 && /receta.*(regular|versionada|worktree)/.test(e.stderr),
      );
      assert.equal(commandIndex(await f.log(), /^tag |^build /), -1);
    });
  }
}

for (const when of ['baseline', 'build']) {
  test(`provenance detects tracked recipe bytes changed during ${when}`, async () => {
    const f = await fixture({ localImages: INPUTS });
    await assert.rejects(
      f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS], {
        SHIM_RECIPE_MUTATION_AT: when,
        SHIM_RECIPE_PATH: path.join(f.dir, 'Dockerfile.trixie'),
      }),
      (e) => e.code === (when === 'build' ? 4 : 1) && /receta|contenido fuente/.test(e.stderr),
    );
    if (when === 'baseline') assert.equal(commandIndex(await f.log(), /^tag |^build /), -1);
    else assert.match(await f.report('verdict.txt'), /^rejected\n/);
  });
}

test('provenance keeps absolute tracked recipes and modified tracked recipes under allow-dirty', async () => {
  const f = await fixture({ localImages: INPUTS });
  await writeFile(
    path.join(f.dir, 'Dockerfile.trixie'),
    `${await readFile(path.join(f.dir, 'Dockerfile.trixie'), 'utf8')}\n# local recipe\n`,
  );
  await assert.rejects(
    f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]),
    (e) => e.code === 1 && /sucio/.test(e.stderr),
  );
  await f.candidate([
    '--tag',
    CANDIDATE_TAG,
    ...WITH_INPUTS,
    '--recipe',
    path.join(f.dir, 'Dockerfile.trixie'),
    '--allow-dirty',
    '--report',
    path.join(f.dir, 'report-dirty'),
  ]);
  assert.match(
    (await f.log()).find((c) => /^build /.test(c)),
    /revision=[0-9a-f]{40}-dirty-[0-9a-f]{64}/,
  );
});

for (const [name, env] of [
  ['second tag failure', { SHIM_SECOND_TAG_FAIL: '1' }],
  ['ambiguous alias receipt', { SHIM_ALIAS_RECEIPT_FAIL: '1' }],
]) {
  test(`provenance records alias intent before Docker mutation on ${name}`, async () => {
    const f = await fixture({ localImages: INPUTS });
    await assert.rejects(f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS], env), (e) => e.code === 1);
    const aliases = (await readFile(path.join(f.dir, 'aliases'), 'utf8')).trim().split('\n');
    const manifest = await f.report('inputs.tsv');
    for (const row of aliases) {
      const [ref, id] = row.split('\t');
      const arg = ref.endsWith(':retained_image') ? 'RETAINED_IMAGE' : 'RENODE_IMAGE';
      assert.ok(manifest.includes(`${arg}_build_ref_intent\t${ref}\t${id}\n`), manifest);
      const before = await readFile(path.join(f.dir, `manifest-before-${ref.split(':').at(-1)}`), 'utf8');
      assert.ok(before.includes(`${arg}_build_ref_intent\t${ref}\t${id}\n`), before);
    }
    if (name === 'second tag failure') {
      const beforeSecond = await readFile(path.join(f.dir, 'manifest-before-renode_image'), 'utf8');
      assert.match(
        beforeSecond,
        /^RETAINED_IMAGE_build_ref_actual\tfirmlab-candidate-input\/[^\t]+\tsha256:[0-9a-f]{64}$/m,
      );
      assert.ok(beforeSecond.includes('RENODE_IMAGE_build_ref_intent\t'), beforeSecond);
      assert.ok(beforeSecond.includes(`\t${inputId(INPUTS[1])}\n`), beforeSecond);
      assert.match(
        manifest,
        /^RETAINED_IMAGE_build_ref_actual\tfirmlab-candidate-input\/[^\t]+\tsha256:[0-9a-f]{64}$/m,
      );
      assert.match(manifest, /^RENODE_IMAGE_build_ref_status\t.*\ttag_failed$/m);
    } else {
      assert.match(manifest, /^RETAINED_IMAGE_build_ref_actual\tfirmlab-candidate-input\/[^\t]+\tunknown$/m);
    }
    assert.equal(commandIndex(await f.log(), /^build /), -1);
  });
}

test('provenance refuses nonignored in-repo report paths before Docker mutations', async () => {
  const f = await fixture({ localImages: INPUTS });
  await assert.rejects(
    f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS, '--report', path.join(f.dir, 'candidate-evidence')]),
    (e) => e.code === 1 && /informe.*(ignorado|fuera)/.test(e.stderr),
  );
  assert.equal(commandIndex(await f.log(), /^tag |^build /), -1);
});

for (const [name, options, env, reason] of [
  ['incomplete inventory', {}, { SHIM_INCOMPLETE: 'candidate' }, /inventario incompleto.*1 de 28 sondeos/],
  ['unknown inventory status', {}, { SHIM_UNKNOWN_STATUS: 'candidate' }, /inventario con estados desconocidos/],
  ['missing timeout', { candidateTimeout: false }, {}, /no tiene timeout/],
  ['missing bash', {}, { SHIM_BASH_MISSING: '1' }, /no se pudo inventariar offline/],
]) {
  test(`provenance writes one final verdict with specific ${name} diagnostic`, async () => {
    const f = await fixture({ localImages: INPUTS, ...options });
    await assert.rejects(f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS], env), (e) => {
      assert.equal(e.code, 4);
      assert.equal(e.stderr.split('rechazada:').length - 1, 1, e.stderr);
      return true;
    });
    assert.match(await f.report('verdict.txt'), reason);
  });
}

for (const tag of [
  'firmlab-candidate-input/tok:retained_image',
  'firmlab-candidate-input:v1',
  'firmlab-campaign/tools:',
  ':v1',
  'repo//name:v1',
  'UpperRepo:v1',
  'repo:bad tag',
  'bad..host/repo:v1',
  'repo:-bad',
  'repo:.bad',
  'docker.io/firmlab-campaign-test/retained-src:abc',
  'index.docker.io/firmlab-campaign-test/retained-src:abc',
  'registry-1.docker.io/firmlab-campaign-test/retained-src:abc',
  RETAINED,
]) {
  test(`provenance tag guard refuses ${JSON.stringify(tag)} by name before any Docker query`, async () => {
    const f = await fixture({ localImages: INPUTS });
    await assert.rejects(f.candidate(['--tag', tag, ...WITH_INPUTS]), (e) => e.code === 1);
    assert.deepEqual(await f.log(), []);
  });
}

test('provenance raw recipe bytes require allow-dirty even when Git status hides an edit', async () => {
  const f = await fixture({ localImages: INPUTS });
  await run('git', ['update-index', '--assume-unchanged', 'Dockerfile.trixie'], { cwd: f.dir });
  const recipe = path.join(f.dir, 'Dockerfile.trixie');
  await writeFile(recipe, `${await readFile(recipe, 'utf8')}\n# hidden tracked edit\n`);
  assert.equal((await run('git', ['status', '--porcelain'], { cwd: f.dir })).stdout, '');
  await assert.rejects(
    f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS]),
    (e) => e.code === 1 && /sucio/.test(e.stderr),
  );
  await f.candidate([
    '--tag',
    CANDIDATE_TAG,
    ...WITH_INPUTS,
    '--allow-dirty',
    '--report',
    path.join(f.dir, 'report-hidden'),
  ]);
  assert.match(
    (await f.log()).find((c) => /^build /.test(c)),
    /revision=[0-9a-f]{40}-dirty-[0-9a-f]{64}/,
  );
});

test('provenance default recipe inputs participate in normalized name checks', async () => {
  const f = await fixture();
  const recipe = path.join(f.dir, 'Dockerfile.trixie');
  await writeFile(recipe, (await readFile(recipe, 'utf8')).replace(RETAINED, 'org/input:v1'));
  await assert.rejects(
    f.candidate(['--tag', 'docker.io/org/input:v1', '--allow-dirty']),
    (e) => e.code === 1 && /imágenes de entrada/.test(e.stderr),
  );
  assert.deepEqual(await f.log(), []);
});

test('provenance removes the token directory before a failed alias mutation', async () => {
  const f = await fixture({ localImages: INPUTS });
  const temporary = await mkdtemp(path.join(tmpdir(), 'firmlab-alias-tokens-'));
  fixtures.push(temporary);
  await assert.rejects(
    f.candidate(['--tag', CANDIDATE_TAG, ...WITH_INPUTS], { TMPDIR: temporary, SHIM_SECOND_TAG_FAIL: '1' }),
    (e) => e.code === 1,
  );
  assert.deepEqual(await readdir(temporary), []);
});

test('provenance default report refuses a nonignored in-repo TMPDIR before Docker', async () => {
  const f = await fixture({ localImages: INPUTS });
  await assert.rejects(
    run('/bin/bash', ['scripts/tools-candidate.sh', '--tag', CANDIDATE_TAG, ...WITH_INPUTS], {
      cwd: f.dir,
      env: { ...f.env, TMPDIR: f.dir },
    }),
    (e) => e.code === 1 && /informe/.test(e.stderr),
  );
  assert.deepEqual(await f.log(), []);
});

test('provenance supported tag spellings remain accepted by the pure name guard', async () => {
  const source = await readFile(path.join(root, 'scripts/tools-candidate.sh'), 'utf8');
  const guard = source.match(/^candidate_tag_refusal\(\) \{[\s\S]*?^\}/m)[0];
  const refusal = async (...args) =>
    (
      await run('/bin/bash', [
        '-c',
        `. "$1"; shift\n${guard}\ncandidate_tag_refusal "$@"`,
        'tag-guard',
        path.join(root, 'scripts/tools-candidate-lib.sh'),
        ...args,
      ])
    ).stdout.trim();
  for (const tag of [
    'org/tools:V1',
    'localhost:5000/org/tools:v1',
    'host.example:5000/tools:v1',
    'org/tool__name:v1',
    'org/tool---name:v1',
  ]) {
    assert.equal(await refusal(tag, 'firmlab-tools:latest'), '', tag);
  }
  for (const host of ['docker.io', 'index.docker.io', 'registry-1.docker.io']) {
    assert.match(await refusal(`${host}/library/input:v1`, 'input:v1'), /imágenes de entrada/);
    assert.match(await refusal('input:v1', `${host}/library/input:v1`), /imágenes de entrada/);
    assert.match(await refusal(`${host}/firmlab-candidate-input/tok:v1`, 'other:v1'), /reservado/);
  }
});

test.after(async () => {
  await Promise.all(fixtures.map((dir) => rm(dir, { recursive: true, force: true })));
});
