/**
 * The candidate evaluator stands between a new YARA Forge release and a lock change, so its two outcomes must never
 * look alike: a comparison that ran (exit 0, «Resultado: completo») and one that did not (exit 3, «INCOMPLETO
 * (<motivo>)»). Each test runs the real script from a fixture tree with its own lock, behind shims for curl (files
 * served by URL; an unserved URL is a refused connection) and docker (recorded, canned yara output), so nothing
 * touches the network, a container, the repository's lock or any corpus.
 */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = [];
after(() => Promise.all(fixtures.map((dir) => rm(dir, { recursive: true, force: true }))));

const LOCK_TAG = '20260101';
const API = 'http://127.0.0.1:9/api';
const BASELINE = { A: 'a1', B: 'b1', C: 'c1', E: null };
const ROOTED = { img1: '/data/extract/img1/rootfs', img2: null };

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const served = (url) => url.replace(/[^A-Za-z0-9._-]/g, '_');
const download = (tag) => `https://github.com/YARAHQ/yara-forge/releases/download/${tag}/yara-forge-rules-core.zip`;

async function rulesZip(dir, name, rules) {
  const stage = path.join(dir, `stage-${name}`);
  await mkdir(path.join(stage, 'packages/core'), { recursive: true });
  const yar = Object.entries(rules)
    .map(
      ([rule, hash]) =>
        `rule ${rule} : tag\n{\n\tmeta:\n${hash ? `\t\tlogic_hash = "${hash}"\n` : ''}\tcondition:\n\t\ttrue\n}\n`,
    )
    .join('\n');
  await writeFile(path.join(stage, 'packages/core/yara-rules-core.yar'), yar);
  const zip = path.join(dir, `${name}.zip`);
  await run('zip', ['-qX', zip, 'packages/core/yara-rules-core.yar'], { cwd: stage });
  return { zip: await readFile(zip), yar: Buffer.from(yar) };
}

async function evaluate({
  candidate = BASELINE,
  rooted = ROOTED,
  apiDown = false,
  unreachableImage = null,
  lockPatch = {},
  matches = { baseline: '', candidate: '' },
} = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'firmlab-yara-eval-'));
  fixtures.push(dir);
  const serve = path.join(dir, 'serve');
  const bin = path.join(dir, 'bin');
  await Promise.all(['serve', 'bin', 'scripts', 'ops/yara'].map((d) => mkdir(path.join(dir, d), { recursive: true })));
  await copyFile(
    path.join(root, 'scripts/evaluate-yara-candidate.sh'),
    path.join(dir, 'scripts/evaluate-yara-candidate.sh'),
  );

  const base = await rulesZip(dir, 'baseline', BASELINE);
  const cand = await rulesZip(dir, 'candidate', candidate);
  const lock = {
    schemaVersion: 1,
    external: {
      release: LOCK_TAG,
      archiveUrl: download(LOCK_TAG),
      archiveSha256: sha(base.zip),
      archiveBytes: base.zip.length,
      archiveMember: 'packages/core/yara-rules-core.yar',
      ruleFileSha256: sha(base.yar),
      ruleFileBytes: base.yar.length,
      rulesDeclared: Object.keys(BASELINE).length,
      ...lockPatch,
    },
  };
  await writeFile(path.join(dir, 'ops/yara/corpus.lock.json'), JSON.stringify(lock));

  const files = {
    [download(LOCK_TAG)]: base.zip,
    [download('20260201')]: cand.zip,
    'https://api.github.com/repos/YARAHQ/yara-forge/releases/latest': JSON.stringify({
      tag_name: '20260201',
      assets: [
        {
          name: 'yara-forge-rules-core.zip',
          browser_download_url: download('20260201'),
          digest: `sha256:${sha(cand.zip)}`,
        },
      ],
    }),
  };
  if (!apiDown) files[`${API}/images`] = JSON.stringify({ images: Object.keys(rooted).map((id) => ({ id })) });
  for (const [id, rootfs] of Object.entries(rooted)) {
    if (id === unreachableImage) continue;
    files[`${API}/images/${id}/yarascan`] = JSON.stringify({ result: rootfs ? { scan: { root: rootfs } } : null });
  }
  await Promise.all(Object.entries(files).map(([url, body]) => writeFile(path.join(serve, served(url)), body)));

  await writeFile(
    path.join(bin, 'curl'),
    `#!/usr/bin/env bash
out=''; url=''; prev=''
for arg in "$@"; do
  [ "$prev" != --output ] || out="$arg"
  case "$arg" in http*) url="$arg" ;; esac
  prev="$arg"
done
printf '%s\\n' "$url" >> "$CURL_LOG"
src="$SERVE/$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_')"
[ -f "$src" ] || { printf 'curl: (7) Failed to connect\\n' >&2; exit 7; }
if [ -n "$out" ]; then cp "$src" "$out"; else cat "$src"; fi
`,
  );
  await writeFile(
    path.join(bin, 'docker'),
    `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$DOCKER_LOG"
[ "$1" = exec ] || exit 0
shift 2
if [ "$1" = yara ] && [ "$4" = -r ]; then
  case "$5" in *candidate*) printf '%s' "$CANDIDATE_MATCHES" ;; *) printf '%s' "$BASELINE_MATCHES" ;; esac
fi
`,
  );
  await Promise.all(['curl', 'docker'].map((name) => chmod(path.join(bin, name), 0o755)));

  const report = path.join(dir, 'report.md');
  // A previous complete report at the same path must not survive a run that could not compare.
  await writeFile(report, '- Resultado: completo\n');
  const { GITHUB_TOKEN: _token, ...inherited } = process.env;
  const env = {
    ...inherited,
    PATH: `${bin}:${process.env.PATH}`,
    TMPDIR: dir,
    FIRMLAB_API_BASE: API,
    SERVE: serve,
    CURL_LOG: path.join(dir, 'curl.log'),
    DOCKER_LOG: path.join(dir, 'docker.log'),
    BASELINE_MATCHES: matches.baseline,
    CANDIDATE_MATCHES: matches.candidate,
  };
  const script = path.join(dir, 'scripts/evaluate-yara-candidate.sh');
  let code = 0;
  let stderr = '';
  try {
    ({ stderr } = await run('bash', [script, 'latest', report], { env }));
  } catch (error) {
    ({ code, stderr } = error);
  }
  const read = (name) => readFile(path.join(dir, name), 'utf8').catch(() => '');
  return {
    code,
    stderr,
    report: await read('report.md'),
    curl: await read('curl.log'),
    docker: await read('docker.log'),
  };
}

function assertIncomplete(result, reason) {
  assert.equal(result.code, 3, result.stderr);
  assert.match(result.stderr, new RegExp(`INCOMPLETO \\(${reason}\\)`));
  assert.match(result.report, new RegExp(`INCOMPLETO\\*\\* \\(\`${reason}\`\\)`));
  assert.doesNotMatch(result.report, /Resultado: completo/);
  assert.doesNotMatch(result.docker, / -r /, 'no rootfs may be scanned by an incomplete evaluation');
}

test('a complete comparison reports name and logic deltas against the lock-verified baseline', async () => {
  const result = await evaluate({
    candidate: { A: 'a1', B: 'b2', D: 'd1', E: null },
    matches: {
      baseline: 'default:A /data/extract/img1/rootfs/bin/x\n',
      candidate: 'default:A /data/extract/img1/rootfs/bin/x\ndefault:D /data/extract/img1/rootfs/www/y\n',
    },
  });
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.report, /Resultado: completo/);
  assert.match(result.report, /Baseline: `20260101` del lock \(4 reglas/);
  assert.match(result.report, /añadidas\/eliminadas\/lógica cambiada: 1 \/ 1 \/ 1/);
  assert.match(result.report, /sin `logic_hash` \(lógica no comparada\): 1/);
  assert.match(result.report, /Imágenes \/ rootfs A\/B: 2 \/ 1/);
  assert.match(result.report, /Matches actual\/candidata: 1 \/ 2/);
  assert.match(result.report, /Matches nuevos\/perdidos: 1 \/ 0/);
  assert.match(result.report, /lógica cambiada\n\n```text\nB\n```/);
  assert.match(
    result.docker,
    /yara -w -e -r \/tmp\/firmlab-yara-core-baseline-20260101\.yar \/data\/extract\/img1\/rootfs/,
  );
  assert.doesNotMatch(result.docker, /\/opt\/firmlab-yara/, 'the baseline is the lock, not whatever is mounted');
  assert.match(result.docker, /rm -f \/tmp\/firmlab-yara-core-candidate-20260201\.yar/);
});

test('a logic-only change is reported even though no rule name moved', async () => {
  const result = await evaluate({ candidate: { A: 'a1', B: 'b2', C: 'c1', E: null } });
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.report, /añadidas\/eliminadas\/lógica cambiada: 0 \/ 0 \/ 1/);
  assert.match(result.report, /lógica cambiada\n\n```text\nB\n```/);
});

test('an unreachable API is a named incomplete result, never an empty comparison', async () => {
  assertIncomplete(await evaluate({ apiDown: true }), 'api_unreachable');
  const perImage = await evaluate({ unreachableImage: 'img2' });
  assertIncomplete(perImage, 'api_unreachable');
  assert.match(perImage.report, /images\/img2\/yarascan/);
});

test('zero discovered rootfs is incomplete, not a clean A/B', async () => {
  const result = await evaluate({ rooted: { img1: null, img2: null } });
  assertIncomplete(result, 'no_rootfs');
  assert.match(result.report, /2 imágenes/);
});

test('a baseline that does not match the lock is refused before anything is compared', async () => {
  for (const lockPatch of [
    { archiveSha256: '0'.repeat(64) },
    { ruleFileBytes: 1 },
    { rulesDeclared: 5 },
    { archiveMember: 'packages/core/missing.yar' },
  ]) {
    const result = await evaluate({ lockPatch });
    assertIncomplete(result, 'baseline_lock_mismatch');
    assert.equal(result.docker, '', JSON.stringify(lockPatch));
    assert.doesNotMatch(result.curl, /api\.github\.com|\/api\/images/, JSON.stringify(lockPatch));
  }
});
