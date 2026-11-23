/**
 * The provisioning script never touches the network here: `fetchImpl` is injected. What these pin is the part that
 * decides what may be fetched and what the manifest then promises the run time — exact URLs only, https and an
 * allowlisted host only, redirects refused, a verified entry kept rather than re-fetched, and a failure left absent
 * (so the run time keeps refusing that URL) rather than recorded.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  MANIFEST_NAME,
  checkUrlDigest,
  collectSvdReferences,
  parseApplySvdUrls,
  parseArgs,
  provision,
  refuseUrl,
  storedFileName,
} from './renode-svd-provision.mjs';

const URL_L0 = 'https://dl.antmicro.com/projects/renode/svd/STM32L0x1.svd';
const URL_F7 = 'https://dl.antmicro.com/projects/renode/svd/STM32F7x6.svd.gz';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

function platforms() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-svd-prov-'));
  fs.mkdirSync(path.join(dir, 'cpus'));
  fs.mkdirSync(path.join(dir, 'boards'));
  fs.writeFileSync(path.join(dir, 'cpus', 'stm32l071.repl'), `sysbus:\n    init:\n        ApplySVD @${URL_L0}\n`);
  fs.writeFileSync(path.join(dir, 'cpus', 'stm32f746.repl'), `sysbus:\n    init:\n        ApplySVD @${URL_F7}\n`);
  fs.writeFileSync(
    path.join(dir, 'cpus', 'stm32f777.repl'),
    `// ApplySVD @https://x.invalid/a.svd\n    ApplySVD @${URL_F7}\n`,
  );
  fs.writeFileSync(path.join(dir, 'boards', 'b.repl'), 'using "platforms/cpus/stm32l071.repl"\n');
  return dir;
}

function fakeFetch(bodies, calls = []) {
  return async (url, init) => {
    calls.push({ url, init });
    const body = bodies[url];
    if (body === undefined) return new Response('nope', { status: 404 });
    return new Response(body, { status: 200, headers: { 'content-type': 'application/octet-stream' } });
  };
}

test('parses ApplySVD URLs and ignores commented ones', () => {
  assert.deepEqual(parseApplySvdUrls(`/* ApplySVD @${URL_F7} */\n  ApplySVD @${URL_L0}\n// ApplySVD @${URL_F7}\n`), [
    URL_L0,
  ]);
});

test('collects each URL once with every platform file that references it', () => {
  const refs = collectSvdReferences(platforms());
  assert.deepEqual([...refs.keys()], [URL_F7, URL_L0]);
  assert.deepEqual(refs.get(URL_F7), ['cpus/stm32f746.repl', 'cpus/stm32f777.repl']);
});

test('refuses anything but https from an allowlisted host', () => {
  assert.equal(refuseUrl(URL_L0), null);
  assert.match(refuseUrl('http://dl.antmicro.com/x.svd'), /not https/);
  assert.match(refuseUrl('https://evil.example/x.svd'), /allowlist/);
  assert.equal(refuseUrl('https://mirror.example/x.svd', ['mirror.example']), null);
});

test('stored file names keep the extension Renode reads and cannot collide across hashes', () => {
  assert.equal(storedFileName(URL_F7, 'ab'.repeat(32)), `${'ab'.repeat(8)}-STM32F7x6.svd.gz`);
  assert.notEqual(storedFileName(URL_F7, 'a'.repeat(64)), storedFileName(URL_F7, 'b'.repeat(64)));
});

test('provisions every referenced SVD from its exact URL, redirects refused, into a manifest', async () => {
  const dir = platforms();
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-svd-data-'));
  const calls = [];
  const report = await provision({
    platformsDir: dir,
    dataDir: data,
    fetchImpl: fakeFetch({ [URL_L0]: 'l0-bytes', [URL_F7]: 'f7-bytes' }, calls),
    now: () => '2026-11-23T00:00:00.000Z',
  });
  assert.deepEqual(report.provisioned.sort(), [URL_F7, URL_L0]);
  assert.deepEqual(
    calls.map((c) => c.url),
    [URL_F7, URL_L0],
  );
  assert.ok(calls.every((c) => c.init.redirect === 'error'));
  const m = JSON.parse(fs.readFileSync(path.join(data, 'renode-svd', MANIFEST_NAME), 'utf8'));
  assert.equal(m.version, 1);
  const l0 = m.entries.find((e) => e.url === URL_L0);
  assert.equal(l0.sha256, sha('l0-bytes'));
  assert.equal(l0.size, 8);
  assert.equal(l0.fetchedAt, '2026-11-23T00:00:00.000Z');
  assert.deepEqual(l0.referencedBy, ['cpus/stm32l071.repl']);
  assert.equal(fs.readFileSync(path.join(data, 'renode-svd', l0.file), 'utf8'), 'l0-bytes');
});

test('keeps a verified entry without fetching again, and re-fetches one whose file changed', async () => {
  const dir = platforms();
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-svd-data-'));
  const bodies = { [URL_L0]: 'l0-bytes', [URL_F7]: 'f7-bytes' };
  await provision({ platformsDir: dir, dataDir: data, fetchImpl: fakeFetch(bodies) });
  const svdDir = path.join(data, 'renode-svd');
  const m = JSON.parse(fs.readFileSync(path.join(svdDir, MANIFEST_NAME), 'utf8'));
  fs.writeFileSync(path.join(svdDir, m.entries.find((e) => e.url === URL_F7).file), 'tampered');
  const calls = [];
  const again = await provision({ platformsDir: dir, dataDir: data, fetchImpl: fakeFetch(bodies, calls) });
  assert.deepEqual(again.kept, [URL_L0]);
  assert.deepEqual(again.provisioned, [URL_F7]);
  assert.deepEqual(
    calls.map((c) => c.url),
    [URL_F7],
  );
});

test('a failed download is reported and left out of the manifest, never recorded as provisioned', async () => {
  const dir = platforms();
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-svd-data-'));
  const report = await provision({ platformsDir: dir, dataDir: data, fetchImpl: fakeFetch({ [URL_L0]: 'l0' }) });
  assert.equal(report.failed.length, 1);
  assert.equal(report.failed[0].url, URL_F7);
  const m = JSON.parse(fs.readFileSync(path.join(data, 'renode-svd', MANIFEST_NAME), 'utf8'));
  assert.deepEqual(
    m.entries.map((e) => e.url),
    [URL_L0],
  );
});

test('a dry run fetches and writes nothing', async () => {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-svd-data-'));
  const calls = [];
  const report = await provision({
    platformsDir: platforms(),
    dataDir: data,
    dryRun: true,
    fetchImpl: fakeFetch({}, calls),
  });
  assert.equal(report.references.size, 2);
  assert.equal(calls.length, 0);
  assert.equal(fs.existsSync(path.join(data, 'renode-svd')), false);
});

test('parses its arguments and rejects unknown ones', () => {
  const o = parseArgs(['--platforms', '/p', '--data-dir', '/d', '--refresh', '--allow-host', 'm.example']);
  assert.equal(o.platformsDir, '/p');
  assert.equal(o.dataDir, '/d');
  assert.equal(o.refresh, true);
  assert.deepEqual(o.allowedHosts, ['dl.antmicro.com', 'm.example']);
  assert.throws(() => parseArgs(['--bogus']), /unknown argument/);
});

test("a URL in Renode's -s_<size>-<sha1> form is checked against the bytes, and a mismatch is not provisioned", async () => {
  const body = Buffer.from('s32k-bytes');
  const sha1 = crypto.createHash('sha1').update(body).digest('hex');
  const good = `https://dl.antmicro.com/projects/renode/S32K118.svd-s_${body.length}-${sha1}`;
  assert.equal(checkUrlDigest(good, body), true);
  assert.equal(checkUrlDigest(URL_L0, body), null);
  assert.match(checkUrlDigest(good, Buffer.from('other-byte')), /sha1/);
  assert.match(checkUrlDigest(good, Buffer.from('short')), /size/);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-svd-prov-'));
  const bad = `https://dl.antmicro.com/projects/renode/X.svd-s_${body.length}-${'0'.repeat(40)}`;
  fs.writeFileSync(path.join(dir, 'a.repl'), `  ApplySVD @${good}\n  ApplySVD @${bad}\n`);
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-svd-data-'));
  const report = await provision({
    platformsDir: dir,
    dataDir: data,
    fetchImpl: fakeFetch({ [good]: body, [bad]: body }),
  });
  assert.deepEqual(report.provisioned, [good]);
  assert.equal(report.failed[0].url, bad);
  const m = JSON.parse(fs.readFileSync(path.join(data, 'renode-svd', MANIFEST_NAME), 'utf8'));
  assert.match(m.entries[0].urlDigest, /verified/);
});
