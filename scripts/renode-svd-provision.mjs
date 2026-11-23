#!/usr/bin/env node
/**
 * Provision, ahead of time and on purpose, the register descriptions (SVD) that Renode's bundled platforms fetch
 * over HTTPS on load.
 *
 * Several platform descriptions under Renode's `platforms/` directory carry `ApplySVD @https://dl.antmicro.com/…`.
 * Renode runs every boot under `OFFLINE_RENODE_ENV` (apps/api/src/providers/renode-offline.ts), so at run time
 * that download is refused and named in the result — the platform boots WITHOUT its SVD. This script is the one
 * place those files may be acquired, and it is explicit: an operator runs it, it reads the platforms directory it
 * is given, it downloads each SVD from the exact URL the platform names and from nowhere else (https only, a host
 * allowlist, redirects refused), and it writes the bytes plus a manifest under `$FIRMLAB_DATA_DIR/renode-svd/`.
 *
 * What the run time does with it (apps/api/src/providers/renode-svd.ts): it re-hashes the stored file on every run
 * and uses a rewritten COPY of the platform only when the manifest entry exists and the sha256 matches. A missing or
 * mismatched file keeps today's behaviour — refused, named. The run time never fetches; this script never runs
 * implicitly.
 *
 * What it does NOT claim. The sha256 recorded is the hash of what the server sent today; for most of these files
 * nothing upstream publishes a digest to check it against, so the manifest pins the bytes the operator accepted, not
 * their authenticity. The exception is a URL in Renode's `-s_<size>-<sha1>` form, which is checked (`checkUrlDigest`). The
 * reference parser here is deliberately small and duplicated from the TypeScript one rather than shared through a
 * build: if the two ever disagree, a URL this script missed is simply "missing" at run time (refused, as before) and
 * one it found in excess is never used — both directions degrade to today's behaviour, never to a silent claim.
 *
 * Usage:
 *   node scripts/renode-svd-provision.mjs --platforms <renode platforms dir> [--data-dir <dir>] [--dry-run]
 *        [--refresh] [--allow-host <host>]…
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const SVD_DIRNAME = 'renode-svd';
export const MANIFEST_NAME = 'manifest.json';
export const MANIFEST_VERSION = 1;
export const DEFAULT_ALLOWED_HOSTS = Object.freeze(['dl.antmicro.com']);
/** Largest SVD accepted. The biggest Renode references today is a few MB; this bounds a misbehaving server. */
export const MAX_SVD_BYTES = 64 * 1024 * 1024;

/** Comments blanked to spaces, offsets and newlines preserved — a commented-out `ApplySVD` is never fetched. */
export function maskComments(text) {
  const blank = (s) => s.replace(/[^\n]/g, ' ');
  return text.replace(/\/\*[\s\S]*?\*\//g, blank).replace(/^[ \t]*\/\/.*$/gm, blank);
}

/** Every `ApplySVD @http(s)://…` URL in one platform file's text, in order, comments excluded. */
export function parseApplySvdUrls(text) {
  const out = [];
  for (const m of maskComments(text).matchAll(/\bApplySVD[ \t]+@(https?:\/\/[^\s"'`;]+)/g)) if (m[1]) out.push(m[1]);
  return out;
}

/** Recursively list `.repl` / `.resc` files under `dir`, as paths relative to it, sorted. */
export function listPlatformFiles(dir) {
  const out = [];
  const walk = (d, depth) => {
    if (depth > 6) return;
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full, depth + 1);
      else if (e.isFile() && /\.(repl|resc)$/.test(e.name)) out.push(path.relative(dir, full));
    }
  };
  walk(dir, 0);
  return out.sort();
}

/** url → the platform files (relative to the platforms dir) that reference it, sorted for a stable manifest. */
export function collectSvdReferences(platformsDir) {
  const refs = new Map();
  for (const rel of listPlatformFiles(platformsDir)) {
    const text = fs.readFileSync(path.join(platformsDir, rel), 'utf8');
    for (const url of parseApplySvdUrls(text)) {
      const list = refs.get(url) ?? [];
      if (!list.includes(rel)) list.push(rel);
      refs.set(url, list);
    }
  }
  return new Map([...refs.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

/** Why a URL may not be fetched, or null when it may: https only, and only from an allowlisted host. */
export function refuseUrl(url, allowedHosts = DEFAULT_ALLOWED_HOSTS) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return 'not a URL';
  }
  if (u.protocol !== 'https:') return `scheme ${u.protocol} is not https`;
  if (!allowedHosts.includes(u.hostname))
    return `host ${u.hostname} is not in the allowlist (${allowedHosts.join(', ')})`;
  return null;
}

/**
 * The stored file name for a URL: the URL path's basename (so `.svd.gz` keeps the extension Renode reads it by),
 * sanitised to a safe character set, prefixed with the first 16 hex digits of its sha256 so two different files
 * with the same basename cannot collide.
 */
export function storedFileName(url, sha256) {
  const base = decodeURIComponent(new URL(url).pathname.split('/').pop() || 'svd').replace(/[^A-Za-z0-9._-]/g, '_');
  return `${sha256.slice(0, 16)}-${base}`;
}

/**
 * Renode's own naming convention for some remote files carries the expected size and SHA-1 in the URL
 * (`…/S32K118.svd-s_4356973-8b6f35da…`), and Renode checks them when it downloads. When a URL carries one, the
 * downloaded bytes must match it — the one upstream digest available for any of these files. Returns null when the
 * URL carries none, `true` when it matched, or the reason it did not.
 */
export function checkUrlDigest(url, bytes) {
  const m = /-s_(\d+)-([0-9a-f]{40})$/.exec(new URL(url).pathname);
  if (!m) return null;
  if (bytes.length !== Number(m[1])) return `size ${bytes.length} differs from the ${m[1]} the URL names`;
  const sha1 = crypto.createHash('sha1').update(bytes).digest('hex');
  return sha1 === m[2] ? true : `sha1 ${sha1} differs from the ${m[2]} the URL names`;
}

export function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/** The manifest at `svdDir`, or an empty one when absent or unreadable (a corrupt one is reported, not trusted). */
export function readManifest(svdDir) {
  try {
    const m = JSON.parse(fs.readFileSync(path.join(svdDir, MANIFEST_NAME), 'utf8'));
    if (m && m.version === MANIFEST_VERSION && Array.isArray(m.entries)) return m;
  } catch {}
  return { version: MANIFEST_VERSION, entries: [] };
}

/** True when the manifest entry's file is present inside `svdDir` and still hashes to what the entry records. */
export function entryVerified(svdDir, entry) {
  if (!entry || typeof entry.file !== 'string' || entry.file.includes('/') || entry.file.includes('\\')) return false;
  try {
    return sha256Hex(fs.readFileSync(path.join(svdDir, entry.file))) === entry.sha256;
  } catch {
    return false;
  }
}

/** Fetch exactly `url`: redirects refused, body bounded. `fetchImpl` is injected so tests never touch the network. */
export async function downloadSvd(url, fetchImpl = fetch, maxBytes = MAX_SVD_BYTES) {
  const res = await fetchImpl(url, { redirect: 'error' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) throw new Error(`declares ${declared} bytes (cap ${maxBytes})`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxBytes) throw new Error(`sent ${buf.length} bytes (cap ${maxBytes})`);
  if (buf.length === 0) throw new Error('empty body');
  return { bytes: buf, contentType: res.headers.get('content-type') ?? null };
}

/**
 * Provision every referenced SVD into `<dataDir>/renode-svd/`. An entry already present and verified is kept
 * (unless `refresh`); a refused or failed URL is reported and left absent, so the run time keeps refusing it. The
 * manifest is written last, atomically, and only lists files whose bytes were hashed as they were written.
 */
export async function provision({
  platformsDir,
  dataDir,
  dryRun = false,
  refresh = false,
  allowedHosts = DEFAULT_ALLOWED_HOSTS,
  fetchImpl = fetch,
  now = () => new Date().toISOString(),
  log = () => {},
}) {
  const svdDir = path.join(dataDir, SVD_DIRNAME);
  const refs = collectSvdReferences(platformsDir);
  const previous = new Map(readManifest(svdDir).entries.map((e) => [e.url, e]));
  const report = { svdDir, references: refs, provisioned: [], kept: [], failed: [], refused: [] };
  if (dryRun) return report;

  fs.mkdirSync(svdDir, { recursive: true });
  const entries = [];
  for (const [url, referencedBy] of refs) {
    const why = refuseUrl(url, allowedHosts);
    if (why) {
      report.refused.push({ url, reason: why });
      log(`refused  ${url}: ${why}`);
      continue;
    }
    const prior = previous.get(url);
    if (!refresh && entryVerified(svdDir, prior)) {
      entries.push({ ...prior, referencedBy });
      report.kept.push(url);
      log(`kept     ${url} (${prior.sha256})`);
      continue;
    }
    try {
      const { bytes, contentType } = await downloadSvd(url, fetchImpl);
      const digest = checkUrlDigest(url, bytes);
      if (typeof digest === 'string') throw new Error(digest);
      const sha256 = sha256Hex(bytes);
      const file = storedFileName(url, sha256);
      const tmp = path.join(svdDir, `.${file}.partial`);
      fs.writeFileSync(tmp, bytes);
      fs.renameSync(tmp, path.join(svdDir, file));
      const entry = { url, file, sha256, size: bytes.length, contentType, fetchedAt: now(), referencedBy };
      if (digest === true) entry.urlDigest = 'sha1+size verified against the URL';
      entries.push(entry);
      report.provisioned.push(url);
      log(`fetched  ${url} → ${file} (${bytes.length} bytes, sha256 ${sha256})`);
    } catch (err) {
      report.failed.push({ url, reason: String(err?.message ?? err) });
      log(`failed   ${url}: ${err?.message ?? err}`);
    }
  }
  const manifest = {
    version: MANIFEST_VERSION,
    generatedAt: now(),
    platformsDir: path.resolve(platformsDir),
    note: 'Written by scripts/renode-svd-provision.mjs. sha256 pins the bytes accepted at fetch time; no upstream digest exists to check them against.',
    entries,
  };
  const tmp = path.join(svdDir, `.${MANIFEST_NAME}.partial`);
  fs.writeFileSync(tmp, `${JSON.stringify(manifest, null, 2)}\n`);
  fs.renameSync(tmp, path.join(svdDir, MANIFEST_NAME));
  report.manifest = manifest;
  return report;
}

export function parseArgs(argv) {
  const opts = {
    platformsDir: null,
    dataDir: null,
    dryRun: false,
    refresh: false,
    allowedHosts: [...DEFAULT_ALLOWED_HOSTS],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--platforms') opts.platformsDir = argv[++i] ?? null;
    else if (a === '--data-dir') opts.dataDir = argv[++i] ?? null;
    else if (a === '--dry-run') opts.dryRun = true;
    else if (a === '--refresh') opts.refresh = true;
    else if (a === '--allow-host') opts.allowedHosts.push(argv[++i] ?? '');
    else throw new Error(`unknown argument: ${a}`);
  }
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.platformsDir) {
    console.error('usage: renode-svd-provision.mjs --platforms <dir> [--data-dir <dir>] [--dry-run] [--refresh]');
    process.exit(2);
  }
  const dataDir = path.resolve(opts.dataDir ?? process.env.FIRMLAB_DATA_DIR ?? './data');
  const report = await provision({ ...opts, dataDir, log: (l) => console.log(l) });
  for (const [url, by] of report.references) if (opts.dryRun) console.log(`${url}\n    ${by.join('\n    ')}`);
  console.log(
    `${report.references.size} SVD URL(s) referenced; ${report.provisioned.length} fetched, ${report.kept.length} kept, ${report.failed.length} failed, ${report.refused.length} refused → ${report.svdDir}`,
  );
  if (report.failed.length > 0 || report.refused.length > 0) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
