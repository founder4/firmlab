#!/usr/bin/env node
/** Install one self-contained user skill and its launchers; refuse unmanaged or locally edited destinations. */
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, realpathSync } from 'node:fs';
import { chmod, lstat, mkdir, readFile, readdir, readlink, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE = fileURLToPath(new URL('..', import.meta.url));
const FILES = [
  'SKILL.md',
  'agents/openai.yaml',
  'scripts/watch.mjs',
  'scripts/watch.test.mjs',
  'scripts/policy.mjs',
  'scripts/policy.test.mjs',
  'scripts/launch-worker.mjs',
  'scripts/launch-worker.test.mjs',
  'scripts/install.mjs',
];
const MARKER = '.orca-campaign-install.json';
const hash = (value) => createHash('sha256').update(value).digest('hex');
const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
async function exists(path) {
  try {
    return await lstat(path);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function entriesWithoutLinks(root, prefix = '') {
  if (prefix.split('/').length > 4) throw new Error('Unexpected nested skill directory');
  const rows = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const name = join(prefix, entry.name);
    rows.push({ entry, name });
    if (entry.isDirectory() && !entry.isSymbolicLink()) rows.push(...(await entriesWithoutLinks(root, name)));
  }
  return rows;
}

export async function install({ home = homedir(), codexHome = process.env.CODEX_HOME, source = SOURCE } = {}) {
  if (process.platform === 'win32') throw new Error('The user launcher currently supports POSIX hosts only');
  const profile = resolve(home);
  const target = join(profile, '.agents', 'skills', 'orca-campaign');
  const launcher = join(profile, '.local', 'bin', 'orca-campaign-watch');
  const launchText = `#!/bin/sh\nexec node ${quote(join(target, 'scripts', 'watch.mjs'))} "$@"\n`;
  // The guarded worker launcher is how a campaign's capacity policy is enforced; raw Orca is not intercepted.
  const workerLauncher = join(profile, '.local', 'bin', 'orca-campaign-launch-worker');
  const workerLaunchText = `#!/bin/sh\nexec node ${quote(join(target, 'scripts', 'launch-worker.mjs'))} "$@"\n`;
  const links = [
    join(codexHome ?? join(profile, '.codex'), 'skills', 'orca-campaign'),
    join(profile, '.claude', 'skills', 'orca-campaign'),
  ];
  const antigravityPlugin = join(profile, '.local', 'share', 'orca-campaign-antigravity');
  const pluginText = `${JSON.stringify({ name: 'orca-campaign', version: '1.0.0', description: 'Independent supervision for authorized Orca project campaigns' }, null, 2)}\n`;
  const pluginLinks = [
    [join(antigravityPlugin, 'skills', 'orca-campaign', 'SKILL.md'), join(target, 'SKILL.md'), 'file'],
    [join(antigravityPlugin, 'skills', 'orca-campaign', 'scripts'), join(target, 'scripts'), 'dir'],
  ];
  if (await exists(antigravityPlugin)) {
    let pluginMetadata;
    try {
      pluginMetadata = await readFile(join(antigravityPlugin, 'plugin.json'), 'utf8');
    } catch {
      throw new Error(`Unmanaged or partial Antigravity plugin: ${antigravityPlugin}`);
    }
    if (
      !(await lstat(antigravityPlugin)).isDirectory() ||
      (await lstat(antigravityPlugin)).isSymbolicLink() ||
      pluginMetadata !== pluginText
    )
      throw new Error(`Unmanaged Antigravity plugin: ${antigravityPlugin}`);
    const allowed = new Set([
      'plugin.json',
      'skills',
      'skills/orca-campaign',
      'skills/orca-campaign/SKILL.md',
      'skills/orca-campaign/scripts',
    ]);
    for (const { name } of await entriesWithoutLinks(antigravityPlugin)) {
      if (!allowed.has(name)) throw new Error(`Unmanaged Antigravity plugin entry: ${name}`);
    }
  }
  for (const [link, destination] of pluginLinks) {
    const entry = await exists(link);
    if (entry && (!entry.isSymbolicLink() || resolve(dirname(link), await readlink(link)) !== destination))
      throw new Error(`Unmanaged Antigravity skill link: ${link}`);
  }
  const contents = new Map(await Promise.all(FILES.map(async (name) => [name, await readFile(join(source, name))])));
  const manifest = {
    managedBy: 'orca-campaign-installer',
    version: 1,
    files: Object.fromEntries([...contents].map(([name, data]) => [name, hash(data)])),
  };
  const current = await exists(target);
  if (current) {
    if (!current.isDirectory() || current.isSymbolicLink()) throw new Error(`Unmanaged skill destination: ${target}`);
    let prior;
    try {
      prior = JSON.parse(await readFile(join(target, MARKER), 'utf8'));
    } catch {
      throw new Error(`Unmanaged skill destination: ${target}`);
    }
    if (prior.managedBy !== manifest.managedBy || prior.version !== 1 || !prior.files)
      throw new Error(`Unmanaged skill destination: ${target}`);
    for (const { entry, name } of await entriesWithoutLinks(target)) {
      if (
        entry.isSymbolicLink() ||
        (entry.isDirectory() && !['agents', 'scripts'].includes(name)) ||
        (!entry.isDirectory() && name !== MARKER && !Object.hasOwn(prior.files, name))
      )
        throw new Error(`Unmanaged file in skill: ${name}`);
    }
    for (const [name, digest] of Object.entries(prior.files)) {
      if (!FILES.includes(name) || hash(await readFile(join(target, name))) !== digest)
        throw new Error(`Locally modified skill file: ${name}`);
    }
  }
  for (const [path, text] of [
    [launcher, launchText],
    [workerLauncher, workerLaunchText],
  ]) {
    if ((await exists(path)) && ((await lstat(path)).isSymbolicLink() || (await readFile(path, 'utf8')) !== text))
      throw new Error(`Unmanaged launcher: ${path}`);
  }
  for (const link of links) {
    const entry = await exists(link);
    if (entry && (!entry.isSymbolicLink() || resolve(dirname(link), await readlink(link)) !== target))
      throw new Error(`Unmanaged skill link: ${link}`);
  }
  // Every existing destination has been checked before the first mutation.
  await mkdir(dirname(target), { recursive: true });
  const staging = `${target}.stage-${randomUUID()}`;
  const backup = `${target}.previous-${randomUUID()}`;
  await mkdir(staging, { mode: 0o700 });
  let moved = false;
  try {
    for (const [name, data] of contents) {
      await mkdir(dirname(join(staging, name)), { recursive: true });
      await writeFile(join(staging, name), data, { mode: 0o644 });
    }
    await writeFile(join(staging, MARKER), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    if (current) {
      await rename(target, backup);
      moved = true;
    }
    try {
      await rename(staging, target);
    } catch (error) {
      if (moved) await rename(backup, target);
      moved = false;
      throw error;
    }
    await mkdir(dirname(launcher), { recursive: true });
    for (const [path, text] of [
      [launcher, launchText],
      [workerLauncher, workerLaunchText],
    ]) {
      await writeFile(path, text, { mode: 0o755 });
      await chmod(path, 0o755);
    }
    for (const link of links) {
      await mkdir(dirname(link), { recursive: true });
      if (!(await exists(link))) await symlink(target, link, 'dir');
    }
    await mkdir(join(antigravityPlugin, 'skills', 'orca-campaign'), { recursive: true });
    await writeFile(join(antigravityPlugin, 'plugin.json'), pluginText);
    for (const [link, destination, type] of pluginLinks)
      if (!(await exists(link))) await symlink(destination, link, type);
    if (moved) await rm(backup, { recursive: true });
    return {
      skill: target,
      launcher,
      workerLauncher,
      links,
      antigravityPlugin,
      sha256: manifest.files['scripts/watch.mjs'],
    };
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

if (
  process.argv[1] &&
  existsSync(process.argv[1]) &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    const args = process.argv.slice(2);
    if (args.length === 1 && args[0] === '--help')
      console.log(
        'install.mjs [--home PATH] (user skill, Codex/Claude links, local Antigravity plugin and POSIX launcher; no campaigns started)',
      );
    else {
      if (args.length && (args.length !== 2 || args[0] !== '--home' || !args[1]))
        throw new Error('Expected --home PATH or no arguments');
      console.log(
        JSON.stringify(
          await install(args.length ? { home: args[1], codexHome: join(resolve(args[1]), '.codex') } : {}),
          null,
          2,
        ),
      );
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
