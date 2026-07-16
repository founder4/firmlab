/**
 * Firmware extraction provider. Prefers `binwalk -Me` (recursive "matryoshka" carve) when available, then
 * walks whatever it produced to locate a Linux rootfs and model it via @firmlab/core's filesystem summarizer.
 * With no extractor present it degrades to a clear "unavailable" result rather than failing — the static
 * analysis (structure/entropy/strings) already gives value without a real rootfs.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { type FsEntry, type FsNode, type FsSummary, buildFsTree, summarizeFs } from '@firmlab/core';
import { EXTRACT_DIR } from '../paths.js';
import { isToolAvailable } from '../tools.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

export interface ExtractResult {
  extractor: 'binwalk' | 'none';
  outputDir: string;
  rootfsPath: string | null;
  tree: FsNode | null;
  summary: FsSummary | null;
  /** A representative network-facing binary to seed emulation, if one was found. */
  suggestedBinary?: string;
}

/** Directory names that mark the root of an extracted Linux rootfs. */
const ROOTFS_MARKERS = ['bin', 'etc', 'sbin', 'lib'];

export async function runExtraction(imageId: string, imagePath: string, handle: JobHandle): Promise<ExtractResult> {
  const outputDir = path.join(EXTRACT_DIR, imageId);
  fs.mkdirSync(outputDir, { recursive: true });

  const haveBinwalk = await isToolAvailable('binwalk');
  if (!haveBinwalk) {
    handle.log('binwalk not available on PATH — build the firmware Docker image to enable real extraction.');
    return { extractor: 'none', outputDir, rootfsPath: null, tree: null, summary: null };
  }

  handle.log(`Running: binwalk -Me -C ${outputDir} ${imagePath}`);
  try {
    const { stdout } = await execFileAsync('binwalk', ['-Me', '-C', outputDir, imagePath], {
      timeout: 10 * 60 * 1000,
      maxBuffer: 32 * 1024 * 1024,
    });
    for (const line of stdout.split('\n').slice(0, 200)) if (line.trim()) handle.log(line);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    handle.log(`binwalk exited non-zero (partial carve may still be usable): ${message}`);
  }

  const rootfsPath = findRootfs(outputDir);
  if (!rootfsPath) {
    handle.log('No Linux rootfs located in the carve output.');
    return { extractor: 'binwalk', outputDir, rootfsPath: null, tree: null, summary: null };
  }

  handle.log(`Rootfs located: ${rootfsPath}`);
  const entries = walkRootfs(rootfsPath);
  handle.log(`Walked ${entries.length} filesystem entries.`);
  const summary = summarizeFs(entries);
  const tree = buildFsTree(entries);
  const suggestedBinary = pickNetworkBinary(entries);

  return {
    extractor: 'binwalk',
    outputDir,
    rootfsPath,
    tree,
    summary,
    ...(suggestedBinary ? { suggestedBinary } : {}),
  };
}

/** Depth-first search for a directory that looks like a rootfs (has >=2 of bin/etc/sbin/lib). */
function findRootfs(root: string, depth = 0): string | null {
  if (depth > 8) return null;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return null;
  }
  const dirNames = new Set(entries.filter((e) => e.isDirectory()).map((e) => e.name));
  const markerHits = ROOTFS_MARKERS.filter((m) => dirNames.has(m)).length;
  if (markerHits >= 2) return root;

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const found = findRootfs(path.join(root, entry.name), depth + 1);
    if (found) return found;
  }
  return null;
}

/** Walk an extracted rootfs into flat FsEntry records, capped so a huge tree can't exhaust memory. */
function walkRootfs(rootfsPath: string, maxEntries = 100000): FsEntry[] {
  const out: FsEntry[] = [];
  const stack: string[] = [rootfsPath];
  while (stack.length > 0 && out.length < maxEntries) {
    const dir = stack.pop() as string;
    let dirents: fs.Dirent[];
    try {
      dirents = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const dirent of dirents) {
      const abs = path.join(dir, dirent.name);
      const rel = path.relative(rootfsPath, abs).split(path.sep).join('/');
      try {
        const stat = fs.lstatSync(abs);
        if (dirent.isSymbolicLink()) {
          out.push({ path: rel, type: 'symlink', size: 0, mode: stat.mode, symlinkTarget: safeReadlink(abs) });
        } else if (dirent.isDirectory()) {
          out.push({ path: rel, type: 'dir', size: 0, mode: stat.mode });
          stack.push(abs);
        } else if (dirent.isFile()) {
          out.push({ path: rel, type: 'file', size: stat.size, mode: stat.mode });
        } else {
          out.push({ path: rel, type: 'other', size: 0, mode: stat.mode });
        }
      } catch {
        // Unreadable node — skip.
      }
    }
  }
  return out;
}

function safeReadlink(abs: string): string {
  try {
    return fs.readlinkSync(abs);
  } catch {
    return '';
  }
}

/** Heuristic: pick a likely network-facing daemon/CGI to seed the emulation menu. */
function pickNetworkBinary(entries: FsEntry[]): string | undefined {
  const candidates = ['httpd', 'lighttpd', 'uhttpd', 'goahead', 'boa', 'mini_httpd', 'dropbear', 'telnetd', 'upnpd'];
  for (const name of candidates) {
    const hit = entries.find((e) => e.type === 'file' && e.path.split('/').pop() === name);
    if (hit) return hit.path;
  }
  const anyCgi = entries.find((e) => e.type === 'file' && e.path.endsWith('.cgi'));
  return anyCgi?.path;
}
