/**
 * Firmware extraction provider. Prefers `binwalk -Me` (recursive "matryoshka" carve) when available, then
 * walks whatever it produced to locate a Linux rootfs and model it via @firmlab/core's filesystem summarizer.
 * With no extractor present it degrades to a clear "unavailable" result rather than failing — the static
 * analysis (structure/entropy/strings) already gives value without a real rootfs.
 */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import {
  type Architecture,
  type Endianness,
  type FsEntry,
  type FsNode,
  type FsSummary,
  type ImageIdentity,
  buildFsTree,
  decodeElfArch,
  summarizeFs,
} from '@firmlab/core';
import { EXTRACT_DIR } from '../paths.js';
import { getImage, updateImageIdentity } from '../store.js';
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
  /** Architecture recovered by probing rootfs ELF headers (authoritative), when it could be determined. */
  detectedArch?: Architecture;
  detectedEndianness?: Endianness;
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

  // binwalk refuses to run its (third-party) extraction utilities as root unless explicitly told to; the Docker
  // image runs as root, so pass --run-as=root there. Harmless to omit when running unprivileged (local dev).
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const args = isRoot ? ['-Me', '--run-as=root', '-C', outputDir, imagePath] : ['-Me', '-C', outputDir, imagePath];
  handle.log(`Running: binwalk ${args.join(' ')}`);
  try {
    const { stdout } = await execFileAsync('binwalk', args, {
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

  const detected = detectRootfsArch(rootfsPath, entries);
  if (detected) {
    handle.log(`Detected architecture from rootfs ELFs: ${detected.arch} (${detected.endianness})`);
    persistRefinedIdentity(imageId, detected);
  }

  return {
    extractor: 'binwalk',
    outputDir,
    rootfsPath,
    tree,
    summary,
    ...(suggestedBinary ? { suggestedBinary } : {}),
    ...(detected ? { detectedArch: detected.arch, detectedEndianness: detected.endianness } : {}),
  };
}

/**
 * Probe the extracted rootfs for its real architecture by reading ELF headers. A firmware rootfs can hold a
 * stray foreign-arch helper, so we sample several binaries (preferring the base dirs) and take the modal
 * e_machine — authoritative where the static header scan only saw packed/compressed data.
 */
function detectRootfsArch(
  rootfsPath: string,
  entries: FsEntry[],
): { arch: Architecture; endianness: Endianness } | null {
  const rank = (p: string): number => {
    if (/^(bin|sbin)\//.test(p)) return 0;
    if (/^usr\/(bin|sbin)\//.test(p)) return 1;
    if (/^lib(64)?\//.test(p) || /^usr\/lib(64)?\//.test(p)) return 2;
    return 3;
  };
  const candidates = entries
    .filter((e) => e.type === 'file' && e.size > 0)
    .sort((a, b) => rank(a.path) - rank(b.path))
    .slice(0, 400);

  const tally = new Map<string, { arch: Architecture; endianness: Endianness; n: number }>();
  let sampled = 0;
  for (const entry of candidates) {
    if (sampled >= 24) break;
    const decoded = readElfArch(path.join(rootfsPath, entry.path));
    if (!decoded || decoded.arch === 'unknown') continue;
    sampled++;
    const key = `${decoded.arch}:${decoded.endianness}`;
    const cur = tally.get(key);
    if (cur) cur.n++;
    else tally.set(key, { ...decoded, n: 1 });
  }
  let best: { arch: Architecture; endianness: Endianness; n: number } | null = null;
  for (const v of tally.values()) if (!best || v.n > best.n) best = v;
  return best ? { arch: best.arch, endianness: best.endianness } : null;
}

/** Read just the ELF identification bytes of a file and decode its architecture, or null if not an ELF. */
function readElfArch(abs: string): { arch: Architecture; endianness: Endianness } | null {
  let fd: number | null = null;
  try {
    fd = fs.openSync(abs, 'r');
    const head = Buffer.alloc(20);
    const read = fs.readSync(fd, head, 0, 20, 0);
    if (read < 20) return null;
    if (head[0] !== 0x7f || head[1] !== 0x45 || head[2] !== 0x4c || head[3] !== 0x46) return null; // \x7fELF
    const bits = head[4] === 2 ? 64 : 32;
    const endianBig = head[5] === 2;
    const machine = endianBig ? head.readUInt16BE(18) : head.readUInt16LE(18);
    return decodeElfArch(machine, endianBig, bits);
  } catch {
    return null;
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
}

/** Merge a rootfs-probed arch into the stored identity (rootfs ELF headers are authoritative). */
function persistRefinedIdentity(imageId: string, detected: { arch: Architecture; endianness: Endianness }): void {
  const row = getImage(imageId);
  if (!row?.identityJson) return;
  try {
    const identity = JSON.parse(row.identityJson) as ImageIdentity;
    if (identity.arch === detected.arch && identity.endianness === detected.endianness) return;
    identity.arch = detected.arch;
    identity.endianness = detected.endianness;
    updateImageIdentity(imageId, JSON.stringify(identity));
  } catch {
    // Leave the cached identity untouched on any parse error.
  }
}

/** Files larger than this are not hashed during the walk (keeps extraction bounded); size-diff still applies. */
const HASH_CAP_BYTES = 8 * 1024 * 1024;

/** SHA-1 of a file's contents, or undefined if it can't be read. */
function hashFile(abs: string): string | undefined {
  try {
    return createHash('sha1').update(fs.readFileSync(abs)).digest('hex');
  } catch {
    return undefined;
  }
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
          const sha1 = stat.size <= HASH_CAP_BYTES ? hashFile(abs) : undefined;
          out.push({ path: rel, type: 'file', size: stat.size, mode: stat.mode, ...(sha1 ? { sha1 } : {}) });
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
