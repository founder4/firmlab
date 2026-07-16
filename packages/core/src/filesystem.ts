/**
 * Model an extracted firmware root filesystem as a tree, and summarize the audit-relevant surface: setuid
 * binaries, world-writable files, and notable config/secret-bearing paths. The API walks a real extracted
 * rootfs on disk and feeds `FsEntry[]` here; keeping the summarization pure makes it unit-testable.
 */
import type { FsNode, FsSummary } from './types.js';

/** A flat filesystem entry as produced by walking an extracted rootfs on disk. */
export interface FsEntry {
  /** Path relative to the rootfs root, using forward slashes, e.g. `etc/passwd`. */
  path: string;
  type: FsNode['type'];
  size: number;
  mode?: number;
  symlinkTarget?: string;
}

const S_ISUID = 0o4000;
const S_ISGID = 0o2000;
const S_IWOTH = 0o0002;

/** Filenames/paths that commonly carry credentials or steer boot, worth surfacing regardless of mode. */
const NOTABLE_RE =
  /(^|\/)(etc\/passwd|etc\/shadow|etc\/rc\.local|etc\/inittab|.*\.pem|.*\.key|.*\.crt|.*_rsa|authorized_keys|shadow|nvram.*|.*\.conf|.*\.cfg)$/i;

/** Build a nested tree from flat entries. Intermediate dirs are synthesized when not explicitly present. */
export function buildFsTree(entries: FsEntry[]): FsNode {
  const root: FsNode = { path: '', name: '/', type: 'dir', size: 0, children: [] };
  const dirIndex = new Map<string, FsNode>();
  dirIndex.set('', root);

  function ensureDir(dirPath: string): FsNode {
    if (dirIndex.has(dirPath)) return dirIndex.get(dirPath) as FsNode;
    const name = dirPath.split('/').pop() ?? dirPath;
    const parentPath = dirPath.includes('/') ? dirPath.slice(0, dirPath.lastIndexOf('/')) : '';
    const parent = ensureDir(parentPath);
    const node: FsNode = { path: dirPath, name, type: 'dir', size: 0, children: [] };
    parent.children = parent.children ?? [];
    parent.children.push(node);
    dirIndex.set(dirPath, node);
    return node;
  }

  const sorted = [...entries].sort((a, b) => a.path.localeCompare(b.path));
  for (const entry of sorted) {
    const normalized = entry.path.replace(/^\/+/, '').replace(/\/+$/, '');
    if (!normalized) continue;
    if (entry.type === 'dir') {
      applyAttrs(ensureDir(normalized), entry);
      continue;
    }
    const parentPath = normalized.includes('/') ? normalized.slice(0, normalized.lastIndexOf('/')) : '';
    const parent = ensureDir(parentPath);
    const name = normalized.split('/').pop() ?? normalized;
    const node: FsNode = { path: normalized, name, type: entry.type, size: entry.size };
    applyAttrs(node, entry);
    parent.children = parent.children ?? [];
    parent.children.push(node);
  }
  return root;
}

function applyAttrs(node: FsNode, entry: FsEntry): void {
  if (entry.mode !== undefined) {
    node.mode = entry.mode;
    if (entry.mode & S_ISUID) node.setuid = true;
    if (entry.mode & S_ISGID) node.setgid = true;
  }
  if (entry.symlinkTarget !== undefined) node.symlinkTarget = entry.symlinkTarget;
}

/** Compute the audit summary from flat entries (independent of the tree, for direct use). */
export function summarizeFs(entries: FsEntry[]): FsSummary {
  let totalFiles = 0;
  let totalDirs = 0;
  let totalSymlinks = 0;
  const setuidBinaries: FsNode[] = [];
  const worldWritable: FsNode[] = [];
  const notable: FsNode[] = [];

  for (const entry of entries) {
    if (entry.type === 'dir') totalDirs++;
    else if (entry.type === 'symlink') totalSymlinks++;
    else totalFiles++;

    const node = toNode(entry);
    if (entry.mode !== undefined) {
      if ((entry.mode & S_ISUID || entry.mode & S_ISGID) && entry.type === 'file') setuidBinaries.push(node);
      if (entry.mode & S_IWOTH && entry.type === 'file') worldWritable.push(node);
    }
    if (NOTABLE_RE.test(entry.path)) notable.push(node);
  }

  return { totalFiles, totalDirs, totalSymlinks, setuidBinaries, worldWritable, notable };
}

function toNode(entry: FsEntry): FsNode {
  const name = entry.path.split('/').pop() ?? entry.path;
  const node: FsNode = { path: entry.path, name, type: entry.type, size: entry.size };
  applyAttrs(node, entry);
  return node;
}
