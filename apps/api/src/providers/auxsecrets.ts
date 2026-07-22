/**
 * Auxiliary-partition secret scan (W1/W3 breadth).
 *
 * `fsaudit` scans the ONE directory `findRootfs` recognizes as a Linux rootfs (>=2 of bin/etc/sbin/lib). But a
 * firmware routinely carves into SEVERAL filesystems — a main rootfs plus sibling data/config partitions — and a
 * secret can live in a sibling that is not a rootfs at all. The re-run's Tenda-Camera is exactly this: binwalk
 * splits it into `jffs2-root` (the rootfs, scanned) and `jffs2-root-0`/`-1` (config partitions, NOT scanned),
 * and the device-wide **1024-bit RSA private key `version/privkey.pem`** lives in the sibling → the app missed it.
 *
 * This provider walks the WHOLE extraction output (everything binwalk/jefferson carved), SKIPS the recognized
 * rootfs subtree (fsaudit already covers it), and content-scans the rest for embedded private keys — reusing
 * fsaudit's `scanContentSecrets`, so a PUBLIC key or certificate is correctly NOT flagged (BeanView-Camera's
 * `private_key.pem` is actually a PUBLIC key — an autonomous-pass overstatement this stays honest about). The
 * runner only reads bounded prefixes of key-ish files; the aggregation is the pure, already-tested detector.
 *
 * Closes docs/AUTONOMOUS-WORKERS.md §9 gap #5 (the extraction half).
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings-normalize.js';
import { scanContentSecrets } from './fsaudit.js';

const WALK_CAP = 20000;
const FILE_CAP = 1500;
const READ_BYTES = 512 * 1024;

// Key-ish files worth reading for an embedded private key (PEM is text; a versioned `.so.N` is not a key).
const SCAN_EXT = new Set(['.pem', '.key', '.crt', '.cer', '.conf', '.cfg', '.xml', '.json', '.txt', '.lua']);

/** Is this basename a candidate for the content secret scan (key-ish extension, or a `*key*`/extensionless name)? */
function isCandidate(base: string): boolean {
  const lower = base.toLowerCase();
  const dot = lower.lastIndexOf('.');
  const ext = dot > 0 ? lower.slice(dot) : '';
  if (SCAN_EXT.has(ext)) return true;
  if (lower.includes('key') || lower.includes('cert') || lower.includes('priv')) return true;
  return ext === ''; // extensionless config/secret files (bounded by FILE_CAP)
}

/** Read a bounded prefix of a file as UTF-8 (missing/unreadable → ''). */
function readBounded(abs: string): string {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, READ_BYTES);
      const b = Buffer.allocUnsafe(size);
      fs.readSync(fd, b, 0, size, 0);
      return b.toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return '';
  }
}

export interface AuxSecretsResult {
  available: boolean;
  findings: FindingDraft[];
  filesScanned: number;
  reason: string;
}

/**
 * Scan every carved filesystem under `outputDir` for embedded private keys, EXCLUDING the recognized rootfs
 * subtree (fsaudit covers that). Honest: no output dir → available:false; a public key/cert is not flagged. The
 * finding paths are output-dir-relative so the operator sees which partition (e.g. `…/jffs2-root-0/version/privkey.pem`).
 */
export function runAuxSecrets(outputDir: string | null | undefined, rootfsPath: string | null): AuxSecretsResult {
  if (!outputDir) {
    return { available: false, findings: [], filesScanned: 0, reason: 'No extraction output to scan.' };
  }
  const root = path.resolve(outputDir);
  try {
    if (!fs.statSync(root).isDirectory()) throw new Error('not a dir');
  } catch {
    return { available: false, findings: [], filesScanned: 0, reason: 'No extraction output to scan.' };
  }
  // Absolute rootfs prefix to skip (fsaudit already scanned it); guard the trailing separator so a sibling named
  // `jffs2-root-0` is not swallowed by a `jffs2-root` prefix match.
  const rootfsAbs = rootfsPath ? path.resolve(rootfsPath) : null;
  const skipPrefix = rootfsAbs ? rootfsAbs + path.sep : null;

  const files: { path: string; content: string }[] = [];
  let walked = 0;
  const stack: string[] = [root];
  while (stack.length > 0 && walked < WALK_CAP && files.length < FILE_CAP) {
    const dir = stack.pop() as string;
    if (skipPrefix && (dir === rootfsAbs || dir.startsWith(skipPrefix))) continue;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (walked >= WALK_CAP || files.length >= FILE_CAP) break;
      walked++;
      if (e.isSymbolicLink()) continue;
      const abs = path.join(dir, e.name);
      if (skipPrefix && (abs === rootfsAbs || abs.startsWith(skipPrefix))) continue;
      if (e.isDirectory()) {
        stack.push(abs);
        continue;
      }
      if (!e.isFile() || !isCandidate(e.name)) continue;
      files.push({ path: path.relative(root, abs), content: readBounded(abs) });
    }
  }

  const findings = scanContentSecrets(files);
  return {
    available: true,
    findings,
    filesScanned: files.length,
    reason: `Auxiliary-partition scan: ${files.length} key-ish file(s) across the carved partitions (excluding the main rootfs), ${findings.length} embedded private key(s) found. Public keys/certs are not flagged.`,
  };
}
