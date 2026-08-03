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
 * rootfs subtree (fsaudit already covers it), and scans the rest for embedded private keys.
 *
 * **What it had wrong until 2026-08-03, and it was the same defect fsaudit had.** The walk only collected files
 * whose extension was on a whitelist (plus anything with `key`/`cert`/`priv` in the name), read 512 KB of each as
 * UTF-8, and reported `filesScanned` without ever saying what it had skipped — so a key inside a binary in a
 * sibling partition was unreachable by construction, and a bound answered as if it were a measurement. It now
 * uses the shared byte-level `pem-scan` over EVERY file the walk finds, claims a block only when its body
 * DECODES, and reports the coverage: files read, files truncated, files skipped, bytes never read, and the rule
 * that chose them. A public key or a certificate is still correctly not flagged — BeanView-Camera's
 * `private_key.pem` is a PUBLIC key, an autonomous-pass overstatement this lane stays honest about.
 *
 * Closes docs/AUTONOMOUS-WORKERS.md §9 gap #5 (the extraction half).
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings-normalize.js';
import { keyMaterialFindings, unclaimedKeyBlockFindings } from './fsaudit.js';
import { DEFAULT_PEM_BUDGET, type PemScanCoverage, scanTreeForPem, summarizePemScan } from './pem-scan.js';

const WALK_CAP = 20000;

export interface AuxSecretsResult {
  available: boolean;
  findings: FindingDraft[];
  filesScanned: number;
  reason: string;
  /**
   * What the scan read and what it did not. OPTIONAL FOREVER — a result stored by an older build has none, and a
   * required field would be a claim about data this code does not own.
   */
  scan?: PemScanCoverage;
  /** True when the directory walk itself hit its cap, so files exist that the scan never even considered. */
  walkTruncated?: boolean;
}

/**
 * Scan every carved filesystem under `outputDir` for embedded private keys, EXCLUDING the recognized rootfs
 * subtree (fsaudit covers that). Honest: no output dir → available:false; a public key/cert is not flagged; a
 * block whose body does not decode is reported as unclaimed rather than counted as a key. The finding paths are
 * output-dir-relative so the operator sees which partition (e.g. `…/jffs2-root-0/version/privkey.pem`).
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

  const files: { path: string; bytes: number }[] = [];
  let walked = 0;
  let walkTruncated = false;
  const stack: string[] = [root];
  while (stack.length > 0) {
    if (walked >= WALK_CAP) {
      walkTruncated = true;
      break;
    }
    const dir = stack.pop() as string;
    if (skipPrefix && (dir === rootfsAbs || dir.startsWith(skipPrefix))) continue;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (walked >= WALK_CAP) {
        walkTruncated = true;
        break;
      }
      walked++;
      if (e.isSymbolicLink()) continue;
      const abs = path.join(dir, e.name);
      if (skipPrefix && (abs === rootfsAbs || abs.startsWith(skipPrefix))) continue;
      if (e.isDirectory()) {
        stack.push(abs);
        continue;
      }
      if (!e.isFile()) continue;
      let bytes = 0;
      try {
        bytes = fs.statSync(abs).size;
      } catch {
        continue;
      }
      files.push({ path: path.relative(root, abs), bytes });
    }
  }

  // Every file the walk found, read as BYTES under a stated budget — no extension whitelist, binaries included.
  const { scanned, skipped, rule } = scanTreeForPem(root, files, DEFAULT_PEM_BUDGET);
  const scan = summarizePemScan(scanned, skipped, rule);
  const keyMaterial = keyMaterialFindings(scanned.map((e) => ({ path: e.path, blocks: e.blocks })));
  const findings = [...keyMaterial.findings, ...unclaimedKeyBlockFindings(keyMaterial.unclaimed)];

  const bounds = [scan.note];
  if (walkTruncated) {
    bounds.push(
      `The directory walk stopped at its ${WALK_CAP}-entry cap, so files exist in this extraction that the scan never considered.`,
    );
  }
  const result: AuxSecretsResult = {
    available: true,
    findings,
    filesScanned: scanned.length,
    reason: `Auxiliary-partition scan across the carved partitions, excluding the main rootfs: ${keyMaterial.findings.length} embedded private key finding(s). Public keys and certificates are not flagged, and a private-key block whose body does not decode is reported rather than claimed. ${bounds.join(' ')}`,
    scan,
  };
  if (walkTruncated) result.walkTruncated = true;
  return result;
}
