/**
 * W1 — recursive, format-graph-driven carve.
 *
 * The historical single-pass extractor (`binwalk -Me`, one shot) returns **0 files** on an OpenWrt-style FIT
 * container: `binwalk -Me` refuses to run its extractors without `--run-as=root`, and `ubireader_extract_files`
 * aborts the whole carve when it trips on an empty UBIFS overlay volume (`rootfs_data`). The real chain a rootfs
 * needs there is FIT-parse → carve the `ubi` sub-image → split the UBI into per-volume LEB-reassembled images →
 * pick the rootfs volume (the largest SquashFS, not `wifi_fw`) → `unsquashfs`. See docs/AUTONOMOUS-WORKERS.md §3.2(1).
 *
 * This module owns that chain. The format parsers (`parseFitImages`, `parseUbiVolumes`, `pickRootfsVolume`) and
 * the recursive planner (`planCarve`) are **pure** — bytes in, structured carve plan out — so they are fully
 * unit-testable without any external tool, and they never abort on a malformed/empty sub-volume (the exact bug
 * that made the app report "no rootfs"): an unreadable volume is simply skipped, not fatal. The only tool-backed
 * step is the final `unsquashfs`/`sasquatch`, which degrades honestly — a carved-but-unextracted SquashFS volume
 * is a first-class, non-empty result, never a silent "0 files".
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { isToolAvailable } from '../tools.js';

const execFileAsync = promisify(execFile);

// === Byte helpers (bounds-guarded; never throw) ===
function be32(b: Uint8Array, o: number): number {
  if (o < 0 || o + 3 >= b.length) return 0;
  return (((b[o] ?? 0) << 24) | ((b[o + 1] ?? 0) << 16) | ((b[o + 2] ?? 0) << 8) | (b[o + 3] ?? 0)) >>> 0;
}
function be16(b: Uint8Array, o: number): number {
  if (o < 0 || o + 1 >= b.length) return 0;
  return (((b[o] ?? 0) << 8) | (b[o + 1] ?? 0)) & 0xffff;
}
function le32(b: Uint8Array, o: number): number {
  if (o < 0 || o + 3 >= b.length) return 0;
  return (((b[o] ?? 0) | ((b[o + 1] ?? 0) << 8) | ((b[o + 2] ?? 0) << 16) | ((b[o + 3] ?? 0) << 24)) >>> 0) >>> 0;
}
function alignUp(n: number, a: number): number {
  return Math.ceil(n / a) * a;
}
function cstr(b: Uint8Array, start: number, max = b.length): string {
  let e = start;
  while (e < max && e < b.length && (b[e] ?? 0) !== 0) e++;
  let s = '';
  for (let i = start; i < e; i++) s += String.fromCharCode(b[i] ?? 0);
  return s;
}

// === Leading-format detection ===
const FDT_MAGIC = 0xd00dfeed;
const UBI_EC_MAGIC = 0x55424923; // "UBI#"
const UBI_VID_MAGIC = 0x55424921; // "UBI!"
const SQUASHFS_LE = 0x73717368; // "hsqs" read as a little-endian u32

/** The recognizable leading format of a blob, for the carve step machine. */
export type BlobFormat = 'fit' | 'ubi' | 'squashfs' | 'ubifs' | 'unknown';

/** SquashFS little-endian ("hsqs") or big-endian ("sqsh") superblock magic at offset 0. */
function isSquashfs(b: Uint8Array): boolean {
  return le32(b, 0) === SQUASHFS_LE || (b[0] === 0x73 && b[1] === 0x71 && b[2] === 0x73 && b[3] === 0x68);
}
export function detectFormat(b: Uint8Array): BlobFormat {
  if (be32(b, 0) === FDT_MAGIC) return 'fit';
  if (be32(b, 0) === UBI_EC_MAGIC) return 'ubi';
  if (isSquashfs(b)) return 'squashfs';
  if (be32(b, 0) === 0x31181006 || le32(b, 0) === 0x06101831) return 'ubifs';
  return 'unknown';
}

// === FIT (Flattened Device Tree) parsing =================================================================

/** One sub-image inside a FIT container (a node under `/images/`), with the absolute range of its inlined data. */
export interface FitSubimage {
  name: string;
  type?: string;
  arch?: string;
  compression?: string;
  /** Absolute offset of the inlined `data` property value within the FIT buffer. */
  dataOffset: number;
  dataSize: number;
}

const FDT_BEGIN_NODE = 0x1;
const FDT_END_NODE = 0x2;
const FDT_PROP = 0x3;
const FDT_NOP = 0x4;
const FDT_END = 0x9;

/**
 * Parse a FIT/FDT and return the `/images/<name>` sub-images with the absolute byte range of their inlined
 * `data`. FIT inlines each payload in the structure block, so the `data` property's position IS where the
 * sub-image lives in the file. Never throws — a truncated/malformed tree returns what it parsed so far.
 */
export function parseFitImages(buf: Uint8Array): FitSubimage[] {
  if (be32(buf, 0) !== FDT_MAGIC) return [];
  const offStruct = be32(buf, 8);
  const offStrings = be32(buf, 12);
  const sizeStruct = be32(buf, 36);
  const structEnd = Math.min(offStruct + sizeStruct || buf.length, buf.length);

  const images: FitSubimage[] = [];
  const pathStack: string[] = [];
  let cur: FitSubimage | null = null;
  let pos = offStruct;
  let guard = 0;

  const isImageNode = (): boolean => pathStack.length === 3 && pathStack[1] === 'images';

  while (pos + 4 <= structEnd && guard++ < 200000) {
    const token = be32(buf, pos);
    pos += 4;
    if (token === FDT_BEGIN_NODE) {
      const name = cstr(buf, pos, structEnd);
      pos = alignUp(pos + name.length + 1, 4);
      pathStack.push(name);
      if (isImageNode()) cur = { name, dataOffset: -1, dataSize: 0 };
    } else if (token === FDT_END_NODE) {
      if (isImageNode() && cur) {
        if (cur.dataOffset >= 0) images.push(cur);
        cur = null;
      }
      pathStack.pop();
    } else if (token === FDT_PROP) {
      const len = be32(buf, pos);
      const nameOff = be32(buf, pos + 4);
      pos += 8;
      const valPos = pos;
      pos = alignUp(pos + len, 4);
      if (cur && isImageNode()) {
        const pname = cstr(buf, offStrings + nameOff);
        if (pname === 'data') {
          cur.dataOffset = valPos;
          cur.dataSize = len;
        } else if (pname === 'type' || pname === 'arch' || pname === 'compression') {
          cur[pname] = cstr(buf, valPos, valPos + len);
        }
      }
    } else if (token === FDT_NOP) {
      // skip
    } else if (token === FDT_END) {
      break;
    } else {
      break; // malformed token stream — stop honestly with what we have
    }
  }
  return images;
}

// === UBI parsing =========================================================================================

/** UBI volume-table volume id — holds the volume-name records, not user data. */
const UBI_LAYOUT_VOL_ID = 0x7fffefff;

/** A reassembled UBI volume: its logical eraseblocks concatenated in `lnum` order. */
export interface UbiVolume {
  volId: number;
  name?: string;
  data: Uint8Array;
  lebCount: number;
}

/** Find the erase-block (PEB) size by locating the stride at which the EC-header magic repeats. */
function detectPebSize(buf: Uint8Array): number {
  if (be32(buf, 0) !== UBI_EC_MAGIC) return 0;
  const candidates = [
    0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000,
  ];
  for (const stride of candidates) {
    let checked = 0;
    let ok = true;
    for (let k = 1; k <= 3; k++) {
      const off = k * stride;
      if (off + 4 > buf.length) break;
      checked++;
      if (be32(buf, off) !== UBI_EC_MAGIC) {
        ok = false;
        break;
      }
    }
    if (ok && checked >= 1) return stride;
  }
  return buf.length; // single-PEB image
}

/**
 * Split a UBI image into its volumes, reassembling each volume's logical eraseblocks (LEBs) in order. This is
 * the step `ubireader_extract_files` performs — except that here an empty/garbage overlay volume (the
 * `rootfs_data` UBIFS that aborted the reference tool) is simply an empty `UbiVolume`, never a fatal error.
 */
export function parseUbiVolumes(buf: Uint8Array): UbiVolume[] {
  const pebSize = detectPebSize(buf);
  if (pebSize <= 0) return [];
  const pebCount = Math.floor(buf.length / pebSize) || (buf.length > 0 ? 1 : 0);

  // Collect LEBs per volume; also capture the layout volume so we can name the user volumes.
  const perVol = new Map<number, { lnum: number; data: Uint8Array }[]>();
  let layout: Uint8Array | null = null;

  for (let p = 0; p < pebCount && p < 200000; p++) {
    const pebStart = p * pebSize;
    if (be32(buf, pebStart) !== UBI_EC_MAGIC) continue; // free/erased PEB
    const vidHdrOffset = be32(buf, pebStart + 0x10);
    const dataOffset = be32(buf, pebStart + 0x14);
    const vidStart = pebStart + vidHdrOffset;
    if (be32(buf, vidStart) !== UBI_VID_MAGIC) continue; // unmapped PEB (no volume payload)
    const volId = be32(buf, vidStart + 0x08);
    const lnum = be32(buf, vidStart + 0x0c);
    const leb = buf.subarray(pebStart + dataOffset, pebStart + pebSize);
    if (volId === UBI_LAYOUT_VOL_ID) {
      if (!layout) layout = leb;
      continue;
    }
    const list = perVol.get(volId) ?? [];
    list.push({ lnum, data: leb });
    perVol.set(volId, list);
  }

  const names = layout ? parseVtblNames(layout) : new Map<number, string>();
  const volumes: UbiVolume[] = [];
  for (const [volId, lebs] of perVol) {
    lebs.sort((a, b) => a.lnum - b.lnum);
    const total = lebs.reduce((n, l) => n + l.data.length, 0);
    const data = new Uint8Array(total);
    let cursor = 0;
    for (const l of lebs) {
      data.set(l.data, cursor);
      cursor += l.data.length;
    }
    const name = names.get(volId);
    volumes.push({ volId, ...(name ? { name } : {}), data, lebCount: lebs.length });
  }
  volumes.sort((a, b) => a.volId - b.volId);
  return volumes;
}

/** Read the UBI volume-table records from the layout volume to recover volume names (best-effort). */
function parseVtblNames(layout: Uint8Array): Map<number, string> {
  const RECORD = 172; // sizeof(struct ubi_vtbl_record)
  const names = new Map<number, string>();
  const count = Math.min(Math.floor(layout.length / RECORD), 128);
  for (let i = 0; i < count; i++) {
    const rec = i * RECORD;
    const nameLen = be16(layout, rec + 0x0e);
    if (nameLen === 0 || nameLen > 127) continue;
    const name = cstr(layout, rec + 0x10, rec + 0x10 + nameLen);
    if (name) names.set(i, name);
  }
  return names;
}

/** Which UBI volume is the root filesystem: prefer the largest SquashFS volume (never `wifi_fw`). */
export interface RootfsPick {
  volume: UbiVolume | null;
  isSquashfs: boolean;
  reason: string;
}
export function pickRootfsVolume(volumes: UbiVolume[]): RootfsPick {
  const squashfs = volumes.filter((v) => isSquashfs(v.data)).sort((a, b) => b.data.length - a.data.length);
  if (squashfs.length > 0) {
    const v = squashfs[0] as UbiVolume;
    return {
      volume: v,
      isSquashfs: true,
      reason: `volume ${v.name ?? `#${v.volId}`} (${v.data.length} B SquashFS) — the largest of ${squashfs.length} SquashFS volume(s)`,
    };
  }
  const largest = [...volumes].sort((a, b) => b.data.length - a.data.length)[0];
  if (largest) {
    return {
      volume: largest,
      isSquashfs: false,
      reason: `no SquashFS volume found; largest is ${largest.name ?? `#${largest.volId}`} (${largest.data.length} B, not SquashFS)`,
    };
  }
  return { volume: null, isSquashfs: false, reason: 'no UBI volumes recovered' };
}

// === Recursive carve planner (pure) ======================================================================

/** One honest step in the carve chain — what a stage did, or why it could go no further. */
export interface CarveStep {
  format: BlobFormat;
  action: string;
  detail: string;
  bytes?: number;
  blocked?: boolean;
}

export interface CarvePlan {
  trace: CarveStep[];
  /** The recovered SquashFS blob ready for `unsquashfs`, or null if the chain could not reach one. */
  squashfs: Uint8Array | null;
  /** The leading format of the blob the chain terminated on. */
  terminalFormat: BlobFormat;
  /** When `squashfs` is null, the honest reason the chain stopped. */
  terminalReason?: string;
}

/**
 * Walk the format graph FIT → UBI → SquashFS, returning the recovered SquashFS blob plus a step-by-step trace.
 * Pure and bounded; no I/O and no external tool. The trace is the chain-of-evidence the flat-rows UI is missing:
 * every stage says what it produced and, at the end, exactly why it stopped.
 */
export function planCarve(input: Uint8Array): CarvePlan {
  const trace: CarveStep[] = [];
  let cur = input;
  for (let depth = 0; depth < 8; depth++) {
    const fmt = detectFormat(cur);
    if (fmt === 'fit') {
      const images = parseFitImages(cur);
      const inv = images.map((i) => `${i.name}${i.type ? `(${i.type})` : ''}=${i.dataSize}B`).join(', ');
      const ubiImg =
        images.find((i) => (i.type ?? '').includes('ubi')) ??
        images.find((i) => be32(cur.subarray(i.dataOffset, i.dataOffset + 4), 0) === UBI_EC_MAGIC) ??
        // largest sub-image as a last resort (the rootfs payload dominates a FIT)
        [...images].sort((a, b) => b.dataSize - a.dataSize)[0];
      if (!ubiImg) {
        trace.push({
          format: 'fit',
          action: 'parse',
          detail: `FIT with no carvable sub-image (${inv})`,
          blocked: true,
        });
        return {
          trace,
          squashfs: null,
          terminalFormat: 'fit',
          terminalReason: 'FIT contained no UBI/rootfs sub-image',
        };
      }
      trace.push({
        format: 'fit',
        action: 'carve sub-image',
        detail: `FIT sub-images: [${inv}] → carved "${ubiImg.name}"`,
        bytes: ubiImg.dataSize,
      });
      cur = cur.subarray(ubiImg.dataOffset, ubiImg.dataOffset + ubiImg.dataSize);
    } else if (fmt === 'ubi') {
      const volumes = parseUbiVolumes(cur);
      const pick = pickRootfsVolume(volumes);
      const inv = volumes.map((v) => `${v.name ?? `#${v.volId}`}=${v.data.length}B`).join(', ');
      if (!pick.volume || !pick.isSquashfs) {
        trace.push({
          format: 'ubi',
          action: 'split volumes',
          detail: `UBI volumes: [${inv}] → ${pick.reason}`,
          blocked: true,
        });
        return {
          trace,
          squashfs: null,
          terminalFormat: 'ubi',
          terminalReason: `UBI split succeeded but ${pick.reason}`,
        };
      }
      trace.push({
        format: 'ubi',
        action: 'split volumes + pick rootfs',
        detail: `UBI volumes: [${inv}] → ${pick.reason}`,
        bytes: pick.volume.data.length,
      });
      cur = pick.volume.data;
    } else if (fmt === 'squashfs') {
      trace.push({
        format: 'squashfs',
        action: 'ready',
        detail: 'SquashFS rootfs volume recovered',
        bytes: cur.length,
      });
      return { trace, squashfs: cur, terminalFormat: 'squashfs' };
    } else {
      trace.push({ format: fmt, action: 'stop', detail: `no carve rule for a leading ${fmt} blob`, blocked: true });
      return { trace, squashfs: null, terminalFormat: fmt, terminalReason: `unhandled leading format: ${fmt}` };
    }
  }
  return { trace, squashfs: null, terminalFormat: detectFormat(cur), terminalReason: 'carve depth limit reached' };
}

// === Runner (I/O + the one tool-backed step) =============================================================

export interface CarveResult {
  /** Path the recovered SquashFS blob was written to, or null if the chain never reached a SquashFS. */
  squashfsPath: string | null;
  /** Path to the extracted rootfs directory, or null when no extractor tool was available. */
  rootfsDir: string | null;
  /** The step-by-step carve chain (the honest chain-of-evidence, surfaced by the extract provider). */
  trace: CarveStep[];
  /** Honest reason a rootfs directory was not produced (chain stopped, or the SquashFS tool is absent). */
  terminalReason?: string;
}

/** Minimal logger surface (matches providers/jobs.ts JobHandle) so this stays testable in isolation. */
interface CarveLogger {
  log(line: string): void;
}

/**
 * Read the image, run the pure carve plan, and — when it reaches a SquashFS volume — extract it with
 * `unsquashfs` (falling back to `sasquatch` for vendor variants). Degrades honestly at every step: if no
 * extractor is installed, the carved SquashFS blob is still written and reported, never a silent empty.
 */
export async function runRecursiveCarve(
  imagePath: string,
  outputDir: string,
  handle: CarveLogger,
): Promise<CarveResult> {
  fs.mkdirSync(outputDir, { recursive: true });
  const bytes = new Uint8Array(fs.readFileSync(imagePath));
  const plan = planCarve(bytes);
  for (const step of plan.trace) {
    handle.log(`carve[${step.format}] ${step.action}: ${step.detail}${step.blocked ? ' (stopped)' : ''}`);
  }

  if (!plan.squashfs) {
    return {
      squashfsPath: null,
      rootfsDir: null,
      trace: plan.trace,
      ...(plan.terminalReason ? { terminalReason: plan.terminalReason } : {}),
    };
  }

  const squashfsPath = path.join(outputDir, 'carved_rootfs.squashfs');
  fs.writeFileSync(squashfsPath, plan.squashfs);
  handle.log(`Wrote carved SquashFS rootfs volume → ${squashfsPath} (${plan.squashfs.length} B)`);

  const rootfsDir = path.join(outputDir, 'rootfs');
  const extractor = (await isToolAvailable('unsquashfs'))
    ? 'unsquashfs'
    : (await isToolAvailable('sasquatch'))
      ? 'sasquatch'
      : null;
  if (!extractor) {
    const reason =
      'SquashFS rootfs volume carved, but neither unsquashfs nor sasquatch is installed — build the firmware Docker image to extract it.';
    handle.log(reason);
    return { squashfsPath, rootfsDir: null, trace: plan.trace, terminalReason: reason };
  }

  fs.rmSync(rootfsDir, { recursive: true, force: true });
  try {
    handle.log(`Running: ${extractor} -f -d ${rootfsDir} ${squashfsPath}`);
    await execFileAsync(extractor, ['-f', '-d', rootfsDir, squashfsPath], {
      timeout: 10 * 60 * 1000,
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    handle.log(`${extractor} exited non-zero (a partial tree may still be usable): ${message}`);
  }
  const extracted = fs.existsSync(rootfsDir) && fs.readdirSync(rootfsDir).length > 0;
  return {
    squashfsPath,
    rootfsDir: extracted ? rootfsDir : null,
    trace: plan.trace,
    ...(extracted ? {} : { terminalReason: `${extractor} produced no files` }),
  };
}
