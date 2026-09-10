/**
 * Binary triage provider. Runs radare2 in batch/quiet mode over a single binary picked from the extracted
 * rootfs and returns a structured triage: binary info + hardening flags, imports, symbols, data-section
 * strings, and the analyzed function count. radare2 is optional — with it absent the job returns a clear
 * `available:false` result. The requested path is confined to the rootfs to prevent traversal.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { isToolAvailable } from '../tools.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

export interface DecompileInfo {
  arch?: string;
  bits?: number;
  bintype?: string;
  os?: string;
  endian?: string;
  canary?: boolean;
  nx?: boolean;
  pic?: boolean;
}

export interface DecompileResult {
  available: boolean;
  reason?: string;
  binary: string;
  info: DecompileInfo;
  functionCount: number;
  /** True pre-cap totals. Optional forever because persisted results from older builds do not carry them. */
  symbolsTotal?: number;
  importsTotal?: number;
  stringsTotal?: number;
  symbols: { name: string; type: string; addr: string }[];
  imports: { name: string; libname?: string }[];
  strings: { addr: string; value: string }[];
}

export const DECOMPILE_LIST_CAP = 300;
const SPLIT = '---R2SPLIT---';

/** Pure: cap a display/persistence list while retaining the denominator from before the cut. */
export function capDecompileItems<T>(
  items: T[],
  cap = DECOMPILE_LIST_CAP,
): {
  items: T[];
  total: number;
  complete: boolean;
} {
  const boundedCap = Math.max(0, Math.floor(cap));
  return { items: items.slice(0, boundedCap), total: items.length, complete: items.length <= boundedCap };
}

function unavailable(binary: string, reason: string): DecompileResult {
  return { available: false, reason, binary, info: {}, functionCount: 0, symbols: [], imports: [], strings: [] };
}

function hex(n: unknown): string {
  const v = typeof n === 'number' ? n : Number(n);
  return Number.isFinite(v) ? `0x${v.toString(16)}` : '0x0';
}

/** Parse a single JSON block, tolerating radare2 noise; returns fallback on any error. */
function parseBlock<T>(block: string | undefined, fallback: T): T {
  if (!block) return fallback;
  const trimmed = block.trim();
  if (!trimmed) return fallback;
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    return fallback;
  }
}

/** Pure: list blocks need a parse bit because `[]` and "radare2 emitted no valid JSON" are opposite evidence. */
export function parseDecompileList<T>(block: string | undefined): { items: T[]; parsed: boolean } {
  if (!block?.trim()) return { items: [], parsed: false };
  try {
    const value = JSON.parse(block.trim()) as unknown;
    return Array.isArray(value) ? { items: value as T[], parsed: true } : { items: [], parsed: false };
  } catch {
    return { items: [], parsed: false };
  }
}

/** Confine a rootfs-relative request to the rootfs; returns the absolute path or null on traversal/miss. */
export function resolveInsideRootfs(rootfsPath: string, binary: string): string | null {
  const root = path.resolve(rootfsPath);
  const abs = path.resolve(root, binary);
  if (abs !== root && !abs.startsWith(root + path.sep)) return null;
  try {
    if (!fs.statSync(abs).isFile()) return null;
  } catch {
    return null;
  }
  return abs;
}

export async function runDecompile(rootfsPath: string, binary: string, handle: JobHandle): Promise<DecompileResult> {
  if (!(await isToolAvailable('radare2'))) {
    handle.log('radare2 not available on PATH — build the firmware Docker image to enable binary triage.');
    return unavailable(binary, 'radare2 not installed');
  }

  const abs = resolveInsideRootfs(rootfsPath, binary);
  if (!abs) {
    handle.log(`Binary not found inside rootfs or path rejected: ${binary}`);
    return unavailable(binary, 'binary not found in rootfs');
  }

  // One analysis pass; JSON blocks separated by a printed sentinel so each parses independently.
  const script = `iIj;?e ${SPLIT};iij;?e ${SPLIT};isj;?e ${SPLIT};izj;?e ${SPLIT};aflj`;
  handle.log(`Running: radare2 -q -2 -A -c '${script}' ${abs}`);
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync('radare2', ['-q', '-2', '-A', '-c', script, abs], {
      timeout: 120 * 1000,
      maxBuffer: 32 * 1024 * 1024,
    }));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    handle.log(`radare2 failed: ${message}`);
    return unavailable(binary, `radare2 failed: ${message}`);
  }

  const [infoB, importsB, symbolsB, stringsB, funcsB] = stdout.split(SPLIT);

  // `iIj` returns the bin-info fields flat at the top level; `ij` nests them under `.bin`. Accept both.
  const rawInfo = parseBlock<Record<string, unknown> & { bin?: Record<string, unknown> }>(infoB, {});
  const bin = (rawInfo.bin ?? rawInfo) as Record<string, unknown>;
  // Build conditionally so absent fields stay absent (tsconfig exactOptionalPropertyTypes).
  const info: DecompileInfo = {
    ...(bin.arch ? { arch: String(bin.arch) } : {}),
    ...(typeof bin.bits === 'number' ? { bits: bin.bits } : {}),
    ...(bin.bintype ? { bintype: String(bin.bintype) } : {}),
    ...(bin.os ? { os: String(bin.os) } : {}),
    ...(bin.endian ? { endian: String(bin.endian) } : {}),
    ...(typeof bin.canary === 'boolean' ? { canary: bin.canary } : {}),
    ...(typeof bin.nx === 'boolean' ? { nx: bin.nx } : {}),
    ...(typeof bin.pic === 'boolean' ? { pic: bin.pic } : {}),
  };

  const rawImports = parseDecompileList<{ name?: string; libname?: string }>(importsB);
  const importInventory = capDecompileItems(rawImports.items);
  const imports = importInventory.items.map((i) => ({
    name: String(i.name ?? '?'),
    ...(i.libname ? { libname: String(i.libname) } : {}),
  }));

  const rawSymbols = parseDecompileList<{ name?: string; type?: string; vaddr?: number }>(symbolsB);
  const symbolInventory = capDecompileItems(rawSymbols.items);
  const symbols = symbolInventory.items.map((s) => ({
    name: String(s.name ?? '?'),
    type: String(s.type ?? ''),
    addr: hex(s.vaddr),
  }));

  const rawStrings = parseDecompileList<{ vaddr?: number; string?: string }>(stringsB);
  const stringInventory = capDecompileItems(rawStrings.items);
  const strings = stringInventory.items.map((s) => ({ addr: hex(s.vaddr), value: String(s.string ?? '') }));

  const rawFuncs = parseBlock<unknown[]>(funcsB, []);
  const functionCount = Array.isArray(rawFuncs) ? rawFuncs.length : 0;

  const describeList = (label: string, parsed: boolean, total: number, listed: number): string =>
    parsed
      ? `${total} ${label} (${listed} listed)`
      : `${listed} ${label} listed (total unavailable: radare2 block did not parse)`;

  handle.log(
    `Triage: ${info.arch ?? '?'}/${info.bits ?? '?'}bit, ${functionCount} functions, ${describeList('imports', rawImports.parsed, importInventory.total, imports.length)}, ${describeList('symbols', rawSymbols.parsed, symbolInventory.total, symbols.length)}, ${describeList('strings', rawStrings.parsed, stringInventory.total, strings.length)}.`,
  );

  return {
    available: true,
    binary,
    info,
    functionCount,
    ...(rawSymbols.parsed ? { symbolsTotal: symbolInventory.total } : {}),
    ...(rawImports.parsed ? { importsTotal: importInventory.total } : {}),
    ...(rawStrings.parsed ? { stringsTotal: stringInventory.total } : {}),
    symbols,
    imports,
    strings,
  };
}
