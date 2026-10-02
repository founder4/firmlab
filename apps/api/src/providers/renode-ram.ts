/**
 * Renode RAM-capture provider — provides RAM snapshots for FreeRTOS task analysis from emulated execution.
 *
 * FreeRTOS task inspection (`rtos-tasks.ts`) walks task list structures (`pxCurrentTCB`, `pxReadyTasksLists`, etc.)
 * in a real RAM buffer. On physical MCUs or bare-metal images, that RAM must either be dumped by the operator or
 * captured from a running emulator. This provider runs the firmware under Renode for a bounded number of seconds,
 * pauses emulation, and dumps the peripheral SRAM binary through Renode's peripheral-level `DumpBinary` method.
 *
 * What it refuses to claim:
 *
 *  - **A RAM capture is not proof that the scheduler ran or that tasks exist.** A dump shows only whatever bytes the
 *    emulated SoC wrote during the bounded run. The proof state is pinned at `needs_runtime_reproduction`:
 *    the snapshot requires runtime validation by the task list walker.
 *  - **A default RAM address is never guessed.** Many Cortex-M MCUs place SRAM at `0x20000000`, but others map it
 *    elsewhere (e.g. TCM at `0x00000000`, DTCM at `0x20000000`, AXI SRAM at `0x24000000`, or external SDRAM).
 *    The target RAM region is selected strictly by matching the platform's declared `Memory.MappedMemory` peripherals
 *    against the ELF's writable `PT_LOAD` segments and/or resolved FreeRTOS kernel symbols. If no match is found,
 *    or the firmware is not an ELF, the capture is refused honestly with the reason.
 *  - **Snapshots exceeding MAX_SNAPSHOT_BYTES are refused.** The FreeRTOS snapshot contract caps buffers at 512 KiB.
 *    Any peripheral region exceeding 512 KiB is refused honestly rather than dumping an arbitrary window around
 *    symbols, because truncated windows risk bisecting heap-allocated TCBs or state list items.
 *  - **Renode runs strictly OFFLINE.** Renode platforms that reference remote SVD files (`ApplySVD @https://...`)
 *    are contained by `OFFLINE_RENODE_ENV` aiming proxy traffic at a refusing loopback port. Refused remote references
 *    are reported in `remoteResourcesRefused`.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  type ElfSymbolsResult,
  type McuFingerprint,
  type ProofState,
  fingerprintMcu,
  readElfSymbols,
  resolveFreeRtosKernelSymbols,
} from '@firmlab/core';

import { type IsolationLevel, type IsolationLimits, loadIsolationLimits, runIsolated } from './isolate.js';
import {
  REMOTE_SCAN_MAX_DEPTH,
  REMOTE_SCAN_MAX_FILES,
  RENODE_PLATFORMS_DIR,
  RENODE_ROOT,
  describeMcu,
  describeRefusedRemote,
  detectRenode,
  isWithin,
  listPlatformCatalog,
  offlineRenodeEnv,
  readFirmwareBounded,
  renodeHintsFrom,
  scanRemoteResources,
  selectPlatform,
  stripReplComments,
} from './renode.js';
import { MAX_SNAPSHOT_BYTES } from './rtos-tasks.js';

/** Default emulation time in seconds before pausing to dump RAM. */
export const DEFAULT_RAM_CAPTURE_SECONDS = 2;
/** Hard bounds on allowed emulation duration for RAM capture. */
export const MIN_RAM_CAPTURE_SECONDS = 1;
export const MAX_RAM_CAPTURE_SECONDS = 30;

/** A memory peripheral declared on sysbus in a Renode `.repl` description. */
export interface MappedMemoryRegion {
  /** Peripheral name on sysbus, e.g. `sram`, `sram0`, `syscfg`. */
  name: string;
  /** Base address on the system bus. */
  base: number;
  /** Size of the memory region in bytes. */
  size: number;
}

/** Parse an integer value in hex (`0x...`) or decimal, tolerating underscores. */
function parseReplNumber(s: string): number | undefined {
  const clean = s.trim().replace(/_/g, '');
  if (/^0x[0-9a-fA-F]+$/i.test(clean)) {
    const val = Number.parseInt(clean, 16);
    return Number.isFinite(val) ? val : undefined;
  }
  if (/^\d+$/.test(clean)) {
    const val = Number.parseInt(clean, 10);
    return Number.isFinite(val) ? val : undefined;
  }
  return undefined;
}

/** A temporary entry during .repl parsing before base/size are validated. */
export interface ReplMemoryEntry {
  name: string;
  base?: number | undefined;
  size?: number | undefined;
}

/**
 * Pure: parse peripheral declarations from the text of a `.repl` file, recording `Memory.MappedMemory` peripherals
 * and property overrides on existing peripherals (e.g. `size:` overrides in board descriptions).
 */
export function parseReplMemoryText(
  text: string,
  map: Map<string, ReplMemoryEntry> = new Map(),
): Map<string, ReplMemoryEntry> {
  const clean = stripReplComments(text);
  const lines = clean.split('\n');
  let current: ReplMemoryEntry | null = null;
  let inMultiRegistration = false;

  for (const line of lines) {
    // Check for an unindented peripheral declaration or override: `ident: ...`
    const header = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:Memory\.MappedMemory\b)?(.*)$/);
    if (header && header[1] !== undefined) {
      const name = header[1];
      const rest = header[2] ?? '';
      const isDecl = line.includes('Memory.MappedMemory');

      if (isDecl) {
        if (!map.has(name)) {
          map.set(name, { name });
        }
        current = map.get(name) ?? null;
        const singleSysbus = rest.match(/@\s*sysbus\s+(0x[0-9a-fA-F_]+|\d+)/i);
        if (singleSysbus && singleSysbus[1] !== undefined && current) {
          const parsed = parseReplNumber(singleSysbus[1]);
          if (parsed !== undefined) current.base = parsed;
        }
        if (rest.includes('@') && rest.includes('{')) {
          inMultiRegistration = true;
        }
      } else if (map.has(name)) {
        current = map.get(name) ?? null;
      } else {
        current = null;
      }
      continue;
    }

    if (inMultiRegistration && current) {
      const sysbusMatch = line.match(/sysbus\s+(0x[0-9a-fA-F_]+|\d+)/i);
      if (sysbusMatch && sysbusMatch[1] !== undefined && current.base === undefined) {
        const parsed = parseReplNumber(sysbusMatch[1]);
        if (parsed !== undefined) current.base = parsed;
      }
      if (line.includes('}')) inMultiRegistration = false;
    }

    if (current) {
      const sizeMatch = line.match(/^\s*size\s*:\s*(0x[0-9a-fA-F_]+|\d+)/i);
      if (sizeMatch && sizeMatch[1] !== undefined) {
        const parsed = parseReplNumber(sizeMatch[1]);
        if (parsed !== undefined) current.size = parsed;
      }
    }
  }

  return map;
}

/**
 * Pure (file reads, bounded): discover all `Memory.MappedMemory` peripherals declared by a platform and its
 * `using`-included dependencies. Follows `./relative` includes relative to the including file and root-relative
 * includes relative to `renodeRoot`. Evaluates dependencies first so board-level definitions can override CPU sizes.
 */
export function parsePlatformMemory(
  platformPath: string,
  renodeRoot: string = RENODE_ROOT,
  bounds: { maxDepth?: number; maxFiles?: number } = {},
): MappedMemoryRegion[] {
  const maxDepth = bounds.maxDepth ?? REMOTE_SCAN_MAX_DEPTH;
  const maxFiles = bounds.maxFiles ?? REMOTE_SCAN_MAX_FILES;
  const root = path.resolve(renodeRoot);
  const seen = new Set<string>();
  let filesScanned = 0;
  const map = new Map<string, ReplMemoryEntry>();

  const visit = (file: string, depth: number): void => {
    const abs = path.resolve(file);
    if (seen.has(abs)) return;
    seen.add(abs);
    if (!isWithin(root, abs) && abs !== path.resolve(platformPath)) return;
    if (depth > maxDepth || filesScanned >= maxFiles) return;

    let text: string;
    try {
      text = fs.readFileSync(abs, 'utf8');
    } catch {
      return;
    }
    filesScanned++;
    const clean = stripReplComments(text);

    // Follow includes first (depth-first) so child definitions can override defaults
    for (const m of clean.matchAll(/^[ \t]*using[ \t]+"([^"]+)"/gm)) {
      const raw = m[1];
      if (!raw) continue;
      const inc = raw.endsWith('.repl') ? raw : `${raw}.repl`;
      const target = inc.startsWith('.') ? path.resolve(path.dirname(abs), inc) : path.resolve(root, inc);
      visit(target, depth + 1);
    }

    parseReplMemoryText(clean, map);
  };

  visit(platformPath, 0);

  const regions: MappedMemoryRegion[] = [];
  for (const r of map.values()) {
    if (r.base !== undefined && r.size !== undefined && r.size > 0) {
      regions.push({ name: r.name, base: r.base, size: r.size });
    }
  }
  return regions;
}

export interface RamRegionSelection {
  region: MappedMemoryRegion;
  rule: 'freertos-symbols' | 'elf-writable-segment';
  reason: string;
}

export type RamRegionSelectionResult = { ok: true; selection: RamRegionSelection } | { ok: false; reason: string };

/**
 * Pure: choose the RAM region to dump by a stated rule:
 *
 * 1. Resolved FreeRTOS kernel symbols (`resolveFreeRtosKernelSymbols`): if present with absolute addresses,
 *    they identify the exact memory space where FreeRTOS task lists live. If all resolved symbols fall into
 *    a single platform memory region, that region is selected under rule `'freertos-symbols'`.
 * 2. Writable `PT_LOAD` segments: if FreeRTOS symbols are absent (e.g. non-FreeRTOS RTOS, Zephyr, stripped ELF),
 *    the ELF's writable load segments (.data / .bss) identify the RAM region. If a single platform memory region
 *    contains the writable segment(s), that region is selected under rule `'elf-writable-segment'`.
 * 3. Otherwise, refuse honestly stating the reason. Never guess a default RAM base such as 0x20000000.
 */
export function selectRamRegion(regions: MappedMemoryRegion[], elf: ElfSymbolsResult): RamRegionSelectionResult {
  if (regions.length === 0) {
    return { ok: false, reason: 'Platform declares no sysbus MappedMemory peripherals to dump.' };
  }

  if (elf.status !== 'parsed') {
    return {
      ok: false,
      reason: `Firmware is not a readable ELF file (${elf.code}: ${elf.detail}); cannot identify target RAM region without load segments or symbols (refusing to guess a default base address).`,
    };
  }

  // Rule 1: Check resolved FreeRTOS kernel symbols
  const kernel = resolveFreeRtosKernelSymbols(elf);
  const resolvedAddresses: { name: string; address: number }[] = [];
  for (const s of kernel.symbols) {
    if (s.status === 'resolved' && s.candidates.length === 1 && s.candidates[0]?.address != null) {
      resolvedAddresses.push({ name: s.name, address: s.candidates[0].address });
    }
  }

  if (resolvedAddresses.length > 0) {
    const matchingRegions = new Set<MappedMemoryRegion>();
    for (const sym of resolvedAddresses) {
      const match = regions.find((r) => sym.address >= r.base && sym.address < r.base + r.size);
      if (match) matchingRegions.add(match);
    }

    if (matchingRegions.size === 1) {
      const region = Array.from(matchingRegions)[0];
      if (region) {
        return {
          ok: true,
          selection: {
            region,
            rule: 'freertos-symbols',
            reason: `RAM region '${region.name}' [0x${region.base.toString(16)}, +0x${region.size.toString(16)}] contains all ${resolvedAddresses.length} resolved FreeRTOS kernel symbols.`,
          },
        };
      }
    }

    if (matchingRegions.size > 1) {
      const names = Array.from(matchingRegions)
        .map((r) => `'${r.name}'`)
        .join(', ');
      return {
        ok: false,
        reason: `Ambiguous RAM match: resolved FreeRTOS symbols span multiple platform regions (${names}).`,
      };
    }
  }

  // Rule 2: Check writable PT_LOAD segments
  // In embedded ELFs, the flash text segment is often mapped with RWX (write+execute).
  // Prefer non-executable writable segments (data/bss in RAM); fall back to all writable segments.
  const nonExecWritable = elf.segments.filter((s) => s.flags.write && !s.flags.execute && s.memsz > 0);
  const writableSegs =
    nonExecWritable.length > 0 ? nonExecWritable : elf.segments.filter((s) => s.flags.write && s.memsz > 0);
  if (writableSegs.length > 0) {
    let matchingRegions = new Set<MappedMemoryRegion>();
    for (const seg of writableSegs) {
      const match = regions.find((r) => seg.vaddr >= r.base && seg.vaddr < r.base + r.size);
      if (match) matchingRegions.add(match);
    }
    if (matchingRegions.size > 1) {
      const ramNamed = Array.from(matchingRegions).filter(
        (r) => /ram/i.test(r.name) && !/^(flash|rom|eeprom|syscfg)/i.test(r.name),
      );
      if (ramNamed.length === 1) {
        matchingRegions = new Set(ramNamed);
      }
    }

    if (matchingRegions.size === 1) {
      const region = Array.from(matchingRegions)[0];
      if (region) {
        return {
          ok: true,
          selection: {
            region,
            rule: 'elf-writable-segment',
            reason: `RAM region '${region.name}' [0x${region.base.toString(16)}, +0x${region.size.toString(16)}] contains the ELF writable PT_LOAD segment(s).`,
          },
        };
      }
    }

    if (matchingRegions.size > 1) {
      const names = Array.from(matchingRegions)
        .map((r) => `'${r.name}'`)
        .join(', ');
      return {
        ok: false,
        reason: `Ambiguous RAM match: ELF writable segments span multiple platform regions (${names}).`,
      };
    }

    const segDescs = writableSegs.map((s) => `[0x${s.vaddr.toString(16)}, +0x${s.memsz.toString(16)}]`).join(', ');
    const regionDescs = regions
      .map((r) => `${r.name}:[0x${r.base.toString(16)}, +0x${r.size.toString(16)}]`)
      .join(', ');
    return {
      ok: false,
      reason: `None of the platform memory regions (${regionDescs}) contain the ELF writable segments (${segDescs}).`,
    };
  }

  return {
    ok: false,
    reason: 'ELF carries neither resolved FreeRTOS symbols nor writable PT_LOAD segments to identify the RAM region.',
  };
}

/**
 * Pure: build the headless Renode script that creates the machine, loads the platform and ELF,
 * runs emulation for a bounded duration, pauses, dumps the peripheral RAM, and quits.
 */
export function buildRenodeRamCaptureScript(
  platformPath: string,
  firmwarePath: string,
  regionName: string,
  dumpSize: number,
  dumpOutputPath: string,
  seconds: number,
): string {
  const lines = [
    'mach create',
    `machine LoadPlatformDescription @${platformPath}`,
    `sysbus LoadELF @${firmwarePath}`,
    'start',
    `sleep ${seconds}`,
    'pause',
    `sysbus.${regionName} DumpBinary @${dumpOutputPath} 0 0x${dumpSize.toString(16)}`,
    'quit',
  ];
  return lines.join('\n');
}

/**
 * Pure: construct the isolated command-line invocation and limits for Renode RAM capture.
 */
export function buildRenodeRamInvocation(
  rescPath: string,
  seconds: number,
  work: string,
  baseEnv: NodeJS.ProcessEnv = process.env,
): { argv: string[]; options: { limits: IsolationLimits; env: NodeJS.ProcessEnv } } {
  return {
    argv: ['renode', '--disable-xwt', '--console', '--plain', '-e', `include @${rescPath}`],
    options: {
      limits: {
        ...loadIsolationLimits(baseEnv),
        cpuSeconds: seconds * 4 + 60,
        addressSpaceBytes: 0,
        fileSizeBytes: 0,
        openFiles: 8192,
        wallMs: (seconds + 45) * 1000,
      },
      env: offlineRenodeEnv(baseEnv, work),
    },
  };
}

export interface RenodeRamCaptureOptions {
  /** Explicit platform .repl path (e.g. `/opt/renode/platforms/cpus/stm32l072.repl`). */
  platform?: string | undefined;
  /** Emulation run duration in seconds before RAM dump (default 2s, bounds 1-30s). */
  seconds?: number | undefined;
  hints?: string[] | undefined;
  identityJson?: string | null | undefined;
  analysisJson?: string | null | undefined;
}

export interface RenodeRamCaptureResult {
  available: boolean;
  ran: boolean;
  captured: boolean;
  reason: string;
  proofState: ProofState;
  platform: string | null;
  region: { name: string; base: number; size: number } | null;
  bytesBase64: string | null;
  /** Alias for bytesBase64 for ergonomic consumption. */
  bytes: string | null;
  bytesCaptured: number;
  seconds: number;
  secondsRun: number;
  layout?: {
    endian: 'little' | 'big';
    pointerWidth: 4 | 8;
  };
  remoteResourcesRefused?: string[];
  command?: string;
  isolation?: IsolationLevel;
}

function withLeadingSpace(sentence: string): string {
  return sentence ? ` ${sentence}` : '';
}

/**
 * Run a bounded Renode emulation session to capture a peripheral RAM dump.
 * Degrades honestly when Renode or a matching platform description is missing.
 */
export async function runRenodeRamCapture(
  firmwarePath: string,
  opts: RenodeRamCaptureOptions = {},
): Promise<RenodeRamCaptureResult> {
  const seconds = Math.min(
    Math.max(opts.seconds ?? DEFAULT_RAM_CAPTURE_SECONDS, MIN_RAM_CAPTURE_SECONDS),
    MAX_RAM_CAPTURE_SECONDS,
  );

  const blocked = (reason: string, platform: string | null = null): RenodeRamCaptureResult => ({
    available: false,
    ran: false,
    captured: false,
    reason,
    proofState: 'blocked_by_platform',
    platform,
    region: null,
    bytesBase64: null,
    bytes: null,
    bytesCaptured: 0,
    seconds,
    secondsRun: seconds,
  });

  if (!(await detectRenode())) {
    return blocked('Renode not installed (opt-in layer).');
  }

  let firmwareBytes: Uint8Array;
  try {
    firmwareBytes = readFirmwareBounded(firmwarePath);
  } catch {
    firmwareBytes = new Uint8Array();
  }

  const elf = readElfSymbols(firmwareBytes);
  const layout =
    elf.status === 'parsed'
      ? {
          endian: elf.identity.endian,
          pointerWidth: elf.identity.pointerWidth,
        }
      : undefined;

  let fp: McuFingerprint;
  try {
    fp = fingerprintMcu(firmwareBytes);
  } catch {
    fp = fingerprintMcu(new Uint8Array());
  }

  let platform = opts.platform ?? null;
  if (!platform) {
    const hints = opts.hints ?? renodeHintsFrom(opts.identityJson ?? null, opts.analysisJson ?? null);
    const sel = selectPlatform(fp, hints, listPlatformCatalog());
    if (sel) {
      platform = path.join(RENODE_PLATFORMS_DIR, sel.repl);
    }
  }

  if (!platform) {
    return {
      ...blocked(
        `No bundled Renode platform for the detected MCU (${describeMcu(fp)}). RAM capture needs a matching .repl; not fabricating a run.`,
      ),
      available: true,
      ...(layout ? { layout } : {}),
    };
  }

  const memoryRegions = parsePlatformMemory(platform, RENODE_ROOT);
  const selection = selectRamRegion(memoryRegions, elf);

  if (!selection.ok) {
    return {
      ...blocked(`Platform ${path.basename(platform)}: ${selection.reason}`, platform),
      available: true,
      ...(layout ? { layout } : {}),
    };
  }

  const { region, rule } = selection.selection;

  // Enforce MAX_SNAPSHOT_BYTES cap
  if (region.size > MAX_SNAPSHOT_BYTES) {
    return {
      ...blocked(
        `Selected RAM region '${region.name}' size (${region.size} bytes) exceeds snapshot limit MAX_SNAPSHOT_BYTES (${MAX_SNAPSHOT_BYTES} bytes). An unwindowed dump preserves full SRAM up to the limit without truncating heap-allocated TCBs.`,
        platform,
      ),
      available: true,
      region,
      ...(layout ? { layout } : {}),
    };
  }

  const remoteScan = scanRemoteResources(platform, RENODE_ROOT);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-renode-ram-'));

  try {
    const dumpFile = path.join(work, 'ram.bin');
    const rescPath = path.join(work, 'capture.resc');
    const script = buildRenodeRamCaptureScript(platform, firmwarePath, region.name, region.size, dumpFile, seconds);
    fs.writeFileSync(rescPath, script);

    const invocation = buildRenodeRamInvocation(rescPath, seconds, work);
    const res = await runIsolated(invocation.argv, invocation.options);

    let captured = false;
    let dumpBuf: Buffer | null = null;
    if (fs.existsSync(dumpFile)) {
      try {
        dumpBuf = fs.readFileSync(dumpFile);
        captured = dumpBuf.length > 0;
      } catch {
        dumpBuf = null;
      }
    }

    const base64 = dumpBuf && captured ? dumpBuf.toString('base64') : null;
    const bytesCaptured = dumpBuf ? dumpBuf.length : 0;

    const reason = captured
      ? `Captured ${bytesCaptured} bytes of RAM peripheral '${region.name}' [0x${region.base.toString(16)}, +0x${region.size.toString(16)}] selected via ${rule} after ${seconds}s emulation on ${path.basename(platform)}.${withLeadingSpace(describeRefusedRemote(remoteScan))}`
      : res.timedOut
        ? `Renode run timed out after ${seconds}s without producing RAM dump file.`
        : `Renode run ended without producing RAM dump (${res.stderr.slice(-200) || res.stdout.slice(-200) || 'no output'}).${withLeadingSpace(describeRefusedRemote(remoteScan))}`;

    return {
      available: true,
      ran: res.ran,
      captured,
      reason,
      proofState: captured ? 'needs_runtime_reproduction' : 'blocked_by_platform',
      platform,
      region,
      bytesBase64: base64,
      bytes: base64,
      bytesCaptured,
      seconds,
      secondsRun: seconds,
      command: res.command,
      isolation: res.isolation,
      remoteResourcesRefused: remoteScan.remote,
      ...(layout ? { layout } : {}),
    };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}
