/**
 * External-tool detection. The workbench is fully functional with none of these (the @firmlab/core engine
 * covers structure/entropy/strings/identity), but each detected tool unlocks a richer provider: binwalk for
 * format-aware carving, the extractors for real rootfs recovery, radare2/Ghidra for decompilation, syft/grype
 * for SBOM+CVEs, and the QEMU/Renode family for emulation. This module answers "what can this deployment do?"
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/** Resolve a binary on PATH (executable), for tools whose --version probe is too slow/costly to run (e.g. a JVM). */
function resolveOnPath(bin: string): string | null {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    const p = path.join(dir, bin);
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch {}
  }
  return null;
}

export type ToolId =
  | 'binwalk'
  | 'unsquashfs'
  | 'sasquatch'
  | 'jefferson'
  | 'ubireader_extract_files'
  | 'cpio'
  | 'radare2'
  | 'analyzeHeadless'
  | 'syft'
  | 'grype'
  | 'gitleaks'
  | 'qemu-mipsel-static'
  | 'qemu-arm-static'
  | 'qemu-aarch64-static'
  | 'qemu-system-mipsel'
  | 'qemu-system-arm'
  | 'renode'
  | 'chipsec';

interface ToolSpec {
  id: ToolId;
  /** Command probed on PATH. */
  bin: string;
  /** Args that make it exit quickly (version/help). */
  probe: string[];
  /** What enabling this tool gives the user. */
  unlocks: string;
  /** Feature group for the UI capabilities panel. */
  group: 'extract' | 'analyze' | 'sbom' | 'emulate' | 'secrets';
  /** Detect by PATH existence instead of executing — for tools whose probe is too slow (Ghidra's JVM startup > the
   *  probe timeout) or exits non-zero on --help. */
  detectByExistence?: boolean;
}

const TOOLS: readonly ToolSpec[] = [
  { id: 'binwalk', bin: 'binwalk', probe: ['--help'], unlocks: 'Format-aware signature carving', group: 'extract' },
  { id: 'unsquashfs', bin: 'unsquashfs', probe: ['-help'], unlocks: 'SquashFS extraction', group: 'extract' },
  { id: 'sasquatch', bin: 'sasquatch', probe: ['-help'], unlocks: 'Vendor SquashFS extraction', group: 'extract' },
  { id: 'jefferson', bin: 'jefferson', probe: ['--help'], unlocks: 'JFFS2 extraction', group: 'extract' },
  {
    id: 'ubireader_extract_files',
    bin: 'ubireader_extract_files',
    probe: ['--help'],
    unlocks: 'UBIFS extraction',
    group: 'extract',
  },
  { id: 'cpio', bin: 'cpio', probe: ['--version'], unlocks: 'CPIO/initramfs extraction', group: 'extract' },
  { id: 'radare2', bin: 'radare2', probe: ['-v'], unlocks: 'Binary triage + disassembly', group: 'analyze' },
  {
    id: 'analyzeHeadless',
    bin: 'analyzeHeadless',
    probe: ['-help'],
    unlocks: 'Ghidra headless decompilation',
    group: 'analyze',
    // Ghidra's analyzeHeadless spins a JVM + Ghidra init on every call — far longer than the probe timeout, and
    // `-help` exits non-zero. Detect by existence so an installed Ghidra is reported (and thus usable), not "absent".
    detectByExistence: true,
  },
  { id: 'syft', bin: 'syft', probe: ['version'], unlocks: 'SBOM generation', group: 'sbom' },
  { id: 'grype', bin: 'grype', probe: ['version'], unlocks: 'CVE matching (N-day)', group: 'sbom' },
  { id: 'gitleaks', bin: 'gitleaks', probe: ['version'], unlocks: 'Deep secret scan', group: 'secrets' },
  {
    id: 'qemu-mipsel-static',
    bin: 'qemu-mipsel-static',
    probe: ['-version'],
    unlocks: 'MIPSel user-mode emulation',
    group: 'emulate',
  },
  {
    id: 'qemu-arm-static',
    bin: 'qemu-arm-static',
    probe: ['-version'],
    unlocks: 'ARM user-mode emulation',
    group: 'emulate',
  },
  {
    id: 'qemu-aarch64-static',
    bin: 'qemu-aarch64-static',
    probe: ['-version'],
    unlocks: 'ARM64 user-mode emulation',
    group: 'emulate',
  },
  {
    id: 'qemu-system-mipsel',
    bin: 'qemu-system-mipsel',
    probe: ['-version'],
    unlocks: 'Full-system MIPS boot',
    group: 'emulate',
  },
  {
    id: 'qemu-system-arm',
    bin: 'qemu-system-arm',
    probe: ['-version'],
    unlocks: 'Full-system ARM boot',
    group: 'emulate',
  },
  { id: 'renode', bin: 'renode', probe: ['--version'], unlocks: 'RTOS / Cortex-M emulation', group: 'emulate' },
  {
    id: 'chipsec',
    bin: 'chipsec_util',
    probe: ['--help'],
    unlocks: 'UEFI/BIOS firmware analysis (offline decode + IOC scan)',
    group: 'analyze',
  },
];

export interface ToolStatus {
  id: ToolId;
  bin: string;
  available: boolean;
  version?: string;
  unlocks: string;
  group: ToolSpec['group'];
}

let cache: ToolStatus[] | null = null;

async function probe(spec: ToolSpec): Promise<ToolStatus> {
  if (spec.detectByExistence) {
    const resolved = resolveOnPath(spec.bin);
    return {
      id: spec.id,
      bin: spec.bin,
      available: resolved !== null,
      ...(resolved ? { version: 'installed' } : {}),
      unlocks: spec.unlocks,
      group: spec.group,
    };
  }
  try {
    const { stdout, stderr } = await execFileAsync(spec.bin, spec.probe, { timeout: 4000 });
    const out = `${stdout}${stderr}`.split('\n')[0]?.trim().slice(0, 120) ?? '';
    return { id: spec.id, bin: spec.bin, available: true, version: out, unlocks: spec.unlocks, group: spec.group };
  } catch {
    return { id: spec.id, bin: spec.bin, available: false, unlocks: spec.unlocks, group: spec.group };
  }
}

/** Probe all tools once and cache the result for the process lifetime. */
export async function detectTools(force = false): Promise<ToolStatus[]> {
  if (cache && !force) return cache;
  cache = await Promise.all(TOOLS.map(probe));
  return cache;
}

export async function isToolAvailable(id: ToolId): Promise<boolean> {
  const tools = await detectTools();
  return tools.find((t) => t.id === id)?.available ?? false;
}
