/**
 * chipsec provider — the UEFI/BIOS analysis track. A `uefi-bios` image (an SPI-flash / BIOS-region dump, an EFI
 * firmware volume) has no Linux rootfs to run and no MCU to emulate, so its "dynamic" analysis path is offline
 * structural analysis with chipsec: parse the firmware volumes, carve every EFI module, and reason about the
 * module inventory + Secure Boot posture from the REAL bytes. This is a separate provider from Renode — chipsec
 * is offline parsing, not emulation — and its proof states top out at `static_confirmed` (facts about the bytes,
 * never a device claim). With chipsec absent it degrades HONESTLY to available:false / blocked_by_platform; it
 * never fabricates a module tree. chipsec runs fully offline (NoneHelper, no kernel driver, no network), so the
 * decode runs inside the same Phase-4 isolation sandbox as the emulators.
 *
 * chipsec writes its parse next to the input file: `<img>.UEFI.lst` (a stable, line-oriented listing) plus a
 * carved `<img>.dir/` tree and a `<img>.UEFI.json`. We parse the `.lst` (robust across versions) into the module
 * inventory. The `.lst` parser, the IOC/security scan, and the type summary are PURE and unit-tested; the runner
 * only copies the image into a throwaway dir, invokes chipsec under isolation, and composes them.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import type { FindingSeverity, ProofState } from '@firmlab/core';
import { type IsolationLevel, loadIsolationLimits, runIsolated } from './isolate.js';

const execFileAsync = promisify(execFile);

/** An EFI module (a file inside a firmware volume) as enumerated from chipsec's decode listing. */
export interface UefiModule {
  /** File GUID, upper-cased. */
  guid: string;
  /** Friendly name chipsec resolved for the GUID, when known (e.g. `PeiCore`, `DxeCore`). */
  name?: string;
  /** EFI_FV_FILETYPE label (DXE_DRIVER, PEIM, APPLICATION, SMM…), when decoded. */
  type?: string;
}

/**
 * A UEFI-specific security observation, shaped like a finding draft so the route can stamp it into the ledger.
 * Proof states are honest: an IOC match or the module inventory is `static_confirmed` (literally in the bytes);
 * a structural lead (an embedded application) is `needs_runtime_reproduction` — worth a look, not a verdict.
 */
export interface UefiSecurityFinding {
  kind: string;
  title: string;
  severity: FindingSeverity;
  proofState: ProofState;
  evidence: Record<string, unknown>;
  rationale: string;
}

/** An entry in a UEFI IOC feed — a known-bad module by GUID and/or name (see `loadUefiIocs`). */
export interface UefiIoc {
  guid?: string;
  name?: string;
  /** Human label for the threat, surfaced in the finding (e.g. "LoJax SecDxe", "MoonBounce"). */
  label: string;
  severity?: FindingSeverity;
}

export interface ChipsecResult {
  available: boolean;
  ran: boolean;
  reason: string;
  proofState: ProofState;
  /** Firmware volumes found in the image. */
  volumes: number;
  /** Total EFI modules carved. */
  moduleCount: number;
  /** Module count by EFI_FV_FILETYPE label. */
  byType: Record<string, number>;
  /** A capped sample of the modules (the full count/byType are always exact). */
  modules: UefiModule[];
  findings: UefiSecurityFinding[];
  command: string;
  isolation?: IsolationLevel;
}

/** EFI_FV_FILETYPE code → label (see PI spec / EDK2 PiFirmwareFile.h). */
const EFI_FILETYPE: Record<number, string> = {
  1: 'RAW',
  2: 'FREEFORM',
  3: 'SECURITY_CORE',
  4: 'PEI_CORE',
  5: 'DXE_CORE',
  6: 'PEIM',
  7: 'DXE_DRIVER',
  8: 'COMBINED_PEIM_DRIVER',
  9: 'APPLICATION',
  10: 'SMM',
  11: 'FIRMWARE_VOLUME_IMAGE',
  12: 'COMBINED_SMM_DXE',
  13: 'SMM_CORE',
  14: 'SMM_STANDALONE',
  15: 'SMM_CORE_STANDALONE',
  240: 'FFS_PAD',
};

const GUID_RE = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}';
// An `EFI_FILE` entry: `b'EFI_FILE' {GUID}` optionally followed by a friendly `b'Name'`.
const EFI_FILE_RE = new RegExp(`b'EFI_FILE'\\s+\\{(${GUID_RE})\\}(?:\\s+b'([^']*)')?`);
const TYPE_RE = /\bType\s+([0-9A-Fa-f]{2})h/;
// A firmware-volume header line: `EFI_FV +00000000h {GUID}: …`.
const EFI_FV_RE = new RegExp(`^EFI_FV\\s+\\+[0-9A-Fa-f]+h\\s+\\{${GUID_RE}\\}`, 'm');

/**
 * Pure: parse chipsec's `<img>.UEFI.lst` decode listing into the firmware-volume count and the EFI module
 * inventory. Each `EFI_FILE {GUID} [name]` line names a module; its EFI_FV_FILETYPE is read from the following
 * `Type XXh` line. Section-level GUIDs (`S_GUID_DEFINED …`) are ignored — only real file entries are modules.
 */
export function parseUefiDecode(lst: string): { volumes: number; modules: UefiModule[] } {
  const lines = lst.split('\n');
  const modules: UefiModule[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const m = EFI_FILE_RE.exec(line);
    if (!m) continue;
    const guid = (m[1] as string).toUpperCase();
    const mod: UefiModule = { guid };
    if (m[2]) mod.name = m[2];
    // The type is on the next non-empty line(s) — scan a short window forward.
    for (let j = i + 1; j < Math.min(i + 4, lines.length); j++) {
      const t = TYPE_RE.exec(lines[j] ?? '');
      if (t) {
        const label = EFI_FILETYPE[Number.parseInt(t[1] as string, 16)];
        if (label) mod.type = label;
        break;
      }
    }
    modules.push(mod);
  }
  const volumes = (lst.match(new RegExp(EFI_FV_RE.source, 'gm')) ?? []).length;
  return { volumes, modules };
}

/** Pure: module count grouped by EFI_FV_FILETYPE label (`unknown` for undecoded types). */
export function summarizeByType(modules: UefiModule[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const m of modules) {
    const key = m.type ?? 'unknown';
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

/**
 * Load a UEFI IOC feed from `FIRMLAB_UEFI_IOC` (a JSON array of {guid?, name?, label, severity?}). Opt-in and
 * extensible, exactly like `FIRMLAB_DESOCK`: point it at a curated known-bad-module feed (public UEFI implant
 * IOCs) to turn on GUID/name matching. Absent or malformed → an empty feed (the scan still runs, matching
 * nothing) — no fabricated built-in detections.
 */
export function loadUefiIocs(env: NodeJS.ProcessEnv = process.env): UefiIoc[] {
  const p = env.FIRMLAB_UEFI_IOC;
  if (!p) return [];
  try {
    const arr = JSON.parse(fs.readFileSync(p, 'utf8')) as unknown;
    if (!Array.isArray(arr)) return [];
    return arr.filter((x): x is UefiIoc => {
      const o = x as Partial<UefiIoc>;
      return Boolean(o && typeof o.label === 'string' && (o.guid || o.name));
    });
  } catch {
    return [];
  }
}

/**
 * Pure: turn a decoded module inventory into honest UEFI findings.
 *   - inventory        → `info` / `static_confirmed`: the factual count of what the bytes contain.
 *   - IOC match        → `critical` / `static_confirmed`: a module whose GUID/name is in the IOC feed.
 *   - embedded app     → `info` / `needs_runtime_reproduction`: a lead — an EFI application inside a firmware
 *                        volume is a known bootkit vector, but is also legitimate (setup UI / shell), so it is
 *                        surfaced for review, never asserted as compromise.
 */
export function scanUefi(volumes: number, modules: UefiModule[], iocs: UefiIoc[]): UefiSecurityFinding[] {
  const findings: UefiSecurityFinding[] = [];
  const byType = summarizeByType(modules);

  if (modules.length > 0) {
    findings.push({
      kind: 'uefi-inventory',
      title: `UEFI image decoded: ${volumes} firmware volume${volumes === 1 ? '' : 's'}, ${modules.length} EFI modules`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { volumes, moduleCount: modules.length, byType },
      rationale:
        'chipsec parsed the firmware volumes and carved every EFI module offline — a factual inventory of the ' +
        'image contents (proves what is present in the bytes, not device behavior).',
    });
  }

  // IOC matches — a module whose GUID or name is a known-bad marker from the feed.
  for (const mod of modules) {
    for (const ioc of iocs) {
      const guidHit = ioc.guid ? ioc.guid.toUpperCase() === mod.guid : false;
      const nameHit = ioc.name && mod.name ? mod.name.toLowerCase().includes(ioc.name.toLowerCase()) : false;
      if (!guidHit && !nameHit) continue;
      findings.push({
        kind: 'uefi-ioc',
        title: `Known-bad UEFI module: ${ioc.label}${mod.name ? ` (${mod.name})` : ''}`,
        severity: ioc.severity ?? 'critical',
        proofState: 'static_confirmed',
        evidence: { guid: mod.guid, name: mod.name, type: mod.type, ioc: ioc.label },
        rationale: `Module ${guidHit ? 'GUID' : 'name'} matches the UEFI IOC feed entry "${ioc.label}" — a known firmware implant/rootkit marker present in the image bytes.`,
      });
    }
  }

  // Embedded UEFI applications — a lead worth a manual look, not a verdict.
  const apps = modules.filter((m) => m.type === 'APPLICATION');
  if (apps.length > 0) {
    findings.push({
      kind: 'uefi-embedded-app',
      title: `${apps.length} UEFI application${apps.length === 1 ? '' : 's'} embedded in firmware`,
      severity: 'info',
      proofState: 'needs_runtime_reproduction',
      evidence: { apps: apps.map((a) => ({ guid: a.guid, name: a.name })) },
      rationale:
        'EFI applications carried inside a firmware volume run before the OS and are a known bootkit vector. ' +
        'Legitimate firmware also ships them (setup UI / UEFI shell), so verify each is expected — this is a ' +
        'lead to review, not proof of compromise.',
    });
  }

  return findings;
}

export async function detectChipsec(): Promise<boolean> {
  try {
    await execFileAsync('chipsec_util', ['--help'], { timeout: 8000 });
    return true;
  } catch (err) {
    // A present binary that exits non-zero still proves availability; only ENOENT means "not installed".
    return (err as { code?: string }).code !== 'ENOENT';
  }
}

const MODULE_SAMPLE_CAP = 80;
const FIRMWARE_READ_CAP = 64 * 1024 * 1024;

function blocked(reason: string): ChipsecResult {
  return {
    available: false,
    ran: false,
    reason,
    proofState: 'blocked_by_platform',
    volumes: 0,
    moduleCount: 0,
    byType: {},
    modules: [],
    findings: [],
    command: '',
  };
}

/**
 * Decode + scan a UEFI/BIOS image with chipsec — offline and honest. Blocked when chipsec is absent or the image
 * has no parseable firmware volumes (not a UEFI image); a successful decode yields `static_confirmed` — a fact
 * about the bytes, never a device claim.
 */
export async function runChipsec(
  firmwarePath: string,
  opts: { seconds?: number; env?: NodeJS.ProcessEnv } = {},
): Promise<ChipsecResult> {
  const seconds = opts.seconds ?? 60;
  const env = opts.env ?? process.env;
  if (!(await detectChipsec())) {
    return blocked('chipsec not installed (opt-in UEFI-analysis layer).');
  }

  // chipsec writes its parse next to the input file, so copy the image into a throwaway dir we own and clean up.
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-chipsec-'));
  try {
    const imgCopy = path.join(work, 'image.fd');
    copyBounded(firmwarePath, imgCopy, FIRMWARE_READ_CAP);

    const res = await runIsolated(['chipsec_util', 'uefi', 'decode', imgCopy], {
      limits: {
        ...loadIsolationLimits(),
        cpuSeconds: seconds * 2 + 30,
        // chipsec's Python runtime reserves a large virtual region up front; an --as ceiling makes it abort. The
        // netns + cpu + wall-clock caps still bound the run. Many carved-module files → a generous fd cap.
        addressSpaceBytes: 0,
        openFiles: 4096,
        wallMs: (seconds + 30) * 1000,
      },
      env: { ...env, HOME: work },
    });

    const lstPath = `${imgCopy}.UEFI.lst`;
    let lst: string | null = null;
    try {
      lst = fs.readFileSync(lstPath, 'utf8');
    } catch {
      lst = null;
    }

    if (!lst) {
      return {
        ...blocked(
          `chipsec produced no decode listing — the image has no parseable UEFI firmware volume${
            res.timedOut ? ' (or the decode hit the time bound)' : ''
          }. Not a UEFI/BIOS image, or an unsupported layout.`,
        ),
        available: true,
        ran: res.ran,
        command: res.command,
        isolation: res.isolation,
      };
    }

    const { volumes, modules } = parseUefiDecode(lst);
    if (modules.length === 0) {
      return {
        ...blocked('chipsec parsed the image but found no EFI modules — not a UEFI firmware image.'),
        available: true,
        ran: res.ran,
        volumes,
        command: res.command,
        isolation: res.isolation,
      };
    }

    const findings = scanUefi(volumes, modules, loadUefiIocs(env));
    return {
      available: true,
      ran: res.ran,
      reason: `Decoded ${volumes} firmware volume${volumes === 1 ? '' : 's'} and ${modules.length} EFI modules offline with chipsec. Static analysis of the image bytes — proves image contents, not device behavior.`,
      proofState: 'static_confirmed',
      volumes,
      moduleCount: modules.length,
      byType: summarizeByType(modules),
      modules: modules.slice(0, MODULE_SAMPLE_CAP),
      findings,
      command: res.command,
      isolation: res.isolation,
    };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

/** Copy at most `cap` bytes of the firmware into `dest` — a mis-routed huge image can't blow up the decode. */
function copyBounded(src: string, dest: string, cap: number): void {
  const fd = fs.openSync(src, 'r');
  try {
    const len = Math.min(fs.fstatSync(fd).size, cap);
    const buf = Buffer.allocUnsafe(len);
    fs.readSync(fd, buf, 0, len, 0);
    fs.writeFileSync(dest, buf);
  } finally {
    fs.closeSync(fd);
  }
}
