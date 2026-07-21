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
  /** Secure Boot / NVRAM posture from the offline variable store, or null when none was extractable. */
  secureBoot: SecureBootPosture | null;
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

/** A UEFI NVRAM variable enumerated from chipsec's decode (`nvram_*.nvram.lst`). */
export interface UefiVariable {
  name: string;
  guid: string;
  /** Raw attribute string chipsec printed, e.g. `0x3 ( NV+BS )`. */
  attributes: string;
  /** First data byte, decoded for single-byte state vars (SecureBoot / SetupMode / CustomMode). */
  firstByte?: number;
}

/** Secure Boot posture derived from the offline NVRAM variable set. Honest: `unknown` when a var isn't extractable. */
export interface SecureBootPosture {
  variableCount: number;
  secureBoot: 'enabled' | 'disabled' | 'unknown';
  setupMode: 'setup' | 'user' | 'unknown';
  customMode: 'enabled' | 'disabled' | 'unknown';
  hasPK: boolean;
  hasKEK: boolean;
  hasDb: boolean;
  hasDbx: boolean;
  /** A documented TEST/self-signed platform-key marker found in a key variable, if any (a real supply-chain IOC). */
  testKey: string | null;
  /** Enumerated variable names (capped). */
  variables: string[];
  note: string;
}

/**
 * Pure: parse chipsec's `nvram_*.nvram.lst` into the UEFI variable list. Each `Name : X / Guid : Y / Attributes :
 * … / Data:` block is one variable; the first data byte is decoded for the single-byte Secure Boot state vars.
 */
export function parseNvramVariables(lst: string): UefiVariable[] {
  const out: UefiVariable[] = [];
  let cur: Partial<UefiVariable> | null = null;
  let expectData = false;
  const flush = (): void => {
    if (cur?.name)
      out.push({
        name: cur.name,
        guid: cur.guid ?? '',
        attributes: cur.attributes ?? '',
        ...(cur.firstByte !== undefined ? { firstByte: cur.firstByte } : {}),
      });
  };
  for (const line of lst.split('\n')) {
    const nameM = /^Name\s*:\s*(.+?)\s*$/.exec(line);
    if (nameM) {
      flush();
      cur = { name: nameM[1] as string };
      expectData = false;
      continue;
    }
    if (!cur) continue;
    const guidM = /^Guid\s*:\s*(\S+)/.exec(line);
    if (guidM) {
      cur.guid = guidM[1] ?? '';
      continue;
    }
    const attrM = /^Attributes:\s*(.+?)\s*$/.exec(line);
    if (attrM) {
      cur.attributes = attrM[1] ?? '';
      continue;
    }
    if (/^Data:/.test(line)) {
      expectData = true;
      continue;
    }
    if (expectData) {
      const hexM = /^\s*([0-9A-Fa-f]{2})\b/.exec(line);
      if (hexM) {
        cur.firstByte = Number.parseInt(hexM[1] as string, 16);
        expectData = false;
      }
    }
  }
  flush();
  return out;
}

// Documented markers for a TEST / self-signed platform key — none of these belong in shipping firmware.
const TEST_KEY_MARKERS: RegExp[] = [
  /DO NOT TRUST/i,
  /DO_NOT_TRUST/i,
  /DO NOT SHIP/i,
  /Snakeoil/i,
  /AMI Test/i,
  /Test(?:ing)? Only/i,
  /TestPlatformKey/i,
];

/** Pure: a documented TEST/self-signed key marker in the key-variable bytes, or null. */
export function detectTestKey(text: string): string | null {
  for (const re of TEST_KEY_MARKERS) {
    const m = re.exec(text);
    if (m) return m[0];
  }
  return null;
}

/**
 * Pure: derive the Secure Boot posture from the NVRAM variables (+ the key-variable bytes for test-key detection).
 * Honest: a state we can't read from the extracted variables is `unknown`, never assumed secure.
 */
export function interpretSecureBoot(vars: UefiVariable[], keyBytes: string): SecureBootPosture {
  const byName = (n: string): UefiVariable | undefined => vars.find((v) => v.name.toLowerCase() === n.toLowerCase());
  const has = (n: string): boolean => byName(n) !== undefined;
  const sb = byName('SecureBoot');
  const setup = byName('SetupMode');
  const custom = byName('CustomMode');
  const secureBoot = sb?.firstByte === 1 ? 'enabled' : sb?.firstByte === 0 ? 'disabled' : 'unknown';
  const setupMode = setup?.firstByte === 1 ? 'setup' : setup?.firstByte === 0 ? 'user' : 'unknown';
  const customMode = custom?.firstByte === 1 ? 'enabled' : custom?.firstByte === 0 ? 'disabled' : 'unknown';
  const testKey = detectTestKey(keyBytes);
  const note =
    secureBoot === 'unknown'
      ? 'Secure Boot state not among the offline-extractable variables for this store — enumerated what chipsec surfaced.'
      : `Secure Boot ${secureBoot}.`;
  return {
    variableCount: vars.length,
    secureBoot,
    setupMode,
    customMode,
    hasPK: has('PK') || has('PlatformKey'),
    hasKEK: has('KEK'),
    hasDb: has('db'),
    hasDbx: has('dbx'),
    testKey,
    variables: vars.map((v) => v.name).slice(0, 40),
    note,
  };
}

/** Pure: the honest Secure Boot findings for a posture (only asserts what the variables actually show). */
export function secureBootFindings(sb: SecureBootPosture): UefiSecurityFinding[] {
  const out: UefiSecurityFinding[] = [];
  if (sb.testKey) {
    out.push({
      kind: 'uefi-test-key',
      title: `Secure Boot uses a TEST / self-signed platform key (${sb.testKey})`,
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: { marker: sb.testKey },
      rationale:
        'A test / "DO NOT TRUST" platform key shipped in production firmware means Secure Boot trusts a publicly ' +
        'known key — a documented supply-chain weakness. Present in the image bytes.',
    });
  }
  if (sb.secureBoot === 'disabled') {
    out.push({
      kind: 'uefi-secure-boot',
      title: 'Secure Boot is disabled',
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: { secureBoot: 'disabled', setupMode: sb.setupMode },
      rationale: 'The SecureBoot NVRAM variable is 0 — unsigned bootloaders/OS will run. Bootkit exposure.',
    });
  }
  if (sb.setupMode === 'setup') {
    out.push({
      kind: 'uefi-secure-boot',
      title: 'Platform is in Secure Boot Setup Mode (no PK enrolled)',
      severity: 'high',
      proofState: 'static_confirmed',
      evidence: { setupMode: 'setup' },
      rationale: 'SetupMode=1 means no Platform Key is enrolled — anyone can enroll keys and defeat Secure Boot.',
    });
  }
  if (sb.secureBoot !== 'unknown' && sb.hasPK && !sb.hasDbx) {
    out.push({
      kind: 'uefi-secure-boot',
      title: 'No dbx revocation list present',
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { hasDbx: false },
      rationale: 'Without a dbx, known-revoked bootloaders (e.g. BootHole-class) are not blocked.',
    });
  }
  return out;
}

/** Read + interpret the Secure Boot posture from the decode output, or null when no NVRAM store was extracted. */
function readNvramPosture(imgCopy: string): SecureBootPosture | null {
  const dir = `${imgCopy}.dir`;
  const lstFiles = findFilesMatching(dir, (n) => /nvram.*\.nvram\.lst$/i.test(n));
  if (lstFiles.length === 0) return null;
  const lst = lstFiles.map((f) => safeRead(f, 'utf8')).join('\n');
  const vars = parseNvramVariables(lst);
  if (vars.length === 0) return null;
  // Key-variable blobs (PK/KEK/db/dbx) carry the certs — read them as latin1 so marker strings survive for the scan.
  const keyBins = findFilesMatching(dir, (n) => /^(pk|platformkey|kek|db|dbx)\b.*\.bin$/i.test(n));
  const keyBytes = keyBins.map((f) => safeRead(f, 'latin1')).join('\n');
  return interpretSecureBoot(vars, keyBytes);
}

/** Recursively collect files under `dir` whose basename matches `pred` (bounded depth). */
function findFilesMatching(dir: string, pred: (basename: string) => boolean, depth = 0): string[] {
  if (depth > 6) return [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...findFilesMatching(full, pred, depth + 1));
    else if (e.isFile() && pred(e.name)) out.push(full);
  }
  return out;
}

function safeRead(p: string, enc: BufferEncoding): string {
  try {
    return fs.readFileSync(p, enc);
  } catch {
    return '';
  }
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
    secureBoot: null,
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
    // A VARS-only image has an NVRAM store but no firmware volumes; a full BIOS image has both. Parse the Secure
    // Boot posture regardless, and only block when NEITHER modules nor NVRAM variables were extracted.
    const secureBoot = readNvramPosture(imgCopy);
    if (modules.length === 0 && (!secureBoot || secureBoot.variableCount === 0)) {
      return {
        ...blocked('chipsec parsed the image but found no EFI modules or NVRAM variables — not a UEFI firmware image.'),
        available: true,
        ran: res.ran,
        volumes,
        command: res.command,
        isolation: res.isolation,
      };
    }

    const findings = [
      ...scanUefi(volumes, modules, loadUefiIocs(env)),
      ...(secureBoot ? secureBootFindings(secureBoot) : []),
    ];
    const nvramNote = secureBoot ? ` NVRAM: ${secureBoot.variableCount} variable(s), ${secureBoot.note}` : '';
    return {
      available: true,
      ran: res.ran,
      reason: `Decoded ${volumes} firmware volume${volumes === 1 ? '' : 's'} and ${modules.length} EFI module${modules.length === 1 ? '' : 's'} offline with chipsec.${nvramNote} Static analysis of the image bytes — proves image contents, not device behavior.`,
      proofState: 'static_confirmed',
      volumes,
      moduleCount: modules.length,
      byType: summarizeByType(modules),
      modules: modules.slice(0, MODULE_SAMPLE_CAP),
      secureBoot,
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
