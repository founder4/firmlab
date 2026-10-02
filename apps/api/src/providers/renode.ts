/**
 * Renode provider (Phase 4, debt #4) — the RTOS / Cortex-M rung of the emulation ladder. Booting a bare-metal MCU
 * firmware needs a per-MCU platform description (.repl). This provider fingerprints the MCU from the real bytes
 * (`@firmlab/core` fingerprintMcu: ELF/vector-table memory map + vendor/SDK/RTOS strings), then picks the best
 * match from Renode's ACTUAL bundled catalog — so coverage tracks whatever the install ships, not a hardcoded
 * family list — builds a headless script that boots the ELF and shows the UART, and decides success from real
 * guest output. Without Renode, or with no platform match, it degrades HONESTLY to blocked_by_platform (naming the
 * detected MCU) — it never fakes an RTOS boot. The fingerprint, catalog scan, and selection are pure/unit-tested.
 *
 * Every Renode invocation runs OFFLINE. Thirteen bundled platform descriptions pull a register description over
 * HTTPS on load (`ApplySVD @https://dl.antmicro.com/…`), the deployed container cannot drop the network namespace
 * that would otherwise contain it, and HOME is a fresh directory per run, so nothing caches — every boot was a
 * download nobody asked for, with every flag off. `OFFLINE_RENODE_ENV` points every proxy variable .NET honours at a
 * loopback port nothing listens on, so the request is refused locally and Renode carries on without the file. The
 * platform's include chain is scanned for what it would have fetched, and the result names it: the run used the
 * platform WITHOUT those resources, and it does not claim the boot would look the same with them.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { type McuFingerprint, type ProofState, type StaticAnalysis, fingerprintMcu } from '@firmlab/core';
import type { FindingDraft } from '@firmlab/core';

import { execFile } from '../job-process.js';
import { type IsolationLevel, type IsolationLimits, loadIsolationLimits, runIsolated } from './isolate.js';

const execFileAsync = promisify(execFile);

/** A loopback port nothing listens on (discard, 9): a proxied request is refused at once, never forwarded. */
export const RENODE_REFUSING_PROXY = 'http://127.0.0.1:9';

/**
 * The proxy variables .NET's default HttpClient reads, in both spellings, all aimed at the refusing port. The
 * bypass list (NO_PROXY / no_proxy) is REMOVED by `offlineRenodeEnv`, not merely left alone: an inherited
 * `NO_PROXY=*` or `.antmicro.com` would send the request straight past the proxy to the network.
 */
export const OFFLINE_RENODE_ENV: Readonly<Record<string, string>> = {
  HTTP_PROXY: RENODE_REFUSING_PROXY,
  HTTPS_PROXY: RENODE_REFUSING_PROXY,
  ALL_PROXY: RENODE_REFUSING_PROXY,
  http_proxy: RENODE_REFUSING_PROXY,
  https_proxy: RENODE_REFUSING_PROXY,
  all_proxy: RENODE_REFUSING_PROXY,
};

/** Variables that would exempt a host from the refusing proxy, and so must not survive into Renode's env. */
export const RENODE_PROXY_BYPASS_VARS: readonly string[] = ['NO_PROXY', 'no_proxy'];

/**
 * Pure: the environment every Renode process gets — the caller's, with the offline proxies forced over it and the
 * bypass list removed. `home`, when given, replaces HOME (the boot run uses a per-run directory); otherwise HOME
 * is passed through untouched.
 */
export function offlineRenodeEnv(base: NodeJS.ProcessEnv, home?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base, ...OFFLINE_RENODE_ENV };
  for (const k of RENODE_PROXY_BYPASS_VARS) delete env[k];
  if (home !== undefined) env.HOME = home;
  return env;
}

/**
 * Build the MCU/vendor hints that drive platform selection, from an image's stored identity + analysis JSON. Kept
 * here (not in a route) so the emulation ladder, the /renode route, and the agent executor all select the same
 * platform from the same evidence. Tolerates missing/garbled JSON — a bad blob just yields fewer hints.
 */
export function renodeHintsFrom(identityJson: string | null, analysisJson: string | null): string[] {
  const hints: string[] = [];
  try {
    if (identityJson) {
      const id = JSON.parse(identityJson) as { firmwareClass?: string; arch?: string; bootloader?: string | null };
      hints.push(id.firmwareClass ?? '', id.arch ?? '', id.bootloader ?? '');
    }
  } catch {}
  try {
    if (analysisJson) {
      const a = JSON.parse(analysisJson) as StaticAnalysis;
      hints.push(...a.secrets.slice(0, 40).map((s) => s.value), ...a.signatures.map((s) => s.description));
    }
  } catch {}
  return hints.filter(Boolean);
}

/** Where Renode installs its bundled platform descriptions (portable release / package). */
export const RENODE_PLATFORMS_DIR = '/opt/renode/platforms';

/** The Renode install root — `using "platforms/…"` includes in a .repl resolve against this. */
const RENODE_ROOT = path.dirname(RENODE_PLATFORMS_DIR);

/**
 * Curated tie-breakers: a detected family → a substring of its preferred board .repl basename. When several
 * bundled platforms match a family, this steers selection to the known-good board (e.g. an STM32F4 firmware →
 * the Discovery board rather than a bare cortex-m core). Not exhaustive: unlisted families fall through to plain
 * token scoring against whatever this Renode actually ships, so coverage tracks the real catalog, not this map.
 */
const FAMILY_PREF: Record<string, string> = {
  stm32f4: 'stm32f4_discovery',
  stm32f0: 'stm32f072',
  stm32l0: 'stm32l0',
  nrf52: 'nrf52840',
  nrf53: 'nrf5340',
  cc2538: 'cc2538',
  cc2650: 'cc2650',
  efr32mg: 'efr32mg',
  fe310: 'sifive_fe310',
};

export interface PlatformSelection {
  /** Chosen platform, relative to the platforms dir (e.g. `boards/stm32f4_discovery-kit.repl`). */
  repl: string;
  /** How it was chosen — surfaced in the honest boot reason. */
  via: 'part' | 'family' | 'catalog';
}

/** Recursively list the `.repl` platform descriptions this Renode ships, as paths relative to `platformsDir`. */
export function listPlatformCatalog(platformsDir = RENODE_PLATFORMS_DIR): string[] {
  const out: string[] = [];
  const walk = (dir: string, depth: number): void => {
    if (depth > 3) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full, depth + 1);
      else if (e.isFile() && e.name.endsWith('.repl')) out.push(path.relative(platformsDir, full));
    }
  };
  walk(platformsDir, 0);
  return out;
}

/** Lowercased alphanumeric tokens (length ≥ 4) mined from the free-text hints, for catalog matching. */
function hintTokens(hints: string[]): string[] {
  const toks = new Set<string>();
  for (const h of hints
    .join(' ')
    .toLowerCase()
    .split(/[^a-z0-9]+/)) {
    if (h.length >= 4) toks.add(h);
  }
  return [...toks];
}

/**
 * Pure: choose the best-matching bundled platform for a fingerprinted MCU. Every catalog entry is scored by how
 * specifically its filename overlaps the firmware's tokens (a longer token — a full part number — outweighs a
 * bare family), with a small board-over-cpu bonus and a curated tie-break toward the known-good board. Returns
 * null — an honest `blocked_by_platform` — when no vendor family matches. No I/O: the catalog is injected, so
 * this is unit-testable without Renode installed.
 *
 * Deliberately NO generic-core fallback: real Renode ships no bare `cortex-mN.repl`, and a core without the
 * SoC's peripherals could never produce UART output (never "boots") — so a bare Cortex-M with no vendor
 * identity is blocked honestly rather than pointed at a platform that cannot run it.
 */
export function selectPlatform(fp: McuFingerprint, hints: string[], catalog: string[]): PlatformSelection | null {
  // Short vendor tokens (st, ti) are excluded to avoid spurious substring hits inside unrelated filenames.
  const tokens = [...new Set([...fp.tokens, ...hintTokens(hints)])].filter((t) => t.length >= 4);
  const pref = fp.family ? FAMILY_PREF[fp.family] : undefined;

  let best: { repl: string; score: number; baseLen: number } | null = null;
  for (const repl of catalog) {
    const base = path.basename(repl, '.repl').toLowerCase();
    const isBoard = repl.replace(/\\/g, '/').startsWith('boards/');
    let score = 0;
    for (const t of tokens) if (base.includes(t)) score += t.length;
    if (score === 0) continue;
    if (isBoard) score += 2; // a full board is more complete than a bare SoC/cpu for a bare-metal blob
    if (pref && base.includes(pref)) score += 8; // curated known-good board wins ties within a family
    // A part-specific board (its filename names the exact MCU part, e.g. nucleo_h753zi) is the best match — the
    // right SoC peripherals AND the right variant. Prefer it decisively over a family board or a bare cpu.
    if (isBoard && ((fp.part && base.includes(fp.part)) || (fp.partCore && base.includes(fp.partCore)))) score += 8;
    // Deterministic: higher score, then the shorter (more exact) basename.
    if (!best || score > best.score || (score === best.score && base.length < best.baseLen)) {
      best = { repl, score, baseLen: base.length };
    }
  }
  if (!best) return null;

  const base = path.basename(best.repl, '.repl').toLowerCase();
  const via = fp.part && base.includes(fp.part) ? 'part' : fp.family && base.includes(fp.family) ? 'family' : 'catalog';
  return { repl: best.repl, via };
}

/** A short human label for the detected MCU, for the honest boot/block reason. */
function describeMcu(fp: McuFingerprint): string {
  const label = fp.part ?? fp.family ?? (fp.cortexM ? `${fp.arch} ${fp.cortexM}` : fp.arch);
  return label === 'unknown' ? 'unrecognized MCU' : label;
}

const FIRMWARE_READ_CAP = 16 * 1024 * 1024;
/** Read a bounded prefix of the firmware for fingerprinting — MCU blobs are tiny; this caps a mis-routed image. */
function readFirmwareBounded(p: string, cap = FIRMWARE_READ_CAP): Uint8Array {
  const fd = fs.openSync(p, 'r');
  try {
    const len = Math.min(fs.fstatSync(fd).size, cap);
    const b = Buffer.allocUnsafe(len);
    fs.readSync(fd, b, 0, len, 0);
    return b;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Discover the UART peripheral names declared by a platform, following its `using` includes. A board .repl rarely
 * declares the UARTs itself — they come from an included SoC .repl (e.g. the STM32F4 board pulls uart4 from
 * `platforms/cpus/stm32f4.repl`). Two include forms: `using "./x.repl"` (relative to the file) and
 * `using "platforms/…"` (relative to the Renode root). Returns the peripheral names (e.g. ['usart1','uart4']) so
 * the script can surface the RIGHT UART — hardcoding uart0 misses every board whose console is elsewhere.
 */
export function discoverUarts(replPath: string, renodeRoot: string, _seen = new Set<string>(), depth = 0): string[] {
  if (depth > 12 || _seen.has(replPath)) return [];
  _seen.add(replPath);
  let text: string;
  try {
    text = fs.readFileSync(replPath, 'utf8');
  } catch {
    return [];
  }
  const names = new Set<string>();
  // `name: <ns.>UART<...> @ sysbus …` — a UART-typed peripheral declaration.
  for (const m of text.matchAll(/^[ \t]*([A-Za-z_]\w*)[ \t]*:[ \t]*[\w.]*UART[\w.]*\b/gm)) {
    if (m[1]) names.add(m[1]);
  }
  for (const m of text.matchAll(/^[ \t]*using[ \t]+"([^"]+)"/gm)) {
    const raw = m[1];
    if (!raw) continue;
    const inc = raw.endsWith('.repl') ? raw : `${raw}.repl`;
    const resolved = inc.startsWith('.') ? path.resolve(path.dirname(replPath), inc) : path.resolve(renodeRoot, inc);
    for (const u of discoverUarts(resolved, renodeRoot, _seen, depth + 1)) names.add(u);
  }
  return [...names];
}

/** Bounds on the include-chain scan — they stop a runaway chain; a cycle stops at its first revisit regardless. */
export const REMOTE_SCAN_MAX_DEPTH = 12;
export const REMOTE_SCAN_MAX_FILES = 64;

export interface RemoteResourceScan {
  /** Every remote `@http(s)://` reference in the chain, deduplicated, in first-seen order. */
  remote: string[];
  /** How many platform files were actually read. */
  filesScanned: number;
  /**
   * Includes that were NOT read, each with why — outside the Renode root, unreadable, or past a bound. Any entry
   * here means `remote` may be incomplete: it lists what the scanned files reference, not what Renode would fetch.
   */
  unscanned: string[];
}

/** `/* … *\/` blocks and whole-line `//` comments removed — a commented-out `ApplySVD` is never fetched. */
function stripReplComments(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .filter((l) => !/^\s*\/\//.test(l))
    .join('\n');
}

/** True when `p` is `root` or lies beneath it — the containment every read in the scan is held to. */
function isWithin(root: string, p: string): boolean {
  const rel = path.relative(root, p);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * Pure (reads files, no network): what the selected platform would fetch over the network. Follows the same
 * `using` include rule as `discoverUarts` — `./x` relative to the including file, anything else relative to the
 * Renode root — and collects every `@http://` / `@https://` reference, which is how a .repl names a remote file
 * (in practice `ApplySVD @https://…svd`). Every read, the starting platform included, must stay inside
 * `renodeRoot`; an include that resolves outside it is refused and reported, never read. Cycles stop at the first
 * revisit; depth and file count are bounded, and anything a bound or a refusal left unread is named in
 * `unscanned` rather than silently dropped. A platform that is itself a URL is reported as remote.
 */
export function scanRemoteResources(
  platformPath: string,
  renodeRoot: string,
  bounds: { maxDepth?: number; maxFiles?: number } = {},
): RemoteResourceScan {
  const maxDepth = bounds.maxDepth ?? REMOTE_SCAN_MAX_DEPTH;
  const maxFiles = bounds.maxFiles ?? REMOTE_SCAN_MAX_FILES;
  const root = path.resolve(renodeRoot);
  const remote = new Set<string>();
  const unscanned: string[] = [];
  const seen = new Set<string>();
  let filesScanned = 0;

  if (/^https?:\/\//i.test(platformPath)) return { remote: [platformPath], filesScanned: 0, unscanned: [] };

  const visit = (file: string, depth: number): void => {
    const abs = path.resolve(file);
    if (seen.has(abs)) return; // a cycle, or a diamond include already read
    seen.add(abs);
    if (!isWithin(root, abs)) {
      unscanned.push(`${abs} (outside the Renode root)`);
      return;
    }
    if (depth > maxDepth) {
      unscanned.push(`${abs} (past the include depth bound of ${maxDepth})`);
      return;
    }
    if (filesScanned >= maxFiles) {
      unscanned.push(`${abs} (past the file bound of ${maxFiles})`);
      return;
    }
    let text: string;
    try {
      text = stripReplComments(fs.readFileSync(abs, 'utf8'));
    } catch {
      unscanned.push(`${abs} (unreadable)`);
      return;
    }
    filesScanned++;
    for (const m of text.matchAll(/@(https?:\/\/[^\s"'`;]+)/gi)) if (m[1]) remote.add(m[1]);
    for (const m of text.matchAll(/^[ \t]*using[ \t]+"([^"]+)"/gm)) {
      const raw = m[1];
      if (!raw) continue;
      const inc = raw.endsWith('.repl') ? raw : `${raw}.repl`;
      visit(inc.startsWith('.') ? path.resolve(path.dirname(abs), inc) : path.resolve(root, inc), depth + 1);
    }
  };
  visit(platformPath, 0);
  return { remote: [...remote], filesScanned, unscanned };
}

/**
 * Pure: the one sentence the boot reason gains from the scan, or '' when there is nothing to say. Names what was
 * refused and what that costs — for an `ApplySVD` file, register names in Renode's peripheral logging, not the
 * peripherals themselves — and, when part of the chain went unread, says the list may be incomplete.
 */
export function describeRefusedRemote(scan: RemoteResourceScan): string {
  const parts: string[] = [];
  if (scan.remote.length > 0) {
    const shown = scan.remote.slice(0, 3).join(', ');
    const more = scan.remote.length > 3 ? ` and ${scan.remote.length - 3} more` : '';
    parts.push(
      `Renode ran offline, so ${scan.remote.length} remote resource${scan.remote.length === 1 ? '' : 's'} the platform references ${scan.remote.length === 1 ? 'was' : 'were'} refused rather than downloaded (${shown}${more}); the run used the platform without ${scan.remote.length === 1 ? 'it' : 'them'}, and what ${scan.remote.length === 1 ? 'it' : 'they'} would have changed was not measured.`,
    );
  }
  if (scan.unscanned.length > 0) {
    parts.push(
      `${scan.unscanned.length} platform include${scan.unscanned.length === 1 ? ' was' : 's were'} not scanned for remote references (${scan.unscanned.slice(0, 2).join('; ')}${scan.unscanned.length > 2 ? '; …' : ''}), so that list may be incomplete; any such fetch was still refused offline.`,
    );
  }
  return parts.join(' ');
}

/**
 * Pure: the headless Renode script — create a machine, load the platform + ELF, and tee every discovered UART to
 * a per-UART file backend (plus an on-console analyzer) so a real boot's output is captured no matter which UART
 * the firmware uses. `start` is the last line; the caller bounds the run and quits. With no UARTs known, it falls
 * back to uart0 rather than emitting nothing.
 */
export function buildRenodeScript(
  platformPath: string,
  firmwarePath: string,
  uarts: string[],
  uartLogDir?: string,
): string {
  const consoles = uarts.length > 0 ? uarts : ['uart0'];
  const lines = ['mach create', `machine LoadPlatformDescription @${platformPath}`, `sysbus LoadELF @${firmwarePath}`];
  for (const u of consoles) {
    if (uartLogDir) lines.push(`sysbus.${u} CreateFileBackend @${path.join(uartLogDir, `uart_${u}.txt`)} true`);
    lines.push(`showAnalyzer sysbus.${u}`);
  }
  lines.push('start');
  return lines.join('\n');
}

export interface RenodeResult {
  available: boolean;
  ran: boolean;
  booted: boolean;
  reason: string;
  proofState: ProofState;
  platform: string | null;
  uartExcerpt: string;
  command: string;
  isolation?: IsolationLevel;
  /**
   * Remote `@http(s)://` resources the platform's include chain references, all refused because Renode runs
   * offline. Optional forever: results stored before this field existed carry none, which is not "none refused".
   */
  remoteResourcesRefused?: string[];
}

/**
 * Compose the ledger rows a Renode run earns — the same half `emulate` was missing until 2026-08-03.
 *
 * This rung is the ONLY dynamic path an RTOS or bare-metal image has: no rootfs comes out of one, so every
 * rootfs-shaped stage skips and the dossier for those images is thin by construction. A boot under Renode that
 * left no row meant the one question that CAN be answered about them was asked and never recorded.
 *
 * Same three rules as the qemu composers. The proof state is carried verbatim from `runRenode`, which decided it
 * from real UART output rather than from the process exiting; every outcome earns a row, including the blocked
 * one, because Renode is an opt-in layer and "not installed" must not read as "nothing to find"; and the boot is
 * a claim about the emulated SoC, never about the physical part — `confirmed_in_emulation` is the ceiling and the
 * title says so.
 */
export function buildRenodeFindings(r: RenodeResult): FindingDraft[] {
  const evidence: Record<string, unknown> = {
    platform: r.platform,
    booted: r.booted,
    command: r.command,
    // The UART is the evidence the verdict was read from, so it travels with it — bounded, because a chatty
    // firmware would otherwise grow a findings row without limit.
    uartExcerpt: r.uartExcerpt.slice(0, 4000),
  };
  if (r.isolation) evidence.isolation = r.isolation;
  if (r.remoteResourcesRefused && r.remoteResourcesRefused.length > 0) {
    evidence.remoteResourcesRefused = r.remoteResourcesRefused;
  }

  const kind = !r.ran ? 'renode-blocked' : r.booted ? 'renode-booted' : 'renode-boot-unconfirmed';
  const title = !r.ran
    ? 'The firmware could not be booted under Renode here — this is not a negative result'
    : r.booted
      ? `The firmware booted under Renode on ${r.platform ?? 'the selected platform'} — in the emulated SoC, not on the part`
      : `Renode ran ${r.platform ? `on ${r.platform} ` : ''}and the firmware printed no recognisable boot — this is not a verdict about the firmware`;

  const draft: FindingDraft = {
    kind,
    title,
    severity: 'info',
    proofState: r.proofState,
    evidence,
    rationale: r.ran
      ? `${r.reason} A boot here proves the emulated platform ran this image; the physical device has peripherals and a bootloader this model does not.`
      : `${r.reason} The question was asked and this deployment could not answer it, which is not evidence that there is nothing to find.`,
  };
  if (r.ran) draft.evidenceChannel = 'emulated_run';
  return [draft];
}

function withLeadingSpace(sentence: string): string {
  return sentence ? ` ${sentence}` : '';
}

export async function detectRenode(): Promise<boolean> {
  try {
    await execFileAsync('renode', ['--version'], { timeout: 8000, env: offlineRenodeEnv(process.env) });
    return true;
  } catch (err) {
    return (err as { code?: string }).code !== 'ENOENT';
  }
}

/**
 * Pure: the isolated boot invocation — argv plus `runIsolated` options. Proven headless recipe: run the script, let
 * it boot, wait the bound, then quit. Renode/.NET reserves a large virtual address space and opens many fds, so it
 * gets generous caps (a tight --as makes the runtime abort). The env is always the offline one, HOME the per-run
 * work directory.
 */
export function buildRenodeInvocation(
  rescPath: string,
  seconds: number,
  work: string,
  baseEnv: NodeJS.ProcessEnv = process.env,
): { argv: string[]; options: { limits: IsolationLimits; env: NodeJS.ProcessEnv } } {
  return {
    argv: ['renode', '--disable-xwt', '--console', '--plain', '-e', `include @${rescPath}; sleep ${seconds}; quit`],
    options: {
      limits: {
        ...loadIsolationLimits(baseEnv),
        cpuSeconds: seconds * 4 + 60,
        // No address-space or file-size caps: .NET's GC aborts under --as, and Renode's mmap'd emulation files
        // trip --fsize (SIGXFSZ). The cpu + wall-clock + nofile caps still bound the run, and the netns where the
          // host allows one; where it does not (the deployed container), the offline proxy env is what keeps it off the net.
        addressSpaceBytes: 0,
        fileSizeBytes: 0,
        openFiles: 8192,
        wallMs: (seconds + 45) * 1000,
      },
      env: offlineRenodeEnv(baseEnv, work),
    },
  };
}

/**
 * Boot an RTOS/Cortex-M firmware under Renode — honestly. Blocked when Renode or a platform is absent; "booted" is
 * decided from real UART output, never assumed.
 */
export async function runRenode(
  firmwarePath: string,
  hints: string[],
  opts: { platform?: string; seconds?: number } = {},
): Promise<RenodeResult> {
  const seconds = opts.seconds ?? 15;
  const blocked = (reason: string, platform: string | null = null): RenodeResult => ({
    available: false,
    ran: false,
    booted: false,
    reason,
    proofState: 'blocked_by_platform',
    platform,
    uartExcerpt: '',
    command: '',
  });

  if (!(await detectRenode())) return blocked('Renode not installed (opt-in layer).');

  // Fingerprint the MCU from the real bytes (ELF/vector-table memory map + vendor/SDK strings), then pick the
  // best bundled platform from Renode's actual catalog — far broader than a hardcoded family list.
  let fp: McuFingerprint;
  try {
    fp = fingerprintMcu(readFirmwareBounded(firmwarePath));
  } catch {
    fp = fingerprintMcu(new Uint8Array());
  }
  let platform = opts.platform ?? null;
  let via: PlatformSelection['via'] | 'explicit' = 'explicit';
  if (!platform) {
    const sel = selectPlatform(fp, hints, listPlatformCatalog());
    if (sel) {
      platform = path.join(RENODE_PLATFORMS_DIR, sel.repl);
      via = sel.via;
    }
  }
  if (!platform) {
    return {
      ...blocked(
        `No bundled Renode platform for the detected MCU (${describeMcu(fp)}). RTOS boot needs a matching .repl; not fabricating a run.`,
      ),
      available: true,
    };
  }
  const detected = `Detected ${describeMcu(fp)} → ${path.basename(platform)}${via === 'explicit' ? ' (explicit)' : ''}. `;

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-renode-'));
  try {
    const uarts = discoverUarts(platform, RENODE_ROOT);
    const script = buildRenodeScript(platform, firmwarePath, uarts, work);
    const rescPath = path.join(work, 'boot.resc');
    fs.writeFileSync(rescPath, script);
    const remoteScan = scanRemoteResources(platform, RENODE_ROOT);
    const invocation = buildRenodeInvocation(rescPath, seconds, work);
    const res = await runIsolated(invocation.argv, invocation.options);

    // "Booted" is decided from the UART file backends — the actual bytes the guest wrote — never from assumption.
    const captures = uarts
      .map((u) => {
        try {
          return { uart: u, text: fs.readFileSync(path.join(work, `uart_${u}.txt`), 'utf8') };
        } catch {
          return { uart: u, text: '' };
        }
      })
      .filter((c) => /[\x20-\x7e]{8,}/.test(c.text));
    const booted = captures.length > 0;
    const excerpt = booted
      ? captures
          .map((c) => `[${c.uart}] ${c.text.trim()}`)
          .join('\n')
          .slice(0, 600)
      : res.stdout.slice(-400);
    return {
      available: true,
      ran: res.ran,
      booted,
      reason:
        detected +
        (booted
          ? `Guest booted and produced UART output on ${captures.map((c) => c.uart).join(', ')}.`
          : res.timedOut
            ? 'Ran to the time bound with no UART output captured.'
            : 'Renode session ended without UART output.') +
        // Only a process that ran can have been refused anything — a launch failure says nothing about the network.
        withLeadingSpace(res.ran ? describeRefusedRemote(remoteScan) : ''),
      proofState: booted ? 'confirmed_in_emulation' : 'blocked_by_platform',
      platform,
      uartExcerpt: excerpt,
      command: res.command,
      isolation: res.isolation,
      remoteResourcesRefused: remoteScan.remote,
    };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}
