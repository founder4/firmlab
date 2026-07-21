/**
 * Renode provider (Phase 4, debt #4) — the RTOS / Cortex-M rung of the emulation ladder. Booting a bare-metal MCU
 * firmware needs a per-MCU platform description (.repl). This provider fingerprints the MCU from the real bytes
 * (`@firmlab/core` fingerprintMcu: ELF/vector-table memory map + vendor/SDK/RTOS strings), then picks the best
 * match from Renode's ACTUAL bundled catalog — so coverage tracks whatever the install ships, not a hardcoded
 * family list — builds a headless script that boots the ELF and shows the UART, and decides success from real
 * guest output. Without Renode, or with no platform match, it degrades HONESTLY to blocked_by_platform (naming the
 * detected MCU) — it never fakes an RTOS boot. The fingerprint, catalog scan, and selection are pure/unit-tested.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { type McuFingerprint, type ProofState, type StaticAnalysis, fingerprintMcu } from '@firmlab/core';
import { type IsolationLevel, loadIsolationLimits, runIsolated } from './isolate.js';

const execFileAsync = promisify(execFile);

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
}

export async function detectRenode(): Promise<boolean> {
  try {
    await execFileAsync('renode', ['--version'], { timeout: 8000 });
    return true;
  } catch (err) {
    return (err as { code?: string }).code !== 'ENOENT';
  }
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
    // Proven headless recipe: run the script, let it boot, wait the bound, then quit. Renode/.NET reserves a large
    // virtual address space and opens many fds, so give it generous caps (a tight --as makes the runtime abort).
    const res = await runIsolated(
      ['renode', '--disable-xwt', '--console', '--plain', '-e', `include @${rescPath}; sleep ${seconds}; quit`],
      {
        limits: {
          ...loadIsolationLimits(),
          cpuSeconds: seconds * 4 + 60,
          // No address-space or file-size caps: .NET's GC aborts under --as, and Renode's mmap'd emulation files
          // trip --fsize (SIGXFSZ). The netns + cpu + wall-clock + nofile caps still bound the run.
          addressSpaceBytes: 0,
          fileSizeBytes: 0,
          openFiles: 8192,
          wallMs: (seconds + 45) * 1000,
        },
        env: { ...process.env, HOME: work },
      },
    );

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
            : 'Renode session ended without UART output.'),
      proofState: booted ? 'confirmed_in_emulation' : 'blocked_by_platform',
      platform,
      uartExcerpt: excerpt,
      command: res.command,
      isolation: res.isolation,
    };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}
