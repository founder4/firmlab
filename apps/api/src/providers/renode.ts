/**
 * Renode provider (Phase 4, debt #4) — the RTOS / Cortex-M rung of the emulation ladder. Booting a bare-metal MCU
 * firmware needs a per-MCU platform description (.repl). This provider selects a bundled Renode platform from
 * hints in the firmware, builds a headless script that boots the ELF and shows the UART, and decides success from
 * real guest output. Without Renode, or with no platform match, it degrades HONESTLY to blocked_by_platform — it
 * never fakes an RTOS boot. The platform-selection map + script builder are pure and unit-tested.
 *
 * Full auto-identification of arbitrary MCUs is future work; this wires a real boot for the common families.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import type { ProofState } from '@firmlab/core';
import { type IsolationLevel, loadIsolationLimits, runIsolated } from './isolate.js';

const execFileAsync = promisify(execFile);

/** Where Renode installs its bundled platform descriptions (portable release / package). */
export const RENODE_PLATFORMS_DIR = '/opt/renode/platforms';

/** The Renode install root — `using "platforms/…"` includes in a .repl resolve against this. */
const RENODE_ROOT = path.dirname(RENODE_PLATFORMS_DIR);

/** Hints (MCU/vendor markers) → a bundled Renode board .repl (relative to the platforms dir). Common families. */
const PLATFORM_MAP: { match: RegExp; repl: string }[] = [
  { match: /stm32f4|stm32f407|discovery/i, repl: 'boards/stm32f4_discovery-kit.repl' },
  { match: /stm32f0|stm32f072/i, repl: 'boards/stm32f072b_discovery.repl' },
  { match: /stm32l0|stm32l07/i, repl: 'boards/stm32l072.repl' },
  { match: /nrf52|nordic/i, repl: 'cpus/nrf52840.repl' },
  { match: /cc2538|cc26|ti\b/i, repl: 'cpus/cc2538.repl' },
  { match: /efr32|silabs|gecko/i, repl: 'cpus/efr32mg.repl' },
  { match: /cortex-?m4|cortex-?m3|arm.*mcu/i, repl: 'cpus/cortex-m4.repl' },
];

/** Pure: choose a bundled platform for a firmware from its hints, or null if nothing matches (→ honest block). */
export function selectPlatform(hints: string[], platformsDir = RENODE_PLATFORMS_DIR): string | null {
  const hay = hints.join(' ');
  for (const { match, repl } of PLATFORM_MAP) {
    if (match.test(hay)) {
      const full = path.join(platformsDir, repl);
      // Prefer a platform that actually ships in this Renode; fall back to the mapped path regardless in tests.
      if (platformsDir === RENODE_PLATFORMS_DIR && !safeExists(full)) continue;
      return full;
    }
  }
  return null;
}

function safeExists(p: string): boolean {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
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
  const platform = opts.platform ?? selectPlatform(hints);
  if (!platform) {
    return {
      ...blocked('No matching Renode platform (.repl) for this MCU — RTOS boot needs one; not fabricating a run.'),
      available: true,
    };
  }

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
      reason: booted
        ? `Guest booted and produced UART output on ${captures.map((c) => c.uart).join(', ')}.`
        : res.timedOut
          ? 'Ran to the time bound with no UART output captured.'
          : 'Renode session ended without UART output.',
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
