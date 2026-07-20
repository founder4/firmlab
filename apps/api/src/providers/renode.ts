/**
 * Renode provider (Phase 4 debt #4, scaffold) — the RTOS / Cortex-M rung of the emulation ladder. Booting a
 * bare-metal MCU firmware needs a per-MCU platform description (.repl); without one (or without Renode installed)
 * this degrades HONESTLY to blocked_by_platform — it never fakes an RTOS boot. When a platform is supplied it
 * builds a headless .resc script and runs it bounded. The script builder is pure and unit-tested.
 *
 * Full class coverage (auto-selecting a platform per detected MCU) is future work; this wires the honest floor.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { ProofState } from '@firmlab/core';
import { type IsolationLevel, runIsolated } from './isolate.js';

const execFileAsync = promisify(execFile);

export interface RenodeResult {
  available: boolean;
  ran: boolean;
  reason: string;
  proofState: ProofState;
  command: string;
  isolation?: IsolationLevel;
}

/** Pure: the headless Renode script that loads a platform and the firmware ELF, then runs it. */
export function buildRenodeScript(platformPath: string, firmwarePath: string): string {
  return [
    'mach create',
    `machine LoadPlatformDescription @${platformPath}`,
    `sysbus LoadELF @${firmwarePath}`,
    'start',
  ].join('\n');
}

export async function detectRenode(): Promise<boolean> {
  try {
    await execFileAsync('renode', ['--version'], { timeout: 5000 });
    return true;
  } catch (err) {
    return (err as { code?: string }).code !== 'ENOENT';
  }
}

/**
 * Boot an RTOS/Cortex-M firmware under Renode — honestly. Blocked when Renode or a platform description is absent.
 */
export async function runRenode(
  firmwarePath: string,
  platformPath: string | null,
  seconds = 20,
): Promise<RenodeResult> {
  if (!(await detectRenode())) {
    return {
      available: false,
      ran: false,
      reason: 'Renode not installed (opt-in layer).',
      proofState: 'blocked_by_platform',
      command: '',
    };
  }
  if (!platformPath) {
    return {
      available: true,
      ran: false,
      reason: 'No Renode platform description (.repl) for this MCU — RTOS boot needs one; not fabricating a run.',
      proofState: 'blocked_by_platform',
      command: '',
    };
  }
  const script = buildRenodeScript(platformPath, firmwarePath);
  const res = await runIsolated(['renode', '--disable-xwt', '--console', '-e', `${script}\nsleep ${seconds}\nquit`]);
  return {
    available: true,
    ran: res.ran,
    reason: res.timedOut ? 'Renode ran to the time bound.' : 'Renode session completed.',
    proofState: res.ran ? 'confirmed_in_emulation' : 'blocked_by_platform',
    command: res.command,
    isolation: res.isolation,
  };
}
