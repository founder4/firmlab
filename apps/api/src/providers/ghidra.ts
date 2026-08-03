/**
 * Ghidra decompilation provider. Runs Ghidra's headless analyzer (`analyzeHeadless`) over a single binary from
 * the extracted rootfs and returns C pseudocode for its functions. Ghidra is an OPTIONAL, heavy tool: the
 * firmware image ships without it by default, so with `analyzeHeadless` absent the job returns a clear
 * `available:false` result (the radare2 triage in decompile.ts already covers the light path). The requested
 * path is confined to the rootfs to prevent traversal.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import type { FindingDraft } from '../findings-normalize.js';
import { isToolAvailable } from '../tools.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

export interface GhidraFunction {
  name: string;
  signature: string;
  pseudocode: string;
}

export interface GhidraResult {
  available: boolean;
  reason?: string;
  binary: string;
  functionCount: number;
  functions: GhidraFunction[];
}

const MAX_FUNCTIONS = 40;
const MAX_PSEUDOCODE = 8000;

/**
 * What a Ghidra run owes the findings ledger, and the answer is: a row ONLY when it could not run.
 *
 * This provider was one of the rungs that executed without ever writing to the ledger, and the fix for the others
 * was to compose a row per outcome. Here that would be wrong. A decompilation is a VIEW, not a claim — pseudocode
 * for forty functions asserts no property of the firmware, and a row reading "40 functions decompiled" would be a
 * status dressed as a finding, which is the same defect as an outcome column that always says `done`. What the
 * run DID belongs in the run ledger (`run-summary.ts`), where the question is "what came of it".
 *
 * The blocked case is the opposite, and it is rule 2 of the proof-state discipline: absence of a tool is not
 * absence of a problem. Ghidra is an opt-in heavy layer the shipped image does not include, so an operator
 * reading a dossier with no Ghidra rows cannot otherwise tell "it was decompiled and there was nothing to assert"
 * from "the decompiler is not installed here". That distinction is exactly what `blocked_by_platform` exists to
 * carry, and it is the only thing this composer says.
 */
export function buildGhidraFindings(r: GhidraResult): FindingDraft[] {
  if (r.available) return [];
  return [
    {
      kind: 'decompilation-blocked',
      title: `${r.binary}: the decompiler could not run here — this is not a negative result`,
      severity: 'info',
      proofState: 'blocked_by_platform',
      // No evidence channel: nothing was read, so nothing was learned through any channel.
      evidence: { binary: r.binary, reason: r.reason ?? 'unavailable' },
      rationale: `Ghidra was asked to decompile this binary and this deployment could not answer: ${r.reason ?? 'the decompiler is unavailable'}. The question stands unanswered — it says nothing about whether the binary holds anything worth finding.`,
    },
  ];
}

function unavailable(binary: string, reason: string): GhidraResult {
  return { available: false, reason, binary, functionCount: 0, functions: [] };
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

/**
 * Locate the bundled Ghidra post-script directory (`apps/api/ghidra-scripts`). The compiled provider runs from
 * `apps/api/dist/providers/`, so the scripts dir is three levels up; overridable with FIRMLAB_GHIDRA_SCRIPTS.
 */
function scriptDir(): string {
  if (process.env.FIRMLAB_GHIDRA_SCRIPTS) return path.resolve(process.env.FIRMLAB_GHIDRA_SCRIPTS);
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, '../../ghidra-scripts');
}

/** Clamp/normalize the raw JSON the post-script writes into the result contract. */
export function normalizeFunctions(raw: unknown): GhidraFunction[] {
  if (!Array.isArray(raw)) return [];
  return raw.slice(0, MAX_FUNCTIONS).map((f) => {
    const o = (f ?? {}) as Record<string, unknown>;
    return {
      name: String(o.name ?? '?'),
      signature: String(o.signature ?? ''),
      pseudocode: String(o.pseudocode ?? '').slice(0, MAX_PSEUDOCODE),
    };
  });
}

export async function runGhidra(rootfsPath: string, binary: string, handle: JobHandle): Promise<GhidraResult> {
  if (!(await isToolAvailable('analyzeHeadless'))) {
    handle.log('Ghidra (analyzeHeadless) not available — rebuild the firmware image with the optional Ghidra layer.');
    return unavailable(binary, 'Ghidra (analyzeHeadless) not installed');
  }

  const abs = resolveInsideRootfs(rootfsPath, binary);
  if (!abs) {
    handle.log(`Binary not found inside rootfs or path rejected: ${binary}`);
    return unavailable(binary, 'binary not found in rootfs');
  }

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-ghidra-'));
  const projDir = path.join(workDir, 'proj');
  const outJson = path.join(workDir, 'out.json');
  fs.mkdirSync(projDir, { recursive: true });

  try {
    const args = [
      projDir,
      'firmlabproj',
      '-import',
      abs,
      '-scriptPath',
      scriptDir(),
      '-postScript',
      'Decompile.java',
      outJson,
      '-deleteProject',
    ];
    handle.log(`Running: analyzeHeadless ${args.join(' ')}`);
    try {
      const { stdout } = await execFileAsync('analyzeHeadless', args, {
        timeout: 10 * 60 * 1000,
        maxBuffer: 64 * 1024 * 1024,
      });
      for (const line of stdout.split('\n').slice(-40)) if (line.trim()) handle.log(line);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      handle.log(`analyzeHeadless failed: ${message}`);
      return unavailable(binary, `Ghidra failed: ${message}`);
    }

    if (!fs.existsSync(outJson)) {
      return unavailable(binary, 'Ghidra produced no output (script did not run)');
    }
    let functions: GhidraFunction[];
    try {
      functions = normalizeFunctions(JSON.parse(fs.readFileSync(outJson, 'utf8')));
    } catch (err) {
      return unavailable(binary, `Could not parse Ghidra output: ${err instanceof Error ? err.message : String(err)}`);
    }

    handle.log(`Ghidra decompiled ${functions.length} functions.`);
    return { available: true, binary, functionCount: functions.length, functions };
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}
