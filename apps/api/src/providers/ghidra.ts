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
  /**
   * How many functions this result LISTS. Always `functions.length`, and that is the whole problem it used to
   * hide: `apps/web/src/capabilities.ts` fed the pair `{functionCount, functions.length}` to the coverage widget
   * as denominator and numerator, so the widget could only ever read "40 of 40" for a binary with thousands of
   * functions. Kept, with its original meaning, because job rows persisted by older builds hold exactly this.
   */
  functionCount: number;
  functions: GhidraFunction[];
  /**
   * Every function Ghidra knows about, and how many of those the script was willing to decompile — thunks and
   * externals are never decompiled, so `eligibleCount` is the honest denominator for `functions.length`.
   *
   * Both OPTIONAL FOREVER. A `GhidraResult` is persisted as JSON on the job row and re-read for as long as the
   * image exists, so a stored result is data written by an older build and cannot carry a field it never had.
   * Absent means the totals were not recorded — never that the decompilation was complete.
   */
  functionTotal?: number;
  eligibleCount?: number;
}

/** What the post-script writes: totals plus the bounded list. An older script wrote the bare array instead. */
export interface GhidraScriptOutput {
  functions: GhidraFunction[];
  functionTotal?: number;
  eligibleCount?: number;
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
  const list = Array.isArray(raw)
    ? raw
    : Array.isArray((raw as { functions?: unknown })?.functions)
      ? (raw as { functions: unknown[] }).functions
      : [];
  return list.slice(0, MAX_FUNCTIONS).map((f) => {
    const o = (f ?? {}) as Record<string, unknown>;
    return {
      name: String(o.name ?? '?'),
      signature: String(o.signature ?? ''),
      pseudocode: String(o.pseudocode ?? '').slice(0, MAX_PSEUDOCODE),
    };
  });
}

/**
 * Pure: read the post-script's output, whichever shape it is in.
 *
 * A bare array is what the script wrote before it counted anything, and a job row holding one is still readable
 * today — so the array form yields NO totals rather than inventing them from the list's own length, which is the
 * fabrication this whole change exists to remove. A total that is absent, or that is somehow smaller than the
 * list it supposedly bounds, is dropped rather than reported.
 */
export function parseScriptOutput(raw: unknown): GhidraScriptOutput {
  const functions = normalizeFunctions(raw);
  if (Array.isArray(raw) || raw === null || typeof raw !== 'object') return { functions };
  const o = raw as Record<string, unknown>;
  const count = (v: unknown): number | undefined =>
    typeof v === 'number' && Number.isFinite(v) && v >= functions.length ? Math.floor(v) : undefined;
  const functionTotal = count(o.functionTotal);
  const eligibleCount = count(o.eligible ?? o.eligibleCount);
  return {
    functions,
    ...(functionTotal !== undefined ? { functionTotal } : {}),
    ...(eligibleCount !== undefined ? { eligibleCount } : {}),
  };
}

/**
 * Pure: whether a run came back with function metadata but no pseudocode anywhere.
 *
 * True only when there is at least one function AND every one of them is empty. One function that fails to
 * decompile is ordinary; all of them failing is a statement about the platform, not about the binary.
 */
export function allPseudocodeEmpty(functions: readonly GhidraFunction[]): boolean {
  return functions.length > 0 && functions.every((f) => f.pseudocode.length === 0);
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
    let parsed: GhidraScriptOutput;
    try {
      parsed = parseScriptOutput(JSON.parse(fs.readFileSync(outJson, 'utf8')));
    } catch (err) {
      return unavailable(binary, `Could not parse Ghidra output: ${err instanceof Error ? err.message : String(err)}`);
    }

    const { functions, functionTotal, eligibleCount } = parsed;

    /**
     * Ghidra present, decompiler absent — and this is the branch that only running it finds.
     *
     * `analyzeHeadless` is a Java launcher; the decompiler it drives is a NATIVE binary that Ghidra ships
     * pre-built for a handful of platforms and otherwise expects you to compile. On the deployed arm64 container
     * it is missing (`ERROR os/linux_arm_64/decompile does not exist`), so the run completes, the script walks
     * every function, and every single one comes back with an empty `pseudocode` string. `isToolAvailable`
     * passes, nothing throws, and the old code returned `available: true` with forty functions containing no
     * pseudocode whatsoever: a decompilation that decompiled nothing, reported as a success.
     *
     * That is rule 2 of the proof-state discipline — absence of a tool is not absence of a problem — and the
     * honest answer is the one `buildGhidraFindings` already composes for the blocked case. Names and signatures
     * come from the analyzer, not the decompiler, so their presence proves nothing about pseudocode.
     *
     * Requiring EVERY function to be empty is deliberate: a single function that fails to decompile is normal and
     * must not condemn the run. All of them empty is a platform fact, not a property of the binary.
     */
    if (allPseudocodeEmpty(functions)) {
      handle.log(
        `Ghidra analysed ${functions.length} function(s) and produced no pseudocode for any of them — its native decompiler is not available on this platform.`,
      );
      return unavailable(
        binary,
        `Ghidra ran but produced no pseudocode for any of ${functions.length} function(s) — its native decompiler is not built for this platform`,
      );
    }

    const denom = eligibleCount ?? functionTotal;
    handle.log(
      denom !== undefined
        ? `Ghidra decompiled ${functions.length} of ${denom} eligible function(s)` +
            `${functionTotal !== undefined ? ` (${functionTotal} total, thunks and externals excluded)` : ''}.`
        : `Ghidra decompiled ${functions.length} functions; the script reported no total.`,
    );
    return {
      available: true,
      binary,
      functionCount: functions.length,
      functions,
      ...(functionTotal !== undefined ? { functionTotal } : {}),
      ...(eligibleCount !== undefined ? { eligibleCount } : {}),
    };
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}
