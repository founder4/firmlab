/**
 * Export reachability — the question a shared object and a kernel module can actually be asked.
 *
 * **The gap this closes, and it was open on both sides.** `symreach` explores symbolically from a program's
 * ENTRY POINT. A `.so` has none — it is entered through an exported function — and neither does a `.ko`, which
 * the kernel calls through a handler it registered. Two backlog entries said the same thing from opposite sides:
 * *"Libraries are permanently unasked"* and *"the `.ko` lane and the `.so` lane are the same missing rung"*. A
 * vulnerable library or module stayed a candidate nothing would ever settle, and the four `symreach` rows this
 * project had to RETIRE were exactly that — angr budget spent on a question that could not be posed.
 *
 * **Why a control-flow query and not symbolic execution. Measured, not assumed.** The obvious extension is a
 * symbolic `call_state` at an exported symbol. It was tried first, on the real `NetUSB.ko` from the WDR3600,
 * against a target provably INSIDE the function being explored — `__kmalloc`'s call site, 0x51c into
 * `SoftwareBus_dispatchNormalEPMsgOut`. **5925 steps, 123 seconds, never reached it.** An exported function's
 * arguments are symbolic pointers into unconstrained memory, so the search fans out through data it cannot
 * constrain. The same question over the recovered CFG is answered in **microseconds** after a ~2 s graph build.
 * The negative result is the reason this provider exists in the shape it does, and it is recorded rather than
 * quietly discarded.
 *
 * **The claim is weaker than `symreach`'s and nothing may merge them.** A path in a control-flow graph is not a
 * FEASIBLE path: nothing checks that the branch conditions along it can hold together. It says the code contains
 * a route from an entry an outsider can invoke to the sink — a real upgrade over "this object imports strcpy",
 * and strictly less than `symreach`'s `reached`. Both are therefore `needs_runtime_reproduction`; what separates
 * them is severity and wording, which is the two-axis split this ledger already draws.
 *
 * **Three different silences, and none of them is a negative.**
 *   - `not_reached` — the RECOVERED graph shows no route. CFGFast does not resolve indirect calls and both
 *     target classes are built on them: a kernel module registers a handler and the kernel calls it through a
 *     pointer, which is why `init_module` reaches almost nothing in the measured run.
 *   - `no_call_site` — the sink symbol is present but no recovered block calls it.
 *   - `no_functions_recovered` — the graph came back EMPTY, which is a failure to analyse and is
 *     `blocked_by_platform`. It is not hypothetical: measured over the corpus, **all 628 `.ko` files carry
 *     section headers and every one is analysable, while 357 of 791 `.so` files (45%) do not** — the WR940N
 *     strips them from all 64 of its libraries, which is the deeper reason its library probes were inconclusive.
 *     CFGFast recovers nothing from a section-less object even with `force_complete_scan` or explicit
 *     `function_starts`, so this is a tool boundary, reported as one.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import type { FindingSeverity } from '@firmlab/core';
import type { FindingDraft } from '../findings-normalize.js';

const execFileAsync = promisify(execFile);

/** Per-sink outcome, exactly as the probe reports it. */
export type SinkOutcome = 'reachable' | 'not_reached' | 'absent' | 'no_call_site' | 'budget_exhausted';

export interface SinkReach {
  sink: string;
  outcome: SinkOutcome;
  /** Functions containing a call to this sink. */
  holders?: number;
  /** How many entry points can reach one of those, through the call graph. */
  reachableFrom?: number;
  /** A bounded sample of those entry points, shortest name first. */
  entryPointsNamed?: string[];
  /** How many more there were than the sample names. */
  namedTruncated?: number;
}

export interface ExportReachResult {
  available: boolean;
  reason: string;
  binary?: string;
  arch?: string;
  /** Functions in the recovered call graph. ZERO is the analysable/not-analysable boundary — see the module doc. */
  functionsRecovered?: number;
  callEdges?: number;
  /** Entry points found: exported functions for a `.so`, global function symbols for a `.ko`. */
  entryPoints?: number;
  entryPointsConsidered?: number;
  cfgSeconds?: number;
  elapsedSeconds?: number;
  /** `no_functions_recovered` when the graph came back empty. */
  outcome?: string;
  sinks: SinkReach[];
  findings: FindingDraft[];
}

/**
 * The sinks worth asking about in an object with no entry point, and what a route to each would mean.
 *
 * Split by TARGET CLASS because the vocabularies do not overlap: a kernel module never calls `system(3)` and a
 * userland library never calls `__kmalloc`. Asking the wrong set wastes nothing here (an absent symbol is
 * reported `absent` in microseconds) but it makes the result read as if the question applied.
 */
export const KERNEL_SINKS = ['__kmalloc', 'kmalloc', 'kzalloc', 'memcpy', 'strcpy', 'sprintf', 'copy_from_user'];
export const USERLAND_SINKS = ['strcpy', 'strcat', 'sprintf', 'vsprintf', 'system', 'popen', 'execve', 'memcpy'];

/** Pure: which sink vocabulary applies, from the file's own extension and ELF type. */
export function sinksFor(relPath: string): readonly string[] {
  return relPath.endsWith('.ko') ? KERNEL_SINKS : USERLAND_SINKS;
}

/** How much a route to this sink matters IF the path is real. The proof state never moves; this axis does. */
export function sinkSeverity(sink: string): FindingSeverity {
  if (sink === 'system' || sink === 'popen' || sink === 'execve') return 'high';
  if (sink === 'strcpy' || sink === 'strcat' || sink === 'sprintf' || sink === 'vsprintf') return 'medium';
  if (sink === 'copy_from_user') return 'medium';
  return 'low';
}

/**
 * Pure: compose the ledger rows.
 *
 * One row per REACHABLE sink, never one per entry point: a library where forty exports all reach `strcpy` is one
 * fact about the library, and forty rows would drown the ledger while saying it once. The count and a bounded
 * sample of names travel in the evidence.
 *
 * An empty graph earns a row too, and it is `blocked_by_platform` — the question was asked and this deployment
 * could not answer it. Leaving it silent would let a section-stripped library read exactly like one that was
 * analysed and found clean, which is the single most important distinction this provider draws.
 */
export function buildExportReachFindings(rel: string, r: ExportReachResult): FindingDraft[] {
  const out: FindingDraft[] = [];
  const kind = rel.endsWith('.ko') ? 'kernel module' : 'shared object';

  if (r.outcome === 'no_functions_recovered') {
    out.push({
      kind: 'export-reach-blocked',
      severity: 'info',
      proofState: 'blocked_by_platform',
      title: `Control-flow recovery returned nothing: ${path.basename(rel)}`,
      evidenceChannel: 'static_bytes',
      evidence: { path: rel, functionsRecovered: 0, arch: r.arch ?? null },
      rationale: [
        `angr recovered ZERO functions from this ${kind}, so no reachability question could be asked of it.`,
        'On this corpus that means the object carries no section headers — CFG recovery finds nothing without',
        'them, and neither a complete scan nor an explicit list of function starts changes it. This is a',
        'boundary of the tool, not a property of the code: it is NOT a statement that the object is free of',
        'reachable sinks, and it must not be read as one.',
      ].join(' '),
    });
    return out;
  }

  for (const s of r.sinks) {
    if (s.outcome !== 'reachable') continue;
    const names = s.entryPointsNamed ?? [];
    const sample = names.slice(0, 6).join(', ');
    const more = (s.namedTruncated ?? 0) + Math.max(0, names.length - 6);
    // The head carries every interpolation (counts, and the optional example list); the tail is fixed prose. Kept
    // as one template + a joined array rather than a chain of `+`, which mixes template and string and reads as
    // string concatenation to the linter — the same shape `symreach`'s rationales use.
    const lead = `In the recovered call graph, ${s.reachableFrom ?? 0} of this ${kind}'s ${r.entryPoints ?? 0} entry point(s) can reach one of the ${s.holders ?? 0} function(s) that call ${s.sink}${sample ? ` — for example ${sample}${more > 0 ? ` (+${more} more)` : ''}` : ''}.`;
    out.push({
      kind: 'export-reachable-sink',
      severity: sinkSeverity(s.sink),
      proofState: 'needs_runtime_reproduction',
      title: `${s.sink} lies on a control-flow path from an entry point: ${path.basename(rel)}`,
      evidenceChannel: 'static_bytes',
      evidence: {
        path: rel,
        sink: s.sink,
        holderFunctions: s.holders ?? 0,
        reachableFromEntryPoints: s.reachableFrom ?? 0,
        entryPointsTotal: r.entryPoints ?? 0,
        entryPointsNamed: names,
        namedTruncated: more,
        functionsRecovered: r.functionsRecovered ?? 0,
      },
      rationale: [
        lead,
        'This object has no entry point of its own, so a path from an ENTRY POINT is the strongest',
        'reachability statement it admits, and it is weaker than symbolic reachability in a specific way:',
        'nothing here checks that the branch conditions along the path can be satisfied together. It says the',
        'route exists in the code, not that an input drives it. A LEAD, and a stronger one than an import.',
      ].join(' '),
    });
  }
  return out;
}

/** Pure: the sentence stating what ran and what it does and does not cover. */
export function summarise(rel: string, r: Omit<ExportReachResult, 'reason' | 'findings'>): string {
  if (r.outcome === 'no_functions_recovered') {
    return `The control-flow graph came back empty for ${rel}, so nothing could be asked of it. That is a failure to analyse, not a clean result.`;
  }
  const reachable = r.sinks.filter((s) => s.outcome === 'reachable').length;
  const absent = r.sinks.filter((s) => s.outcome === 'absent').length;
  const notReached = r.sinks.filter((s) => s.outcome === 'not_reached').length;
  return [
    `${r.functionsRecovered ?? 0} function(s) recovered, ${r.entryPoints ?? 0} entry point(s);`,
    `${reachable} sink(s) reachable, ${notReached} not reached in the recovered graph, ${absent} absent.`,
    'A sink not reached is NOT a sink that cannot be reached: indirect calls are unresolved here, and both',
    'shared objects and kernel modules are built on them.',
  ].join(' ');
}

/** Probe availability: the angr venv, the same one `symreach` uses. */
async function angrAvailable(pythonBin: string): Promise<{ ok: boolean; reason?: string }> {
  try {
    await execFileAsync(pythonBin, ['-c', 'import angr'], { timeout: 60000 });
    return { ok: true };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return { ok: false, reason: `The angr interpreter (${pythonBin}) is not installed.` };
    return { ok: false, reason: `angr could not be imported by ${pythonBin}.` };
  }
}

const SCRIPT = 'angr-cfgreach.py';

/** Where the probe script lives, relative to the built provider. */
function scriptPath(): string {
  return path.resolve(process.cwd(), 'apps/api/scripts', SCRIPT);
}

/**
 * Run the export-reachability probe over one object.
 *
 * `budgetSeconds` bounds the SINK LOOP, not the graph build — the build is a single up-front cost of a couple of
 * seconds and cutting it in half would leave a partial graph whose silences mean nothing.
 */
export async function runExportReach(
  absPath: string,
  relPath: string,
  opts: { sinks?: readonly string[]; budgetSeconds?: number } = {},
): Promise<ExportReachResult> {
  const pythonBin = process.env.FIRMLAB_ANGR_PYTHON ?? 'python3';
  const probe = await angrAvailable(pythonBin);
  if (!probe.ok) {
    return {
      available: false,
      reason: `${probe.reason ?? 'angr unavailable'} No reachability question was asked, which is not an answer about this object.`,
      sinks: [],
      findings: [],
    };
  }
  if (!fs.existsSync(absPath)) {
    return { available: false, reason: `No such file in the rootfs: ${relPath}`, sinks: [], findings: [] };
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-cfgreach-'));
  const specFile = path.join(dir, 'spec.json');
  const outFile = path.join(dir, 'out.json');
  const budgetSeconds = Math.max(15, Math.min(600, opts.budgetSeconds ?? 240));
  try {
    fs.writeFileSync(
      specFile,
      JSON.stringify({ binary: absPath, sinks: opts.sinks ?? sinksFor(relPath), budgetSeconds }),
    );
    await execFileAsync(pythonBin, [scriptPath(), specFile, outFile], {
      timeout: (budgetSeconds + 120) * 1000,
      maxBuffer: 16 * 1024 * 1024,
    });
    const raw = JSON.parse(fs.readFileSync(outFile, 'utf8')) as Record<string, unknown>;
    if (raw.ok !== true) {
      return {
        available: false,
        reason: `The probe could not analyse ${relPath}: ${String(raw.error ?? 'unknown error')}`,
        sinks: [],
        findings: [],
      };
    }
    const parsed: Omit<ExportReachResult, 'reason' | 'findings'> = {
      available: true,
      binary: relPath,
      ...(typeof raw.arch === 'string' ? { arch: raw.arch } : {}),
      ...(typeof raw.functionsRecovered === 'number' ? { functionsRecovered: raw.functionsRecovered } : {}),
      ...(typeof raw.callEdges === 'number' ? { callEdges: raw.callEdges } : {}),
      ...(typeof raw.entryPoints === 'number' ? { entryPoints: raw.entryPoints } : {}),
      ...(typeof raw.entryPointsConsidered === 'number' ? { entryPointsConsidered: raw.entryPointsConsidered } : {}),
      ...(typeof raw.cfgSeconds === 'number' ? { cfgSeconds: raw.cfgSeconds } : {}),
      ...(typeof raw.elapsedSeconds === 'number' ? { elapsedSeconds: raw.elapsedSeconds } : {}),
      ...(typeof raw.outcome === 'string' ? { outcome: raw.outcome } : {}),
      sinks: Array.isArray(raw.sinks) ? (raw.sinks as SinkReach[]) : [],
    };
    const result: ExportReachResult = { ...parsed, reason: summarise(relPath, parsed), findings: [] };
    result.findings = buildExportReachFindings(relPath, result);
    return result;
  } catch (e) {
    return {
      available: false,
      reason: `The probe failed on ${relPath}: ${(e as Error).message}. Nothing was concluded about this object.`,
      sinks: [],
      findings: [],
    };
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // A leaked temp dir is not worth failing a run over.
    }
  }
}
