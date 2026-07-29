/**
 * Symbolic-reachability provider (W5 depth) — the answer to the one question `binvuln` cannot answer.
 *
 * `binvuln` sweeps the rootfs and flags every ELF that imports an unbounded-copy function and lacks a stack canary.
 * That is a *precondition*, not a bug, so every candidate lands as `needs_runtime_reproduction` and the operator is
 * left with a list of maybes. This provider takes one such candidate and asks angr a single, checkable question per
 * sink: **is that call site reachable from the entry point under attacker-controlled input?** A path that angr can
 * exhibit — with the concrete argv/stdin that walks it — upgrades the candidate from "imports strcpy" to "strcpy is
 * on a live path from input", which is a real, static-confirmable claim.
 *
 * The honesty contract, which is the whole reason this is a separate provider and not a severity bump:
 *
 *  - `reached` ⇒ `static_confirmed`, and the claim is *reachability*, never exploitability. FirmLab proves
 *    reachability and drafts disclosure; it does not build PoCs (docs/BACKLOG.md, out-of-scope).
 *  - `not_reached_in_budget` ⇒ the finding KEEPS `needs_runtime_reproduction`. Bounded symbolic execution that
 *    runs out of wall-clock, steps, or state budget has proven nothing: indirect jumps and unmodelled syscalls hide
 *    real paths routinely. An exhausted search is never a downgrade to `false_positive`, and the budget that ran
 *    out is recorded so the inconclusive reads as one.
 *  - angr absent / arch unsupported / loader failure ⇒ `blocked_by_platform` with the reason, never a silent skip.
 *
 * The spec builder, the result parser and the verdict mapper are PURE and unit-tested; the runner only shells out to
 * the bundled `scripts/angr-reach.py` under a hard timeout.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import type { FindingDraft } from '../findings-normalize.js';
import { angrPython, isToolAvailable } from '../tools.js';
import { UNSAFE_COPY_FNS, assessBinaryFile } from './binvuln.js';
import { resolveInsideRootfs } from './decompile.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

/** Per-run budgets. Deliberately modest: this runs inside an autonomous scan, not as a standalone campaign. */
export const DEFAULT_BUDGET_SECONDS = 90;
export const DEFAULT_MAX_STEPS = 400;
export const DEFAULT_MAX_ACTIVE = 24;
/** Asking about more than a handful of sinks splits the budget until every slice is useless. */
export const MAX_SINKS = 4;
/** A manual probe is an operator sitting in front of it, not a background scan — let them spend more wall-clock. */
export const MIN_BUDGET_SECONDS = 15;
export const MAX_BUDGET_SECONDS = 600;

/**
 * Which sink names are legitimate questions.
 *
 *  - `unsafe-copy` (the autonomous path): only the unbounded-copy functions W5 flags, because the lead being
 *    settled is specifically "this binary imports an unbounded copy and has no canary".
 *  - `as-given` (the manual route): whatever the operator named. The reachability question is not intrinsically
 *    about `strcpy` — "is `system` reachable in this CGI?" is the same question and the probe answers it the same
 *    way. A symbol the binary does not actually import comes back `absent` from the probe, so a wrong guess is
 *    reported as a wrong guess rather than silently dropped.
 */
export type SinkPolicy = 'unsafe-copy' | 'as-given';

export interface SymReachOptions {
  budgetSeconds?: number;
  policy?: SinkPolicy;
}

export interface ReachSpec {
  binary: string;
  sinks: string[];
  budgetSeconds: number;
  maxSteps: number;
  maxActive: number;
}

/** One sink's outcome as the python probe reports it. */
export type SinkOutcome = 'reached' | 'not_reached_in_budget' | 'absent' | 'skipped';

export interface SinkResult {
  sink: string;
  outcome: SinkOutcome;
  addresses: string[];
  steps: number;
  /** Active states were dropped to stay inside the memory bound — a not-reached under pruning is weaker still. */
  pruned: boolean;
  /** States lost to angr-internal crashes (its libc models are imperfect on real firmware) — paths never explored. */
  errors: number;
  reason?: string;
  /** Concrete inputs that walk the path (bounded previews, never a full payload). */
  argv1?: string;
  stdin?: string;
  /** The tail of the basic-block trace that got there — followable back into the disassembly. */
  path?: string[];
}

export interface SymReachResult {
  available: boolean;
  reason: string;
  binary: string;
  arch?: string;
  entry?: string;
  sinks: SinkResult[];
  findings: FindingDraft[];
  /** The sinks actually sent to the probe, and the ones the per-run cap left unasked (never silently dropped). */
  asked?: string[];
  dropped?: string[];
  /** True when the caller named no sinks and they were derived from the binary's own unbounded-copy imports. */
  derivedSinks?: boolean;
  budgetSeconds?: number;
}

/**
 * Pure: choose which sinks to ask about, ordered by how directly they overflow (`gets` takes no bound at all) and
 * capped so each sink gets a usable slice of the shared budget. Sinks dropped by the cap are returned separately so
 * the caller can say so rather than pretending they were answered.
 *
 * Under the default `unsafe-copy` policy only the unbounded-copy functions survive — the autonomous path is
 * settling a W5 candidate, and asking about `malloc` would answer a question nobody posed. Under `as-given` the
 * operator's list is kept verbatim (deduped): a manual probe gets to ask about `system`, `memcpy` or a
 * vendor-specific `doSystem` too. Known-unsafe names still sort first, so a mixed list spends the budget on the
 * sharpest question available.
 */
export function pickSinks(
  requestedSinks: string[],
  policy: SinkPolicy = 'unsafe-copy',
): { asked: string[]; dropped: string[] } {
  const priority = ['gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf', 'scanf', 'sscanf', 'vscanf'];
  const rank = (f: string): number => (priority.includes(f) ? priority.indexOf(f) : priority.length);
  const kept =
    policy === 'as-given'
      ? [...new Set(requestedSinks.map((f) => f.trim()).filter(Boolean))]
      : requestedSinks.filter((f) => UNSAFE_COPY_FNS.includes(f));
  // Stable within a rank: an operator's ordering is a preference, so preserve it among equally-ranked names.
  const ordered = kept
    .map((f, i) => ({ f, i }))
    .sort((a, b) => rank(a.f) - rank(b.f) || a.i - b.i)
    .map((e) => e.f);
  return { asked: ordered.slice(0, MAX_SINKS), dropped: ordered.slice(MAX_SINKS) };
}

/**
 * The findings source for a MANUAL probe — keyed by the question, not just by the binary.
 *
 * W9's re-planned probe keys on `symreach:<path>` alone, which is right for it: it always derives the same sinks
 * from the same candidate, so re-running a scan re-syncs the same rows instead of duplicating them. A manual probe
 * is different — the operator asks a *different question* about the same binary, and a per-binary key makes the
 * second question silently delete the first question's answer. Observed in validation on the real DVRF_v03:
 * `system` proven reachable in `usr/sbin/generate_pin` vanished from the ledger when a later probe on the same
 * binary asked about `sprintf` instead. A confirmed reachability result must not evaporate because a different one
 * was asked for, so the sink set is part of the key; re-asking the SAME question still re-syncs, never duplicates.
 *
 * A derived-sink probe (no sinks named) keeps the bare per-binary key, since that is the same question W9 asks.
 */
export function manualSource(binary: string, sinks: string[]): string {
  if (sinks.length === 0) return `symreach:${binary}`;
  return `symreach:${binary}#${[...sinks].sort().join(',')}`;
}

/** A symbol name the probe can actually look up — anything else is a typo, not a question. */
const SINK_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

/**
 * Pure: split an operator-supplied sink list into the names worth sending to the probe and the ones that are not
 * symbol names at all. Rejected entries are returned rather than filtered away, so the route can say which of the
 * operator's words it refused instead of silently answering a smaller question than the one that was asked.
 */
export function validateSinkNames(sinks: string[]): { valid: string[]; rejected: string[] } {
  const valid: string[] = [];
  const rejected: string[] = [];
  for (const raw of sinks) {
    const s = raw.trim();
    if (!s) continue;
    if (SINK_NAME_RE.test(s)) valid.push(s);
    else rejected.push(s);
  }
  return { valid: [...new Set(valid)], rejected: [...new Set(rejected)] };
}

/** Pure: the JSON spec handed to the python probe. */
export function buildSpec(absBinary: string, sinks: string[], budgetSeconds = DEFAULT_BUDGET_SECONDS): ReachSpec {
  return {
    binary: absBinary,
    sinks,
    budgetSeconds,
    maxSteps: DEFAULT_MAX_STEPS,
    maxActive: DEFAULT_MAX_ACTIVE,
  };
}

function str(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback;
}

/**
 * Pure: normalize the probe's JSON. Anything unrecognised degrades to an inconclusive entry rather than being
 * dropped — a sink we asked about and cannot read the answer for is not a sink that came back clean.
 */
export function parseReachOutput(raw: unknown): {
  ok: boolean;
  error?: string;
  arch?: string;
  entry?: string;
  sinks: SinkResult[];
} {
  if (!raw || typeof raw !== 'object') return { ok: false, error: 'probe produced no JSON object', sinks: [] };
  const o = raw as Record<string, unknown>;
  if (o.ok !== true) return { ok: false, error: str(o.error, 'probe reported failure'), sinks: [] };

  const rows = Array.isArray(o.results) ? o.results : [];
  const sinks: SinkResult[] = rows.map((r) => {
    const e = (r ?? {}) as Record<string, unknown>;
    const outcome = str(e.outcome);
    const known: SinkOutcome[] = ['reached', 'not_reached_in_budget', 'absent', 'skipped'];
    const result: SinkResult = {
      sink: str(e.sink, '?'),
      outcome: (known as string[]).includes(outcome) ? (outcome as SinkOutcome) : 'not_reached_in_budget',
      addresses: Array.isArray(e.addresses) ? e.addresses.map((a) => str(a)) : [],
      steps: typeof e.steps === 'number' ? e.steps : 0,
      pruned: e.pruned === true,
      errors: typeof e.errors === 'number' ? e.errors : 0,
    };
    if (!(known as string[]).includes(outcome)) {
      result.reason = `unrecognised probe outcome '${outcome}' — treated as inconclusive`;
    } else if (typeof e.reason === 'string') {
      result.reason = e.reason;
    }
    if (typeof e.argv1 === 'string' && e.argv1) result.argv1 = e.argv1;
    if (typeof e.stdin === 'string' && e.stdin) result.stdin = e.stdin;
    if (Array.isArray(e.path)) result.path = e.path.map((a) => str(a));
    return result;
  });

  return {
    ok: true,
    ...(typeof o.arch === 'string' ? { arch: o.arch } : {}),
    ...(typeof o.entry === 'string' ? { entry: o.entry } : {}),
    sinks,
  };
}

/**
 * Pure: turn the per-sink outcomes into findings.
 *
 * A `reached` sink is the only outcome that produces a NEW claim: the call site is on a feasible path from the
 * entry point, and here is the input that walks it — `high` / `static_confirmed`, phrased as reachability. Every
 * other outcome produces at most one aggregate note that records what was asked and what the budget did, so the
 * absence of an upgrade can never be misread as a clean result. `absent` sinks say nothing at all (the symbol just
 * is not in this binary) and are folded into the note.
 */
export function buildReachFindings(binary: string, sinks: SinkResult[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];

  for (const s of sinks.filter((x) => x.outcome === 'reached')) {
    const input = [s.argv1 ? `argv[1]="${s.argv1}"` : '', s.stdin ? `stdin="${s.stdin}"` : '']
      .filter(Boolean)
      .join(' · ');
    drafts.push({
      kind: 'sink-reachable',
      title: `${s.sink} in ${binary} is reachable from the entry point under symbolic input`,
      severity: 'high',
      proofState: 'static_confirmed',
      evidenceChannel: 'symbolic_execution',
      evidence: {
        binary,
        sink: s.sink,
        addresses: s.addresses,
        steps: s.steps,
        ...(input ? { concreteInput: input } : {}),
        ...(s.path ? { pathTail: s.path } : {}),
      },
      rationale: [
        `Symbolic execution found a feasible path from the entry point to the ${s.sink} call site and produced a`,
        'concrete input that walks it, so the sink is on a live path from attacker-controlled input rather than',
        'merely imported. This confirms REACHABILITY, not exploitability: whether the copy actually overflows a',
        'buffer and whether that is exploitable are separate questions this does not answer.',
      ].join(' '),
    });
  }

  const inconclusive = sinks.filter((s) => s.outcome === 'not_reached_in_budget');
  if (inconclusive.length > 0) {
    const pruned = inconclusive.some((s) => s.pruned);
    const toolErrors = inconclusive.reduce((n, s) => n + s.errors, 0);
    const detail = inconclusive.map((s) => `${s.sink} (${s.reason ?? 'budget spent'})`).join('; ');
    const prunedNote = pruned
      ? 'Active states were pruned to stay inside the memory bound, so the search was narrower still.'
      : '';
    // Naming the tool's own failures matters: a reader must not attribute to the firmware what is angr's model
    // breaking on it. angr's libc SimProcedures crash on real firmware inputs, and each crash is a path never walked.
    const errorNote = toolErrors
      ? `${toolErrors} state(s) were lost to angr-internal errors, so those paths were never explored at all.`
      : '';
    drafts.push({
      kind: 'sink-reachability-inconclusive',
      title: `Reachability of ${inconclusive.length} sink(s) in ${binary} is unresolved — the bounded search did not settle it`,
      severity: 'info',
      proofState: 'needs_runtime_reproduction',
      // The search RAN and did not settle it, which is still something the solver observed.
      evidenceChannel: 'symbolic_execution',
      evidence: { binary, sinks: inconclusive.map((s) => s.sink), detail, statesPruned: pruned, toolErrors },
      rationale: [
        'The bounded symbolic search did not reach these sinks before it stopped.',
        prunedNote,
        errorNote,
        'That is NOT evidence they are unreachable — indirect jumps and unmodelled syscalls routinely hide real',
        'paths from a bounded search. The corresponding candidates keep their needs-reproduction state; raising the',
        'budget or fuzzing the binary is the next rung.',
      ]
        .filter(Boolean)
        .join(' '),
    });
  }

  return drafts;
}

function unavailable(binary: string, reason: string): SymReachResult {
  return {
    available: false,
    reason,
    binary,
    sinks: [],
    findings: [
      {
        kind: 'sink-reachability-blocked',
        title: `Symbolic reachability could not run on ${binary}`,
        severity: 'info',
        proofState: 'blocked_by_platform',
        // No `evidenceChannel`, deliberately. angr is absent, so nothing was symbolically executed — stamping
        // this row `symbolic_execution` would name a means that was never used, on the one row whose entire
        // purpose is to say that the question could not be answered.
        evidence: { binary, reason },
        rationale:
          'The reachability question was asked but the deployment could not answer it. This is recorded so the ' +
          'absence of a reachability verdict is visible as a missing capability, not mistaken for a clean result.',
      },
    ],
  };
}

/** Locate the bundled probe. The compiled provider runs from `apps/api/dist/providers/`, so scripts is two up. */
function probeScript(): string {
  if (process.env.FIRMLAB_ANGR_SCRIPT) return path.resolve(process.env.FIRMLAB_ANGR_SCRIPT);
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, '../../scripts/angr-reach.py');
}

/**
 * Ask angr whether the named sinks are reachable inside one rootfs binary. Degrades honestly at every step: angr
 * absent, binary outside the rootfs, probe crash and unparsable output each produce a `blocked` finding with the
 * reason rather than an empty result.
 *
 * `sinks` may be empty — then they are DERIVED from the binary's own unbounded-copy imports, which is what a lead
 * that names a target but not its symbols (a W4 taint chain pointing at a native helper) and a manual probe with
 * no sink specified both need. A binary that imports none of them is reported as having nothing to ask about,
 * which is a real answer, not a failure.
 */
export async function runSymReach(
  rootfsPath: string | null,
  binary: string,
  sinks: string[],
  handle: JobHandle,
  opts: SymReachOptions = {},
): Promise<SymReachResult> {
  const policy = opts.policy ?? 'unsafe-copy';
  const budgetSeconds = Math.min(
    MAX_BUDGET_SECONDS,
    Math.max(MIN_BUDGET_SECONDS, opts.budgetSeconds ?? DEFAULT_BUDGET_SECONDS),
  );
  if (!rootfsPath) return unavailable(binary, 'No extracted rootfs.');
  if (!(await isToolAvailable('angr'))) {
    handle.log('angr not available — rebuild the tools base with the optional angr layer to answer reachability.');
    return unavailable(binary, 'angr not installed in this deployment');
  }

  const abs = resolveInsideRootfs(rootfsPath, binary);
  if (!abs) return unavailable(binary, 'binary not found inside the rootfs');

  // No sinks named → read them off the binary itself. This is the same symbol extraction the W5 sweep uses, so a
  // derived question asks exactly what the sweep would have flagged.
  const derivedSinks = sinks.length === 0;
  const requested = derivedSinks ? assessBinaryFile(abs, binary).unsafeCopy : sinks;
  const { asked, dropped } = pickSinks(requested, derivedSinks ? 'unsafe-copy' : policy);
  if (asked.length === 0) {
    return unavailable(
      binary,
      derivedSinks
        ? 'binary imports no unbounded-copy function — name a sink explicitly to ask about something else'
        : 'no sink to ask about',
    );
  }

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-angr-'));
  const specPath = path.join(workDir, 'spec.json');
  const outPath = path.join(workDir, 'out.json');

  try {
    fs.writeFileSync(specPath, JSON.stringify(buildSpec(abs, asked, budgetSeconds)));
    handle.log(`angr: asking reachability of ${asked.join('/')} in ${binary} (budget ${budgetSeconds}s).`);
    try {
      // Hard kill a little past the probe's own budget — the probe self-limits, this is the backstop.
      await execFileAsync(angrPython(), [probeScript(), specPath, outPath], {
        timeout: (budgetSeconds + 60) * 1000,
        maxBuffer: 8 * 1024 * 1024,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // The probe writes its JSON before exiting non-zero in most failure modes; only give up if it wrote nothing.
      if (!fs.existsSync(outPath)) {
        handle.log(`angr probe failed: ${message}`);
        return unavailable(binary, `angr probe failed: ${message}`);
      }
    }

    if (!fs.existsSync(outPath)) return unavailable(binary, 'angr probe produced no output');
    let parsed: ReturnType<typeof parseReachOutput>;
    try {
      parsed = parseReachOutput(JSON.parse(fs.readFileSync(outPath, 'utf8')));
    } catch (err) {
      return unavailable(binary, `could not parse angr output: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (!parsed.ok) return unavailable(binary, parsed.error ?? 'angr probe reported failure');

    const reached = parsed.sinks.filter((s) => s.outcome === 'reached').length;
    const droppedNote = dropped.length > 0 ? ` ${dropped.length} further sink(s) not asked (per-run cap).` : '';
    const reason =
      `angr on ${binary} (${parsed.arch ?? 'unknown arch'}): ${reached}/${asked.length} sink(s) proven reachable ` +
      `from the entry point.${droppedNote} A sink not reached is inconclusive, never proven unreachable.`;
    handle.log(reason);

    return {
      available: true,
      reason,
      binary,
      ...(parsed.arch ? { arch: parsed.arch } : {}),
      ...(parsed.entry ? { entry: parsed.entry } : {}),
      sinks: parsed.sinks,
      findings: buildReachFindings(binary, parsed.sinks),
      asked,
      dropped,
      derivedSinks,
      budgetSeconds,
    };
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}
