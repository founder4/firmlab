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
 *  - a question that could not be POSED — no rootfs, the binary is not in it, the sink policy kept none of the
 *    names asked about — is none of the above and writes NO row. See `SymReachBlockedBy`.
 *
 * **Two rungs, one prover.** Everything above describes the EXECUTABLE rung and it is unchanged. A shared object
 * (ET_DYN with a `DT_SONAME`) has no entry point to explore from, so it keeps the same bounded symbolic search and
 * starts it at each EXPORTED function instead — see the library rung at the bottom of this file. What that proves
 * is weaker, because an export's arguments are unconstrained, so its rows stay `needs_runtime_reproduction`, they
 * never enter `sinks` (whose `reached` means the entry-point claim), and the `exportreach` lane's control-flow
 * answer about the same object is left exactly where it is.
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
import { type BinAssessment, UNSAFE_COPY_FNS, assessBinaryFile, isRunnableElf } from './binvuln.js';
import { resolveInsideRootfs } from './decompile.js';
import { sinkSeverity } from './exportreach.js';
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

/**
 * WHY a reachability question went unanswered. `blocked_by_platform` is the only proof state the vocabulary offers
 * for any of them, so the distinction lives here, on the RESULT — exactly as `dynprobe-run.ts` does it, and for
 * exactly the same reason: the three send an operator to three different places.
 *
 *  `platform`  this deployment cannot answer it. angr is not installed, or the probe ran and reported that it
 *              could not load this binary (unsupported architecture, loader refusal). Retrying changes nothing.
 *  `harness`   angr is here and the ATTEMPT broke: the probe crashed before writing, wrote nothing, or wrote
 *              output that would not parse. Nothing was learned about the deployment's reach; a retry may succeed.
 *  `request`   neither — the QUESTION could not be posed. There is no rootfs, the binary is not inside it, or the
 *              sink policy kept none of the names this call asked about.
 *
 * `request` is the one that earns this type. It is a defect in the CALLER, and it must never reach the findings
 * ledger as a capability limit: a `blocked_by_platform` row reading *"the deployment could not answer it"* is
 * precisely how `a20f2850`'s bug hid. W9 asked about `system/popen/execve` under the default `unsafe-copy` policy,
 * which kept nothing, and the resulting row blamed a deployment that had proven the very same sink reachable in
 * the very same binary eleven seconds earlier on the manual route. An honest-sounding row absorbed the blame, and
 * the only reason it was caught is that a human happened to have run the manual probe minutes before.
 */
export type SymReachBlockedBy = 'platform' | 'harness' | 'request';

/**
 * Which question was actually asked. `executable` is the symbolic search from the entry point this module opens
 * with; `library` is the control-flow question an object entered through its exports admits instead. They make
 * different claims and nothing may merge them — see the library rung below.
 */
export type SymReachMode = 'executable' | 'library';

export interface SymReachResult {
  available: boolean;
  reason: string;
  /** Present only when `available` is false. See `SymReachBlockedBy`. */
  blockedBy?: SymReachBlockedBy;
  binary: string;
  arch?: string;
  entry?: string;
  /**
   * Which RUNG answered. Absent on every result stored before the library rung existed, and absent is
   * `executable` — a stored result is JSON written by an older build and a field added to one is optional forever.
   */
  mode?: SymReachMode;
  /**
   * Present only in library mode: the export-start search's own outcomes and bounds. They are deliberately NOT in
   * `sinks`: a `reached` there is the entry-point claim that every reader — the panel badge, W9's summary, the
   * reproduction queue — treats as `static_confirmed` reachability from program input, and a path from an export
   * under unconstrained arguments is a weaker fact that must not be counted as one.
   */
  library?: LibraryReach;
  /** ENTRY-POINT outcomes only, and empty in library mode. See `library`. */
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

export function unavailable(binary: string, reason: string, blockedBy: SymReachBlockedBy = 'platform'): SymReachResult {
  return {
    available: false,
    reason,
    blockedBy,
    binary,
    sinks: [],
    // A malformed REQUEST writes no row, and that is the point of the discriminant. The ledger is read as *what is
    // true of this firmware*: coverage counts its rows, the narrative composes them, and they outlive the caller
    // that produced them. A row there stating a limit of the deployment that does not exist is worse than silence
    // — it is a false negative dressed as diligence. The reason travels on the result instead, where the run
    // ledger reports it as the failed request it is and an operator goes and fixes the caller.
    findings:
      blockedBy === 'request'
        ? []
        : [
            {
              kind: 'sink-reachability-blocked',
              title: `Symbolic reachability could not run on ${binary}`,
              severity: 'info',
              proofState: 'blocked_by_platform',
              // No `evidenceChannel`, deliberately. Nothing was symbolically executed — stamping this row
              // `symbolic_execution` would name a means that was never used, on the one row whose entire purpose
              // is to say that the question could not be answered.
              evidence: { binary, reason, blockedBy },
              rationale:
                blockedBy === 'harness'
                  ? 'The prover for this question is present and the attempt itself broke, so a retry may ' +
                    'succeed. Recorded either way, so the absence of a reachability verdict never reads as ' +
                    'evidence the sink is unreachable.'
                  : 'The reachability question was asked but the deployment could not answer it. This is ' +
                    'recorded so the absence of a reachability verdict is visible as a missing capability, not ' +
                    'mistaken for a clean result.',
            },
          ],
  };
}

/**
 * The DERIVED question posed against a binary that has no subject for it: the caller named no sinks, so they were
 * read off the binary itself, and it names none of the unbounded-copy functions the W5 sweep flags.
 *
 * This is an answer, and this module's own header has said so since it was written — *"a binary that imports none
 * of them is reported as having nothing to ask about, which is a real answer, not a failure"*. The code returned
 * `blocked_by_platform` anyway, so the contract and the behaviour disagreed and the row blamed a deployment that
 * was working perfectly. It is the same shape of bounded negative `credmatch` emits for a hash its candidates did
 * not reproduce, and it states the same two limits out loud: the criterion is a SYMBOL, so a statically linked or
 * inlined copy leaves nothing to read, and where there was no symbol table the evidence is the weaker string
 * superset — a name merely mentioned, not an import.
 */
export function nothingToAsk(binary: string, assessment: BinAssessment): SymReachResult {
  const source =
    assessment.symbolSource === 'dynsym'
      ? "the binary's dynamic symbol table"
      : 'the printable-string superset (this binary has no readable symbol table)';
  const reason = [
    `${binary} names none of the ${UNSAFE_COPY_FNS.length} unbounded-copy functions in ${source},`,
    'so the derived reachability question has no subject. Nothing was symbolically executed.',
  ].join(' ');
  return {
    available: true,
    reason,
    binary,
    sinks: [],
    asked: [],
    dropped: [],
    derivedSinks: true,
    findings: [
      {
        kind: 'sink-reachability-not-applicable',
        title: `No unbounded-copy sink to ask about in ${binary}`,
        severity: 'info',
        proofState: 'static_confirmed',
        // The claim is about the bytes — which symbols this file does and does not name — and nothing else.
        evidenceChannel: 'static_bytes',
        evidence: {
          binary,
          symbolSource: assessment.symbolSource,
          checked: UNSAFE_COPY_FNS,
          cmdExec: assessment.cmdExec,
        },
        rationale: [
          `${reason} This is a bounded negative about ${source} and nothing more.`,
          'It does NOT say the binary contains no unbounded copy: a statically linked or inlined `strcpy` has no',
          'symbol to name, and a sink that was never asked about has had its reachability tested by nothing.',
          assessment.cmdExec.length
            ? `Its symbols do name ${assessment.cmdExec.join(', ')} — command-exec sinks that can be asked about explicitly.`
            : '',
        ]
          .filter(Boolean)
          .join(' '),
      },
    ],
  };
}

/* ------------------------------------------------------------------------------------------------------------ *
 * The LIBRARY rung — the same symbolic question, started where a shared object can actually be entered.
 *
 * Everything above explores from the ENTRY POINT. A `.so` has none: it is entered through an exported function,
 * so the search was structurally unable to answer anything about one — and it ran anyway. Four
 * `symreach:lib/lib*.so` rows in this project's own ledger had to be RETIRED for exactly that, each having spent
 * a real angr budget to come back inconclusive about a question that was never posed.
 *
 * So a library target keeps the prover and changes the START STATE: `angr-reach.py` in `mode: 'library'` builds a
 * `call_state` at each exported function and asks the same bounded question from there.
 *
 * **What a `reached` means here, and it is NOT what it means above.** The arguments of an exported function are
 * unconstrained, so a path found from one proves the branch conditions along it can be satisfied by *some*
 * argument values — not that any caller can produce them, and not that an outsider's input reaches it. That is
 * strictly more than `exportreach`'s control-flow route (which checks no condition at all) and strictly less than
 * an entry-point `reached`, so the rows say so and the proof state stays `needs_runtime_reproduction`. The
 * `exportreach` lane is untouched and keeps writing its own rows under its own source: the two answer different
 * questions about the same object and neither replaces the other.
 *
 * **What a silence means, on two axes rather than one.** This search is bounded by wall-clock, steps and states
 * like the one above, AND by how many exports it starts from at all — a symbolic `call_state` at an export was
 * measured on a real module at 5925 steps and 123 seconds without reaching a target 0x51c inside the very
 * function being explored. So the result carries exports declared, exports considered, exports actually attempted
 * per sink, and how many of those searches ended by running out of states rather than out of budget. An object
 * that declares NO export is not a library with nothing reachable in it — there was nowhere to ask from, and that
 * comes back blocked.
 * ------------------------------------------------------------------------------------------------------------ */

/** Which rung a target belongs on. `not-elf` is the caller's problem; the routes refuse it before reaching here. */
export type ReachTargetKind = 'executable' | 'library' | 'not-elf';

const ET_DYN = 3;

/**
 * Pure: read the ELF header and say which rung this object belongs on.
 *
 * The axis is ET_DYN + `DT_SONAME`, and that predicate already exists — `isRunnableElf` in `binvuln.ts` settled it
 * after measuring that PT_INTERP alone does NOT separate a PIE from a library (uClibc builds `libc` with an
 * interpreter so it can print its own banner, and 37 `.so` files across the corpus were classed runnable on that
 * reasoning). This defers to it rather than growing a second copy of the dynamic-section walk that can drift.
 *
 * `e_type` is read here for one reason: `isRunnableElf` answers `false` for a file it cannot PARSE, and a
 * truncated ET_EXEC must not fall into library mode on a failed parse. Only ET_DYN is routed. ET_REL (a `.ko`) is
 * deliberately NOT: it stays on the executable path exactly as before, and the `exportreach` route owns it.
 */
export function classifyReachTarget(buf: Uint8Array): ReachTargetKind {
  if (buf.length < 64) return 'not-elf';
  if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)) return 'not-elf';
  if (buf[4] !== 1 && buf[4] !== 2) return 'not-elf';
  if (buf[5] !== 1 && buf[5] !== 2) return 'not-elf';
  const lo = buf[0x10] as number;
  const hi = buf[0x11] as number;
  const eType = buf[5] === 1 ? lo | (hi << 8) : hi | (lo << 8);
  if (eType !== ET_DYN) return 'executable';
  return isRunnableElf(buf) ? 'executable' : 'library';
}

/** The same 4 MB prefix bound `binvuln` reads binaries under — a dynamic section past it is not worth a full read. */
const CLASSIFY_READ_CAP = 4 * 1024 * 1024;

/** Classify a file on disk. Unreadable ⇒ `not-elf`, which leaves the existing executable path to report it. */
export function reachTargetKind(abs: string): ReachTargetKind {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const size = fs.fstatSync(fd).size;
      const buf = Buffer.allocUnsafe(Math.min(size, CLASSIFY_READ_CAP));
      fs.readSync(fd, buf, 0, buf.length, 0);
      return classifyReachTarget(buf);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return 'not-elf';
  }
}

/**
 * How many exported functions one run starts a search from.
 *
 * The second bound, and the one that does not exist on the executable rung: there is exactly one entry point, and
 * there are ~1600 exports in a C library. Sixteen is deliberately small — a slice of wall-clock too thin to take a
 * step proves nothing about the export it was spent on — and the count of exports NOT considered travels on every
 * result so the cap is never mistaken for the whole set.
 */
export const MAX_ENTRY_POINTS = 16;

/** One sink's outcome in library mode, plus the export accounting that makes its silence readable. */
export interface LibrarySinkResult {
  sink: string;
  outcome: SinkOutcome;
  addresses: string[];
  /** Exports this sink's search actually started from — never more than `entryPointsConsidered`. */
  entryPointsAttempted: number;
  /** Of those, the searches that ran out of STATES rather than out of budget, and pruned nothing on the way. */
  entryPointsCompleted: number;
  /** The exported function the path was found from, when one was. */
  reachedFrom?: string;
  steps: number;
  pruned: boolean;
  errors: number;
  reason?: string;
  path?: string[];
}

/** What the library rung did. Optional on the result, forever — a stored result may predate this rung. */
export interface LibraryReach {
  /** Exported functions the object declares. ZERO means there was nowhere to ask FROM, not that nothing is reachable. */
  entryPointsTotal: number;
  /** How many of them this run could consider, after `maxEntryPoints`. */
  entryPointsConsidered: number;
  maxEntryPoints: number;
  /** `dynsym-export`, or `global-symbol` where the object declares no dynamic exports at all. */
  entryPointSource?: string;
  entryPointsNamed?: string[];
  sinks: LibrarySinkResult[];
  budgetSeconds: number;
}

/** Pure: the JSON spec for a library run — the executable spec plus the start-state mode and its own bound. */
export function buildLibrarySpec(
  absBinary: string,
  sinks: string[],
  budgetSeconds = DEFAULT_BUDGET_SECONDS,
): ReachSpec & { mode: 'library'; maxEntryPoints: number } {
  return { ...buildSpec(absBinary, sinks, budgetSeconds), mode: 'library', maxEntryPoints: MAX_ENTRY_POINTS };
}

/**
 * Pure: normalize the probe's library JSON. Same rule as `parseReachOutput` — an outcome that cannot be read is an
 * inconclusive, never a sink that came back clean — plus one of its own: a missing export count reads as ZERO,
 * which routes to the blocked path rather than to a library that answered with no exports.
 */
export function parseLibraryReachOutput(raw: unknown): {
  ok: boolean;
  error?: string;
  arch?: string;
  library?: Omit<LibraryReach, 'budgetSeconds'>;
} {
  if (!raw || typeof raw !== 'object') return { ok: false, error: 'probe produced no JSON object' };
  const o = raw as Record<string, unknown>;
  if (o.ok !== true) return { ok: false, error: str(o.error, 'probe reported failure') };

  const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
  const rows = Array.isArray(o.results) ? o.results : [];
  const known: SinkOutcome[] = ['reached', 'not_reached_in_budget', 'absent', 'skipped'];
  const sinks: LibrarySinkResult[] = rows.map((r) => {
    const e = (r ?? {}) as Record<string, unknown>;
    const outcome = str(e.outcome);
    const result: LibrarySinkResult = {
      sink: str(e.sink, '?'),
      outcome: (known as string[]).includes(outcome) ? (outcome as SinkOutcome) : 'not_reached_in_budget',
      addresses: Array.isArray(e.addresses) ? e.addresses.map((a) => str(a)) : [],
      entryPointsAttempted: num(e.entryPointsAttempted),
      entryPointsCompleted: num(e.entryPointsCompleted),
      steps: num(e.steps),
      pruned: e.pruned === true,
      errors: num(e.errors),
    };
    if (!(known as string[]).includes(outcome)) {
      result.reason = `unrecognised probe outcome '${outcome}' — treated as inconclusive`;
    } else if (typeof e.reason === 'string') {
      result.reason = e.reason;
    }
    if (typeof e.reachedFrom === 'string' && e.reachedFrom) result.reachedFrom = e.reachedFrom;
    if (Array.isArray(e.path)) result.path = e.path.map((a) => str(a));
    return result;
  });

  const entryPointsTotal = num(o.entryPointsTotal);
  return {
    ok: true,
    ...(typeof o.arch === 'string' ? { arch: o.arch } : {}),
    library: {
      entryPointsTotal,
      entryPointsConsidered: num(o.entryPointsConsidered),
      maxEntryPoints: typeof o.maxEntryPoints === 'number' ? o.maxEntryPoints : MAX_ENTRY_POINTS,
      ...(typeof o.entryPointSource === 'string' ? { entryPointSource: o.entryPointSource } : {}),
      ...(Array.isArray(o.entryPointsNamed) ? { entryPointsNamed: o.entryPointsNamed.map((n) => str(n)) } : {}),
      sinks,
    },
  };
}

/**
 * Pure: the sentence stating what the library run covered. Both bounds are in it, with both counts, because the
 * export cap is the one a reader cannot infer from anything else on the result.
 */
export function summariseLibraryReach(binary: string, lib: LibraryReach): string {
  const reached = lib.sinks.filter((s) => s.outcome === 'reached');
  const unconsidered = Math.max(0, lib.entryPointsTotal - lib.entryPointsConsidered);
  const capNote = unconsidered
    ? [
        `${lib.entryPointsConsidered} of its ${lib.entryPointsTotal} exported entry point(s) were considered`,
        `(per-run cap ${lib.maxEntryPoints}); the other ${unconsidered} were never started from, so nothing`,
        'was asked about them.',
      ].join(' ')
    : `all ${lib.entryPointsTotal} of its exported entry point(s) were considered.`;
  return [
    `${binary} is a shared object: explored symbolically from its EXPORTS, not from an entry point it does not`,
    `have. ${reached.length}/${lib.sinks.length} sink(s) reached — ${capNote}`,
    'A path from an export holds under unconstrained arguments, which is weaker than reachability from program',
    'input, and a sink not reached is inconclusive rather than unreachable.',
  ].join(' ');
}

/**
 * Pure: the ledger rows for a library run.
 *
 * A `reached` sink is a real, checkable upgrade over "this library imports strcpy" and it is deliberately NOT
 * `static_confirmed`: what was proven is a satisfiable path from an exported function under arguments nothing
 * constrains, and whether a caller on this device can produce them is exactly the unproven part. Every other
 * outcome composes one aggregate note carrying the two bounds, so a library that was barely looked at cannot read
 * like one that was cleared.
 */
export function buildLibraryFindings(binary: string, lib: LibraryReach): FindingDraft[] {
  const drafts: FindingDraft[] = [];

  for (const s of lib.sinks.filter((x) => x.outcome === 'reached')) {
    drafts.push({
      kind: 'library-sink-reachable',
      title: `${s.sink} in ${binary} is reachable from the exported function ${s.reachedFrom ?? '(unnamed)'}`,
      severity: sinkSeverity(s.sink),
      // NOT static_confirmed. The path is real; the arguments that walk it were never shown to be producible.
      proofState: 'needs_runtime_reproduction',
      evidenceChannel: 'symbolic_execution',
      evidence: {
        binary,
        sink: s.sink,
        addresses: s.addresses,
        reachedFrom: s.reachedFrom ?? null,
        steps: s.steps,
        entryPointsAttempted: s.entryPointsAttempted,
        entryPointsTotal: lib.entryPointsTotal,
        ...(s.path ? { pathTail: s.path } : {}),
      },
      rationale: [
        `Symbolic execution started at the exported function ${s.reachedFrom ?? '(unnamed)'} and found a path to`,
        `the ${s.sink} call site whose branch conditions are satisfiable together. This library has no entry point`,
        'of its own, so an export is the strongest place to start from — and the claim is bounded there: the',
        "export's arguments are UNCONSTRAINED, so nothing here shows that a caller on this device can supply the",
        'values that walk this path. That is why this is a lead and not a confirmed reachability from input, and',
        'it is strictly stronger than a control-flow route, which checks no condition at all.',
      ].join(' '),
    });
  }

  const unresolved = lib.sinks.filter((s) => s.outcome === 'not_reached_in_budget' || s.outcome === 'skipped');
  if (unresolved.length > 0) {
    const attempted = unresolved.reduce((n, s) => n + s.entryPointsAttempted, 0);
    const completed = unresolved.reduce((n, s) => n + s.entryPointsCompleted, 0);
    const toolErrors = unresolved.reduce((n, s) => n + s.errors, 0);
    const pruned = unresolved.some((s) => s.pruned);
    const unconsidered = Math.max(0, lib.entryPointsTotal - lib.entryPointsConsidered);
    drafts.push({
      kind: 'library-sink-reachability-inconclusive',
      title: `Reachability of ${unresolved.length} sink(s) in ${binary} from its exports is unresolved`,
      severity: 'info',
      proofState: 'needs_runtime_reproduction',
      evidenceChannel: 'symbolic_execution',
      evidence: {
        binary,
        sinks: unresolved.map((s) => s.sink),
        entryPointsTotal: lib.entryPointsTotal,
        entryPointsConsidered: lib.entryPointsConsidered,
        entryPointsNotConsidered: unconsidered,
        entryPointSearchesAttempted: attempted,
        entryPointSearchesCompleted: completed,
        statesPruned: pruned,
        toolErrors,
        budgetSeconds: lib.budgetSeconds,
        detail: unresolved.map((s) => `${s.sink} (${s.reason ?? 'budget spent'})`).join('; '),
      },
      rationale: [
        `The bounded search started from ${attempted} export search(es) for these sinks and did not reach them.`,
        `Only ${completed} of those searches ran out of states inside their bounds; the rest ran out of budget,`,
        unconsidered ? `and ${unconsidered} of this object's exports were never started from at all.` : '',
        pruned ? 'Active states were pruned to stay inside the memory bound, narrowing the search further.' : '',
        toolErrors ? `${toolErrors} state(s) were lost to angr-internal errors — paths never explored.` : '',
        'None of that is evidence the sinks are unreachable: from an export the argument space is unconstrained,',
        'so the search fans out and rarely converges. The candidates keep their needs-reproduction state; a larger',
        'budget, more exports, or the control-flow route the `exportreach` lane reports are the next rungs.',
      ]
        .filter(Boolean)
        .join(' '),
    });
  }

  return drafts;
}

/**
 * The library question asked of an object that declares no export to ask it from.
 *
 * `blocked_by_platform`, not an answer: a stripped object whose export table is gone and a library with no
 * reachable sink look identical from here, and reporting the second would be a bound read as a result. Measured
 * context for how common this is: 357 of the corpus's 791 `.so` files carry no section headers at all.
 */
export function noEntryPoints(binary: string, lib: LibraryReach): SymReachResult {
  const reason = [
    `${binary} is a shared object that declares NO exported function, so there was nowhere to start a symbolic`,
    'search FROM. No sink was examined. This is a failure to pose the question here, not a library free of',
    'reachable sinks.',
  ].join(' ');
  return {
    ...unavailable(binary, reason, 'platform'),
    mode: 'library',
    library: lib,
    budgetSeconds: lib.budgetSeconds,
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
  // A caller reaching here without a rootfs asked a question it had no subject for: W9 skips a stage that lacks
  // one and the route gate refuses first, so this is a caller defect, not a limit of this deployment.
  if (!rootfsPath) return unavailable(binary, 'No extracted rootfs.', 'request');
  if (!(await isToolAvailable('angr'))) {
    handle.log('angr not available — rebuild the tools base with the optional angr layer to answer reachability.');
    return unavailable(binary, 'angr not installed in this deployment');
  }

  const abs = resolveInsideRootfs(rootfsPath, binary);
  if (!abs) return unavailable(binary, 'binary not found inside the rootfs', 'request');

  // No sinks named → read them off the binary itself. This is the same symbol extraction the W5 sweep uses, so a
  // derived question asks exactly what the sweep would have flagged.
  const derivedSinks = sinks.length === 0;
  const assessment = derivedSinks ? assessBinaryFile(abs, binary) : null;
  const requested = assessment ? assessment.unsafeCopy : sinks;
  const { asked, dropped } = pickSinks(requested, derivedSinks ? 'unsafe-copy' : policy);
  if (asked.length === 0) {
    // Two different situations, and only one of them is anybody's fault. Derived: the binary has no unbounded-copy
    // symbol, which ANSWERS the question. Named: the caller handed sinks and the policy discarded every one of
    // them, which is the caller asking with a filter that deletes its own question — so the reason names the
    // policy and the names it dropped, rather than the deployment.
    if (assessment) return nothingToAsk(binary, assessment);
    return unavailable(
      binary,
      `no sink to ask about — the '${policy}' policy kept none of the ${requested.length} name(s) requested ` +
        `(${requested.join('/')}). Nothing was asked, so nothing about this deployment was learned.`,
      'request',
    );
  }

  // WHERE the search starts is the only thing the target class changes. Everything above — derivation, the sink
  // policy, the per-run cap — is the same question; everything below is the same prover under the same budget.
  const mode: SymReachMode = reachTargetKind(abs) === 'library' ? 'library' : 'executable';

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-angr-'));
  const specPath = path.join(workDir, 'spec.json');
  const outPath = path.join(workDir, 'out.json');

  try {
    const spec =
      mode === 'library' ? buildLibrarySpec(abs, asked, budgetSeconds) : buildSpec(abs, asked, budgetSeconds);
    fs.writeFileSync(specPath, JSON.stringify(spec));
    handle.log(
      mode === 'library'
        ? `angr: ${binary} is a shared object — asking reachability of ${asked.join('/')} from up to ` +
            `${MAX_ENTRY_POINTS} exported function(s), since it has no entry point (budget ${budgetSeconds}s).`
        : `angr: asking reachability of ${asked.join('/')} in ${binary} (budget ${budgetSeconds}s).`,
    );
    try {
      // Hard kill a little past the probe's own budget — the probe self-limits, this is the backstop.
      await execFileAsync(angrPython(), [probeScript(), specPath, outPath], {
        timeout: (budgetSeconds + 60) * 1000,
        maxBuffer: 8 * 1024 * 1024,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // The probe writes its JSON before exiting non-zero in most failure modes; only give up if it wrote nothing.
      // The line between `harness` and `platform` for everything below: **the probe never answered ⇒ harness; the
      // probe answered "I cannot" ⇒ platform.** A crash before it wrote, no output, unparsable output — those are
      // the attempt breaking, and a retry may well clear them. A probe that ran to completion and reported failure
      // is telling us angr could not load THIS binary here (unsupported arch, loader refusal), which no retry
      // fixes. Drawing the line by what the probe managed to say needs no string-matching on its error text.
      if (!fs.existsSync(outPath)) {
        handle.log(`angr probe failed: ${message}`);
        return unavailable(binary, `angr probe failed: ${message}`, 'harness');
      }
    }

    if (!fs.existsSync(outPath)) return unavailable(binary, 'angr probe produced no output', 'harness');
    let raw: unknown;
    try {
      raw = JSON.parse(fs.readFileSync(outPath, 'utf8'));
    } catch (err) {
      return unavailable(
        binary,
        `could not parse angr output: ${err instanceof Error ? err.message : String(err)}`,
        'harness',
      );
    }

    if (mode === 'library') {
      const lib = parseLibraryReachOutput(raw);
      if (!lib.ok || !lib.library) return unavailable(binary, lib.error ?? 'angr probe reported failure');
      const library: LibraryReach = { ...lib.library, budgetSeconds };
      const shared = {
        binary,
        ...(lib.arch ? { arch: lib.arch } : {}),
        mode: 'library' as const,
        library,
        asked,
        dropped,
        derivedSinks,
        budgetSeconds,
      };
      // Nowhere to start from is not a library with nothing in it — see `noEntryPoints`.
      if (library.entryPointsTotal === 0) {
        const blocked = { ...noEntryPoints(binary, library), ...shared };
        handle.log(blocked.reason);
        return blocked;
      }
      const reason = summariseLibraryReach(binary, library);
      handle.log(reason);
      return { ...shared, available: true, reason, sinks: [], findings: buildLibraryFindings(binary, library) };
    }

    const parsed = parseReachOutput(raw);
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
      mode: 'executable',
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
