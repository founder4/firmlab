/**
 * What one execution DID — the pure half of the run ledger.
 *
 * Every provider already persists a job row, and every route then exposed exactly one of them:
 * `listJobs(id).find(j => j.kind === … && j.status === 'done')`, twenty times over. That returns the most recent
 * run and silently discards the rest, so probing three binaries left an operator looking at a single result with
 * no indication that two others had happened, what they were aimed at, or what they returned. The history existed
 * in the database the whole time; nothing read it back.
 *
 * This module turns a stored job into a line an operator can act on, and it is deliberately store-free so the
 * per-kind reading of each result stays unit-testable (vitest cannot resolve `node:sqlite`, so anything importing
 * `store.js` cannot be loaded by a test at all).
 *
 * **The outcome vocabulary is the proof-state discipline, not a status.** A job's `status` says whether the
 * process finished; it says nothing about what was learned, and conflating the two is how "done" comes to read as
 * "clean". A dynamic probe that completes without reaching its sink is `done` and has proven nothing. A probe
 * blocked because the sandbox lacks `/dev/nvram` is also `done`, and the question was asked and could not be
 * answered — which is not a negative result. So each run carries BOTH: `status` for the process, `outcome` for the
 * epistemics, and they are never collapsed.
 */

/** The subset of a persisted job this module reads. Structural on purpose — no import from the store. */
export interface RunInput {
  id: string;
  kind: string;
  status: string;
  createdAt: number;
  updatedAt: number;
  params: string | null;
  resultJson: string | null;
  error: string | null;
}

/**
 * How to read what came back — never how the process exited.
 *
 * `proven`   the run established a fact about the target (a reproduced crash, a reached sink, an injection echoed)
 * `lead`     something worth pursuing was observed; nothing was proven
 * `empty`    the run completed and found nothing — for THIS input, THIS budget, THIS question
 * `blocked`  the question was asked and this deployment could not answer it. NOT a negative
 * `failed`   the harness broke; no statement about the target either way
 * `running`  still going
 */
export type RunOutcome = 'proven' | 'lead' | 'empty' | 'blocked' | 'failed' | 'running';

export interface RunSummary {
  jobId: string;
  kind: string;
  status: string;
  startedAt: number;
  finishedAt: number | null;
  /** What this run was aimed at — a binary path, a URL. Null when the run is image-wide rather than targeted. */
  target: string | null;
  /** The specific question put to that target (a sink, a sink set, a harness). Null when the kind has none. */
  question: string | null;
  /** One line stating what came back. Never empty — a run with no result says exactly that. */
  headline: string;
  outcome: RunOutcome;
  /** The bound this run operated under, when it had one worth stating (a budget, a pattern length, a timeout). */
  bound: string | null;
}

function parse<T>(json: string | null): T | null {
  if (!json) return null;
  try {
    return JSON.parse(json) as T;
  } catch {
    return null;
  }
}

/** Human-facing wording for each dynamic-probe verdict, plus how much it is allowed to claim. */
const DYNPROBE: Record<string, { outcome: RunOutcome; text: string }> = {
  crash_input_controlled: { outcome: 'proven', text: 'Crash, and the input controls the return address' },
  crash: { outcome: 'proven', text: 'Crashed, but the faulting address is not input bytes' },
  sink_executed: { outcome: 'lead', text: 'The sink executed; the program did not fault' },
  ran_clean: { outcome: 'empty', text: 'Ran without reaching the sink and without faulting' },
  emulation_artifact: { outcome: 'blocked', text: 'The sandbox came up short — nothing was learned' },
  not_attached: { outcome: 'failed', text: 'gdb never attached; nothing was observed' },
};

/** Wording for each symbolic-reachability outcome. `not reached` is a spent budget, never a proof of absence. */
const SYMREACH: Record<string, { outcome: RunOutcome; text: string }> = {
  reached: { outcome: 'proven', text: 'reachable from the entry point' },
  not_reached_in_budget: { outcome: 'empty', text: 'not reached before the budget expired — not proven unreachable' },
  absent: { outcome: 'empty', text: 'not imported by this binary' },
  error: { outcome: 'failed', text: 'the prover failed' },
};

/**
 * The image-wide providers driven by the boot/platform workbench. They all persist the same small contract even
 * though their detailed result shapes differ: availability, a reader-facing reason and zero or more findings.
 * Keeping that contract here prevents ten completed runs falling through to the content-free default summary.
 */
const DEEP_ANALYSIS_KINDS = new Set([
  'uboot',
  'devicetree',
  'kernel',
  'fsaudit',
  'certs',
  'services',
  'updatepath',
  'compmap',
  'rtos',
  'fcc',
]);

function conciseReason(value: unknown, fallback: string): string {
  const reason = typeof value === 'string' && value.trim() ? value.trim() : fallback;
  const first = reason.split(/(?<=\.)\s/)[0] ?? reason;
  return first.length > 220 ? `${first.slice(0, 219)}…` : first;
}

function rows(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value)
    ? value.filter((item): item is Record<string, unknown> => item !== null && typeof item === 'object')
    : [];
}

/**
 * Read what the findings establish before looking at provider-specific inventory. A provider can establish a
 * useful fact without emitting a security finding (one parsed U-Boot environment is the worked example), so
 * `null` deliberately means "the findings do not decide" rather than `empty`.
 */
function findingsOutcome(result: Record<string, unknown>): RunOutcome | null {
  if (result.available === false) return 'blocked';
  const findings = rows(result.findings);
  if (findings.length === 0) return null;
  const states = findings
    .map((finding) => finding.proofState)
    .filter((state): state is string => typeof state === 'string');
  if (states.some((state) => ['static_confirmed', 'confirmed_in_emulation', 'confirmed_full_system'].includes(state))) {
    return 'proven';
  }
  if (states.length > 0 && states.every((state) => state.startsWith('blocked_'))) return 'blocked';
  return 'lead';
}

/** A stored provider result can contain useful measured inventory even when it emitted no security finding. */
function deepAnalysisOutcome(kind: string, result: Record<string, unknown>): RunOutcome {
  const fromFindings = findingsOutcome(result);
  if (fromFindings) return fromFindings;

  switch (kind) {
    case 'uboot':
    case 'devicetree':
      return result.found === true ? 'proven' : 'empty';
    case 'kernel':
      if (result.located === false) return 'blocked';
      return result.located === true || typeof result.version === 'string' ? 'proven' : 'empty';
    case 'certs':
      return (typeof result.certCount === 'number' && result.certCount > 0) || rows(result.certs).length > 0
        ? 'proven'
        : 'empty';
    case 'services':
      return rows(result.services).length > 0 ? 'proven' : 'empty';
    case 'updatepath': {
      const integrity =
        result.imageIntegrity !== null && typeof result.imageIntegrity === 'object'
          ? (result.imageIntegrity as Record<string, unknown>)
          : null;
      return rows(result.updaters).length > 0 || rows(integrity?.items).length > 0 ? 'proven' : 'empty';
    }
    case 'compmap':
      return typeof result.binaryCount === 'number' && result.binaryCount > 0 ? 'proven' : 'empty';
    case 'rtos':
      return result.isCortexM === true || (typeof result.rtosKernel === 'string' && result.rtosKernel.trim() !== '')
        ? 'proven'
        : 'empty';
    case 'fcc':
      return rows(result.links).length > 0 || (Array.isArray(result.ids) && result.ids.length > 0) ? 'proven' : 'empty';
    default:
      return 'empty';
  }
}

function deepAnalysisHeadline(kind: string, result: Record<string, unknown>): string {
  const fallback = `${kind} completed without a result summary`;
  if (kind === 'rtos' && typeof result.rtosKernel === 'string' && result.rtosKernel.trim()) {
    const reason = conciseReason(result.reason, fallback);
    const detected = `RTOS kernel detected: ${result.rtosKernel.trim()}.`;
    const combined = `${detected} ${reason}`;
    return combined.length > 220 ? `${combined.slice(0, 219)}…` : combined;
  }
  return conciseReason(result.reason, fallback);
}

/**
 * Pure: read one stored job into a line.
 *
 * Each kind gets its own reading because each result means something different, and a generic
 * "done / N bytes of JSON" would be exactly the uninformative row this exists to replace. Kinds with no special
 * reading fall through to a shape that still states the target and refuses to imply more than it knows.
 */
export function summarizeRun(job: RunInput): RunSummary {
  const params = parse<Record<string, unknown>>(job.params) ?? {};
  const result = parse<Record<string, unknown>>(job.resultJson);
  const base = {
    jobId: job.id,
    kind: job.kind,
    status: job.status,
    startedAt: job.createdAt,
    finishedAt: job.status === 'done' || job.status === 'error' ? job.updatedAt : null,
    target:
      typeof params.binary === 'string' ? params.binary : typeof params.target === 'string' ? params.target : null,
    question: null as string | null,
    bound: null as string | null,
  };

  if (job.status === 'running' || job.status === 'queued') {
    return { ...base, outcome: 'running', headline: job.status === 'queued' ? 'Queued' : 'Running…' };
  }
  if (job.status === 'error') {
    return { ...base, outcome: 'failed', headline: job.error?.slice(0, 200) || 'Failed with no message' };
  }
  // `done` with nothing stored is its own case: the process finished and left no result to read. Reporting that
  // as an empty finding would be the conflation this module exists to prevent.
  if (!result) return { ...base, outcome: 'failed', headline: 'Finished but stored no result' };

  if (DEEP_ANALYSIS_KINDS.has(job.kind)) {
    return {
      ...base,
      outcome: deepAnalysisOutcome(job.kind, result),
      headline: deepAnalysisHeadline(job.kind, result),
    };
  }

  switch (job.kind) {
    case 'dynprobe': {
      const probe = (result.probe ?? {}) as { verdict?: string; controlOffset?: { offset?: number } };
      const sink = typeof params.sink === 'string' ? params.sink : null;
      const known = DYNPROBE[probe.verdict ?? ''];
      const offset = probe.controlOffset?.offset;
      const len = typeof params.patternLength === 'number' ? params.patternLength : null;
      if (result.available === false) {
        // `available: false` covers two situations that lead an operator to opposite next steps: this deployment
        // cannot do it at all (retrying changes nothing) versus the tools are here and the attempt broke (a retry
        // may well succeed). The provider now says which; older rows carry no `blockedBy` and stay `blocked`,
        // which is the conservative reading — it never claims a negative either way.
        const harness = result.blockedBy === 'harness';
        return {
          ...base,
          question: sink,
          outcome: harness ? 'failed' : 'blocked',
          headline: String(result.reason ?? 'The probe could not run here'),
          bound: null,
        };
      }
      return {
        ...base,
        question: sink,
        outcome: known?.outcome ?? 'empty',
        headline: known ? `${known.text}${offset !== undefined ? ` (offset ${offset})` : ''}` : 'Ran',
        bound: len ? `${len}-byte cyclic input` : null,
      };
    }

    case 'symreach': {
      const sinks = Array.isArray(result.sinks) ? (result.sinks as { sink?: string; outcome?: string }[]) : [];
      if (result.available === false) {
        // Three reasons, three next steps — see `SymReachBlockedBy`. Only `platform` is a capability limit and
        // stays `blocked`; `harness` (the attempt broke) and `request` (the question could not be posed) are
        // failures a corrected retry clears, and reporting either as `blocked` sends the operator off to fix a
        // deployment that is fine. Rows stored by an older build carry no `blockedBy` and stay `blocked`, which is
        // the conservative reading: it claims no negative either way.
        const platform = result.blockedBy === undefined || result.blockedBy === 'platform';
        return {
          ...base,
          outcome: platform ? 'blocked' : 'failed',
          headline: String(result.reason ?? 'The prover is unavailable'),
        };
      }
      const reached = sinks.filter((s) => s.outcome === 'reached');
      const names =
        sinks
          .map((s) => s.sink)
          .filter(Boolean)
          .join(', ') || null;
      const budget = typeof params.budgetSeconds === 'number' ? `${params.budgetSeconds}s budget` : null;
      // Ran, no sink. The provider's own sentence says WHY — for a derived question against a binary that names no
      // unbounded copy it is a bounded negative, not a caller who forgot to ask, and the generic headline said the
      // opposite of the row the same run wrote.
      if (sinks.length === 0)
        return {
          ...base,
          question: names,
          outcome: 'empty',
          headline: String(result.reason ?? 'No sink was asked about').slice(0, 200),
          bound: budget,
        };
      if (reached.length > 0) {
        const one = reached[0] as { sink?: string };
        return {
          ...base,
          question: names,
          outcome: 'proven',
          headline:
            reached.length === 1
              ? `${one.sink} is ${SYMREACH.reached?.text}`
              : `${reached.length} of ${sinks.length} sinks reachable from the entry point`,
          bound: budget,
        };
      }
      const first = sinks[0] as { sink?: string; outcome?: string };
      const known = SYMREACH[first.outcome ?? ''];
      return {
        ...base,
        question: names,
        outcome: known?.outcome ?? 'empty',
        headline: `${first.sink ?? 'the sink'} — ${known?.text ?? 'no answer'}`,
        bound: budget,
      };
    }

    case 'webprobe': {
      const findings = Array.isArray(result.findings) ? result.findings : [];
      if (result.available === false) {
        return {
          ...base,
          target: (result.target as string) ?? base.target,
          outcome: 'blocked',
          headline: String(result.reason ?? 'Could not probe'),
        };
      }
      const reqs = typeof result.requests === 'number' ? `${result.requests} requests` : null;
      return {
        ...base,
        target: (result.target as string) ?? base.target,
        outcome: findings.length > 0 ? 'proven' : 'empty',
        headline:
          findings.length > 0
            ? `${findings.length} injection point(s) reproduced against the booted service`
            : 'No injection reproduced — for the points this probe knows how to test',
        bound: reqs,
      };
    }

    case 'fuzz': {
      if (result.available === false) {
        return { ...base, outcome: 'blocked', headline: String(result.reason ?? 'The fuzzer is unavailable') };
      }
      const crashes = typeof result.crashes === 'number' ? result.crashes : 0;
      const secs = typeof result.seconds === 'number' ? `${result.seconds}s` : null;
      const harness = typeof result.harness === 'string' ? result.harness : null;
      return {
        ...base,
        question: harness ? `${harness} harness` : null,
        outcome: crashes > 0 ? 'proven' : 'empty',
        headline: crashes > 0 ? `${crashes} crashing input(s)` : 'No crash in this budget — which is not "no bug"',
        bound: secs,
      };
    }

    case 'decompile': {
      if (result.available === false) {
        return { ...base, outcome: 'blocked', headline: String(result.reason ?? 'The decompiler is unavailable') };
      }
      const fns = typeof result.functionCount === 'number' ? result.functionCount : 0;
      const imports = Array.isArray(result.imports) ? result.imports.length : 0;
      return { ...base, outcome: 'lead', headline: `${fns} functions, ${imports} imports catalogued`, bound: null };
    }

    case 'ghidra': {
      // The counterpart of `buildGhidraFindings` refusing to write a findings row for a successful run: what the
      // decompilation DID belongs here, in the ledger whose column asks "what came of it", and not in a dossier of
      // claims about the firmware.
      if (result.available === false) {
        return { ...base, outcome: 'blocked', headline: String(result.reason ?? 'The decompiler is unavailable') };
      }
      const fns = typeof result.functionCount === 'number' ? result.functionCount : 0;
      return {
        ...base,
        outcome: 'lead',
        headline:
          fns > 0 ? `${fns} function(s) decompiled — pseudocode available for review` : 'Ran, decompiled no functions',
        bound: null,
      };
    }

    case 'renode': {
      if (result.available === false) {
        return { ...base, outcome: 'blocked', headline: String(result.reason ?? 'Renode is unavailable') };
      }
      const platform = typeof result.platform === 'string' ? result.platform : null;
      return {
        ...base,
        question: platform,
        outcome: result.booted === true ? 'proven' : result.ran === true ? 'empty' : 'blocked',
        headline:
          result.booted === true
            ? `Booted under Renode${platform ? ` on ${platform}` : ''}`
            : String(result.reason ?? 'Did not boot'),
        bound: null,
      };
    }

    case 'emulate': {
      // THREE rungs share this job kind — user-mode, chroot-service and full-system — and this case used to read
      // all of them as the cheapest one. A boot that returned `confirmed_full_system` rendered in the run ledger
      // as `lead` / "Ran under user-mode emulation, exit ?", i.e. the strongest result the ladder can produce,
      // described as the weakest rung failing to report an exit code. The two system rungs are told apart by the
      // fields only they carry, and where they carry a proof state the runner already DECIDED it — from the boot
      // markers and the ports that answered — so this reads it rather than re-deriving one from `ran`/`exitCode`.
      const strategy = typeof result.strategy === 'string' ? result.strategy : null;
      const proofState = typeof result.proofState === 'string' ? result.proofState : null;
      if (strategy !== null && proofState !== null) {
        const openPorts = Array.isArray(result.open) ? result.open.length : 0;
        const rung = strategy === 'full-system' ? 'Full-system boot' : 'Chroot service';
        const outcome: RunOutcome =
          proofState === 'confirmed_full_system' || proofState === 'confirmed_in_emulation'
            ? 'proven'
            : proofState.startsWith('blocked')
              ? 'blocked'
              : result.ran === true
                ? 'empty'
                : 'blocked';
        // The runner's `reason` is a paragraph written for a reader; the ledger wants its first sentence.
        const reason = typeof result.reason === 'string' ? result.reason : '';
        const firstSentence = reason.split(/(?<=\.)\s/)[0] ?? '';
        const headline =
          outcome === 'proven'
            ? `${rung} confirmed${openPorts > 0 ? `, ${openPorts} forwarded port(s) answered` : ' — nothing answered on a forwarded port'}`
            : firstSentence || `${rung}: ${proofState}`;
        return {
          ...base,
          question: strategy,
          outcome,
          headline: headline.length > 160 ? `${headline.slice(0, 159)}…` : headline,
          bound: null,
        };
      }
      const ran = result.ran === true;
      const timedOut = result.timedOut === true;
      return {
        ...base,
        outcome: ran ? (timedOut ? 'empty' : 'lead') : 'blocked',
        headline: ran
          ? timedOut
            ? 'Ran until the timeout — no exit observed'
            : `Ran under user-mode emulation, exit ${result.exitCode ?? '?'}`
          : 'Did not run',
        bound: null,
      };
    }

    default: {
      // An unknown kind still gets an honest row: it happened, it finished, and this module does not pretend to
      // read its result. Better than inventing a summary the caller might trust.
      return { ...base, outcome: 'lead', headline: 'Completed — open the run for its full result' };
    }
  }
}

/**
 * Pure: group runs by what they were aimed at, newest first within each target.
 *
 * The test bench is organised by TARGET rather than by tool, because that is the question an operator actually
 * has: "what do I know about this binary", not "what did the prober do lately". Runs with no target (image-wide
 * jobs like extraction) collect under a null key so they are never silently dropped.
 */
export function groupRunsByTarget(runs: RunSummary[]): { target: string | null; runs: RunSummary[] }[] {
  const byTarget = new Map<string, RunSummary[]>();
  for (const r of runs) {
    // A NUL sentinel for the image-wide bucket: it cannot occur in a filesystem path, so it can never collide with
    // a real target the way a plausible string like 'image' could. Written as the ESCAPE and never as the byte —
    // a literal NUL passes tsc, biome and vitest silently while `file` calls the source `data` and grep skips it
    // without saying so, which is how a correct change comes to look like it was never made.
    const key = r.target ?? '\u0000image';
    const list = byTarget.get(key);
    if (list) list.push(r);
    else byTarget.set(key, [r]);
  }
  return [...byTarget.entries()]
    .map(([key, list]) => ({
      target: key === '\u0000image' ? null : key,
      runs: [...list].sort((a, b) => b.startedAt - a.startedAt),
    }))
    .sort((a, b) => {
      // Image-wide runs last: they are context, not the thing being investigated.
      if (a.target === null) return 1;
      if (b.target === null) return -1;
      return (b.runs[0]?.startedAt ?? 0) - (a.runs[0]?.startedAt ?? 0);
    });
}
