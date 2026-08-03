/**
 * agents — the console over the autonomous engine, at workspace level. English source of truth.
 *
 * **The unit here is a RUN, not an image.** That is the whole re-architecture: the old screen listed images and
 * every click left for `/image/:id/…`, which is the static-analysis shell — so opening a result dropped the reader
 * into another section, under a pipeline strip about a different activity, with no way back to the console they
 * came from. A run now opens INSIDE this section, and leaving for the image is a labelled choice.
 *
 * **A row states an outcome, not a status.** `done` says a process finished and says nothing about what was
 * learned, and `725 findings` is the exact number the coverage discipline exists to qualify. So a scan row reads
 * "12 of 15 workers · 725 findings" and names the ones that did NOT complete — a total drawn from an incomplete
 * plan is the misreading this workbench is built to prevent, and a console that hides it is where that misreading
 * starts.
 *
 * Run STATUSES (`queued`, `running`, `awaiting_approval`, `error`, `halted`) are job values that cross the API and
 * land in SQLite, so they render verbatim; only the words around them are localised. Filenames, worker ids and
 * provider/model names are records too.
 */
export const agents = {
  eyebrow: 'Autonomy',
  title: 'Agents',
  desc: 'Autonomous runs across every target. Each one records what it planned, what it actually executed and what it could not answer — the engine drives the pipeline, it never invents findings.',

  /** The two engines as one compact strip, rather than two panels of prose nobody reads twice. */
  engine: {
    scanName: 'Autonomous scan',
    scanKind: 'deterministic',
    scanReady: 'always available',
    scanWhat: 'Plans a class-routed worker chain, runs it end to end, re-plans from leads, and reports its gaps.',
    agentName: 'Conscious agent',
    agentOff: 'off',
    agentWhat:
      'LLM at the judgment nodes only, behind a human approval gate and a governor capping steps, tokens, cost and time.',
    /** The env var keeps its name in every language — it is what the operator has to type. */
    agentDisabled: 'Set FIRMLAB_AGENT=1 and an API key to enable it. The deterministic scan runs without either.',
  },

  runs: {
    title: 'Runs',
    live: (n: number) => `${n} live`,
    refresh: 'Refresh',
    emptyTitle: 'Nothing has been run yet',
    emptyBody: 'Start an autonomous scan on a ready target below. Runs appear here and open into their own trace.',
    colTarget: 'Target',
    colOutcome: 'What came of it',
    colWhen: 'When',
    kindScan: 'scan',
    kindAgent: 'agent',

    /** A scan's outcome, in the order a reader needs it: how much of the plan ran, THEN what it found. */
    workers: (ran: number, total: number) => `${ran} of ${total} workers`,
    findings: (n: number) => `${n} findings`,
    /** The half a bare total hides. Never omitted when it is non-zero. */
    incomplete: (n: number) => `${n} did not complete`,
    /** A run waiting on a person is not a run in progress; it is a run that needs the operator. */
    needsYou: 'waiting for your approval',
    /** While a run has produced no result, so an empty outcome cell never reads as "it found nothing". */
    pending: 'no result recorded yet',

    /**
     * An agent session's outcome — the half of this column that used to read `done · 7 steps` for every finished
     * session, which is the same word by construction and therefore no word at all.
     *
     * **The verdict WORD is not here.** It comes from `shell.runHistory.outcome`, the run ledger's own vocabulary,
     * because a console with a second set of six words for the same six states is how two vocabularies for one
     * thing begin. What lives here is the sentence saying what THIS session established, and three of them carry
     * the whole honesty of the column: a session that never reached a target could not ASK its question — it did
     * not fail and it did not pass; a zero-day node that formed nothing formed nothing *for that scaffold*, which
     * is a result and not a clean bill of health; and a candidate is a lead written `needs_runtime_reproduction`,
     * never a proven bug. None of these three may be softened in translation.
     */
    agent: {
      confirmed: 'Reproduced under emulation — which proves the sandbox, never the device',
      candidates: (n: number) => `${n} zero-day candidate${n === 1 ? '' : 's'} to reproduce`,
      noCandidate: 'The zero-day node formed no candidate from the scaffold it had — not a clean binary',
      noTriage: 'No binary triage was possible, so the zero-day question was never put',
      noTarget: 'No target was selected — the session had nothing to analyse',
      halted: 'The governor stopped the run before it reached an answer',
      failed: 'The session broke before it could conclude',
      running: 'Still going',
      /** How the human-approval gate was settled. `gateAuto` ran without one because isolation contained it. */
      gateApproved: 'you approved the emulation',
      gateDeclined: 'you declined the emulation',
      gateAuto: 'ran unattended — fully isolated',
      /** Proof-state codes, node names and preflight strategies are records: the frame is localised, they are not. */
      emulation: (proofState: string) => `emulation → ${proofState}`,
      preflight: (strategy: string) => `preflight: ${strategy}`,
      endedAt: (node: string) => `ended at ${node}`,
      stoppedAt: (node: string) => `stopped at ${node}`,
      /** The governor's leash, consumed against its cap — a spend with no cap beside it states nothing. */
      leash: (used: number, max: number) => `${used} of ${max} steps`,
      leashDetail: (usd: number, maxUsd: number, entries: number) =>
        `$${usd.toFixed(4)} of $${maxUsd.toFixed(2)} spent · ${entries} transcript entries`,
    },
  },

  /** The run view: the same trace the image section renders, inside this section's own frame. */
  run: {
    back: 'All runs',
    scanTitle: 'Autonomous scan',
    agentTitle: 'Agent session',
    /** Leaving for the static-analysis shell is a labelled choice here, never the side effect of a click. */
    openImage: 'Open the full analysis of this firmware',
    openImageHint: 'Leaves Agents for the static-analysis view of this image.',
    notFound: 'That target is not in this workspace.',
  },

  launch: {
    title: 'Start a run',
    ready: (n: number) => `${n} ready`,
    emptyTitle: 'No targets yet',
    emptyLead: 'Upload firmware in',
    emptyLink: 'Local analysis',
    emptyTail: '— an analyzed image becomes a target here.',
    scan: 'Scan',
    agent: 'Agent',
    launched: (filename: string) => `Autonomous scan started on ${filename}`,
  },
};
