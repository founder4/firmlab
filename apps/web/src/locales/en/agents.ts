/**
 * agents — the console over the autonomous engine, at workspace level. English source of truth.
 *
 * The claim this screen must never overstate is in its own description: the agent drives the pipeline, it does not
 * invent findings. Run STATUSES (`queued`, `running`, `awaiting_approval`, `error`, `halted`) are job values that
 * cross the API and land in SQLite, so they render verbatim; only the words around them are localised.
 */
export const agents = {
  eyebrow: 'Autonomy',
  title: 'Agents',
  desc: "Launch and monitor autonomous analysis runs across every target. Each run records its steps and keeps every claim's proof state — the agent drives the pipeline, it never invents findings.",

  scan: {
    title: 'Autonomous scan',
    badge: 'deterministic',
    sub: 'One click plans a class-routed worker chain, runs it end-to-end and returns a reasoning trace with honest gaps. No LLM key required.',
  },

  llm: {
    title: 'Conscious agent',
    off: 'off',
    on: 'LLM decision nodes with a human approval gate before emulation and a governor capping steps, tokens, cost and time.',
    /** The env var keeps its name in every language — it is what the operator has to type. */
    disabled:
      'Disabled — set FIRMLAB_AGENT=1 and an API key for LLM-driven decisions. The deterministic scan still runs.',
  },

  history: {
    title: 'Run history',
    live: (n: number) => `${n} live`,
    refresh: 'Refresh',
    emptyTitle: 'No runs yet',
    emptyBody:
      'Launch an autonomous scan on a ready target below. Runs appear here with live status, and open into their step transcript and evidence.',
    colTarget: 'Target',
    colKind: 'Kind',
    colStatus: 'Status',
    colDetail: 'Detail',
    view: 'View',
    kindScan: 'scan',
    kindAgent: 'agent',
    findings: (n: number) => `${n} findings`,
    steps: (n: number) => `${n} steps`,
  },

  launch: {
    title: 'Launch on a target',
    ready: (n: number) => `${n} ready`,
    emptyTitle: 'No targets yet',
    emptyLead: 'Upload firmware in',
    emptyLink: 'Local analysis',
    emptyTail: '— analyzed images become agent targets here.',
    scan: 'Scan',
    agent: 'Agent',
    launched: (filename: string) => `Autonomous scan launched on ${filename}`,
  },
};
