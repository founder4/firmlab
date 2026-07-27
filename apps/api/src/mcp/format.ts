/**
 * MCP result shaping — the honesty contract at the agent boundary.
 *
 * This is the part of the MCP surface that matters. Everything else is plumbing over an HTTP API that already
 * exists; this module exists because handing FirmLab's output to a language model reintroduces, at a layer where
 * nobody is looking, precisely the failure the whole workbench is built against.
 *
 * The UI solves it with a banner: a findings list is meaningless until you know which stages produced it, so
 * `CoverageBanner` sits above it and says so. An agent has no banner. It calls a tool, gets `{"findings": []}`,
 * and writes "no vulnerabilities were found" — a sentence the data does not support and cannot support, because
 * an empty list is produced identically by "every applicable stage ran and found nothing" and by "extraction
 * never recovered a rootfs so eight of twelve stages never ran". Those are opposite conclusions.
 *
 * So the rule here is: **a result that could be read as a negative carries its own verdict inline.** Not in a
 * companion tool the agent may not think to call, not in the tool description it may skim — in the same payload,
 * in the first field. `findingsPayload` will not emit a findings list without the coverage sentence attached, and
 * when nothing has been examined it says so before it says anything else.
 *
 * The second rule is that proof states survive verbatim. FirmLab distinguishes `static_confirmed` from
 * `needs_runtime_reproduction` from `blocked_by_platform` for exactly the reason an agent is prone to collapse
 * them, so they are never summarised away, and `HONESTY_INSTRUCTIONS` tells the model what each one licenses it
 * to claim.
 *
 * Pure — takes plain data, returns plain data, unit-tested.
 */

/** A finding as the API serves it (the fields that matter for the agent boundary). */
export interface McpFinding {
  kind: string;
  title: string;
  severity: string;
  proofState: string;
  source: string;
  evidence?: Record<string, unknown>;
  rationale?: string;
}

/** The coverage report shape `GET /images/:id/coverage` returns. */
export interface McpCoverage {
  firmwareClass: string;
  classRationale?: string;
  applicable: number;
  executed: number;
  findingCount: number;
  verdict: string;
  ambiguous: boolean;
  stages: { worker: string; reason: string; status: string; detail?: string; findingCount?: number }[];
}

/**
 * Server-level instructions, sent at initialize. This is the model's briefing on how to read the bench: what the
 * proof-state ladder licenses, and the two inferences that are always wrong here. Kept short enough to survive
 * being in every context window, and specific enough to be actionable rather than a disclaimer.
 */
export const HONESTY_INSTRUCTIONS = [
  'FirmLab is a firmware analysis workbench. You are driving it; it does the analysis and you interpret it.',
  '',
  'Every finding carries a PROOF STATE, and it bounds what you may claim:',
  '  static_confirmed          — the code fact is present in the bytes. Claim the fact, not its exploitability.',
  '  confirmed_in_emulation    — reproduced against a booted image. Proves the sandbox, not the physical device.',
  '  confirmed_full_system     — reproduced under full-system emulation.',
  '  needs_runtime_reproduction— a LEAD. A precondition was observed, nothing was proven. Never report as a bug.',
  '  blocked_by_platform       — the question was asked and this deployment could not answer it. NOT a negative.',
  '  blocked_by_security       — a control (encryption, secure boot) stopped the analysis. NOT a negative.',
  '  false_positive            — checked and dismissed.',
  '',
  'Two inferences are always wrong here, and both are easy to make:',
  '  1. An empty findings list does NOT mean the firmware is clean. It means the stages that ran found nothing —',
  '     and stages that never ran found nothing by definition. Every findings result carries a coverage verdict;',
  '     read it before you characterise the result, and quote its limits when you report.',
  '  2. A tool being absent, or a bounded search expiring, is not evidence of absence. Symbolic reachability that',
  '     does not reach a sink has proven nothing about that sink.',
  '',
  'When you report, say what was examined and what was not. An honest partial answer is the deliverable here;',
  'a confident complete-sounding one built on unexamined stages is the failure this workbench exists to prevent.',
].join('\n');

/**
 * Pure: the one-line reading of coverage, phrased for a model that is about to write a conclusion. Leads with the
 * imperative when the count is misleading, because that is the sentence most likely to be skimmed into the answer.
 */
export function coverageHeadline(c: McpCoverage): string {
  if (c.executed === 0) {
    return `UNEXAMINED — ${c.verdict} Do not characterise this image as clean or as analyzed.`;
  }
  if (c.executed < c.applicable) {
    return `PARTIAL COVERAGE — ${c.verdict} Any conclusion must be scoped to the stages that ran.`;
  }
  return `FULL COVERAGE OF WHAT THIS DEPLOYMENT CAN CHECK — ${c.verdict}`;
}

/** Stage statuses that mean the stage did NOT produce a result — the ones a conclusion must exclude. */
const UNCOVERED = new Set(['no-input', 'not-built', 'not-run']);

/**
 * Pure: the findings payload. The verdict comes FIRST, and the stages that produced no result are named, so the
 * model cannot reach the list without passing the caveat that bounds it. `findings` is never returned alone.
 */
export function findingsPayload(
  coverage: McpCoverage | null,
  findings: McpFinding[],
): {
  coverageVerdict: string;
  notCovered: string[];
  proofStateCounts: Record<string, number>;
  findingCount: number;
  findings: McpFinding[];
} {
  const proofStateCounts: Record<string, number> = {};
  for (const f of findings) proofStateCounts[f.proofState] = (proofStateCounts[f.proofState] ?? 0) + 1;

  // Coverage unavailable is itself a caveat, not a licence to present the list as complete.
  const coverageVerdict = coverage
    ? coverageHeadline(coverage)
    : 'COVERAGE UNKNOWN — the coverage report could not be read, so it is not known which analysis stages ran. Do not treat this list as complete.';

  return {
    coverageVerdict,
    notCovered: coverage ? coverage.stages.filter((s) => UNCOVERED.has(s.status)).map((s) => s.worker) : [],
    proofStateCounts,
    findingCount: findings.length,
    findings,
  };
}

/** One worker's outcome as the opacidad run reports it. */
export interface McpStep {
  worker: string;
  status: string;
  summary: string;
  note?: string;
  findingCount?: number;
  origin?: string;
  trigger?: string;
}

/**
 * Pure: an autonomous-scan payload. Degraded and skipped workers are lifted OUT of the step list into their own
 * field — buried in a 15-entry array a model reads them as noise, and they are exactly the entries that bound
 * what the scan's findings are worth.
 */
export function scanPayload(input: {
  firmwareClass: string;
  arch: string;
  steps: McpStep[];
  findings: { total: number; bySeverity?: Record<string, number> };
  attackPath: string[];
  narrative: string;
  honestGaps: string[];
}): Record<string, unknown> {
  const incomplete = input.steps.filter((s) => s.status !== 'ran');
  return {
    firmwareClass: input.firmwareClass,
    arch: input.arch,
    workersRun: input.steps.filter((s) => s.status === 'ran').length,
    workersTotal: input.steps.length,
    // Named before the narrative: what did NOT happen bounds everything the narrative says.
    workersThatDidNotComplete: incomplete.map((s) => ({
      worker: s.worker,
      status: s.status,
      why: s.note ?? s.summary,
    })),
    honestGaps: input.honestGaps,
    findings: input.findings,
    attackPath: input.attackPath,
    narrative: input.narrative,
    steps: input.steps,
  };
}

/**
 * Pure: a symbolic-reachability payload. The per-sink outcome is restated in words the model cannot collapse,
 * because `not_reached_in_budget` looks like a negative result and is not one — it is the absence of a result.
 */
export function reachabilityPayload(result: {
  available: boolean;
  reason: string;
  binary: string;
  arch?: string;
  entry?: string;
  asked?: string[];
  sinks: { sink: string; outcome: string; reason?: string; argv1?: string; steps?: number; errors?: number }[];
}): Record<string, unknown> {
  const meaning: Record<string, string> = {
    reached:
      'PROVEN REACHABLE from the entry point under symbolic input. This is a reachability claim only — it does not establish that the call overflows anything, nor that it is exploitable.',
    not_reached_in_budget:
      'NO RESULT. The bounded search stopped before reaching it. This is NOT evidence the sink is unreachable — indirect jumps and unmodelled syscalls routinely hide real paths from a bounded search.',
    absent: 'The symbol is not in this binary, so the question did not apply. Nothing was learned about the binary.',
    skipped: 'Not asked — the run budget was spent on earlier sinks. Nothing was learned about this sink.',
  };
  return {
    available: result.available,
    binary: result.binary,
    ...(result.arch ? { arch: result.arch } : {}),
    ...(result.entry ? { entry: result.entry } : {}),
    ...(result.asked ? { sinksAsked: result.asked } : {}),
    reason: result.reason,
    sinks: result.sinks.map((s) => ({
      ...s,
      meaning: meaning[s.outcome] ?? 'Unrecognised outcome — treat as no result.',
    })),
  };
}

/**
 * Pure: wrap any payload as an MCP tool result. Text content holding JSON is what every current client renders
 * reliably; `structuredContent` carries the same object for clients that use it.
 */
export function toolResult(payload: unknown): {
  content: { type: 'text'; text: string }[];
  structuredContent?: Record<string, unknown>;
} {
  const text = JSON.stringify(payload, null, 2);
  return typeof payload === 'object' && payload !== null && !Array.isArray(payload)
    ? { content: [{ type: 'text', text }], structuredContent: payload as Record<string, unknown> }
    : { content: [{ type: 'text', text }] };
}

/** Pure: an error result that names the failure instead of returning an empty success. */
export function toolError(message: string): { content: { type: 'text'; text: string }[]; isError: true } {
  return { content: [{ type: 'text', text: message }], isError: true };
}
