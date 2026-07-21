/**
 * W9 (opacidad) narrative composition — the pure, LLM-independent core of the orchestrator's report.
 *
 * The value of the autonomous pass over the fixed pipeline was never a longer list of flat rows; it was the
 * *reasoning* — why a finding is real, and the chain source → sink → privilege → path that turns a lead into an
 * engagement vector (docs/AUTONOMOUS-WORKERS.md §4). This module builds that narrative deterministically from the
 * real findings + the per-worker step outcomes, so opacidad produces a coherent, honest report **with the LLM
 * off**; when the LLM is on, `buildLlmPrompt` hands it the same structured facts to phrase more fluidly — never to
 * invent. Everything here is pure (context in, strings out) and fully unit-testable.
 */
import type { Finding } from '@firmlab/core';

export type OpacidadStepStatus = 'ran' | 'degraded' | 'skipped' | 'not-built';

/** One worker's outcome in the run — what it produced, or the honest reason it could not. */
export interface OpacidadStep {
  worker: string;
  status: OpacidadStepStatus;
  summary: string;
  note?: string;
  findingCount?: number;
}

/** A planned worker and why the class routed to it (shown before/independent of execution). */
export interface OpacidadPlanEntry {
  worker: string;
  reason: string;
}

export interface FindingsSummary {
  total: number;
  bySeverity: Record<string, number>;
  byProofState: Record<string, number>;
  top: { title: string; severity: string; proofState: string; source: string }[];
}

/** Everything the narrative composer needs — assembled by the orchestrator from real provider outputs. */
export interface OpacidadContext {
  filename: string;
  firmwareClass: string;
  arch: string;
  classRationale?: string;
  carveTrace?: { format: string; action: string; detail: string }[];
  plan: OpacidadPlanEntry[];
  steps: OpacidadStep[];
  findings: Finding[];
}

const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const PROOF_RANK: Record<string, number> = {
  confirmed_full_system: 6,
  confirmed_in_emulation: 5,
  static_confirmed: 4,
  needs_runtime_reproduction: 3,
  blocked_by_platform: 2,
  blocked_by_security: 2,
  false_positive: 0,
};

/** Rank a finding for prioritization: severity first, then how well it is proven. */
function findingRank(f: Finding): number {
  return (SEVERITY_RANK[f.severity] ?? 0) * 10 + (PROOF_RANK[f.proofState] ?? 0);
}

/** Tally findings by severity + proof state and surface the highest-ranked handful. */
export function summarizeFindings(findings: Finding[]): FindingsSummary {
  const bySeverity: Record<string, number> = {};
  const byProofState: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byProofState[f.proofState] = (byProofState[f.proofState] ?? 0) + 1;
  }
  const top = [...findings]
    .sort((a, b) => findingRank(b) - findingRank(a))
    .slice(0, 8)
    .map((f) => ({ title: f.title, severity: f.severity, proofState: f.proofState, source: f.source }));
  return { total: findings.length, bySeverity, byProofState, top };
}

/**
 * Build the chain-of-evidence lines. A finding whose evidence carries source/sink/privilege is rendered as the
 * source → sink → (privilege) chain the autonomous pass produced; otherwise the title stands, always tagged with
 * its honest proof state so a static lead is never dressed up as a reproduced exploit.
 */
export function buildAttackPath(findings: Finding[]): string[] {
  const ranked = [...findings]
    .filter((f) => f.proofState !== 'false_positive' && (SEVERITY_RANK[f.severity] ?? 0) >= 3)
    .sort((a, b) => findingRank(b) - findingRank(a))
    .slice(0, 6);
  return ranked.map((f) => {
    const ev = (f.evidence ?? {}) as Record<string, unknown>;
    const source = ev.source ?? ev.input ?? ev.param;
    const sink = ev.sink ?? ev.binary ?? ev.file;
    const priv = ev.privilege ?? ev.user ?? ev.runsAs;
    const chain = [source, sink, priv].filter((x) => typeof x === 'string' && x).join(' → ');
    const head = chain ? `${chain}` : f.title;
    return `[${f.severity}/${f.proofState}] ${head}`;
  });
}

/** The honest-degradation surface: what could NOT be done, so "few findings" is never read as "clean/secure". */
export function honestGaps(ctx: OpacidadContext): string[] {
  const gaps: string[] = [];
  for (const s of ctx.steps) {
    if (s.status === 'not-built') gaps.push(`${s.worker}: not built yet — ${s.note ?? s.summary}`);
    else if (s.status === 'degraded' || s.status === 'skipped') {
      gaps.push(`${s.worker}: ${s.status} — ${s.note ?? s.summary}`);
    }
  }
  if (ctx.findings.length === 0) {
    gaps.push(
      'Zero findings here does NOT mean "secure": it can mean the class-appropriate deep worker is not built or a ' +
        'stage never reached its input. Read the per-worker outcomes above before concluding anything.',
    );
  }
  return gaps;
}

function severityLine(s: FindingsSummary): string {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const parts = order.filter((k) => s.bySeverity[k]).map((k) => `${s.bySeverity[k]} ${k}`);
  return parts.length ? parts.join(' · ') : 'none';
}

/**
 * Compose the full markdown narrative deterministically. This is what opacidad shows when the LLM is off — a
 * coherent report: what the image is (and why not Linux, when so), what each worker did, the carve chain, the
 * findings by severity/proof, the attack path, and the honest gaps.
 */
export function composeDeterministicNarrative(ctx: OpacidadContext): string {
  const summary = summarizeFindings(ctx.findings);
  const gaps = honestGaps(ctx);
  const path = buildAttackPath(ctx.findings);
  const L: string[] = [];

  L.push(`# Autonomous scan — ${ctx.filename}`);
  L.push('');
  L.push(`**Class:** \`${ctx.firmwareClass}\` · **arch:** \`${ctx.arch}\``);
  if (ctx.classRationale) L.push(`\n${ctx.classRationale}`);

  if (ctx.carveTrace?.length) {
    L.push('\n## Extraction chain');
    for (const s of ctx.carveTrace) L.push(`- **${s.format}** ${s.action}: ${s.detail}`);
  }

  L.push('\n## Workers');
  for (const s of ctx.steps) {
    const tag = s.status === 'ran' ? '✓' : s.status === 'not-built' ? '▢' : '⚠';
    const count = s.findingCount ? ` (${s.findingCount} findings)` : '';
    L.push(`- ${tag} **${s.worker}** — ${s.summary}${count}${s.note ? ` _(${s.note})_` : ''}`);
  }

  L.push('\n## Findings');
  L.push(`${summary.total} total · ${severityLine(summary)}`);
  if (summary.top.length) {
    for (const f of summary.top) L.push(`- **[${f.severity}]** ${f.title} — _${f.proofState}_ (${f.source})`);
  }

  if (path.length) {
    L.push('\n## Attack path (chain of evidence)');
    for (const p of path) L.push(`- ${p}`);
  }

  if (gaps.length) {
    L.push('\n## Honest gaps');
    for (const g of gaps) L.push(`- ${g}`);
  }

  L.push('\n_Findings are proof-stated: `static_confirmed`/`confirmed_in_emulation` are reproduced from the bytes/');
  L.push(
    'sandbox; `needs_runtime_reproduction` is a lead, not a verdict. No claim is made about the physical device._',
  );
  return L.join('\n');
}

/** The system + user prompts for the LLM narrative path — it may only reorganize/explain the provided facts. */
export function buildLlmPrompt(ctx: OpacidadContext): { system: string; user: string } {
  const summary = summarizeFindings(ctx.findings);
  const system =
    "You are FirmLab's autonomous-scan narrator. Write a concise, technically precise engagement narrative for a " +
    'firmware image using ONLY the facts provided. Never invent findings, CVEs, versions, or exploit steps. Where ' +
    'the facts support it, connect a finding into a source → sink → privilege → path chain and name the engagement ' +
    "vector; otherwise say the lead is unproven. Always preserve each finding's proof state (a static lead is not " +
    'a reproduced exploit) and never claim anything about the physical device. Prefer plain prose over lists.';
  const facts = {
    image: ctx.filename,
    firmwareClass: ctx.firmwareClass,
    arch: ctx.arch,
    classRationale: ctx.classRationale ?? null,
    extractionChain: ctx.carveTrace?.map((s) => `${s.format}:${s.action}:${s.detail}`) ?? [],
    workers: ctx.steps.map((s) => ({ worker: s.worker, status: s.status, summary: s.summary, note: s.note ?? null })),
    findingsBySeverity: summary.bySeverity,
    findingsByProofState: summary.byProofState,
    topFindings: summary.top,
    honestGaps: honestGaps(ctx),
  };
  const user = `Facts (JSON):\n${JSON.stringify(facts, null, 2)}\n\nWrite the narrative now.`;
  return { system, user };
}
