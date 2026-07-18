import { corpusRefs } from './corpus.js';
import { rowToFinding } from './findings.js';
/**
 * The copilot — Phase 2, read-only. It interprets the deterministic analysis already computed for an image
 * (findings with proof-states, binaries, coverage, corpus cross-refs) and returns a prioritized, cited
 * assessment. It executes nothing and invents nothing: the proof-state discipline is enforced in the prompt,
 * and every claim must trace to a data point we hand it. The corpus gives priors, never conclusions.
 */
import type { LlmConfig, LlmResult } from './llm.js';
import { complete } from './llm.js';
import { getImage, listBinaries, listFindings, listJobs } from './store.js';

/** The compact, structured view of an image the copilot reasons over. Deliberately bounded to control tokens. */
interface CopilotContext {
  identity: unknown;
  coverage: Record<string, boolean>;
  findings: { kind: string; title: string; severity: string; proofState: string; source: string }[];
  binaries: { path: string; arch: string | null; networkFacing: boolean; hardening: string }[];
  corpusRefs: { credentials: number; components: number; artifacts: number };
  counts: { findings: number; binaries: number };
}

/** The proof-state discipline, as a system prompt. This is the copilot's conscience. */
export const COPILOT_SYSTEM_PROMPT = `You are FirmLab's firmware-analysis copilot. You interpret the results of a
deterministic analysis pipeline. You do NOT run tools and you do NOT have any information beyond the JSON you are
given.

Non-negotiable rules:
1. Ground every statement in a provided finding or data point. Never invent findings, CVEs, credentials, or
   capabilities. If the data doesn't support a claim, don't make it.
2. Respect proof states. A finding is only as proven as its proofState says:
   - needs_runtime_reproduction = plausible, NOT confirmed — never present it as exploitable.
   - static_confirmed = present in the bytes; the fact is proven, exploitability is not.
   - confirmed_in_emulation = proven under emulation only — this is NOT device compromise.
   - blocked_by_platform / blocked_by_security = could not be reproduced here; say so.
   Do not upgrade a finding's certainty beyond its proofState.
3. Corpus cross-references (credentials/components/binaries seen in other images) are priors worth checking,
   not conclusions.
4. Your job: (a) a short honest risk summary, (b) the findings prioritized by real risk with a one-line reason
   each, (c) concrete next analysis steps the user could run (e.g. extract, run SBOM, triage a specific binary,
   attempt emulation of a network-facing service). Recommend steps that the coverage shows haven't run yet.

Output concise GitHub-flavored markdown. Be direct and useful; do not hedge with disclaimers beyond what the
proof states require.`;

/** Assemble the read-only context for an image from what the deterministic pipeline already produced. */
export function gatherContext(imageId: string): CopilotContext | null {
  const row = getImage(imageId);
  if (!row) return null;
  const jobsDone = (kind: string): boolean => listJobs(imageId).some((j) => j.kind === kind && j.status === 'done');

  const findings = listFindings(imageId).map(rowToFinding);
  const binaries = listBinaries(imageId);
  const refs = corpusRefs(imageId);
  const hardening = (b: (typeof binaries)[number]): string =>
    b.triaged ? `nx=${b.nx} canary=${b.canary} pic=${b.pic}` : 'not-triaged';

  return {
    identity: row.identityJson ? JSON.parse(row.identityJson) : null,
    coverage: {
      static: row.status === 'ready',
      extraction: jobsDone('extract'),
      sbom: jobsDone('sbom'),
      gitleaks: jobsDone('gitleaks'),
      emulation: jobsDone('emulate'),
    },
    findings: findings.slice(0, 120).map((f) => ({
      kind: f.kind,
      title: f.title,
      severity: f.severity,
      proofState: f.proofState,
      source: f.source,
    })),
    binaries: binaries.slice(0, 60).map((b) => ({
      path: b.path,
      arch: b.arch,
      networkFacing: b.networkFacing === 1,
      hardening: hardening(b),
    })),
    corpusRefs: {
      credentials: refs.credentials.length,
      components: refs.components.length,
      artifacts: refs.artifacts.length,
    },
    counts: { findings: findings.length, binaries: binaries.length },
  };
}

/** The user turn: the structured context plus the ask. */
export function buildCopilotUserPrompt(ctx: CopilotContext): string {
  return [
    'Analyze this firmware image from the following deterministic-analysis results.',
    'Counts may exceed the arrays shown (they are truncated); use `counts` for totals.',
    '',
    '```json',
    JSON.stringify(ctx, null, 2),
    '```',
  ].join('\n');
}

/** Run the copilot for an image: gather → prompt → provider. Returns null if the image has no context. */
export async function runCopilot(imageId: string, cfg: LlmConfig): Promise<LlmResult | null> {
  const ctx = gatherContext(imageId);
  if (!ctx) return null;
  return complete(COPILOT_SYSTEM_PROMPT, buildCopilotUserPrompt(ctx), cfg);
}
