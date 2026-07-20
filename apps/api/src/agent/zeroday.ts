/**
 * Decision node ④ — zero-day reasoning. Given the deterministic taint scaffold for one binary (sinks it imports,
 * attacker-controlled sources, CGI hints, hardening) plus Level-2 corpus priors (vulnerable components seen in
 * this device family, reachability confirmed before), the agent hypothesizes a source→sink taint path, classifies
 * the vuln, and constructs a trigger. It is bound hard by the proof-state machine: node ④ only ever produces
 * CANDIDATES — every one is `needs_runtime_reproduction`. It can never declare a confirmed finding; only the
 * deterministic trigger run (isolated emulation / fuzzing) can upgrade a candidate, and that decision is code's.
 *
 * The context gatherer reads the store/corpus lazily; the prompt + parse helpers are pure and unit-tested.
 */
import type { LlmConfig, LlmResult } from '../llm.js';
import { complete } from '../llm.js';
import type { DecompileResult } from '../providers/decompile.js';
import { type TaintScaffold, buildTaintScaffold } from '../providers/taint.js';

const REACHABILITY = ['likely', 'possible', 'unlikely'] as const;
const SEVERITY = ['low', 'medium', 'high', 'critical'] as const;

export interface ZerodayPriors {
  /** Level 2: components in this binary's image that are also seen (with CVEs) across the device family. */
  vulnerableComponents: { name: string; version: string; cveCount: number; otherImages: number }[];
  /** Reachability priors: subjects confirmed reachable before in this family — a flag to check, not a verdict. */
  confirmedBefore: { subject: string; proofState: string }[];
}

export interface ZerodayContext {
  binary: string;
  arch: string | undefined;
  networkFacing: boolean;
  taint: TaintScaffold;
  priors: ZerodayPriors;
}

export interface ZerodayCandidate {
  sink: string;
  source: string;
  vulnClass: string;
  reachability: (typeof REACHABILITY)[number];
  severity: (typeof SEVERITY)[number];
  trigger: string;
  rationale: string;
}

export interface ZerodayDecision {
  candidates: ZerodayCandidate[];
  rationale: string;
}

export const ZERODAY_SYSTEM_PROMPT = `You are FirmLab's zero-day node — decision node ④. You reason about whether a
binary has a reachable vulnerability, from a DETERMINISTIC taint scaffold you are given (the dangerous sinks it
imports, the attacker-controlled sources, CGI/HTTP hints, and hardening). You never run anything; deterministic
code will try your trigger under isolation afterwards.

Rules, non-negotiable:
1. Only hypothesize a source→sink path when the scaffold actually contains BOTH a plausible source (or CGI hint)
   and a dangerous sink. If it doesn't, return an empty candidate list — never invent a sink, source, or CVE.
2. Everything you output is a CANDIDATE to be tested, not a proven bug. Estimate reachability honestly
   (likely/possible/unlikely) from the evidence; missing xref proof means at most "possible".
3. Corpus priors (vulnerable components in the family, reachability confirmed before) are flags worth checking,
   not conclusions. A prior does not raise your reachability by itself.
4. For each candidate give {sink, source, vulnClass, reachability, severity, trigger, rationale}. vulnClass ∈
   {command-injection, stack-overflow, format-string, path-traversal, other}. The trigger is a concrete input
   (e.g. an HTTP request/param, an NVRAM value) that would drive the source into the sink.

Respond with ONLY a JSON object, no prose or code fences:
{"candidates": [{"sink": string, "source": string, "vulnClass": string, "reachability": "likely"|"possible"|"unlikely",
  "severity": "low"|"medium"|"high"|"critical", "trigger": string, "rationale": string}], "rationale": string}`;

// --- pure JSON coercion (shared shape with nodes.ts, kept local to avoid a cross-node import) ---
function extractObject(text: string): Record<string, unknown> {
  let t = text.trim();
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence?.[1]) t = fence[1].trim();
  const start = t.indexOf('{');
  const end = t.lastIndexOf('}');
  if (start === -1 || end === -1 || end < start) throw new Error('No JSON object found in the model response');
  return JSON.parse(t.slice(start, end + 1)) as Record<string, unknown>;
}
const asStr = (v: unknown, fb = ''): string => (typeof v === 'string' ? v : fb);
const asEnum = <T extends string>(v: unknown, allowed: readonly T[], fb: T): T =>
  typeof v === 'string' && (allowed as readonly string[]).includes(v) ? (v as T) : fb;

/**
 * Coerce a model response into a valid ZerodayDecision. Candidates are capped and empties dropped; proof-state is
 * deliberately absent here — the session assigns `needs_runtime_reproduction` and only a real trigger run upgrades.
 */
export function parseZerodayDecision(text: string): ZerodayDecision {
  const o = extractObject(text);
  const raw = Array.isArray(o.candidates) ? o.candidates : [];
  const candidates: ZerodayCandidate[] = raw
    .filter((c): c is Record<string, unknown> => typeof c === 'object' && c !== null)
    .map((c) => ({
      sink: asStr(c.sink),
      source: asStr(c.source),
      vulnClass: asStr(c.vulnClass, 'other'),
      reachability: asEnum(c.reachability, REACHABILITY, 'possible'),
      severity: asEnum(c.severity, SEVERITY, 'medium'),
      trigger: asStr(c.trigger),
      rationale: asStr(c.rationale, ''),
    }))
    .filter((c) => c.sink !== '')
    .slice(0, 8);
  return { candidates, rationale: asStr(o.rationale, '(no rationale returned)') };
}

export function buildZerodayUserPrompt(ctx: ZerodayContext): string {
  return [
    'Assess this binary for a reachable vulnerability from its taint scaffold:',
    '',
    '```json',
    JSON.stringify(ctx, null, 2),
    '```',
  ].join('\n');
}

/** Assemble node ④'s context for a binary: taint scaffold (from its triage) + Level-2 corpus priors. */
export async function gatherZerodayContext(imageId: string, decompile: DecompileResult): Promise<ZerodayContext> {
  const { getImage, listBinaries } = await import('../store.js');
  const { corpusRefs, listReachabilityPriors, deviceFamilyKey } = await import('../corpus.js');

  const taint = buildTaintScaffold(decompile);
  const bin = listBinaries(imageId).find((b) => b.path === decompile.binary);
  const refs = corpusRefs(imageId);
  const row = getImage(imageId);
  const familyKey = row?.identityJson ? deviceFamilyKey(JSON.parse(row.identityJson)) : '';

  const priors: ZerodayPriors = {
    vulnerableComponents: refs.components
      .filter((c) => c.cveCount > 0)
      .slice(0, 10)
      .map((c) => ({ name: c.name, version: c.version, cveCount: c.cveCount, otherImages: c.otherImages.length })),
    confirmedBefore: (familyKey ? listReachabilityPriors(familyKey) : [])
      .filter((p) => p.proofState === 'confirmed_in_emulation' || p.proofState === 'confirmed_full_system')
      .slice(0, 10)
      .map((p) => ({ subject: p.subject, proofState: p.proofState })),
  };

  return {
    binary: decompile.binary,
    arch: decompile.info.arch,
    networkFacing: bin?.networkFacing === 1,
    taint,
    priors,
  };
}

export interface ZerodayRun {
  decision: ZerodayDecision;
  result: LlmResult;
}

export async function runZerodayNode(ctx: ZerodayContext, cfg: LlmConfig): Promise<ZerodayRun> {
  const result = await complete(ZERODAY_SYSTEM_PROMPT, buildZerodayUserPrompt(ctx), cfg);
  return { decision: parseZerodayDecision(result.text), result };
}
