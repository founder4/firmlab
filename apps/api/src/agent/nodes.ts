/**
 * The two Phase-3 decision nodes — ① Triage and ② Target selection. This is where the agent reasons, and the
 * ONLY thing it does is *choose a branch and interpret*: it never types the mechanics. Each node is handed a
 * compact, structured view of what the deterministic pipeline already computed, and must return a structured
 * decision (strict JSON) with an auditable rationale. Node ② is hard-bounded by the deterministic preflight —
 * the agent cannot pick an emulation rung the deployment can't actually run; requested rungs are clamped down
 * and the honest ceiling wins.
 *
 * The prompt builders, JSON extraction, and decision parsers are pure so they unit-test without a provider.
 * The gather* functions read the store; run* functions call the LLM.
 */
import type { FirmwareClass, StaticAnalysis } from '@firmlab/core';
import type { LlmConfig, LlmResult } from '../llm.js';
import { completeJson, parseLlmOutput } from '../llm.js';
import type { RuntimeCapabilities, RuntimeStrategy } from '../providers/preflight.js';
// `store` and `corpus` are imported lazily inside the gather* functions so the pure prompt/parse helpers in this
// module unit-test without loading node:sqlite (the same convention as providers/diff.ts and preflight.ts).

// === Shared: strict JSON extraction + coercion (pure) ===

/** Pull the first JSON object out of a model response, tolerating ```json fences and surrounding prose. */
export function extractJsonObject(text: string): Record<string, unknown> {
  let t = text.trim();
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence?.[1]) t = fence[1].trim();
  const start = t.indexOf('{');
  const end = t.lastIndexOf('}');
  if (start === -1 || end === -1 || end < start) throw new Error('No JSON object found in the model response');
  const parsed = JSON.parse(t.slice(start, end + 1));
  if (typeof parsed !== 'object' || parsed === null) throw new Error('Model response was not a JSON object');
  return parsed as Record<string, unknown>;
}

const asString = (v: unknown, fallback = ''): string => (typeof v === 'string' ? v : fallback);
const asStringArray = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
const asEnum = <T extends string>(v: unknown, allowed: readonly T[], fallback: T): T =>
  typeof v === 'string' && (allowed as readonly string[]).includes(v) ? (v as T) : fallback;

// === Emulation rungs + the preflight bound ===

export type EmulationRung = 'none' | 'qemu-user' | 'chroot-service' | 'full-system' | 'rtos-renode';
const CONFIDENCE = ['low', 'medium', 'high'] as const;
const PRIORITY = ['low', 'medium', 'high'] as const;
const RUNGS: readonly EmulationRung[] = ['none', 'qemu-user', 'chroot-service', 'full-system', 'rtos-renode'];

/** Rank within the Linux emulation track (rtos-renode is a separate track, ranked alongside qemu-user). */
const RUNG_RANK: Record<EmulationRung, number> = {
  none: 0,
  'qemu-user': 1,
  'chroot-service': 2,
  'full-system': 3,
  'rtos-renode': 1,
};

/** The highest rung the deterministic preflight permits for a strategy — the ceiling the agent cannot exceed. */
export function maxRungFor(strategy: RuntimeStrategy): EmulationRung {
  switch (strategy) {
    case 'qemu-user':
      return 'qemu-user';
    case 'chroot-service':
      return 'chroot-service';
    case 'full-system':
      return 'full-system';
    case 'rtos-renode':
      return 'rtos-renode';
    default:
      return 'none'; // static-only, unsupported-arch — nothing runs here
  }
}

/**
 * Clamp a requested rung to what the preflight allows. This is the enforcement point for the proof-state
 * machine's honesty: a static-only image drops every emulation to `none`; a qemu-user ceiling can't be raised
 * to full-system by the agent's say-so.
 */
export function clampRung(requested: EmulationRung, strategy: RuntimeStrategy): EmulationRung {
  const max = maxRungFor(strategy);
  if (max === 'none') return 'none';
  if (max === 'rtos-renode') return requested === 'rtos-renode' ? 'rtos-renode' : 'none';
  if (requested === 'rtos-renode') return 'none'; // RTOS rung on a Linux ceiling is a category error
  return RUNG_RANK[requested] <= RUNG_RANK[max] ? requested : max;
}

// === Node ① Triage ===

export interface TriageContext {
  /** Operator intent guides prioritisation, but never overrides measured evidence or proof state. */
  goal: string | null;
  identity: {
    firmwareClass: FirmwareClass;
    arch: string;
    endianness: string;
    filesystems: string[];
    bootloader: string | null;
  };
  size: number;
  entropy: {
    mean: number;
    max: number;
    likelyEncrypted: boolean;
    likelyCompressed: boolean;
    highEntropyRegions: number;
  };
  signatures: { id: string; category: string; description: string; confidence: string; offset: number }[];
  secretKinds: Record<string, number>;
  corpus: { familyKey: string; familyImageCount: number; reusedCredentials: number };
  alreadyExtracted: boolean;
  measurement: {
    completedStages: string[];
    findings: {
      total: number;
      byProofState: Record<string, number>;
      top: {
        source: string;
        kind: string;
        severity: string;
        proofState: string;
        title: string;
        subject: string | null;
      }[];
    };
  };
}

export interface TriageDecision {
  /** The measured classifier always wins; this is never copied blindly from model output. */
  resolvedClass: string;
  /** The model's proposal is retained separately so disagreements remain visible in the transcript. */
  suggestedClass?: string;
  classAgreement?: 'confirmed' | 'conflict' | 'measured-unknown';
  classReconciliation?: string;
  classConfidence: (typeof CONFIDENCE)[number];
  shouldExtract: boolean;
  extractionCascade: string[];
  attackSurface: string[];
  rationale: string;
}

export const TRIAGE_SYSTEM_PROMPT = `You are FirmLab's triage node — decision node ① in a deterministic firmware-analysis
skeleton. Everything mechanical (extraction, emulation, proof capture) is done by deterministic code; your job is
ONLY to choose a branch and justify it from the evidence you are given. You never invent facts.

Given the static-analysis summary of one firmware image, decide:
- resolvedClass: your best read of the firmware class (confirm or refine the inferred one) and classConfidence.
- shouldExtract: is filesystem extraction warranted? (An image that is likely encrypted as a whole, or has no
  recognizable filesystem, usually is not worth extracting yet — say so.)
- extractionCascade: an ordered list of extractor preferences given the detected filesystems (e.g. ["unsquashfs",
  "binwalk"] for squashfs, ["jefferson"] for jffs2, ["ubireader"] for ubifs). Empty if shouldExtract is false.
- attackSurface: a prioritized list of what deserves attention next (e.g. "network-facing daemons",
  "hardcoded credentials", "web CGI", "bootloader env"). Ground each in the evidence.
- rationale: 1-3 sentences citing the specific inputs (entropy, signatures, secrets, corpus priors) behind your call.

Corpus priors (same device family seen before, reused credentials) are hints worth checking, never conclusions.
The optional operator goal may prioritize which evidenced surface matters, but it cannot create facts, override the
measured firmware identity, or raise confidence. Generic byte signatures that conflict with a strong container or
firmware-volume identity are likely false positives unless several coherent measurements support the reclassification.
Respond with ONLY a JSON object, no prose or code fences:
{"resolvedClass": string, "classConfidence": "low"|"medium"|"high", "shouldExtract": boolean,
 "extractionCascade": string[], "attackSurface": string[], "rationale": string}`;

/** Assemble the deterministic triage context for an image, or null if it has no cached analysis. */
export async function gatherTriageContext(imageId: string, goal: string | null = null): Promise<TriageContext | null> {
  const { getImage, listFindings, listJobs } = await import('../store.js');
  const { partitionByProvenance } = await import('../operator-findings.js');
  const { corpusOverview, corpusRefs, deviceFamilyKey } = await import('../corpus.js');
  const row = getImage(imageId);
  if (!row?.analysisJson || !row.identityJson) return null;
  const analysis = JSON.parse(row.analysisJson) as StaticAnalysis;
  const identity = analysis.identity;

  const secretKinds: Record<string, number> = {};
  for (const s of analysis.secrets) {
    const k = s.secretKind ?? 'unclassified';
    secretKinds[k] = (secretKinds[k] ?? 0) + 1;
  }

  const familyKey = deviceFamilyKey(identity);
  const family = corpusOverview().deviceFamilies.find((f) => f.familyKey === familyKey);
  const refs = corpusRefs(imageId);
  const jobs = listJobs(imageId);
  const extracted = jobs.some((j) => j.kind === 'extract' && j.status === 'done');
  const completedStages = [...new Set(jobs.filter((j) => j.status === 'done').map((j) => j.kind))].sort();
  const { measured } = partitionByProvenance(listFindings(imageId));
  const byProofState: Record<string, number> = {};
  for (const finding of measured) {
    byProofState[finding.proofState] = (byProofState[finding.proofState] ?? 0) + 1;
  }
  const topFindings = [...measured]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.createdAt - a.createdAt)
    .slice(0, 12)
    .map((finding) => ({
      source: finding.source,
      kind: finding.kind,
      severity: finding.severity,
      proofState: finding.proofState,
      title: finding.title,
      subject: findingSubject(finding.evidenceJson),
    }));

  return {
    goal,
    identity: {
      firmwareClass: identity.firmwareClass,
      arch: identity.arch,
      endianness: identity.endianness,
      filesystems: identity.filesystems,
      bootloader: identity.bootloader ?? null,
    },
    size: analysis.size,
    entropy: {
      mean: Number(analysis.entropy.mean.toFixed(3)),
      max: Number(analysis.entropy.max.toFixed(3)),
      likelyEncrypted: analysis.entropy.likelyEncrypted,
      likelyCompressed: analysis.entropy.likelyCompressed,
      highEntropyRegions: analysis.entropy.highEntropyRegions.length,
    },
    signatures: analysis.signatures.slice(0, 40).map((s) => ({
      id: s.id,
      category: s.category,
      description: s.description,
      confidence: s.confidence,
      offset: s.offset,
    })),
    secretKinds,
    corpus: {
      familyKey,
      familyImageCount: family?.images.length ?? 1,
      reusedCredentials: refs.credentials.length,
    },
    alreadyExtracted: extracted,
    measurement: {
      completedStages,
      findings: { total: measured.length, byProofState, top: topFindings },
    },
  };
}

const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const severityRank = (severity: string): number => SEVERITY_RANK[severity] ?? 0;

function findingSubject(evidenceJson: string | null): string | null {
  if (!evidenceJson) return null;
  try {
    const evidence = JSON.parse(evidenceJson) as Record<string, unknown>;
    for (const key of ['path', 'binary', 'subject', 'component', 'cve']) {
      if (typeof evidence[key] === 'string') return evidence[key];
    }
  } catch {
    // Malformed legacy evidence is omitted from model context; the persisted finding remains intact.
  }
  return null;
}

export function buildTriageUserPrompt(ctx: TriageContext): string {
  return [
    'Triage this firmware image from its deterministic static analysis:',
    '',
    '```json',
    JSON.stringify(ctx, null, 2),
    '```',
  ].join('\n');
}

/** Coerce a model response into a valid TriageDecision (defaults applied; never throws on missing fields). */
export function parseTriageDecision(text: string): TriageDecision {
  const o = extractJsonObject(text);
  const shouldExtract = o.shouldExtract === true;
  return {
    resolvedClass: asString(o.resolvedClass, 'unknown'),
    classConfidence: asEnum(o.classConfidence, CONFIDENCE, 'low'),
    shouldExtract,
    extractionCascade: shouldExtract ? asStringArray(o.extractionCascade) : [],
    attackSurface: asStringArray(o.attackSurface),
    rationale: asString(o.rationale, '(no rationale returned)'),
  };
}

const NON_ROOTFS_CLASSES = new Set<FirmwareClass>(['esp-soc', 'baremetal', 'rtos', 'uefi-bios', 'encrypted']);

/**
 * Reconcile model interpretation with the deterministic classifier. The proposal stays auditable, but it can
 * neither rewrite measured identity nor launch a Linux extraction branch for a measured non-rootfs image.
 */
export function reconcileTriageDecision(ctx: TriageContext, proposal: TriageDecision): TriageDecision {
  const measured = ctx.identity.firmwareClass;
  const suggested = proposal.resolvedClass;
  const classAgreement =
    measured === 'unknown' ? 'measured-unknown' : suggested === measured ? 'confirmed' : 'conflict';
  const blocksRootfsExtraction = NON_ROOTFS_CLASSES.has(measured);

  return {
    ...proposal,
    resolvedClass: measured,
    suggestedClass: suggested,
    classAgreement,
    classReconciliation:
      classAgreement === 'confirmed'
        ? `Model proposal agrees with measured class: ${measured}.`
        : classAgreement === 'measured-unknown'
          ? `Measured class remains unknown; model proposal ${suggested} is advisory only.`
          : `Measured class ${measured} overrides model proposal ${suggested}.`,
    shouldExtract: blocksRootfsExtraction ? false : proposal.shouldExtract,
    extractionCascade: blocksRootfsExtraction ? [] : proposal.extractionCascade,
  };
}

export interface NodeRun<T> {
  decision: T;
  result: LlmResult;
}

export async function runTriageNode(ctx: TriageContext, cfg: LlmConfig): Promise<NodeRun<TriageDecision>> {
  const result = await completeJson(TRIAGE_SYSTEM_PROMPT, buildTriageUserPrompt(ctx), cfg);
  const proposal = parseLlmOutput(result, parseTriageDecision);
  return { decision: reconcileTriageDecision(ctx, proposal), result };
}

// === Node ② Target selection ===

export interface TargetSelectionContext {
  /** Operator intent guides prioritisation, but does not change the deterministic runtime ceiling. */
  goal: string | null;
  identity: { firmwareClass: string; arch: string };
  capabilities: { strategy: RuntimeStrategy; proofCeiling: string; reason: string; maxRung: EmulationRung };
  binaries: {
    path: string;
    arch: string | null;
    networkFacing: boolean;
    hardening: string;
    imports: string | null;
    emulationStatus: string | null;
  }[];
  findings: {
    /** MEASURED findings only — assertions are counted separately and never enter the proof-state histogram. */
    total: number;
    bySeverity: Record<string, number>;
    byProofState: Record<string, number>;
    /** Claims a person or agent recorded on this image. Not measurements, not evidence. */
    operatorAssertions: number;
    top: {
      source: string;
      kind: string;
      severity: string;
      proofState: string;
      title: string;
      subject: string | null;
    }[];
  };
  corpus: { reusedArtifacts: number; prevalentComponents: number };
}

export interface TargetSelection {
  path: string;
  rung: EmulationRung;
  priority: (typeof PRIORITY)[number];
  reason: string;
}

export interface TargetSelectionDecision {
  targets: TargetSelection[];
  /** Derived from the clamped targets — every emulation needs explicit human approval in Phase 3. */
  emulationPlan: { binary: string; rung: EmulationRung; requiresApproval: true }[];
  rationale: string;
}

export const TARGET_SELECTION_SYSTEM_PROMPT = `You are FirmLab's target-selection node — decision node ② in a
deterministic firmware-analysis skeleton. You choose WHICH binaries deserve deeper analysis and WHICH emulation
rung to attempt for each. You do not run anything; a human approves emulation and deterministic code executes it.

You are given the first-class binaries table, the findings summary, corpus cross-refs, and — critically — the
deterministic runtime preflight (\`capabilities\`). The preflight's \`maxRung\` is a HARD ceiling: never propose a
rung above it. If maxRung is "none" (static-only or unsupported arch), you may still prioritize binaries for static
review but must set every rung to "none". Prefer network-facing, weakly-hardened binaries with dangerous imports.
The optional operator goal may rank candidates, but it never changes capabilities, proof state, or measured facts.
Choose at most three targets; a short, evidence-backed queue is more useful than enumerating every binary.
maxRung is a ceiling, not a recommendation: choose the LEAST sufficient rung. Prefer qemu-user for one binary,
chroot-service for a rootfs service, and full-system only when boot/kernel/device integration is evidenced and needed.

For each chosen target return {path, rung, priority, reason}. rung ∈ {"none","qemu-user","chroot-service",
"full-system","rtos-renode"} and must respect maxRung. Ground every choice in the data (hardening flags, imports,
network-facing, corpus reuse). Respond with ONLY a JSON object, no prose or code fences:
{"targets": [{"path": string, "rung": string, "priority": "low"|"medium"|"high", "reason": string}],
 "rationale": string}`;

/** Assemble the deterministic target-selection context, bounded by the preflight capabilities. */
export async function gatherTargetSelectionContext(
  imageId: string,
  caps: RuntimeCapabilities,
  goal: string | null = null,
): Promise<TargetSelectionContext> {
  const { listBinaries, listFindings } = await import('../store.js');
  const { corpusRefs } = await import('../corpus.js');
  const { partitionByProvenance } = await import('../operator-findings.js');
  const binaries = listBinaries(imageId);
  const refs = corpusRefs(imageId);

  // This context is fed to a model choosing what to investigate next, and the proof-state histogram is how it
  // judges how well-evidenced the image already is. An operator assertion in that tally would be a claim voting
  // on the strength of the evidence for itself, so assertions are counted on their own line instead.
  const { measured, asserted } = partitionByProvenance(listFindings(imageId));
  const findings = measured;

  const bySeverity: Record<string, number> = {};
  const byProofState: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byProofState[f.proofState] = (byProofState[f.proofState] ?? 0) + 1;
  }

  return {
    goal,
    identity: { firmwareClass: caps.firmwareClass, arch: caps.arch },
    capabilities: {
      strategy: caps.strategy,
      proofCeiling: caps.proofCeiling,
      reason: caps.reason,
      maxRung: maxRungFor(caps.strategy),
    },
    binaries: binaries.slice(0, 60).map((b) => ({
      path: b.path,
      arch: b.arch,
      networkFacing: b.networkFacing === 1,
      hardening: b.triaged ? `nx=${b.nx} canary=${b.canary} pic=${b.pic}` : 'not-triaged',
      imports: b.importsSummary,
      emulationStatus: b.emulationStatus,
    })),
    findings: {
      total: findings.length,
      bySeverity,
      byProofState,
      operatorAssertions: asserted.length,
      top: [...findings]
        .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.createdAt - a.createdAt)
        .slice(0, 15)
        .map((finding) => ({
          source: finding.source,
          kind: finding.kind,
          severity: finding.severity,
          proofState: finding.proofState,
          title: finding.title,
          subject: findingSubject(finding.evidenceJson),
        })),
    },
    corpus: { reusedArtifacts: refs.artifacts.length, prevalentComponents: refs.components.length },
  };
}

export function buildTargetSelectionUserPrompt(ctx: TargetSelectionContext): string {
  return [
    'Select analysis/emulation targets for this image. Respect capabilities.maxRung as a hard ceiling:',
    '',
    '```json',
    JSON.stringify(ctx, null, 2),
    '```',
  ].join('\n');
}

/**
 * Coerce a model response into a valid TargetSelectionDecision. Every requested rung is clamped to the preflight
 * strategy, and the emulation plan is DERIVED from the clamped targets (rung != none) — so the honest ceiling is
 * enforced in code, not left to the model's goodwill.
 */
export function parseTargetSelectionDecision(text: string, strategy: RuntimeStrategy): TargetSelectionDecision {
  const o = extractJsonObject(text);
  const rawTargets = Array.isArray(o.targets) ? o.targets : [];
  const targets: TargetSelection[] = rawTargets
    .filter((t): t is Record<string, unknown> => typeof t === 'object' && t !== null)
    .map((t) => {
      const requested = asEnum(t.rung, RUNGS, 'none');
      return {
        path: asString(t.path),
        rung: clampRung(requested, strategy),
        priority: asEnum(t.priority, PRIORITY, 'medium'),
        reason: asString(t.reason, ''),
      };
    })
    .filter((t) => t.path !== '')
    .slice(0, 3);

  const emulationPlan = targets
    .filter((t) => t.rung !== 'none')
    .map((t) => ({ binary: t.path, rung: t.rung, requiresApproval: true as const }));

  return { targets, emulationPlan, rationale: asString(o.rationale, '(no rationale returned)') };
}

export async function runTargetSelectionNode(
  ctx: TargetSelectionContext,
  caps: RuntimeCapabilities,
  cfg: LlmConfig,
): Promise<NodeRun<TargetSelectionDecision>> {
  const result = await completeJson(TARGET_SELECTION_SYSTEM_PROMPT, buildTargetSelectionUserPrompt(ctx), cfg);
  return { decision: parseLlmOutput(result, (text) => parseTargetSelectionDecision(text, caps.strategy)), result };
}
