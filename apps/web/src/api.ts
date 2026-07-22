/**
 * Typed API client for the FirmLab backend. All calls are same-origin (dev proxies /api → :8799), so the
 * workbench never talks to a remote host.
 */
import type {
  EntropyProfile,
  FsNode,
  FsSummary,
  ImageIdentity,
  SignatureHit,
  StaticAnalysis,
  StringHit,
  StructureSegment,
} from '@firmlab/core';

export type {
  EntropyProfile,
  FsNode,
  FsSummary,
  ImageIdentity,
  SignatureHit,
  StaticAnalysis,
  StringHit,
  StructureSegment,
};

export interface ImageSummary {
  id: string;
  filename: string;
  size: number;
  sha256: string;
  uploadedAt: number;
  status: 'analyzing' | 'ready' | 'error';
  identity: ImageIdentity | null;
  tags: string[];
}

export interface ToolStatus {
  id: string;
  bin: string;
  available: boolean;
  version?: string;
  unlocks: string;
  group: 'extract' | 'analyze' | 'sbom' | 'emulate' | 'secrets';
}

export interface EmulationRecipe {
  id: string;
  mode: 'user-qemu' | 'chroot-qemu' | 'system-qemu' | 'renode' | 'uefi-chipsec';
  title: string;
  description: string;
  requires: string[];
  runnable: boolean;
  command: string;
  rank: number;
  notes?: string;
}

export type RuntimeStrategy =
  | 'qemu-user'
  | 'chroot-service'
  | 'full-system'
  | 'rtos-renode'
  | 'uefi-chipsec'
  | 'static-only'
  | 'unsupported-arch';

/** The deterministic runtime-capability preflight for an image (the honest floor for the proof-state machine). */
export interface RuntimeCapabilities {
  arch: string;
  firmwareClass: string;
  hasRootfs: boolean;
  userEmulator: string | null;
  systemEmulator: string | null;
  strategy: RuntimeStrategy;
  proofCeiling: ProofState;
  reason: string;
}

export interface EmulationMenu {
  identity: ImageIdentity;
  rootfsReady: boolean;
  suggestedBinary: string | null;
  recipes: EmulationRecipe[];
  capabilities: RuntimeCapabilities | null;
}

/** One EFI module carved from a UEFI firmware volume by chipsec. */
export interface UefiModule {
  guid: string;
  name?: string;
  type?: string;
}

/** A UEFI-specific finding from the chipsec decode (inventory, IOC match, or an embedded-app review lead). */
export interface UefiSecurityFinding {
  kind: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  proofState: ProofState;
  evidence: Record<string, unknown>;
  rationale: string;
}

/** Secure Boot / NVRAM posture from chipsec's offline variable store (honest: `unknown` when not extractable). */
export interface SecureBootPosture {
  variableCount: number;
  secureBoot: 'enabled' | 'disabled' | 'unknown';
  setupMode: 'setup' | 'user' | 'unknown';
  customMode: 'enabled' | 'disabled' | 'unknown';
  hasPK: boolean;
  hasKEK: boolean;
  hasDb: boolean;
  hasDbx: boolean;
  testKey: string | null;
  variables: string[];
  note: string;
}

/** chipsec offline UEFI decode result — proof tops out at static_confirmed (facts about the bytes). */
export interface ChipsecResult {
  available: boolean;
  ran: boolean;
  reason: string;
  proofState: ProofState;
  volumes: number;
  moduleCount: number;
  byType: Record<string, number>;
  modules: UefiModule[];
  secureBoot: SecureBootPosture | null;
  findings: UefiSecurityFinding[];
  command: string;
  isolation?: string;
}

/** Active web-probe result — a reproduced hit against the emulated service is confirmed_in_emulation. */
export interface WebProbeResult {
  available: boolean;
  reason: string;
  target: string;
  requests: number;
  points: number;
  findings: {
    kind: string;
    title: string;
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    proofState: ProofState;
    evidence: Record<string, unknown>;
    rationale: string;
  }[];
}

/** Renode RTOS/Cortex-M boot result — "booted" is decided from real UART bytes, never assumed. */
export interface RenodeResult {
  available: boolean;
  ran: boolean;
  booted: boolean;
  reason: string;
  proofState: ProofState;
  platform: string | null;
  uartExcerpt: string;
  command: string;
  isolation?: string;
}

/** AFL++ coverage-guided fuzz result — honest crash count (0 is a real, valid outcome for hardened binaries). */
export type HarnessClass = 'file' | 'stdin' | 'network';

export interface FuzzResult {
  available: boolean;
  reason?: string;
  binary: string;
  harness: HarnessClass;
  harnessNote?: string;
  seconds: number;
  execsDone: number | null;
  crashes: number;
  crashSamples: { name: string; hexPreview: string }[];
  isolation: string;
  command: string;
}

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Negligible' | 'Unknown';

export interface SbomVuln {
  id: string;
  severity: Severity;
  packageName: string;
  packageVersion: string;
  fixedIn: string | null;
}

export interface SbomResult {
  available: boolean;
  reason?: string;
  target: string;
  packageCount: number;
  packages: { name: string; version: string; type: string }[];
  grypeAvailable: boolean;
  vulnerabilities: SbomVuln[];
  counts: Record<Severity, number>;
}

export interface DecompileResult {
  available: boolean;
  reason?: string;
  binary: string;
  info: {
    arch?: string;
    bits?: number;
    bintype?: string;
    os?: string;
    endian?: string;
    canary?: boolean;
    nx?: boolean;
    pic?: boolean;
  };
  functionCount: number;
  symbols: { name: string; type: string; addr: string }[];
  imports: { name: string; libname?: string }[];
  strings: { addr: string; value: string }[];
}

export interface GitleaksFinding {
  rule: string;
  description: string;
  file: string;
  line: number;
  match: string;
}

export interface GitleaksResult {
  available: boolean;
  reason?: string;
  target: string;
  findingCount: number;
  findings: GitleaksFinding[];
}

export interface IdentityChange {
  field: string;
  a: string;
  b: string;
}

export interface FirmwareDiffResult {
  a: { id: string; filename: string };
  b: { id: string; filename: string };
  identity: IdentityChange[];
  packages: {
    hasData: boolean;
    added: { name: string; version: string }[];
    removed: { name: string; version: string }[];
    changed: { name: string; a: string; b: string }[];
  };
  cves: {
    hasData: boolean;
    addedIds: string[];
    removedIds: string[];
    addedBySeverity: Record<Severity, number>;
  };
  files: {
    hasData: boolean;
    added: string[];
    removed: string[];
    changed: string[];
    counts: { added: number; removed: number; changed: number };
  };
}

export interface GhidraFunction {
  name: string;
  signature: string;
  pseudocode: string;
}

export interface GhidraResult {
  available: boolean;
  reason?: string;
  binary: string;
  functionCount: number;
  functions: GhidraFunction[];
}

export interface StorageUsage {
  imageCount: number;
  imagesBytes: number;
  extractsBytes: number;
  totalBytes: number;
  quotaBytes: number;
  maxAgeDays: number;
}

export interface Job {
  id: string;
  imageId: string;
  kind: string;
  status: 'queued' | 'running' | 'done' | 'error';
  createdAt: number;
  updatedAt: number;
  params: unknown;
  log: string;
  result: unknown;
  error: string | null;
}

export type ProofState =
  | 'needs_runtime_reproduction'
  | 'static_confirmed'
  | 'confirmed_in_emulation'
  | 'confirmed_full_system'
  | 'blocked_by_platform'
  | 'blocked_by_security'
  | 'false_positive';

export interface Finding {
  id: string;
  imageId: string;
  source: string;
  kind: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  proofState: ProofState;
  evidence?: Record<string, unknown>;
  rationale?: string;
  createdAt: number;
}

/** Whether the flag-gated copilot is enabled, and which provider/model backs it (no secrets). */
export interface AgentStatus {
  enabled: boolean;
  provider?: string;
  model?: string;
}

export interface CopilotResult {
  text: string;
  model: string;
  provider: string;
  inputTokens?: number;
  outputTokens?: number;
}

// === Phase 3: agent sessions (conscious autonomy — decision nodes ①/② under a governor) ===

export interface GovernorBudget {
  maxSteps: number;
  maxTokens: number;
  maxUsd: number;
  maxWallMs: number;
}

export interface GovernorConsumed {
  steps: number;
  inputTokens: number;
  outputTokens: number;
  usd: number;
  elapsedMs: number;
}

/** Agent config: whether the agent is enabled, the backing model, and the governor's hard caps. */
export interface AgentConfig {
  enabled: boolean;
  provider?: string;
  model?: string;
  budget?: GovernorBudget;
}

export type AgentSessionStatus = 'running' | 'awaiting_approval' | 'done' | 'error' | 'halted';

export interface AgentSession {
  id: string;
  imageId: string;
  status: AgentSessionStatus;
  goal: string | null;
  budget: GovernorBudget;
  consumed: GovernorConsumed;
  haltReason: string | null;
  createdAt: number;
  updatedAt: number;
}

/** One transcript entry: a node's structured input, its decision output, and the rationale — the audit trail. */
export interface AgentStep {
  seq: number;
  node: string;
  status: string;
  input: unknown;
  output: unknown;
  rationale: string | null;
  model: string | null;
  inputTokens: number;
  outputTokens: number;
  createdAt: number;
}

// === Phase 5: external-intelligence track (OSINT / published-vuln correlation) ===

export interface ResearchStatus {
  enabled: boolean;
  allowlist?: string[];
}

export interface OsvAdvisory {
  id: string;
  aliases: string[];
  summary: string;
  severity: string | null;
  references: string[];
}

export interface NvdAdvisory {
  id: string;
  summary: string;
  severity: string | null;
  score: number | null;
  references: string[];
}

export interface KevMatch {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  knownRansomware: string;
}

export interface ResearchResult {
  enabled: true;
  provenance: {
    identity: { firmwareClass: string; arch: string; bootloader: string | null };
    vendors: string[];
    models: string[];
    versions: string[];
    urls: string[];
    domains: string[];
    certCNs: string[];
    banners: string[];
  };
  egress: { destinations: { host: string; sends: string; count: number }[]; neverSent: string[] };
  osv: {
    queried: number;
    skipped: number;
    withAdvisories: number;
    totalAdvisories: number;
    components: { name: string; version: string; ecosystem: string | null; advisories: OsvAdvisory[] }[];
  };
  nvd: {
    queried: number;
    notQueried: number;
    withAdvisories: number;
    totalAdvisories: number;
    components: { name: string; version: string; advisories: NvdAdvisory[] }[];
  };
  kev: { checked: boolean; catalogSize: number; matches: KevMatch[]; reason?: string };
  keyMaterial: { kind: string; redacted: string; effectivelyPublic: boolean; sharedInImages?: number }[];
  securityContacts: { domain: string; checked: boolean; found: boolean; reason?: string; contact: string[] }[];
  synthesis?: { text: string; model: string; provider: string };
}

export interface AgentSessionView {
  session: AgentSession | null;
  steps: AgentStep[];
}

export interface ImageRef {
  id: string;
  filename: string;
}

export interface CorpusRefs {
  credentials: { hash: string; kind: string | null; otherImages: ImageRef[] }[];
  components: { name: string; version: string; cveCount: number; otherImages: ImageRef[] }[];
  artifacts: { sha1: string; path: string; otherImages: ImageRef[] }[];
}

export interface CorpusRule {
  id: string;
  type: string;
  key: string;
  label: string;
  note: string | null;
  createdAt: number;
}

export interface CorpusOverview {
  imageCount: number;
  ruleCount: number;
  credentialReuse: { hash: string; kind: string | null; imageCount: number; watchlistLabel: string | null }[];
  componentPrevalence: { name: string; version: string; cveCount: number; imageCount: number }[];
  deviceFamilies: { familyKey: string; images: ImageRef[] }[];
}

/** A binary from the extracted rootfs (0/1/null columns preserved as returned by the API). */
export interface BinaryEntry {
  imageId: string;
  path: string;
  sha1: string | null;
  size: number;
  arch: string | null;
  bits: number | null;
  endianness: string | null;
  nx: number | null;
  canary: number | null;
  pic: number | null;
  networkFacing: number;
  importsSummary: string | null;
  triaged: number;
  emulationStatus: string | null;
}

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}
async function post<T>(url: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method: 'POST' };
  if (body !== undefined) {
    init.headers = { 'content-type': 'application/json' };
    init.body = JSON.stringify(body);
  }
  const res = await fetch(url, init);
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(err.error ?? `${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}
async function del<T>(url: string): Promise<T> {
  const res = await fetch(url, { method: 'DELETE' });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

/** The deep static-analysis providers runnable per image; their findings appear in the dossier. */
export type AnalysisKind = 'uboot' | 'fsaudit' | 'certs' | 'rtos' | 'compmap' | 'services' | 'fcc';

/** The result of a W9 autonomous scan (opacidad): the class-routed plan, per-worker outcomes, and the narrative. */
export interface OpacidadResult {
  firmwareClass: string;
  arch: string;
  classRationale?: string;
  plan: { worker: string; reason: string }[];
  steps: {
    worker: string;
    status: 'ran' | 'degraded' | 'skipped' | 'not-built';
    summary: string;
    note?: string;
    findingCount?: number;
    /** `replan` = W9 scheduled this worker dynamically in response to a lead (not a seed of the class DAG). */
    origin?: 'replan';
    trigger?: string;
  }[];
  findings: {
    total: number;
    bySeverity: Record<string, number>;
    byProofState: Record<string, number>;
    top: { title: string; severity: string; proofState: string; source: string }[];
  };
  attackPath: string[];
  narrative: string;
  narrativeSource: 'llm' | 'deterministic';
  honestGaps: string[];
  llm?: { provider: string; model: string };
}

/** A saved emulation preset — a named, reusable recipe config for an image. */
export interface EmulationPreset {
  id: string;
  name: string;
  mode: 'user-qemu' | 'chroot-qemu' | 'system-qemu' | 'renode' | 'uefi-chipsec';
  binary: string | null;
  args: string[];
  createdAt: number;
}

// === Phase 6: capture & acquisition ===

export interface CaptureBackend {
  id: string;
  role: 'positioning' | 'interception' | 'radio' | 'physical';
  transports: string[];
  unlocks: string;
  available: boolean;
  reason: string;
  capabilities: { decrypt?: boolean; needsHardware?: string; needsCaps?: string[] };
  detail?: Record<string, unknown>;
}

export interface CaptureBackendsView {
  enabled: boolean;
  backends: CaptureBackend[];
  transports: string[];
}

export interface CaptureDevice {
  id: string;
  mac: string;
  ouiVendor: string | null;
  ip: string | null;
  mdnsIdentity: string | null;
  openPorts: string | null;
  typeGuess: string | null;
  typeConfidence: string | null;
  firstSeen: number;
  lastSeen: number;
}

export interface CaptureSession {
  id: string;
  status: string;
  subnet: string | null;
  targetDeviceId: string | null;
  transcript: string;
  deviceCount: number;
  error: string | null;
  createdAt: number;
  updatedAt: number;
}

export interface CaptureStatus {
  enabled: boolean;
  gatewayDeclared?: boolean;
  defaultSubnet?: string | null;
}

export interface CaptureScanView {
  session: CaptureSession;
  devices: CaptureDevice[];
}

export interface CaptureFlow {
  id: string;
  sessionId: string;
  host: string | null;
  url: string | null;
  method: string | null;
  contentType: string | null;
  size: number;
  tlsPosture: string | null;
  firmwareScore: number;
  carved: number;
  bodyPath: string | null;
  createdAt: number;
}

export interface CaptureSessionView {
  session: CaptureSession;
  flows: CaptureFlow[];
}

export interface StartCaptureResult {
  sessionId: string;
  watching: boolean;
  reason: string;
  port: number;
}

export const api = {
  health: () =>
    get<{ status: string; exposedToNetwork: boolean; trustedProxy?: boolean; host?: string; port?: number }>('/health'),
  listImages: () => get<{ images: ImageSummary[] }>('/api/images').then((r) => r.images),
  getImage: (id: string) => get<{ image: ImageSummary }>(`/api/images/${id}`).then((r) => r.image),
  deleteImage: (id: string) => fetch(`/api/images/${id}`, { method: 'DELETE' }).then(() => undefined),
  deleteImages: (ids: string[]) => post<{ deleted: string[] }>('/api/images/delete', { ids }).then((r) => r.deleted),
  setTags: (id: string, tags: string[]) =>
    post<{ image: ImageSummary }>(`/api/images/${id}/tags`, { tags }).then((r) => r.image),
  analysis: (id: string) => get<{ analysis: StaticAnalysis }>(`/api/images/${id}/analysis`).then((r) => r.analysis),
  entropy: (id: string) => get<{ size: number; entropy: EntropyProfile }>(`/api/images/${id}/entropy`),
  structure: (id: string) =>
    get<{ size: number; structure: StructureSegment[]; signatures: SignatureHit[] }>(`/api/images/${id}/structure`),
  secrets: (id: string) => get<{ secrets: StringHit[] }>(`/api/images/${id}/secrets`).then((r) => r.secrets),
  tools: () => get<{ tools: ToolStatus[]; groups: Record<string, { available: number; total: number }> }>('/api/tools'),
  storage: () => get<{ usage: StorageUsage }>('/api/storage').then((r) => r.usage),
  emulation: (id: string) => get<EmulationMenu>(`/api/images/${id}/emulation`),
  emulate: (id: string, binary?: string) =>
    post<{ jobId: string }>(`/api/images/${id}/emulate`, binary ? { binary } : {}),
  emulateSystem: (id: string, rung: 'chroot-service' | 'full-system', binary?: string) =>
    post<{ jobId: string }>(`/api/images/${id}/emulate-system`, { rung, ...(binary ? { binary } : {}) }),
  renodeStatus: () => get<{ available: boolean }>('/api/renode/status'),
  runRenode: (id: string, opts?: { platform?: string; seconds?: number }) =>
    post<{ jobId: string }>(`/api/images/${id}/renode`, opts ?? {}),
  renodeResult: (id: string) => get<{ result: RenodeResult | null }>(`/api/images/${id}/renode`).then((r) => r.result),
  chipsecStatus: () => get<{ available: boolean }>('/api/chipsec/status'),
  runChipsec: (id: string, seconds?: number) =>
    post<{ jobId: string }>(`/api/images/${id}/chipsec`, seconds ? { seconds } : {}),
  chipsecResult: (id: string) =>
    get<{ result: ChipsecResult | null }>(`/api/images/${id}/chipsec`).then((r) => r.result),
  runWebProbe: (id: string, url: string) => post<{ jobId: string }>(`/api/images/${id}/webprobe`, { url }),
  webprobeResult: (id: string) =>
    get<{ result: WebProbeResult | null }>(`/api/images/${id}/webprobe`).then((r) => r.result),
  fuzzStatus: () => get<{ available: boolean }>('/api/fuzz/status'),
  runFuzz: (id: string, binary: string, seconds?: number, harness?: HarnessClass | 'auto') =>
    post<{ jobId: string }>(`/api/images/${id}/fuzz`, {
      binary,
      ...(seconds ? { seconds } : {}),
      ...(harness && harness !== 'auto' ? { harness } : {}),
    }),
  fuzzResult: (id: string) => get<{ result: FuzzResult | null }>(`/api/images/${id}/fuzz`).then((r) => r.result),
  extract: (id: string) => post<{ jobId: string }>(`/api/images/${id}/extract`),
  /** Run one of the deep static-analysis providers; findings land in the dossier. */
  runAnalysis: (id: string, kind: AnalysisKind) => post<{ jobId: string }>(`/api/images/${id}/${kind}`, {}),
  analysisResult: (id: string, kind: AnalysisKind) =>
    get<{ result: { reason?: string; findings?: unknown[] } | null }>(`/api/images/${id}/${kind}`).then(
      (r) => r.result,
    ),
  listPresets: (id: string) => get<{ presets: EmulationPreset[] }>(`/api/images/${id}/presets`).then((r) => r.presets),
  savePreset: (id: string, p: { name: string; mode: EmulationPreset['mode']; binary?: string; args?: string[] }) =>
    post<{ preset: EmulationPreset }>(`/api/images/${id}/presets`, p).then((r) => r.preset),
  deletePreset: (presetId: string) => del<{ deleted: string }>(`/api/presets/${presetId}`),
  /** W9 autonomous scan: plan the class-routed worker chain, run it, compose the narrative. */
  runOpacidad: (id: string) => post<{ jobId: string }>(`/api/images/${id}/opacidad`),
  opacidadResult: (id: string) =>
    get<{ result: OpacidadResult | null }>(`/api/images/${id}/opacidad`).then((r) => r.result),
  jobs: (id: string) => get<{ jobs: Job[] }>(`/api/images/${id}/jobs`).then((r) => r.jobs),
  job: (jobId: string) => get<{ job: Job }>(`/api/jobs/${jobId}`).then((r) => r.job),
  sbom: (id: string) => get<{ result: SbomResult | null }>(`/api/images/${id}/sbom`).then((r) => r.result),
  runSbom: (id: string) => post<{ jobId: string }>(`/api/images/${id}/sbom`),
  decompileResult: (id: string) =>
    get<{ result: DecompileResult | null }>(`/api/images/${id}/decompile`).then((r) => r.result),
  decompile: (id: string, binary: string) => post<{ jobId: string }>(`/api/images/${id}/decompile`, { binary }),
  binaries: (id: string) => get<{ binaries: BinaryEntry[] }>(`/api/images/${id}/binaries`).then((r) => r.binaries),
  findings: (id: string) => get<{ findings: Finding[] }>(`/api/images/${id}/findings`).then((r) => r.findings),
  corpusRefs: (id: string) => get<{ refs: CorpusRefs }>(`/api/images/${id}/corpus-refs`).then((r) => r.refs),
  agentStatus: () => get<AgentStatus>('/api/agent/status'),
  runCopilot: (id: string) => post<{ jobId: string }>(`/api/images/${id}/copilot`),
  copilotResult: (id: string) =>
    get<{ result: CopilotResult | null }>(`/api/images/${id}/copilot`).then((r) => r.result),
  agentConfig: () => get<AgentConfig>('/api/agent/config'),
  startAgentSession: (id: string, goal?: string) =>
    post<{ session: AgentSession }>(`/api/images/${id}/agent/session`, goal ? { goal } : {}).then((r) => r.session),
  agentSession: (id: string) => get<AgentSessionView>(`/api/images/${id}/agent/session`),
  approveEmulation: (sid: string, binary?: string) =>
    post<AgentSessionView>(`/api/agent/sessions/${sid}/approve`, binary ? { binary } : {}),
  declineEmulation: (sid: string) => post<AgentSessionView>(`/api/agent/sessions/${sid}/decline`),
  researchStatus: () => get<ResearchStatus>('/api/research/status'),
  runResearch: (id: string) => post<{ jobId: string }>(`/api/images/${id}/research`),
  researchResult: (id: string) =>
    get<{ result: ResearchResult | null }>(`/api/images/${id}/research`).then((r) => r.result),
  corpusOverview: () => get<{ overview: CorpusOverview }>('/api/corpus/overview').then((r) => r.overview),
  corpusRules: () => get<{ rules: CorpusRule[] }>('/api/corpus/rules').then((r) => r.rules),
  promoteRule: (type: string, key: string, label: string, note?: string) =>
    post<{ rule: CorpusRule }>('/api/corpus/rules', { type, key, label, note }).then((r) => r.rule),
  deleteRule: (id: string) => fetch(`/api/corpus/rules/${id}`, { method: 'DELETE' }).then(() => undefined),
  ghidraResult: (id: string) => get<{ result: GhidraResult | null }>(`/api/images/${id}/ghidra`).then((r) => r.result),
  ghidra: (id: string, binary: string) => post<{ jobId: string }>(`/api/images/${id}/ghidra`, { binary }),
  gitleaks: (id: string) => get<{ result: GitleaksResult | null }>(`/api/images/${id}/gitleaks`).then((r) => r.result),
  runGitleaks: (id: string) => post<{ jobId: string }>(`/api/images/${id}/gitleaks`),
  diffResult: (id: string, against: string) =>
    get<{ result: FirmwareDiffResult | null }>(`/api/images/${id}/diff?against=${encodeURIComponent(against)}`).then(
      (r) => r.result,
    ),
  runDiff: (id: string, against: string) => post<{ jobId: string }>(`/api/images/${id}/diff`, { against }),
  /** Phase 6 capture lane — all top-level (a capture precedes any image), gated by FIRMLAB_CAPTURE. */
  captureStatus: () => get<CaptureStatus>('/api/capture/status'),
  captureBackends: () => get<CaptureBackendsView>('/api/capture/backends'),
  captureDevices: () => get<{ devices: CaptureDevice[] }>('/api/capture/devices').then((r) => r.devices),
  runCaptureDiscover: (subnet: string | null, acknowledged: boolean) =>
    post<{ scanId: string }>('/api/capture/discover', { ...(subnet ? { subnet } : {}), acknowledged }),
  captureScan: (scanId: string) => get<CaptureScanView>(`/api/capture/discover/${scanId}`),
  // Phase 6.1 interception sessions.
  startCaptureSession: (deviceId: string | null, acknowledged: boolean) =>
    post<StartCaptureResult>('/api/capture/session', { ...(deviceId ? { deviceId } : {}), acknowledged }),
  captureSession: (sessionId: string) => get<CaptureSessionView>(`/api/capture/session/${sessionId}`),
  ingestCaptureFlow: (sessionId: string, flowId: string) =>
    post<{ imageId: string; filename: string }>(`/api/capture/session/${sessionId}/ingest`, { flowId }),
  teardownCapture: (sessionId: string) =>
    post<{ session: CaptureSession | null }>(`/api/capture/session/${sessionId}/teardown`),

  async upload(file: File): Promise<ImageSummary> {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch('/api/images', { method: 'POST', body: form });
    if (!res.ok) {
      const err = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(err.error ?? `Upload failed: ${res.status}`);
    }
    return ((await res.json()) as { image: ImageSummary }).image;
  },
};

/** Shared signature-category → color map. Mirrors the CSS custom properties in theme.css. */
export const CATEGORY_COLORS: Record<string, string> = {
  filesystem: '#4db5ff',
  compression: '#f5b642',
  executable: '#7c5cff',
  bootloader: '#37d19a',
  kernel: '#ff9d5c',
  container: '#5cc8ff',
  crypto: '#ff5d6c',
  certificate: '#ff3b5b',
  image: '#b06cff',
  other: '#4a5468',
};

export function categoryColor(cat: string): string {
  return CATEGORY_COLORS[cat] ?? CATEGORY_COLORS.other ?? '#4a5468';
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function fmtHex(n: number): string {
  return `0x${n.toString(16)}`;
}
