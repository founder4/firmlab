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
  mode: 'user-qemu' | 'chroot-qemu' | 'system-qemu' | 'renode';
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
export interface FuzzResult {
  available: boolean;
  reason?: string;
  binary: string;
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
  fuzzStatus: () => get<{ available: boolean }>('/api/fuzz/status'),
  runFuzz: (id: string, binary: string, seconds?: number) =>
    post<{ jobId: string }>(`/api/images/${id}/fuzz`, { binary, ...(seconds ? { seconds } : {}) }),
  fuzzResult: (id: string) => get<{ result: FuzzResult | null }>(`/api/images/${id}/fuzz`).then((r) => r.result),
  extract: (id: string) => post<{ jobId: string }>(`/api/images/${id}/extract`),
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
