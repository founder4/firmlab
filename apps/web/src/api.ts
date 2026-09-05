/**
 * Typed API client for the FirmLab backend. All calls are same-origin (dev proxies /api → :8799), so the
 * workbench never talks to a remote host.
 *
 * **The `lang` parameter, and why only three endpoints have one.** Most of what the API returns is data or a
 * record: identity, findings, provider results stored on a job row. Those are written at measurement time and
 * stay in the language that produced them — re-translating a stored measurement would be rewriting it. Three
 * surfaces are the opposite. The coverage verdict, the tool table and the lane flags are recomposed from live
 * state on every request and describe THIS DEPLOYMENT and THIS ANALYSIS RUN, so they are interface copy that
 * merely happens to be built server-side, and the caller passes the locale it is rendering in. It is optional
 * everywhere and absent means English, which is exactly what the endpoints answered before it existed.
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
import type { Locale } from './i18n';

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
  /** The provider's own sentence about what this posture can and cannot say. Rendered beside the state badge. */
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
  /**
   * Why there is no posture, when there is none. Optional forever — a result stored before this existed carries
   * no such field, and `secureBoot: null` on its own was rendered as blank space, which reads as "this image has
   * no variable store": the one conclusion none of the three situations behind that null supports.
   */
  nvramStoreNote?: string;
  findings: UefiSecurityFinding[];
  command: string;
  isolation?: string;
}

/**
 * Where a booted firmware tried to go, read off its own wire by `providers/egress.ts`.
 *
 * Every field is optional on the result that carries it, and permanently: a full-system run stored before this
 * existed has none of them, and a required field would make these types assert something about a persisted row
 * they cannot know — the class of defect that took down the whole image view once already.
 */
export interface EgressAttempt {
  address: string;
  protocol: 'tcp' | 'udp' | 'icmp' | 'other';
  port?: number;
  /** `external` is the egress; the rest is the firmware talking to the sandbox, its own subnet, or announcing. */
  scope: 'external' | 'emulator' | 'local' | 'multicast';
  frames: number;
}

export interface DnsQuery {
  name: string;
  server: string;
  frames: number;
}

/**
 * Why nothing answered on a full-system boot. An empty `open` list covers at least five situations that want
 * different work — a daemon that crashed, a guest that drops packets, a stack that refuses them — and this is
 * what separates them. Optional forever, like every field added to a persisted result type.
 */
export interface BootDiagnosis {
  cause:
    | 'answered'
    | 'service-died'
    | 'guest-dropped'
    | 'nothing-listening'
    | 'no-syns'
    | 'no-service-started'
    | 'unknown';
  summary: string;
  evidence: string[];
  daemonsStarted: string[];
  daemonsExited: { binary: string; pid: string; code: number; signal: number | null; lastOpen: string | null }[];
}

export interface EgressObservation {
  attempts: EgressAttempt[];
  dnsQueries: DnsQuery[];
  dnsTruncated: number;
  guestFrames: number;
  /**
   * Optional forever, all four: a boot stored before the direction gate existed carries none of them, and this
   * type is re-read for every run that image has ever had. `answeredFrames` counts TCP frames the guest sent on
   * flows it never opened — its answers to the probes this workbench itself made, which the panel used to list
   * as destinations the firmware chose.
   */
  answeredFrames?: number;
  undecidedFrames?: number;
  attemptsDropped?: number;
  queriesDropped?: number;
  truncated: boolean;
  problem: string;
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
  /** True totals from syft/grype. Optional forever — a result stored by an older build carries neither. */
  packageTotal?: number;
  vulnerabilityTotal?: number;
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

/**
 * One sink's symbolic-reachability outcome. `reached` is the only one that upgrades a claim, and it claims
 * REACHABILITY — never exploitability. `not_reached_in_budget` is an honest inconclusive (the search stopped), so
 * the UI must never render it as "safe"; `absent` means the symbol is not in this binary at all.
 */
export interface SinkResult {
  sink: string;
  outcome: 'reached' | 'not_reached_in_budget' | 'absent' | 'skipped';
  addresses: string[];
  steps: number;
  pruned: boolean;
  errors: number;
  reason?: string;
  argv1?: string;
  stdin?: string;
  path?: string[];
}

export interface SymReachResult {
  available: boolean;
  reason: string;
  binary: string;
  arch?: string;
  entry?: string;
  sinks: SinkResult[];
  asked?: string[];
  dropped?: string[];
  /** The sinks were read off the binary's own unbounded-copy imports rather than named by the operator. */
  derivedSinks?: boolean;
  budgetSeconds?: number;
}

/** How the export-reachability probe reports one sink. `reachable` is the only outcome that files a lead. */
export type ExportReachSinkOutcome = 'reachable' | 'not_reached' | 'absent' | 'no_call_site' | 'budget_exhausted';

export interface ExportReachSink {
  sink: string;
  outcome: ExportReachSinkOutcome;
  holders?: number;
  reachableFrom?: number;
  entryPointsNamed?: string[];
  namedTruncated?: number;
}

/**
 * Export reachability over a `.so`/`.ko` — the question those objects admit, since neither has an entry point for
 * `symreach` to explore from. Every detail field is optional: a stored result is JSON written by an older build,
 * and `outcome: 'no_functions_recovered'` (an empty graph, a failure to analyse) carries almost none of them.
 */
export interface ExportReachResult {
  available: boolean;
  reason: string;
  binary?: string;
  arch?: string;
  functionsRecovered?: number;
  callEdges?: number;
  entryPoints?: number;
  entryPointsConsidered?: number;
  cfgSeconds?: number;
  elapsedSeconds?: number;
  /** `no_functions_recovered` when the graph came back empty — analysable/not-analysable is the load-bearing line. */
  outcome?: string;
  sinks: ExportReachSink[];
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

/**
 * The four capability results that had no type here at all.
 *
 * Deliberately PARTIAL: each declares only what a reader renders, plus the `available`/`reason` contract every
 * provider shares. A fuller mirror of the server's interfaces would be a second source of truth that drifts, and
 * every field is optional beyond the contract because a stored result is data written by an OLDER build — the rule
 * this codebase learned when `nvd.uncheckedIdentities.map` took down the image view for three of four images.
 */
export interface YaraScanResultView {
  available: boolean;
  reason?: string;
  state?: string;
  corpus?: { rulesDeclared?: number; rulesApplied?: number; rulesLost?: number; ruleFiles?: number };
  scan?: { filesScanned?: number; filesFound?: number } | null;
  matches?: { rule: string; namespace?: string; tags?: string[]; files?: string[] }[];
  findings?: unknown[];
}

export interface FwHuntResultView {
  available: boolean;
  reason?: string;
  rulesRun?: number;
  rulesInCorpus?: number;
  rulesNotApplicable?: number;
  matches?: { rule?: string; category?: string; verdict?: string }[];
  modulePass?: {
    batchIndex?: number;
    batchCount?: number;
    batchSize?: number;
    batchesCompleted?: number[];
    modulesCarved?: number;
    modulesScanned?: unknown[];
    modulesScannedThisBatch?: number;
    batches?: { index?: number; complete?: boolean }[];
  } | null;
  findings?: unknown[];
}

export interface NvramResultView {
  available: boolean;
  reason?: string;
  bytesScanned?: number;
  stores?: { name?: string; offset?: number; variables?: number; capped?: boolean; duplicateKeys?: number }[];
  findings?: unknown[];
}

export interface FuncDiffResultView {
  available: boolean;
  reason?: string;
  binaries?: { path?: string; changed?: number; added?: number; removed?: number; unmatchable?: number }[];
  findings?: unknown[];
}

/**
 * The dynamic probe's result, which was not typed here at all — so `controlOffset`, the whole point of the probe,
 * had nowhere to be read. Optional throughout for the same persisted-result reason.
 */
export interface DynProbeResultView {
  available: boolean;
  reason?: string;
  binary?: string;
  sink?: string;
  verdict?: string;
  proofState?: string;
  /** The offset at which the input controls the saved return address. `null` is "not recovered", never 0. */
  controlOffset?: number | null;
  faultingPc?: string;
  sinkHits?: number;
  attached?: boolean;
  blockedBy?: string;
  sandboxShortfalls?: string[];
  targetOutput?: string;
  findings?: unknown[];
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

/**
 * What a person may assert. Deliberately disjoint from `ProofState`: a proof state is code's record of what it
 * measured, and an operator finding records what someone claims. The two vocabularies share no token, so nothing
 * in the UI can render one as the other.
 */
export type OperatorClaim =
  | 'asserted_unverified'
  | 'asserted_from_device'
  | 'asserted_from_external_evidence'
  | 'disputes_finding';

/**
 * One claim an assertion used to make, kept after an amendment replaced it.
 *
 * Every field is optional, and not out of caution: this is JSON persisted on a finding row and re-read for as long
 * as the image exists, so a revision appended by an older build simply does not carry the fields that build did not
 * write (`title` is the live example — it was added to the API's revision after the first ones were already
 * stored). A renderer states what is there and says so where something is not; it never asserts a field it cannot
 * know it owns. See the `nvd` incident in CLAUDE.md, where one required field took the image view down.
 */
export interface AssertionRevision {
  claim?: OperatorClaim;
  rationale?: string;
  /** The title the row carried while this claim stood. Absent on a revision written before it was recorded. */
  title?: string;
  /** When this claim started standing — the original assertion, or the amendment that introduced it. */
  from?: number;
  supersededAt?: number;
  disputesFindingId?: string;
}

/** Who asserted a finding, when, on what basis, and whether it still stands. */
export interface OperatorAssertion {
  assertedBy: string;
  authorKind: 'human' | 'agent';
  assertedAt: number;
  claim: OperatorClaim;
  rationale: string;
  status: 'active' | 'withdrawn';
  disputesFindingId?: string;
  withdrawnBy?: string;
  withdrawnAt?: number;
  withdrawnReason?: string;
  amendedAt?: number;
  /**
   * What this claim replaced, oldest first. Append-only on the API side: an amendment adds a revision and never
   * rewrites one, because an author restating a strong claim as a weak one with no trace is the same erasure a
   * delete performs. Absent means "never amended, or amended by a build that did not keep the predecessor" — the
   * two are distinguished by `amendedAt`, and the UI must not read a missing array as an empty history.
   */
  supersedes?: AssertionRevision[];
  /** The title as the assertion itself recorded it. The finding row's title stays authoritative for the CURRENT claim. */
  title?: string;
}

/**
 * A finding's provenance: a code-decided proof state, or the one sentinel that means a person asserted it.
 * `ProofState` stays the ladder; this is the field's full domain.
 */
export type FindingProvenance = ProofState | 'operator_assertion';

export interface Finding {
  id: string;
  imageId: string;
  source: string;
  kind: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  proofState: FindingProvenance;
  evidence?: Record<string, unknown>;
  rationale?: string;
  /**
   * HOW it was known, beside how far it was proven — a second axis, not a finer proof state. Absent means NOT
   * RECORDED (a row written before the field existed, or a provider not yet taught its channel) and is never to
   * be rendered as though it were `static_bytes`.
   */
  evidenceChannel?:
    | 'static_bytes'
    | 'symbolic_execution'
    | 'emulated_run'
    | 'probe_response'
    | 'captured_traffic'
    | 'external_advisory'
    | 'operator_report';
  /** What the workbench changed about the firmware to obtain this. Absent = the image as shipped. */
  interventions?: string[];
  /** Present iff a person or agent asserted this row rather than FirmLab measuring it. */
  assertion?: OperatorAssertion;
  createdAt: number;
}

/** An operator assertion as the ledger route serves it, with the one-line attribution already composed. */
export interface AssertedFinding extends Finding {
  attribution: string;
}

/** The operator ledger for one image, partitioned so active and retracted claims are never summed. */
export interface OperatorLedger {
  notAMeasurement: string;
  claimMeanings: Record<OperatorClaim, string>;
  measuredFindingCount: number;
  assertions: AssertedFinding[];
  withdrawn: AssertedFinding[];
}

/** A working note. Explicitly NOT a finding — never counted, never reported, never rendered as one. */
export interface ImageNote {
  id: string;
  imageId: string;
  author: string;
  body: string;
  createdAt: number;
  updatedAt: number;
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
  reasoning?: {
    thinking: 'enabled' | 'disabled';
    effort: 'high' | 'max';
    maxOutputTokens: number;
    requestTimeoutMs: number;
  };
  budget?: GovernorBudget;
  approval?: AgentApprovalState;
}

export interface AgentApprovalState {
  key: 'FIRMLAB_AGENT_PREAPPROVE';
  preapproveAll: boolean;
  source: 'override' | 'environment' | 'default';
  environmentValue: boolean;
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
  reasoningTokens: number;
  fallbackUsed: boolean;
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
    components: {
      name: string;
      version: string;
      advisories: NvdAdvisory[];
      matchedBy?: 'cpe' | 'keyword';
      /** What NVD says the true match count is — `advisories` may be a prefix of it. */
      totalMatching?: number | null;
    }[];
    /**
     * Everything below is OPTIONAL, and that is not laziness — a research result is JSON persisted on the job row
     * and re-read months later, so a stored result is data written by an OLDER version of this code and simply
     * does not have fields added since. Declaring them required made the type lie about what comes back and let a
     * `.map` on `undefined` through the compiler, which took down the whole dossier for any image analysed before
     * the field existed. Optional here turns that class of crash into a compile error at every call site.
     */
    askedByCpe?: number;
    askedByKeyword?: number;
    /** What the rate-limit cap dropped and by what rule — empty when it dropped nothing. */
    notQueriedRule?: string;
    /** Components whose CPE answer was empty while other NVD identities for the same software went unqueried. */
    uncheckedIdentities?: { name: string; version: string; identities: string[] }[];
    /** Components whose advisory list is a prefix of what NVD holds — one page is returned per question. */
    truncated?: { name: string; version: string; shown: number; total: number }[];
  };
  kev: { checked: boolean; catalogSize: number; matches: KevMatch[]; reason?: string };
  keyMaterial: { kind: string; redacted: string; effectivelyPublic: boolean; sharedInImages?: number }[];
  securityContacts: { domain: string; checked: boolean; found: boolean; reason?: string; contact: string[] }[];
  hashLookup: {
    enabled: boolean;
    reason: string;
    attempted: number;
    resolved: number;
    notQueried: number;
    entries: {
      account: string;
      source: string;
      scheme: string;
      outcome: 'resolved' | 'unverified' | 'miss' | 'skipped_salted' | 'skipped_cap' | 'skipped_other';
      verifiedAs?: string;
      passwordMasked?: string;
      manualLookupUrl?: string;
    }[];
  };
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

/**
 * One execution against this image. `status` is the process; `outcome` is what was learned, and they are separate
 * on purpose — a probe that finishes without reaching its sink is `done` and has proven nothing, while one blocked
 * by a missing device is also `done` and asked a question this deployment could not answer.
 */
export interface RunSummary {
  jobId: string;
  kind: string;
  status: string;
  startedAt: number;
  finishedAt: number | null;
  /** The binary or service this run was aimed at. Null for image-wide runs. */
  target: string | null;
  /** The specific question put to it — a sink, a harness, a platform. */
  question: string | null;
  headline: string;
  outcome: 'proven' | 'lead' | 'empty' | 'blocked' | 'failed' | 'running';
  /** The bound it ran under (a budget, an input length), so no result reads as unbounded. */
  bound: string | null;
}

export interface RunLedger {
  runs: RunSummary[];
  byTarget: { target: string | null; runs: RunSummary[] }[];
}

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

/**
 * `?lang=` for the endpoints that compose prose. Omitted entirely when no locale is passed, so the request looks
 * byte-for-byte like it did before — a caller that has not been threaded through yet is served English, which is
 * a language, rather than `?lang=undefined`, which is a bug report waiting to happen.
 */
function lang(locale?: Locale, sep: '?' | '&' = '?'): string {
  return locale ? `${sep}lang=${locale}` : '';
}
/**
 * GET whose 4xx body IS the answer.
 *
 * The file browser's guard refuses a path with the rule that refused it, and that sentence is the whole value —
 * "400 Bad Request" and "refused by the symlink rule: etc/passwd points at /dev/null, outside the extraction" are
 * the same status and completely different answers. So a refusal comes back as data, merged onto the payload the
 * route sent alongside it (the extraction verdict), and only a genuine transport failure throws.
 */
async function getOrRefusal<T extends { refusal?: { error: string; rule: string; symlinkTarget?: string } }>(
  url: string,
): Promise<T> {
  const res = await fetch(url);
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (res.ok) return body as T;
  if (typeof body.error === 'string' && typeof body.rule === 'string') {
    return {
      ...(body as object),
      refusal: {
        error: body.error,
        rule: body.rule,
        ...(typeof body.symlinkTarget === 'string' ? { symlinkTarget: body.symlinkTarget } : {}),
      },
    } as T;
  }
  throw new Error(typeof body.error === 'string' ? body.error : `${res.status} ${res.statusText}`);
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
async function put<T>(url: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method: 'PUT' };
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
/** Like `post`, but for amending something that already exists. Surfaces the route's `{ error }` verbatim — the
 *  operator routes answer a refusal with the reason (why a proof state may not be asserted, why a rationale is
 *  required), and that sentence is the whole point of the refusal. */
async function patch<T>(url: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method: 'PATCH' };
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

/** A content search over the extraction. Every field optional: this is a provider shape read back from the API. */
export interface SearchHit {
  path?: string;
  offset?: number;
  line?: number;
  excerpt?: string;
  binary?: boolean;
}

export interface FilesSearch {
  query?: string;
  hits?: SearchHit[];
  coverage?: {
    filesExamined?: number;
    entriesWalked?: number;
    skipped?: { tooLarge?: number; unreadable?: number; budgetExhausted?: number };
    walkTruncated?: boolean;
    hitCapReached?: boolean;
  };
  /** What this answer does and does not cover — rendered always, never only when something went wrong. */
  verdict?: string;
}

/** The deep static-analysis providers runnable per image; their findings appear in the dossier. */
export type AnalysisKind =
  | 'uboot'
  | 'fsaudit'
  | 'certs'
  | 'rtos'
  | 'compmap'
  | 'services'
  | 'fcc'
  | 'kernel'
  | 'binvuln'
  | 'updatepath'
  | 'devicetree';

/**
 * Shapes of the three providers whose results this UI reads field by field rather than only counting findings.
 *
 * EVERY field is optional, without exception, and that is not defensive style — it is the rule this codebase paid
 * for. A provider result is JSON on a job row, written once and re-read for as long as the image exists, so a field
 * added after a result was stored is absent from that result forever. Declaring one required made the web types
 * assert something about persisted data they cannot know, and `nvd.uncheckedIdentities.map` then took down the whole
 * image view for three of four images. Optional turns that class of crash into a compile error.
 */
export interface DtPeripheral {
  path?: string;
  kind?: 'uart' | 'watchdog' | 'spi' | 'i2c' | 'usb' | 'gpio' | 'flash' | 'mmc';
  compatible?: string[];
  status?: string;
  enabled?: boolean;
  console?: boolean;
}

export interface DtPartition {
  nodeName?: string;
  label?: string;
  offset?: number;
  size?: number;
  /** The `read-only` property is present — a request to the kernel, NOT hardware write protection. */
  declaredReadOnly?: boolean;
}

export interface DeviceTreeBlob {
  origin?: string;
  sizeBytes?: number;
  model?: string;
  compatible?: string[];
  bootargs?: string;
  bootargsFrom?: string[];
  stdoutPath?: string;
  consolePath?: string;
  partitions?: DtPartition[];
  partitionNode?: string;
  partitionNote?: string;
  peripherals?: DtPeripheral[];
  peripheralsDropped?: number;
  nestedNodesSkipped?: number;
  peripheralNote?: string;
  nodeCount?: number;
  selected?: boolean;
}

export interface DeviceTreeResult {
  available?: boolean;
  found?: boolean;
  blobs?: DeviceTreeBlob[];
  /**
   * FDT headers that validated and whose tree could not be walked to the end. `reason` is the provider's own
   * sentence and quotes offsets and token values — it is a measurement, printed as written. Never empty-meaning:
   * an entry here is a device tree this reader could not read, which is not the same as no tree being there.
   */
  rejected?: { origin?: string; sizeBytes?: number; reason?: string }[];
  /** Every place that was searched — what a `found: false` does and does not cover. */
  searched?: string[];
  findings?: unknown[];
  reason?: string;
}

export interface PostureAnswer {
  id?: string;
  option?: string;
  question?: string;
  verdict?: 'on' | 'off' | 'unknown';
  reason?: string;
  source?: string;
  detail?: string;
  bad?: boolean;
  severity?: string;
}

/**
 * The binary-hardening sweep's own result — the numbers that say whether its findings list is everything.
 *
 * Optional throughout below the first four: `relocatableSkipped`, `neuteredSkipped` and `exposedDropped` were each
 * added after results were already being persisted, and a stored row written by an older build carries none of
 * them. `0` or `[]` would be a claim about a walk that never counted.
 */
export interface BinVulnResult {
  available: boolean;
  binariesScanned: number;
  /** Candidates FOUND. `findings` holds what survived the cap, so on a busy rootfs this is the larger number. */
  candidates: number;
  findings: Finding[];
  /** `.ko`/`.o` objects the walk passed over: this sweep's question does not apply to a relocatable object. */
  relocatableSkipped?: number;
  /** Exposed binaries that still did not fit the cap — NAMED, so the shortfall is legible instead of inferable. */
  exposedDropped?: string[];
  /** Entries the extractor cut to `/dev/null`. Shipped by the firmware and destroyed by the carve, not out of scope. */
  neuteredSkipped?: number;
  reason: string;
}

/**
 * The kernel-module sweep's result.
 *
 * Every field added here is OPTIONAL forever: a result is JSON persisted on a job row and re-read for as long as
 * the image exists, so a stored result is data written by an older build. Declaring a newly-added field required
 * made `nvd.uncheckedIdentities.map` throw on a row two commits old and took down the whole image view.
 */
export interface KmodResult {
  available: boolean;
  reason: string;
  modulesFound?: number;
  notRelocatable?: number;
  symbolTableUnreadable?: number;
  provenance?: { intreeTagInUse?: boolean; licenceDeclared?: boolean; note?: string };
  callSitePass?: {
    available?: boolean;
    reason?: string;
    modulesExamined?: number;
    modulesDropped?: string[];
    sitesDropped?: number;
    sitesHoisted?: number;
    rule?: string;
  };
  modules?: KmodModule[];
  findings: Finding[];
}

export interface KmodModule {
  file: string;
  size?: number;
  identity?: {
    license?: string;
    author?: string;
    descriptions?: string[];
    version?: string;
    versionCandidate?: { value: string; from: string };
    vermagic?: string;
    depends?: string[];
    intree?: boolean;
  };
  api?: Record<string, string[]>;
  importCount?: number;
  keys?: { nonGpl?: boolean; outOfTree?: boolean; socket?: boolean; allocAndCopy?: boolean; score?: number };
  symbolsRead?: boolean;
  sites?: Array<{
    sink: string;
    addr: number;
    fn: string | null;
    evidence: { byteSwapped: boolean; compared: boolean; addend: number | null; chain: string[] } | null;
    evidenceGap?: string;
  }>;
}

export interface KernelPostureResult {
  available?: boolean;
  located?: boolean;
  version?: string | null;
  versionSource?: string | null;
  bannerPath?: string | null;
  configPath?: string | null;
  age?: { years?: number; severity?: string; detail?: string } | null;
  /**
   * The module set, as the provider records it. Every field optional and permanently so: `moduleCount` /
   * `inspectedCount` / `signedCount` are what `kernelposture.ts` writes today, `total` / `signed` are what an
   * older stored result carries, and a reader that demanded either shape would throw on the other.
   */
  modules?: {
    total?: number;
    signed?: number;
    vermagic?: string;
    moduleCount?: number;
    inspectedCount?: number;
    signedCount?: number;
  } | null;
  answers?: PostureAnswer[];
  searched?: string[];
  findings?: unknown[];
  reason?: string;
}

/**
 * Verification or flash evidence found in a file that an updater `source`s, with the chain that reached it.
 *
 * `file` is the point of the type: the lines are IN that file, not in the candidate that sources it. `sbin/sysupgrade`
 * invokes no verifier — it *reaches* one in `lib/upgrade/fwtool.sh` — and a reader must never be told the entry point
 * contains a line it does not contain. Optional throughout: a result stored before the source pass existed carries
 * none of this, and the renderer has to say "no chain was recorded" rather than "this script sources nothing".
 */
export interface SourcedEvidence {
  /** The file the lines physically live in. */
  file?: string;
  /** From the candidate to that file inclusive — the chain a reader retraces. */
  via?: string[];
  verifyCommands?: string[];
  signatureCommands?: string[];
  missingVerifiers?: string[];
  flashWrites?: string[];
  rollbackMarkers?: string[];
}

/** A `source`/`.`/`include` directive that could not be turned into a file, and the reason it could not. */
export interface UnresolvedSource {
  from?: string;
  directive?: string;
  spec?: string;
  reason?: string;
}

export interface UpdaterCandidate {
  path?: string;
  kind?: 'elf' | 'script';
  why?: string;
  symbolSource?: string;
  signatureFns?: string[];
  digestFns?: string[];
  /** The script's OWN lines only. Anything it merely reaches lives in `sourced` — a different claim. */
  verifyCommands?: string[];
  /** Verification executables the script invokes that are NOT present in the rootfs — the fail-open case. */
  missingVerifiers?: string[];
  flashWrites?: string[];
  /**
   * Evidence credited from files this script sources. A source edge is one static fact — this file names that file
   * where a POSIX shell would read it — and crediting it never raises a proof state, because sourcing a file defines
   * its functions and does not call them.
   */
  sourced?: SourcedEvidence[];
  /** Directives that named something no static read could resolve, each with why. An honest unknown, not a drop. */
  unresolvedSources?: UnresolvedSource[];
  /** Where following `source` edges stopped short — depth, cycle or file bound. A bound is not an answer. */
  sourceBounds?: string[];
  /**
   * True when the pass that follows `source` edges ran for this candidate, whatever it found. Without it an empty
   * chain is unreadable: a script that sources nothing and a result written before the pass existed are the same
   * absence. Optional forever — absent means the older build, which is exactly the case it distinguishes.
   */
  sourcesFollowed?: boolean;
}

export interface UpdatePathResult {
  available?: boolean;
  imageIntegrity?: {
    container?: string;
    containerNote?: string;
    items?: { kind?: string; strength?: string; detail?: string }[];
    siblings?: string[];
  };
  updaters?: UpdaterCandidate[];
  droppedUpdaters?: number;
  rollback?: { state?: string; evidence?: string };
  filesWalked?: number;
  elfsExamined?: number;
  elfBudgetExhausted?: boolean;
  findings?: unknown[];
  reason?: string;
}

/** What the U-Boot provider decoded — the env is a flat key/value map, so the console lives in `vars`. */
export interface UbootResult {
  available?: boolean;
  found?: boolean;
  varCount?: number;
  vars?: Record<string, string>;
  findings?: unknown[];
  reason?: string;
}

/**
 * The rootfs link-dependency graph (`providers/compmap.ts`): one node per ELF the walk found, plus one per soname
 * some binary references and the walk did NOT find, and a "needs" edge for every DT_NEEDED entry.
 *
 * Nodes are keyed by BASENAME, because a DT_NEEDED reference is a basename — two files called `busybox` in
 * different directories are one node, which is why the node count and `binaryCount` can disagree.
 *
 * Optional throughout, and not out of caution: this is JSON persisted on a job row and re-read for as long as the
 * image exists, so any result stored before a field existed simply does not carry it (see the `nvd` comment above,
 * where a required field took the image view down for three of four images).
 */
export interface CompGraphNode {
  id?: string;
  /**
   * `binary` = the walk found this file. `link` = provided only by a symlink whose target the carve holds — a
   * weaker fact than a walked file, and the reason `libc.so.0` stopped reading as missing on every uClibc rootfs.
   * `lib` = only referenced, never found — i.e. a genuinely unresolved soname.
   *
   * A result stored before link resolution existed carries no `link` nodes at all, which is why absence here means
   * "this build never looked", not "nothing is link-provided".
   */
  kind?: 'binary' | 'link' | 'lib';
}

export interface CompGraphEdge {
  from?: string;
  to?: string;
}

export interface CompGraph {
  nodes?: CompGraphNode[];
  edges?: CompGraphEdge[];
  /** Sonames referenced by some binary and absent from the entries' basenames. */
  unresolved?: string[];
}

export interface CompMapResult {
  /** False when rabin2 is absent or there is no rootfs — an empty graph that must never read as "no dependencies". */
  available?: boolean;
  graph?: CompGraph;
  /** ELF FILES walked (not graph nodes — see the basename note above). */
  binaryCount?: number;
  findings?: unknown[];
  reason?: string;
}

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

/**
 * Analysis coverage — what the image's class routes to, what actually ran, and the one honest sentence about what
 * its finding count covers. Computed server-side from the same class plan W9 executes, so the banner and the
 * autonomous scan cannot disagree.
 */
export interface CoverageStage {
  worker: string;
  reason: string;
  status: 'found' | 'ran-empty' | 'no-input' | 'degraded' | 'not-built' | 'not-run';
  detail?: string;
  findingCount?: number;
}
export interface CoverageReport {
  firmwareClass: string;
  classRationale?: string;
  applicable: number;
  executed: number;
  /** MEASURED findings only — operator assertions are counted separately and cover no stage. */
  findingCount: number;
  /** Absent from a response that predates operator assertions; treat as 0. */
  operatorAssertions?: number;
  stages: CoverageStage[];
  verdict: string;
  /** The finding count alone would mislead — show the banner prominently. */
  ambiguous: boolean;
}

/**
 * One image's coverage, compact enough for a corpus listing. Same computation as the per-image banner, so a
 * dashboard row and the image's own banner can never tell different stories about what was examined.
 */
export interface CoverageSummary {
  imageId: string;
  filename: string;
  firmwareClass: string;
  applicable: number;
  executed: number;
  findingCount: number;
  ambiguous: boolean;
  verdict: string;
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
  ceiling: string | null;
}

export interface CaptureStrategy {
  transport: string;
  positioning: string | null;
  viable: boolean;
  ceiling: string;
  reason: string;
}

export interface CapturabilityPlan {
  strategies: CaptureStrategy[];
  ceiling: string;
  reason: string;
  unlockHint: string | null;
}

export interface OtaVersion {
  imageId: string;
  filename: string;
  capturedAt: number;
  endpoint: string | null;
  transport: string | null;
  tlsPosture: string | null;
  size: number;
  firmwareClass: string | null;
}

export interface DeviceFamily {
  key: string;
  vendor: string | null;
  captures: OtaVersion[];
  transports: string[];
  endpoints: string[];
}

export interface VendorPrior {
  vendor: string;
  ships: string;
  cdns: string[];
  captureCount: number;
}

export interface LearningSurface {
  families: DeviceFamily[];
  vendorPriors: VendorPrior[];
  cdnGraph: { host: string; families: string[] }[];
}

// === The extraction browser (providers/fsbrowse.ts) ===

/** Which of the several different "nothing to show" states an image's extraction is in. */
export type ExtractionBrowseState = 'never-run' | 'in-progress' | 'failed' | 'no-output' | 'volumes-only' | 'rootfs';

export interface ExtractionBrowseView {
  state: ExtractionBrowseState;
  browsable: boolean;
  /** The sentence an empty tree must be read next to. The UI never renders the tree without it. */
  verdict: string;
  rootfsRel?: string;
  extractor?: string;
}

export interface DirEntryView {
  name: string;
  path: string;
  type: 'file' | 'dir' | 'symlink' | 'other';
  size: number;
  mode: number;
  modeString: string;
  setuid?: boolean;
  symlinkTarget?: string;
  /** The link resolves outside the extraction — reported, never followed. */
  symlinkEscapes?: boolean;
  symlinkResolved?: string;
}

export interface DirListing {
  path: string;
  entries: DirEntryView[];
  totalEntries: number;
  fileCount: number;
  dirCount: number;
  symlinkCount: number;
  truncated: boolean;
  truncationRule?: string;
  note?: string;
}

export interface ByteClassification {
  kind: 'text' | 'binary' | 'empty';
  reason: string;
  sampled: number;
  nulBytes: number;
  nonPrintable: number;
  utf8: boolean;
}

export interface FileRead {
  path: string;
  size: number;
  offset: number;
  bytesRead: number;
  truncated: boolean;
  unreadBefore: number;
  unreadAfter: number;
  truncationRule?: string;
  classification: ByteClassification;
  view: 'text' | 'hex';
  viewReason: string;
  text?: string;
  hexdump?: string;
  adjustments: string[];
  claim: string;
}

/** A path the guard refused, carrying WHICH rule refused it — the part a bare status code destroys. */
export interface PathRefusal {
  error: string;
  rule: string;
  symlinkTarget?: string;
}

export interface FilesListing {
  extraction: ExtractionBrowseView;
  listing: DirListing | null;
  claim: string;
  /** Set instead of `listing` when the path was refused; the panel renders the rule rather than an empty tree. */
  refusal?: PathRefusal;
}

export interface FilesRead {
  extraction: ExtractionBrowseView;
  read: FileRead | null;
  claim: string;
  refusal?: PathRefusal;
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
  /** `unlocks` is composed per tool by the API, so the Capabilities page asks for it in the language it renders. */
  tools: (locale?: Locale) =>
    get<{ tools: ToolStatus[]; groups: Record<string, { available: number; total: number }> }>(
      `/api/tools${lang(locale)}`,
    ),
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
  /**
   * Browse the extraction. A refused path resolves rather than throwing: the rule that refused it is the answer
   * the panel has to show, and `get`'s bare "400 Bad Request" would throw it away.
   */
  files: (id: string, path?: string) =>
    getOrRefusal<FilesListing>(`/api/images/${id}/files${path ? `?path=${encodeURIComponent(path)}` : ''}`),
  readFile: (id: string, path: string, opts?: { offset?: number; limit?: number; view?: 'text' | 'hex' }) => {
    const params = new URLSearchParams({ path });
    if (opts?.offset !== undefined) params.set('offset', String(opts.offset));
    if (opts?.limit !== undefined) params.set('limit', String(opts.limit));
    if (opts?.view !== undefined) params.set('view', opts.view);
    return getOrRefusal<FilesRead>(`/api/images/${id}/files/read?${params.toString()}`);
  },
  /** Run one of the deep static-analysis providers; findings land in the dossier. */
  runAnalysis: (id: string, kind: AnalysisKind) => post<{ jobId: string }>(`/api/images/${id}/${kind}`, {}),
  analysisResult: (id: string, kind: AnalysisKind) =>
    get<{ result: { reason?: string; findings?: unknown[] } | null }>(`/api/images/${id}/${kind}`).then(
      (r) => r.result,
    ),
  /**
   * The same GET, typed for the callers that read a provider's fields rather than only its finding count. Separate
   * from `analysisResult` so that one keeps its deliberately narrow shape — a caller that only counts findings
   * should not be handed a type inviting it to read fields a stored result may not carry.
   */
  searchFiles: (id: string, q: string, regex = false, deep = false) =>
    get<{ result: FilesSearch | null }>(
      `/api/images/${id}/files/search?q=${encodeURIComponent(q)}${regex ? '&regex=1' : ''}${deep ? '&deep=1' : ''}`,
    ).then((r) => r.result),
  deviceTree: (id: string) =>
    get<{ result: DeviceTreeResult | null }>(`/api/images/${id}/devicetree`).then((r) => r.result),
  binvuln: (id: string) => get<{ result: BinVulnResult | null }>(`/api/images/${id}/binvuln`).then((r) => r.result),
  runBinvuln: (id: string) => post<{ jobId: string }>(`/api/images/${id}/binvuln`, {}),
  kmod: (id: string) => get<{ result: KmodResult | null }>(`/api/images/${id}/kmod`).then((r) => r.result),
  runKmod: (id: string) => post<{ jobId: string }>(`/api/images/${id}/kmod`, {}),
  kernelPosture: (id: string) =>
    get<{ result: KernelPostureResult | null }>(`/api/images/${id}/kernel`).then((r) => r.result),
  runKernelPosture: (id: string) => post<{ jobId: string }>(`/api/images/${id}/kernel`, {}),
  updatePath: (id: string) =>
    get<{ result: UpdatePathResult | null }>(`/api/images/${id}/updatepath`).then((r) => r.result),
  ubootEnv: (id: string) => get<{ result: UbootResult | null }>(`/api/images/${id}/uboot`).then((r) => r.result),
  /** The stored rootfs dependency graph. `null` means nobody has built one — never "this rootfs links nothing". */
  compmapResult: (id: string) =>
    get<{ result: CompMapResult | null }>(`/api/images/${id}/compmap`).then((r) => r.result),
  listPresets: (id: string) => get<{ presets: EmulationPreset[] }>(`/api/images/${id}/presets`).then((r) => r.presets),
  savePreset: (id: string, p: { name: string; mode: EmulationPreset['mode']; binary?: string; args?: string[] }) =>
    post<{ preset: EmulationPreset }>(`/api/images/${id}/presets`, p).then((r) => r.preset),
  deletePreset: (presetId: string) => del<{ deleted: string }>(`/api/presets/${presetId}`),
  /** W9 autonomous scan: plan the class-routed worker chain, run it, compose the narrative. */
  runOpacidad: (id: string) => post<{ jobId: string }>(`/api/images/${id}/opacidad`),
  opacidadResult: (id: string) =>
    get<{ result: OpacidadResult | null }>(`/api/images/${id}/opacidad`).then((r) => r.result),
  /**
   * The verdict is recomputed from the stage table on every read and describes the analysis run, not the firmware,
   * so it is requested in the locale the banner is rendering. Stage ids and every count come back identical.
   */
  coverage: (id: string, locale?: Locale) => get<CoverageReport>(`/api/images/${id}/coverage${lang(locale)}`),
  /** Corpus-wide coverage — one row per image, so the dashboard can say what was actually examined. */
  coverageAll: (locale?: Locale) =>
    get<{ images: CoverageSummary[] }>(`/api/coverage${lang(locale)}`).then((r) => r.images),
  jobs: (id: string) => get<{ jobs: Job[] }>(`/api/images/${id}/jobs`).then((r) => r.jobs),
  job: (jobId: string) => get<{ job: Job }>(`/api/jobs/${jobId}`).then((r) => r.job),
  sbom: (id: string) => get<{ result: SbomResult | null }>(`/api/images/${id}/sbom`).then((r) => r.result),
  runSbom: (id: string) => post<{ jobId: string }>(`/api/images/${id}/sbom`),
  decompileResult: (id: string) =>
    get<{ result: DecompileResult | null }>(`/api/images/${id}/decompile`).then((r) => r.result),
  decompile: (id: string, binary: string) => post<{ jobId: string }>(`/api/images/${id}/decompile`, { binary }),
  /** Every run against this image, newest first, plus the same set grouped by what it targeted. */
  runs: (id: string, opts?: { kind?: string; scope?: 'targeted' }) =>
    get<RunLedger>(
      `/api/images/${id}/runs${opts?.kind ? `?kind=${encodeURIComponent(opts.kind)}` : opts?.scope ? `?scope=${opts.scope}` : ''}`,
    ),
  /** One run in full — its stored result, params and log, for a run that is no longer the most recent. */
  runDetail: (id: string, jobId: string) =>
    get<{ summary: RunSummary; params: unknown; result: unknown; log: string; error: string | null }>(
      `/api/images/${id}/runs/${jobId}`,
    ),
  binaries: (id: string) => get<{ binaries: BinaryEntry[] }>(`/api/images/${id}/binaries`).then((r) => r.binaries),
  /** Ask angr about ANY rootfs binary and ANY sink — not only what the W5 sweep happened to flag. */
  /** Break on an exact sink address under qemu+gdb. `addresses` is required — a reachability run produces them. */
  dynprobe: (id: string, body: { binary: string; sink: string; addresses: string[]; patternLength?: number }) =>
    post<{ jobId: string }>(`/api/images/${id}/dynprobe`, body),
  symreach: (id: string, body: { binary: string; sinks?: string[]; budgetSeconds?: number }) =>
    post<{ jobId: string }>(`/api/images/${id}/symreach`, body),
  symreachResult: (id: string) =>
    get<{ result: SymReachResult | null }>(`/api/images/${id}/symreach`).then((r) => r.result),
  /** Ask a `.so`/`.ko` the reachability question it admits — a control-flow route from an export to a sink. */
  exportreach: (id: string, body: { binary: string; sinks?: string[]; budgetSeconds?: number }) =>
    post<{ jobId: string }>(`/api/images/${id}/exportreach`, body),
  /** The route returns every done probe (one per target); the panel shows the most recent, RunHistory the rest. */
  exportreachResult: (id: string) =>
    get<{ results: ExportReachResult[] }>(`/api/images/${id}/exportreach`).then((r) => r.results.at(-1) ?? null),
  findings: (id: string) => get<{ findings: Finding[] }>(`/api/images/${id}/findings`).then((r) => r.findings),

  // === Operator assertions: the ledger's only hand-authored rows. No proofState is ever sent or accepted. ===
  operatorLedger: (id: string) => get<OperatorLedger>(`/api/images/${id}/operator-findings`),
  addAssertion: (
    id: string,
    body: {
      assertedBy: string;
      title: string;
      claim: OperatorClaim;
      rationale: string;
      severity?: Finding['severity'];
      references?: string[];
      disputesFindingId?: string;
    },
  ) => post<{ finding: Finding; attribution: string }>(`/api/images/${id}/operator-findings`, body),
  amendAssertion: (
    id: string,
    findingId: string,
    body: { title: string; claim: OperatorClaim; rationale: string; severity?: Finding['severity'] },
  ) =>
    patch<{ finding: Finding; attribution: string }>(`/api/images/${id}/operator-findings/${findingId}`, body).then(
      (r) => r.finding,
    ),
  /** Retract, never delete: the claim and the reason it was retracted both stay in the ledger. */
  withdrawAssertion: (id: string, findingId: string, body: { withdrawnBy: string; reason: string }) =>
    post<{ finding: Finding }>(`/api/images/${id}/operator-findings/${findingId}/withdraw`, body).then(
      (r) => r.finding,
    ),

  // === Working notes: reasoning that is not a claim. Deleteable, precisely because nobody relied on it. ===
  notes: (id: string) => get<{ notes: ImageNote[] }>(`/api/images/${id}/notes`).then((r) => r.notes),
  addNote: (id: string, body: { author: string; body: string }) =>
    post<{ note: ImageNote }>(`/api/images/${id}/notes`, body).then((r) => r.note),
  updateNote: (id: string, noteId: string, body: string) =>
    patch<{ note: ImageNote }>(`/api/images/${id}/notes/${noteId}`, { body }).then((r) => r.note),
  deleteNote: (id: string, noteId: string) => del<{ deleted: string }>(`/api/images/${id}/notes/${noteId}`),
  corpusRefs: (id: string) => get<{ refs: CorpusRefs }>(`/api/images/${id}/corpus-refs`).then((r) => r.refs),
  agentStatus: () => get<AgentStatus>('/api/agent/status'),
  runCopilot: (id: string) => post<{ jobId: string }>(`/api/images/${id}/copilot`),
  copilotResult: (id: string) =>
    get<{ result: CopilotResult | null }>(`/api/images/${id}/copilot`).then((r) => r.result),
  agentConfig: () => get<AgentConfig>('/api/agent/config'),
  /**
   * The lane descriptions state what leaves this machine, and they are what an operator reads BEFORE flipping a
   * switch — so all three verbs carry the locale. A write answers with the whole resolved set, and a lane switched
   * from a Spanish UI coming back in English would repaint the panel into the wrong language mid-interaction.
   */
  flags: (locale?: Locale) =>
    get<{ flags: LaneFlag[]; appliesImmediately: boolean }>(`/api/settings/flags${lang(locale)}`),
  setFlag: (name: string, enabled: boolean, locale?: Locale) =>
    put<{ flags: LaneFlag[] }>(`/api/settings/flags/${name}${lang(locale)}`, { enabled }).then((r) => r.flags),
  clearFlag: (name: string, locale?: Locale) =>
    del<{ flags: LaneFlag[] }>(`/api/settings/flags/${name}${lang(locale)}`).then((r) => r.flags),
  /** The model provider. No locale: every string in the payload is either an identifier or a provider's own id. */
  llmSettings: () => get<{ llm: LlmSettings; updatedAt: Record<string, number> }>('/api/settings/llm'),
  setLlmSetting: (key: string, value: string) =>
    put<{ llm: LlmSettings }>(`/api/settings/llm/${key}`, { value }).then((r) => r.llm),
  clearLlmSetting: (key: string) => del<{ llm: LlmSettings }>(`/api/settings/llm/${key}`).then((r) => r.llm),
  agentApproval: () => get<{ approval: AgentApprovalState }>('/api/settings/agent-approval').then((r) => r.approval),
  setAgentApproval: (preapproveAll: boolean) =>
    put<{ approval: AgentApprovalState }>('/api/settings/agent-approval', { preapproveAll }).then((r) => r.approval),
  clearAgentApproval: () =>
    del<{ approval: AgentApprovalState }>('/api/settings/agent-approval').then((r) => r.approval),
  startAgentSession: (id: string, goal?: string) =>
    post<{ session: AgentSession }>(`/api/images/${id}/agent/session`, goal ? { goal } : {}).then((r) => r.session),
  agentSession: (id: string) => get<AgentSessionView>(`/api/images/${id}/agent/session`),
  approveEmulation: (sid: string, binary?: string, all = false) =>
    post<AgentSessionView>(`/api/agent/sessions/${sid}/approve`, all ? { all: true } : binary ? { binary } : {}),
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
  // The five capabilities that had routes and no reader. `null` from any of these means the stage has NOT run —
  // distinct from a result whose `available` is false, which means it ran and this deployment could not answer.
  yarascanResult: (id: string) =>
    get<{ result: YaraScanResultView | null }>(`/api/images/${id}/yarascan`).then((r) => r.result),
  runYarascan: (id: string) => post<{ jobId: string }>(`/api/images/${id}/yarascan`),
  fwhuntResult: (id: string) =>
    get<{ result: FwHuntResultView | null }>(`/api/images/${id}/fwhunt`).then((r) => r.result),
  runFwhunt: (id: string, moduleBatch?: number, restart = false) =>
    post<{ jobId: string }>(`/api/images/${id}/fwhunt`, {
      ...(moduleBatch === undefined ? {} : { moduleBatch }),
      ...(restart ? { restart: true } : {}),
    }),
  nvramResult: (id: string) => get<{ result: NvramResultView | null }>(`/api/images/${id}/nvram`).then((r) => r.result),
  runNvram: (id: string) => post<{ jobId: string }>(`/api/images/${id}/nvram`),
  funcdiffResult: (id: string, against: string) =>
    get<{ result: FuncDiffResultView | null }>(
      `/api/images/${id}/funcdiff?against=${encodeURIComponent(against)}`,
    ).then((r) => r.result),
  dynprobeResult: (id: string) =>
    get<{ result: DynProbeResultView | null }>(`/api/images/${id}/dynprobe`).then((r) => r.result),
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
  /**
   * `unlocks` is composed per backend by the API from the hardware and privileges present at request time, so the
   * Capture page asks for it in the language it renders. The ids, the transports and each probe's own reason are
   * what this deployment answered and come back identical either way.
   */
  captureBackends: (locale?: Locale) => get<CaptureBackendsView>(`/api/capture/backends${lang(locale)}`),
  captureDevices: () => get<{ devices: CaptureDevice[] }>('/api/capture/devices').then((r) => r.devices),
  runCaptureDiscover: (subnet: string | null, acknowledged: boolean) =>
    post<{ scanId: string }>('/api/capture/discover', { ...(subnet ? { subnet } : {}), acknowledged }),
  captureScan: (scanId: string) => get<CaptureScanView>(`/api/capture/discover/${scanId}`),
  capturePreflight: (deviceId: string) =>
    get<{ device: CaptureDevice; plan: CapturabilityPlan }>(`/api/capture/preflight/${deviceId}`).then((r) => r.plan),
  captureFamilies: () => get<LearningSurface>('/api/capture/families'),
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

/**
 * A network/AI lane the operator can switch at runtime, with everything needed to decide: what turns on, what
 * leaves the machine, whether the environment or a stored override is deciding, and whether it is on-but-inert
 * because the lane it depends on is off.
 */
/**
 * The model provider as Settings describes it. Every field says whether the ENVIRONMENT or an OVERRIDE won, the
 * same contract the lane flags have.
 *
 * **The API key is described and never disclosed.** There is no field here that holds it: `present` says whether
 * one exists, `tail` is its last four characters — enough to tell two keys apart, useless as a credential — and
 * `envVar` names where the deployment would read it from instead. A type that could carry the key would be one
 * refactor away from rendering it.
 */
export interface LlmFieldState {
  value: string;
  source: 'override' | 'environment' | 'default';
}

export interface LlmSettings {
  provider: LlmFieldState;
  model: LlmFieldState;
  baseUrl: LlmFieldState;
  apiKey: {
    present: boolean;
    source: 'override' | 'environment' | 'default';
    tail: string;
    envVar: string;
  };
  /** True when a model would actually be contacted. */
  ready: boolean;
  /** Empty when ready; otherwise what is missing, in words — never a silently absent copilot. */
  reason: string;
  providers: string[];
  defaultModels: Record<string, string>;
}

export interface LaneFlag {
  name: string;
  label: string;
  effect: string;
  egress: string;
  requires?: string;
  outward: boolean;
  enabled: boolean;
  source: 'override' | 'environment' | 'default';
  environmentValue: boolean;
  inert: boolean;
  overriddenAt?: number;
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
