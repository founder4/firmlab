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
  /**
   * Why the probe said no — `missing` is genuinely absent, `timeout` is installed and did not answer inside its
   * probe budget, `error` is installed and refused. OPTIONAL FOREVER: an API build older than this field answers
   * without it, and a page that required it would assert something it cannot know.
   */
  outcome?: 'missing' | 'timeout' | 'error';
  /** The API's sentence for `outcome`, already in this page's language. Absent for the same reasons. */
  outcomeReason?: string;
  /**
   * The DATA this tool answers from, for the tools that need one — grype and its vulnerability database today.
   * A tool can be `available: true` and still be unable to answer, which is a second axis and not a worse value
   * of the first. OPTIONAL FOREVER, and absent means this tool needs no dataset, NEVER that its dataset is fine:
   * an API build older than this field answers without it, and a page that read absence as readiness would make
   * exactly the overstatement the field was added to remove.
   */
  dataset?: { ready: boolean; detail: string };
}

export interface CapabilityClassPlan {
  classId: string;
  stages: Array<{
    worker: string;
    reason: string;
    needsRootfs: boolean;
    built: boolean;
    provider?: string;
  }>;
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
  /** Static Intel flash-descriptor reading (`providers/spi-descriptor.ts`). Optional forever, like every field in it. */
  spiDescriptor?: SpiDescriptorView;
}

export type SpiGrantVerdict = 'granted' | 'denied' | 'layout-dependent' | 'unknown';

/** What the shipped descriptor says; never the live FRAP/PRx registers, which `runtimeRegisterPosture` states unknown. */
export interface SpiDescriptorView {
  status?: 'parsed' | 'unknown';
  reason?: string;
  regions?: { name?: string; enabled?: boolean; startBytes?: number | null; endBytesExclusive?: number | null }[];
  runtimeRegisterPosture?: { state?: string; reason?: string };
  hostMasterAccess?: {
    status?: 'read' | 'unknown';
    reason?: string;
    descriptorWrite?: SpiGrantVerdict;
    meWrite?: SpiGrantVerdict;
    meWriteReason?: string;
  };
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
  probeVersion?: number;
  revalidation?: { required: boolean; reason: string };
  available: boolean;
  reason: string;
  target: string;
  requests: number;
  points: number;
  coverage?: {
    discoveredPoints: number;
    eligiblePoints: number;
    plannedPoints: number;
    attemptedPoints: number;
    completedPoints: number;
    skippedUnsupportedMethod: number;
    skippedPointLimit: number;
    skippedBudget: number;
    requestBudget: number;
    budgetExhausted: boolean;
    failedRequests: number;
  };
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
  vendorVex?: VendorVexSearchSummary;
  available: boolean;
  reason?: string;
  target: string;
  packageCount: number;
  /** True totals from syft/grype. Optional forever — a result stored by an older build carries neither. */
  packageTotal?: number;
  vulnerabilityTotal?: number;
  packages: { name: string; version: string; type: string }[];
  grypeAvailable: boolean;
  /**
   * Why CVE matching did not run, and what it ran against. Optional forever, like the totals above: a result
   * stored before the SBOM lane stopped downloading its database on its own has neither, and its
   * `grypeAvailable:false` really did mean "grype is not installed".
   */
  grypeReason?: string;
  grypeDb?: { schemaVersion: string | null; built: string | null; from: string | null; ageDays: number | null };
  /**
   * CISA KEV membership as grype's OWN database annotated this run's matches — offline, and deliberately not the
   * research lane's KEV cross-reference. Optional forever: absent is "not asked" (grype did not match, or the
   * result predates the field), `no-kev-provider` is unknown, and only `annotated` with an empty list is a zero.
   */
  grypeKev?: GrypeKev;
  vulnerabilities: SbomVuln[];
  counts: Record<Severity, number>;
}

/** One CVE grype's KEV snapshot lists, with every match id (CVE, GHSA, distro) that carried it. */
export interface GrypeKevMatch {
  cve: string;
  vulnerabilityIds: string[];
  packages: string[];
  dateAdded: string;
  knownRansomware: string;
}

export type GrypeKev =
  | { state: 'annotated'; captured: string; matches: GrypeKevMatch[] }
  | { state: 'no-kev-provider'; reason: string };

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
  symbolsTotal?: number;
  importsTotal?: number;
  stringsTotal?: number;
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

/**
 * A shared object is asked from its EXPORTS under unconstrained arguments — a weaker claim than entry-point
 * reachability, so its outcomes live here and never in `sinks`.
 */
export interface LibraryReach {
  entryPointsTotal: number;
  entryPointsConsidered: number;
  maxEntryPoints: number;
  entryPointSource?: string;
  sinks: (SinkResult & { reachedFrom?: string; entryPointsAttempted?: number; entryPointsCompleted?: number })[];
}

export interface SymReachResult {
  available: boolean;
  reason: string;
  binary: string;
  arch?: string;
  entry?: string;
  /** Absent on results stored before the library rung existed, and absent is `executable`. */
  mode?: 'executable' | 'library';
  library?: LibraryReach;
  /** Entry-point outcomes only — empty in library mode. */
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

/**
 * credmatch — the JOIN of an image's stored credential hashes against its own printable strings. NOT a crack: a hit
 * means the plaintext is written down in the firmware, so the recovered password is `static_confirmed` and a miss is
 * a BOUNDED NEGATIVE, never "the password is strong".
 *
 * Every detail field is optional-tolerant even though this is a new result type: a persisted job result is JSON
 * re-read for as long as the image exists, so the panel reads `candidates`/`targets` defensively and never asserts a
 * nested field it cannot know an older build wrote. `candidates: null` (no set was built) is deliberately distinct
 * from a set that matched nothing — the coverage numbers are only present when a set existed.
 */
export type CredMatchState = 'no_target' | 'no_account_files' | 'no_hashes' | 'no_candidates' | 'scanned';

/** Where a candidate came from — rendered verbatim so a hit's provenance can be gone and looked at. */
export interface CredMatchCandidate {
  value: string;
  derivation: string;
  key?: string;
  file: string;
  offset: number;
}

/** One stored hash and what this run established about it — the three outcomes stay disjoint. */
export type CredMatchTargetOutcome =
  | { outcome: 'recovered'; password: string; candidate: CredMatchCandidate; tested: number }
  | { outcome: 'not-recovered'; tested: number; collapsed: number }
  | { outcome: 'blocked'; reason: string };

export interface CredMatchTarget {
  account: string;
  uid: number | null;
  file: string;
  scheme: string;
  schemeLabel: string;
  hashRedacted: string;
  locked: boolean;
  result: CredMatchTargetOutcome;
}

/** How the candidate set was built, and every bound that kept it from being larger. */
export interface CredMatchCandidateSummary {
  root: string;
  filesFound: number;
  filesRead: number;
  filesTooLarge: number;
  filesUnreadable: number;
  dirsUnreadable: number;
  deepDirsSkipped: number;
  bytesRead: number;
  stringsHarvested: number;
  candidatesDistinct: number;
  candidatesTested: number;
  candidatesDropped: number;
  cap: number;
  capRule: string;
  minStringLength: number;
  maxCandidateLength: number;
}

/** Which openssl `passwd` flags this deployment could verify against a known answer. A scheme it cannot compute is blocked, not clean. */
export interface CredMatchOpenssl {
  available: boolean;
  verifiedFlags: string[];
  failures: Array<{ flag: string; reason: string }>;
}

export interface CredMatchResult {
  /** True once the run reached candidate testing; false for the four states blocked before hashing anything. */
  available?: boolean;
  state?: CredMatchState;
  reason?: string;
  /** Null whenever no candidate set was ever built — distinct from a set that matched nothing. */
  candidates?: CredMatchCandidateSummary | null;
  targets?: CredMatchTarget[];
  openssl?: CredMatchOpenssl;
  /**
   * The provider's own findings. The panel does NOT render them — the findings ledger owns that view under source
   * `credmatch`, and a second table here would be the same rows twice. Typed only so the shape is documented.
   */
  findings?: unknown[];
}

export interface GitleaksFinding {
  rule: string;
  description: string;
  file: string;
  line: number;
  match: string;
  /** Exact secret in new local results; older persisted scans only carry the redacted match. */
  value?: string;
  entropy?: number;
  context?: string;
  lineText?: string;
}

export interface GitleaksResult {
  available: boolean;
  reason?: string;
  target: string;
  findingCount: number;
  /** True total before the listing cap; when it exceeds findingCount the table is a truncated view. */
  total?: number;
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
    /** Pre-cap counts. Optional forever — a diff stored by an older build has none. */
    addedTotal?: number;
    removedTotal?: number;
    changedTotal?: number;
  };
  cves: {
    hasData: boolean;
    addedIds: string[];
    removedIds: string[];
    addedBySeverity: Record<Severity, number>;
    /** Pre-cap counts. Optional forever — a diff stored by an older build has none. */
    addedTotal?: number;
    removedTotal?: number;
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
  /** How many functions this result LISTS — always `functions.length`, never a denominator. */
  functionCount: number;
  functions: GhidraFunction[];
  /**
   * The real totals from the post-script. `eligibleCount` excludes thunks and externals, which are never
   * decompiled, so it is the denominator `functions.length` was drawn from. Optional forever — a result stored
   * before the script counted anything has neither, and absent is not "complete".
   */
  functionTotal?: number;
  eligibleCount?: number;
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
  stores?: {
    offset?: number;
    headerBytes?: number;
    bodyOffset?: number;
    recordCount?: number;
    malformedCount?: number;
    terminated?: boolean;
    confidence?: 'crc-verified' | 'structural';
    records?: { key: string; value: string; offset: number }[];
    duplicateKeys?: string[];
    capped?: string | null;
    crc?: { stored: number; regionSize: number } | null;
  }[];
  findings?: unknown[];
}

export interface FsAuditResultView {
  available: boolean;
  reason?: string;
  recoveredValues?: {
    kind: 'shadow-hash' | 'empty-password' | 'private-key';
    path: string;
    value: string;
    account?: string;
    label?: string;
    offset?: number;
  }[];
}

/** One changed/added/removed function in a binary diff. `delta` is newer minus older, present on `changed`. */
export interface FuncDiffFunctionView {
  name: string;
  status: 'changed' | 'added' | 'removed';
  delta?: { size: number; nbbs: number; cc: number; ninstrs: number };
}

/**
 * One binary pair's function diff. `functions` is WITHHELD (empty) on a `recompiled` verdict by the provider, because
 * a list that long localizes nothing — so an empty list there is not "no change".
 */
export interface FuncDiffBinaryView {
  path: string;
  verdict: 'identical' | 'patched' | 'recompiled' | 'incomparable';
  matched?: number;
  changed?: number;
  added?: number;
  removed?: number;
  /** Functions whose fingerprint was ambiguous on one side, so pairing them would have been guesswork. */
  unmatchable?: number;
  functions?: FuncDiffFunctionView[];
  reason?: string;
}

/**
 * `providers/funcdiff-run.ts` `FuncDiffResult`, as far as this client reads it. The server field is `diffs`; an
 * earlier version of this type declared `binaries`, which the server never sends. Optional beyond the shared
 * contract, for the persisted-result reason above.
 */
export interface FuncDiffResultView {
  available: boolean;
  reason?: string;
  older?: string;
  newer?: string;
  /** Binaries present at the same path in both rootfs. */
  paired?: number;
  /** Of those, byte-identical (skipped). */
  identical?: number;
  analyzed?: number;
  /** Differing pairs NOT compared because the per-run cap was reached. */
  notAnalyzed?: number;
  /** A rootfs walk hit its budget, so `paired` is a floor. Absent means "not recorded", never "complete". */
  walkTruncated?: boolean;
  diffs?: FuncDiffBinaryView[];
  /** Optional forever: older saved runs did not record decompiled hunks. */
  textDiffs?: {
    binary: string;
    function: string;
    decompiler: 'pdg' | 'pdc';
    headline: string;
    looksTargeted: boolean;
    unified: string;
    stats?: { added: number; removed: number; unchanged: number; truncated: boolean };
  }[];
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
  status: 'queued' | 'running' | 'done' | 'error' | 'cancelling' | 'cancelled';
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
  /**
   * Who stated this claim: the amendment that introduced it, mirroring `from`. Absent means the original author
   * did — or that the build that superseded it recorded no editor. Never read it as the current author's.
   */
  amendedBy?: string;
  amendedByKind?: 'human' | 'agent';
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
  /**
   * Over which transport it was retracted. Absent means NOT RECORDED, and unlike `amendedByKind` that case is
   * ordinary rather than historical: `withdrawnBy` predates this field, so every row retracted by an older build
   * has the name and not the kind. Rendering the gap as "human" would state the very thing that was not recorded.
   */
  withdrawnByKind?: 'human' | 'agent';
  withdrawnAt?: number;
  withdrawnReason?: string;
  amendedAt?: number;
  /**
   * Who made the last amendment, and over which transport. Separate from `assertedBy` because anyone may amend
   * anyone's claim: absent means NOT RECORDED (a row amended before the API kept it), never "the author did it".
   */
  amendedBy?: string;
  amendedByKind?: 'human' | 'agent';
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

/** Result of retiring one computed source via DELETE /images/:id/findings. */
export interface RetireFindingsResult {
  source: string;
  dryRun: boolean;
  removedCount: number;
  removed: { kind: string; title: string; proofState: string }[];
  summary: string;
  note?: ImageNote;
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
  /** Optional for deployments predating the runtime posture contract. */
  phase4?: {
    isolation: 'full' | 'partial' | 'none';
    netns?: '-n' | '-rn' | null;
    resourceLimits?: boolean;
    autoRun?: boolean;
  };
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
  /** The advisories this record derives from — where a distro record names its CVE. Absent on older results. */
  upstream?: string[];
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
  vendorVex?: VendorVexSearchSummary;
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
    components: {
      name: string;
      version: string;
      ecosystem: string | null;
      advisories: OsvAdvisory[];
      /** How many advisories OSV held. Absent on results stored before the listing carried its denominator. */
      totalMatching?: number;
    }[];
    /** Answerable components the per-run query cap dropped; absent on results stored before the cap said so. */
    notQueried?: number;
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
  kev: {
    checked: boolean;
    catalogSize: number;
    matches: KevMatch[];
    reason?: string;
    /**
     * Why there is no verdict, machine-readable. `no-input` means nothing upstream produced a CVE id, so the
     * catalog was never requested — the opposite of a count of zero. Optional: a result stored before this
     * existed carries only `reason`, and the panel must still render it.
     */
    notCheckedCode?: 'no-input' | 'fetch-failed';
    /** How many CVE ids went into the cross-reference. Absent on results stored before it was recorded. */
    inputCveCount?: number;
  };
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
  /**
   * How many reused credentials / prevalent component versions exist, counted before the listing cap. The two
   * arrays are a ranked prefix of these. Optional: a deployment older than the totals sends neither, and the page
   * then shows what it has without claiming it is everything.
   */
  credentialReuseTotal?: number;
  componentPrevalenceTotal?: number;
  listing?: { cap: number; rule: string };
  sbomImageCount: number;
  deviceFamilies: { familyKey: string; images: ImageRef[] }[];
}

/** Report returned by POST /api/corpus/reindex. */
export interface CorpusReindexReport {
  imageCount: number;
  sources: {
    source: string;
    imagesWithInput: number;
    imagesWithoutInput: number;
    rowsOffered: number;
    rowsInserted: number;
  }[];
  boundedInputs: { imageId: string; filename: string; kind: string; covered: number; total: number }[];
  unrecordedBounds: { kind: string; imageCount: number }[];
  unstampedCredentials: { imageId: string; filename: string; rows: number }[];
  notReconciled: { table: string; reason: string }[];
  verdict: string;
}

/**
 * One image's line in POST /api/analysis/reanalyze-all. `before`/`after` are firmware-class identifiers; `before` is
 * null when the image never had a stored identity. On `error` the stored analysis was left alone, so `after` repeats
 * `before` — it is the class the image still plans against, not a result of the failed run.
 */
export interface ReanalyzeRow {
  id: string;
  filename: string;
  before: string | null;
  after: string | null;
  error?: string;
}

/** POST /api/analysis/reanalyze-all: the intake analysis recomputed from every image's stored bytes. */
export interface ReanalyzeAllReport {
  total: number;
  changed: number;
  failed: number;
  results: ReanalyzeRow[];
}

/** POST /api/images/:id/analysis: one image's intake analysis recomputed from its stored bytes. */
export interface ReanalyzeImageResult {
  id: string;
  before: string | null;
  after: string | null;
  changed: boolean;
  identity: ImageIdentity;
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

/** Saved static leads: every result field is optional because older jobs may lack newer coverage/evidence. */
export interface SwitchFamilyEvidence {
  lane?: 'raw' | 'rootfs';
  path?: string;
  offset?: number;
  context?: string;
  matchedText?: string;
  ruleId?: string;
}

export interface SwitchFamilyRead {
  /** `not-scanned`: no byte was read in any lane, so nothing was observed either way (newer builds only). */
  verdict?: 'single-family-lead' | 'template-only' | 'ambiguous' | 'vendor-only' | 'none-observed' | 'not-scanned';
  summary?: string;
  candidates?: {
    family?: string;
    standing?: 'exact-literal' | 'family-template';
    distinctTokens?: string[];
    hitCount?: number;
    evidence?: SwitchFamilyEvidence[];
  }[];
  vendorMentions?: {
    vendor?: string;
    count?: number;
    sources?: { lane?: 'raw' | 'rootfs'; path?: string; offsets?: number[] }[];
  }[];
  deferred?: { what?: string; reason?: string }[];
  coverage?: {
    bytesTotal?: number;
    bytesScanned?: number;
    completed?: boolean;
    stoppedBy?: string;
    maxScanBytes?: number;
    maxHitsPerRule?: number;
    rulesAttempted?: string[];
    recordsDropped?: { ruleId?: string; dropped?: number }[];
    edgeUnresolved?: number;
    statement?: string;
  };
}

export interface SwitchFamilyFile {
  lane?: 'raw' | 'rootfs';
  path?: string;
  fileBytes?: number;
  result?: SwitchFamilyRead;
}

export interface SwitchFamilyAnalysis {
  raw?: {
    status?: 'completed' | 'partial' | 'error';
    reason?: string;
    file?: SwitchFamilyFile | null;
    result?: SwitchFamilyRead | null;
  };
  rootfs?: {
    status?: 'completed' | 'partial' | 'not-run' | 'error';
    reason?: string;
    result?: SwitchFamilyRead | null;
    files?: SwitchFamilyFile[];
    coverage?: {
      limits?: { maxFiles?: number; maxBytesPerFile?: number; maxTotalBytes?: number; maxEntries?: number };
      selection?: string;
      inventoryComplete?: boolean;
      entriesExamined?: number;
      filesDiscovered?: number;
      filesExamined?: number;
      filesSkipped?: number;
      filesTruncated?: number;
      /** Per-file details retained/omitted after scanning, not files skipped by a scan cap. Absent on older jobs. */
      fileResultsRetained?: number;
      fileResultsOmitted?: number;
      fileResultsSelection?: string;
      bytesScanned?: number;
      symlinksSkipped?: number;
      specialFilesSkipped?: number;
      errors?: { path?: string; reason?: string }[];
    };
  };
  overall?: SwitchFamilyRead;
}

/**
 * FreeRTOS RAM-snapshot walk (`POST/GET /images/:id/rtos/tasks`). The request mirrors the API contract exactly:
 * layout is DECLARED, never defaulted. The result is persisted on a job row, so every field is optional forever.
 */
export interface RtosTaskSnapshotInput {
  memory: { base: number; endian: 'little' | 'big'; pointerWidth: 4 | 8; bytesBase64: string };
  symbols: {
    pxCurrentTCB?: number | null;
    readyLists?: { priority: number; address: number | null }[];
    /**
     * The whole `pxReadyTasksLists` array instead of `readyLists` (the API refuses both): the base and, as DECLARED
     * for the build, `configMAX_PRIORITIES` and `sizeof(List_t)`; `symbolSize` is the symbol's `st_size`, if known.
     */
    readyListArray?: { base: number | null; maxPriorities: number; listSize: number; symbolSize?: number | null };
    /** A name containing "overflow" makes the lane `delayed_overflow`; the API defaults to `xDelayedTaskList<n>`. */
    delayedLists?: { name?: string; address: number | null }[];
    /** Omitted → not walked; null → a `missing_symbol` lane. Same for the two below. */
    suspendedList?: number | null;
    pendingReadyList?: number | null;
    terminatedList?: number | null;
  };
}

export type RtosListKind = 'ready' | 'delayed' | 'delayed_overflow' | 'suspended' | 'pending' | 'terminated';

export interface RtosTaskLane {
  coverage?: 'complete' | 'cycle_capped' | 'truncated' | 'out_of_range' | 'missing_symbol';
  attempted?: number;
  completed?: number;
  tasks?: { listItemAddress?: number; itemValue?: number; tcbAddress?: number }[];
  evidence?: string[];
  priority?: number | null;
  listAddress?: number | null;
  bytesAttempted?: number;
  bytesCompleted?: number;
  /** `uxNumberOfItems` from the list header; on ready lanes only when they were derived from the array. */
  declaredItems?: number | null;
  /** Visited items whose `pxContainer` does not point back to this list (same condition as `declaredItems`). */
  containerMismatches?: number;
}

/** A delayed, suspended, pending-ready or waiting-termination lane. Only `wake_tick` values are wake ticks. */
export interface RtosNamedListLane extends RtosTaskLane {
  kind?: RtosListKind;
  name?: string;
  itemValueMeaning?: 'wake_tick' | 'event_order' | 'not_maintained';
  orderViolations?: number;
}

export interface RtosTaskSnapshotResult {
  proofState?: ProofState;
  coverage?: 'complete' | 'partial' | 'none';
  summary?: string;
  snapshot?: { base?: number; endian?: 'little' | 'big'; pointerWidth?: 4 | 8; bytesSupplied?: number };
  limits?: { maxSnapshotBytes?: number; maxListItems?: number; maxReadyLists?: number; maxDelayedLists?: number };
  currentTask?: {
    coverage?: 'complete' | 'out_of_range' | 'truncated' | 'missing_symbol';
    tcbAddress?: number | null;
    evidence?: string[];
    pxCurrentTcbAddress?: number | null;
    bytesAttempted?: number;
    bytesCompleted?: number;
  };
  readyLists?: RtosTaskLane[];
  totals?: { nodesAttempted?: number; nodesCompleted?: number; bytesAttempted?: number; bytesCompleted?: number };
  delayedLists?: RtosNamedListLane[];
  suspendedList?: RtosNamedListLane;
  pendingReadyList?: RtosNamedListLane;
  terminatedList?: RtosNamedListLane;
  unwalkedKinds?: RtosListKind[];
  tcbsOnSeveralLists?: number[];
  /** Present only when the ready lists were declared as the `pxReadyTasksLists` array. */
  readyListArray?: {
    base?: number | null;
    maxPriorities?: number;
    listSize?: number;
    stride?: number;
    symbolSize?: number | null;
    sizeCrossCheck?: 'agrees' | 'not_available';
  };
}

/**
 * FreeRTOS kernel symbols read from the image's own ELF (`POST/GET /images/:id/rtos/elf-symbols`). Link-time
 * addresses, never runtime proof; a raw or stripped image is a stated reason, never "no FreeRTOS". Persisted on a job
 * row, so every field is optional forever.
 */
export type RtosElfSymbolStatus =
  | 'resolved'
  | 'ambiguous'
  | 'absent'
  | 'not-examined'
  | 'undefined-only'
  | 'unavailable';

export type RtosElfSymbolsVerdict =
  | 'symbols-read'
  | 'no-section-headers'
  | 'no-static-symbol-table'
  | 'sections-not-examined'
  | 'static-symbol-table-unreadable'
  | 'refused'
  | 'file-too-large'
  | 'file-unreadable';

export interface RtosElfSymbolCandidate {
  /** Present only for an absolute (ET_EXEC) image whose value fits a number. */
  address?: number | null;
  valueHex?: string;
  size?: number | null;
  sizeHex?: string;
  binding?: string;
  type?: string;
  sectionIndex?: number;
  segments?: { index?: number; fileBacked?: boolean }[];
  entries?: number;
}

export interface RtosElfSymbolResolution {
  name?: string;
  variant?: 'single-core' | 'smp';
  status?: RtosElfSymbolStatus;
  candidates?: RtosElfSymbolCandidate[];
  note?: string;
}

export interface RtosElfSymbolsResult {
  verdict?: RtosElfSymbolsVerdict;
  summary?: string;
  file?: { bytes?: number | null; maxBytes?: number; read?: boolean; error?: string };
  refusal?: { code?: string; detail?: string };
  identity?: {
    elfClass?: 'elf32' | 'elf64';
    pointerWidth?: 4 | 8;
    endian?: 'little' | 'big';
    machine?: number;
    machineName?: string;
    type?: number;
    addressBasis?: 'absolute' | 'load-base-relative' | 'section-relative' | 'unknown';
  };
  coverage?: { statement?: string; symbolsDropped?: number; sectionsDropped?: number };
  complete?: boolean;
  smpVariantPresent?: boolean;
  symbols?: RtosElfSymbolResolution[];
  /** Snapshot-contract fields; a null is a name that did not resolve to exactly one absolute address. */
  prefill?: {
    pxCurrentTCB?: number | null;
    delayedLists?: { name?: string; address?: number | null }[];
    suspendedList?: number | null;
    pendingReadyList?: number | null;
    terminatedList?: number | null;
    /** `pxReadyTasksLists`' address and raw `st_size` only; the two declared numbers never come from the ELF. */
    readyListArray?: { base?: number | null; symbolSize?: number | null };
  } | null;
  notCarried?: { name?: string; reason?: string }[];
  bounds?: { maxFileBytes?: number; maxSections?: number; maxSymbols?: number; maxProgramHeaders?: number };
}

/**
 * RAM snapshot dumped from bounded Renode emulation (`POST/GET /images/:id/rtos/ram-capture`).
 * Stored on a job row, so every field remains optional forever.
 */
export interface RenodeRamCaptureResult {
  available?: boolean;
  ran?: boolean;
  captured?: boolean;
  reason?: string;
  proofState?: ProofState;
  platform?: string | null;
  region?: { name?: string; base?: number; size?: number } | null;
  bytesBase64?: string | null;
  bytes?: string | null;
  bytesCaptured?: number;
  seconds?: number;
  secondsRun?: number;
  layout?: {
    endian?: 'little' | 'big';
    pointerWidth?: 4 | 8;
  };
  remoteResourcesRefused?: string[];
  command?: string;
  isolation?: string;
}

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
  /** Absent on results stored before extracted-file coverage was recorded. */
  extractionScan?: {
    candidateFiles?: number;
    filesRead?: number;
    skippedByFileCap?: number;
    skippedOversize?: number;
    skippedUnreadable?: number;
    traversalComplete?: boolean;
    directoriesVisited?: number;
    fileCap?: number;
    selectionRule?: string;
  };
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

/**
 * A vendor VEX verdict riding on a CVE row as `evidence.vendorVex` (kernel-cve, kernel-cve-candidate, sbom). A claim
 * the vendor shipped in the image, never a measurement: it changes no proof state, severity or row. Read off
 * `Finding.evidence`, which is untyped JSON from a stored row, so every field is optional and checked before use.
 */
export type VendorVexVerdictKind =
  | 'vendor_states_fixed'
  | 'vendor_states_not_affected'
  | 'vendor_states_affected'
  | 'vendor_under_investigation'
  | 'conflicting';

export interface VendorVexRowVerdict {
  verdict?: string;
  basis?: string;
  sourcePath?: string | null;
  statementIndex?: number | null;
  justification?: string | null;
  sources?: {
    sourcePath?: string | null;
    statementIndex?: number | null;
    status?: string;
    justification?: string | null;
  }[];
  rationale?: string;
}

/**
 * What the kernel-posture run searched for in the rootfs (`KernelPostureResult.vendorVex`). Absent on a result stored
 * before the search existed or run without a rootfs: absence cannot establish whether a search ran.
 */
export interface VendorVexCoverage {
  [key: string]: unknown;
  rule?: string;
  /** Discovery ranking before file/byte caps. Not recorded by older builds. */
  selectionRule?: string;
  candidatesFound?: number;
  examined?: number;
  parsed?: number;
  refused?: number;
  droppedByFileCap?: number;
  droppedByByteCap?: number;
  symlinksSkipped?: number;
  entriesVisited?: number;
  walkTruncated?: boolean;
  bytesRead?: number;
  caps?: {
    [key: string]: unknown;
    maxFiles?: number;
    maxTotalBytes?: number;
    maxDocumentBytes?: number;
    maxEntries?: number;
  };
  statement?: string;
  unreadableDirectories?: number;
  unreadableDirectoryPaths?: string[];
  unmatchableIdentities?: number;
  unmatchableIdentityExamples?: {
    [key: string]: unknown;
    sourcePath?: string;
    statementIndex?: number;
    identity?: string;
    reason?: string;
  }[];
  documents?: VendorVexDocumentSummary[];
  refusals?: { [key: string]: unknown; path?: string; reason?: string; message?: string }[];
}

/** Persisted summaries are optional forever, including their nested fields and future omission counters. */
export interface VendorVexDocumentSummary {
  [key: string]: unknown;
  path?: string;
  format?: string;
  statements?: number;
  droppedStatementsCount?: number;
  droppedProductsCount?: number;
  ignoredNonCveCount?: number;
  unrecognisedStatusCount?: number;
  unrecognisedStatusExamples?: { [key: string]: unknown; vulnerabilityId?: string; status?: string }[];
  unreadStructureCount?: number;
  unreadStructureExamples?: { [key: string]: unknown; vulnerabilityId?: string; kind?: string; reference?: string }[];
  unreadStructureRule?: string;
  boundsRule?: string;
  author?: string | null;
  timestamp?: string | null;
}

/** Absent attempted is unknown, never a zero or a positive record that the search did not run. */
export interface VendorVexSearchSummary extends VendorVexCoverage {
  attempted?: boolean;
  notAttemptedReason?: string;
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
    moduleInventoryComplete?: boolean;
  } | null;
  answers?: PostureAnswer[];
  configOptions?: Array<{ option: string; state: 'on' | 'off' | 'unknown'; evidence: string | null }>;
  cves?: Array<{
    id: string;
    impact: 'LPE' | 'RCE' | 'DoS';
    state: 'applicable' | 'ruled_out' | 'unknown';
    reason: string;
    note: string;
  }>;
  searched?: string[];
  findings?: unknown[];
  reason?: string;
  vendorVex?: VendorVexCoverage;
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
  /** Optional forever: absent on stored results that predate the loader-derived key audit. */
  loaderKeyAudit?: {
    attempted?: boolean;
    completed?: boolean;
    leadsFound?: number;
    scan?: { bytesRead?: number; totalBytes?: number; complete?: boolean };
  };
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
    vendorVex?: VendorVexSearchSummary;
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
  /** An LLM narrative was produced and discarded for stopping at the token ceiling. Optional forever. */
  narrativeLlmTruncated?: boolean;
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
  /** Structured next move for a degraded stage. Absent on stored runs that predate remedy declarations. */
  remedy?: CoverageRemedy;
}
export type CoverageRemedy =
  | 'retry'
  | 'raise-bound'
  | 'install-tool'
  | 'escalate-full-system'
  | 'reacquire-input'
  | 'settled'
  | 'unbounded-search'
  | 'defect';
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
  bodyBytes: number | null;
  bodyBytesInspected: number | null;
  bodyInspectionComplete: number | null;
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

export type CompletenessStatus = 'complete' | 'incomplete' | 'unknown';

export interface MissingGaps {
  sequences?: number[];
  bytes?: number;
}

export interface ReassemblyCompleteness {
  status: CompletenessStatus;
  receivedBytes: number;
  expectedBytes?: number;
  missingBytes?: number;
  missingSequences?: number[];
  missing?: MissingGaps;
  reason: string;
}

export interface BleDfuResult {
  flowId: string;
  size: number;
  firmwareScore: number;
  carved: boolean;
  completeness?: ReassemblyCompleteness;
}

export interface ZigbeeOtaResult {
  flowId: string;
  size: number;
  manufacturerCode: number;
  imageType: number;
  fileVersion: number;
  firmwareScore: number;
  carved: boolean;
  completeness?: ReassemblyCompleteness;
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
export type ExtractionBrowseState =
  | 'never-run'
  | 'in-progress'
  | 'cancelling'
  | 'cancelled'
  | 'failed'
  | 'no-output'
  | 'volumes-only'
  | 'rootfs';

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
    get<{
      tools: ToolStatus[];
      groups: Record<string, { available: number; total: number; notReady?: number }>;
      /** OPTIONAL FOREVER: older API builds expose the tool inventory without the class-routed pre-run plan. */
      plans?: CapabilityClassPlan[];
    }>(`/api/tools${lang(locale)}`),
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
   * Walk an operator-supplied FreeRTOS RAM snapshot. A 400 resolves as `{ refused }` rather than throwing: the
   * route names every bad field in `details`, and that list is the answer the form has to show.
   */
  runRtosTasks: async (
    id: string,
    input: RtosTaskSnapshotInput,
  ): Promise<{ jobId: string } | { refused: { error: string; details: string[] } }> => {
    const res = await fetch(`/api/images/${id}/rtos/tasks`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
    });
    const body = (await res.json().catch(() => ({}))) as { jobId?: string; error?: string; details?: unknown };
    if (res.ok && typeof body.jobId === 'string') return { jobId: body.jobId };
    if (res.status === 400) {
      const details = Array.isArray(body.details) ? body.details.filter((d): d is string => typeof d === 'string') : [];
      return { refused: { error: body.error ?? `${res.status} ${res.statusText}`, details } };
    }
    throw new Error(body.error ?? `${res.status} ${res.statusText}`);
  },
  rtosTasksResult: (id: string) =>
    get<{ result: RtosTaskSnapshotResult | null }>(`/api/images/${id}/rtos/tasks`).then((r) => r.result),
  /** Static switch-family leads only; no findings or hardware claims are produced. */
  runSwitchFamily: (id: string) => post<{ jobId: string }>(`/api/images/${id}/switch-family`, {}),
  switchFamilyResult: (id: string) =>
    get<{ result: SwitchFamilyAnalysis | null }>(`/api/images/${id}/switch-family`).then((r) => r.result),
  /** Read the FreeRTOS kernel addresses from the image's own ELF symbol table (a job; nothing is synced). */
  runRtosElfSymbols: (id: string) => post<{ jobId: string }>(`/api/images/${id}/rtos/elf-symbols`, {}),
  rtosElfSymbolsResult: (id: string) =>
    get<{ result: RtosElfSymbolsResult | null }>(`/api/images/${id}/rtos/elf-symbols`).then((r) => r.result),
  /** Renode bounded RAM capture for RTOS snapshot walking (a job; nothing is synced). */
  runRenodeRamCapture: (id: string, opts?: { seconds?: number; platform?: string }) =>
    post<{ jobId: string }>(`/api/images/${id}/rtos/ram-capture`, opts ?? {}),
  renodeRamCaptureResult: (id: string) =>
    get<{ result: RenodeRamCaptureResult | null }>(`/api/images/${id}/rtos/ram-capture`).then((r) => r.result),
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
  runComponentCve: (id: string) => post<{ jobId: string }>(`/api/images/${id}/component-cve`, {}),
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
  cancelJob: (jobId: string) => post<{ job: Job }>(`/api/jobs/${jobId}/cancel`, {}).then((r) => r.job),
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
  /**
   * Start a credential cross-reference. A rootfs-gate refusal (extraction not run / in progress / no rootfs) comes
   * back 4xx and `post` throws its sentence — that sentence IS the prerequisite answer the panel renders.
   */
  runCredmatch: (id: string) => post<{ jobId: string }>(`/api/images/${id}/credmatch`, {}),
  runAuxSecrets: (id: string) => post<{ jobId: string }>(`/api/images/${id}/auxsecrets`, {}),
  auxSecretsResult: (id: string) =>
    get<{ result: { findings?: Finding[]; reason?: string } | null }>(`/api/images/${id}/auxsecrets`).then(
      (r) => r.result,
    ),
  /** The most recent completed run, or null when none has finished — never-run must never read as clean. */
  credmatchResult: (id: string) =>
    get<{ result: CredMatchResult | null }>(`/api/images/${id}/credmatch`).then((r) => r.result),
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
  /**
   * Amend an assertion. `amendedBy` is required by the API and is NOT `assertedBy`: an amendment records its own
   * author beside the original one, so a rewording is never attributed to the person who made the first claim.
   * The author KIND is not sent — the transport stamps it, and a body that tried would be ignored.
   */
  amendAssertion: (
    id: string,
    findingId: string,
    body: {
      title: string;
      claim: OperatorClaim;
      rationale: string;
      severity?: Finding['severity'];
      amendedBy: string;
    },
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
  retireFindings: async (id: string, body: { source: string; retiredBy: string; reason: string; dryRun?: boolean }) => {
    const res = await fetch(`/api/images/${id}/findings`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(err.error ?? `${res.status} ${res.statusText}`);
    }
    return (await res.json()) as RetireFindingsResult;
  },
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
  reindexCorpus: (locale?: Locale) =>
    post<{ report: CorpusReindexReport }>(`/api/corpus/reindex${lang(locale)}`).then((r) => r.report),
  /**
   * Re-run the intake classifier over stored bytes. No locale: the payload is class identifiers and filenames, and
   * the only prose — a failure's `error` — is the route's own message, rendered verbatim. Neither call re-runs a
   * provider or touches findings; a changed class re-routes the scan plan and the coverage banner from then on.
   */
  reanalyzeImage: (id: string) => post<ReanalyzeImageResult>(`/api/images/${id}/analysis`, {}),
  reanalyzeCorpus: () => post<ReanalyzeAllReport>('/api/analysis/reanalyze-all', {}),
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
  fsauditResult: (id: string) =>
    get<{ result: FsAuditResultView | null }>(`/api/images/${id}/fsaudit`).then((r) => r.result),
  runNvram: (id: string) => post<{ jobId: string }>(`/api/images/${id}/nvram`),
  funcdiffResult: (id: string, against: string) =>
    get<{ result: FuncDiffResultView | null }>(
      `/api/images/${id}/funcdiff?against=${encodeURIComponent(against)}`,
    ).then((r) => r.result),
  /** `:id` is the NEWER build, `against` the older baseline. Both need an extracted rootfs (400 otherwise). */
  runFuncdiff: (id: string, against: string) => post<{ jobId: string }>(`/api/images/${id}/funcdiff`, { against }),
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
  // Phase 6.4 BLE DFU capture reassembly.
  createBleCaptureSession: (deviceId: string | null, acknowledged: boolean) =>
    post<{ sessionId: string }>('/api/capture/ble/session', { ...(deviceId ? { deviceId } : {}), acknowledged }),
  stageBleDfu: (sessionId: string, chunks: string[], name?: string, initPacket?: string, chunkSeqs?: number[]) =>
    post<BleDfuResult>('/api/capture/ble/dfu', {
      sessionId,
      chunks,
      ...(name ? { name } : {}),
      ...(initPacket ? { initPacket } : {}),
      ...(chunkSeqs && chunkSeqs.length > 0 ? { chunkSeqs } : {}),
    }),
  // Phase 6.5 Zigbee OTA capture reassembly.
  createZigbeeCaptureSession: (deviceId: string | null, acknowledged: boolean) =>
    post<{ sessionId: string }>('/api/capture/zigbee/session', { ...(deviceId ? { deviceId } : {}), acknowledged }),
  stageZigbeeOta: (sessionId: string, blocks: string[], name?: string, blockSeqs?: number[]) =>
    post<ZigbeeOtaResult>('/api/capture/zigbee/ota', {
      sessionId,
      blocks,
      ...(name ? { name } : {}),
      ...(blockSeqs && blockSeqs.length > 0 ? { blockSeqs } : {}),
    }),

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
