/**
 * Corpus reconciliation — the reindex path the recording side never had.
 *
 * Every corpus row until now was written at the instant a provider ran: the upload route classified secrets, the
 * SBOM route landed components, `extract` hashed binaries, `fsaudit`/`nvram`/`auxsecrets` stamped key material.
 * Nothing ever reconciled what was ALREADY on the bench, so a knowledge base whose whole claim is to persist
 * across images accumulated the bias of *when* each image happened to be uploaded rather than what the bench
 * holds. The images analysed before a recorder existed keep their findings and their SBOM; the corpus simply
 * never saw them — and `credentialReuse: 0` then reads as "no reuse" when it means "never recorded".
 *
 * This module decides, purely, what a reconciliation should record for one image, from state that is ALREADY
 * PERSISTED. It runs no tool, opens no socket and re-reads no firmware bytes: every row it proposes derives from
 * a row already in SQLite — the analysis bundle on the image, the findings ledger, a completed job's stored
 * result, the binaries table. That is what makes it safe to point at a live deployment, and what makes it cheap.
 *
 * `INSERT OR IGNORE` over immutable data makes the reindex idempotent by construction — a second run inserts
 * nothing — so `rowsInserted` is a measurement of what was actually missing and not a count of how many times we
 * called insert. `rowsOffered` beside it is what the bench could have contributed all along.
 *
 * It ADDS and never deletes, and it reads each provider's LATEST stored result, so it reconciles towards what the
 * bench last measured rather than towards the union of everything it ever measured. Measured by wiping one image
 * from a copy of the deployed database and reconciling it back: 361 component rows had accumulated over the
 * GL.iNet's two SBOM runs and 358 came back, the three from the superseded run being unreachable by definition.
 * That is a limit on what a reindex can RESTORE, not on production, where nothing is removed for it to miss.
 *
 * Three things it refuses to do, and each is the reason a line of this file exists:
 *
 * 1. **An operator assertion never enters the corpus.** An assertion is the one kind of row FirmLab did not
 *    compute; letting one seed a cross-image occurrence would turn a person's claim into a prior that OTHER
 *    images are then measured against — the corpus concluding, which is precisely what its module comment
 *    forbids. The exclusion lives here, in the pure layer, so a test reaches it.
 * 2. **It does not invent what it cannot derive.** `reachability_prior` is written only on a live confirmation
 *    and its subject key is a property of that run (`binary:sink`), not of any stored row; `corpus_rule` is
 *    human-curated by definition. Both are named in `notReconciled` rather than left as a silence that a reader
 *    would fill in with "then there are none".
 * 3. **It reproduces the bound it reconciles from, and says so.** A reconciliation reads results written by an
 *    OLDER build, so it inherits every cap that build applied — and does not widen one: the GL.iNet's stored SBOM
 *    holds 500 packages of the 2 019 syft catalogued, because it was written before the cap that produced that
 *    number was fixed, and its raw string scan stopped at 11 % of the file. A reader who took the reconciled
 *    count for the image's own total would be making exactly the mistake those coverage fields were added to
 *    prevent, so a bounded input is reported per image and per kind rather than aggregated away.
 *
 *    A THIRD state matters as much as the two: a stored result written before the coverage field existed carries
 *    no bound at all, and that is "not recorded", never "scanned whole". Measured on the deployed bench, seven of
 *    the eight stored SBOMs are in exactly that state — a reindex that reported only the one bound it can read
 *    would imply the other seven had catalogued everything.
 */
import { OPERATOR_ASSERTION, type StaticAnalysis } from '@firmlab/core';
import { classifyGitleaksHit, credentialHashesFromFindings } from './findings-normalize.js';
import { isOperatorSource } from './operator-findings.js';
import type { GitleaksResult } from './providers/gitleaks.js';
import type { SbomResult } from './providers/sbom.js';

/** The recorders a reconciliation can drive, named after the corpus table each one feeds. */
export type CorpusReindexSource = 'static-secrets' | 'gitleaks' | 'credential-hashes' | 'components' | 'artifacts';

export const CORPUS_REINDEX_SOURCES: readonly CorpusReindexSource[] = [
  'static-secrets',
  'gitleaks',
  'credential-hashes',
  'components',
  'artifacts',
] as const;

/**
 * The sources and finding kinds that stamp a redaction-safe credential identity.
 *
 * Named here so a reconciliation can tell apart two zeroes that look identical in the ledger: a provider that ran
 * and found no key material, and a provider that ran BEFORE it learned to stamp one. The second is the state the
 * A provider also emits posture findings (boot delay, accounts, services, suspicious filenames) that are not
 * credentials and must not be counted as missing stamps merely because they share the same source.
 */
export const CREDENTIAL_STAMPING_SOURCES = ['fsaudit', 'nvram', 'auxsecrets'] as const;

function isStampingSource(source: string): boolean {
  return CREDENTIAL_STAMPING_SOURCES.some((s) => source === s || source.startsWith(`${s}:`));
}

export const CREDENTIAL_STAMPING_KINDS = new Set([
  'embedded-private-key',
  'private-key-matches-shipped-certificate',
  'nvram-credential',
  'nvram-wifi-key',
]);

function expectsStampedIdentity(finding: ReindexFindingRow): boolean {
  return isStampingSource(finding.source) && CREDENTIAL_STAMPING_KINDS.has(finding.kind);
}

/** The ledger columns a reconciliation reads. A subset of `FindingRow`, so the pure layer needs no store type. */
export interface ReindexFindingRow {
  source: string;
  kind: string;
  severity: string;
  proofState: string;
  evidenceJson: string | null;
}

/** One image's already-persisted inputs. `null` means the input does not exist, never that it exists and is empty. */
export interface ReindexImageInput {
  imageId: string;
  filename: string;
  /** The analysis bundle on the image row. Null for an image whose static analysis errored. */
  analysis: StaticAnalysis | null;
  /** The most recent completed gitleaks job's stored result, if any job ever completed. */
  gitleaks: GitleaksResult | null;
  /** The most recent completed SBOM job's stored result, if any job ever completed. */
  sbom: SbomResult | null;
  /** The whole ledger for this image, operator rows included — they are excluded here, where it is tested. */
  findings: ReindexFindingRow[];
  /** The binaries table for this image: what `extract` hashed, and the same list it recorded from. */
  binaries: { path: string; sha1: string | null; arch: string | null }[];
}

export interface CredentialRow {
  value: string;
  kind: string | null;
  severity: string | null;
}

export interface CredentialHashRow {
  hash: string;
  kind: string | null;
  severity: string | null;
}

export interface ComponentRow {
  name: string;
  version: string;
  cveCount: number;
}

export interface ArtifactRow {
  sha1: string;
  path: string;
  arch: string | null;
}

/** What one image contributes, plus which of its inputs existed at all. */
export interface ReindexImagePlan {
  imageId: string;
  filename: string;
  staticCredentials: CredentialRow[];
  gitleaksCredentials: CredentialRow[];
  credentialHashes: CredentialHashRow[];
  components: ComponentRow[];
  artifacts: ArtifactRow[];
  /** Per source: did the persisted input this source reads exist? False is "never ran", not "ran and found none". */
  inputs: Record<CorpusReindexSource, boolean>;
  /** Stored inputs that state they were bounded. The rows are what that bounded pass saw. */
  boundedInputs: BoundedInput[];
  /** Stored inputs whose bound is NOT RECORDED — written before the field that would say existed. */
  unrecordedBounds: BoundedInputKind[];
  /**
   * Ledger rows from a credential-stamping provider that carry no identity — written before the stamping existed.
   * A non-zero here is why `credential-hashes` can offer nothing while every image has a ledger, and it is the one
   * gap a reindex cannot close: re-running the provider is what computes the hash.
   */
  unstampedCredentialRows: number;
}

/** The stored inputs whose own coverage a reconciliation inherits. */
export type BoundedInputKind = 'static-scan' | 'sbom-packages';

export const BOUNDED_INPUT_KINDS: readonly BoundedInputKind[] = ['static-scan', 'sbom-packages'] as const;

export interface BoundedInput {
  kind: BoundedInputKind;
  /** What the stored pass actually covered — bytes read, packages listed. */
  covered: number;
  /** What the same result says exists. */
  total: number;
}

/**
 * Read the coverage a stored result declares about itself.
 *
 * Three outcomes, and the third is the one that needs a name: bounded (the result says it stopped short), whole
 * (it says it covered everything), and NOT RECORDED — a result written before the field existed, which knows
 * nothing about its own coverage and must not be counted as either.
 */
export function readBounds(input: ReindexImageInput): {
  bounded: BoundedInput[];
  unrecorded: BoundedInputKind[];
} {
  const bounded: BoundedInput[] = [];
  const unrecorded: BoundedInputKind[] = [];

  const scan = input.analysis?.secretScan;
  if (input.analysis) {
    if (!scan) unrecorded.push('static-scan');
    // The two coverage numbers only, NEVER the whole object: `SecretScan` also carries `secrets`, which holds the
    // raw values, and this travels over HTTP. A reconciliation report is the last place a secret should appear.
    else if (scan.scannedBytes < scan.totalBytes)
      bounded.push({ kind: 'static-scan', covered: scan.scannedBytes, total: scan.totalBytes });
  }

  const sbom = input.sbom;
  if (sbom?.available) {
    if (sbom.packageTotal === undefined) unrecorded.push('sbom-packages');
    else if (sbom.packageTotal > sbom.packages.length)
      bounded.push({ kind: 'sbom-packages', covered: sbom.packages.length, total: sbom.packageTotal });
  }

  return { bounded, unrecorded };
}

/**
 * Static secrets, as the upload route records them: the classified hits only, value-keyed.
 *
 * Reads `secrets` — the same array the route reads — rather than `secretScan.secrets`, because a result stored by
 * a build older than that field has the former and not the latter, and those images are the entire point of a
 * reindex.
 */
export function planStaticCredentials(analysis: StaticAnalysis | null): CredentialRow[] {
  if (!analysis) return [];
  return dedupe(
    analysis.secrets
      .filter((s) => s.secretKind)
      .map((s) => ({ value: s.value, kind: s.secretKind ?? null, severity: s.severity ?? null })),
    (r) => r.value,
  );
}

/**
 * Collapse rows that share a corpus primary key, keeping the first — which is what `INSERT OR IGNORE` keeps, so
 * this changes nothing that lands and everything that is REPORTED.
 *
 * Measured on the deployed bench: the GL.iNet SBOM offers 500 package rows that are 358 distinct (name, version)
 * pairs. Reporting 500 offered against 0 inserted invites exactly one reading — "the corpus holds 500 of these" —
 * and it holds 358. A count of insert CALLS wearing the name of a row count is the same defect this reconciliation
 * was written in the middle of fixing everywhere else.
 */
function dedupe<T>(rows: T[], key: (row: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const row of rows) {
    const k = key(row);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(row);
  }
  return out;
}

/**
 * gitleaks hits, classified by the SAME function the ledger row gets. Hardcoding a severity here is the defect the
 * route's comment already records — seven upstream dnscrypt PUBLIC keys entering the cross-image credential table
 * as high-severity credentials — and a reindex that re-derived it independently would reintroduce it wholesale.
 */
export function planGitleaksCredentials(result: GitleaksResult | null): CredentialRow[] {
  if (!result?.available) return [];
  return dedupe(
    result.findings.map((f) => ({ value: f.match, kind: f.rule, severity: classifyGitleaksHit(f).severity })),
    (r) => r.value,
  );
}

/**
 * The redaction-safe path: credential identities that providers stamped on their findings as a hash. The value
 * never left its provider and does not exist to be re-derived, so the ledger IS the persisted input here.
 *
 * Operator rows are dropped by both of the tests the store uses for the same purpose — the `operator:` source
 * prefix and the `operator_assertion` proof state. Belt and braces, because either alone has a way to be absent:
 * a row predating the prefix convention, or one whose provenance column was never written.
 */
export function planCredentialHashes(findings: ReindexFindingRow[]): CredentialHashRow[] {
  const codeAuthored = findings.filter((f) => !isOperatorSource(f.source) && f.proofState !== OPERATOR_ASSERTION);
  return dedupe(
    credentialHashesFromFindings(
      codeAuthored.map((f) => ({ kind: f.kind, severity: f.severity, evidence: parseEvidence(f.evidenceJson) })),
    ),
    (r) => r.hash,
  );
}

function parseEvidence(json: string | null): unknown {
  if (!json) return undefined;
  try {
    return JSON.parse(json) as unknown;
  } catch {
    // A row whose evidence does not parse contributes nothing rather than aborting the image. It cannot be a
    // hash-bearing row: the recorder that would have written one serialized the object it is reading back.
    return undefined;
  }
}

/**
 * Components, with the CVE count grype matched to each — the same pairing `routes/sbom.ts` computes, over the
 * stored result rather than the live one.
 */
export function planComponents(sbom: SbomResult | null): ComponentRow[] {
  if (!sbom?.available) return [];
  const cveCount = (name: string, version: string): number =>
    sbom.vulnerabilities.filter((v) => v.packageName === name && v.packageVersion === version).length;
  return dedupe(
    sbom.packages.map((p) => ({ name: p.name, version: p.version, cveCount: cveCount(p.name, p.version) })),
    (r) => `${r.name}\u0000${r.version}`,
  );
}

/** Hashed binaries, from the table `extract` populated — so an image whose extraction directory was swept still counts. */
export function planArtifacts(binaries: ReindexImageInput['binaries']): ArtifactRow[] {
  return dedupe(
    binaries
      .filter((b): b is { path: string; sha1: string; arch: string | null } => Boolean(b.sha1))
      .map((b) => ({ sha1: b.sha1, path: b.path, arch: b.arch })),
    (r) => `${r.sha1}\u0000${r.path}`,
  );
}

/**
 * What one image contributes.
 *
 * `inputs` records existence, not emptiness, and the two must not be collapsed: an image with no gitleaks result
 * was never scanned, while one with an available result and no hits was scanned and is clean. Reporting both as
 * "0 rows" would rebuild, inside the reindex, the very conflation the ledger's coverage verdict exists to stop.
 */
export function planImageReindex(input: ReindexImageInput): ReindexImagePlan {
  const bounds = readBounds(input);
  return {
    imageId: input.imageId,
    filename: input.filename,
    staticCredentials: planStaticCredentials(input.analysis),
    gitleaksCredentials: planGitleaksCredentials(input.gitleaks),
    credentialHashes: planCredentialHashes(input.findings),
    components: planComponents(input.sbom),
    artifacts: planArtifacts(input.binaries),
    inputs: {
      'static-secrets': input.analysis !== null,
      gitleaks: input.gitleaks !== null,
      // The ledger is the input, so "present" means the image has code-authored rows at all. An image with rows
      // but no hash-bearing evidence contributes zero for the providers that ran — which stages ran at all is a
      // question `providers/coverage.ts` already answers, and is not re-derived here.
      'credential-hashes': input.findings.some((f) => !isOperatorSource(f.source)),
      components: input.sbom !== null,
      artifacts: input.binaries.length > 0,
    },
    boundedInputs: bounds.bounded,
    unrecordedBounds: bounds.unrecorded,
    unstampedCredentialRows: input.findings.filter(
      (f) => expectsStampedIdentity(f) && !isOperatorSource(f.source) && !hasStampedIdentity(f.evidenceJson),
    ).length,
  };
}

function hasStampedIdentity(evidenceJson: string | null): boolean {
  const ev = parseEvidence(evidenceJson) as { secretHash?: unknown; secretHashes?: unknown } | undefined;
  if (typeof ev?.secretHash === 'string' && ev.secretHash) return true;
  return Array.isArray(ev?.secretHashes) && ev.secretHashes.length > 0;
}

export interface ReindexSourceReport {
  source: CorpusReindexSource;
  /** Images whose persisted input for this source exists at all. */
  imagesWithInput: number;
  /** Images with no stored input — the provider never ran for them. NOT images where it ran and found nothing. */
  imagesWithoutInput: number;
  /** Rows the bench could contribute. */
  rowsOffered: number;
  /** Rows the reconciliation actually inserted — the rest were already there (INSERT OR IGNORE). */
  rowsInserted: number;
}

/** A table this reconciliation structurally cannot rebuild, named so its emptiness is not read as a measurement. */
export interface UnreconciledTable {
  table: string;
  reason: string;
}

export interface CorpusReindexReport {
  imageCount: number;
  sources: ReindexSourceReport[];
  /** Stored inputs that declare they were bounded; the reconciled rows inherit that bound. */
  boundedInputs: { imageId: string; filename: string; kind: BoundedInputKind; covered: number; total: number }[];
  /** How many stored inputs, per kind, predate the field that would state their coverage. Not recorded ≠ whole. */
  unrecordedBounds: { kind: BoundedInputKind; imageCount: number }[];
  /** Images holding ledger rows from a credential-stamping provider that predate the stamping, with the row count. */
  unstampedCredentials: { imageId: string; filename: string; rows: number }[];
  notReconciled: UnreconciledTable[];
  /** The sentence stating what this run does and does not let a reader conclude. Localised at the route. */
  verdict: string;
}

/** How many rows a plan offers for one source — the single place the source→array mapping is written down. */
export function rowsFor(plan: ReindexImagePlan, source: CorpusReindexSource): number {
  switch (source) {
    case 'static-secrets':
      return plan.staticCredentials.length;
    case 'gitleaks':
      return plan.gitleaksCredentials.length;
    case 'credential-hashes':
      return plan.credentialHashes.length;
    case 'components':
      return plan.components.length;
    case 'artifacts':
      return plan.artifacts.length;
  }
}

/**
 * The localised prose a report needs, injected rather than imported: this module composes the SHAPE of the
 * sentence (whether the bounded-input note applies at all) and the catalogue supplies the words, so the decision
 * is unit-tested here while the language stays the request's.
 */
export interface ReindexText {
  verdict: (p: { imageCount: number; inserted: number; offered: number }) => string;
  boundedNote: (p: { count: number }) => string;
  unrecordedNote: (p: { count: number }) => string;
  unstampedNote: (p: { rows: number; imageCount: number }) => string;
}

/**
 * Fold the per-image plans and the insert counts the recorders returned into the report.
 *
 * `inserted` is keyed by source and supplied by the caller, because only the store knows how many of the offered
 * rows were new. A caller that cannot measure it passes zero — and zero inserted against a non-zero offered then
 * reads, correctly, as "the corpus already had these".
 */
export function summarizeReindex(
  plans: ReindexImagePlan[],
  inserted: Record<CorpusReindexSource, number>,
  text: ReindexText,
  notReconciled: UnreconciledTable[],
): CorpusReindexReport {
  const sources = CORPUS_REINDEX_SOURCES.map((source) => {
    const withInput = plans.filter((p) => p.inputs[source]);
    return {
      source,
      imagesWithInput: withInput.length,
      imagesWithoutInput: plans.length - withInput.length,
      rowsOffered: plans.reduce((n, p) => n + rowsFor(p, source), 0),
      rowsInserted: inserted[source],
    };
  });
  const boundedInputs = plans.flatMap((p) =>
    p.boundedInputs.map((b) => ({ imageId: p.imageId, filename: p.filename, ...b })),
  );

  const unrecordedBounds = BOUNDED_INPUT_KINDS.map((kind) => ({
    kind,
    imageCount: plans.filter((p) => p.unrecordedBounds.includes(kind)).length,
  })).filter((r) => r.imageCount > 0);

  const base = text.verdict({
    imageCount: plans.length,
    inserted: sources.reduce((n, s) => n + s.rowsInserted, 0),
    offered: sources.reduce((n, s) => n + s.rowsOffered, 0),
  });

  // Each note is appended only when it applies. A run over inputs that all declared full coverage must not carry a
  // caveat about a truncation it did not suffer — a caveat printed every time stops being read, which costs more
  // than the sentence saves on the run where it is true.
  const unstampedCredentials = plans
    .filter((p) => p.unstampedCredentialRows > 0)
    .map((p) => ({ imageId: p.imageId, filename: p.filename, rows: p.unstampedCredentialRows }));

  const notes = [
    boundedInputs.length > 0 ? text.boundedNote({ count: boundedInputs.length }) : null,
    unrecordedBounds.length > 0
      ? text.unrecordedNote({ count: unrecordedBounds.reduce((n, r) => n + r.imageCount, 0) })
      : null,
    unstampedCredentials.length > 0
      ? text.unstampedNote({
          rows: unstampedCredentials.reduce((n, r) => n + r.rows, 0),
          imageCount: unstampedCredentials.length,
        })
      : null,
  ].filter((n): n is string => n !== null);

  return {
    imageCount: plans.length,
    sources,
    boundedInputs,
    unrecordedBounds,
    unstampedCredentials,
    notReconciled,
    verdict: [base, ...notes].join(' '),
  };
}
