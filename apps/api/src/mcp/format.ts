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
 * The third rule arrived with operator assertions, and it closes a loop that only exists at this boundary. An
 * agent can now WRITE to the ledger. If its own assertion came back in the same array as the measured findings, a
 * model would read the workbench agreeing with it — and it would be reading its own sentence, laundered through a
 * database round-trip into something that looks like corroboration. So assertions are lifted out of `findings`
 * entirely, `proofStateCounts` never sees them, and every agent-authored row is returned carrying the explicit
 * statement that the agent may have written it and that a record of a claim is not evidence for the claim.
 * Partitioning is by the `operator_assertion` sentinel, not by source, so no string a model controls decides
 * which array it lands in.
 *
 * The fourth rule is the one the HTML report learned first and this surface inherited: **the ledger's history is
 * part of the ledger.** An amended assertion returns what it replaced, in its own object, under keys that are not
 * `claim`/`title`/`rationale` — a model scanning for those must not find a retired sentence under them, and the
 * history's first field says so before the retired claim appears. A computed row a named author has contested
 * carries the contest inline, next to its unchanged proof state, because the agent reading a `static_confirmed`
 * row has the same right to know someone disagrees as a human opening the report — and the same obligation not to
 * treat the disagreement as having moved the row. Both fields are read defensively: `supersedes` and the
 * revision's `title` were added late, and a stored assertion written by an older build has neither. No history is
 * the correct reading of such a row, never a throw.
 *
 * Pure — takes plain data, returns plain data, unit-tested.
 */
import type { OperatorAssertion } from '@firmlab/core';
import {
  type AssertionRevision,
  CLAIM_MEANING,
  NOT_A_MEASUREMENT,
  assertionDay,
  describeAssertion,
  indexDisputes,
  partitionByProvenance,
  revisionsOf,
} from '../operator-findings.js';

/** A finding as the API serves it (the fields that matter for the agent boundary). */
export interface McpFinding {
  /**
   * The ledger row id. Optional: this interface describes a payload that has been served by more than one build,
   * and a dispute that cannot find its target must degrade to "not annotated", never to a crash.
   */
  id?: string;
  kind: string;
  title: string;
  severity: string;
  proofState: string;
  source: string;
  evidence?: Record<string, unknown>;
  rationale?: string;
  /** Present iff a person or agent asserted this row rather than FirmLab measuring it. */
  assertion?: OperatorAssertion | undefined;
}

/**
 * One operator contest, attached to the computed row it contests.
 *
 * `meaning` comes first and names the target's proof state inside itself, because the misreading here is the
 * mirror image of the one the rest of this module guards: a bare `disputed: true` invites a model to discount the
 * measurement, which is exactly the override an assertion is not allowed to perform.
 */
export interface McpDisputeNote {
  /** First field: what a dispute does, and what it does not do, to the row it is attached to. */
  meaning: string;
  disputedBy: string;
  authorKind: string;
  assertedOn: string;
  assertionTitle: string;
  statedBasis?: string;
  assertionId?: string;
}

/**
 * A measured row as this surface returns it: the finding verbatim, plus the contest if one stands against it.
 * Nothing here rewrites `proofState` — the annotation sits beside it and says so.
 */
export interface McpMeasuredFinding extends McpFinding {
  /** Present iff an ACTIVE operator assertion contests this row. Never present on an undisputed finding. */
  disputedByOperator?: McpDisputeNote[];
}

/** The coverage report shape `GET /images/:id/coverage` returns. */
export interface McpCoverage {
  firmwareClass: string;
  classRationale?: string;
  applicable: number;
  /** MEASURED findings only. Operator assertions are reported separately and cover no stage. */
  findingCount: number;
  executed: number;
  /** Absent on a deployment that predates operator assertions — treat as 0. */
  operatorAssertions?: number;
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
  'A filename is not its contents. firmlab_read_file opens the file a finding cites, and the one entry this',
  "project's backlog had to WITHDRAW was written from a filename without opening it — `private_key.pem`, which",
  'holds a PUBLIC key. If you are about to characterise a file, read it first.',
  '',
  'OPERATOR ASSERTIONS are the one kind of row FirmLab did not compute. A person — or you — asserted them. They',
  'carry no proof state (their provenance field reads `operator_assertion`), they count towards NO analysis stage,',
  'and they are returned in their own array, never mixed into findings. Three rules bind you here:',
  '  - Never cite an assertion as though the workbench measured it. Cite the author: "X asserts …".',
  '  - An assertion YOU recorded is a restatement of your own claim, never evidence for it. Reading your own note',
  '    back out of the ledger and reporting it as corroboration is circular; the payload labels which rows you may',
  '    have written, and you must not use them to support the claim they contain.',
  '  - Record one only for something you actually concluded or observed, with the basis stated. Do not mirror a',
  '    measured finding into an assertion — that inflates the ledger and adds no knowledge.',
  '',
  'The ledger keeps its own history, and two fields carry it:',
  '  - `amendmentHistory` on an assertion holds the claims it SUPERSEDED. They are retired: the live claim is the',
  '    one in the row’s own fields. Quote a superseded claim only as what the author previously stated.',
  '  - `disputedByOperator` on a MEASURED finding means a named author says that finding is wrong. It is testimony',
  '    about a measurement, not a measurement: the proof state stays exactly as code decided it, the row stands,',
  '    and you report both — never silently drop the finding, and never downgrade it because someone objected.',
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
    // Coverage counts the autonomous scan's workers, so an image analyzed a stage at a time reads as executed:0
    // while holding real findings. Labelling that UNEXAMINED would contradict the verdict it introduces — the
    // same self-contradiction the coverage verdict itself was fixed for, one layer up.
    if (c.findingCount > 0) {
      return `COVERAGE UNKNOWN — ${c.verdict} The findings are real; what has NOT been examined is unknown, so do not present this as a complete analysis.`;
    }
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
 * The notice that heads every operator block. It states the circularity in the second person because the model
 * reading it is the party that might close the loop, and an abstract caveat about "authored content" would not
 * connect to the fact that the row it is looking at may be its own from twenty minutes ago.
 */
export const SELF_AUTHORSHIP_NOTICE =
  'None of these rows was produced by analysis. Each is a claim recorded by a named author, and some may have ' +
  'been recorded BY YOU in this or an earlier session — `authorKind: "agent"` marks those. A record of a claim is ' +
  'not evidence for the claim: you may report that someone asserted it, attributed to them, but you may never ' +
  'cite one as measurement, as confirmation, or as support for the same conclusion you are arguing.';

/**
 * One superseded claim from an amended assertion.
 *
 * Not one field is named `claim`, `title` or `rationale`. That is the whole design: a model — or a caller
 * flattening this object — that reaches for those keys must not come back holding a sentence the author has
 * already replaced. The window the claim stood in travels with it, because "they said X, then narrowed it to Y"
 * is only readable if you can see when each one applied.
 */
export interface McpSupersededClaim {
  supersededClaim: string;
  /** Absent on a revision written before the title was preserved — see `AssertionRevision.title`. */
  supersededTitle?: string;
  supersededBasis: string;
  stoodFrom: string;
  supersededOn: string;
  /** The finding this retired claim contested, if it was a dispute. It no longer contests anything. */
  contestedFindingId?: string;
}

/**
 * The amendment record for one assertion: the note first, the retired claims after it.
 *
 * `note` leads for the same reason `notAMeasurement` leads the row it sits on — the field that bounds how the
 * data may be read has to be encountered before the data. The two notes differ because the two situations do:
 * a build that amended without preserving its predecessor leaves a hole, and saying "no history" for that row
 * would report the hole as an absence of amendment.
 */
export interface McpAmendmentHistory {
  /** First field: everything below is retired, and the live claim is on the row itself. */
  note: string;
  amendedOn: string;
  supersededClaimCount: number;
  supersededClaims: McpSupersededClaim[];
}

/** One asserted row, shaped so no field of it can be read as a measurement. */
export interface McpAssertedFinding {
  /** First field: the reading, before the model gets to anything that looks like a result. */
  notAMeasurement: string;
  title: string;
  severity: string;
  claim: string;
  claimMeaning: string;
  assertedBy: string;
  authorKind: string;
  attribution: string;
  rationale?: string;
  /** Set on agent-authored rows — the ones a model is at risk of citing back to itself. */
  selfAuthored?: boolean;
  withdrawn?: boolean;
  /** Which computed row this assertion contests, set only for `claim: 'disputes_finding'`. */
  contestsFinding?: { findingId: string; stillInLedger: boolean; note: string };
  /** Present iff this claim replaced an earlier one. Absent means never amended — including on an older row. */
  amendmentHistory?: McpAmendmentHistory;
}

function shapeRevision(r: AssertionRevision): McpSupersededClaim {
  return {
    supersededClaim: r.claim,
    ...(r.title ? { supersededTitle: r.title } : {}),
    supersededBasis: r.rationale,
    stoodFrom: assertionDay(r.from),
    supersededOn: assertionDay(r.supersededAt),
    ...(r.disputesFindingId ? { contestedFindingId: r.disputesFindingId } : {}),
  };
}

/**
 * Pure: the amendment record, or null for a claim that was never amended.
 *
 * Read defensively at both ends. `revisionsOf` tolerates a `supersedes` column written by a build that shipped a
 * different shape, and an `amendedAt` with no revisions behind it is a real, reachable state — it is every row
 * amended before amendment became append-only — so it reports the gap instead of pretending the current claim is
 * the original one. A row with neither returns null, which is the correct reading of every assertion ever stored
 * before this feature existed.
 */
export function amendmentHistoryOf(a: OperatorAssertion | undefined): McpAmendmentHistory | null {
  if (!a) return null;
  const revisions = revisionsOf(a);
  if (a.amendedAt === undefined && revisions.length === 0) return null;
  const amendedOn = assertionDay(a.amendedAt ?? a.assertedAt);
  if (revisions.length === 0) {
    return {
      note:
        'HISTORY UNAVAILABLE — this assertion was amended, but the build that amended it did not preserve the ' +
        'claim it replaced, so what it superseded cannot be shown. Only the current claim stands; do not read it ' +
        'as the author’s original one.',
      amendedOn,
      supersededClaimCount: 0,
      supersededClaims: [],
    };
  }
  return {
    note:
      'HISTORY, NOT A LIVE CLAIM — the claim, title and basis on the row above are the current ones. Everything ' +
      'listed here was superseded by an amendment and is no longer asserted: cite it only as what the author ' +
      'previously stated, never as the claim that stands. An amendment appends; it never overwrites.',
    amendedOn,
    supersededClaimCount: revisions.length,
    supersededClaims: revisions.map(shapeRevision),
  };
}

function shapeAssertion(f: McpFinding, ledgerIds: ReadonlySet<string>): McpAssertedFinding {
  const a = f.assertion;
  const claim = a?.claim ?? 'asserted_unverified';
  const isAgent = a?.authorKind === 'agent';
  const target = a?.disputesFindingId;
  const history = amendmentHistoryOf(a);
  // A withdrawn contest gets its own sentence: the live one promises the target row "carries the annotation", and
  // a retracted dispute deliberately does not annotate anything — that wording would send a reader looking for a
  // field that is not there.
  const contestNote = !ledgerIds.has(target ?? '')
    ? 'The finding this contests is no longer in this image’s ledger — re-running a provider replaces its rows with new ids, so a dispute can outlive its target. The claim is kept; what it pointed at cannot be shown.'
    : a?.status === 'withdrawn'
      ? 'The objection has been retracted, so that row carries no dispute note: it stands exactly as code decided it, and the dispute never moved it.'
      : 'That row stands exactly as code decided it. This assertion is recorded beside it, not over it, and it carries the annotation.';
  return {
    notAMeasurement: NOT_A_MEASUREMENT,
    title: f.title,
    severity: f.severity,
    claim,
    claimMeaning: CLAIM_MEANING[claim] ?? 'Unrecognised claim — treat as an unverified assertion.',
    assertedBy: a?.assertedBy ?? 'unknown',
    authorKind: a?.authorKind ?? 'unknown',
    attribution: a ? describeAssertion(a) : 'Asserted by an unrecorded author.',
    ...(f.rationale ? { rationale: f.rationale } : {}),
    ...(isAgent ? { selfAuthored: true } : {}),
    ...(a?.status === 'withdrawn' ? { withdrawn: true } : {}),
    ...(target
      ? { contestsFinding: { findingId: target, stillInLedger: ledgerIds.has(target), note: contestNote } }
      : {}),
    ...(history ? { amendmentHistory: history } : {}),
  };
}

/** The contest as it hangs off the row it contests: who, when, on what basis, and what it did NOT do. */
function disputeNotes(target: McpFinding, disputes: readonly McpFinding[]): McpDisputeNote[] {
  return disputes.map((d) => {
    const a = d.assertion;
    return {
      meaning: `An operator contests this finding. This is testimony ABOUT a measurement, not a measurement: the proof state of this row is still \`${target.proofState}\`, decided by code from the evidence, and the dispute neither changes it, downgrades it nor removes the row. Both stand — report the finding and the objection together, attributed to their authors.`,
      disputedBy: a?.assertedBy ?? 'unknown',
      authorKind: a?.authorKind ?? 'unknown',
      assertedOn: a ? assertionDay(a.assertedAt) : 'an unrecorded date',
      assertionTitle: d.title,
      ...(d.rationale ? { statedBasis: d.rationale } : {}),
      ...(d.id ? { assertionId: d.id } : {}),
    };
  });
}

/**
 * Pure: the findings payload. The verdict comes FIRST, and the stages that produced no result are named, so the
 * model cannot reach the list without passing the caveat that bounds it. `findings` is never returned alone.
 *
 * `findings` holds measured rows only. Assertions are lifted into `operatorAssertions` and withdrawn ones into
 * `withdrawnAssertions`, and `proofStateCounts` is computed over the measured population alone — an assertion
 * incrementing a proof-state histogram would put a human's sentence into the same tally the model uses to judge
 * how well-evidenced the image is.
 *
 * A measured row that a standing assertion contests is returned with the contest attached and its proof state
 * untouched, so the annotation cannot be reached without the sentence saying it changed nothing. An undisputed
 * row is returned exactly as it arrived: no empty array, no `disputed: false`, nothing to make the common case
 * look like it was considered and cleared.
 */
export function findingsPayload(
  coverage: McpCoverage | null,
  findings: McpFinding[],
): {
  coverageVerdict: string;
  notCovered: string[];
  proofStateCounts: Record<string, number>;
  findingCount: number;
  contestedFindingCount?: number;
  contestedFindingsNotice?: string;
  findings: McpMeasuredFinding[];
  operatorAssertionCount: number;
  operatorAssertionsNotice?: string;
  operatorAssertions?: McpAssertedFinding[];
  withdrawnAssertions?: McpAssertedFinding[];
} {
  const { measured, asserted, withdrawn } = partitionByProvenance(findings);

  const proofStateCounts: Record<string, number> = {};
  for (const f of measured) proofStateCounts[f.proofState] = (proofStateCounts[f.proofState] ?? 0) + 1;

  // Coverage unavailable is itself a caveat, not a licence to present the list as complete.
  const coverageVerdict = coverage
    ? coverageHeadline(coverage)
    : 'COVERAGE UNKNOWN — the coverage report could not be read, so it is not known which analysis stages ran. Do not treat this list as complete.';

  const ledgerIds = new Set<string>();
  for (const f of findings) if (f.id) ledgerIds.add(f.id);
  const disputesByTarget = indexDisputes(asserted);
  const annotated: McpMeasuredFinding[] = measured.map((f) => {
    const disputes = f.id ? disputesByTarget.get(f.id) : undefined;
    return disputes?.length ? { ...f, disputedByOperator: disputeNotes(f, disputes) } : f;
  });
  const contested = annotated.filter((f) => f.disputedByOperator).length;

  return {
    coverageVerdict,
    notCovered: coverage ? coverage.stages.filter((s) => UNCOVERED.has(s.status)).map((s) => s.worker) : [],
    proofStateCounts,
    findingCount: measured.length,
    // Before the list, for the same reason the coverage verdict is: a caveat encountered after the data it bounds
    // has already been read is a caveat that arrived too late. Absent when nothing is contested.
    ...(contested
      ? {
          contestedFindingCount: contested,
          contestedFindingsNotice: `${contested} of these measured findings ${
            contested === 1 ? 'is' : 'are'
          } contested by an operator, and ${contested === 1 ? 'carries' : 'carry'} a \`disputedByOperator\` note. A dispute is testimony about a measurement: the proof states below are exactly what code decided, no row was removed or downgraded, and an honest report gives both the finding and the objection.`,
        }
      : {}),
    findings: annotated,
    operatorAssertionCount: asserted.length,
    // Emitted only when there is something to caveat, so the common case is not padded with a warning about an
    // empty array — a warning that is always present is a warning that is never read.
    ...(asserted.length || withdrawn.length ? { operatorAssertionsNotice: SELF_AUTHORSHIP_NOTICE } : {}),
    ...(asserted.length ? { operatorAssertions: asserted.map((f) => shapeAssertion(f, ledgerIds)) } : {}),
    ...(withdrawn.length ? { withdrawnAssertions: withdrawn.map((f) => shapeAssertion(f, ledgerIds)) } : {}),
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

/** The extraction verdict a file listing must be read next to (`providers/fsbrowse.ts`). */
export interface McpExtraction {
  state: string;
  browsable: boolean;
  verdict: string;
  rootfsRel?: string;
}

/** One directory entry as the files route serves it. */
export interface McpDirEntry {
  name: string;
  path: string;
  type: string;
  size: number;
  modeString: string;
  setuid?: boolean;
  symlinkTarget?: string;
  symlinkEscapes?: boolean;
  symlinkResolved?: string;
}

export interface McpDirListing {
  path: string;
  entries: McpDirEntry[];
  totalEntries: number;
  fileCount: number;
  dirCount: number;
  symlinkCount: number;
  truncated: boolean;
  truncationRule?: string;
  note?: string;
}

/**
 * Pure: a directory-listing payload.
 *
 * Same rule as `findingsPayload`, one layer down: an empty listing reads as "the firmware has nothing here" and is
 * produced identically by an empty directory, an extraction that recovered nothing, and an extraction that never
 * ran — so the extraction verdict comes FIRST and the entries cannot be reached without it. Symlinks that leave the
 * extraction are lifted out of the entry array for the reason `scanPayload` lifts incomplete workers: buried in a
 * long list a model reads them as noise, and they are the entries whose contents it must NOT claim to have read.
 */
export function fileListingPayload(extraction: McpExtraction, listing: McpDirListing | null): Record<string, unknown> {
  if (!listing) {
    return {
      extractionVerdict: extraction.verdict,
      state: extraction.state,
      browsable: false,
      entryCount: 0,
      entries: [],
      note: 'There is nothing on disk to list. This is NOT an empty filesystem — read the extraction verdict above; it says which of the several different reasons applies and what would change it.',
    };
  }
  const escaping = listing.entries.filter((e) => e.symlinkEscapes);
  return {
    extractionVerdict: extraction.verdict,
    state: extraction.state,
    path: listing.path,
    entryCount: listing.totalEntries,
    shown: listing.entries.length,
    counts: { files: listing.fileCount, directories: listing.dirCount, symlinks: listing.symlinkCount },
    ...(listing.truncated ? { truncation: listing.truncationRule } : {}),
    ...(listing.note ? { note: listing.note } : {}),
    // Named up front: reading through one of these is refused, so a model must not describe their contents.
    symlinksLeavingTheExtraction: escaping.map((e) => ({
      path: e.path,
      target: e.symlinkTarget,
      meaning:
        'This link points outside the extraction. It is left unfollowed and CANNOT be read — the bytes on the ' +
        'other side belong to the machine running FirmLab, not to the firmware. That the firmware ships this link ' +
        'is itself the fact worth reporting.',
    })),
    entries: listing.entries,
  };
}

/** One bounded read as the files route serves it. */
export interface McpFileRead {
  path: string;
  size: number;
  offset: number;
  bytesRead: number;
  truncated: boolean;
  unreadBefore: number;
  unreadAfter: number;
  truncationRule?: string;
  classification: { kind: string; reason: string };
  view: string;
  viewReason: string;
  text?: string;
  hexdump?: string;
  adjustments: string[];
  claim: string;
}

/**
 * Pure: the one-line reading of a read, phrased for a model about to quote the content as evidence.
 *
 * `not truncated` is the only case that licenses "the file says X". Everything else is a window, and a window read
 * as the file is how a config's first 64 KB becomes a claim about a 4 MB blob.
 */
export function readHeadline(read: McpFileRead): string {
  if (read.size === 0) {
    return 'EMPTY FILE — 0 bytes on disk. There is no content to quote; an empty file is a result, not an absence of one.';
  }
  if (!read.truncated) {
    return `COMPLETE FILE — all ${read.size} bytes were read. Quotes from this content are quotes from the whole file as extracted.`;
  }
  return `PARTIAL READ — ${read.bytesRead} of ${read.size} bytes (${read.unreadBefore} skipped before, ${read.unreadAfter} unread after). This is a WINDOW, not the file: do not characterise what you have not read.`;
}

/**
 * Pure: a file-read payload. The bound leads, then what the bytes prove, then the content — so a model cannot
 * reach the text without passing both the truncation and the fact that this is an extraction, not a device.
 */
export function fileReadPayload(extraction: McpExtraction, read: McpFileRead): Record<string, unknown> {
  return {
    readVerdict: readHeadline(read),
    claim: read.claim,
    extractionVerdict: extraction.verdict,
    path: read.path,
    size: read.size,
    offset: read.offset,
    bytesRead: read.bytesRead,
    ...(read.truncationRule ? { truncation: read.truncationRule } : {}),
    ...(read.adjustments.length ? { requestAdjustments: read.adjustments } : {}),
    // The classification is served with its reason because "binary" decided from the bytes and "binary" guessed
    // from an extension are different claims, and only the first one is being made here.
    classification: read.classification.kind,
    classificationReason: read.classification.reason,
    view: read.view,
    viewReason: read.viewReason,
    ...(read.text !== undefined ? { text: read.text } : {}),
    ...(read.hexdump !== undefined ? { hexdump: read.hexdump } : {}),
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

/** The search result as the API serves it — mirrors `providers/fssearch.ts`, fields optional for stored shapes. */
export interface McpSearchResult {
  query?: string;
  regex?: boolean;
  hits?: { path?: string; offset?: number; line?: number; excerpt?: string; binary?: boolean }[];
  coverage?: {
    filesExamined?: number;
    entriesWalked?: number;
    skipped?: { tooLarge?: number; unreadable?: number; budgetExhausted?: number };
    walkTruncated?: boolean;
    hitCapReached?: boolean;
  };
  verdict?: string;
}

/**
 * Shape a search for a model that is about to write "the term does not appear in this firmware".
 *
 * It cannot: the search declined to open some files, and a model reading a `hits: []` will not go looking for the
 * coverage object to find out how many. So the verdict leads, in the first field, and a result with any hole
 * carries an explicit `isCompleteSearch: false` beside it — the same discipline `findingsPayload` applies to an
 * empty findings list, at the layer where the equivalent mistake is even easier to make.
 */
export function searchPayload(extraction: McpExtraction, r: McpSearchResult): Record<string, unknown> {
  const sk = r.coverage?.skipped ?? {};
  const holes = (sk.tooLarge ?? 0) + (sk.unreadable ?? 0) + (sk.budgetExhausted ?? 0);
  const complete = holes === 0 && !r.coverage?.walkTruncated && !r.coverage?.hitCapReached;
  return {
    searchVerdict: r.verdict ?? 'This result was stored without a coverage verdict; treat its completeness as unknown.',
    isCompleteSearch: complete,
    ...(complete
      ? {}
      : {
          whyNotComplete:
            'Files were left unopened or the hit list was capped. An absent term here means "not found in what was searched", never "not present in this firmware".',
        }),
    extractionVerdict: extraction.verdict,
    query: r.query,
    matchCount: r.hits?.length ?? 0,
    filesExamined: r.coverage?.filesExamined ?? null,
    hits: r.hits ?? [],
  };
}
