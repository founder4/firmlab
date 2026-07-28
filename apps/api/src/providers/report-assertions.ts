/**
 * The findings ledger as the HTML report renders it — and the wall between the two populations inside it.
 *
 * The report is the artifact that leaves the workbench. It gets archived, attached to a ticket, forwarded to a
 * vendor, read six months later by someone who never used FirmLab, and read without the UI's coverage banner,
 * without the MCP honesty instructions, without anyone to ask. Every separation the rest of the codebase enforces
 * has to survive being flattened into one HTML file by itself, or it does not survive at all.
 *
 * Three things follow, and this module exists to do all three in one place so they cannot drift apart:
 *
 *   1. **Assertions are rendered apart, never interleaved.** The caller hands over the whole ledger and gets back
 *      two strings it cannot recombine into a single table — measured rows and asserted ones are partitioned here,
 *      by the `operator_assertion` sentinel rather than by source, so no caller and no hand-edited source string
 *      decides which section a row lands in. The operator section emits no proof-state markup at all: not a greyed
 *      badge, not an em dash where one would go. A reader scanning the document sees a different shape, states the
 *      author on the row's face, and is told in the section's own prose that these count towards no analysis stage.
 *
 *   2. **A dispute annotates; it never overrides.** `disputes_finding` was recorded and then read by nobody: a
 *      reader looking at a computed row had no indication that a named person had contested it. Here the contested
 *      row carries the contest inline — who, when, on what basis — while its proof state is printed verbatim, and
 *      the annotation says in as many words that code decided that state and the dispute does not move it. The
 *      dispute is testimony about a measurement; both stand and the reader weighs them. That is also why an
 *      operator cannot express a dispute any other way: the ladder is not theirs to edit.
 *
 *   3. **History is shown, not summarised away.** An amended assertion renders the claim it superseded underneath
 *      the current one, and a withdrawn assertion is rendered as withdrawn rather than dropped. A ledger whose
 *      argument is that a retraction survives cannot present a report in which the retraction is invisible.
 *
 * Pure string building over plain data: no store import, no I/O, so every rule above is reachable from a unit test.
 * `report.ts` binds it to the database. Everything interpolated goes through `escapeHtml` — an assertion is a
 * sentence a human typed, and this document is opened in a browser.
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

/**
 * A ledger row, structurally typed so `Finding` from core satisfies it without this module importing the store.
 * `severity` and `proofState` are `string`: a stored row was written by an older build and may hold a value this
 * one does not know, and a report that throws on an unfamiliar label is worse than one that prints it.
 */
export interface ReportFinding {
  id: string;
  source: string;
  kind: string;
  title: string;
  severity: string;
  proofState: string;
  rationale?: string | undefined;
  evidence?: Record<string, unknown> | undefined;
  assertion?: OperatorAssertion | undefined;
}

/** Severity order for display. Anything unrecognised sorts last rather than being dropped. */
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * How many measured rows the table prints. A bound is not an answer (CLAUDE.md): the cut is by severity and never
 * by arrival order, the rule is stated in the document beside the table, and a contested row is exempt — dropping
 * one would silently delete the dispute annotation that is the whole point of rendering it.
 */
export const MAX_MEASURED_ROWS = 300;

export function escapeHtml(s: unknown): string {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] ?? c);
}

/**
 * Styles for both sections. They ship with the markup rather than in the report's stylesheet because the visual
 * distinction between a measurement and a claim is part of this module's contract, not a theme detail: the operator
 * block is dashed and inset, the contest is a tinted callout, and neither borrows the table's chrome.
 */
export const LEDGER_CSS = `
  section.operator { border: 1px dashed #b0894833; border-left: 3px dashed #b08948; border-radius: 6px; padding: 2px 16px 16px; margin-top: 34px; }
  section.operator h2 { border-bottom: 1px solid #b0894855; }
  section.operator h3 { font-size: 13px; margin: 26px 0 6px; padding-bottom: 4px; border-bottom: 1px dashed #b0894855; }
  .notice { background: #b0894814; border-left: 3px solid #b08948; padding: 8px 12px; margin: 10px 0; font-size: 12.5px; }
  .assert { border-left: 3px dashed #b08948; padding: 2px 0 2px 12px; margin: 16px 0; }
  .assert.retracted { border-left-color: #8b93a6; }
  .assert-title { font-weight: 600; margin: 4px 0; }
  .badge-asserted { font-family: ui-monospace, monospace; font-size: 10.5px; border: 1px dashed #b08948; color: #8a6a34; border-radius: 4px; padding: 1px 6px; }
  .badge-asserted.retracted { border-color: #8b93a6; color: #6b7488; }
  .attribution { font-size: 12.5px; margin: 4px 0; }
  .basis { font-size: 12.5px; margin: 4px 0; }
  .history { font-size: 12px; margin: 6px 0 0; padding: 6px 10px; border-left: 2px solid #b0894877; background: #b089480f; }
  .history ol { margin: 4px 0 0; padding-left: 20px; }
  .dispute { border-left: 3px solid #b08948; background: #b0894814; padding: 6px 10px; margin-top: 6px; font-size: 12px; }
  tr.contested td { background: #b089480a; }
  .rationale { font-size: 11.5px; margin-top: 3px; }
  /* The report's base rule is word-break: break-word, and the annotation makes the last column wide enough that
     the first three collapse to one character per line ("needs_runt / ime_reprodu / ction") — which is what
     rendering the page showed and no assertion about the HTML would have. */
  table.ledger td.narrow, table.ledger th.narrow { white-space: nowrap; width: 1%; }
  @media (prefers-color-scheme: dark) {
    .badge-asserted { color: #d0a862 !important; }
    .notice, .dispute, .history { background: #b089481f !important; }
    tr.contested td { background: #b0894814 !important; }
  }`;

function sevCell(severity: string): string {
  return `<span class="mono">${escapeHtml(severity)}</span>`;
}

/** Deterministic display order: severity, then proof state, then title, then id. Never insertion order. */
function bySeverityThenName(a: ReportFinding, b: ReportFinding): number {
  const ra = SEVERITY_RANK[a.severity] ?? 9;
  const rb = SEVERITY_RANK[b.severity] ?? 9;
  if (ra !== rb) return ra - rb;
  if (a.proofState !== b.proofState) return a.proofState < b.proofState ? -1 : 1;
  if (a.title !== b.title) return a.title < b.title ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/**
 * The contest, rendered onto the computed row. Says who and why, then says — in the same block, not in a legend —
 * that the proof state beside it is unchanged. The two sentences have to travel together: an annotation reading
 * only "DISPUTED" invites the reader to discount the measurement, which is precisely the override this refuses.
 */
function disputeBlock(target: ReportFinding, disputes: readonly ReportFinding[]): string {
  const blocks = disputes.map((d) => {
    const a = d.assertion;
    const who = a ? (a.authorKind === 'agent' ? `${a.assertedBy} (agent)` : a.assertedBy) : 'an unrecorded author';
    const when = a ? assertionDay(a.assertedAt) : 'an unrecorded date';
    const basis = d.rationale ? ` ${escapeHtml(d.rationale)}` : '';
    return `<div class="dispute"><strong>CONTESTED BY AN OPERATOR</strong> — ${escapeHtml(who)} asserts on ${escapeHtml(
      when,
    )} that this finding is wrong: “${escapeHtml(d.title)}”.${basis}<div class="muted">Recorded as operator assertion <code>${escapeHtml(
      d.id,
    )}</code>, and listed in full in the operator section. This is testimony about a measurement, not a measurement: the proof state of this row is still <code>${escapeHtml(
      target.proofState,
    )}</code>, decided by code from the evidence, and the dispute neither changes it, downgrades it nor removes the row. Both stand; a reader weighs them.</div></div>`;
  });
  return blocks.join('');
}

function measuredRow(f: ReportFinding, disputes: readonly ReportFinding[]): string {
  const rationale = f.rationale ? `<div class="muted rationale">${escapeHtml(f.rationale)}</div>` : '';
  const contested = disputes.length > 0;
  const cells: [string, string][] = [
    ['narrow', sevCell(f.severity)],
    ['narrow', `<code class="proof">${escapeHtml(f.proofState)}</code>`],
    ['narrow', `<code>${escapeHtml(f.source)}</code>`],
    ['', `${escapeHtml(f.title)}${rationale}${contested ? disputeBlock(f, disputes) : ''}`],
  ];
  const tds = cells.map(([cls, c]) => (cls ? `<td class="${cls}">${c}</td>` : `<td>${c}</td>`)).join('');
  return `<tr${contested ? ' class="contested"' : ''}>${tds}</tr>`;
}

/**
 * The measured half. Rendered even when it is empty, with the sentence that an empty ledger is not a clean image —
 * an omitted section reads as "nothing to say here", which is the single inference this workbench exists to refuse.
 */
function renderMeasured(measured: ReportFinding[], disputesByTarget: Map<string, ReportFinding[]>): string {
  const head = `<section><h2>Findings — measured (${measured.length})</h2>`;
  if (measured.length === 0) {
    return `${head}<p class="muted">No measured findings are recorded for this image. That is a count of rows in the ledger, not a verdict: a stage that never ran contributes nothing to it, and an empty list here is not evidence that the image is clean. Check which analyses were executed before reading this as a negative.</p></section>`;
  }

  // Contested rows are selected first and exempt from the cap: the annotation is the reason this section exists,
  // and a cut that could drop it would make the dispute inert again for exactly the images with the most rows.
  const contested = measured.filter((f) => disputesByTarget.has(f.id)).sort(bySeverityThenName);
  const rest = measured.filter((f) => !disputesByTarget.has(f.id)).sort(bySeverityThenName);
  const room = Math.max(0, MAX_MEASURED_ROWS - contested.length);
  const shown = [...contested, ...rest.slice(0, room)].sort(bySeverityThenName);
  const omitted = measured.length - shown.length;

  const rule =
    omitted > 0
      ? `<p class="muted">Showing ${shown.length} of ${measured.length}. Rows are ordered by severity (highest first, then proof state and title) and the ${omitted} lowest-ranked are omitted — the cut is by that rule, never by the order the rows were written. Every contested row is shown regardless of the cap.</p>`
      : '';
  const rows = shown.map((f) => measuredRow(f, disputesByTarget.get(f.id) ?? []));
  const header = [
    ['narrow', 'Severity'],
    ['narrow', 'Proof state'],
    ['narrow', 'Source'],
    ['', 'Finding'],
  ]
    .map(([cls, h]) => (cls ? `<th class="${cls}">${escapeHtml(h)}</th>` : `<th>${escapeHtml(h)}</th>`))
    .join('');
  return `${head}<p class="muted">Every row below was decided by code, and its proof state says what was actually established. This count excludes operator assertions entirely — those are recorded further down and are not measurements.</p>${rule}<table class="ledger"><thead><tr>${header}</tr></thead><tbody>${rows.join(
    '',
  )}</tbody></table></section>`;
}

/** The references an author cited, if any survived onto the row's evidence. */
function referenceList(f: ReportFinding): string {
  const raw = f.evidence?.references;
  if (!Array.isArray(raw)) return '';
  const refs = raw.filter((r): r is string => typeof r === 'string' && r.trim().length > 0);
  if (refs.length === 0) return '';
  return `<div class="basis"><strong>Cited:</strong> ${refs.map((r) => `<code>${escapeHtml(r)}</code>`).join(' · ')}</div>`;
}

function revisionLine(r: AssertionRevision): string {
  const title = r.title ? ` — “${escapeHtml(r.title)}”` : '';
  const target = r.disputesFindingId ? ` (contested <code>${escapeHtml(r.disputesFindingId)}</code>)` : '';
  return `<li><code>${escapeHtml(r.claim)}</code>, stood from ${escapeHtml(assertionDay(r.from))} to ${escapeHtml(
    assertionDay(r.supersededAt),
  )}${title}${target}<div class="muted">${escapeHtml(r.rationale)}</div></li>`;
}

/**
 * What this claim replaced. An amendment that showed only its result would let an author restate a strong claim as
 * a weak one with no trace, which is the same erasure a delete performs — so the predecessors are printed, oldest
 * first, each with the window it stood in.
 */
function historyBlock(a: OperatorAssertion): string {
  const revisions = revisionsOf(a);
  if (a.amendedAt === undefined && revisions.length === 0) return '';
  if (revisions.length === 0) {
    return `<div class="history"><strong>Amended ${escapeHtml(
      assertionDay(a.amendedAt ?? a.assertedAt),
    )}.</strong> The claim it replaced was not preserved — this row was amended by a build that overwrote its predecessor. What stands here is the current claim only.</div>`;
  }
  const plural = revisions.length === 1 ? 'claim' : 'claims';
  return `<div class="history"><strong>Amended ${escapeHtml(assertionDay(a.amendedAt ?? a.assertedAt))}, superseding ${
    revisions.length
  } earlier ${plural}.</strong> An amendment appends; it never overwrites. What the author previously stated, and on what basis:<ol>${revisions
    .map(revisionLine)
    .join('')}</ol></div>`;
}

/** The finding a dispute names, or an honest statement that it can no longer be shown. */
function disputeTargetLine(f: ReportFinding, ledger: readonly ReportFinding[]): string {
  const targetId = f.assertion?.disputesFindingId;
  if (!targetId) return '';
  const target = ledger.find((r) => r.id === targetId);
  if (!target) {
    return `<div class="basis">Contests finding <code>${escapeHtml(
      targetId,
    )}</code>, which is no longer in this image's ledger. Re-running a provider replaces its rows with new ids, so a dispute can outlive the row it was recorded against: the claim is kept, and what it pointed at cannot be shown here.</div>`;
  }
  return `<div class="basis">Contests finding <code>${escapeHtml(targetId)}</code> — “${escapeHtml(
    target.title,
  )}” (<code>${escapeHtml(target.proofState)}</code>, source <code>${escapeHtml(
    target.source,
  )}</code>). That row stands exactly as code decided it; this assertion is recorded beside it, not over it.</div>`;
}

/**
 * One asserted row. Deliberately not a table row: an assertion has no proof state, no source worth printing and a
 * basis that is a paragraph, so giving it the findings table's columns would force it into the shape of a
 * measurement and leave a reader comparing the two by column position.
 */
function assertionBlock(f: ReportFinding, ledger: readonly ReportFinding[]): string {
  const a = f.assertion;
  const retracted = a?.status === 'withdrawn';
  const cls = retracted ? 'assert retracted' : 'assert';
  const badge = retracted ? 'withdrawn · not measured' : 'asserted · not measured';
  const meaning = a ? (CLAIM_MEANING[a.claim] ?? 'Unrecognised claim — read it as an unverified assertion.') : '';
  const attribution = a
    ? escapeHtml(describeAssertion(a))
    : `This row carries the operator-assertion provenance but no author record. Treat it as an unattributed claim; ${escapeHtml(
        NOT_A_MEASUREMENT,
      )}`;
  const basis = f.rationale ? `<div class="basis"><strong>Stated basis:</strong> ${escapeHtml(f.rationale)}</div>` : '';
  // The meaning appears once per block, not twice. `describeAssertion` already carries it for a standing claim, and
  // a caveat printed twice two lines apart is one a reader learns to skip — the skipped paragraph being the caveat.
  // A withdrawn row's attribution states the retraction instead, so this is where its meaning gets said.
  const claimLine = a
    ? `<div class="basis"><strong>Claim:</strong> <code>${escapeHtml(a.claim)}</code>${
        retracted ? ` — ${escapeHtml(meaning)}` : ''
      }</div>`
    : '';
  return `<div class="${cls}"><span class="badge-asserted${
    retracted ? ' retracted' : ''
  }">${badge}</span> <span class="muted mono">severity asserted: ${escapeHtml(
    f.severity,
  )}</span><div class="assert-title">${escapeHtml(
    f.title,
  )}</div><div class="attribution">${attribution}</div>${claimLine}${basis}${referenceList(f)}${disputeTargetLine(
    f,
    ledger,
  )}${a ? historyBlock(a) : ''}</div>`;
}

/**
 * The operator half. Returns the empty string when there is nothing to show: a standing heading over an empty
 * section trains a reader to skip it, and the one time it is not empty is the time it must not be skipped.
 */
function renderOperator(
  asserted: ReportFinding[],
  withdrawn: ReportFinding[],
  ledger: readonly ReportFinding[],
): string {
  if (asserted.length === 0 && withdrawn.length === 0) return '';
  const active =
    asserted.length > 0
      ? `${asserted
          .sort(bySeverityThenName)
          .map((f) => assertionBlock(f, ledger))
          .join('')}`
      : '<p class="muted">No assertion currently stands on this image; the retracted ones below are kept as part of the record.</p>';
  const retracted =
    withdrawn.length > 0
      ? `<h3>Withdrawn assertions (${withdrawn.length}) — retracted, and kept</h3><p class="muted">A retraction is part of the record, so it is shown rather than deleted: "this was wrong, and here is why" is often the most useful row a ledger holds. A withdrawn claim is counted nowhere and contests nothing.</p>${withdrawn
          .sort(bySeverityThenName)
          .map((f) => assertionBlock(f, ledger))
          .join('')}`
      : '';
  return `<section class="operator"><h2>Operator assertions (${asserted.length}) — asserted by a named author, not measured</h2><p class="notice">${escapeHtml(
    NOT_A_MEASUREMENT,
  )}</p><p class="muted">Nothing in this section was produced by an analysis. Each block is a claim recorded by the named author on the basis they state, and it is kept apart from the findings above for that reason: none of it carries a proof state, none of it counts towards any analysis stage, and none of it is included in the measured count. Where an author disputes a computed finding, that finding is annotated where it appears above and its proof state is left exactly as code decided it.</p>${active}${retracted}</section>`;
}

/**
 * Pure: render the whole ledger as two independent sections.
 *
 * Takes the complete ledger and does the partition itself — the caller never receives the pieces, so it cannot
 * interleave the populations or hand the wrong one to the wrong renderer. Partitioning is by the
 * `operator_assertion` sentinel, so a row whose source was hand-edited still lands where its provenance says.
 */
export function renderLedgerSections(findings: readonly ReportFinding[]): { measured: string; operator: string } {
  const { measured, asserted, withdrawn } = partitionByProvenance(findings);
  const disputesByTarget = indexDisputes(findings);
  return {
    measured: renderMeasured(measured, disputesByTarget),
    operator: renderOperator(asserted, withdrawn, findings),
  };
}
