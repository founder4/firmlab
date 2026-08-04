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
 *
 * **Language.** Every sentence above lives in `../i18n`, not here, and the locale arrives as a parameter — there is
 * no global to read, because two requests for two languages can be in flight at once. What is NOT localised is
 * anything a reader may need to match against the API, the database or another document: proof states, sources,
 * kinds, severities, assertion claims and ids all print verbatim in both languages, and a finding's title and
 * rationale print as the provider recorded them. Only the document's own scaffolding is translated. The proof-state
 * gloss under the table exists so a code that stays verbatim is still readable in the reader's language.
 */
import { type OperatorAssertion, compareFindings } from '@firmlab/core';
import { type Locale, type Messages, escapeHtml, messages } from '../i18n/index.js';
import {
  type AssertionRevision,
  assertionDay,
  indexDisputes,
  partitionByProvenance,
  revisionsOf,
} from '../operator-findings.js';

export { escapeHtml };

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

// The severity order and the display comparator used to be declared here — the fourth copy of one rule, and it
// carried the same defect as the ledger's: a severity tie broken by `a.proofState < b.proofState`, a string
// comparison under which `blocked_by_platform` outranks `confirmed_full_system` because 'b' precedes 'c'. Both
// read `compareFindings` from `@firmlab/core` now, so the report and the screen cannot order the same rows
// differently.

/**
 * How many measured rows the table prints. A bound is not an answer (CLAUDE.md): the cut is by severity and never
 * by arrival order, the rule is stated in the document beside the table, and a contested row is exempt — dropping
 * one would silently delete the dispute annotation that is the whole point of rendering it.
 */
export const MAX_MEASURED_ROWS = 300;

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
  .gloss { font-size: 12px; margin: 12px 0 0; }
  .gloss dl { margin: 6px 0 0; }
  .gloss dt { font-family: ui-monospace, monospace; font-size: 11.5px; margin-top: 6px; }
  .gloss dd { margin: 1px 0 0 18px; }
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

/** Deterministic display order: the shared rule from core, which reads exactly the four fields it names. */
const bySeverityThenName = compareFindings;

/**
 * The contest, rendered onto the computed row. Says who and why, then says — in the same block, not in a legend —
 * that the proof state beside it is unchanged. The two sentences have to travel together: an annotation reading
 * only "DISPUTED" invites the reader to discount the measurement, which is precisely the override this refuses.
 */
function disputeBlock(target: ReportFinding, disputes: readonly ReportFinding[], t: Messages): string {
  const blocks = disputes.map((d) => {
    const a = d.assertion;
    const who = a
      ? a.authorKind === 'agent'
        ? t.ledger.agentAuthor(a.assertedBy)
        : a.assertedBy
      : t.ledger.unrecordedAuthor;
    const when = a ? assertionDay(a.assertedAt) : t.ledger.unrecordedDate;
    return t.ledger.dispute({
      who,
      when,
      title: d.title,
      rationale: d.rationale,
      assertionId: d.id,
      proofState: target.proofState,
    });
  });
  return blocks.join('');
}

function measuredRow(f: ReportFinding, disputes: readonly ReportFinding[], t: Messages): string {
  const rationale = f.rationale ? `<div class="muted rationale">${escapeHtml(f.rationale)}</div>` : '';
  const contested = disputes.length > 0;
  const cells: [string, string][] = [
    ['narrow', sevCell(f.severity)],
    ['narrow', `<code class="proof">${escapeHtml(f.proofState)}</code>`],
    ['narrow', `<code>${escapeHtml(f.source)}</code>`],
    ['', `${escapeHtml(f.title)}${rationale}${contested ? disputeBlock(f, disputes, t) : ''}`],
  ];
  const tds = cells.map(([cls, c]) => (cls ? `<td class="${cls}">${c}</td>` : `<td>${c}</td>`)).join('');
  return `<tr${contested ? ' class="contested"' : ''}>${tds}</tr>`;
}

/**
 * The measured half. Rendered even when it is empty, with the sentence that an empty ledger is not a clean image —
 * an omitted section reads as "nothing to say here", which is the single inference this workbench exists to refuse.
 */
function renderMeasured(
  measured: ReportFinding[],
  disputesByTarget: Map<string, ReportFinding[]>,
  t: Messages,
): string {
  // Catalogue prose is inserted raw and only DATA is escaped — the same rule the module had before it was
  // localised. Every sentence here is written in this repository; escaping them would render the quotation marks
  // in "this was wrong, and here is why" as entities for no gain.
  const head = `<section><h2>${t.ledger.measuredHeading(measured.length)}</h2>`;
  if (measured.length === 0) {
    return `${head}<p class="muted">${t.ledger.measuredEmpty}</p></section>`;
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
      ? `<p class="muted">${t.ledger.cutRule({ shown: shown.length, total: measured.length, omitted })}</p>`
      : '';
  const rows = shown.map((f) => measuredRow(f, disputesByTarget.get(f.id) ?? [], t));
  const header = [
    ['narrow', t.ledger.columns.severity],
    ['narrow', t.ledger.columns.proofState],
    ['narrow', t.ledger.columns.source],
    ['', t.ledger.columns.finding],
  ]
    .map(([cls, h]) => (cls ? `<th class="${cls}">${escapeHtml(h)}</th>` : `<th>${escapeHtml(h)}</th>`))
    .join('');
  return `${head}<p class="muted">${t.ledger.measuredIntro}</p>${rule}<table class="ledger"><thead><tr>${header}</tr></thead><tbody>${rows.join(
    '',
  )}</tbody></table>${proofStateGloss(shown, t)}</section>`;
}

/**
 * The gloss under the table: every proof state that actually appears above it, code first and explanation after.
 *
 * The code is an identifier and prints verbatim in every language — a reader who greps the ledger, the API or the
 * database for `blocked_by_platform` has to find the same token here. That is exactly why the gloss exists: a
 * Spanish reader gets the sentence saying the question WAS asked and could not be answered, without the token
 * being translated out from under them. Only the states present are listed, so the legend is about this image
 * rather than a standing table of everything the ladder can hold. A code this build does not recognise is printed
 * with the "written by another version" sentence rather than dropped or guessed at.
 */
function proofStateGloss(shown: readonly ReportFinding[], t: Messages): string {
  const order = Object.keys(t.proofState.meaning);
  const rank = (code: string): number => {
    const i = order.indexOf(code);
    return i < 0 ? order.length : i;
  };
  const present = [...new Set(shown.map((f) => f.proofState))].sort(
    (a, b) => rank(a) - rank(b) || (a < b ? -1 : a > b ? 1 : 0),
  );
  if (present.length === 0) return '';
  const meanings: Record<string, string | undefined> = t.proofState.meaning;
  const items = present
    .map(
      (code) =>
        `<dt><code>${escapeHtml(code)}</code></dt><dd class="muted">${meanings[code] ?? t.proofState.unknown}</dd>`,
    )
    .join('');
  return `<div class="gloss"><strong>${t.ledger.glossHeading}</strong> <span class="muted">${t.ledger.glossNote}</span><dl>${items}</dl></div>`;
}

/** The references an author cited, if any survived onto the row's evidence. */
function referenceList(f: ReportFinding, t: Messages): string {
  const raw = f.evidence?.references;
  if (!Array.isArray(raw)) return '';
  const refs = raw.filter((r): r is string => typeof r === 'string' && r.trim().length > 0);
  if (refs.length === 0) return '';
  return `<div class="basis"><strong>${t.ledger.cited}</strong> ${refs.map((r) => `<code>${escapeHtml(r)}</code>`).join(' · ')}</div>`;
}

function revisionLine(r: AssertionRevision, t: Messages): string {
  return t.ledger.revision({
    claim: r.claim,
    from: assertionDay(r.from),
    to: assertionDay(r.supersededAt),
    rationale: r.rationale,
    title: r.title,
    disputesFindingId: r.disputesFindingId,
  });
}

/**
 * What this claim replaced. An amendment that showed only its result would let an author restate a strong claim as
 * a weak one with no trace, which is the same erasure a delete performs — so the predecessors are printed, oldest
 * first, each with the window it stood in.
 */
function historyBlock(a: OperatorAssertion, t: Messages): string {
  const revisions = revisionsOf(a);
  if (a.amendedAt === undefined && revisions.length === 0) return '';
  const when = assertionDay(a.amendedAt ?? a.assertedAt);
  if (revisions.length === 0) return t.ledger.historyLost(when);
  return t.ledger.history({ when, items: revisions.map((r) => revisionLine(r, t)) });
}

/** The finding a dispute names, or an honest statement that it can no longer be shown. */
function disputeTargetLine(f: ReportFinding, ledger: readonly ReportFinding[], t: Messages): string {
  const targetId = f.assertion?.disputesFindingId;
  if (!targetId) return '';
  const target = ledger.find((r) => r.id === targetId);
  if (!target) return t.ledger.disputeTargetGone(targetId);
  return t.ledger.disputeTarget({
    targetId,
    title: target.title,
    proofState: target.proofState,
    source: target.source,
  });
}

/**
 * One asserted row. Deliberately not a table row: an assertion has no proof state, no source worth printing and a
 * basis that is a paragraph, so giving it the findings table's columns would force it into the shape of a
 * measurement and leave a reader comparing the two by column position.
 */
function assertionBlock(f: ReportFinding, ledger: readonly ReportFinding[], t: Messages): string {
  const a = f.assertion;
  const retracted = a?.status === 'withdrawn';
  const cls = retracted ? 'assert retracted' : 'assert';
  const badge = retracted ? t.ledger.badgeWithdrawn : t.ledger.badgeAsserted;
  const meaning = a ? (t.ledger.claimMeaning[a.claim] ?? t.ledger.unrecognisedClaim) : '';
  const attribution = a ? escapeHtml(t.ledger.describeAssertion(a)) : t.ledger.noAuthorRecord;
  const basis = f.rationale
    ? `<div class="basis"><strong>${t.ledger.statedBasis}</strong> ${escapeHtml(f.rationale)}</div>`
    : '';
  // The meaning appears once per block, not twice. `describeAssertion` already carries it for a standing claim, and
  // a caveat printed twice two lines apart is one a reader learns to skip — the skipped paragraph being the caveat.
  // A withdrawn row's attribution states the retraction instead, so this is where its meaning gets said.
  const claimLine = a
    ? `<div class="basis"><strong>${t.ledger.claim}</strong> <code>${escapeHtml(a.claim)}</code>${
        retracted ? ` — ${meaning}` : ''
      }</div>`
    : '';
  return `<div class="${cls}"><span class="badge-asserted${
    retracted ? ' retracted' : ''
  }">${badge}</span> <span class="muted mono">${t.ledger.assertedSeverity(
    f.severity,
  )}</span><div class="assert-title">${escapeHtml(
    f.title,
  )}</div><div class="attribution">${attribution}</div>${claimLine}${basis}${referenceList(f, t)}${disputeTargetLine(
    f,
    ledger,
    t,
  )}${a ? historyBlock(a, t) : ''}</div>`;
}

/**
 * The operator half. Returns the empty string when there is nothing to show: a standing heading over an empty
 * section trains a reader to skip it, and the one time it is not empty is the time it must not be skipped.
 */
function renderOperator(
  asserted: ReportFinding[],
  withdrawn: ReportFinding[],
  ledger: readonly ReportFinding[],
  t: Messages,
): string {
  if (asserted.length === 0 && withdrawn.length === 0) return '';
  const active =
    asserted.length > 0
      ? `${asserted
          .sort(bySeverityThenName)
          .map((f) => assertionBlock(f, ledger, t))
          .join('')}`
      : `<p class="muted">${t.ledger.noAssertionStands}</p>`;
  const retracted =
    withdrawn.length > 0
      ? `<h3>${t.ledger.withdrawnHeading(withdrawn.length)}</h3><p class="muted">${
          t.ledger.withdrawnIntro
        }</p>${withdrawn
          .sort(bySeverityThenName)
          .map((f) => assertionBlock(f, ledger, t))
          .join('')}`
      : '';
  return `<section class="operator"><h2>${t.ledger.operatorHeading(
    asserted.length,
  )}</h2><p class="notice">${t.ledger.notAMeasurement}</p><p class="muted">${
    t.ledger.operatorIntro
  }</p>${active}${retracted}</section>`;
}

/**
 * Pure: render the whole ledger as two independent sections, in one language.
 *
 * Takes the complete ledger and does the partition itself — the caller never receives the pieces, so it cannot
 * interleave the populations or hand the wrong one to the wrong renderer. Partitioning is by the
 * `operator_assertion` sentinel, so a row whose source was hand-edited still lands where its provenance says.
 *
 * The locale is a parameter with an English default, never a module global: `report.ts` passes what the request
 * asked for, and two requests in two languages cannot interfere.
 */
export function renderLedgerSections(
  findings: readonly ReportFinding[],
  locale: Locale = 'en',
): { measured: string; operator: string } {
  const t = messages(locale);
  const { measured, asserted, withdrawn } = partitionByProvenance(findings);
  const disputesByTarget = indexDisputes(findings);
  return {
    measured: renderMeasured(measured, disputesByTarget, t),
    operator: renderOperator(asserted, withdrawn, findings, t),
  };
}
