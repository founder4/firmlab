/**
 * The findings ledger as the workbench renders it — and the one thing in it that a person, not code, wrote.
 *
 * Every row here was decided by code, and its `ProofState` is the record of what was actually established. An
 * operator can contest one (`disputes_finding`), and until now that contest was recorded and read by nobody: the
 * dispute lived in the operator ledger, the measurement lived here, and a reader of this table had no indication
 * that a named person had said it was wrong. The HTML report started annotating the contested row in `422c18f`;
 * this is the same annotation on the screen the analyst actually looks at.
 *
 * Three rules the annotation obeys, and they are the reason it is a block of prose rather than a "DISPUTED" chip:
 *
 *   1. **It annotates; it never overrides.** The proof state beside it is printed exactly as code decided it, and
 *      the annotation says so in the same block — who contested it, when, on what basis, and then that the state is
 *      unchanged, not downgraded, and the row not removed. The two sentences have to travel together: a bare
 *      "DISPUTED" invites a reader to discount the measurement, which is precisely the override this refuses. A
 *      dispute is testimony ABOUT a measurement; both stand and a reader weighs them.
 *   2. **It never moves the row.** The dispute changes neither the row's position (severity order, as before) nor
 *      its severity, and a contested row is exempt from the display cap — a cut that could drop it would make the
 *      dispute inert again on exactly the largest images, which are the ones where it is hardest to notice.
 *   3. **A dangling dispute is stated, not dropped.** `syncFindings` replaces a provider's rows with new ids on
 *      every re-run, so a dispute recorded against yesterday's row id points at nothing today. Silently rendering
 *      nothing would delete a person's claim by accident; it is reported above the table instead, with why.
 *
 * The badge and severity vocabulary live here too, because they are what makes an assertion legible as *not* a
 * measurement at a glance, and this is now the only table that shows both kinds of row side by side.
 *
 * Localisation stops at the gloss. The proof-state CODE is an identifier that crosses the API and lands in SQLite,
 * so the dispute annotation prints it verbatim — that is the whole point of the sentence it sits in. What the badge
 * shows is the shared `proofState` gloss, the same one the operator ledger and the report read, so a row cannot be
 * worded three ways. Finding titles, rationales and source strings are the record providers wrote when they ran and
 * are shown as written, in whatever language produced them.
 */
import { Fragment, useState } from 'react';
import type { Finding, FindingProvenance, OperatorAssertion } from '../api';
import { messages, useMessages } from '../i18n';

/**
 * The ladder, plus the one value that is not on it. `operator_assertion` gets a dashed border and the theme's
 * agent/heuristic trust colour rather than a rung's colour, so an asserted row is distinguishable from a measured
 * one at a glance and not only by reading the label — the ladder's own colours are reserved for code's verdicts.
 *
 * The human gloss is deliberately NOT here. It lives in the shared `proofState` namespace beside the sentence
 * stating what each state does and does not claim, so a label and its meaning cannot drift apart, and so the one
 * translation of `blocked_by_*` that must never read as "clean" has exactly one home.
 */
export const PROOF_STATE_META: Record<FindingProvenance, { color: string; asserted?: boolean }> = {
  confirmed_full_system: { color: 'var(--ok)' },
  confirmed_in_emulation: { color: 'var(--ok)' },
  static_confirmed: { color: 'var(--info)' },
  needs_runtime_reproduction: { color: 'var(--sev-medium)' },
  blocked_by_platform: { color: 'var(--text-dim)' },
  blocked_by_security: { color: 'var(--text-dim)' },
  false_positive: { color: 'var(--text-dim)' },
  operator_assertion: { color: 'var(--trust-agent)', asserted: true },
};

export function ProofStateBadge({ state }: { state: FindingProvenance }): JSX.Element {
  const t = useMessages();
  const m = PROOF_STATE_META[state] ?? { color: 'var(--text-dim)' };
  // A state the catalogue does not know falls back to the CODE, never to a blank: an unglossed identifier is still
  // the truth about the row, and an empty badge would quietly drop it.
  const label = t.proofState.label[state] ?? state;
  return (
    <span
      className="mono"
      style={{
        color: m.color,
        border: `1px ${m.asserted ? 'dashed' : 'solid'} ${m.color}`,
        borderRadius: 4,
        padding: '1px 6px',
        fontSize: 10.5,
      }}
    >
      {label}
    </span>
  );
}

export const SEV_COLOR: Record<string, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--text-dim)',
  info: 'var(--text-dim)',
};

/** How many rows the table prints before it states what it cut and by what rule. Contested rows are exempt. */
export const MAX_LEDGER_ROWS = 300;

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Deterministic display order: severity, then proof state, then title, then id — the same order the HTML report
 * uses, and never insertion order. Ties broken by arrival order would make the cap's cut an artifact of the order
 * providers happened to run in, which is the "a bound is not an answer" rule in CLAUDE.md.
 */
function bySeverityThenName(a: Finding, b: Finding): number {
  const ra = SEVERITY_RANK[a.severity] ?? 9;
  const rb = SEVERITY_RANK[b.severity] ?? 9;
  if (ra !== rb) return ra - rb;
  if (a.proofState !== b.proofState) return a.proofState < b.proofState ? -1 : 1;
  if (a.title !== b.title) return a.title < b.title ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/**
 * Pure: an ISO day, the granularity every operator surface dates a claim to.
 *
 * The date itself is an ISO string in both languages — a claim is dated the way it was recorded — but the sentence
 * standing in for a missing one is prose, so it comes from the catalogue. `messages()` rather than a hook because
 * this is a helper, not a component; it is called from a render pass that already subscribes to the locale.
 */
export function assertionDay(ms: number | undefined): string {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return messages().findings.unrecordedDate;
  return new Date(ms).toISOString().slice(0, 10);
}

/** Pure: how a dispute's author is named, agent-hood included, or an honest blank when the row carries no author. */
export function disputeAuthor(d: Finding): string {
  const a = d.assertion;
  if (!a) return messages().findings.unrecordedAuthor;
  return a.authorKind === 'agent' ? `${a.assertedBy}${messages().findings.agentSuffix}` : a.assertedBy;
}

/**
 * Pure: index the ACTIVE disputes by the finding each one contests.
 *
 * Withdrawn disputes are excluded deliberately. A retraction means the author took the contest back, so continuing
 * to mark the row contested would report a disagreement that no longer exists — and the withdrawn row is still
 * shown, in the operator ledger, naming what it used to contest, so nothing is hidden by leaving it out here.
 */
export function indexDisputes(findings: readonly Finding[]): Map<string, Finding[]> {
  const byTarget = new Map<string, Finding[]>();
  for (const f of findings) {
    const a = f.assertion;
    if (!a || a.claim !== 'disputes_finding' || a.status === 'withdrawn') continue;
    const target = a.disputesFindingId;
    if (!target) continue;
    const list = byTarget.get(target);
    if (list) list.push(f);
    else byTarget.set(target, [f]);
  }
  return byTarget;
}

/**
 * Pure: the active disputes whose target is not in this ledger any more.
 *
 * These are the rows a naive renderer loses: it looks up the target, finds nothing, and draws nothing at all — so a
 * claim someone recorded disappears from the screen because an unrelated provider was re-run. They are returned so
 * the table can say what happened instead.
 */
export function danglingDisputes(findings: readonly Finding[]): Finding[] {
  const present = new Set(findings.map((f) => f.id));
  const out: Finding[] = [];
  for (const f of findings) {
    const a = f.assertion;
    if (!a || a.claim !== 'disputes_finding' || a.status === 'withdrawn') continue;
    const target = a.disputesFindingId;
    if (!target || present.has(target)) continue;
    out.push(f);
  }
  return out;
}

export interface LedgerView {
  rows: Finding[];
  omitted: number;
  /** The sentence stating what was cut and by what rule, or null when nothing was. */
  rule: string | null;
}

/**
 * Pure: which rows the table prints, in what order, and what it says about the ones it did not.
 *
 * Contested rows are selected first and exempt from the cap for the reason the report gives: the annotation is the
 * whole point of rendering the contest, and a cut that could drop it would make the dispute inert again exactly
 * where a reader is least able to notice.
 */
export function selectLedgerRows(
  findings: readonly Finding[],
  contestedIds: ReadonlySet<string>,
  cap = MAX_LEDGER_ROWS,
): LedgerView {
  const sorted = [...findings].sort(bySeverityThenName);
  if (sorted.length <= cap) return { rows: sorted, omitted: 0, rule: null };
  const contested = sorted.filter((f) => contestedIds.has(f.id));
  const rest = sorted.filter((f) => !contestedIds.has(f.id));
  const room = Math.max(0, cap - contested.length);
  const rows = [...contested, ...rest.slice(0, room)].sort(bySeverityThenName);
  const omitted = sorted.length - rows.length;
  if (omitted === 0) return { rows, omitted: 0, rule: null };
  // The sentence travels with the selection rather than being assembled at the render site: a bound that states
  // what it dropped is part of the answer, and keeping the two together is what lets a test hold this to it.
  return { rows, omitted, rule: messages().findings.cutRule(rows.length, sorted.length, omitted) };
}

/**
 * The contest, rendered onto the computed row. Says who and why, then says — in the same block, not in a legend a
 * reader has to go and find — that the proof state beside it is untouched.
 */
function DisputeNote({ target, disputes }: { target: Finding; disputes: readonly Finding[] }): JSX.Element {
  const t = useMessages();
  return (
    <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 6 }}>
      {disputes.map((d) => (
        <div
          key={d.id}
          style={{
            borderLeft: '3px dashed var(--trust-agent)',
            background: 'color-mix(in srgb, var(--trust-agent) 8%, transparent)',
            borderRadius: 'var(--r-sm)',
            padding: '6px 10px',
            maxWidth: '72ch',
          }}
        >
          <div style={{ fontSize: 12 }}>
            <strong style={{ color: 'var(--trust-agent)' }}>{t.findings.dispute.heading}</strong> —{' '}
            {t.findings.dispute.claim(disputeAuthor(d), assertionDay(d.assertion?.assertedAt), d.title)}
            {d.rationale ? ` ${d.rationale}` : ''}
          </div>
          {/* One block, never two: the id and the proof-state code are printed verbatim between the runs of prose,
              and the half saying the state is untouched cannot be separated from the half naming the contest. */}
          <div className="hint" style={{ marginTop: 4 }}>
            {t.findings.dispute.recordedAs} <span className="mono">{d.id}</span>
            {t.findings.dispute.stillStates} <span className="mono">{target.proofState}</span>
            {t.findings.dispute.stands}
          </div>
        </div>
      ))}
    </div>
  );
}

/** The disputes that name a row this ledger no longer holds — surfaced, because dropping one deletes a claim. */
function DanglingDisputeNote({ dangling }: { dangling: readonly Finding[] }): JSX.Element {
  const t = useMessages();
  return (
    <div className="banner banner-warn" style={{ marginTop: 10 }}>
      {/* 72ch, like `.panel-sub`: the prose that carries this screen's refusals is the prose most likely to be
          skipped, and at full panel width it runs past 150 characters a line. */}
      <div style={{ maxWidth: '72ch' }}>{t.findings.dangling.lead(dangling.length)}</div>
      <ul style={{ margin: '6px 0 0', paddingLeft: 18, maxWidth: '72ch' }}>
        {dangling.map((d) => (
          <li key={d.id} style={{ fontSize: 12 }}>
            {t.findings.dangling.contests(disputeAuthor(d))}{' '}
            <span className="mono">{d.assertion?.disputesFindingId}</span> {t.findings.dangling.quoted(d.title)}
            {d.rationale ? `. ${d.rationale}` : ''}
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * The ledger table. `findings` is the whole ledger — measured rows AND the operator assertions the same endpoint
 * serves — because a dispute is only findable by looking at both: the annotation lives on a measured row and the
 * claim that produces it is an asserted one.
 */
export function FindingsLedger({ findings }: { findings: readonly Finding[] }): JSX.Element {
  const t = useMessages();
  const [showAll, setShowAll] = useState(false);
  /**
   * Which rows have their reasoning open.
   *
   * `rationale` is the sentence saying WHY a finding sits at its proof state — the difference between "this is a
   * lead" and "this is a lead BECAUSE the bounded search expired before it settled" — and until now it reached
   * the reader on operator disputes only. It cannot simply be printed: 98% of the rows in this corpus carry one,
   * median 196 characters, so always-on would triple the height of a 740-row table and make the ledger unusable.
   * A row therefore opens, and the affordance is a real focusable button rather than a click on the `<tr>`.
   */
  const [openReasons, setOpenReasons] = useState<ReadonlySet<string>>(new Set());
  const toggleReason = (id: string): void =>
    setOpenReasons((prev) => {
      const next = new Set(prev);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  const disputesByTarget = indexDisputes(findings);
  const dangling = danglingDisputes(findings);
  const contestedIds = new Set(disputesByTarget.keys());
  const view = selectLedgerRows(findings, contestedIds, showAll ? Number.POSITIVE_INFINITY : MAX_LEDGER_ROWS);
  // Counted, not filtered: an assertion belongs in this table — it just may never be read as a measurement.
  const assertedCount = findings.filter((f) => f.assertion).length;

  return (
    <div className="panel">
      <div className="panel-title">{t.findings.title(findings.length)}</div>
      <div className="panel-sub">
        {t.findings.sub}
        {assertedCount > 0 ? <> {t.findings.asserted(assertedCount)}</> : null}
        {disputesByTarget.size > 0 ? <> {t.findings.contested(disputesByTarget.size)}</> : null}
      </div>

      {dangling.length > 0 ? <DanglingDisputeNote dangling={dangling} /> : null}

      {view.rows.length === 0 ? (
        <div className="hint">{t.findings.empty}</div>
      ) : (
        <>
          {view.rule ? (
            <div className="hint" style={{ marginTop: 10, maxWidth: '72ch' }}>
              {view.rule}{' '}
              <button type="button" className="btn btn-sm btn-ghost" onClick={() => setShowAll(true)}>
                {t.findings.showAllCount(findings.length)}
              </button>
            </div>
          ) : null}
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data">
              <thead>
                <tr>
                  <th style={{ width: 28 }} />
                  <th>{t.findings.col.severity}</th>
                  <th>{t.findings.col.finding}</th>
                  <th>{t.findings.col.source}</th>
                  <th>{t.findings.col.proofState}</th>
                </tr>
              </thead>
              <tbody>
                {view.rows.map((f) => {
                  const disputes = disputesByTarget.get(f.id) ?? [];
                  const open = openReasons.has(f.id);
                  return (
                    <Fragment key={f.id}>
                      <tr>
                        {/* A contested row is marked with an inset rule rather than a background: an inline background
                          would beat `.data tbody tr:hover` and silently cost the row its hover feedback. */}
                        <td style={disputes.length ? { boxShadow: 'inset 2px 0 0 var(--trust-agent)' } : undefined}>
                          {/* The reasoning toggle. A real button rather than a click on the `<tr>`: a row is not
                            focusable, and the sentence behind it is the one that separates "this is a lead" from
                            "this is a lead BECAUSE the search expired". Absent when the provider wrote none, so an
                            empty chevron never promises an explanation that does not exist. */}
                          {f.rationale ? (
                            <button
                              type="button"
                              className="btn btn-sm btn-ghost reason-toggle"
                              aria-expanded={open}
                              aria-label={t.findings.whyLabel}
                              title={t.findings.whyLabel}
                              onClick={() => toggleReason(f.id)}
                            >
                              {open ? '▾' : '▸'}
                            </button>
                          ) : null}
                        </td>
                        <td>
                          <span style={{ color: SEV_COLOR[f.severity] ?? 'var(--text-dim)' }}>●</span>
                        </td>
                        <td style={{ fontSize: 12.5 }}>
                          {f.title}
                          {/* An assertion never appears here without its author on the same line. */}
                          {f.assertion ? (
                            <div className="hint">
                              {t.findings.assertedBy(f.assertion.assertedBy)}
                              {f.assertion.authorKind === 'agent' ? t.findings.agentSuffix : ''}
                              {f.assertion.status === 'withdrawn' ? t.findings.withdrawnSuffix : ''}
                            </div>
                          ) : null}
                          {/* Why it was retracted, on the row rather than behind the chevron. The chevron holds
                            the ORIGINAL rationale, so a retracted row expanded into the argument FOR a claim
                            that had been taken back, with the taking-back nowhere. Reading a retraction must not
                            require a click. */}
                          {f.assertion?.status === 'withdrawn' ? <WithdrawalNote assertion={f.assertion} /> : null}
                          {disputes.length ? <DisputeNote target={f} disputes={disputes} /> : null}
                        </td>
                        <td className="mono hint" style={{ fontSize: 11 }}>
                          {f.source}
                        </td>
                        <td>
                          {/* Printed verbatim on a contested row: the dispute is recorded beside it, never over it. */}
                          <ProofStateBadge state={f.proofState} />
                          {/* The second axis, UNDER the rung rather than beside it: how far it was proven is the
                            headline, how it was known qualifies it. A row with no channel recorded prints
                            nothing at all — an "unknown" chip would imply the question was asked and answered. */}
                          {f.evidenceChannel && (
                            <div className="hint mono" style={{ fontSize: 10.5, marginTop: 3 }}>
                              {f.evidenceChannel}
                            </div>
                          )}
                          {/* And the one thing that changes what the rung MEANS: the subject was not as shipped. */}
                          {f.interventions?.length ? (
                            <div
                              className="hint"
                              style={{ fontSize: 11, marginTop: 3, color: 'var(--sev-medium, #e6b45c)' }}
                              title={f.interventions.join(' · ')}
                            >
                              {t.findings.interventionMark(f.interventions.length)}
                            </div>
                          ) : null}
                        </td>
                      </tr>
                      {open && f.rationale ? (
                        <tr>
                          {/* Full width, under the row it explains. The provider WROTE this sentence while measuring,
                            so it renders as written, in whatever language produced it. */}
                          <td colSpan={5} className="reason-cell">
                            {/* A retracted row's reasoning is labelled as the retracted claim's, so an expanded
                              cell is never read as a standing argument. */}
                            <span className="eyebrow">
                              {f.assertion?.status === 'withdrawn' ? t.findings.whyWithdrawn : t.findings.why}
                            </span>{' '}
                            {f.rationale}
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

/**
 * The sentence that says a claim was taken back, and by whom.
 *
 * `withdrawnReason` had no reader here at all: the row printed "— WITHDRAWN" beside the author and the chevron
 * expanded the ORIGINAL rationale, so the only prose a reader could reach was the argument for a claim that no
 * longer stands. `withdrawnBy` is named because withdrawing your own claim and withdrawing someone else's are
 * different acts, and a retraction with no reason recorded says so rather than rendering as no retraction.
 */
function WithdrawalNote({ assertion }: { assertion: OperatorAssertion }): JSX.Element {
  const t = useMessages();
  const by = assertion.withdrawnBy ?? t.findings.withdrawnUnknownBy;
  return (
    <div className="hint" style={{ fontSize: 11.5, marginTop: 2 }}>
      {assertion.withdrawnReason ? (
        <>
          {t.findings.withdrawnBecause(by)} {assertion.withdrawnReason}
        </>
      ) : (
        t.findings.withdrawnNoReason(by)
      )}
    </div>
  );
}
