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
 */
import { useState } from 'react';
import type { Finding, FindingProvenance } from '../api';

/**
 * The ladder, plus the one value that is not on it. `operator_assertion` gets a dashed border and the theme's
 * agent/heuristic trust colour rather than a rung's colour, so an asserted row is distinguishable from a measured
 * one at a glance and not only by reading the label — the ladder's own colours are reserved for code's verdicts.
 */
export const PROOF_STATE_META: Record<FindingProvenance, { label: string; color: string; asserted?: boolean }> = {
  confirmed_full_system: { label: 'confirmed (full-system)', color: 'var(--ok)' },
  confirmed_in_emulation: { label: 'confirmed (emulated)', color: 'var(--ok)' },
  static_confirmed: { label: 'static-confirmed', color: 'var(--info)' },
  needs_runtime_reproduction: { label: 'needs reproduction', color: 'var(--sev-medium)' },
  blocked_by_platform: { label: 'blocked (platform)', color: 'var(--text-dim)' },
  blocked_by_security: { label: 'blocked (control)', color: 'var(--text-dim)' },
  false_positive: { label: 'false positive', color: 'var(--text-dim)' },
  operator_assertion: { label: 'asserted · not measured', color: 'var(--trust-agent)', asserted: true },
};

export function ProofStateBadge({ state }: { state: FindingProvenance }): JSX.Element {
  const m = PROOF_STATE_META[state] ?? { label: state, color: 'var(--text-dim)' };
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
      {m.label}
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

/** Pure: an ISO day, the granularity every operator surface dates a claim to. */
export function assertionDay(ms: number | undefined): string {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return 'an unrecorded date';
  return new Date(ms).toISOString().slice(0, 10);
}

/** Pure: how a dispute's author is named, agent-hood included, or an honest blank when the row carries no author. */
export function disputeAuthor(d: Finding): string {
  const a = d.assertion;
  if (!a) return 'an unrecorded author';
  return a.authorKind === 'agent' ? `${a.assertedBy} (agent)` : a.assertedBy;
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
  const rule = [
    `Showing ${rows.length} of ${sorted.length}.`,
    'Rows are ordered by severity (highest first, then proof state and title) and the',
    `${omitted} lowest-ranked are omitted — the cut is by that rule, never by the order the rows were written.`,
    'Every contested row is shown regardless of the cap.',
  ].join(' ');
  return { rows, omitted, rule };
}

/**
 * The contest, rendered onto the computed row. Says who and why, then says — in the same block, not in a legend a
 * reader has to go and find — that the proof state beside it is untouched.
 */
function DisputeNote({ target, disputes }: { target: Finding; disputes: readonly Finding[] }): JSX.Element {
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
            <strong style={{ color: 'var(--trust-agent)' }}>Contested by an operator</strong> — {disputeAuthor(d)}{' '}
            asserts on {assertionDay(d.assertion?.assertedAt)} that this finding is wrong: “{d.title}”.
            {d.rationale ? ` ${d.rationale}` : ''}
          </div>
          <div className="hint" style={{ marginTop: 4 }}>
            Recorded as operator assertion <span className="mono">{d.id}</span>, and listed in full in the operator
            ledger. This is testimony about a measurement, not a measurement: the proof state of this row is still{' '}
            <span className="mono">{target.proofState}</span>, decided by code from the evidence, and the dispute
            neither changes it, downgrades it nor removes the row. Both stand; a reader weighs them.
          </div>
        </div>
      ))}
    </div>
  );
}

/** The disputes that name a row this ledger no longer holds — surfaced, because dropping one deletes a claim. */
function DanglingDisputeNote({ dangling }: { dangling: readonly Finding[] }): JSX.Element {
  return (
    <div className="banner banner-warn" style={{ marginTop: 10 }}>
      {/* 72ch, like `.panel-sub`: the prose that carries this screen's refusals is the prose most likely to be
          skipped, and at full panel width it runs past 150 characters a line. */}
      <div style={{ maxWidth: '72ch' }}>
        {dangling.length} recorded dispute{dangling.length === 1 ? '' : 's'} name{dangling.length === 1 ? 's' : ''} a
        finding that is not in this ledger. Re-running a provider replaces its rows with new ids, so a dispute can
        outlive the row it was recorded against: the claim is kept, and what it pointed at cannot be annotated here.
      </div>
      <ul style={{ margin: '6px 0 0', paddingLeft: 18, maxWidth: '72ch' }}>
        {dangling.map((d) => (
          <li key={d.id} style={{ fontSize: 12 }}>
            {disputeAuthor(d)} contests <span className="mono">{d.assertion?.disputesFindingId}</span> — “{d.title}”
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
  const [showAll, setShowAll] = useState(false);
  const disputesByTarget = indexDisputes(findings);
  const dangling = danglingDisputes(findings);
  const contestedIds = new Set(disputesByTarget.keys());
  const view = selectLedgerRows(findings, contestedIds, showAll ? Number.POSITIVE_INFINITY : MAX_LEDGER_ROWS);
  // Counted, not filtered: an assertion belongs in this table — it just may never be read as a measurement.
  const assertedCount = findings.filter((f) => f.assertion).length;

  return (
    <div className="panel">
      <div className="panel-title">Findings ({findings.length})</div>
      <div className="panel-sub">
        Each carries an explicit proof state — not just what was found, but how much it is proven.
        {assertedCount > 0 ? (
          <>
            {' '}
            {assertedCount} of these {assertedCount === 1 ? 'was' : 'were'} asserted by a person rather than measured;
            those rows name their author and count towards no analysis stage.
          </>
        ) : null}
        {disputesByTarget.size > 0 ? (
          <>
            {' '}
            {disputesByTarget.size} row{disputesByTarget.size === 1 ? ' is' : 's are'} contested by an operator and
            annotated in place — the annotation records the disagreement and changes nothing code decided.
          </>
        ) : null}
      </div>

      {dangling.length > 0 ? <DanglingDisputeNote dangling={dangling} /> : null}

      {view.rows.length === 0 ? (
        <div className="hint">No findings yet. Run extraction, SBOM and the deep scans to populate the ledger.</div>
      ) : (
        <>
          {view.rule ? (
            <div className="hint" style={{ marginTop: 10, maxWidth: '72ch' }}>
              {view.rule}{' '}
              <button type="button" className="btn btn-sm btn-ghost" onClick={() => setShowAll(true)}>
                Show all {findings.length}
              </button>
            </div>
          ) : null}
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Sev</th>
                  <th>Finding</th>
                  <th>Source</th>
                  <th>Proof state</th>
                </tr>
              </thead>
              <tbody>
                {view.rows.map((f) => {
                  const disputes = disputesByTarget.get(f.id) ?? [];
                  return (
                    <tr key={f.id}>
                      {/* A contested row is marked with an inset rule rather than a background: an inline background
                          would beat `.data tbody tr:hover` and silently cost the row its hover feedback. */}
                      <td style={disputes.length ? { boxShadow: 'inset 2px 0 0 var(--trust-agent)' } : undefined}>
                        <span style={{ color: SEV_COLOR[f.severity] ?? 'var(--text-dim)' }}>●</span>
                      </td>
                      <td style={{ fontSize: 12.5 }}>
                        {f.title}
                        {/* An assertion never appears here without its author on the same line. */}
                        {f.assertion ? (
                          <div className="hint">
                            asserted by {f.assertion.assertedBy}
                            {f.assertion.authorKind === 'agent' ? ' (agent)' : ''}
                            {f.assertion.status === 'withdrawn' ? ' — WITHDRAWN' : ''}
                          </div>
                        ) : null}
                        {disputes.length ? <DisputeNote target={f} disputes={disputes} /> : null}
                      </td>
                      <td className="mono hint" style={{ fontSize: 11 }}>
                        {f.source}
                      </td>
                      <td>
                        {/* Printed verbatim on a contested row: the dispute is recorded beside it, never over it. */}
                        <ProofStateBadge state={f.proofState} />
                      </td>
                    </tr>
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
