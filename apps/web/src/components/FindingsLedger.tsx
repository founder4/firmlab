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
import { type FindingCategory, compareFindings, findingCategory, isEstablished, severityCensus } from '@firmlab/core';
import { Fragment, useMemo, useState } from 'react';
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

/**
 * The severity mark, carrying both axes: hue is how bad if true, fill is whether it was established.
 *
 * The table used to print one glyph — `●`, coloured by severity — so a `critical` lead and a `critical` property
 * read out of the bytes were the same red dot. Fill now answers only the binary question the shape can carry:
 * whether the row establishes a property. The badge and census carry the finer semantic category.
 *
 * Fill rather than a second colour or a chip, for three reasons: it reuses the grammar `ProofStateBadge` already
 * set (a solid stroke is code's verdict, a dashed one is not a measurement), it leaves severity's own hue to say
 * exactly what it always said, and it survives being read by someone who cannot separate the hues. The label is
 * not decorative either — colour and fill are both visual, so the accessible name states both axes in words.
 */
function SeverityMark({
  severity,
  proofState,
  decorative = false,
}: {
  severity: string;
  proofState: FindingProvenance;
  /**
   * The legend's copies of the mark, where the count beside them already says the split in words. They are
   * hidden from assistive tech rather than labelled: announcing "critical — established" twice, once as a
   * legend and once as a row, is noise, and the census sentence is the accessible version of the same fact.
   */
  decorative?: boolean;
}): JSX.Element {
  const t = useMessages();
  const color = SEV_COLOR[severity] ?? 'var(--text-dim)';
  const established = isEstablished(proofState);
  const label = established ? t.findings.mark.established(severity) : t.findings.mark.unproven(severity);
  return (
    <span
      {...(decorative ? { 'aria-hidden': true } : { role: 'img', 'aria-label': label, title: label })}
      style={{
        display: 'inline-block',
        width: 9,
        height: 9,
        borderRadius: '50%',
        border: `1.5px solid ${color}`,
        background: established ? color : 'transparent',
        verticalAlign: 'middle',
      }}
    />
  );
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
  const sorted = [...findings].sort(compareFindings);
  if (sorted.length <= cap) return { rows: sorted, omitted: 0, rule: null };
  const contested = sorted.filter((f) => contestedIds.has(f.id));
  const rest = sorted.filter((f) => !contestedIds.has(f.id));
  const room = Math.max(0, cap - contested.length);
  const rows = [...contested, ...rest.slice(0, room)].sort(compareFindings);
  const omitted = sorted.length - rows.length;
  if (omitted === 0) return { rows, omitted: 0, rule: null };
  // The sentence travels with the selection rather than being assembled at the render site: a bound that states
  // what it dropped is part of the answer, and keeping the two together is what lets a test hold this to it.
  return { rows, omitted, rule: messages().findings.cutRule(rows.length, sorted.length, omitted) };
}

/** How many rows sharing a shape it takes before the table folds them. Below this, folding hides more than it saves. */
export const MIN_GROUP_SIZE = 3;

/** What a masked token is replaced by — an ellipsis, so a folded title still reads as a sentence. */
export const SHAPE_ELISION = '⋯';

/** Runs of elision, with whatever punctuation separates them, read as one gap. Only ever passed to
 *  `String.replace`, which resets `lastIndex`; a shared global regex is not safe with `.test()`. */
const ELISION_RUN = new RegExp(`(?:${SHAPE_ELISION}[\\s.,:;—-]*)+${SHAPE_ELISION}`, 'g');

/**
 * Pure: a finding title with its SUBJECT masked out, so two rows that say the same thing about different
 * subjects can be recognised as the same thing.
 *
 * Measured on DVRF (`57c12e70`): 129 rows, of which 45 read `Stack-overflow candidate: <path> imports <fn> with
 * no stack canary` and 15 read `Command-exec sink: <path> imports system`. Printed flat they are ~16 000 px of
 * near-identical text, and the four `static_confirmed` rows that state a shipped private key sit somewhere inside
 * it. The ledger was ordering correctly and still could not be triaged, because ordering does not help when 60
 * consecutive rows differ only in a path.
 *
 * **What is masked, and what is deliberately not.** Only tokens that IDENTIFY a subject: paths, dotted versions,
 * CVE ids, long hex digests and bare numbers. Ordinary words are left alone, which is the whole point — `imports
 * sprintf` and `imports sscanf` stay different shapes and therefore different groups, so folding never merges two
 * different unsafe functions into one line. The rule under-folds on purpose: a group that failed to form costs a
 * reader some scrolling, and a group that should not have formed hides a finding.
 */
export function titleShape(title: string): string {
  return title
    .replace(/\bCVE-\d{4}-\d+\b/gi, SHAPE_ELISION)
    .replace(/\S*\/\S*/g, SHAPE_ELISION)
    .replace(/\b\d+(?:\.\d+)+[\w.+-]*\b/g, SHAPE_ELISION)
    .replace(/\b[0-9a-f]{8,}\b/gi, SHAPE_ELISION)
    .replace(/\b\d+\b/g, SHAPE_ELISION)
    .replace(ELISION_RUN, SHAPE_ELISION)
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Pure: what a folded group's header actually says, derived from its members rather than from the mask.
 *
 * `titleShape` is built for KEYING, and keying is allowed to be blunt: it masks every token that could identify a
 * subject, including ones that turn out to be identical across the whole group. Printed as a label that reads
 * badly — the twelve busybox CVEs keyed to `⋯ — busybox ⋯`, which tells a reader neither the component version
 * nor that the varying part is a CVE id.
 *
 * So the label is computed the other way round: compare the members token by token and elide only the positions
 * where they actually DISAGREE. `⋯ — busybox 1.7.2` is then not a guess about which tokens are versions, it is a
 * fact about these twelve rows. Where the members genuinely differ the elision stays — the group of binaries
 * importing `sprintf/sscanf`, `strcpy/strcat` and so on keeps its `⋯`, which is the honest label for it.
 *
 * Titles that disagree on token count cannot be compared position by position, and fall back to the shape rather
 * than to an alignment invented to make them line up.
 */
export function groupLabel(members: readonly Finding[]): string {
  const first = members[0];
  if (!first) return '';
  if (members.length === 1) return first.title;
  const rows = members.map((m) => m.title.split(' '));
  const width = rows[0]?.length ?? 0;
  if (!rows.every((r) => r.length === width)) return titleShape(first.title);
  const out: string[] = [];
  for (let i = 0; i < width; i++) {
    const token = rows[0]?.[i] ?? '';
    out.push(rows.every((r) => r[i] === token) ? token : SHAPE_ELISION);
  }
  return out.join(' ').replace(ELISION_RUN, SHAPE_ELISION).trim();
}

/**
 * Pure: whether a row may be folded into a group at all.
 *
 * The exemptions are the same ones the display cap already makes, and for the same reason. A contested row carries
 * an operator's annotation, an asserted row is testimony rather than a measurement, and an intervention mark says
 * the subject was not the firmware as shipped — each is a claim about THAT row which a count cannot carry. Folding
 * one behind a collapsed header would make it inert exactly where a reader is least able to notice, which is what
 * the cap's contested-row exemption exists to prevent.
 */
export function isFoldable(f: Finding, contestedIds: ReadonlySet<string>): boolean {
  return !contestedIds.has(f.id) && !f.assertion && !f.interventions?.length;
}

/**
 * Pure: the fold key.
 *
 * Severity and proof state are IN the key, which is what makes folding compatible with the one display order
 * `compareFindings` defines. A group is therefore homogeneous on exactly the two axes that order the table, so it
 * occupies a single well-defined position rather than standing for a span of them — folding changes how many rows
 * are drawn, never which row outranks which. `source` is in the key because the ledger already namespaces per
 * target (`binary:<path>`, `dynprobe:<path>#<sink>`), and two providers that happen to word a title the same way
 * are not making the same statement.
 */
export function ledgerGroupKey(f: Finding): string {
  return [f.source, f.severity, f.proofState, titleShape(f.title)].join('\u0000');
}

export interface LedgerGroup {
  key: string;
  /** The highest-ranked member, and the row a folded group is drawn from. */
  lead: Finding;
  members: Finding[];
  /** True when this group is drawn folded — a singleton is a group of one and renders exactly as it always did. */
  folded: boolean;
}

export interface GroupedLedger {
  groups: LedgerGroup[];
  /** How many rows disappeared into a folded header — the number a reader needs to trust the shorter table. */
  foldedRows: number;
  /** The sentence stating what was folded and by what rule, or null when nothing was. */
  rule: string | null;
}

/**
 * Pure: fold the already-ordered rows into groups, preserving that order exactly.
 *
 * A group is emitted at the position of its FIRST member, and every member shares the group's severity and proof
 * state, so the sequence of groups is the sequence `compareFindings` produced with runs removed. Members are not
 * contiguous in the input — rows of one severity are ordered by title, so two shapes interleave alphabetically —
 * which is why this buckets rather than scanning for runs.
 *
 * Rows that may not fold become groups of one. They keep their exact position, so an exempt row never moves in
 * order to stay visible; it was already where it belonged.
 */
export function groupLedgerRows(
  rows: readonly Finding[],
  contestedIds: ReadonlySet<string>,
  minSize = MIN_GROUP_SIZE,
): GroupedLedger {
  const buckets = new Map<string, Finding[]>();
  const order: string[] = [];
  for (const f of rows) {
    // An exempt row gets a key nothing else can share, so it stays a singleton without a branch at render time.
    const key = isFoldable(f, contestedIds) ? ledgerGroupKey(f) : `\u0000exempt\u0000${f.id}`;
    const bucket = buckets.get(key);
    if (bucket) bucket.push(f);
    else {
      buckets.set(key, [f]);
      order.push(key);
    }
  }
  let foldedRows = 0;
  let foldedGroups = 0;
  const groups: LedgerGroup[] = [];
  for (const key of order) {
    const members = buckets.get(key) ?? [];
    const lead = members[0];
    if (!lead) continue;
    const folded = members.length >= minSize;
    if (folded) {
      foldedGroups += 1;
      foldedRows += members.length;
    }
    groups.push({ key, lead, members, folded });
  }
  if (foldedGroups === 0) return { groups, foldedRows: 0, rule: null };
  // The sentence travels with the fold for the same reason the cap's does: a table that draws fewer rows than the
  // count above it has to say why, or the census and the table read as though they disagree.
  return { groups, foldedRows, rule: messages().findings.foldRule(rows.length, groups.length, foldedRows) };
}

/**
 * The severity census, and the sentence that makes the marks in the table readable.
 *
 * It sits above the table rather than under it because it qualifies the number in the panel title, and a
 * qualifier printed after 300 rows is a qualifier nobody reads. Each band shows its own mark at the size the
 * rows use, filled and hollow side by side, so the legend is demonstrated rather than described — and the
 * counts beside it name the finer categories the hollow mark deliberately does not collapse.
 *
 * It counts the whole ledger even when the table is capped, and it is rendered from `severityCensus` rather
 * than tallied here so the ledger, the narrative and the report cannot disagree about what "established" means.
 */
function SeverityCensus({ census }: { census: ReturnType<typeof severityCensus> }): JSX.Element {
  const t = useMessages();
  return (
    <div className="severity-census">
      <div className="severity-census-grid">
        {census.map((c) => (
          <div key={c.severity} className={`severity-summary severity-${c.severity}`}>
            <div className="severity-summary-head">
              <span className="severity-name">{c.severity}</span>
              <strong className="num">{c.total}</strong>
            </div>
            <div className="severity-summary-split">
              {c.established > 0 ? (
                <SeverityMark severity={c.severity} proofState="static_confirmed" decorative />
              ) : null}
              {c.total - c.established > 0 ? (
                <SeverityMark severity={c.severity} proofState="needs_runtime_reproduction" decorative />
              ) : null}
              <span>
                {t.findings.census.split(c.established, c.leads, c.blocked, c.dismissed, c.asserted, c.other)}
              </span>
            </div>
            <span className="sr-only">
              {t.findings.census.band(
                c.severity,
                c.total,
                c.established,
                c.leads,
                c.blocked,
                c.dismissed,
                c.asserted,
                c.other,
              )}
            </span>
          </div>
        ))}
      </div>
      <div className="hint" style={{ marginTop: 6, maxWidth: '72ch' }}>
        {t.findings.census.legend}
      </div>
    </div>
  );
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
 * One measured row, unchanged by folding.
 *
 * Lifted out of the table body so a folded group's members render through exactly the same component as a row that
 * never folded — the dispute annotation, the retraction note, the intervention mark and the reasoning toggle are
 * the parts of this table that carry its refusals, and a second copy of the row for "inside a group" is how one of
 * them would quietly go missing. `nested` indents and nothing else.
 */
function LedgerRow({
  f,
  disputes,
  open,
  onToggleReason,
  nested = false,
}: {
  f: Finding;
  disputes: readonly Finding[];
  open: boolean;
  onToggleReason: (id: string) => void;
  nested?: boolean;
}): JSX.Element {
  const t = useMessages();
  return (
    <Fragment>
      <tr className={nested ? 'ledger-nested' : undefined}>
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
              onClick={() => onToggleReason(f.id)}
            >
              {open ? '▾' : '▸'}
            </button>
          ) : null}
        </td>
        <td>
          <span className={`severity-pill severity-${f.severity}`}>
            <SeverityMark severity={f.severity} proofState={f.proofState} />
            {f.severity}
          </span>
        </td>
        <td style={{ fontSize: 12.5 }}>
          <div className="finding-title">{f.title}</div>
          <div className="finding-meta mono">
            <span>{f.source}</span>
            {f.evidenceChannel ? <span>{f.evidenceChannel}</span> : null}
          </div>
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
        <td>
          {/* Printed verbatim on a contested row: the dispute is recorded beside it, never over it. */}
          <ProofStateBadge state={f.proofState} />
          {/* The second axis, UNDER the rung rather than beside it: how far it was proven is the
                            headline, how it was known qualifies it. A row with no channel recorded prints
                            nothing at all — an "unknown" chip would imply the question was asked and answered. */}
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
        <tr className={nested ? 'ledger-nested' : undefined}>
          {/* Full width, under the row it explains. The provider WROTE this sentence while measuring,
                            so it renders as written, in whatever language produced it. */}
          <td colSpan={4} className="reason-cell">
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
}

/**
 * The row that stands for a run of rows saying the same thing about different subjects.
 *
 * It carries the group's severity mark and proof badge exactly as a single row would, because every member shares
 * both — that is what `ledgerGroupKey` guarantees, and it is why one header can speak for all of them without
 * averaging anything. What it must never do is imply that a count is a severity: forty leads are forty leads, and
 * the badge beside the count still says `needs_runtime_reproduction`.
 *
 * The title is the masked shape, with the elision standing where the subject was. The subjects are not summarised
 * or sampled into the header — a "e.g. sbin/foo and 44 others" line would put one arbitrary path in front of a
 * reader as though it were representative. Expanding is the only way to see them, and it shows all of them.
 */
function GroupHeaderRow({
  group,
  open,
  onToggle,
}: {
  group: LedgerGroup;
  open: boolean;
  onToggle: (key: string) => void;
}): JSX.Element {
  const t = useMessages();
  const f = group.lead;
  const label = t.findings.group.toggle(group.members.length, open);
  return (
    <tr className={`ledger-group-head${open ? ' is-open' : ''}`}>
      <td>
        <button
          type="button"
          className="btn btn-sm btn-ghost reason-toggle"
          aria-expanded={open}
          aria-label={label}
          title={label}
          onClick={() => onToggle(group.key)}
        >
          {open ? '▾' : '▸'}
        </button>
      </td>
      <td>
        <span className={`severity-pill severity-${f.severity}`}>
          <SeverityMark severity={f.severity} proofState={f.proofState} />
          {f.severity}
        </span>
      </td>
      <td style={{ fontSize: 12.5 }}>
        <div className="finding-title">
          <span className="ledger-group-count mono">{group.members.length}</span>
          {groupLabel(group.members)}
        </div>
        <div className="finding-meta mono">
          <span>{f.source}</span>
          <span>{t.findings.group.subjects(group.members.length)}</span>
        </div>
      </td>
      <td>
        <ProofStateBadge state={f.proofState} />
      </td>
    </tr>
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
  const [filter, setFilter] = useState<'all' | 'priority' | FindingCategory>('all');
  const [query, setQuery] = useState('');
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
  /**
   * Which folded groups are expanded. Folded by default and never remembered across a filter change: the fold is
   * how the table stays readable, and a session that slowly re-expands every group ends up back at the flat list
   * this exists to replace.
   */
  const [openGroups, setOpenGroups] = useState<ReadonlySet<string>>(new Set());
  const toggleGroup = (key: string): void =>
    setOpenGroups((prev) => {
      const next = new Set(prev);
      if (!next.delete(key)) next.add(key);
      return next;
    });
  const disputesByTarget = indexDisputes(findings);
  const dangling = danglingDisputes(findings);
  const contestedIds = new Set(disputesByTarget.keys());
  // The whole ledger, not the capped view: a census of the rows that happened to fit would be a different claim.
  const census = severityCensus(findings);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f) => {
      const inScope =
        filter === 'all' ||
        (filter === 'priority' && (f.severity === 'critical' || f.severity === 'high')) ||
        findingCategory(f.proofState) === filter;
      if (!inScope) return false;
      if (!q) return true;
      return [f.title, f.source, f.severity, f.proofState, f.evidenceChannel, f.rationale]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(q));
    });
  }, [findings, filter, query]);
  const view = selectLedgerRows(filtered, contestedIds, showAll ? Number.POSITIVE_INFINITY : MAX_LEDGER_ROWS);
  // Folded AFTER the cap, never instead of it. The cap's rule is about which rows the table is willing to print;
  // the fold is about how many lines those rows need. Folding first would let a group of forty count as one row
  // against the cap and quietly change what the cut sentence above the table is describing.
  const grouped = groupLedgerRows(view.rows, contestedIds);
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

      {census.length > 0 ? <SeverityCensus census={census} /> : null}

      {findings.length > 0 ? (
        <div className="ledger-toolbar">
          <fieldset className="ledger-filters" aria-label={t.findings.filters.aria}>
            {(['all', 'priority', 'established', 'lead', 'blocked', 'dismissed', 'asserted', 'other'] as const).map(
              (value) => (
                <button
                  key={value}
                  type="button"
                  className={`btn btn-sm ${filter === value ? 'is-active' : 'btn-ghost'}`}
                  aria-pressed={filter === value}
                  onClick={() => {
                    setFilter(value);
                    setShowAll(false);
                  }}
                >
                  {t.findings.filters[value]}
                </button>
              ),
            )}
          </fieldset>
          <label className="ledger-search">
            <span className="sr-only">{t.findings.filters.searchLabel}</span>
            <input
              className="input"
              type="search"
              value={query}
              placeholder={t.findings.filters.searchPlaceholder}
              onChange={(event) => {
                setQuery(event.target.value);
                setShowAll(false);
              }}
            />
          </label>
          <span className="hint mono ledger-results">
            {t.findings.filters.results(filtered.length, findings.length)}
          </span>
        </div>
      ) : null}

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
          {/* The fold states what it did, for the same reason the cut does: the table now draws fewer lines than
              the count in the panel title, and a reader who cannot see why has to assume rows were dropped. */}
          {grouped.rule ? (
            <div className="hint" style={{ marginTop: 10, maxWidth: '72ch' }}>
              {grouped.rule}{' '}
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={() =>
                  setOpenGroups((prev) =>
                    prev.size > 0 ? new Set() : new Set(grouped.groups.filter((g) => g.folded).map((g) => g.key)),
                  )
                }
              >
                {openGroups.size > 0 ? t.findings.group.collapseAll : t.findings.group.expandAll}
              </button>
            </div>
          ) : null}
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data findings-table">
              <thead>
                <tr>
                  <th style={{ width: 28 }} />
                  <th>{t.findings.col.severity}</th>
                  <th>{t.findings.col.finding}</th>
                  <th>{t.findings.col.proofState}</th>
                </tr>
              </thead>
              <tbody>
                {grouped.groups.map((g) => {
                  if (!g.folded) {
                    const f = g.lead;
                    return (
                      <LedgerRow
                        key={f.id}
                        f={f}
                        disputes={disputesByTarget.get(f.id) ?? []}
                        open={openReasons.has(f.id)}
                        onToggleReason={toggleReason}
                      />
                    );
                  }
                  const open = openGroups.has(g.key);
                  return (
                    <Fragment key={g.key}>
                      <GroupHeaderRow group={g} open={open} onToggle={toggleGroup} />
                      {open
                        ? g.members.map((f) => (
                            <LedgerRow
                              key={f.id}
                              f={f}
                              disputes={disputesByTarget.get(f.id) ?? []}
                              open={openReasons.has(f.id)}
                              onToggleReason={toggleReason}
                              nested
                            />
                          ))
                        : null}
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
