/**
 * The operator ledger — the one place in the workbench where a person writes a row instead of a provider.
 *
 * Everything about this panel is arranged so the reader cannot lose track of which kind of evidence they are
 * looking at. The form has no proof-state control at all: not a disabled one, not a warned one — the ladder is
 * simply absent from the vocabulary, and the author picks a *claim* instead. The assertions table never borrows
 * the proof-state badge; it uses a distinct badge, in the agent/heuristic trust colour the theme already reserves
 * for non-deterministic provenance, and every row states its author on its face.
 *
 * Withdrawn claims stay visible in their own table rather than disappearing, because the retraction and its reason
 * are usually the most informative rows in the file. Nothing here can delete an assertion.
 *
 * An amendment is append-only, so this panel shows the claims a row has superseded rather than only the one that
 * stands now. That distinction is the whole argument of the ledger: an author who could restate "I saw a root shell
 * on the shipped unit" as something milder, with no trace, would be performing the same erasure a delete performs.
 * History is therefore rendered as history — behind its own affordance, headed as superseded, greyed and struck
 * through the badge — and never as a second live claim a reader might weigh alongside the current one.
 *
 * Notes sit below, deliberately plainer and deliberately deleteable: they are reasoning, not claims, and the
 * asymmetry — a note can be thrown away, an assertion can only be retracted — is the visible form of the
 * difference between the two. For the same reason a note is edited in place with no history kept.
 *
 * Retiring a computed source is the ledger's one deletion path, and it sits in its own panel, closed by default and
 * previewing by default, because it is the action on this page most likely to be misread. It refuses an `operator:`
 * source before the request leaves — an assertion is withdrawn, never removed, and the refusal names that surface —
 * and a real retirement shows the note the API left in place of the rows, since that note is the only thing that
 * stops the gap reading as "the question was asked and came back clean".
 *
 * What translation may not touch: the claim CODES and the severity codes are the values that leave this form and
 * land in SQLite, so the `<option>` carries the code and only its explanation is localised; the attribution
 * sentence and the not-a-measurement caveat come from the API precisely so the UI, the report and the MCP payload
 * cannot word the same row three ways; and the asserted badge reuses the shared `proofState` gloss for the same
 * reason. The `operator` namespace carries the rest, including the two sentences that must never read as live
 * claims — the superseded history heading and its note.
 */
import { useCallback, useEffect, useState } from 'react';
import { type AmendableFields, amendmentIsSendable, describeChangedFields, diffAmendment } from '../amend';
import {
  type AssertedFinding,
  type AssertionRevision,
  type Finding,
  type ImageNote,
  type OperatorAssertion,
  type OperatorClaim,
  type OperatorLedger,
  type RetireFindingsResult,
  api,
} from '../api';
import { messages, useMessages } from '../i18n';
import { Dialog } from './Dialog';

/** The claim codes, in the order the form offers them. The label is a lookup, so the vocabulary lives in one place. */
const CLAIMS: OperatorClaim[] = [
  'asserted_unverified',
  'asserted_from_device',
  'asserted_from_external_evidence',
  'disputes_finding',
];

const SEVERITIES: Finding['severity'][] = ['info', 'low', 'medium', 'high', 'critical'];

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--text-dim)',
  info: 'var(--text-dim)',
};

/**
 * Mirror the API's `MAX_NOTE` / `MAX_NOTE_AUTHOR`, on creation and on edit alike. One bound for both, because a
 * note the create form accepted — or a retirement note the API wrote, which it holds to the same bound — must stay
 * one the edit form can save. A tighter edit cap made exactly those notes uneditable.
 */
export const MAX_NOTE = 20000;
/** The edit bound, kept as a name for callers that ask for it; it is `MAX_NOTE`, never a tighter value. */
export const MAX_NOTE_EDIT = MAX_NOTE;
export const MAX_NOTE_AUTHOR = 80;
/** Mirrors the route's `MAX_RETIRE_*` bounds, so the refusal arrives before the request does. */
export const MAX_RETIRE_REASON = 2000;
export const MAX_RETIRE_AUTHOR = 80;
export const MAX_RETIRE_SOURCE = 1024;
/** The namespace of hand-authored rows. Mirrors `OPERATOR_SOURCE_PREFIX` in the API, which refuses it too. */
const OPERATOR_SOURCE_PREFIX = 'operator:';

export type NoteBodyProblem = { kind: 'empty' } | { kind: 'tooLong'; length: number };

/** Pure: why a note body — new or edited — cannot be sent, or null when it can. Measured trimmed, as it is sent. */
export function noteBodyProblem(body: string): NoteBodyProblem | null {
  const text = body.trim();
  if (!text) return { kind: 'empty' };
  if (text.length > MAX_NOTE) return { kind: 'tooLong', length: text.length };
  return null;
}

/** Pure: whether a note's author is longer than the API stores. Measured trimmed, as it is sent. */
export function noteAuthorTooLong(author: string): boolean {
  return author.trim().length > MAX_NOTE_AUTHOR;
}

export type RetireField = 'source' | 'retiredBy' | 'reason';
export type RetireProblem =
  | { kind: 'operatorSource'; source: string }
  | { kind: 'missing'; fields: RetireField[] }
  | { kind: 'reasonTooLong'; length: number }
  | { kind: 'whoTooLong' }
  | { kind: 'sourceTooLong'; length: number };

/**
 * Pure: why a retirement cannot be sent, or null when it can.
 *
 * An `operator:` source is refused first, ahead of any missing field: someone aiming at an assertion needs to learn
 * they are on the wrong surface, not be asked for a reason they would then write for nothing.
 */
export function retireProblem(form: { source: string; retiredBy: string; reason: string }): RetireProblem | null {
  const source = form.source.trim();
  const retiredBy = form.retiredBy.trim();
  const reason = form.reason.trim();
  if (source.startsWith(OPERATOR_SOURCE_PREFIX)) return { kind: 'operatorSource', source };
  const missing: RetireField[] = [
    ...(source ? [] : ['source' as const]),
    ...(retiredBy ? [] : ['retiredBy' as const]),
    ...(reason ? [] : ['reason' as const]),
  ];
  if (missing.length > 0) return { kind: 'missing', fields: missing };
  if (source.length > MAX_RETIRE_SOURCE) return { kind: 'sourceTooLong', length: source.length };
  if (retiredBy.length > MAX_RETIRE_AUTHOR) return { kind: 'whoTooLong' };
  if (reason.length > MAX_RETIRE_REASON) return { kind: 'reasonTooLong', length: reason.length };
  return null;
}

/**
 * Never the proof-state badge. A separate component in a separate colour, reading "asserted", so the two kinds of
 * row cannot be told apart only by squinting at a label — a reader scanning the table sees a different shape.
 */
function AssertedBadge({ f }: { f: AssertedFinding }): JSX.Element {
  const t = useMessages();
  const withdrawn = f.assertion?.status === 'withdrawn';
  const color = withdrawn ? 'var(--text-faint)' : 'var(--trust-agent)';
  return (
    <span
      className="mono"
      style={{ color, border: `1px dashed ${color}`, borderRadius: 4, padding: '1px 6px', fontSize: 10.5 }}
    >
      {/* The live label is the SHARED proof-state gloss for `operator_assertion`, not a second wording of it. */}
      {withdrawn ? t.operator.withdrawnBadge : t.proofState.label.operator_assertion}
    </span>
  );
}

/**
 * Pure: the revisions an assertion has been through, oldest first, read defensively.
 *
 * `supersedes` arrives from a JSON column written by an older build, so its shape is asserted, not known — a row
 * recorded before amendment history existed carries no array at all, and one written by a build with a different
 * shape must degrade to "nothing readable" rather than throw in the middle of the ledger. Anything that is not an
 * object is dropped; nothing else is, because a revision missing one field is still the claim someone made.
 */
export function revisionsOf(a: OperatorAssertion | undefined): AssertionRevision[] {
  const raw = a?.supersedes;
  if (!Array.isArray(raw)) return [];
  return raw.filter((r): r is AssertionRevision => !!r && typeof r === 'object');
}

/**
 * Pure: an ISO day, or an honest blank — a revision written by an older build may carry no timestamp at all.
 *
 * The day is an ISO string in every language (a claim is dated the way it was recorded); only the stand-in for a
 * date nobody wrote is prose, and that comes from the catalogue via `messages()` — this is a helper, not a
 * component, and it is called from a render pass that already subscribes to the locale.
 */
function day(ms: number | undefined): string {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return messages().operator.unrecordedDate;
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * What this claim replaced. Collapsed by default and opened deliberately: the current claim is what stands, and a
 * superseded one shown at equal weight beside it is a second live claim to anyone skimming.
 *
 * The two "no history" cases are different and are worded differently. A row that was never amended gets no
 * affordance at all — there is nothing behind it. A row that WAS amended by a build that overwrote its predecessor
 * says exactly that, because "amended, and the earlier claim is gone" is information, and rendering it as though
 * nothing had ever been replaced would be the erasure this ledger exists to refuse.
 */
function AssertionHistory({ a }: { a: OperatorAssertion | undefined }): JSX.Element | null {
  const t = useMessages();
  const [open, setOpen] = useState(false);
  const revisions = revisionsOf(a);
  if (!a || (a.amendedAt === undefined && revisions.length === 0)) return null;

  if (revisions.length === 0) {
    return (
      <div className="hint" style={{ marginTop: 4 }}>
        {t.operator.history.noneReadable(day(a.amendedAt))}
      </div>
    );
  }

  return (
    <div style={{ marginTop: 4 }}>
      <button
        type="button"
        className="btn btn-sm btn-ghost"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        style={{ padding: '0 4px' }}
      >
        {open ? t.operator.history.hide : t.operator.history.show(day(a.amendedAt), revisions.length)}
      </button>
      {open ? (
        <div
          style={{
            marginTop: 6,
            borderLeft: '2px solid var(--border-strong)',
            background: 'var(--bg-inset)',
            borderRadius: 'var(--r-sm)',
            padding: '6px 10px',
            maxWidth: '72ch',
          }}
        >
          <div className="eyebrow">{t.operator.history.heading}</div>
          <div className="hint">{t.operator.history.note}</div>
          <ol style={{ margin: '6px 0 0', paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 6 }}>
            {revisions.map((r, i) => (
              <li key={`${r.supersededAt ?? 'unknown'}-${i}`} style={{ fontSize: 12.5 }}>
                <span
                  className="mono"
                  style={{
                    color: 'var(--text-faint)',
                    border: '1px dashed var(--text-faint)',
                    borderRadius: 4,
                    padding: '1px 6px',
                    fontSize: 10.5,
                  }}
                >
                  {t.operator.history.superseded} · {r.claim ?? t.operator.history.claimNotRecorded}
                </span>{' '}
                <span style={{ color: 'var(--text-dim)' }}>
                  {t.operator.history.stood(day(r.from), day(r.supersededAt))}
                  {/* Only when an amendment is on record as having introduced this claim. Absent means the
                      original author stated it, and naming the current one there would be the attribution this
                      whole record exists to prevent. */}
                  {r.amendedBy
                    ? t.operator.history.statedBy(
                        r.amendedByKind === 'agent' ? `${r.amendedBy}${t.findings.agentSuffix}` : r.amendedBy,
                      )
                    : ''}
                </span>
                {r.title ? <div style={{ marginTop: 2 }}>“{r.title}”</div> : null}
                {r.disputesFindingId ? (
                  <div className="hint">
                    {t.operator.history.contested} <span className="mono">{r.disputesFindingId}</span>
                  </div>
                ) : null}
                <div className="hint">{r.rationale ?? t.operator.history.noBasis}</div>
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </div>
  );
}

/**
 * The form that produces an amendment — the writer for a history this panel could already display.
 *
 * It opens pre-filled with what is stored, so the operator edits the claim rather than retyping it, and it will not
 * send when nothing changed: `diffAmendment` decides that, and the two ways of changing nothing get their own
 * sentence. The claim and severity are `select`s over the values the API accepts, because an assertion's claim
 * decides what a reader may conclude from it and a free-text field there would let a typo become a provenance.
 */
function AmendForm({
  f,
  onCancel,
  onDone,
  onError,
  imageId,
  defaultWho,
}: {
  f: AssertedFinding;
  onCancel: () => void;
  onDone: () => void;
  onError: (m: string) => void;
  imageId: string;
  /** Who the panel is being driven as, prefilled — never `f.assertion.assertedBy`, which is a different person. */
  defaultWho: string;
}): JSX.Element {
  const t = useMessages();
  const [amendedBy, setAmendedBy] = useState(defaultWho);
  const current: AmendableFields = {
    title: f.title,
    claim: f.assertion?.claim ?? 'asserted_unverified',
    rationale: f.rationale ?? '',
    severity: f.severity,
  };
  const [next, setNext] = useState<AmendableFields>(current);
  const [touched, setTouched] = useState<Set<keyof AmendableFields>>(new Set());
  const [busy, setBusy] = useState(false);

  const set = (k: keyof AmendableFields, v: string): void => {
    setNext((n) => ({ ...n, [k]: v }));
    setTouched((s) => new Set(s).add(k));
  };

  const diff = diffAmendment(current, next, touched);
  // The API refuses an unnamed amendment, so the button does too — and for the same reason, not as UI politeness:
  // an edit to a named person's claim has to say who made it.
  const sendable = amendmentIsSendable(diff) && amendedBy.trim().length > 0;

  const save = async (): Promise<void> => {
    if (!sendable) return;
    setBusy(true);
    try {
      await api.amendAssertion(imageId, f.id, {
        title: next.title.trim(),
        claim: next.claim as OperatorClaim,
        rationale: next.rationale.trim(),
        severity: next.severity as Finding['severity'],
        amendedBy: amendedBy.trim(),
      });
      onDone();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div data-testid={`amend-${f.id}`} style={{ display: 'grid', gap: 8, marginTop: 10 }}>
      <strong style={{ fontSize: 12.5 }}>{t.operator.amend.heading}</strong>
      <span className="hint" style={{ maxWidth: '72ch' }}>
        {t.operator.amend.intro}
      </span>
      <label style={{ display: 'grid', gap: 4 }}>
        <span className="hint">{t.operator.amend.who}</span>
        <input value={amendedBy} onChange={(e) => setAmendedBy(e.target.value)} aria-label="amend-by" />
      </label>
      <label style={{ display: 'grid', gap: 4 }}>
        <span className="hint">{t.operator.amend.fields.title}</span>
        <input value={next.title} onChange={(e) => set('title', e.target.value)} aria-label="amend-title" />
      </label>
      <label style={{ display: 'grid', gap: 4 }}>
        <span className="hint">{t.operator.amend.fields.claim}</span>
        <select value={next.claim} onChange={(e) => set('claim', e.target.value)} aria-label="amend-claim">
          {CLAIMS.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </label>
      <label style={{ display: 'grid', gap: 4 }}>
        <span className="hint">{t.operator.amend.fields.rationale}</span>
        <textarea
          value={next.rationale}
          rows={3}
          onChange={(e) => set('rationale', e.target.value)}
          aria-label="amend-rationale"
        />
      </label>
      <label style={{ display: 'grid', gap: 4 }}>
        <span className="hint">{t.operator.amend.fields.severity}</span>
        <select value={next.severity} onChange={(e) => set('severity', e.target.value)} aria-label="amend-severity">
          {SEVERITIES.map((sv) => (
            <option key={sv} value={sv}>
              {sv}
            </option>
          ))}
        </select>
      </label>
      {/* The review line: an amendment the operator cannot see before sending is a change to a named person's claim
          made blind. And when there is nothing to send, WHICH nothing it is gets its own sentence. */}
      {sendable ? (
        <span className="mono" data-role="changing" style={{ fontSize: 11.5 }}>
          {t.operator.amend.changing(describeChangedFields(diff))}
        </span>
      ) : amendmentIsSendable(diff) ? (
        <span className="hint" data-role="refusal-unsigned" style={{ maxWidth: '72ch' }}>
          {t.operator.amend.unsigned}
        </span>
      ) : (
        <span className="hint" data-role={`refusal-${diff.refusal}`} style={{ maxWidth: '72ch' }}>
          {diff.refusal === 'retyped' ? t.operator.amend.retyped : t.operator.amend.untouched}
        </span>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        {/* Gated on the diff AND on an author. The author is the amender, not the asserter: `assertedBy` is still
            carried over by the route so an edit cannot reassign the original claim, and `amendedBy` is recorded
            beside it so the edit is attributed to whoever actually made it. */}
        <button type="button" className="btn btn-sm" disabled={!sendable || busy} onClick={() => void save()}>
          {t.operator.amend.save}
        </button>
        <button type="button" className="btn btn-sm btn-ghost" onClick={onCancel}>
          {t.operator.amend.cancel}
        </button>
      </div>
    </div>
  );
}

function AssertionTable({
  rows,
  onWithdraw,
  amend,
}: {
  rows: AssertedFinding[];
  onWithdraw?: (f: AssertedFinding) => void;
  /** Present only where amending is offered — the withdrawn ledger is history and must not be editable. */
  amend?: {
    openFor: string | null;
    imageId: string;
    setOpenFor: (id: string | null) => void;
    onDone: () => void;
    onError: (m: string) => void;
    /** Who the panel is being driven as, used to prefill the amendment's author. */
    who: string;
  };
}): JSX.Element {
  const t = useMessages();
  return (
    <div className="table-wrap" style={{ marginTop: 10 }}>
      <table className="data">
        <thead>
          <tr>
            <th>{t.operator.col.severity}</th>
            <th>{t.operator.col.claim}</th>
            <th>{t.operator.col.provenance}</th>
            {onWithdraw ? <th /> : null}
          </tr>
        </thead>
        <tbody>
          {rows.map((f) => (
            <tr key={f.id}>
              <td style={{ width: '1%' }}>
                <span style={{ color: SEV_COLOR[f.severity] ?? 'var(--text-dim)' }}>●</span>
              </td>
              <td style={{ fontSize: 12.5 }}>
                <div>{f.title}</div>
                {/* The attribution sentence comes from the API, so the UI and a report can never word it apart. */}
                <div className="hint">{f.attribution}</div>
                {/* …and what it replaced, if anything, kept visibly apart from the claim that stands. */}
                <AssertionHistory a={f.assertion} />
                {amend?.openFor === f.id && (
                  <AmendForm
                    f={f}
                    imageId={amend.imageId}
                    defaultWho={amend.who}
                    onCancel={() => amend.setOpenFor(null)}
                    onDone={() => {
                      amend.setOpenFor(null);
                      amend.onDone();
                    }}
                    onError={amend.onError}
                  />
                )}
              </td>
              <td style={{ width: '1%', whiteSpace: 'nowrap' }}>
                <AssertedBadge f={f} />
              </td>
              {onWithdraw ? (
                <td style={{ width: '1%', whiteSpace: 'nowrap' }}>
                  {amend && (
                    <button
                      type="button"
                      className="btn btn-sm btn-ghost"
                      onClick={() => amend.setOpenFor(amend.openFor === f.id ? null : f.id)}
                    >
                      {t.operator.amend.open}
                    </button>
                  )}
                  <button type="button" className="btn btn-sm btn-ghost" onClick={() => onWithdraw(f)}>
                    {t.operator.withdraw}
                  </button>
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Retire one computed source. Closed by default and previewing by default: the first click a curious reader makes
 * lists what would go, and removing anything takes unticking the preview and pressing a button that says so.
 *
 * The summary sentence and the note body come from the API, like the attribution sentence above — the route words
 * a retirement once, and the UI shows that wording rather than restating it.
 */
function RetireSourcePanel({
  imageId,
  defaultWho,
  onRetired,
}: {
  imageId: string;
  /** Who the panel is being driven as, used to prefill the author when the form opens. */
  defaultWho: string;
  onRetired: () => void;
}): JSX.Element {
  const t = useMessages();
  const [open, setOpen] = useState(false);
  const [source, setSource] = useState('');
  const [retiredBy, setRetiredBy] = useState('');
  const [reason, setReason] = useState('');
  const [dryRun, setDryRun] = useState(true);
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<RetireFindingsResult | null>(null);

  const problem = retireProblem({ source, retiredBy, reason });
  const label: Record<RetireField, string> = {
    source: t.operator.retire.sourceLabel,
    retiredBy: t.operator.retire.whoLabel,
    reason: t.operator.retire.reasonLabel,
  };
  const invalid = (f: RetireField): true | undefined =>
    tried && problem?.kind === 'missing' && problem.fields.includes(f) ? true : undefined;

  /** Any edit invalidates a result shown for the form as it was — a stale preview must not read as this one's. */
  const edit =
    <T,>(set: (v: T) => void) =>
    (v: T): void => {
      set(v);
      setResult(null);
      setErr(null);
    };

  const submit = async (): Promise<void> => {
    setTried(true);
    if (problem || busy) return;
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const r = await api.retireFindings(imageId, {
        source: source.trim(),
        retiredBy: retiredBy.trim(),
        reason: reason.trim(),
        dryRun,
      });
      setResult(r);
      if (!r.dryRun) {
        // Back to previewing, so the next retirement starts from the safe side again.
        setReason('');
        setDryRun(true);
        setTried(false);
        onRetired();
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const problemText = (p: RetireProblem): string => {
    switch (p.kind) {
      case 'operatorSource':
        return t.operator.retire.operatorRefused(p.source);
      case 'missing':
        return t.operator.retire.missing(p.fields.map((f) => label[f]));
      case 'whoTooLong':
        return t.operator.retire.whoTooLong(MAX_RETIRE_AUTHOR);
      case 'reasonTooLong':
        return t.operator.retire.reasonTooLong(MAX_RETIRE_REASON, p.length);
      case 'sourceTooLong':
        return t.operator.retire.sourceTooLong(MAX_RETIRE_SOURCE, p.length);
    }
  };
  // An operator source is refused as soon as it is typed; everything else waits for a submit attempt.
  const shownProblem = problem && (tried || problem.kind === 'operatorSource') ? problem : null;

  return (
    <div className="panel" data-testid="retire-source">
      <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', justifyContent: 'space-between' }}>
        <div className="panel-title">{t.operator.retire.title}</div>
        <button
          type="button"
          className="btn btn-sm btn-ghost"
          aria-expanded={open}
          onClick={() => {
            if (!open && !retiredBy) setRetiredBy(defaultWho);
            setOpen((v) => !v);
          }}
        >
          {open ? t.operator.retire.close : t.operator.retire.open}
        </button>
      </div>
      <div className="panel-sub" style={{ maxWidth: '72ch' }}>
        {t.operator.retire.sub}
      </div>

      {open ? (
        <div style={{ display: 'grid', gap: 8, marginTop: 12 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <input
              className="input mono"
              placeholder={t.operator.retire.sourcePlaceholder}
              aria-label={t.operator.retire.sourceLabel}
              aria-invalid={invalid('source') ?? (problem?.kind === 'operatorSource' ? true : undefined)}
              value={source}
              onChange={(e) => edit(setSource)(e.target.value)}
              style={{ flex: '2 1 280px', minWidth: 0 }}
            />
            <input
              className="input"
              placeholder={t.operator.retire.whoPlaceholder}
              aria-label={t.operator.retire.whoLabel}
              aria-invalid={invalid('retiredBy')}
              value={retiredBy}
              onChange={(e) => edit(setRetiredBy)(e.target.value)}
              style={{ flex: '1 1 160px', minWidth: 0 }}
            />
          </div>
          <textarea
            className="input"
            placeholder={t.operator.retire.reasonPlaceholder}
            aria-label={t.operator.retire.reasonLabel}
            aria-invalid={invalid('reason')}
            value={reason}
            onChange={(e) => edit(setReason)(e.target.value)}
            style={{ height: 72, padding: '8px 10px', resize: 'vertical' }}
          />
          <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={dryRun} onChange={(e) => edit(setDryRun)(e.target.checked)} />
            <span className="hint">{t.operator.retire.dryRunLabel}</span>
          </label>
          <div>
            <button
              type="button"
              className={dryRun ? 'btn btn-sm' : 'btn btn-sm btn-danger'}
              disabled={busy}
              onClick={() => void submit()}
            >
              {busy ? t.operator.retire.working : dryRun ? t.operator.retire.preview : t.operator.retire.submit}
            </button>
          </div>
          {shownProblem ? (
            <div className="field-error" role="alert" style={{ maxWidth: '72ch' }}>
              {problemText(shownProblem)}
            </div>
          ) : null}
          {err ? <div className="banner banner-warn">{err}</div> : null}
          {result ? (
            <div
              data-role={result.dryRun ? 'retire-preview' : 'retire-done'}
              style={{
                borderLeft: '2px solid var(--border-strong)',
                background: 'var(--bg-inset)',
                borderRadius: 'var(--r-sm)',
                padding: '6px 10px',
                maxWidth: '72ch',
              }}
            >
              <div className="eyebrow">
                {result.dryRun ? t.operator.retire.previewHeading : t.operator.retire.doneHeading} ·{' '}
                {t.operator.retire.removedCount(result.removedCount)}
              </div>
              <div style={{ fontSize: 12.5, marginTop: 4 }}>{result.summary}</div>
              {result.removed.length > 0 ? (
                <ul style={{ margin: '6px 0 0', paddingLeft: 18, maxHeight: 240, overflowY: 'auto', fontSize: 12 }}>
                  {result.removed.map((r, i) => (
                    <li key={`${r.kind}-${r.title}-${i}`}>
                      <span className="mono">[{r.proofState}]</span> {r.kind} — {r.title}
                    </li>
                  ))}
                </ul>
              ) : null}
              {result.note ? (
                <>
                  <div className="eyebrow" style={{ marginTop: 8 }}>
                    {t.operator.retire.noteHeading}
                  </div>
                  <div className="hint" style={{ whiteSpace: 'pre-wrap' }}>
                    {result.note.body}
                  </div>
                </>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export function OperatorPanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const [ledger, setLedger] = useState<OperatorLedger | null>(null);
  const [notes, setNotes] = useState<ImageNote[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [assertedBy, setAssertedBy] = useState('');
  const [title, setTitle] = useState('');
  const [claim, setClaim] = useState<OperatorClaim>('asserted_unverified');
  const [rationale, setRationale] = useState('');
  const [severity, setSeverity] = useState<Finding['severity']>('info');
  const [disputes, setDisputes] = useState('');

  /** Which row's amend form is open. One at a time: two open forms editing one ledger invites a lost update. */
  const [amendOpen, setAmendOpen] = useState<string | null>(null);

  const [noteAuthor, setNoteAuthor] = useState('');
  const [noteBody, setNoteBody] = useState('');
  /** The note being edited and its draft text. One at a time, like the amend form. */
  const [noteEdit, setNoteEdit] = useState<{ id: string; body: string } | null>(null);
  const [noteBusy, setNoteBusy] = useState(false);

  const load = useCallback(() => {
    api
      .operatorLedger(imageId)
      .then(setLedger)
      .catch(() => setLedger(null));
    api
      .notes(imageId)
      .then(setNotes)
      .catch(() => setNotes([]));
  }, [imageId]);

  useEffect(load, [load]);

  const add = useCallback(async () => {
    setErr(null);
    setBusy(true);
    try {
      await api.addAssertion(imageId, {
        assertedBy: assertedBy.trim(),
        title: title.trim(),
        claim,
        rationale: rationale.trim(),
        severity,
        ...(claim === 'disputes_finding' && disputes.trim() ? { disputesFindingId: disputes.trim() } : {}),
      });
      setTitle('');
      setRationale('');
      setDisputes('');
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [imageId, assertedBy, title, claim, rationale, severity, disputes, load]);

  const [withdrawing, setWithdrawing] = useState<AssertedFinding | null>(null);
  const withdraw = useCallback(
    async (f: AssertedFinding, reason: string, who: string) => {
      setErr(null);
      try {
        await api.withdrawAssertion(imageId, f.id, { withdrawnBy: who, reason });
        load();
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    },
    [imageId, load],
  );

  // An empty draft is not a problem worth announcing — the button is simply not ready. A draft that is too long is,
  // because the button would otherwise sit disabled with no reason given.
  const newBodyProblem = noteBodyProblem(noteBody);
  const newNoteTooLong = newBodyProblem?.kind === 'tooLong' ? newBodyProblem : null;
  const newAuthorTooLong = noteAuthorTooLong(noteAuthor);
  const canAddNote = !!noteAuthor.trim() && !newBodyProblem && !newAuthorTooLong;

  const addNote = useCallback(async () => {
    if (!canAddNote) return;
    setErr(null);
    try {
      await api.addNote(imageId, { author: noteAuthor.trim(), body: noteBody.trim() });
      setNoteBody('');
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [imageId, noteAuthor, noteBody, canAddNote, load]);

  const removeNote = useCallback(
    async (noteId: string) => {
      try {
        await api.deleteNote(imageId, noteId);
        if (noteEdit?.id === noteId) setNoteEdit(null);
        load();
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    },
    [imageId, load, noteEdit],
  );

  const saveNoteEdit = useCallback(async () => {
    if (!noteEdit || noteBusy || noteBodyProblem(noteEdit.body)) return;
    const body = noteEdit.body.trim();
    if (body === notes.find((n) => n.id === noteEdit.id)?.body) {
      setNoteEdit(null);
      return;
    }
    setErr(null);
    setNoteBusy(true);
    try {
      const updated = await api.updateNote(imageId, noteEdit.id, body);
      setNotes((ns) => ns.map((n) => (n.id === updated.id ? updated : n)));
      setNoteEdit(null);
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setNoteBusy(false);
    }
  }, [imageId, noteEdit, noteBusy, notes, load]);

  const editProblem = noteEdit ? noteBodyProblem(noteEdit.body) : null;

  // Which required fields are empty, by their visible label. The button stays enabled: a disabled button said
  // "not yet" without saying why, so a click now names the missing fields instead.
  const missing = [
    ...(assertedBy.trim() ? [] : [t.operator.form.whoLabel]),
    ...(title.trim() ? [] : [t.operator.form.claimLabel]),
    ...(claim === 'disputes_finding' && !disputes.trim() ? [t.operator.form.disputesLabel] : []),
    ...(rationale.trim() ? [] : [t.operator.form.rationaleLabel]),
  ];
  const [tried, setTried] = useState(false);
  const invalid = (label: string): true | undefined => (tried && missing.includes(label) ? true : undefined);

  return (
    <>
      <div className="panel">
        <div className="panel-title">{t.operator.assertionsTitle(ledger?.assertions.length ?? 0)}</div>
        <div className="panel-sub">{t.operator.assertionsSub}</div>

        {/* The caveat is served by the API so the UI cannot drift from the report or the MCP payload. */}
        <div className="banner" style={{ marginTop: 12 }}>
          {ledger?.notAMeasurement ?? t.operator.notAMeasurement}
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginTop: 12 }}>
          <input
            className="input"
            placeholder={t.operator.form.whoPlaceholder}
            aria-label={t.operator.form.whoLabel}
            aria-invalid={invalid(t.operator.form.whoLabel)}
            value={assertedBy}
            onChange={(e) => setAssertedBy(e.target.value)}
            style={{ flex: '1 1 160px', minWidth: 0 }}
          />
          <input
            className="input"
            placeholder={t.operator.form.claimPlaceholder}
            aria-label={t.operator.form.claimLabel}
            aria-invalid={invalid(t.operator.form.claimLabel)}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            style={{ flex: '2 1 280px', minWidth: 0 }}
          />
          {/* There is no proof-state control here, and there is not meant to be one. */}
          <select
            className="select"
            aria-label={t.operator.form.basisLabel}
            value={claim}
            onChange={(e) => setClaim(e.target.value as OperatorClaim)}
            style={{ flex: '1 1 260px', minWidth: 0 }}
          >
            {CLAIMS.map((c) => (
              <option key={c} value={c}>
                {t.operator.claim[c]}
              </option>
            ))}
          </select>
          {/* The severity CODE is what is submitted and what SQLite stores, so it is what the option shows. */}
          <select
            className="select"
            aria-label={t.operator.form.severityLabel}
            value={severity}
            onChange={(e) => setSeverity(e.target.value as Finding['severity'])}
            style={{ flex: '0 0 110px' }}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>

        {claim === 'disputes_finding' ? (
          <input
            className="input mono"
            placeholder={t.operator.form.disputesPlaceholder}
            aria-label={t.operator.form.disputesLabel}
            aria-invalid={invalid(t.operator.form.disputesLabel)}
            value={disputes}
            onChange={(e) => setDisputes(e.target.value)}
            style={{ marginTop: 8 }}
          />
        ) : null}

        <textarea
          className="input"
          placeholder={t.operator.form.rationalePlaceholder}
          aria-label={t.operator.form.rationaleLabel}
          aria-invalid={invalid(t.operator.form.rationaleLabel)}
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          style={{ marginTop: 8, height: 72, padding: '8px 10px', resize: 'vertical' }}
        />

        <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy}
            onClick={() => {
              setTried(true);
              if (missing.length === 0) void add();
            }}
          >
            {busy ? t.operator.form.recording : t.operator.form.record}
          </button>
          {ledger ? <span className="hint">{t.operator.measuredCount(ledger.measuredFindingCount)}</span> : null}
        </div>
        {tried && missing.length > 0 ? (
          <div className="field-error" role="alert">
            {t.operator.form.missing(missing)}
          </div>
        ) : null}

        {err ? (
          <div className="banner banner-warn" style={{ marginTop: 10 }}>
            {err}
          </div>
        ) : null}

        {ledger && ledger.assertions.length > 0 ? (
          <AssertionTable
            rows={ledger.assertions}
            onWithdraw={setWithdrawing}
            amend={{
              openFor: amendOpen,
              imageId,
              setOpenFor: setAmendOpen,
              onDone: load,
              onError: setErr,
              who: assertedBy,
            }}
          />
        ) : (
          <div className="hint" style={{ marginTop: 12 }}>
            {t.operator.noAssertions}
          </div>
        )}

        {ledger && ledger.withdrawn.length > 0 ? (
          <>
            <div className="eyebrow" style={{ marginTop: 16 }}>
              {t.operator.withdrawnHeading(ledger.withdrawn.length)}
            </div>
            <div className="hint">{t.operator.withdrawnNote}</div>
            <AssertionTable rows={ledger.withdrawn} />
          </>
        ) : null}
      </div>

      <div className="panel">
        <div className="panel-title">{t.operator.notes.title(notes.length)}</div>
        <div className="panel-sub">{t.operator.notes.sub}</div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
          <input
            className="input"
            placeholder={t.operator.notes.authorPlaceholder}
            aria-label={t.operator.notes.authorLabel}
            aria-invalid={newAuthorTooLong ? true : undefined}
            value={noteAuthor}
            onChange={(e) => setNoteAuthor(e.target.value)}
            style={{ flex: '0 1 160px', minWidth: 0 }}
          />
          <textarea
            className="input"
            placeholder={t.operator.notes.bodyPlaceholder}
            aria-label={t.operator.notes.bodyLabel}
            aria-invalid={newNoteTooLong ? true : undefined}
            value={noteBody}
            onChange={(e) => setNoteBody(e.target.value)}
            style={{ flex: '1 1 320px', minWidth: 0, height: 56, padding: '8px 10px', resize: 'vertical' }}
          />
          <button type="button" className="btn btn-sm" disabled={!canAddNote} onClick={addNote}>
            {t.operator.notes.save}
          </button>
        </div>
        {newAuthorTooLong || newNoteTooLong ? (
          <div className="field-error" role="alert" style={{ marginTop: 6 }}>
            {[
              ...(newAuthorTooLong ? [t.operator.notes.authorTooLong(MAX_NOTE_AUTHOR)] : []),
              ...(newNoteTooLong ? [t.operator.notes.tooLong(MAX_NOTE, newNoteTooLong.length)] : []),
            ].join(' ')}
          </div>
        ) : null}

        {notes.length === 0 ? (
          <div className="hint" style={{ marginTop: 12 }}>
            {t.operator.notes.empty}
          </div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data">
              <tbody>
                {notes.map((n) => (
                  <tr key={n.id}>
                    <td style={{ fontSize: 12.5 }}>
                      {noteEdit?.id === n.id ? (
                        <div style={{ display: 'grid', gap: 6 }}>
                          <textarea
                            className="input"
                            aria-label={t.operator.notes.editLabel}
                            aria-invalid={editProblem ? true : undefined}
                            value={noteEdit.body}
                            disabled={noteBusy}
                            onChange={(e) => setNoteEdit({ id: n.id, body: e.target.value })}
                            style={{ height: 72, padding: '8px 10px', resize: 'vertical' }}
                          />
                          {/* Save is disabled while the draft cannot be sent, so the reason sits right beside it. */}
                          {editProblem ? (
                            <div className="field-error" role="alert">
                              {editProblem.kind === 'empty'
                                ? t.operator.notes.emptyBody
                                : t.operator.notes.tooLong(MAX_NOTE, editProblem.length)}
                            </div>
                          ) : null}
                          <div style={{ display: 'flex', gap: 8 }}>
                            <button
                              type="button"
                              className="btn btn-sm"
                              disabled={noteBusy || !!editProblem}
                              onClick={() => void saveNoteEdit()}
                            >
                              {noteBusy ? t.operator.notes.savingEdit : t.operator.notes.saveEdit}
                            </button>
                            <button
                              type="button"
                              className="btn btn-sm btn-ghost"
                              disabled={noteBusy}
                              onClick={() => setNoteEdit(null)}
                            >
                              {t.operator.notes.cancelEdit}
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div style={{ whiteSpace: 'pre-wrap' }}>{n.body}</div>
                      )}
                      <div className="hint">
                        {n.author} · {new Date(n.createdAt).toISOString().slice(0, 16).replace('T', ' ')}
                      </div>
                    </td>
                    <td style={{ width: '1%', whiteSpace: 'nowrap' }}>
                      {noteEdit?.id === n.id ? null : (
                        <button
                          type="button"
                          className="btn btn-sm btn-ghost"
                          disabled={noteBusy}
                          onClick={() => setNoteEdit({ id: n.id, body: n.body })}
                        >
                          {t.operator.notes.edit}
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn btn-sm btn-ghost"
                        disabled={noteBusy}
                        onClick={() => removeNote(n.id)}
                      >
                        {t.common.delete}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <RetireSourcePanel imageId={imageId} defaultWho={noteAuthor.trim() || assertedBy.trim()} onRetired={load} />
      {withdrawing ? (
        <Dialog
          title={t.operator.withdrawTitle}
          body={t.operator.withdrawBody}
          confirmLabel={t.operator.withdraw}
          fields={[
            { name: 'reason', label: t.operator.withdrawPrompt, multiline: true },
            {
              name: 'who',
              label: t.operator.withdrawWho,
              initial: assertedBy || withdrawing.assertion?.assertedBy || '',
            },
          ]}
          onCancel={() => setWithdrawing(null)}
          onConfirm={({ reason, who }) => {
            const f = withdrawing;
            setWithdrawing(null);
            void withdraw(f, reason ?? '', who ?? '');
          }}
        />
      ) : null}
    </>
  );
}
