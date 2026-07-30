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
 * difference between the two.
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
  api,
} from '../api';
import { messages, useMessages } from '../i18n';

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
}: {
  f: AssertedFinding;
  onCancel: () => void;
  onDone: () => void;
  onError: (m: string) => void;
  imageId: string;
}): JSX.Element {
  const t = useMessages();
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
  const sendable = amendmentIsSendable(diff);

  const save = async (): Promise<void> => {
    if (!sendable) return;
    setBusy(true);
    try {
      await api.amendAssertion(imageId, f.id, {
        title: next.title.trim(),
        claim: next.claim as OperatorClaim,
        rationale: next.rationale.trim(),
        severity: next.severity as Finding['severity'],
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
      ) : (
        <span className="hint" data-role={`refusal-${diff.refusal}`} style={{ maxWidth: '72ch' }}>
          {diff.refusal === 'retyped' ? t.operator.amend.retyped : t.operator.amend.untouched}
        </span>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        {/* Gated on the DIFF alone. An earlier version also required an author here and that was wrong twice: the
            amend route deliberately does not accept one — `assertedBy` is carried over so an edit cannot reassign
            authorship — and requiring it disabled the button for no reason the API asks for. */}
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

  const withdraw = useCallback(
    async (f: AssertedFinding) => {
      const reason = window.prompt(t.operator.withdrawPrompt);
      if (!reason?.trim()) return;
      const who = window.prompt(t.operator.withdrawWho, assertedBy || f.assertion?.assertedBy || '');
      if (!who?.trim()) return;
      setErr(null);
      try {
        await api.withdrawAssertion(imageId, f.id, { withdrawnBy: who.trim(), reason: reason.trim() });
        load();
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    },
    [imageId, assertedBy, load, t],
  );

  const addNote = useCallback(async () => {
    setErr(null);
    try {
      await api.addNote(imageId, { author: noteAuthor.trim(), body: noteBody.trim() });
      setNoteBody('');
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [imageId, noteAuthor, noteBody, load]);

  const removeNote = useCallback(
    async (noteId: string) => {
      try {
        await api.deleteNote(imageId, noteId);
        load();
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    },
    [imageId, load],
  );

  const canAdd =
    assertedBy.trim() && title.trim() && rationale.trim() && (claim !== 'disputes_finding' || disputes.trim());

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
            value={assertedBy}
            onChange={(e) => setAssertedBy(e.target.value)}
            style={{ flex: '1 1 160px', minWidth: 0 }}
          />
          <input
            className="input"
            placeholder={t.operator.form.claimPlaceholder}
            aria-label={t.operator.form.claimLabel}
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
            value={disputes}
            onChange={(e) => setDisputes(e.target.value)}
            style={{ marginTop: 8 }}
          />
        ) : null}

        <textarea
          className="input"
          placeholder={t.operator.form.rationalePlaceholder}
          aria-label={t.operator.form.rationaleLabel}
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          style={{ marginTop: 8, height: 72, padding: '8px 10px', resize: 'vertical' }}
        />

        <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' }}>
          <button type="button" className="btn btn-primary" disabled={busy || !canAdd} onClick={add}>
            {busy ? t.operator.form.recording : t.operator.form.record}
          </button>
          {ledger ? <span className="hint">{t.operator.measuredCount(ledger.measuredFindingCount)}</span> : null}
        </div>

        {err ? (
          <div className="banner banner-warn" style={{ marginTop: 10 }}>
            {err}
          </div>
        ) : null}

        {ledger && ledger.assertions.length > 0 ? (
          <AssertionTable
            rows={ledger.assertions}
            onWithdraw={withdraw}
            amend={{
              openFor: amendOpen,
              imageId,
              setOpenFor: setAmendOpen,
              onDone: load,
              onError: setErr,
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
            value={noteAuthor}
            onChange={(e) => setNoteAuthor(e.target.value)}
            style={{ flex: '0 1 160px', minWidth: 0 }}
          />
          <textarea
            className="input"
            placeholder={t.operator.notes.bodyPlaceholder}
            aria-label={t.operator.notes.bodyLabel}
            value={noteBody}
            onChange={(e) => setNoteBody(e.target.value)}
            style={{ flex: '1 1 320px', minWidth: 0, height: 56, padding: '8px 10px', resize: 'vertical' }}
          />
          <button
            type="button"
            className="btn btn-sm"
            disabled={!noteAuthor.trim() || !noteBody.trim()}
            onClick={addNote}
          >
            {t.operator.notes.save}
          </button>
        </div>

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
                      <div style={{ whiteSpace: 'pre-wrap' }}>{n.body}</div>
                      <div className="hint">
                        {n.author} · {new Date(n.createdAt).toISOString().slice(0, 16).replace('T', ' ')}
                      </div>
                    </td>
                    <td style={{ width: '1%' }}>
                      <button type="button" className="btn btn-sm btn-ghost" onClick={() => removeNote(n.id)}>
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
    </>
  );
}
