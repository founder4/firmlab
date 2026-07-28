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
 * Notes sit below, deliberately plainer and deliberately deleteable: they are reasoning, not claims, and the
 * asymmetry — a note can be thrown away, an assertion can only be retracted — is the visible form of the
 * difference between the two.
 */
import { useCallback, useEffect, useState } from 'react';
import {
  type AssertedFinding,
  type Finding,
  type ImageNote,
  type OperatorClaim,
  type OperatorLedger,
  api,
} from '../api';

const CLAIMS: { value: OperatorClaim; label: string }[] = [
  { value: 'asserted_unverified', label: 'I believe this — nothing here measured it' },
  { value: 'asserted_from_device', label: 'I observed this on the physical device' },
  { value: 'asserted_from_external_evidence', label: 'An external source says so (advisory, datasheet)' },
  { value: 'disputes_finding', label: 'A code-decided finding is wrong' },
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
  const withdrawn = f.assertion?.status === 'withdrawn';
  const color = withdrawn ? 'var(--text-faint)' : 'var(--trust-agent)';
  return (
    <span
      className="mono"
      style={{ color, border: `1px dashed ${color}`, borderRadius: 4, padding: '1px 6px', fontSize: 10.5 }}
    >
      {withdrawn ? 'withdrawn' : 'asserted · not measured'}
    </span>
  );
}

function AssertionTable({
  rows,
  onWithdraw,
}: { rows: AssertedFinding[]; onWithdraw?: (f: AssertedFinding) => void }): JSX.Element {
  return (
    <div className="table-wrap" style={{ marginTop: 10 }}>
      <table className="data">
        <thead>
          <tr>
            <th>Sev</th>
            <th>Claim</th>
            <th>Provenance</th>
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
              </td>
              <td style={{ width: '1%', whiteSpace: 'nowrap' }}>
                <AssertedBadge f={f} />
              </td>
              {onWithdraw ? (
                <td style={{ width: '1%' }}>
                  <button type="button" className="btn btn-sm btn-ghost" onClick={() => onWithdraw(f)}>
                    Withdraw
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
      const reason = window.prompt('Why does this claim no longer stand? (recorded with the retraction)');
      if (!reason?.trim()) return;
      const who = window.prompt('Who is retracting it?', assertedBy || f.assertion?.assertedBy || '');
      if (!who?.trim()) return;
      setErr(null);
      try {
        await api.withdrawAssertion(imageId, f.id, { withdrawnBy: who.trim(), reason: reason.trim() });
        load();
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    },
    [imageId, assertedBy, load],
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
        <div className="panel-title">Operator assertions ({ledger?.assertions.length ?? 0})</div>
        <div className="panel-sub">
          What a person knows, recorded as such. These carry no proof state, count towards no analysis stage, and are
          never deleted — only withdrawn, with the reason.
        </div>

        {/* The caveat is served by the API so the UI cannot drift from the report or the MCP payload. */}
        <div className="banner" style={{ marginTop: 12 }}>
          {ledger?.notAMeasurement ??
            'An operator assertion is evidence that a person asserted something. It is not a measurement.'}
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginTop: 12 }}>
          <input
            className="input"
            placeholder="who is asserting this"
            aria-label="Who is asserting this"
            value={assertedBy}
            onChange={(e) => setAssertedBy(e.target.value)}
            style={{ flex: '1 1 160px', minWidth: 0 }}
          />
          <input
            className="input"
            placeholder="the claim, in one line"
            aria-label="The claim"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            style={{ flex: '2 1 280px', minWidth: 0 }}
          />
          {/* There is no proof-state control here, and there is not meant to be one. */}
          <select
            className="select"
            aria-label="On what basis"
            value={claim}
            onChange={(e) => setClaim(e.target.value as OperatorClaim)}
            style={{ flex: '1 1 260px', minWidth: 0 }}
          >
            {CLAIMS.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
          <select
            className="select"
            aria-label="Asserted severity"
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
            placeholder="id of the finding you dispute"
            aria-label="Disputed finding id"
            value={disputes}
            onChange={(e) => setDisputes(e.target.value)}
            style={{ marginTop: 8 }}
          />
        ) : null}

        <textarea
          className="input"
          placeholder="on what basis — required, because nobody else can evaluate a claim without it"
          aria-label="Stated basis"
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          style={{ marginTop: 8, height: 72, padding: '8px 10px', resize: 'vertical' }}
        />

        <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' }}>
          <button type="button" className="btn btn-primary" disabled={busy || !canAdd} onClick={add}>
            {busy ? 'Recording…' : 'Record assertion'}
          </button>
          {ledger ? (
            <span className="hint">
              {ledger.measuredFindingCount} measured finding(s) on this image, counted separately.
            </span>
          ) : null}
        </div>

        {err ? (
          <div className="banner banner-warn" style={{ marginTop: 10 }}>
            {err}
          </div>
        ) : null}

        {ledger && ledger.assertions.length > 0 ? (
          <AssertionTable rows={ledger.assertions} onWithdraw={withdraw} />
        ) : (
          <div className="hint" style={{ marginTop: 12 }}>
            No assertions recorded. Everything in this image's ledger was decided by code.
          </div>
        )}

        {ledger && ledger.withdrawn.length > 0 ? (
          <>
            <div className="eyebrow" style={{ marginTop: 16 }}>
              Withdrawn ({ledger.withdrawn.length})
            </div>
            <div className="hint">
              Kept on purpose. "This was wrong, and here is why" is a more useful record than a gap.
            </div>
            <AssertionTable rows={ledger.withdrawn} />
          </>
        ) : null}
      </div>

      <div className="panel">
        <div className="panel-title">Working notes ({notes.length})</div>
        <div className="panel-sub">
          Reasoning that is not a claim: a hypothesis, a thread to pull next, why you ruled something out. Notes are
          never counted, never reported, and never rendered as findings.
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
          <input
            className="input"
            placeholder="author"
            aria-label="Note author"
            value={noteAuthor}
            onChange={(e) => setNoteAuthor(e.target.value)}
            style={{ flex: '0 1 160px', minWidth: 0 }}
          />
          <textarea
            className="input"
            placeholder="what you are thinking"
            aria-label="Note body"
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
            Save note
          </button>
        </div>

        {notes.length === 0 ? (
          <div className="hint" style={{ marginTop: 12 }}>
            No notes yet.
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
                        Delete
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
