/**
 * SymReachPanel — the manual way to ask angr a question.
 *
 * The symbolic prober used to be reachable by exactly one path: the autonomous scan handed it the first few
 * `binary-pwnable-candidate` leads the W5 sweep produced. That made a working symbolic prover into something the
 * operator owned but could not interrogate. Here they pick any binary from the extracted rootfs, name any sinks
 * (or leave it blank to derive them from the binary's own unbounded-copy imports) and get the same answer the
 * autonomous path gets — under the same honesty contract, which this panel is careful to render rather than blur:
 *
 *  - `reached` is a REACHABILITY claim with the concrete input that walks the path. It is not exploitability.
 *  - `not reached` is an inconclusive, NOT a clean bill: the search was bounded, and it says which budget stopped
 *    it, whether states were pruned, and how many paths were lost to angr's own crashes. It is never styled as OK.
 *  - `absent` means the symbol is not in this binary — the question did not apply, and nothing was learned.
 *
 * The outcome codes, the sink names, the addresses and the arch are identifiers and render as the prober sent them;
 * only the prose is localised. The one sentence that must survive that in every language is the bounded-search
 * caveat under the table: it names the two proof states it keeps apart — the sinks stay at
 * `needs_runtime_reproduction`, and a search that ran out of budget never demotes one to `false_positive`.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { type SinkResult, type SymReachResult, api } from '../api';
import { useMessages } from '../i18n';
import { RunHistory } from './RunHistory';

/**
 * How each outcome is allowed to look. Nothing but `reached` earns an affirmative colour, and the labels live in
 * the catalogue keyed by the same codes, so no language can invent a fifth outcome or restyle a bounded search.
 */
const OUTCOME_CLASS: Record<SinkResult['outcome'], string> = {
  reached: 'badge-crit',
  not_reached_in_budget: 'badge-medium',
  absent: 'badge',
  skipped: 'badge',
};

export function SymReachPanel({
  imageId,
  binary,
  onBinary,
}: {
  imageId: string;
  binary: string;
  onBinary: (b: string) => void;
}): JSX.Element {
  const t = useMessages();
  const [sinks, setSinks] = useState('');
  const [budget, setBudget] = useState(90);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState('');
  const [result, setResult] = useState<SymReachResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    api
      .symreachResult(imageId)
      .then(setResult)
      .catch(() => setResult(null));
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [imageId]);

  const run = useCallback(async () => {
    if (!binary.trim()) return;
    setBusy(true);
    setError(null);
    setLog('');
    setResult(null);
    try {
      const named = sinks
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const { jobId } = await api.symreach(imageId, {
        binary: binary.trim(),
        ...(named.length ? { sinks: named } : {}),
        budgetSeconds: budget,
      });
      timer.current = window.setInterval(async () => {
        const j = await api.job(jobId);
        setLog(j.log);
        if (j.status === 'done' || j.status === 'error') {
          if (timer.current) window.clearInterval(timer.current);
          setBusy(false);
          if (j.status === 'done') setResult(j.result as SymReachResult);
          else setError(j.error ?? t.panels.symreach.probeFailed);
        }
      }, 900);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }, [imageId, binary, sinks, budget, t]);

  const reached = result?.sinks.filter((s) => s.outcome === 'reached') ?? [];

  return (
    <div className="panel">
      <div className="panel-title">{t.panels.symreach.title}</div>
      <div className="panel-sub">
        {t.panels.symreach.sub.lead} <em>{t.panels.symreach.sub.question}</em> {t.panels.symreach.sub.provesLead}{' '}
        <strong>{t.panels.symreach.sub.reachability}</strong>
        {t.panels.symreach.sub.provesTail}
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginTop: 12 }}>
        <input
          className="input mono"
          placeholder={t.panels.symreach.binaryPlaceholder}
          value={binary}
          onChange={(e) => onBinary(e.target.value)}
          style={{ flex: '1 1 240px', minWidth: 0 }}
        />
        <input
          className="input mono"
          placeholder={t.panels.symreach.sinksPlaceholder}
          value={sinks}
          onChange={(e) => setSinks(e.target.value)}
          style={{ flex: '1 1 200px', minWidth: 0 }}
          aria-label={t.panels.symreach.sinksLabel}
        />
        <label className="hint" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {t.panels.symreach.budget}
          <input
            className="input mono"
            type="number"
            min={15}
            max={600}
            value={budget}
            onChange={(e) => setBudget(Number(e.target.value))}
            style={{ width: 74 }}
            aria-label={t.panels.symreach.budgetLabel}
          />
          s
        </label>
        <button type="button" className="btn btn-primary" disabled={busy || !binary.trim()} onClick={run}>
          {busy ? (
            <>
              <span className="spinner" /> {t.panels.symreach.probing}
            </>
          ) : (
            t.panels.symreach.ask
          )}
        </button>
      </div>
      <div className="hint" style={{ marginTop: 6 }}>
        {t.panels.symreach.hint.lead} <span className="mono">strcpy</span>, <span className="mono">system</span>,{' '}
        <span className="mono">sscanf</span>
        {t.panels.symreach.hint.beforeAbsent} <em>{t.panels.symreach.hint.absentWord}</em>
        {t.panels.symreach.hint.afterAbsent}
      </div>

      {error && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          {error}
        </div>
      )}

      {busy && log && (
        <pre className="mono" style={{ marginTop: 12, maxHeight: 160, overflow: 'auto', fontSize: 11.5 }}>
          {log}
        </pre>
      )}

      {result && !result.available && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          <span className="eyebrow">{t.panels.symreach.notAnswered}</span>
          <p style={{ margin: '4px 0 0' }}>{result.reason}</p>
          <p className="hint" style={{ margin: '4px 0 0' }}>
            {t.panels.symreach.notAnsweredHint(result.binary)}
          </p>
        </div>
      )}

      {result?.available && (
        <div style={{ marginTop: 14 }}>
          <div className="hint mono" style={{ marginBottom: 8 }}>
            {result.binary} · {result.arch ?? t.panels.symreach.unknownArch} · {t.panels.symreach.entry}{' '}
            {result.entry ?? '—'} · {t.panels.symreach.reachableCount(reached.length, result.sinks.length)}
            {result.derivedSinks ? ` · ${t.panels.symreach.derivedSinks}` : ''}
            {result.dropped?.length ? ` · ${t.panels.symreach.dropped(result.dropped.length)}` : ''}
          </div>

          <div className="table-wrap">
            <table className="data">
              <tbody>
                {result.sinks.map((s) => {
                  const input = [s.argv1 ? `argv[1]="${s.argv1}"` : '', s.stdin ? `stdin="${s.stdin}"` : '']
                    .filter(Boolean)
                    .join(' · ');
                  return (
                    <tr key={s.sink}>
                      <td style={{ width: '1%', whiteSpace: 'nowrap' }}>
                        <span className={`badge ${OUTCOME_CLASS[s.outcome]} mono`}>
                          {t.panels.symreach.outcome[s.outcome]}
                        </span>
                      </td>
                      <td>
                        <div className="mono">
                          {s.sink}
                          {s.addresses.length ? ` @ ${s.addresses.join(', ')}` : ''}
                        </div>
                        {s.outcome === 'reached' ? (
                          <div className="hint">
                            {input || t.panels.symreach.pathFound} · {t.panels.symreach.steps(s.steps)}
                            {s.path?.length ? (
                              <div className="mono" style={{ fontSize: 11, opacity: 0.8 }}>
                                {t.panels.symreach.pathTail} {s.path.join(' → ')}
                              </div>
                            ) : null}
                          </div>
                        ) : (
                          <div className="hint">
                            {s.reason ?? t.panels.symreach.noReason}
                            {s.pruned ? ` · ${t.panels.symreach.pruned}` : ''}
                            {s.errors ? ` · ${t.panels.symreach.errors(s.errors)}` : ''}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* The proof states are printed as the codes they are, with the sentence that keeps them apart around
              them: a bounded search that reached nothing leaves every sink a lead, and demotes none of them. */}
          <p className="hint" style={{ marginTop: 10 }}>
            {reached.length > 0 ? (
              t.panels.symreach.reachedNote
            ) : (
              <>
                {t.panels.symreach.notReached.lead} <span className="mono">needs_runtime_reproduction</span>{' '}
                {t.panels.symreach.notReached.beforeFalsePositive} <span className="mono">false_positive</span>
                {t.panels.symreach.notReached.tail}
              </>
            )}
          </p>
        </div>
      )}
      <RunHistory imageId={imageId} kinds={['symreach']} label={t.panels.symreach.runLabel} />
    </div>
  );
}
