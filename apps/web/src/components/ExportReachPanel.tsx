/**
 * ExportReachPanel — the manual way to ask a library or a kernel module the one reachability question it admits.
 *
 * `symreach` sits beside this in the same tab and refuses exactly these targets: it explores from an entry point,
 * and a `.so` (entered through an exported function) and a `.ko` (entered through a handler the kernel calls) have
 * none. So an operator staring at a vendor `.so` or a proprietary `.ko` had a prover they could not point at
 * anything. This points it — over the recovered control-flow graph rather than symbolically, because a symbolic
 * `call_state` at an export fans out through unconstrained pointer arguments and never converges (measured: 5925
 * steps and 123 s on NetUSB.ko, never reaching a target inside the function it started in).
 *
 * The panel renders three states the provider is careful to keep apart, and it must not blur them:
 *  - `reachable` is a LEAD held at `needs_runtime_reproduction`. A route exists in the code; nothing checks the
 *    branch conditions along it can hold together, so it is strictly weaker than `symreach`'s `reached`.
 *  - `not reached` is a bounded negative, NOT a clean bill — CFGFast leaves indirect calls unresolved and both
 *    target classes are built on them.
 *  - an empty graph (`no_functions_recovered`) is a FAILURE TO ANALYSE, styled as a block rather than a result: a
 *    section-stripped object would otherwise read exactly like one that was analysed and found clean.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { type ExportReachResult, type ExportReachSink, api } from '../api';
import { useMessages } from '../i18n';
import { RunHistory } from './RunHistory';

/** Only a reachable sink earns a warm badge; nothing else is an affirmative result. */
const OUTCOME_CLASS: Record<ExportReachSink['outcome'], string> = {
  reachable: 'badge-medium',
  not_reached: 'badge',
  absent: 'badge',
  no_call_site: 'badge',
  budget_exhausted: 'badge',
};

export function ExportReachPanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const m = t.exportreach;
  const [binary, setBinary] = useState('');
  const [sinks, setSinks] = useState('');
  const [budget, setBudget] = useState(240);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState('');
  const [result, setResult] = useState<ExportReachResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    api
      .exportreachResult(imageId)
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
      const { jobId } = await api.exportreach(imageId, {
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
          if (j.status === 'done') setResult(j.result as ExportReachResult);
          else setError(j.error ?? m.probeFailed);
        }
      }, 900);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }, [imageId, binary, sinks, budget, m]);

  const blocked = result?.available && result.outcome === 'no_functions_recovered';
  const reachable = result?.sinks.filter((s) => s.outcome === 'reachable') ?? [];

  return (
    <div className="panel">
      <div className="panel-title">{m.title}</div>
      <div className="panel-sub">{m.sub}</div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginTop: 12 }}>
        <input
          className="input mono"
          placeholder={m.binaryPlaceholder}
          value={binary}
          onChange={(e) => setBinary(e.target.value)}
          style={{ flex: '1 1 240px', minWidth: 0 }}
        />
        <input
          className="input mono"
          placeholder={m.sinksPlaceholder}
          value={sinks}
          onChange={(e) => setSinks(e.target.value)}
          style={{ flex: '1 1 200px', minWidth: 0 }}
          aria-label={m.sinksLabel}
        />
        <label className="hint" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {m.budget}
          <input
            className="input mono"
            type="number"
            min={15}
            max={600}
            value={budget}
            onChange={(e) => setBudget(Number(e.target.value))}
            style={{ width: 74 }}
            aria-label={m.budgetLabel}
          />
          s
        </label>
        <button type="button" className="btn btn-primary" disabled={busy || !binary.trim()} onClick={run}>
          {busy ? (
            <>
              <span className="spinner" /> {m.probing}
            </>
          ) : (
            m.ask
          )}
        </button>
      </div>
      <div className="hint" style={{ marginTop: 6 }}>
        {m.hint}
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
          <span className="eyebrow">{m.notAnswered}</span>
          <p style={{ margin: '4px 0 0' }}>{result.reason}</p>
          <p className="hint" style={{ margin: '4px 0 0' }}>
            {m.notAnsweredHint(result.binary)}
          </p>
        </div>
      )}

      {/* An empty graph is a block, not a result: it must never share styling with "analysed, nothing reachable". */}
      {blocked && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          <span className="eyebrow">{m.blockedHeading}</span>
          <p className="mono" style={{ margin: '4px 0 0' }}>
            {result?.binary} · {result?.arch ?? m.unknownArch}
          </p>
          <p style={{ margin: '4px 0 0' }}>{m.blockedBody}</p>
        </div>
      )}

      {result?.available && !blocked && (
        <div style={{ marginTop: 14 }}>
          <div className="hint mono" style={{ marginBottom: 8 }}>
            {result.binary} · {result.arch ?? m.unknownArch} ·{' '}
            {m.summary(result.functionsRecovered ?? 0, result.entryPoints ?? 0, reachable.length, result.sinks.length)}
            {typeof result.cfgSeconds === 'number' ? ` · ${m.cfgSeconds(result.cfgSeconds)}` : ''}
          </div>

          <div className="table-wrap">
            <table className="data">
              <tbody>
                {result.sinks.map((s) => {
                  const names = s.entryPointsNamed ?? [];
                  const sample = names.slice(0, 6).join(', ');
                  const more = (s.namedTruncated ?? 0) + Math.max(0, names.length - 6);
                  return (
                    <tr key={s.sink}>
                      <td style={{ width: '1%', whiteSpace: 'nowrap' }}>
                        <span className={`badge ${OUTCOME_CLASS[s.outcome]} mono`}>{m.outcome[s.outcome]}</span>
                      </td>
                      <td>
                        <div className="mono">{s.sink}</div>
                        {s.outcome === 'reachable' ? (
                          <div className="hint">
                            {m.reachableDetail(s.reachableFrom ?? 0, result.entryPoints ?? 0, s.holders ?? 0)}
                            {sample ? ` · ${m.sample(sample, more)}` : ''}
                          </div>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* The caveat is load-bearing and its proof state renders as the code it is: a reachable route in the
              graph is a lead held at needs_runtime_reproduction, never a proof. */}
          <p className="hint" style={{ marginTop: 10 }}>
            {/* The proof-state code is a literal, not a catalogue string: it crosses the API into SQLite and must
                read identically in every language. */}
            {m.caveat.lead} <span className="mono">needs_runtime_reproduction</span>
            {m.caveat.tail}
          </p>
          <p className="hint" style={{ marginTop: 6 }}>
            {m.notReachedNote}
          </p>
        </div>
      )}

      {result === null && !busy && !error && (
        <p className="hint" style={{ marginTop: 12 }}>
          {m.notRun}
        </p>
      )}

      <RunHistory imageId={imageId} kinds={['exportreach']} label={m.runLabel} />
    </div>
  );
}
