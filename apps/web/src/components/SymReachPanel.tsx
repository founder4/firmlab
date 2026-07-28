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
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { type SinkResult, type SymReachResult, api } from '../api';
import { RunHistory } from './RunHistory';

/** How each outcome is allowed to look. Nothing but `reached` earns an affirmative colour. */
const OUTCOME_META: Record<SinkResult['outcome'], { label: string; cls: string }> = {
  reached: { label: 'reachable from entry', cls: 'badge-crit' },
  not_reached_in_budget: { label: 'inconclusive — search bounded', cls: 'badge-medium' },
  absent: { label: 'symbol not in this binary', cls: 'badge' },
  skipped: { label: 'not asked — run budget spent', cls: 'badge' },
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
          else setError(j.error ?? 'probe failed');
        }
      }, 900);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }, [imageId, binary, sinks, budget]);

  const reached = result?.sinks.filter((s) => s.outcome === 'reached') ?? [];

  return (
    <div className="panel">
      <div className="panel-title">Symbolic reachability (angr)</div>
      <div className="panel-sub">
        One checkable question per sink:{' '}
        <em>is that call site reachable from the entry point under symbolic argv/stdin?</em> A reached sink proves{' '}
        <strong>reachability</strong>, not exploitability. A sink not reached proves nothing at all — the search is
        bounded, so it stays a lead.
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginTop: 12 }}>
        <input
          className="input mono"
          placeholder="rootfs-relative binary, e.g. usr/sbin/bpalogin"
          value={binary}
          onChange={(e) => onBinary(e.target.value)}
          style={{ flex: '1 1 240px', minWidth: 0 }}
        />
        <input
          className="input mono"
          placeholder="sinks (blank = derive from imports)"
          value={sinks}
          onChange={(e) => setSinks(e.target.value)}
          style={{ flex: '1 1 200px', minWidth: 0 }}
          aria-label="Sink symbols to ask about"
        />
        <label className="hint" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          budget
          <input
            className="input mono"
            type="number"
            min={15}
            max={600}
            value={budget}
            onChange={(e) => setBudget(Number(e.target.value))}
            style={{ width: 74 }}
            aria-label="Budget in seconds"
          />
          s
        </label>
        <button type="button" className="btn btn-primary" disabled={busy || !binary.trim()} onClick={run}>
          {busy ? (
            <>
              <span className="spinner" /> Probing…
            </>
          ) : (
            'Ask'
          )}
        </button>
      </div>
      <div className="hint" style={{ marginTop: 6 }}>
        Sinks are function symbols — <span className="mono">strcpy</span>, <span className="mono">system</span>,{' '}
        <span className="mono">sscanf</span>. Leave blank to ask about whichever unbounded-copy functions this binary
        imports. A symbol the binary does not import comes back as <em>absent</em>, not as a clean result.
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
          <span className="eyebrow">Not answered</span>
          <p style={{ margin: '4px 0 0' }}>{result.reason}</p>
          <p className="hint" style={{ margin: '4px 0 0' }}>
            This is a missing capability, not a clean result — nothing about {result.binary} was ruled out.
          </p>
        </div>
      )}

      {result?.available && (
        <div style={{ marginTop: 14 }}>
          <div className="hint mono" style={{ marginBottom: 8 }}>
            {result.binary} · {result.arch ?? 'unknown arch'} · entry {result.entry ?? '—'} · {reached.length}/
            {result.sinks.length} reachable
            {result.derivedSinks ? ' · sinks derived from imports' : ''}
            {result.dropped?.length ? ` · ${result.dropped.length} sink(s) not asked (per-run cap)` : ''}
          </div>

          <div className="table-wrap">
            <table className="data">
              <tbody>
                {result.sinks.map((s) => {
                  const meta = OUTCOME_META[s.outcome];
                  const input = [s.argv1 ? `argv[1]="${s.argv1}"` : '', s.stdin ? `stdin="${s.stdin}"` : '']
                    .filter(Boolean)
                    .join(' · ');
                  return (
                    <tr key={s.sink}>
                      <td style={{ width: '1%', whiteSpace: 'nowrap' }}>
                        <span className={`badge ${meta.cls} mono`}>{meta.label}</span>
                      </td>
                      <td>
                        <div className="mono">
                          {s.sink}
                          {s.addresses.length ? ` @ ${s.addresses.join(', ')}` : ''}
                        </div>
                        {s.outcome === 'reached' ? (
                          <div className="hint">
                            {input || 'path found'} · {s.steps} steps
                            {s.path?.length ? (
                              <div className="mono" style={{ fontSize: 11, opacity: 0.8 }}>
                                path tail: {s.path.join(' → ')}
                              </div>
                            ) : null}
                          </div>
                        ) : (
                          <div className="hint">
                            {s.reason ?? 'no reason recorded'}
                            {s.pruned ? ' · states pruned to stay in the memory bound' : ''}
                            {s.errors ? ` · ${s.errors} state(s) lost to angr-internal errors` : ''}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <p className="hint" style={{ marginTop: 10 }}>
            {reached.length > 0
              ? 'A reached sink means the call site is on a feasible path from the entry point with an input that walks it. Whether the copy overflows, and whether that is exploitable, are separate questions this does not answer.'
              : 'Nothing was reached inside the budget. That is not evidence of unreachability — indirect jumps and unmodelled syscalls routinely hide real paths from a bounded search. Raise the budget or fuzz the binary.'}
          </p>
        </div>
      )}
      <RunHistory imageId={imageId} kinds={['symreach']} label="reachability" />
    </div>
  );
}
