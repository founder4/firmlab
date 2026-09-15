/**
 * CredMatchPanel — the credential cross-reference on a screen.
 *
 * The provider keeps outcomes disjoint and this panel must not blur them, because every one of them is a place the
 * "empty means clean" failure would land:
 *
 *  - **A recovered password is `static_confirmed`.** It carries the plaintext and its provenance — the string is a
 *    fact about the bytes — but `recoveredCeiling` is rendered beside it so a hit never reads as a live login.
 *  - **A miss is a `static_confirmed` BOUNDED NEGATIVE.** The row states how many candidates were tried, and
 *    `emptyNotClean` under the table refuses the reading that the password is strong.
 *  - **A blocked target is `blocked_by_platform`** — a scheme this build cannot compute, recorded so the missing
 *    capability is visible rather than mistaken for a hash that held.
 *
 * Four run states are kept apart, none allowed to read as another: **never-run** (the GET returned nothing — not a
 * clean result), **running** (a job is polled), **blocked by prerequisite** (the rootfs gate refused the POST; the
 * sentence it returned IS the answer), and **done** — which itself splits into a run blocked before hashing
 * (`available === false`) and a scanned run.
 *
 * It does NOT re-render the findings ledger: every target maps to a `credmatch` finding, and a second table of the
 * same rows is the trap this codebase names. It shows the cross-reference's own coverage — the denominators the
 * ledger cannot — and points at the ledger for the rest.
 */
import { type JSX, useCallback, useEffect, useRef, useState } from 'react';
import { type CredMatchResult, type CredMatchTarget, api } from '../api';
import { useMessages } from '../i18n';
import { RunHistory } from './RunHistory';

/** Only a recovered password earns a hot badge; a miss is neutral and a block is a warning, never affirmative. */
const OUTCOME_CLASS: Record<CredMatchTarget['result']['outcome'], string> = {
  recovered: 'badge-crit',
  'not-recovered': 'badge',
  blocked: 'badge-warn',
};

export function CredMatchPanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const m = t.credmatch;
  const [result, setResult] = useState<CredMatchResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState('');
  // A refused POST (the rootfs gate) and a job that started and then errored are DIFFERENT failures — one is a
  // prerequisite, the other a bench fault — and must not read as each other.
  const [error, setError] = useState<{ kind: 'prereq' | 'run'; message: string } | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    api
      .credmatchResult(imageId)
      // A client that could not learn otherwise reads as "has not run", never as a credential store with nothing in it.
      .then(setResult)
      .catch(() => setResult(null))
      .finally(() => setLoading(false));
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [imageId]);

  const run = useCallback(async () => {
    setBusy(true);
    setError(null);
    setLog('');
    try {
      const { jobId } = await api.runCredmatch(imageId);
      timer.current = window.setInterval(async () => {
        try {
          const j = await api.job(jobId);
          setLog(j.log);
          if (j.status !== 'done' && j.status !== 'error') return;
          if (timer.current) window.clearInterval(timer.current);
          setBusy(false);
          if (j.status === 'done') setResult(j.result as CredMatchResult);
          // The run started and the provider threw — a fault on this bench, not a statement about the firmware.
          else setError({ kind: 'run', message: j.error ?? m.runFailed });
        } catch (e) {
          if (timer.current) window.clearInterval(timer.current);
          setBusy(false);
          setError({ kind: 'run', message: e instanceof Error ? e.message : m.runFailed });
        }
      }, 900);
    } catch (e) {
      // A rootfs-gate refusal lands here: its sentence is the whole prerequisite answer, not a transport failure.
      setError({ kind: 'prereq', message: e instanceof Error ? e.message : String(e) });
      setBusy(false);
    }
  }, [imageId, m.runFailed]);

  if (loading) return <div className="skeleton" style={{ height: 160 }} />;

  const runButton = (
    <button type="button" className="btn btn-primary" onClick={run} disabled={busy}>
      {busy ? (
        <>
          <span className="spinner" /> {m.running}
        </>
      ) : result ? (
        m.rerun
      ) : (
        m.run
      )}
    </button>
  );

  const summary = result?.candidates ?? null;
  const targets = result?.targets ?? [];
  const openssl = result?.openssl ?? { available: false, verifiedFlags: [], failures: [] };

  return (
    <div className="panel">
      <div className="panel-title">{m.title}</div>
      <div className="panel-sub" style={{ maxWidth: '72ch' }}>
        {m.sub}
      </div>

      {busy && log && (
        <pre className="mono" style={{ marginTop: 12, maxHeight: 160, overflow: 'auto', fontSize: 11.5 }}>
          {log}
        </pre>
      )}

      {/* A prerequisite the gate refused, kept apart from both a completed result and a bench fault mid-run. */}
      {error && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          <span className="eyebrow">{error.kind === 'prereq' ? m.prereqHeading : m.runFailedHeading}</span>
          <p style={{ margin: '4px 0 0', maxWidth: '72ch' }}>{error.message}</p>
          <p className="hint" style={{ margin: '6px 0 0', maxWidth: '72ch' }}>
            {error.kind === 'prereq' ? m.prereqHint : m.runFailedHint}
          </p>
        </div>
      )}

      {/* Never run: this is "has not run", and it must not read as a clean image. */}
      {!result && !busy && !error && (
        <div className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
          {m.notRun}
        </div>
      )}

      {/* Done, but blocked before hashing anything: the question was asked and could not be answered. */}
      {result && result.available !== true && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          <span className="eyebrow">{m.blockedHeading}</span>
          <p style={{ margin: '4px 0 0', maxWidth: '72ch' }}>{result.reason || m.persistedUnavailable}</p>
          <p className="hint" style={{ margin: '6px 0 0', maxWidth: '72ch' }}>
            {m.blockedCaveat}
          </p>
        </div>
      )}

      {/* A scanned run: coverage denominators, capability caveats, and the per-hash outcomes. */}
      {result?.available === true && (
        <>
          <div style={{ marginTop: 14, display: 'flex', gap: 22, flexWrap: 'wrap', alignItems: 'baseline' }}>
            <Fact label={m.fact.recovered} value={String(recoveredCount(targets))} />
            <Fact label={m.fact.targets} value={String(targets.length)} />
            {summary && <Fact label={m.fact.tested} value={String(summary.candidatesTested)} />}
            {summary && <Fact label={m.fact.distinct} value={String(summary.candidatesDistinct)} />}
            {summary && summary.candidatesDropped > 0 && (
              <Fact label={m.fact.dropped} value={String(summary.candidatesDropped)} />
            )}
            {summary && <Fact label={m.fact.strings} value={String(summary.stringsHarvested)} />}
            {summary && <Fact label={m.fact.files} value={String(summary.filesRead)} />}
          </div>

          {/* The provider's own run-level sentence, verbatim — it states what was joined and what bounds the result. */}
          {result.reason && (
            <div className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
              <span className="eyebrow" style={{ marginRight: 6 }}>
                {m.coverageHeading}
              </span>
              {result.reason}
            </div>
          )}

          {/* Absence of a tool is not absence of a problem: say what could not be computed. */}
          {openssl.available === false && (
            <div className="hint" style={{ marginTop: 10, maxWidth: '72ch' }}>
              {m.opensslMissing}
            </div>
          )}
          {openssl.failures.map((f) => (
            <div key={f.flag} className="hint" style={{ marginTop: 8, maxWidth: '72ch' }}>
              {m.opensslFailure(f.flag, f.reason)}
            </div>
          ))}

          {targets.length > 0 && (
            <div className="table-wrap" style={{ marginTop: 14 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th>{m.col.account}</th>
                    <th>{m.col.scheme}</th>
                    <th style={{ width: 120 }}>{m.col.outcome}</th>
                    <th>{m.col.detail}</th>
                  </tr>
                </thead>
                <tbody>
                  {targets.map((target) => (
                    <TargetRow key={`${target.file}:${target.account}`} target={target} m={m} />
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* The sentence a miss is not allowed to be without — a bounded negative is not a clean bill. */}
          <p className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
            {m.emptyNotClean}
          </p>
          <p className="hint" style={{ marginTop: 8, maxWidth: '72ch' }}>
            {m.ledgerHint}
          </p>
        </>
      )}

      <div style={{ marginTop: 14 }}>{runButton}</div>

      <RunHistory imageId={imageId} kinds={['credmatch']} label={m.runLabel} />
    </div>
  );
}

function recoveredCount(targets: CredMatchTarget[]): number {
  return targets.filter((target) => target.result.outcome === 'recovered').length;
}

function TargetRow({
  target,
  m,
}: {
  target: CredMatchTarget;
  m: ReturnType<typeof useMessages>['credmatch'];
}): JSX.Element {
  const { result } = target;
  return (
    <tr>
      <td className="mono" style={{ fontSize: 11.5 }}>
        {target.account}
        {target.uid === 0 && <span className="hint"> · {m.uidRoot}</span>}
        {target.locked && <span className="hint"> · {m.locked}</span>}
        <div className="hint" style={{ fontSize: 11 }}>
          {target.file}
        </div>
      </td>
      <td className="hint" style={{ fontSize: 11.5 }}>
        {target.schemeLabel}
      </td>
      <td style={{ width: '1%', whiteSpace: 'nowrap' }}>
        <span className={`badge ${OUTCOME_CLASS[result.outcome]} mono`}>{m.outcome[result.outcome]}</span>
      </td>
      <td style={{ fontSize: 12.5 }}>
        {result.outcome === 'recovered' && (
          <>
            <div>
              <span className="eyebrow" style={{ marginRight: 6 }}>
                {m.recoveredLabel}
              </span>
              <span className="mono">{result.password}</span>
            </div>
            <div className="hint" style={{ marginTop: 3 }}>
              {m.recoveredDetail(result.tested)}{' '}
              {m.provenance(result.candidate.derivation, result.candidate.file, result.candidate.offset)}
            </div>
            <div className="hint" style={{ marginTop: 3 }}>
              {/* The proof-state code is a literal — it crosses the API into SQLite and reads identically everywhere. */}
              {m.proof.confirmed} <span className="mono">static_confirmed</span>. {m.recoveredCeiling}
            </div>
          </>
        )}
        {result.outcome === 'not-recovered' && (
          <div className="hint">
            {m.notRecoveredDetail(result.tested)} {m.proof.negative} <span className="mono">static_confirmed</span>.
          </div>
        )}
        {result.outcome === 'blocked' && (
          <div className="hint">
            {result.reason}. {m.proof.blocked} <span className="mono">blocked_by_platform</span>.
          </div>
        )}
      </td>
    </tr>
  );
}

function Fact({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="mono" style={{ fontSize: 12.5 }}>
        {value}
      </div>
    </div>
  );
}
