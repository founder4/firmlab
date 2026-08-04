/**
 * The binary-hardening sweep, on a screen.
 *
 * It is the corpus's second-largest source of findings — 337 rows against `sbom`'s 474 — and until now it had no
 * route at all: it ran only inside the autonomous scan, its rows landed in the ledger, and the sweep's own result
 * reached nobody. So there was no way to ask "is this list everything?", which for this provider is most of the
 * question.
 *
 * **What the header states, and why it is not decoration.** `binariesScanned` → `candidates` → `findings.length`
 * are three different numbers and the gaps between them are the coverage story:
 *
 *   - `candidates` counts **stack-overflow candidates only**, while `findings` carries every kind the sweep
 *     emits, so `findings.length` is legitimately the LARGER number on this corpus — 49 listed against 37
 *     candidates on the WR940N. The first draft of this panel printed `candidates - listed` as a drop count and
 *     would have shipped a negative bound dressed as an answer; the walk found that, not a test;
 *   - the cap truncates on merit (`selectFindings` ranks by exposure, never by arrival order) and the provider
 *     states the cut **in its own `reason`**, which is rendered verbatim rather than re-derived here — the count
 *     it cut is not in the result at all, so any arithmetic this panel did would be a guess;
 *   - `exposedDropped` NAMES the exposed binaries that still did not fit, because a count of dropped rows on a
 *     rootfs of 300 binaries tells a reader nothing about which ones they are missing;
 *   - `relocatableSkipped` and `neuteredSkipped` are two different silences — a `.ko` the question does not apply
 *     to, versus a file the extractor cut to `/dev/null` — and collapsing them would report the carve's damage as
 *     a scope decision.
 *
 * **Every row is a lead and the panel says so once, at the top.** These are syntactic candidates: an import of
 * `strcpy` plus no stack canary. Nothing here was executed and nothing was proven reachable; the sweep's own
 * findings carry `needs_runtime_reproduction` and this panel must not let a table of red rows read as a table of
 * bugs. The route to a verdict is symbolic reachability or a reproduced crash, and both live elsewhere.
 */
import { type JSX, useEffect, useState } from 'react';
import { type BinVulnResult, api } from '../api';
import { useMessages } from '../i18n';
import { SEV_COLOR } from './FindingsLedger';

export function BinVulnPanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const b = t.binvuln;
  const [result, setResult] = useState<BinVulnResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const load = (): void => {
    api
      .binvuln(imageId)
      .then(setResult)
      // A client that could not learn otherwise reads as "has not run", never as a rootfs with no weak binary.
      .catch(() => setResult(null))
      .finally(() => setLoading(false));
  };
  // Keyed on the image only: `load` is re-created every render and listing it would poll the route.
  useEffect(load, [imageId]);

  const run = async (): Promise<void> => {
    setBusy(true);
    try {
      await api.runBinvuln(imageId);
    } finally {
      setBusy(false);
      load();
    }
  };

  if (loading) return <div className="skeleton" style={{ height: 160 }} />;

  const runButton = (
    <button type="button" className="btn btn-sm" onClick={run} disabled={busy}>
      {busy ? b.running : result ? b.rerun : b.run}
    </button>
  );

  if (!result || result.available === false) {
    return (
      <div className="panel">
        <div className="panel-title">{b.title}</div>
        <div className="panel-sub" style={{ maxWidth: '72ch' }}>
          {b.sub}
        </div>
        <div className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
          {result ? b.empty.unavailable(result.reason) : b.empty.notRun}
        </div>
        <div style={{ marginTop: 10 }}>{runButton}</div>
      </div>
    );
  }

  const shown = result.findings ?? [];

  return (
    <div className="panel">
      <div className="panel-title">{b.title}</div>
      <div className="panel-sub" style={{ maxWidth: '72ch' }}>
        {b.sub}
      </div>

      <div style={{ marginTop: 12, display: 'flex', gap: 22, flexWrap: 'wrap', alignItems: 'baseline' }}>
        <Fact label={b.field.scanned} value={String(result.binariesScanned)} />
        <Fact label={b.field.candidates} value={String(result.candidates)} />
        <Fact label={b.field.listed} value={String(shown.length)} />
        {result.relocatableSkipped !== undefined && (
          <Fact label={b.field.relocatable} value={String(result.relocatableSkipped)} />
        )}
        {result.neuteredSkipped !== undefined && (
          <Fact label={b.field.neutered} value={String(result.neuteredSkipped)} />
        )}
      </div>

      {/* The one sentence that has to be read before the table, because a table of red rows reads as bugs. */}
      <div className="banner banner-warn" style={{ marginTop: 12 }}>
        <div style={{ maxWidth: '72ch' }}>{b.leadsOnly}</div>
      </div>

      {/* The provider's own sentence, verbatim. It already states the cap and what it dropped, the ranking rule
          the cut used, whether an exposure signal ever reached the sweep, and the two kinds of skip — and the
          number it dropped is not in the result, so anything this panel computed would be a guess. */}
      {result.reason && (
        <div className="hint" style={{ marginTop: 10, maxWidth: '72ch' }}>
          {result.reason}
        </div>
      )}

      {result.exposedDropped && result.exposedDropped.length > 0 && (
        <div className="hint" style={{ marginTop: 8, maxWidth: '72ch' }}>
          {b.exposedDropped(result.exposedDropped.length)}
          <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {result.exposedDropped.map((p) => (
              <li key={p} className="mono" style={{ fontSize: 11.5 }}>
                {p}
              </li>
            ))}
          </ul>
        </div>
      )}

      {shown.length === 0 ? (
        <div className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
          {b.empty.noCandidates(result.binariesScanned)}
        </div>
      ) : (
        <div className="table-wrap" style={{ marginTop: 10 }}>
          <table className="data">
            <thead>
              <tr>
                <th style={{ width: 28 }} />
                <th>{b.col.finding}</th>
                <th style={{ width: 150 }}>{b.col.kind}</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((f, i) => (
                <tr key={f.id ?? `${f.kind}-${f.title}-${i}`}>
                  <td>
                    {/* Hollow, always: every row here is a lead. The ledger's own mark uses fill for established,
                        and nothing this sweep produces is established. */}
                    <span
                      aria-label={b.leadMark(f.severity)}
                      role="img"
                      style={{
                        display: 'inline-block',
                        width: 9,
                        height: 9,
                        borderRadius: '50%',
                        border: `1.5px solid ${SEV_COLOR[f.severity] ?? 'var(--text-dim)'}`,
                        background: 'transparent',
                        verticalAlign: 'middle',
                      }}
                    />
                  </td>
                  <td style={{ fontSize: 12.5 }}>
                    {f.title}
                    {f.rationale && (
                      <div className="hint" style={{ marginTop: 2 }}>
                        {f.rationale}
                      </div>
                    )}
                  </td>
                  <td className="mono hint" style={{ fontSize: 11 }}>
                    {f.kind}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ marginTop: 12 }}>{runButton}</div>
    </div>
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
