import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { type CorpusOverview, type CorpusRule, api } from '../api';
import { toast } from '../toast';

/**
 * The corpus — FirmLab's cross-image knowledge base. Everything here is a prior / cross-reference: it says
 * where things recur, never that something is vulnerable. The per-image findings remain the source of truth.
 */
export function Corpus(): JSX.Element {
  const [overview, setOverview] = useState<CorpusOverview | null>(null);
  const [rules, setRules] = useState<CorpusRule[]>([]);

  const refresh = useCallback(() => {
    api
      .corpusOverview()
      .then(setOverview)
      .catch(() => setOverview(null));
    api
      .corpusRules()
      .then(setRules)
      .catch(() => setRules([]));
  }, []);

  useEffect(refresh, [refresh]);

  const ruleKeys = new Set(rules.filter((r) => r.type === 'known-credential').map((r) => r.key));

  const promote = useCallback(
    async (hash: string, kind: string | null) => {
      const label = window.prompt('Label for this known-bad credential:', kind ?? 'known-bad credential');
      if (!label) return;
      try {
        await api.promoteRule('known-credential', hash, label);
        toast.success('Promoted to the watchlist');
        refresh();
      } catch (err) {
        toast.error(err);
      }
    },
    [refresh],
  );

  const removeRule = useCallback(
    async (id: string) => {
      await api.deleteRule(id).catch((err) => toast.error(err));
      refresh();
    },
    [refresh],
  );

  if (!overview) return <div className="empty">Loading corpus…</div>;

  return (
    <div>
      <div className="grid grid-3" style={{ marginBottom: 18 }}>
        <Stat label="Images" value={String(overview.imageCount)} />
        <Stat label="Reused credentials" value={String(overview.credentialReuse.length)} />
        <Stat label="Watchlist rules" value={String(overview.ruleCount)} />
      </div>

      <div className="panel">
        <div className="panel-title">Credential reuse</div>
        <div className="panel-sub">
          Secrets that appear in more than one image — a prior worth checking, not a verdict. Promote a recurring one to
          the known-bad watchlist to auto-flag it on future uploads.
        </div>
        {overview.credentialReuse.length === 0 ? (
          <div className="hint">No credential appears in more than one image yet.</div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Kind</th>
                  <th>Hash</th>
                  <th>Images</th>
                  <th>Watchlist</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {overview.credentialReuse.map((c) => (
                  <tr key={c.hash}>
                    <td>{c.kind ?? '—'}</td>
                    <td className="mono" style={{ fontSize: 11 }}>
                      {c.hash.slice(0, 16)}…
                    </td>
                    <td className="mono">{c.imageCount}</td>
                    <td>{c.watchlistLabel ? <span className="badge badge-high">{c.watchlistLabel}</span> : '—'}</td>
                    <td>
                      {!ruleKeys.has(c.hash) && (
                        <button type="button" className="btn btn-sm" onClick={() => promote(c.hash, c.kind)}>
                          + watchlist
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">Component prevalence</div>
        <div className="panel-sub">Which component versions span the most images, and how many CVEs grype matched.</div>
        {overview.componentPrevalence.length === 0 ? (
          <div className="hint">No SBOM data yet — run SBOM on some images.</div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Version</th>
                  <th>Images</th>
                  <th>CVEs</th>
                </tr>
              </thead>
              <tbody>
                {overview.componentPrevalence.slice(0, 100).map((c) => (
                  <tr key={`${c.name}@${c.version}`}>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {c.name}
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {c.version}
                    </td>
                    <td className="mono">{c.imageCount}</td>
                    <td>{c.cveCount > 0 ? <span className="badge badge-high">{c.cveCount}</span> : '0'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">Device families</div>
        <div className="panel-sub">
          Images grouped by identity (vendor:class:arch). A family with several versions is the basis for cross-version
          diff.
        </div>
        {overview.deviceFamilies.map((fam) => (
          <div key={fam.familyKey} style={{ marginTop: 12 }}>
            <div className="mono" style={{ fontSize: 12.5, marginBottom: 4 }}>
              {fam.familyKey} <span className="hint">({fam.images.length})</span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {fam.images.map((img) => (
                <Link key={img.id} to={`/image/${img.id}`} className="badge" style={{ textDecoration: 'none' }}>
                  {img.filename}
                </Link>
              ))}
            </div>
          </div>
        ))}
      </div>

      {rules.length > 0 && (
        <div className="panel">
          <div className="panel-title">Watchlist rules ({rules.length})</div>
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Label</th>
                  <th>Key</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td className="mono" style={{ fontSize: 11.5 }}>
                      {r.type}
                    </td>
                    <td>{r.label}</td>
                    <td className="mono" style={{ fontSize: 11 }}>
                      {r.key.slice(0, 16)}…
                    </td>
                    <td>
                      <button type="button" className="btn btn-sm" onClick={() => removeRule(r.id)}>
                        remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  );
}
