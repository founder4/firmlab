import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { type CorpusOverview, type CorpusRule, api } from '../api';
import { useMessages } from '../i18n';
import { toast } from '../toast';

/**
 * The corpus — FirmLab's cross-image knowledge base. Everything here is a prior / cross-reference: it says
 * where things recur, never that something is vulnerable. The per-image findings remain the source of truth.
 */
export function Corpus(): JSX.Element {
  const [overview, setOverview] = useState<CorpusOverview | null>(null);
  const [rules, setRules] = useState<CorpusRule[]>([]);
  const t = useMessages();

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
      // `kind` is the detector's own label for the secret — a stored measurement, offered as-is rather than
      // re-worded, and only the fallback the operator sees when there is none is localised.
      const label = window.prompt(t.corpus.reuse.promptLabel, kind ?? t.corpus.reuse.promptDefault);
      if (!label) return;
      try {
        await api.promoteRule('known-credential', hash, label);
        toast.success(t.corpus.reuse.promoted);
        refresh();
      } catch (err) {
        toast.error(err);
      }
    },
    [refresh, t],
  );

  const removeRule = useCallback(
    async (id: string) => {
      await api.deleteRule(id).catch((err) => toast.error(err));
      refresh();
    },
    [refresh],
  );

  if (!overview) return <div className="empty">{t.corpus.loading}</div>;

  return (
    <div>
      <div className="grid grid-3" style={{ marginBottom: 18 }}>
        <Stat label={t.corpus.stats.images} value={String(overview.imageCount)} />
        <Stat label={t.corpus.stats.reusedCredentials} value={String(overview.credentialReuse.length)} />
        <Stat label={t.corpus.stats.watchlistRules} value={String(overview.ruleCount)} />
      </div>

      <div className="panel">
        <div className="panel-title">{t.corpus.reuse.title}</div>
        <div className="panel-sub">{t.corpus.reuse.sub}</div>
        {overview.credentialReuse.length === 0 ? (
          <div className="hint">{t.corpus.reuse.empty}</div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>{t.corpus.reuse.colKind}</th>
                  <th>{t.corpus.reuse.colHash}</th>
                  <th>{t.corpus.reuse.colImages}</th>
                  <th>{t.corpus.reuse.colWatchlist}</th>
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
                          {t.corpus.reuse.promote}
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
        <div className="panel-title">{t.corpus.prevalence.title}</div>
        <div className="panel-sub">{t.corpus.prevalence.sub}</div>
        {overview.componentPrevalence.length === 0 ? (
          <div className="hint">{t.corpus.prevalence.empty}</div>
        ) : (
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>{t.corpus.prevalence.colComponent}</th>
                  <th>{t.corpus.prevalence.colVersion}</th>
                  <th>{t.corpus.prevalence.colImages}</th>
                  <th>{t.corpus.prevalence.colCves}</th>
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
        <div className="panel-title">{t.corpus.families.title}</div>
        <div className="panel-sub">{t.corpus.families.sub}</div>
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
          <div className="panel-title">{t.corpus.rules.title(rules.length)}</div>
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>{t.corpus.rules.colType}</th>
                  <th>{t.corpus.rules.colLabel}</th>
                  <th>{t.corpus.rules.colKey}</th>
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
                        {t.corpus.rules.remove}
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
