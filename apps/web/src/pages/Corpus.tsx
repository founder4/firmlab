import { type ReactNode, useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { type CorpusOverview, type CorpusReindexReport, type CorpusRule, api } from '../api';
import { Dialog, type DialogField } from '../components/Dialog';
import { useLocale, useMessages } from '../i18n';
import { toast } from '../toast';

/**
 * The cross-image corpus — FirmLab's knowledge base. Everything here is a prior / cross-reference: it says
 * where things recur, never that something is vulnerable. The per-image findings remain the source of truth.
 *
 * The page carries a `page-head` for the same reason every other page does, and here it does a second job: three
 * unrelated things in this repository are called "corpus" (see "The three corpora" in docs/ARCHITECTURE.md), and
 * this was the only screen that named none of them — it opened straight into the stat tiles, leaving the sidebar
 * entry as the only label, and that entry read just "Corpus".
 */
export function Corpus(): JSX.Element {
  const [overview, setOverview] = useState<CorpusOverview | null>(null);
  const [rules, setRules] = useState<CorpusRule[]>([]);
  const t = useMessages();
  const locale = useLocale();

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

  // One pending dialog at a time: promoting asks for a label, removing asks for confirmation.
  const [dialog, setDialog] = useState<
    { kind: 'promote'; hash: string; kind0: string | null } | { kind: 'remove'; rule: CorpusRule } | null
  >(null);

  const promote = useCallback(
    async (hash: string, label: string) => {
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

  // The reconciliation is additive (INSERT OR IGNORE) and idempotent, so it needs no confirmation; what it needs is
  // a report read in full, because "0 inserted" and "nothing to read" are different answers.
  const [reindexing, setReindexing] = useState(false);
  const [report, setReport] = useState<CorpusReindexReport | null>(null);

  const reindex = useCallback(async () => {
    setReindexing(true);
    try {
      setReport(await api.reindexCorpus(locale));
      refresh();
    } catch (err) {
      toast.error(err);
    } finally {
      setReindexing(false);
    }
  }, [locale, refresh]);

  if (!overview) return <div className="empty">{t.corpus.loading}</div>;

  return (
    <div>
      <div className="page-head">
        <div className="eyebrow">{t.corpus.eyebrow}</div>
        <h1 className="page-title">{t.corpus.title}</h1>
        <div className="page-desc">{t.corpus.desc}</div>
      </div>

      <div className="grid grid-3" style={{ marginBottom: 18 }}>
        <Stat label={t.corpus.stats.images} value={String(overview.imageCount)} />
        <Stat
          label={t.corpus.stats.reusedCredentials}
          value={String(overview.credentialReuseTotal ?? overview.credentialReuse.length)}
        />
        <Stat label={t.corpus.stats.watchlistRules} value={String(overview.ruleCount)} />
      </div>

      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="panel-title">{t.corpus.reindex.title}</div>
            <div className="panel-sub">{t.corpus.reindex.sub}</div>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            disabled={reindexing}
            aria-busy={reindexing}
            onClick={() => void reindex()}
          >
            {reindexing ? t.corpus.reindex.running : t.corpus.reindex.run}
          </button>
        </div>
        {report ? <ReindexReport report={report} /> : null}
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
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => setDialog({ kind: 'promote', hash: c.hash, kind0: c.kind })}
                        >
                          {t.corpus.reuse.promote}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {overview.credentialReuseTotal !== undefined &&
              overview.credentialReuseTotal > overview.credentialReuse.length && (
                <div className="hint" style={{ marginTop: 8 }}>
                  {t.corpus.listNote(
                    overview.credentialReuse.length,
                    overview.credentialReuseTotal,
                    overview.listing?.rule ?? '',
                  )}
                </div>
              )}
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">{t.corpus.prevalence.title}</div>
        <div className="panel-sub">{t.corpus.prevalence.sub}</div>
        {overview.componentPrevalence.length === 0 ? (
          <div className="hint">{t.corpus.prevalence.empty(overview.sbomImageCount, overview.imageCount)}</div>
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
                {overview.componentPrevalence.map((c) => (
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
            {overview.componentPrevalenceTotal !== undefined &&
              overview.componentPrevalenceTotal > overview.componentPrevalence.length && (
                <div className="hint" style={{ marginTop: 8 }}>
                  {t.corpus.listNote(
                    overview.componentPrevalence.length,
                    overview.componentPrevalenceTotal,
                    overview.listing?.rule ?? '',
                  )}
                </div>
              )}
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
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={() => setDialog({ kind: 'remove', rule: r })}
                      >
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
      {dialog?.kind === 'promote' ? (
        <Dialog
          title={t.corpus.reuse.promptTitle}
          body={t.corpus.reuse.promptBody}
          confirmLabel={t.corpus.reuse.promote}
          fields={[
            {
              name: 'label',
              label: t.corpus.reuse.promptLabel,
              // `kind` is the detector's own label for the secret — offered as-is; only the fallback is localised.
              initial: dialog.kind0 ?? t.corpus.reuse.promptDefault,
            } satisfies DialogField,
          ]}
          onCancel={() => setDialog(null)}
          onConfirm={({ label }) => {
            const hash = dialog.hash;
            setDialog(null);
            void promote(hash, label ?? '');
          }}
        />
      ) : null}
      {dialog?.kind === 'remove' ? (
        <Dialog
          title={t.corpus.rules.removeTitle(dialog.rule.label)}
          body={t.corpus.rules.removeBody}
          confirmLabel={t.corpus.rules.removeConfirm}
          danger
          onCancel={() => setDialog(null)}
          onConfirm={() => {
            const id = dialog.rule.id;
            setDialog(null);
            void removeRule(id);
          }}
        />
      ) : null}
    </div>
  );
}

/**
 * What one reconciliation did. The verdict is the API's own sentence, already localised and already carrying the
 * notes that apply to this run; the tables below it are the counts that sentence summarises, so an operator can
 * see which source contributed and which never had an input to read. Source and kind identifiers render verbatim —
 * they are the API's names for things, not prose.
 */
function ReindexReport({ report }: { report: CorpusReindexReport }): JSX.Element {
  const t = useMessages().corpus.reindex;
  const inserted = report.sources.reduce((n, s) => n + s.rowsInserted, 0);
  return (
    <div aria-live="polite" style={{ marginTop: 4 }}>
      <p style={{ maxWidth: '72ch', margin: 0 }}>{report.verdict}</p>
      <div className="hint" style={{ marginTop: 6 }}>
        {t.totalInserted(inserted, report.imageCount)}
      </div>

      <div className="table-wrap" style={{ marginTop: 10 }}>
        <table className="data">
          <thead>
            <tr>
              <th>{t.colSource}</th>
              <th>{t.colInserted}</th>
              <th>{t.colOffered}</th>
              <th>{t.colWithInput}</th>
              <th>{t.colWithoutInput}</th>
            </tr>
          </thead>
          <tbody>
            {report.sources.map((s) => (
              <tr key={s.source}>
                <td className="mono" style={{ fontSize: 12 }}>
                  {s.source}
                </td>
                <td className="mono">{s.rowsInserted}</td>
                <td className="mono">{s.rowsOffered}</td>
                <td className="mono">{s.imagesWithInput}</td>
                <td className="mono">{s.imagesWithoutInput}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="hint" style={{ marginTop: 6, maxWidth: '72ch' }}>
        {t.withoutInputNote}
      </div>

      {report.boundedInputs.length > 0 && (
        <ReportList title={t.boundedTitle}>
          {report.boundedInputs.map((b) => (
            <li key={`${b.imageId}:${b.kind}`}>{t.boundedRow(b.filename, b.kind, b.covered, b.total)}</li>
          ))}
        </ReportList>
      )}
      {report.unrecordedBounds.length > 0 && (
        <ReportList title={t.unrecordedTitle}>
          {report.unrecordedBounds.map((u) => (
            <li key={u.kind}>{t.unrecordedRow(u.kind, u.imageCount)}</li>
          ))}
        </ReportList>
      )}
      {report.unstampedCredentials.length > 0 && (
        <ReportList title={t.unstampedTitle}>
          {report.unstampedCredentials.map((u) => (
            <li key={u.imageId}>{t.unstampedRow(u.filename, u.rows)}</li>
          ))}
        </ReportList>
      )}
      {report.notReconciled.length > 0 && (
        <ReportList title={t.notReconciledTitle} sub={t.notReconciledSub}>
          {report.notReconciled.map((n) => (
            <li key={n.table}>
              <span className="mono" style={{ fontSize: 12 }}>
                {n.table}
              </span>{' '}
              — {n.reason}
            </li>
          ))}
        </ReportList>
      )}
    </div>
  );
}

function ReportList({ title, sub, children }: { title: string; sub?: string; children: ReactNode }): JSX.Element {
  return (
    <div style={{ marginTop: 14, maxWidth: '72ch' }}>
      <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{title}</div>
      {sub ? <div className="panel-sub">{sub}</div> : null}
      <ul style={{ margin: '6px 0 0', paddingLeft: 18, lineHeight: 1.5 }}>{children}</ul>
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
