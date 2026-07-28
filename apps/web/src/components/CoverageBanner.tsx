/**
 * CoverageBanner — the answer to the question a findings list silently begs: *does this number mean anything?*
 *
 * An empty findings list looks the same whether every applicable stage ran and found nothing, or extraction never
 * recovered a rootfs and most of the pipeline was skipped. Those are opposite conclusions. This states which one it
 * is, in one sentence, above the findings — and lists the stages this firmware's class routes to with what actually
 * happened to each, so "what can I even run on this image?" is answered up front rather than discovered by clicking.
 *
 * The reading is computed server-side (`GET /images/:id/coverage`) from the same class plan the autonomous scan
 * executes, so this can never claim coverage the scan disagrees with.
 *
 * The verdict, the class rationale and each stage's reason arrive from the API and are printed as it states them:
 * they are the record of what this deployment measured, not interface copy. What IS localised is the status badge,
 * and that is the part with a trap in it — `not-run` and `ran-empty` produce the same empty findings list and are
 * opposite conclusions, so neither label may read as the other in any language (the `coverage` namespace).
 */
import { useEffect, useState } from 'react';
import { type CoverageReport, type CoverageStage, api } from '../api';
import { useMessages } from '../i18n';

const STATUS_META: Record<CoverageStage['status'], { mark: string; cls: string }> = {
  found: { mark: '✓', cls: 'badge-ok' },
  'ran-empty': { mark: '✓', cls: 'badge' },
  degraded: { mark: '⚠', cls: 'badge-medium' },
  'no-input': { mark: '–', cls: 'badge-medium' },
  'not-built': { mark: '▢', cls: 'badge' },
  'not-run': { mark: '○', cls: 'badge' },
};

export function CoverageBanner({ imageId }: { imageId: string }): JSX.Element | null {
  const t = useMessages();
  const [report, setReport] = useState<CoverageReport | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let alive = true;
    api
      .coverage(imageId)
      .then((r) => alive && setReport(r))
      .catch(() => alive && setReport(null));
    return () => {
      alive = false;
    };
  }, [imageId]);

  if (!report) return null;

  return (
    <div className={`banner ${report.ambiguous ? 'banner-warn' : ''}`} style={{ marginBottom: 16 }}>
      <div>
        <span className="eyebrow">{t.coverage.eyebrow(report.firmwareClass)}</span>
        <p style={{ margin: '4px 0 0' }}>{report.verdict}</p>
        {report.classRationale ? <p className="hint">{report.classRationale}</p> : null}
        {/* The verdict already names them; this states the arithmetic explicitly, because a reader who sees more
            rows in the findings table than the count admits will otherwise assume the count is simply wrong. */}
        {report.operatorAssertions ? (
          <p className="hint">{t.coverage.assertions(report.findingCount, report.operatorAssertions)}</p>
        ) : null}
      </div>

      <button
        type="button"
        className="btn btn-sm"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        style={{ marginTop: 8 }}
      >
        {open ? t.coverage.hide : t.coverage.whatCanRun(report.executed, report.applicable)}
      </button>

      {open ? (
        <div className="table-wrap" style={{ marginTop: 12 }}>
          <table className="data">
            <tbody>
              {report.stages.map((s) => {
                const meta = STATUS_META[s.status];
                return (
                  <tr key={s.worker}>
                    <td style={{ width: '1%', whiteSpace: 'nowrap' }}>
                      <span className={`badge ${meta.cls} mono`}>
                        {meta.mark} {t.coverage.status[s.status]}
                      </span>
                    </td>
                    <td>
                      <div className="mono">{s.worker}</div>
                      {/* The reason is what this stage COULD tell you — the part a bare status hides. */}
                      <div className="hint">{s.detail ?? s.reason}</div>
                    </td>
                    <td className="num" style={{ textAlign: 'right' }}>
                      {s.findingCount !== undefined ? s.findingCount : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
