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
 */
import { useEffect, useState } from 'react';
import { type CoverageReport, type CoverageStage, api } from '../api';

const STATUS_META: Record<CoverageStage['status'], { mark: string; cls: string; label: string }> = {
  found: { mark: '✓', cls: 'badge-ok', label: 'found' },
  'ran-empty': { mark: '✓', cls: 'badge', label: 'ran · nothing' },
  degraded: { mark: '⚠', cls: 'badge-medium', label: 'degraded' },
  'no-input': { mark: '–', cls: 'badge-medium', label: 'no input' },
  'not-built': { mark: '▢', cls: 'badge', label: 'not built' },
  'not-run': { mark: '○', cls: 'badge', label: 'not run' },
};

export function CoverageBanner({ imageId }: { imageId: string }): JSX.Element | null {
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
        <span className="eyebrow">Coverage · {report.firmwareClass}</span>
        <p style={{ margin: '4px 0 0' }}>{report.verdict}</p>
        {report.classRationale ? <p className="hint">{report.classRationale}</p> : null}
      </div>

      <button
        type="button"
        className="btn btn-sm"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        style={{ marginTop: 8 }}
      >
        {open ? 'Hide' : `What can run on this image? (${report.executed}/${report.applicable})`}
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
                        {meta.mark} {meta.label}
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
