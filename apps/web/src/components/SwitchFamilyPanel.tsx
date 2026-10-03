/** Static leads only: show provider verdicts verbatim, with distinct lane coverage and optional saved fields. */
import { type JSX, useEffect, useRef, useState } from 'react';
import { type SwitchFamilyAnalysis, type SwitchFamilyEvidence, type SwitchFamilyFile, api } from '../api';
import { messages, useMessages } from '../i18n';

const prose = { maxWidth: '72ch', overflowWrap: 'anywhere' as const };
const stack = { display: 'grid', gap: 12, minWidth: 0 };

function Metrics({ rows }: { rows: [string, number | undefined][] }): JSX.Element {
  const m = useMessages().switchFamily;
  return (
    <dl
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 180px), 1fr))',
        gap: 12,
        margin: 0,
      }}
    >
      {rows.map(([label, value]) => (
        <div key={label} style={{ minWidth: 0 }}>
          <dt className="stat-label">{label}</dt>
          <dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{value ?? m.notRecorded}</dd>
        </div>
      ))}
    </dl>
  );
}

function Evidence({ rows }: { rows: SwitchFamilyEvidence[] }): JSX.Element {
  const m = useMessages().switchFamily;
  const [page, setPage] = useState(0);
  const start = Math.min(page * 20, Math.max(0, Math.floor((rows.length - 1) / 20) * 20));
  return (
    <details>
      <summary>
        {m.evidence} ({rows.length})
      </summary>
      <p className="hint" style={prose}>
        {m.evidencePage(rows.length ? start + 1 : 0, Math.min(start + 20, rows.length), rows.length)}
      </p>
      <ol start={start + 1} style={{ ...stack, paddingInlineStart: 24 }}>
        {rows.slice(start, start + 20).map((hit, index) => (
          <li key={`${hit.lane}:${hit.path}:${hit.offset}:${start + index}`} style={{ ...prose, minWidth: 0 }}>
            <div>
              <strong>{m.lane}:</strong> {hit.lane ? m[hit.lane] : m.notRecorded}
            </div>
            <div>
              <strong>{m.path}:</strong>{' '}
              <code style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{hit.path ?? m.notRecorded}</code>
            </div>
            <div>
              <strong>{m.offset}:</strong>{' '}
              {typeof hit.offset === 'number' ? `0x${hit.offset.toString(16)}` : m.notRecorded}
            </div>
            <div>
              <strong>{m.context}:</strong>{' '}
              <code style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                {hit.context ?? hit.matchedText ?? m.notRecorded}
              </code>
            </div>
          </li>
        ))}
      </ol>
      {rows.length > 20 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          <button
            type="button"
            className="btn btn-sm"
            disabled={start === 0}
            onClick={() => setPage(Math.max(0, page - 1))}
          >
            {m.previous}
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={start + 20 >= rows.length}
            onClick={() => setPage(page + 1)}
          >
            {m.next}
          </button>
        </div>
      )}
    </details>
  );
}

function FileCoverage({ file }: { file: SwitchFamilyFile }): JSX.Element {
  const m = useMessages().switchFamily;
  const coverage = file.result?.coverage;
  return (
    <div style={stack}>
      <strong style={prose}>{file.path ?? m.notRecorded}</strong>
      <Metrics
        rows={[
          [m.bytesScanned, coverage?.bytesScanned],
          [m.bytesTotal, file.fileBytes],
          [m.maxScanBytes, coverage?.maxScanBytes],
          [m.maxHits, coverage?.maxHitsPerRule],
          [m.unresolved, coverage?.edgeUnresolved],
        ]}
      />
      <p className="hint" style={prose}>
        {coverage?.statement ?? m.notRecorded}
      </p>
      {!!coverage?.recordsDropped?.length && (
        <ul style={prose}>
          {coverage.recordsDropped.map((drop, index) => (
            <li key={`${drop.ruleId}:${index}`}>
              {m.recordsDropped}: {drop.ruleId ?? m.notRecorded} — {drop.dropped ?? m.notRecorded}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Keyed per image so a late response from a previous image cannot overwrite the next panel's state. */
export function SwitchFamilyPanel({ imageId }: { imageId: string }): JSX.Element {
  return <SwitchFamilyView key={imageId} imageId={imageId} />;
}

function SwitchFamilyView({ imageId }: { imageId: string }): JSX.Element {
  const m = useMessages().switchFamily;
  const [result, setResult] = useState<SwitchFamilyAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => {
    const current = ++generation.current;
    api
      .switchFamilyResult(imageId)
      .then((saved) => {
        if (generation.current === current) setResult(saved);
      })
      .catch(() => {
        if (generation.current === current) setError(messages().switchFamily.loadFailed);
      })
      .finally(() => {
        if (generation.current === current) setLoading(false);
      });
    return () => {
      generation.current++;
      clearTimeout(timer.current);
    };
  }, [imageId]);

  const run = async () => {
    const current = generation.current;
    setBusy(true);
    setError(null);
    const fail = (cause: unknown) => {
      if (generation.current !== current) return;
      setError(cause instanceof Error ? cause.message : m.failed);
      setBusy(false);
    };
    try {
      const { jobId } = await api.runSwitchFamily(imageId);
      if (generation.current !== current) return;
      const poll = async (): Promise<void> => {
        try {
          const job = await api.job(jobId);
          if (generation.current !== current) return;
          if (job.status === 'done') {
            const saved = await api.switchFamilyResult(imageId);
            if (generation.current !== current) return;
            setResult(saved);
            setBusy(false);
          } else if (job.status === 'error' || job.status === 'cancelled') {
            fail(new Error(job.status === 'cancelled' ? m.cancelled : (job.error ?? m.failed)));
          } else {
            timer.current = setTimeout(() => void poll(), 900);
          }
        } catch (cause) {
          fail(cause);
        }
      };
      await poll();
    } catch (cause) {
      fail(cause);
    }
  };

  const overall = result?.overall;
  const coverage = result?.rootfs?.coverage;
  const limits = coverage?.limits;
  return (
    <section className="panel" aria-label={m.title} style={{ minWidth: 0 }}>
      <div className="panel-head" style={{ flexWrap: 'wrap', gap: 12 }}>
        <h2 className="panel-title">{m.title}</h2>
        <button type="button" className="btn btn-sm" onClick={() => void run()} disabled={loading || busy}>
          {busy ? m.running : result ? m.rerun : m.run}
        </button>
      </div>
      <p className="panel-sub" style={prose}>
        {m.intro}
      </p>
      {loading && <output>{m.loading}</output>}
      {error && (
        <p role="alert" className="hint" style={prose}>
          {error}
        </p>
      )}
      {!loading && !result && !error && (
        <p className="hint" style={prose}>
          {m.empty}
        </p>
      )}
      {result && (
        <div style={stack}>
          <div>
            <p className="hint">{m.latest}</p>
            <h3>
              {m.overall}: {overall?.verdict ? (m.verdict[overall.verdict] ?? overall.verdict) : m.notRecorded}
            </h3>
            <p style={prose}>{overall?.summary ?? m.notRecorded}</p>
          </div>
          <div
            style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 300px), 1fr))', gap: 20 }}
          >
            {(['raw', 'rootfs'] as const).map((lane) => {
              const read = result[lane];
              return (
                <section key={lane} aria-label={m[lane]} style={{ ...stack, alignContent: 'start' }}>
                  <h3>
                    {m[lane]} — {read?.status ? (m.status[read.status] ?? read.status) : m.notRecorded}
                  </h3>
                  <p style={prose}>{read?.reason ?? m.notRecorded}</p>
                  {read?.result?.verdict && <span>{m.verdict[read.result.verdict] ?? read.result.verdict}</span>}
                  {lane === 'raw' && result.raw?.file && <FileCoverage file={result.raw.file} />}
                  {/* A lane that never ran, or failed before examining a file, has no coverage: zero counts would read as
                      "examined, found nothing". Its reason above is the whole account. */}
                  {lane === 'rootfs' &&
                    read?.status !== 'not-run' &&
                    !(read?.status === 'error' && !coverage?.filesExamined) && (
                      <>
                        <h4>{m.coverage}</h4>
                        <Metrics
                          rows={[
                            [m.filesExamined, coverage?.filesExamined],
                            [m.filesDiscovered, coverage?.filesDiscovered],
                            [m.filesSkipped, coverage?.filesSkipped],
                            [m.filesTruncated, coverage?.filesTruncated],
                            [m.bytesScanned, coverage?.bytesScanned],
                            [m.links, coverage?.symlinksSkipped],
                            [m.special, coverage?.specialFilesSkipped],
                            [m.entries, coverage?.entriesExamined],
                          ]}
                        />
                        <p className="hint" style={prose}>
                          {coverage?.inventoryComplete === true
                            ? m.completeInventory
                            : coverage?.inventoryComplete === false
                              ? m.incompleteInventory
                              : m.notRecorded}
                        </p>
                        {coverage?.fileResultsSelection !== undefined && (
                          <>
                            <Metrics
                              rows={[
                                [m.fileResultsRetained, coverage.fileResultsRetained],
                                [m.fileResultsOmitted, coverage.fileResultsOmitted],
                              ]}
                            />
                            <p className="hint" style={prose}>
                              {coverage.fileResultsSelection}
                            </p>
                          </>
                        )}
                        <details>
                          <summary>{m.limits}</summary>
                          <p style={prose}>{coverage?.selection ?? m.notRecorded}</p>
                          <Metrics
                            rows={[
                              [m.maxFiles, limits?.maxFiles],
                              [m.maxBytesPerFile, limits?.maxBytesPerFile],
                              [m.maxTotalBytes, limits?.maxTotalBytes],
                              [m.maxEntries, limits?.maxEntries],
                            ]}
                          />
                        </details>
                        {!!result.rootfs?.files?.length && (
                          <details>
                            <summary>{m.fileCoverage}</summary>
                            <div style={stack}>
                              {result.rootfs.files.map((file, index) => (
                                <details key={`${file.path}:${index}`}>
                                  <summary style={prose}>{file.path ?? m.notRecorded}</summary>
                                  <FileCoverage file={file} />
                                </details>
                              ))}
                            </div>
                          </details>
                        )}
                        {!!coverage?.errors?.length && (
                          <details>
                            <summary>
                              {m.errors} ({coverage.errors.length})
                            </summary>
                            <ul style={prose}>
                              {coverage.errors.map((failure, index) => (
                                <li key={`${failure.path}:${index}`}>
                                  {failure.path ?? m.notRecorded}: {failure.reason ?? m.notRecorded}
                                </li>
                              ))}
                            </ul>
                          </details>
                        )}
                      </>
                    )}
                </section>
              );
            })}
          </div>
          <section aria-label={m.candidates} style={stack}>
            <h3>{m.candidates}</h3>
            {overall?.candidates === undefined ? (
              <p>{m.notRecorded}</p>
            ) : overall.candidates.length === 0 ? (
              <p style={prose}>{m.noCandidates}</p>
            ) : (
              overall.candidates.map((candidate, index) => (
                <article
                  key={`${candidate.family}:${index}`}
                  style={{ ...stack, borderTop: '1px solid var(--border)', paddingTop: 12 }}
                >
                  <h4>{candidate.family ?? m.notRecorded}</h4>
                  <div>
                    {m.standing}:{' '}
                    <code>
                      {candidate.standing ? (m.standingValue[candidate.standing] ?? candidate.standing) : m.notRecorded}
                    </code>
                  </div>
                  <div style={prose}>
                    {m.tokens}: {(candidate.distinctTokens ?? []).join(', ') || m.notRecorded}
                  </div>
                  <div>
                    {m.hits}: {candidate.hitCount ?? m.notRecorded}
                  </div>
                  {candidate.evidence ? (
                    <Evidence rows={candidate.evidence} />
                  ) : (
                    <p>
                      {m.evidence}: {m.notRecorded}
                    </p>
                  )}
                </article>
              ))
            )}
          </section>
          <section aria-label={m.vendors}>
            <h3>{m.vendors}</h3>
            <p style={prose}>{m.vendorNote}</p>
            {overall?.vendorMentions === undefined ? (
              <p>{m.notRecorded}</p>
            ) : overall.vendorMentions.length === 0 ? (
              <p>{m.noVendors}</p>
            ) : (
              <ul>
                {overall.vendorMentions.map((vendor, index) => (
                  <li key={`${vendor.vendor}:${index}`} style={prose}>
                    {vendor.vendor ?? m.notRecorded} — {m.hits}: {vendor.count ?? m.notRecorded}
                  </li>
                ))}
              </ul>
            )}
          </section>
          <details>
            <summary>{m.deferred}</summary>
            {overall?.deferred?.length ? (
              <ul style={prose}>
                {overall.deferred.map((item, index) => (
                  <li key={`${item.what}:${index}`}>
                    <strong>{item.what ?? m.notRecorded}</strong>: {item.reason ?? m.notRecorded}
                  </li>
                ))}
              </ul>
            ) : (
              <p>{m.noDeferred}</p>
            )}
          </details>
        </div>
      )}
    </section>
  );
}
