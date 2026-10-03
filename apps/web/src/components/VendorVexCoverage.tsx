/**
 * Search coverage is evidence independent of findings. Only a recorded attempt can report counts; missing fields
 * stay unknown. Provider prose, refusal codes and bounded examples render verbatim, including future counters.
 */
import type { VendorVexSearchSummary } from '../api';
import { useMessages } from '../i18n';

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}
function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
function count(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}
function records(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(record) : [];
}
function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

export function vendorVexSearchState(value: unknown): 'attempted' | 'not-attempted' | 'not-recorded' {
  const attempted = record(value).attempted;
  return attempted === true ? 'attempted' : attempted === false ? 'not-attempted' : 'not-recorded';
}

export function VendorVexCoverage({
  vex,
  kernel = false,
}: { vex?: VendorVexSearchSummary | undefined; kernel?: boolean }): JSX.Element {
  const k = useMessages().kernelPosture.vendorVex;
  const state = vendorVexSearchState(vex);
  const v = record(vex);
  const n = (value: unknown) => count(value) ?? k.unknown;
  if (state === 'not-recorded') return <p className="hint vendor-vex-coverage">{k.notRecorded}</p>;
  if (state === 'not-attempted') {
    return (
      <section className="vendor-vex-coverage" aria-label={k.heading}>
        <div className="eyebrow">{k.heading}</div>
        <p className="hint">{k.notAttempted(text(v.notAttemptedReason) ?? k.reasonUnknown)}</p>
      </section>
    );
  }
  const documents = records(v.documents);
  const refusals = records(v.refusals);
  const caps = record(v.caps);
  const bounds = [
    (count(v.droppedByFileCap) ?? 0) > 0 ? k.droppedFiles(n(v.droppedByFileCap), n(caps.maxFiles)) : null,
    (count(v.droppedByByteCap) ?? 0) > 0 ? k.droppedBytes(n(v.droppedByByteCap)) : null,
    v.walkTruncated === true ? k.walkTruncated(n(v.entriesVisited)) : null,
    (count(v.symlinksSkipped) ?? 0) > 0 ? k.symlinks(n(v.symlinksSkipped)) : null,
  ].filter((line): line is string => line !== null);
  const omissionLabels: Record<string, string> = {
    droppedStatementsCount: k.droppedStatements,
    droppedProductsCount: k.droppedProducts,
    ignoredNonCveCount: k.ignoredNonCve,
    unrecognisedStatusCount: k.unrecognisedStatus,
    unreadStructureCount: k.unreadStructures,
  };
  return (
    <section className="vendor-vex-coverage" aria-label={k.heading}>
      <div className="eyebrow">{k.heading}</div>
      <p>{k.counts(n(v.candidatesFound), n(v.examined), n(v.parsed), n(v.refused))}</p>
      {count(v.candidatesFound) === 0 && (
        <p className="hint">
          {count(v.entriesVisited) === 0 ? k.nothingRead : kernel ? k.noneMatched : k.noneMatchedFirmware}
        </p>
      )}
      {text(v.statement) && <p className="hint">{text(v.statement)}</p>}
      <p className="hint">{k.walk(n(v.entriesVisited), n(v.bytesRead))}</p>
      {text(v.rule) && (
        <p className="hint">
          {k.rule}: {text(v.rule)}
        </p>
      )}
      {text(v.selectionRule) && (
        <p className="hint">
          {k.selectionRule}: {text(v.selectionRule)}
        </p>
      )}
      {Object.keys(caps).length > 0 && (
        <p className="hint">
          {k.caps(n(caps.maxFiles), n(caps.maxTotalBytes), n(caps.maxDocumentBytes), n(caps.maxEntries))}
        </p>
      )}
      {bounds.length > 0 && (
        <ul className="hint">
          {bounds.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
      {count(v.unreadableDirectories) !== undefined && (
        <p className="hint">{k.unreadable(n(v.unreadableDirectories))}</p>
      )}
      {strings(v.unreadableDirectoryPaths).length > 0 && (
        <ul className="hint">
          {strings(v.unreadableDirectoryPaths).map((path, i) => (
            <li key={`${path}-${i}`} className="mono">
              {path}
            </li>
          ))}
        </ul>
      )}
      {count(v.unmatchableIdentities) !== undefined && (
        <p className="hint">{k.unmatchable(n(v.unmatchableIdentities))}</p>
      )}
      {records(v.unmatchableIdentityExamples).length > 0 && (
        <ul className="hint">
          {records(v.unmatchableIdentityExamples).map((example, i) => (
            <li key={`${text(example.sourcePath)}-${i}`}>
              <span className="mono">
                {text(example.sourcePath) ?? '?'} — {text(example.identity) ?? '?'}
              </span>
              : {text(example.reason) ?? k.reasonUnknown}
            </li>
          ))}
        </ul>
      )}
      {documents.length > 0 && (
        <div className="hint">
          {k.parsedHeading}
          <ul>
            {documents.map((d, i) => (
              <li key={`${text(d.path)}-${i}`}>
                <div className="mono">{k.document(text(d.path) ?? '?', text(d.format) ?? '?', n(d.statements))}</div>
                {Object.entries(d)
                  .filter(([key, value]) => key.endsWith('Count') && count(value) !== undefined)
                  .map(([key, value]) => (
                    <div key={key}>
                      {omissionLabels[key] ?? k.otherCounter(key)}: {n(value)}
                    </div>
                  ))}
                {text(d.boundsRule) && (
                  <div>
                    {k.documentBounds}: {text(d.boundsRule)}
                  </div>
                )}
                {text(d.author) && (
                  <div>
                    {k.author}: {text(d.author)}
                  </div>
                )}
                {text(d.timestamp) && (
                  <div>
                    {k.timestamp}: {text(d.timestamp)}
                  </div>
                )}
                {records(d.unrecognisedStatusExamples).map((example, j) => (
                  <div key={`${text(example.vulnerabilityId)}-${j}`} className="mono">
                    {text(example.vulnerabilityId) ?? '?'} — {text(example.status) ?? '?'}
                  </div>
                ))}
                {records(d.unreadStructureExamples).map((example, j) => (
                  <div key={`unread-${text(example.vulnerabilityId)}-${j}`} className="mono">
                    {text(example.vulnerabilityId) ?? '?'} — {text(example.kind) ?? '?'}
                    {text(example.reference) ? ` — ${text(example.reference)}` : ''}
                  </div>
                ))}
                {text(d.unreadStructureRule) && (
                  <div>
                    {k.unreadStructureRule}: {text(d.unreadStructureRule)}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {refusals.length > 0 && (
        <div className="hint">
          {k.refusedHeading}
          <ul>
            {refusals.map((r, i) => (
              <li key={`${text(r.path)}-${i}`}>
                <span className="mono">{text(r.path) ?? '?'}</span> —{' '}
                <span className="mono">{text(r.reason) ?? '?'}</span>
                {text(r.message) ? `: ${text(r.message)}` : ''}
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="hint">{k.assertion}</p>
    </section>
  );
}
