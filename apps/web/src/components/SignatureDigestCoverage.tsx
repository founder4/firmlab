/**
 * Present persisted, bounded digest work without reconstructing coverage from signature rows. New result
 * fields stay optional forever: old, partial or malformed JSON is uncertainty, never an invented zero.
 * Counts describe listed supported MediaTek BootROM hits, not all signatures, firmware bytes or proof states.
 */
import { useId } from 'react';
import { useMessages } from '../i18n';

export const DIGEST_COUNT_FIELDS = [
  'listed',
  'planned',
  'attempted',
  'completed',
  'matched',
  'mismatched',
  'unavailable',
  'invalidCandidates',
  'skipped',
  'skippedExecutionBudget',
  'skippedByteBudget',
  'bytesPlanned',
  'bytesSubmitted',
  'bytesCompleted',
  'maxExecutions',
  'maxBytes',
] as const;
export type DigestCountField = (typeof DIGEST_COUNT_FIELDS)[number];
export interface DigestCoveragePresentation {
  state: 'not-recorded' | 'unknown' | 'partial' | 'recorded';
  counts: Record<DigestCountField, number | null>;
  capability: 'provided' | 'unavailable' | null;
  note: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Read fields independently; keep valid raw counts even when the surrounding record is incomplete. */
export function presentSignatureDigestCoverage(value: unknown): DigestCoveragePresentation {
  const counts = Object.fromEntries(DIGEST_COUNT_FIELDS.map((key) => [key, null])) as Record<
    DigestCountField,
    number | null
  >;
  const empty = { counts, capability: null, note: null };
  if (value === undefined) return { ...empty, state: 'not-recorded' };
  if (!isRecord(value) || value.scope !== 'listed_mediatek_brom_hits') return { ...empty, state: 'unknown' };
  for (const key of DIGEST_COUNT_FIELDS) {
    const n = value[key];
    if (typeof n === 'number' && Number.isSafeInteger(n) && n >= 0) counts[key] = n;
  }
  // A recorded applied limit cannot exceed the core's hard ceilings. Never clamp it into plausible data.
  if (counts.maxExecutions !== null && counts.maxExecutions > 8) counts.maxExecutions = null;
  if (counts.maxBytes !== null && counts.maxBytes > 67_108_864) counts.maxBytes = null;
  const capability = value.capability === 'provided' || value.capability === 'unavailable' ? value.capability : null;
  const note = typeof value.note === 'string' ? value.note : null;
  const allPresent = DIGEST_COUNT_FIELDS.every((key) => counts[key] !== null) && capability !== null && note !== null;
  let consistent = true;
  if (allPresent) {
    // Only validate a complete record; do not derive missing counts or infer completion from capability.
    const n = counts as Record<DigestCountField, number>;
    consistent =
      n.listed === n.planned + n.invalidCandidates &&
      n.planned === n.completed + n.unavailable + n.skipped &&
      n.completed === n.matched + n.mismatched &&
      n.skipped === n.skippedExecutionBudget + n.skippedByteBudget &&
      n.completed <= n.attempted &&
      n.attempted <= n.completed + n.unavailable &&
      n.attempted <= n.maxExecutions &&
      n.bytesCompleted <= n.bytesSubmitted &&
      n.bytesSubmitted <= n.bytesPlanned &&
      n.bytesSubmitted <= n.maxBytes &&
      (n.planned !== 0 || n.bytesPlanned === 0) &&
      (n.attempted !== 0 || n.bytesSubmitted === 0) &&
      (n.completed !== 0 || n.bytesCompleted === 0) &&
      (capability !== 'unavailable' || (n.attempted === 0 && n.completed === 0 && n.skipped === 0));
  }
  return { counts, capability, note, state: allPresent && consistent ? 'recorded' : 'partial' };
}

const SUMMARY_FIELDS = DIGEST_COUNT_FIELDS.slice(0, 9);
const DETAIL_FIELDS = DIGEST_COUNT_FIELDS.slice(9);

export function SignatureDigestCoverage({ coverage }: { coverage?: unknown }): JSX.Element {
  const t = useMessages().imageDetail.signatureDigests;
  const headingId = useId();
  const view = presentSignatureDigestCoverage(coverage);
  const metrics = (fields: readonly DigestCountField[]) => (
    <dl className="signature-digest-counts">
      {fields.map((key) => (
        <div key={key}>
          <dt>{t.labels[key]}</dt>
          <dd>{view.counts[key] === null ? t.unknown : String(view.counts[key])}</dd>
        </div>
      ))}
    </dl>
  );
  return (
    <section className="signature-digest-coverage" aria-labelledby={headingId}>
      <h3 id={headingId}>{t.title}</h3>
      <p>{t.scope}</p>
      {view.state !== 'recorded' && <p>{t.state[view.state]}</p>}
      {(view.state === 'recorded' || view.state === 'partial') && (
        <>
          {metrics(SUMMARY_FIELDS)}
          <p>{t.resultsMeaning}</p>
          <details>
            <summary>{t.details}</summary>
            <p>{t.capability[view.capability ?? 'unknown']}</p>
            {metrics(DETAIL_FIELDS)}
            <p>{t.budget}</p>
            <p>{t.submittedMeaning}</p>
            {view.note !== null && (
              <div className="signature-digest-provider-note">
                <h4>{t.providerNote}</h4>
                <p>{view.note}</p>
              </div>
            )}
          </details>
        </>
      )}
      <p>{t.caveat}</p>
    </section>
  );
}
