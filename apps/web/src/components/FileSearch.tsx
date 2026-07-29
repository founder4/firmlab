/**
 * Content search over the extraction — "which file says this".
 *
 * The panel is built around the verdict, not the hit list. A result renders its coverage sentence FIRST and
 * always, including on a clean complete search, because the sentence is what tells a reader whether an empty
 * list is a negative or a hole. Hiding it when everything went well would train people not to look for it in the
 * one case that matters, which is how a caveat becomes decoration.
 *
 * A hit in a binary is labelled and carries a byte offset instead of a line number, because a line number in an
 * ELF is a fiction and presenting one would send an analyst to a place that does not exist.
 *
 * The two empty-result sentences are the whole point of the panel and live in the `files` namespace so they survive
 * translation: only a COMPLETE search is allowed to say "no file in this extraction contains that term", and a
 * partial one says "no match in what was searched", which is not the same as absent from this firmware. The
 * verdict itself is composed by the API from what it actually opened and is rendered as written.
 */
import { type FormEvent, useCallback, useState } from 'react';
import { type FilesSearch, api } from '../api';
import { useMessages } from '../i18n';

/** True when the search opened every file and capped nothing — the only case an empty result is a real negative. */
export function isCompleteSearch(s: FilesSearch | null): boolean {
  const c = s?.coverage;
  if (!c) return false;
  const sk = c.skipped ?? {};
  const holes = (sk.tooLarge ?? 0) + (sk.unreadable ?? 0) + (sk.budgetExhausted ?? 0);
  return holes === 0 && !c.walkTruncated && !c.hitCapReached;
}

/**
 * What the search actually opened, and what it did not.
 *
 * `isCompleteSearch` collapses all of this into one boolean, which is the right verdict and the wrong amount of
 * information: an operator deciding whether an empty result is a real negative needs to know WHICH hole it has —
 * ten files too large is a different next action from a walk that was truncated. The denominator is always shown
 * because a hole is only readable against one.
 */
function SearchCoverage({ coverage }: { coverage: FilesSearch['coverage'] }): JSX.Element | null {
  const t = useMessages();
  if (!coverage) return null;
  const sk = coverage.skipped ?? {};
  const holes: string[] = [];
  if (sk.tooLarge) holes.push(t.files.search.cov.tooLarge(sk.tooLarge));
  if (sk.unreadable) holes.push(t.files.search.cov.unreadable(sk.unreadable));
  if (sk.budgetExhausted) holes.push(t.files.search.cov.budget(sk.budgetExhausted));
  if (coverage.walkTruncated) holes.push(t.files.search.cov.walkTruncated);
  if (coverage.hitCapReached) holes.push(t.files.search.cov.hitCap);

  return (
    <div className="hint mono" style={{ marginTop: 6, fontSize: 11.5 }}>
      {t.files.search.cov.examined(coverage.filesExamined ?? 0, coverage.entriesWalked ?? 0)}
      {holes.length > 0 && <span style={{ color: 'var(--sev-medium, #e6b45c)' }}> · {holes.join(' · ')}</span>}
    </div>
  );
}

export function FileSearch({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const [q, setQ] = useState('');
  const [regex, setRegex] = useState(false);
  const [deep, setDeep] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<FilesSearch | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      if (!q.trim()) return;
      setBusy(true);
      setError(null);
      setResult(null);
      try {
        setResult(await api.searchFiles(imageId, q, regex, deep));
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setBusy(false);
      }
    },
    [imageId, q, regex, deep],
  );

  const hits = result?.hits ?? [];
  const complete = isCompleteSearch(result);

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">{t.files.search.title}</div>
      <div className="panel-sub">{t.files.search.sub}</div>

      <form onSubmit={run} style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
        <input
          className="mono fsq-input"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="updates.vendor.example"
          aria-label={t.files.search.termLabel}
        />
        <label className="hint" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" checked={regex} onChange={(e) => setRegex(e.target.checked)} />
          {/* `regex` is the term of art in both languages. */}
          regex
        </label>
        {/* Without this the GL.iNet can never return a complete search: 10 of its files exceed the default cap,
            so every answer there carries a permanent hole. Slower, and the operator chooses when to pay. */}
        <label className="hint" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} />
          {t.files.search.deep}
        </label>
        <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !q.trim()}>
          {busy ? <span className="spinner" /> : t.common.search}
        </button>
      </form>

      {error && (
        <div className="banner banner-warn" style={{ marginTop: 10 }}>
          {error}
        </div>
      )}

      {result && (
        <>
          {/* The verdict leads and is never conditional on something having gone wrong. */}
          <div className={`fsq-verdict ${complete ? 'fsq-complete' : 'fsq-partial'}`}>
            <span className="eyebrow">{complete ? t.files.search.complete : t.files.search.partial}</span>
            <p className="hint" style={{ margin: '4px 0 0' }}>
              {result.verdict ?? t.files.search.noVerdict}
            </p>
            {/* The NUMBERS behind the verdict. They were collected, reduced to one boolean by `isCompleteSearch`,
                and thrown away — so "3 files were unreadable" and "0 were" rendered identically, which is exactly
                the shape where a bound reads as an answer. Only the non-zero holes are listed: a row of zeros
                would bury the one count that matters. */}
            <SearchCoverage coverage={result.coverage} />
          </div>

          {hits.length === 0 ? (
            <p className="hint" style={{ marginTop: 10 }}>
              {complete ? t.files.search.noneComplete : t.files.search.nonePartial}
            </p>
          ) : (
            <div style={{ overflowX: 'auto', marginTop: 10 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th>{t.files.search.file}</th>
                    <th className="num">{t.files.search.at}</th>
                    <th>{t.files.search.match}</th>
                  </tr>
                </thead>
                <tbody>
                  {hits.map((h) => (
                    <tr key={`${h.path}-${h.offset}`}>
                      <td className="mono">
                        {h.path}
                        {h.binary && (
                          <span className="badge" style={{ marginLeft: 6 }}>
                            {t.files.search.binary}
                          </span>
                        )}
                      </td>
                      <td className="num mono">
                        {h.line !== undefined ? `:${h.line}` : `0x${(h.offset ?? 0).toString(16)}`}
                      </td>
                      <td className="mono fsq-excerpt">{h.excerpt}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
