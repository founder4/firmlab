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
 */
import { type FormEvent, useCallback, useState } from 'react';
import { type FilesSearch, api } from '../api';

/** True when the search opened every file and capped nothing — the only case an empty result is a real negative. */
export function isCompleteSearch(s: FilesSearch | null): boolean {
  const c = s?.coverage;
  if (!c) return false;
  const sk = c.skipped ?? {};
  const holes = (sk.tooLarge ?? 0) + (sk.unreadable ?? 0) + (sk.budgetExhausted ?? 0);
  return holes === 0 && !c.walkTruncated && !c.hitCapReached;
}

export function FileSearch({ imageId }: { imageId: string }): JSX.Element {
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
      <div className="panel-title">Search the extraction</div>
      <div className="panel-sub">
        Which file says this — a certificate CN, a hostname, a symbol, an NVRAM key. Binaries are searched too; their
        hits carry a byte offset rather than a line number.
      </div>

      <form onSubmit={run} style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
        <input
          className="mono fsq-input"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="updates.vendor.example"
          aria-label="Search term"
        />
        <label className="hint" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" checked={regex} onChange={(e) => setRegex(e.target.checked)} />
          regex
        </label>
        {/* Without this the GL.iNet can never return a complete search: 10 of its files exceed the default cap,
            so every answer there carries a permanent hole. Slower, and the operator chooses when to pay. */}
        <label className="hint" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} />
          deep (open large files)
        </label>
        <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !q.trim()}>
          {busy ? <span className="spinner" /> : 'Search'}
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
            <span className="eyebrow">{complete ? 'complete search' : 'partial search'}</span>
            <p className="hint" style={{ margin: '4px 0 0' }}>
              {result.verdict ??
                'This result carries no coverage verdict, so how much of the extraction it covered is unknown.'}
            </p>
          </div>

          {hits.length === 0 ? (
            <p className="hint" style={{ marginTop: 10 }}>
              {complete
                ? 'No file in this extraction contains that term.'
                : 'No match in what was searched — which is not the same as absent from this firmware. See above.'}
            </p>
          ) : (
            <div style={{ overflowX: 'auto', marginTop: 10 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th>File</th>
                    <th className="num">At</th>
                    <th>Match</th>
                  </tr>
                </thead>
                <tbody>
                  {hits.map((h) => (
                    <tr key={`${h.path}-${h.offset}`}>
                      <td className="mono">
                        {h.path}
                        {h.binary && (
                          <span className="badge" style={{ marginLeft: 6 }}>
                            binary
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
