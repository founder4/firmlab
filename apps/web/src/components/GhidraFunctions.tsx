/**
 * A saved decompilation is a bounded reconstruction, not a finding or a complete source listing.
 * Keep it readable even when a persisted run predates totals, or one function produced no text.
 */
import { type JSX, useState } from 'react';
import type { GhidraResult } from '../api';
import { useMessages } from '../i18n';

export function GhidraFunctions({ result }: { result: GhidraResult }): JSX.Element {
  const t = useMessages().capabilities.ghidra;
  const [index, setIndex] = useState(0);
  const functions = (result.functions ?? []).slice(0, 40);
  const fn = functions[index] ?? functions[0];
  const code = fn?.pseudocode ?? '';
  return (
    <div className="code-reader" data-testid="ghidra-functions">
      <h3 className="panel-title">{t.functionsTitle}</h3>
      <p className="hint">{t.reconstruction}</p>
      {functions.length === 0 ? (
        <p className="hint">{t.emptyFunctions}</p>
      ) : (
        <>
          <label>
            {t.selectFunction}
            <select
              className="input mono"
              value={functions[index] ? index : 0}
              onChange={(e) => setIndex(Number(e.target.value))}
            >
              {functions.map((f, i) => (
                <option key={`${i}:${f.name}`} value={i}>
                  {f.name ?? '?'}
                  {f.signature ? ` — ${f.signature}` : ''}
                </option>
              ))}
            </select>
          </label>
          {fn?.signature && <pre className="reader-code mono">{fn.signature.slice(0, 8000)}</pre>}
          {code ? <pre className="reader-code mono">{code.slice(0, 8000)}</pre> : <p className="hint">{t.emptyCode}</p>}
          {code.length >= 8000 && <p className="hint">{t.textBound}</p>}
          {(result.functions?.length ?? 0) > 40 && <p className="hint">{t.listBound}</p>}
        </>
      )}
    </div>
  );
}
