/**
 * The kernel-module surface, on a screen.
 *
 * **The header is mostly denominators, and that is the point.** `modulesFound` → `sites` → `chased` are three
 * different numbers and the gaps between them are the coverage story, in a way a row count never is:
 *
 *   - `hoisted` counts sink references where the compiler materialised the sink's ADDRESS and calls it from
 *     somewhere else. Those were deliberately not examined, because the instructions above such a reference are
 *     the function prologue rather than any call's argument setup. On the corpus's MIPS images that is 29% of
 *     all references — a silence big enough that hiding it would misrepresent the pass;
 *   - `modulesDropped` NAMES the eligible modules the budget did not reach, because a count tells a reader
 *     nothing about which ones they are missing;
 *   - `symbolTableUnreadable` is a module whose kernel API could not be read at all, which is distinct from a
 *     module that binds nothing.
 *
 * **The provenance note is rendered whichever way it falls.** On an image where the `intree` tag is absent from
 * every module the tag decides nothing, and the ranking says so out loud rather than quietly ordering by a signal
 * the image does not carry. That is not an edge case here: it is the state of the very image this provider was
 * built for.
 *
 * **`windowOnly` sits above the table for the same reason `leadsOnly` does in `BinVulnPanel`.** A row reading
 * "no comparison appears before the call" is a statement about a fixed window of instructions, and without a
 * sentence in front of it a list of unchecked allocations reads as a list of kernel bugs.
 */
import { type JSX, useEffect, useState } from 'react';
import { type KmodResult, api } from '../api';
import { useMessages } from '../i18n';
import { SEV_COLOR } from './FindingsLedger';

export function KmodPanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const k = t.kmod;
  const [result, setResult] = useState<KmodResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const load = (): void => {
    api
      .kmod(imageId)
      // A client that could not learn otherwise reads as "has not run", never as a rootfs with no weak module.
      .then(setResult)
      .catch(() => setResult(null))
      .finally(() => setLoading(false));
  };
  // Keyed on the image only: `load` is re-created every render and listing it would poll the route.
  useEffect(load, [imageId]);

  const run = async (): Promise<void> => {
    setBusy(true);
    try {
      await api.runKmod(imageId);
    } finally {
      setBusy(false);
      load();
    }
  };

  if (loading) return <div className="skeleton" style={{ height: 160 }} />;

  const runButton = (
    <button type="button" className="btn btn-sm" onClick={run} disabled={busy}>
      {busy ? k.running : result ? k.rerun : k.run}
    </button>
  );

  if (!result || result.available === false) {
    return (
      <div className="panel">
        <div className="panel-title">{k.title}</div>
        <div className="panel-sub" style={{ maxWidth: '72ch' }}>
          {k.sub}
        </div>
        <div className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
          {result ? k.empty.unavailable(result.reason) : k.empty.notRun}
        </div>
        <div style={{ marginTop: 10 }}>{runButton}</div>
      </div>
    );
  }

  const modules = result.modules ?? [];
  const rows = result.findings ?? [];
  const pass = result.callSitePass ?? {};
  const sites = modules.reduce((n, m) => n + (m.sites?.length ?? 0), 0);
  const chased = modules.reduce((n, m) => n + (m.sites ?? []).filter((s) => s.evidence).length, 0);
  const ranked = modules.filter((m) => (m.keys?.score ?? 0) > 0).slice(0, 8);
  const prov = result.provenance ?? {};

  return (
    <div className="panel">
      <div className="panel-title">{k.title}</div>
      <div className="panel-sub" style={{ maxWidth: '72ch' }}>
        {k.sub}
      </div>

      <div style={{ marginTop: 12, display: 'flex', gap: 22, flexWrap: 'wrap', alignItems: 'baseline' }}>
        <Fact label={k.field.modules} value={String(result.modulesFound ?? modules.length)} />
        <Fact label={k.field.examined} value={String(pass.modulesExamined ?? 0)} />
        <Fact label={k.field.sites} value={String(sites)} />
        <Fact label={k.field.chased} value={String(chased)} />
        {pass.sitesHoisted !== undefined && pass.sitesHoisted > 0 && (
          <Fact label={k.field.hoisted} value={String(pass.sitesHoisted)} />
        )}
        {result.symbolTableUnreadable !== undefined && result.symbolTableUnreadable > 0 && (
          <Fact label={k.field.unreadable} value={String(result.symbolTableUnreadable)} />
        )}
      </div>

      {/* The sentence that has to precede the table: every call-site row is bounded by the window it was read in. */}
      <div className="banner banner-warn" style={{ marginTop: 12 }}>
        <div style={{ maxWidth: '72ch' }}>{k.windowOnly}</div>
      </div>

      {/* Which provenance key this image supports — stated in both directions, never assumed. */}
      <div className="hint" style={{ marginTop: 10, maxWidth: '72ch' }}>
        <span className="eyebrow" style={{ marginRight: 6 }}>
          {k.provenance.heading}
        </span>
        {prov.intreeTagInUse ? k.provenance.tagInUse : k.provenance.tagUnused}
        {prov.licenceDeclared === false && ` ${k.provenance.noLicence}`}
      </div>

      {pass.available === false && (
        <div className="hint" style={{ marginTop: 8, maxWidth: '72ch' }}>
          {k.empty.passUnavailable(pass.reason ?? '')}
        </div>
      )}

      {pass.sitesHoisted !== undefined && pass.sitesHoisted > 0 && (
        <div className="hint" style={{ marginTop: 8, maxWidth: '72ch' }}>
          {k.hoistedNote(pass.sitesHoisted)}
        </div>
      )}

      {pass.sitesDropped !== undefined && pass.sitesDropped > 0 && (
        <div className="hint" style={{ marginTop: 8, maxWidth: '72ch' }}>
          {k.sitesDropped(pass.sitesDropped)}
        </div>
      )}

      {pass.modulesDropped && pass.modulesDropped.length > 0 && (
        <div className="hint" style={{ marginTop: 8, maxWidth: '72ch' }}>
          {k.modulesDropped(pass.modulesDropped.length)}
          <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {pass.modulesDropped.map((p) => (
              <li key={p} className="mono" style={{ fontSize: 11.5 }}>
                {p}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* The provider's own sentence, verbatim — it states the counts, the provenance calibration and the rule. */}
      {result.reason && (
        <div className="hint" style={{ marginTop: 10, maxWidth: '72ch' }}>
          {result.reason}
        </div>
      )}

      {ranked.length > 0 && (
        <>
          <div className="eyebrow" style={{ marginTop: 16 }}>
            {k.topRanked}
          </div>
          <div className="table-wrap" style={{ marginTop: 6 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>{k.rankCol.module}</th>
                  <th style={{ width: 110 }}>{k.rankCol.licence}</th>
                  <th style={{ width: 60 }}>{k.rankCol.score}</th>
                  <th>{k.rankCol.api}</th>
                  <th style={{ width: 60 }}>{k.rankCol.sites}</th>
                </tr>
              </thead>
              <tbody>
                {ranked.map((m) => {
                  const version = m.identity?.version ?? m.identity?.versionCandidate?.value;
                  const cats = Object.keys(m.api ?? {});
                  return (
                    <tr key={m.file}>
                      <td className="mono" style={{ fontSize: 11.5 }}>
                        {m.file.split('/').pop()}
                        {version && <span className="hint"> {version}</span>}
                      </td>
                      <td className="hint" style={{ fontSize: 11.5 }}>
                        {m.identity?.license ?? '—'}
                      </td>
                      <td className="mono" style={{ fontSize: 11.5 }}>
                        {m.keys?.score ?? 0}
                      </td>
                      <td className="hint" style={{ fontSize: 11.5 }}>
                        {cats.length > 0 ? cats.join(', ') : '—'}
                      </td>
                      <td className="mono" style={{ fontSize: 11.5 }}>
                        {m.sites?.length ?? 0}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {rows.length === 0 ? (
        <div className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
          {(result.modulesFound ?? modules.length) === 0 ? k.empty.noModules : k.empty.noRows(modules.length)}
        </div>
      ) : (
        <div className="table-wrap" style={{ marginTop: 14 }}>
          <table className="data">
            <thead>
              <tr>
                <th style={{ width: 28 }} />
                <th>{k.col.finding}</th>
                <th style={{ width: 210 }}>{k.col.kind}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f, i) => (
                <tr key={f.id ?? `${f.kind}-${f.title}-${i}`}>
                  <td>
                    {/* Filled for `static_confirmed` (the symbol table really does carry those imports), hollow
                        for a lead. The two kinds this provider emits sit at genuinely different proof states and
                        the mark has to keep them apart. */}
                    <span
                      aria-label={k.leadMark(f.severity)}
                      role="img"
                      style={{
                        display: 'inline-block',
                        width: 9,
                        height: 9,
                        borderRadius: '50%',
                        border: `1.5px solid ${SEV_COLOR[f.severity] ?? 'var(--text-dim)'}`,
                        background:
                          f.proofState === 'static_confirmed'
                            ? (SEV_COLOR[f.severity] ?? 'var(--text-dim)')
                            : 'transparent',
                        verticalAlign: 'middle',
                      }}
                    />
                  </td>
                  <td style={{ fontSize: 12.5 }}>
                    {f.title}
                    {f.rationale && (
                      <div className="hint" style={{ marginTop: 2 }}>
                        {f.rationale}
                      </div>
                    )}
                  </td>
                  <td className="mono hint" style={{ fontSize: 11 }}>
                    {f.kind}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ marginTop: 12 }}>{runButton}</div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="mono" style={{ fontSize: 12.5 }}>
        {value}
      </div>
    </div>
  );
}
