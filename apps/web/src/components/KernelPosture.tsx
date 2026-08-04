/**
 * The kernel-posture result, on a screen — for the first time.
 *
 * The provider is 1618 lines, contributes 36 findings across this corpus, has had a POST and a GET route since it
 * was written, and `api.kernelPosture` was declared in the client and called by nothing at all. Running the stage
 * and then being unable to find what it said is not a complaint about this panel's predecessor; there was no
 * predecessor.
 *
 * **The table's shape is the reading it enforces.** Answers are grouped by `answerClass`, and the group that
 * matters is `not-applicable`: `CONFIG_RANDOMIZE_BASE` landed upstream in 3.14, so asking a 2.6.31 kernel about
 * KASLR is asking about a feature that could not exist. On the WR940N that is most of the table — eight of nine
 * answers are `unknown` and only one of those is a gap. A flat list of "unknown" would report eight hardening
 * failures on an image that has one, which is the workbench's central conflation committed one level below
 * `ProofState`.
 *
 * **Every empty state says which empty it is.** Not run · this deployment could not answer · no kernel was located
 * (with the list of places it looked, because that is a coverage gap and never a statement about the image) ·
 * located and every question settled. An empty table would collapse all four.
 *
 * **The version's provenance travels with it.** `versionSource` is `kernel-banner` here and `kernel-config` or
 * `module-vermagic` elsewhere; a banner string and a shipped config are not the same standard of evidence, and the
 * age arithmetic downstream is only as good as which one it read. The same goes for the per-answer `source`.
 *
 * Every decision is in `kernel-posture.ts` and unit-tested without a DOM; this file fetches and renders.
 */
import { type JSX, useEffect, useState } from 'react';
import { type KernelPostureResult, type PostureAnswer, api } from '../api';
import { useMessages } from '../i18n';
import {
  type AnswerClass,
  answerClass,
  moduleSigning,
  orderAnswers,
  postureCensus,
  postureState,
} from '../kernel-posture';

const CLASS_COLOR: Record<AnswerClass, string> = {
  bad: 'var(--sev-high)',
  unanswered: 'var(--text-dim)',
  good: 'var(--ok)',
  'not-applicable': 'var(--text-faint)',
};

/** The mark for one row's class. Never colour alone — the class word is printed beside it in the same cell. */
function ClassMark({ kind }: { kind: AnswerClass }): JSX.Element {
  const t = useMessages();
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}>
      <span
        aria-hidden="true"
        style={{
          display: 'inline-block',
          width: 8,
          height: 8,
          borderRadius: '50%',
          border: `1.5px solid ${CLASS_COLOR[kind]}`,
          background: kind === 'bad' || kind === 'good' ? CLASS_COLOR[kind] : 'transparent',
        }}
      />
      <span style={{ color: CLASS_COLOR[kind], fontSize: 11.5 }}>{t.kernelPosture.class[kind]}</span>
    </span>
  );
}

export function KernelPosture({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const k = t.kernelPosture;
  const [result, setResult] = useState<KernelPostureResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const load = (): void => {
    api
      .kernelPosture(imageId)
      .then((r) => setResult(r))
      // A client that could not learn otherwise reads as "has not run". It never reads as a clean kernel.
      .catch(() => setResult(null))
      .finally(() => setLoading(false));
  };
  // Keyed on the image only. `load` is re-created every render by design, and listing it here would re-fetch on
  // every render — a poll of the route dressed as a dependency array.
  useEffect(load, [imageId]);

  const run = async (): Promise<void> => {
    setBusy(true);
    try {
      await api.runKernelPosture(imageId);
    } finally {
      setBusy(false);
      load();
    }
  };

  if (loading) return <div className="skeleton" style={{ height: 160 }} />;

  const state = postureState(result);
  const answers = orderAnswers(result?.answers ?? []);
  const census = postureCensus(answers);
  const mods = moduleSigning(result);

  const runButton = (
    <button type="button" className="btn btn-sm" onClick={run} disabled={busy}>
      {busy ? k.running : state.kind === 'not-run' ? k.run : k.rerun}
    </button>
  );

  return (
    <div className="panel">
      <div className="panel-title">{k.title}</div>
      <div className="panel-sub" style={{ maxWidth: '72ch' }}>
        {k.sub}
      </div>

      {state.kind !== 'located' ? (
        <div style={{ marginTop: 12, display: 'grid', gap: 10, justifyItems: 'start' }}>
          <div className="hint" style={{ maxWidth: '72ch' }}>
            {state.kind === 'not-run' && k.empty.notRun}
            {state.kind === 'unavailable' && k.empty.unavailable(state.reason)}
            {state.kind === 'not-located' && k.empty.notLocated(state.reason)}
          </div>
          {state.kind === 'not-located' && state.searched.length > 0 && (
            <div className="hint" style={{ maxWidth: '72ch' }}>
              {k.empty.searchedHeading}
              <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
                {state.searched.map((s) => (
                  <li key={s} className="mono" style={{ fontSize: 11.5 }}>
                    {s}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {runButton}
        </div>
      ) : (
        <>
          <div style={{ marginTop: 12, display: 'flex', gap: 22, flexWrap: 'wrap', alignItems: 'baseline' }}>
            <Fact label={k.field.version} value={result?.version ?? k.unknownValue} mono />
            {/* A banner string and a shipped config are not the same standard of evidence. */}
            <Fact label={k.field.versionSource} value={result?.versionSource ?? k.unrecorded} mono />
            {result?.age?.years !== undefined && <Fact label={k.field.age} value={k.years(result.age.years)} />}
            {result?.configPath && <Fact label={k.field.configPath} value={result.configPath} mono />}
            {mods && (
              <Fact label={k.field.modules} value={k.modulesValue(mods.signed, mods.inspected, mods.total)} mono />
            )}
          </div>

          <div style={{ marginTop: 12, maxWidth: '72ch' }}>
            <div style={{ fontSize: 12.5 }}>{k.census(census)}</div>
            <div className="hint" style={{ marginTop: 4 }}>
              {k.legend}
            </div>
          </div>

          {answers.length === 0 ? (
            <div className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
              {k.empty.noQuestions}
            </div>
          ) : (
            <div className="table-wrap" style={{ marginTop: 10 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th style={{ width: 130 }}>{k.col.state}</th>
                    <th>{k.col.question}</th>
                    <th style={{ width: 190 }}>{k.col.option}</th>
                    <th style={{ width: 130 }}>{k.col.evidence}</th>
                  </tr>
                </thead>
                <tbody>
                  {answers.map((ans: PostureAnswer) => (
                    <tr key={`${ans.id ?? ''}${ans.option ?? ''}`}>
                      <td>
                        <ClassMark kind={answerClass(ans)} />
                      </td>
                      <td style={{ fontSize: 12.5 }}>
                        {ans.question ?? ans.id}
                        {/* The provider's own sentence — what it found, or what it looked for and why that did
                            not settle it. It is the row's whole value and is shown, not hidden behind a click. */}
                        {ans.detail && (
                          <div className="hint" style={{ marginTop: 2 }}>
                            {ans.detail}
                          </div>
                        )}
                      </td>
                      <td className="mono hint" style={{ fontSize: 11 }}>
                        {ans.option}
                      </td>
                      {/* `source` on a settled answer, `reason` on an undetermined one — the provider sets exactly
                          one, and which one it set is itself the information. */}
                      <td className="mono hint" style={{ fontSize: 11 }}>
                        {ans.source ?? ans.reason ?? ''}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div style={{ marginTop: 12 }}>{runButton}</div>
        </>
      )}
    </div>
  );
}

function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }): JSX.Element {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className={mono ? 'mono' : undefined} style={{ fontSize: 12.5 }}>
        {value}
      </div>
    </div>
  );
}
