/**
 * Every previous run of a provider, wherever that provider's panel lives.
 *
 * The panels each render one result, because their route returns one: `listJobs().find(…)`, the most recent
 * finished job of that kind. That is fine for "show me the current answer" and silently wrong for everything else
 * — a provider re-run after a fix, a scan repeated on a different budget, a run that was blocked and then worked
 * all look identical from outside, which is to say invisible.
 *
 * This is the small shared piece that closes the gap without rewriting each panel: drop it under a result and the
 * runs behind it become readable. It reads the same ledger and the same pure summarizer the test bench does, so a
 * `blocked` run reads as blocked here too rather than as an empty one.
 *
 * Collapsed by default and silent when there is nothing but the current run, so it costs a panel nothing until it
 * has something to say.
 *
 * **The heading is one string from the catalogue, and it was not always.** It used to be assembled here, out of an
 * English frame with a hole in it — `{n} {label} run{s} on this image` — and the noun came from the caller. Hand it
 * a Spanish noun and you get *"2 análisis profundo runs on this image"*: half a sentence in each language, and the
 * defect is invisible in English because in English the frame happens to fit. So the WHOLE sentence is now a
 * catalogue function of the count and the noun, and each language builds its own — Spanish agrees in number and
 * needs a preposition English does not have, and neither of those survives a placeholder scheme.
 *
 * A panel names its runs one of two ways. `runKind` is a key the shell catalogue owns the word for, and is what a
 * panel whose noun belongs to the shell should use. `label` is for a panel that already holds an ALREADY-TRANSLATED
 * noun in its own namespace — `ImageDetail` passes `t.imageDetail.diff.runLabel`, and that is the correct use of
 * it. What it must never be handed is an English literal: `FuzzPanel`, `OpacidadPanel`, `WebProbePanel` and
 * `SymReachPanel` still do, so their heading reads in Spanish with an English noun in it until each moves its word
 * into its own catalogue or into `runKind`.
 *
 * A run's `kind` and `target` are identifiers: a job kind crosses the API into SQLite and a target is a path. They
 * render verbatim on every row, in every language.
 */
import { useEffect, useState } from 'react';
import { type RunSummary, api } from '../api';
import { type Messages, useMessages } from '../i18n';

/** The nouns this shell has words for. A panel says which; the catalogue says how it reads. */
export type RunKind = keyof Messages['shell']['runHistory']['kind'];

/** The dot's colour class. A presentation detail, so it stays here rather than in the catalogue. */
const OUTCOME_CLASS: Record<RunSummary['outcome'], string> = {
  proven: 'run-proven',
  lead: 'run-lead',
  empty: 'run-empty',
  blocked: 'run-blocked',
  failed: 'run-failed',
  running: 'run-running',
};

/**
 * Pure: how long ago, in the largest unit that still reads as a number. One catalogue entry per unit, because
 * "2m ago" and "hace 2 min" put their words in different places and neither is a substitution of the other.
 */
export function ago(ts: number, m: Messages['shell']['runHistory']['ago'], now = Date.now()): string {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return m.seconds(s);
  if (s < 3600) return m.minutes(Math.round(s / 60));
  if (s < 86400) return m.hours(Math.round(s / 3600));
  return m.days(Math.round(s / 86400));
}

type RunHistoryProps = {
  imageId: string;
  /** One or more job kinds this panel drives. */
  kinds: string[];
  /** Bump to re-read after the panel starts a run of its own. */
  refreshKey?: number;
} & (
  | {
      /** What to call these runs — the catalogue owns the word. Preferred. */
      runKind: RunKind;
      label?: never;
    }
  | {
      /** An already-translated noun the panel owns. Never an English literal. */
      label: string;
      runKind?: never;
    }
);

export function RunHistory({ imageId, kinds, runKind, label, refreshKey }: RunHistoryProps): JSX.Element | null {
  const t = useMessages();
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    api
      .runs(imageId, { kind: kinds.join(',') })
      .then((l) => setRuns(l.runs))
      .catch(() => setRuns([]));
  }, [imageId, kinds.join(','), refreshKey]);

  // Nothing to add while there is at most the one run the panel is already showing.
  if (!runs || runs.length < 2) return null;

  // The prop union guarantees one of the two arrived; TypeScript cannot correlate them once destructured, so the
  // empty fallback is unreachable rather than a default.
  const noun = runKind ? t.shell.runHistory.kind[runKind] : (label ?? '');

  return (
    <div className="run-history">
      <button type="button" className="run-history-toggle" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span>{t.shell.runHistory.heading(runs.length, noun)}</span>
        <span className="hint">{open ? t.shell.runHistory.hide : t.shell.runHistory.show}</span>
      </button>
      {open && (
        <div className="run-list">
          {runs.map((r) => {
            const meta = t.shell.runHistory.outcome[r.outcome];
            return (
              <div className="run-row is-static" key={r.jobId} title={meta.means}>
                <span className={`run-dot ${OUTCOME_CLASS[r.outcome]}`} aria-hidden="true" />
                <span className="run-kind">{r.target ?? r.kind}</span>
                {r.question && <span className="run-question mono">{r.question}</span>}
                <span className="run-headline">{r.headline}</span>
                <span className="run-tail">
                  {r.bound && <span className="run-bound">{r.bound}</span>}
                  <span className={`badge ${OUTCOME_CLASS[r.outcome]}`}>{meta.label}</span>
                  <time dateTime={new Date(r.startedAt).toISOString()}>{ago(r.startedAt, t.shell.runHistory.ago)}</time>
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
