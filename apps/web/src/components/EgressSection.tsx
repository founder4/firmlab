/**
 * What the firmware itself tried to reach — as a section, across every boot, instead of a panel inside a menu.
 *
 * `providers/egress.ts` reads the guest's own frames off `filter-dump`, so the workbench knows what a booted
 * firmware ADDRESSED whether or not it was allowed to get there — measured, not assumed: with `restrict=on` the
 * capture still holds the guest's ARP and its three ICMP to 8.8.8.8 and simply no replies. That is one of the more
 * interesting things this workbench produces about a device, and until now the only way to see it was to open the
 * emulation menu, which showed **the most recent run and nothing else**.
 *
 * Two things this section does that the buried panel could not:
 *
 *  1. **Every boot, not the last one.** A firmware that phones home on one boot and not another is a fact about
 *     the firmware; a reader shown only the newest run cannot see it. Runs are listed newest first, each with what
 *     it was and when, so a destination can be attributed to a run rather than to "the image".
 *  2. **It distinguishes the three empties.** No boot has run · boots ran and none recorded a wire observation ·
 *     boots recorded one and the guest addressed nothing. The middle case is not a property of the firmware at
 *     all: it is a run stored before the observation existed, or a qemu with no `filter-dump` object, and reading
 *     it as "this firmware contacts nothing" is exactly the inference this codebase exists to refuse.
 *
 * The rendering of a single observation is `EgressPanel`, imported from the simulation menu rather than copied:
 * the two surfaces must not be able to describe the same capture differently.
 */
import { type JSX, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { type EgressObservation, type RunSummary, api } from '../api';
import { useMessages } from '../i18n';
import { EgressPanel } from './SimulationMenu';

/** One boot's wire observation, with the run it came from. */
interface RunEgress {
  run: RunSummary;
  egress: EgressObservation;
  isolated: boolean;
}

/** The half of a stored emulation result this section reads. Optional forever — older runs carry neither field. */
interface StoredResult {
  egress?: EgressObservation;
  isolated?: boolean;
}

export function EgressSection({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const e = t.egressSection;
  const [state, setState] = useState<{ loading: boolean; runsDone: number; withEgress: RunEgress[] }>({
    loading: true,
    runsDone: 0,
    withEgress: [],
  });

  useEffect(() => {
    let cancelled = false;
    api
      .runs(imageId, { kind: 'emulate' })
      .then(async (ledger) => {
        const done = ledger.runs.filter((r) => r.status === 'done');
        const details = await Promise.all(
          done.map(async (run) => {
            try {
              const d = await api.runDetail(imageId, run.jobId);
              const r = (d.result ?? null) as StoredResult | null;
              return r?.egress ? { run, egress: r.egress, isolated: r.isolated === true } : null;
            } catch {
              // A run whose detail cannot be read is not a run that observed nothing; it is dropped from the
              // list and still counted in `runsDone`, which is what the empty-state sentence is computed from.
              return null;
            }
          }),
        );
        if (!cancelled) {
          setState({ loading: false, runsDone: done.length, withEgress: details.filter((x): x is RunEgress => !!x) });
        }
      })
      .catch(() => {
        if (!cancelled) setState({ loading: false, runsDone: 0, withEgress: [] });
      });
    return () => {
      cancelled = true;
    };
  }, [imageId]);

  if (state.loading) return <div className="skeleton" style={{ height: 120 }} />;

  return (
    <div className="panel">
      <div className="panel-title">{e.title}</div>
      <div className="panel-sub" style={{ maxWidth: '72ch' }}>
        {e.sub}
      </div>

      {state.withEgress.length === 0 ? (
        <div className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
          {state.runsDone === 0 ? (
            <>
              {e.noRuns}{' '}
              <Link className="btn btn-sm btn-ghost" to={`/image/${imageId}/simulate`}>
                {e.toSimulate}
              </Link>
            </>
          ) : (
            e.runsWithoutCapture(state.runsDone)
          )}
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 16, marginTop: 12 }}>
          {state.withEgress.map((r) => (
            <div key={r.run.jobId}>
              <div className="eyebrow" style={{ marginBottom: 4 }}>
                {e.runLabel(r.run.headline, new Date(r.run.startedAt).toISOString().slice(0, 16).replace('T', ' '))}
              </div>
              <EgressPanel egress={r.egress} isolated={r.isolated} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
