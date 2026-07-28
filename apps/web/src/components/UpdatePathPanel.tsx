/**
 * UpdatePathPanel — what the updater in this rootfs actually checks, and where that check physically lives.
 *
 * `providers/updatepath.ts` has been answering "does anything here verify the image before it is flashed?" for as
 * long as it has existed, and the workbench has only ever shown the *effect* of the answer: the findings it synced,
 * and a count on a launch tile. The candidates themselves — the files, the commands, the chain — had nowhere to be
 * seen. This is that surface.
 *
 * **Why the chain is the point.** `sbin/sysupgrade` is OpenWrt's update entry point and it verifies nothing in its
 * own text: it opens with `. /lib/functions.sh` and `include /lib/upgrade`, and the `ucert -V` that authenticates
 * the image lives in `lib/upgrade/fwtool.sh`. Read a file at a time, the entry point looks like an updater with no
 * verification at all — a false negative manufactured by the unit of analysis. `d485237` taught the provider to
 * follow `source` edges and credit a script with what the files it reads do; without this panel a reader sees the
 * corrected findings and never the chain that corrected them, which is the same as being asked to trust it.
 *
 * **So evidence is never printed as the candidate's own.** A sourced command is rendered under the file it is
 * physically in, with the chain that reached it, because a reader must never be told `sysupgrade` contains a line
 * it does not contain. The provider keeps the two in separate fields for that reason and this panel keeps the
 * separation on screen.
 *
 * **And a credit is not a runtime proof.** A resolved source edge proves ONE static fact: this file names that file
 * at a command position where a POSIX shell would read it. Sourcing a file defines its functions; it does not call
 * them. The call may sit behind a branch, behind a flag nobody sets, or inside a function that returns 0 without
 * verifying anything. The sentence saying so sits inside the chain block, next to the credit it qualifies, rather
 * than in a legend — a caveat a reader has to go and find is a caveat that does not travel.
 *
 * **What could not be followed is shown too.** An interpolated path, a path leaving the rootfs, a cycle, a depth or
 * file bound: each is an honest unknown, and an absence measured across a partially-followed graph is weaker than
 * one measured across a whole one. A reader cannot tell which without being told, so they are told.
 *
 * Every kind of nothing gets its own sentence — nobody ran the provider, it ran and found no updater, it could not
 * run at all — because this codebase has already shipped the conflation of the first with the second once.
 */
import { useEffect, useState } from 'react';
import { type SourcedEvidence, type UnresolvedSource, type UpdatePathResult, type UpdaterCandidate, api } from '../api';

/**
 * Which of the several different nothings this image is in. Pure and exported: "nobody asked" must never render as
 * "nothing to show", and a rule a test cannot call is a rule held on trust.
 */
export type UpdatePathState = 'loading' | 'not-run' | 'unavailable' | 'no-updaters' | 'updaters';

export function updatePathState(result: UpdatePathResult | null, loaded: boolean): UpdatePathState {
  if (!loaded) return 'loading';
  if (!result) return 'not-run';
  if (result.available === false) return 'unavailable';
  return (result.updaters?.length ?? 0) > 0 ? 'updaters' : 'no-updaters';
}

/** The source-following record for one candidate, read defensively out of a result an older build may have written. */
export interface SourceChainView {
  sourced: SourcedEvidence[];
  unresolved: UnresolvedSource[];
  bounds: string[];
  /**
   * Whether this candidate carries any source-following record at all — i.e. whether there is a chain to draw.
   */
  recorded: boolean;
  /**
   * Whether the pass that follows `source` edges ran for this candidate, whatever it found. This is what makes an
   * empty chain readable: `followed && !recorded` is "this build looked and there is no chain", while `!followed`
   * is "the result predates the pass" — two facts that were the same absence until the provider started saying
   * which. Measured on the real Tenda camera, whose updater genuinely sources nothing: the panel could previously
   * only report that it did not know.
   */
  followed: boolean;
}

/**
 * Pure: the chain as this candidate recorded it. Every field is optional on a persisted result, so each is checked
 * for being an array before it is read; a malformed one degrades to empty rather than throwing inside a panel.
 */
export function sourceChainOf(c: UpdaterCandidate): SourceChainView {
  const sourced = Array.isArray(c.sourced)
    ? c.sourced.filter((s): s is SourcedEvidence => !!s && typeof s === 'object')
    : [];
  const unresolved = Array.isArray(c.unresolvedSources)
    ? c.unresolvedSources.filter((u): u is UnresolvedSource => !!u && typeof u === 'object')
    : [];
  const bounds = Array.isArray(c.sourceBounds) ? c.sourceBounds.filter((b): b is string => typeof b === 'string') : [];
  const recorded = sourced.length > 0 || unresolved.length > 0 || bounds.length > 0;
  return {
    sourced,
    unresolved,
    bounds,
    recorded,
    // A record implies the pass ran, so an older result that somehow carries a chain without the flag still reads
    // as followed rather than as unknown.
    followed: c.sourcesFollowed === true || recorded,
  };
}

/** A labelled row of monospaced items, or nothing at all — an empty list is never rendered as an empty claim. */
function ItemRow({
  label,
  items,
  tone,
}: { label: string; items: string[] | undefined; tone?: string }): JSX.Element | null {
  if (!items || items.length === 0) return null;
  return (
    <div style={{ fontSize: 12, marginTop: 2 }}>
      <span className="hint">{label}: </span>
      {items.map((i, n) => (
        <span key={`${i}-${n}`} className="mono" style={{ color: tone ?? 'var(--text)' }}>
          {n > 0 ? ' · ' : ''}
          {i}
        </span>
      ))}
    </div>
  );
}

/** One file reached through `source`, printed under the file the lines are IN — never under the one that reads it. */
function SourcedBlock({ s }: { s: SourcedEvidence }): JSX.Element {
  const via = Array.isArray(s.via) ? s.via.filter((v): v is string => typeof v === 'string') : [];
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ fontSize: 12.5 }}>
        <span className="mono" style={{ color: 'var(--text)' }}>
          {s.file ?? '(the file was not recorded)'}
        </span>{' '}
        <span className="hint">— the file these lines are physically in</span>
      </div>
      <div className="hint" style={{ fontSize: 11.5 }}>
        {via.length > 0 ? (
          <>
            reached: <span className="mono">{via.join(' → ')}</span>
          </>
        ) : (
          'the chain that reached it was not recorded on this result'
        )}
      </div>
      <ItemRow label="verifies" items={s.verifyCommands} />
      <ItemRow label="authenticates origin" items={s.signatureCommands} />
      <ItemRow
        label="invokes, but the binary is absent from the rootfs"
        items={s.missingVerifiers}
        tone="var(--warn)"
      />
      <ItemRow label="writes flash" items={s.flashWrites} />
      <ItemRow label="rollback markers" items={s.rollbackMarkers} />
    </div>
  );
}

/** The whole source-chain record for one candidate: what was credited, what was not resolved, what was not followed. */
function SourceChain({ chain, path }: { chain: SourceChainView; path: string }): JSX.Element {
  return (
    <div
      style={{
        marginTop: 10,
        borderLeft: '3px solid var(--accent-line)',
        background: 'var(--accent-soft)',
        borderRadius: 'var(--r-sm)',
        padding: '8px 12px',
        maxWidth: '72ch',
      }}
    >
      <div className="eyebrow">Source chain</div>
      {chain.sourced.length > 0 ? (
        <>
          <div className="hint">
            {chain.sourced.length} file{chain.sourced.length === 1 ? '' : 's'} that <span className="mono">{path}</span>{' '}
            reads with <span className="mono">source</span> / <span className="mono">.</span> /{' '}
            <span className="mono">include</span> were credited to it. The evidence is listed under the file it lives
            in, not under <span className="mono">{path}</span>, which contains none of these lines.
          </div>
          {chain.sourced.map((s, i) => (
            <SourcedBlock key={`${s.file ?? 'unnamed'}-${i}`} s={s} />
          ))}
          <div className="hint" style={{ marginTop: 8 }}>
            A resolved source edge is one static fact: this file names that file where a POSIX shell would read it.
            Being credited with a sourced verification does <strong>not</strong> prove the check runs — sourcing a file
            defines its functions, it does not call them, and the call may sit behind a branch, behind a flag nobody
            sets, or inside a function that returns 0 without verifying anything. No source edge raises a proof state.
          </div>
        </>
      ) : null}

      {chain.unresolved.length > 0 ? (
        <div style={{ marginTop: 10 }}>
          <div className="hint">
            {chain.unresolved.length} directive{chain.unresolved.length === 1 ? '' : 's'} could not be turned into a
            file. Guessing one would fabricate; dropping it silently would hide that this graph is incomplete.
          </div>
          <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {chain.unresolved.map((u, i) => (
              <li key={`${u.from ?? '?'}-${u.spec ?? '?'}-${i}`} style={{ fontSize: 12 }}>
                <span className="mono">
                  {u.from ?? '(file not recorded)'}: {u.directive ?? '.'} {u.spec ?? '(no operand recorded)'}
                </span>{' '}
                <span className="hint">— {u.reason ?? 'no reason was recorded'}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {chain.bounds.length > 0 ? (
        <div style={{ marginTop: 10 }}>
          <div className="hint">
            Where following stopped short. A bound is not an answer: anything past it was not looked at, and is absent
            from what this candidate is credited with rather than cleared by it.
          </div>
          <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {chain.bounds.map((b, i) => (
              <li key={`${b}-${i}`} style={{ fontSize: 12 }} className="hint">
                {b}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function CandidateBlock({ c }: { c: UpdaterCandidate }): JSX.Element {
  const chain = sourceChainOf(c);
  const path = c.path ?? '(path not recorded)';
  return (
    <div className="panel" style={{ margin: '10px 0 0' }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
        <span className="mono" style={{ fontSize: 12.5, color: 'var(--text)' }}>
          {path}
        </span>
        <span className="badge">{c.kind ?? 'unknown kind'}</span>
        {c.symbolSource ? <span className="badge mono">{c.symbolSource}</span> : null}
      </div>
      {c.why ? (
        <div className="hint" style={{ marginTop: 4, maxWidth: '72ch' }}>
          {c.why}
        </div>
      ) : null}
      <ItemRow label="verifies (its own lines)" items={c.verifyCommands} />
      <ItemRow label="signature routines" items={c.signatureFns} />
      <ItemRow label="digest routines" items={c.digestFns} />
      <ItemRow
        label="invokes, but the binary is absent from the rootfs"
        items={c.missingVerifiers}
        tone="var(--warn)"
      />
      <ItemRow label="writes flash" items={c.flashWrites} />
      {chain.recorded ? <SourceChain chain={chain} path={path} /> : null}
    </div>
  );
}

export function UpdatePathPanel({ imageId }: { imageId: string }): JSX.Element {
  const [result, setResult] = useState<UpdatePathResult | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    setLoaded(false);
    api
      .updatePath(imageId)
      .then((r) => {
        if (!alive) return;
        setResult(r);
        setLoaded(true);
      })
      .catch(() => {
        if (!alive) return;
        setResult(null);
        setLoaded(true);
      });
    return () => {
      alive = false;
    };
  }, [imageId]);

  const state = updatePathState(result, loaded);
  const updaters = result?.updaters ?? [];
  const chains = updaters.map((c) => sourceChainOf(c));
  const anyChain = chains.some((c) => c.recorded);
  // Every candidate was put through the pass and none had a chain — a real answer, not a gap.
  const allFollowed = chains.length > 0 && chains.every((c) => c.followed);

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">Update path — what the updater checks, and where that check lives</div>
      <div className="panel-sub">
        The files this rootfs would run to install new firmware, the verification each one performs, and — because an
        entry point routinely delegates its checking to a file it sources — the chain that reached the check.
      </div>

      {state === 'loading' ? <div className="skeleton" style={{ height: 60, marginTop: 12 }} /> : null}

      {state === 'not-run' ? (
        <div className="banner" style={{ marginTop: 12, maxWidth: '72ch' }}>
          Nobody has run the update-path provider on this image. That is not a statement about the firmware: no updater
          has been looked for, so nothing here has been cleared. Run <span className="mono">updatepath</span> from Deep
          analysis above.
        </div>
      ) : null}

      {state === 'unavailable' ? (
        <div className="banner banner-warn" style={{ marginTop: 12, maxWidth: '72ch' }}>
          {result?.reason ?? 'The update-path provider could not run on this image.'}
        </div>
      ) : null}

      {state === 'no-updaters' ? (
        <div className="banner" style={{ marginTop: 12, maxWidth: '72ch' }}>
          The provider ran and located no updater candidate. That is a statement about what the walk read, not a verdict
          that the device has no update path — an updater outside the carved rootfs, in a second partition or past a
          walk bound was never opened. {result?.reason ?? ''}
        </div>
      ) : null}

      {state === 'updaters' ? (
        <>
          <div className="hint" style={{ marginTop: 12, maxWidth: '72ch' }}>
            {result?.reason}
          </div>
          {!anyChain ? (
            <div className="hint" style={{ marginTop: 8, maxWidth: '72ch' }}>
              {allFollowed ? (
                <>
                  No candidate below sources another file. This run followed <span className="mono">source</span> edges
                  and found none — an answer about these scripts, not a gap in the analysis.
                </>
              ) : (
                <>
                  No source chain is recorded on any candidate below. Two readings, and this result cannot tell them
                  apart: these scripts source nothing, or the result was stored by a build that did not follow{' '}
                  <span className="mono">source</span> edges at all. Re-run the provider to be sure which.
                </>
              )}
            </div>
          ) : null}
          {updaters.map((c, i) => (
            <CandidateBlock key={`${c.path ?? 'unnamed'}-${i}`} c={c} />
          ))}
          {result?.droppedUpdaters ? (
            <div className="hint" style={{ marginTop: 10, maxWidth: '72ch' }}>
              {result.droppedUpdaters} further candidate(s) were dropped by the candidate cap — kept by
              entry-point/verification/flash evidence, never by directory order — and are absent from the list above
              rather than cleared by it.
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
