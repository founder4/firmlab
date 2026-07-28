/**
 * ComponentMap — the rootfs link-dependency graph, drawn.
 *
 * `providers/compmap.ts` has been building this graph, persisting it, counting it towards coverage and feeding it
 * into the autonomous scan since it was written, and the workbench has never once shown it: the string `compmap`
 * appeared in the web app four times (a job-kind union member, a launch button, a timeline tick and a coverage row)
 * and zero times in any panel. This is that panel.
 *
 * **What the graph is.** For every ELF the walk found under the rootfs, its `DT_NEEDED` entries — the shared
 * objects the LINKER recorded, read out of the bytes with `rabin2 -l`. An edge is a static fact about a file, and
 * that is the whole of what it proves. It is not a runtime call graph: a library opened with `dlopen(3)` at
 * runtime — which is how most plugin, PAM and NSS surfaces load — leaves no `DT_NEEDED` entry and therefore no
 * edge here. Silence in this graph is silence about linking, not about loading.
 *
 * **Why the unresolved list is above the picture and not inside it.** The interesting row is a binary whose
 * `DT_NEEDED` names something the carve does not contain, and in a hairball of 300 binaries and 40 libraries that
 * row is the one a reader will never find. So the unresolved references are a table, with who needs each one, and
 * the drawing below is the shape — not the evidence. Orphans get the same treatment for the same reason.
 *
 * **What an unresolved reference does NOT mean.** Two properties of the walk make false unresolved entries normal,
 * and both are stated on screen rather than only here, because an operator who does not know them will read this
 * table as a broken rootfs:
 *   • the walk does not follow symlinks (it must not — symlink loops and rootfs escapes), and a soname is very
 *     often a symlink (`libc.so.0 → libuClibc-0.9.33.so`), so the target exists and the reference still lists here;
 *   • resolution is by basename against what the carve recovered, and a partial carve, a second partition, or a
 *     vendor overlay mounted at boot are all libraries the device has and this image does not.
 * A missing library is a hypothesis to check in the file browser, never a finding.
 *
 * **Every kind of nothing gets its own sentence.** "Nobody has built the map", "there is no extracted rootfs to
 * build one from", "rabin2 is not installed here" and "the map was built and the rootfs links nothing" are four
 * different claims about the world, and this codebase has already shipped the conflation of the first with the
 * last once (three hardware panels reporting "no device tree has been read" for an image whose device-tree run had
 * completed and found nothing). `compMapState` is the one place that decision is made, and it is pure so a test
 * can hold it to it.
 *
 * Hand-rolled SVG, like every other visual in this shell — no chart library, and every colour is a theme token so
 * the diagram reads in both themes.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { type CompGraph, type CompMapResult, type ExtractionBrowseView, api } from '../api';

/** How many nodes the drawing shows per column before it stops and says what it dropped, and by what rule. */
export const GRAPH_BIN_CAP = 26;
export const GRAPH_LIB_CAP = 20;
/** How many "needed by" binaries a single unresolved row names inline. */
const NEEDED_BY_CAP = 8;
/** How many orphan binaries the list names before it reports the remainder as a count. */
const ORPHAN_CAP = 40;

/**
 * Which of the several different nothings this image is in. Pure, and exported, because the whole point is that
 * "nobody asked" can never render as "nothing to show" — and a rule you can't call from a test is a rule on trust.
 *
 * Order matters. A stored graph with nodes in it wins outright: it is a real computed answer and must be drawn
 * whatever the extraction looks like now. Only when there is nothing to draw does the question become *why*, and
 * then the extraction is asked first — "there is no rootfs" is both the more likely cause and the actionable one,
 * and it is read from the extraction's own structural state rather than by pattern-matching the provider's prose.
 */
export type CompMapState = 'graph' | 'no-rootfs' | 'not-run' | 'unavailable' | 'empty';

export function compMapState(result: CompMapResult | null, extraction: ExtractionBrowseView | null): CompMapState {
  if ((result?.graph?.nodes?.length ?? 0) > 0 && result?.available !== false) return 'graph';
  // `null` = the extraction state could not be read at all, which is not the same as knowing there is no rootfs.
  const hasRootfs = extraction ? extraction.state === 'rootfs' : null;
  if (hasRootfs === false) return 'no-rootfs';
  if (!result) return 'not-run';
  if (result.available === false) return 'unavailable';
  return 'empty';
}

/**
 * Pure: the sonames some binary references and the walk did not find.
 *
 * `graph.unresolved` is the provider's own answer and is used whenever it is there. A result stored before that
 * field existed is not lost, though, because the graph carries the same set structurally: `buildGraph` marks a node
 * `lib` exactly when the referenced soname is absent from the entry basenames — the same condition, on the same
 * pass, that fills `unresolved`. So the fallback is the identical set, not an approximation of it.
 */
export function unresolvedSonames(graph: CompGraph | undefined): Set<string> {
  const declared = graph?.unresolved;
  if (Array.isArray(declared)) return new Set(declared.filter((s): s is string => typeof s === 'string'));
  const ids = (graph?.nodes ?? []).filter((n) => n.kind === 'lib').map((n) => n.id);
  return new Set(ids.filter((s): s is string => typeof s === 'string'));
}

/**
 * Pure: the binaries nothing links against — no incoming "needs" edge. The same rule `orphanBinaries` applies in
 * the provider, recomputed here from the persisted graph so the list is not the finding's 200-item slice.
 *
 * Not a verdict, and the UI says so: a daemon, a CLI and an init script's helper are all legitimately orphans in a
 * link graph. What the list is good for is the opposite reading — it is the set of top-level executables, i.e. the
 * things something outside this graph has to start.
 */
export function orphanBinaries(graph: CompGraph | undefined): string[] {
  const depended = new Set((graph?.edges ?? []).map((e) => e.to).filter((s): s is string => typeof s === 'string'));
  return (graph?.nodes ?? [])
    .filter((n) => n.kind === 'binary' && typeof n.id === 'string' && !depended.has(n.id))
    .map((n) => n.id as string)
    .sort((a, b) => a.localeCompare(b));
}

export interface GraphViewNode {
  id: string;
  /** Edges out of (binary) or into (library) this node. */
  degree: number;
  /** For a binary: how many of its references are unresolved. For a library: whether it is one. */
  unresolved: number;
}

export interface GraphView {
  binaries: GraphViewNode[];
  libs: GraphViewNode[];
  edges: { from: string; to: string; unresolved: boolean }[];
  droppedBinaries: number;
  droppedLibs: number;
  /** The sentence stating what was left out and by what rule. Rendered always, not only when something was cut. */
  rule: string;
}

/**
 * Pure: choose what the drawing shows.
 *
 * A cap that truncates by arrival order makes the picture an artifact of directory layout (CLAUDE.md rule 4), and
 * it would also drop the rows the section exists for. So the ranking is explicit and the unresolved end of it is
 * protected: libraries the carve does not contain sort ahead of the ones it does, and binaries that reference one
 * sort ahead of the ones that don't. Within each half it is degree, then name — never readdir order.
 */
export function selectGraphView(
  graph: CompGraph | undefined,
  binCap = GRAPH_BIN_CAP,
  libCap = GRAPH_LIB_CAP,
): GraphView {
  const unresolved = unresolvedSonames(graph);
  const edges = (graph?.edges ?? []).flatMap((e) =>
    typeof e.from === 'string' && typeof e.to === 'string' ? [{ from: e.from, to: e.to }] : [],
  );

  const outDeg = new Map<string, number>();
  const outUnresolved = new Map<string, number>();
  const inDeg = new Map<string, number>();
  for (const e of edges) {
    outDeg.set(e.from, (outDeg.get(e.from) ?? 0) + 1);
    inDeg.set(e.to, (inDeg.get(e.to) ?? 0) + 1);
    if (unresolved.has(e.to)) outUnresolved.set(e.from, (outUnresolved.get(e.from) ?? 0) + 1);
  }

  const libsAll: GraphViewNode[] = [...inDeg]
    .map(([id, degree]) => ({ id, degree, unresolved: unresolved.has(id) ? 1 : 0 }))
    .sort((a, b) => b.unresolved - a.unresolved || b.degree - a.degree || a.id.localeCompare(b.id));
  const binsAll: GraphViewNode[] = [...outDeg]
    .map(([id, degree]) => ({ id, degree, unresolved: outUnresolved.get(id) ?? 0 }))
    .sort(
      (a, b) =>
        Math.sign(b.unresolved) - Math.sign(a.unresolved) ||
        b.unresolved - a.unresolved ||
        b.degree - a.degree ||
        a.id.localeCompare(b.id),
    );

  const libs = libsAll.slice(0, libCap);
  const binaries = binsAll.slice(0, binCap);
  const libSet = new Set(libs.map((n) => n.id));
  const binSet = new Set(binaries.map((n) => n.id));

  return {
    binaries,
    libs,
    edges: edges
      .filter((e) => binSet.has(e.from) && libSet.has(e.to))
      .map((e) => ({ ...e, unresolved: unresolved.has(e.to) })),
    droppedBinaries: binsAll.length - binaries.length,
    droppedLibs: libsAll.length - libs.length,
    rule: 'Ranked with unresolved references first, then by number of links, then by name — never by directory order.',
  };
}

/**
 * Pure: shorten a label from the MIDDLE. A soname carries its identity at both ends (`libcrypto` … `.so.1.1`), so
 * a tail-clipped `libcrypto.so…` throws away the version, which is the half a reader is checking against an SBOM.
 */
/**
 * Pure: does this node name look like a shared object rather than a program? The same shape `parseNeeded` matches
 * on the provider side — a `.so` extension that terminates a version segment, so `foo.socket` is not one.
 *
 * It matters for exactly one sentence. An orphan is a node nothing links against, and for an executable that is
 * ordinary (init starts it). For a `.so` it is a different statement: nothing in the graph names it, which usually
 * means it is `dlopen`ed — invisible here — and occasionally that nothing uses it at all.
 */
export function looksLikeSharedObject(id: string): boolean {
  return /\.so(\.[0-9A-Za-z_]+)*$/.test(id);
}

export function middleTruncate(s: string, max: number): string {
  if (s.length <= max) return s;
  const head = Math.ceil((max - 1) / 2);
  const tail = Math.floor((max - 1) / 2);
  return `${s.slice(0, head)}…${s.slice(s.length - tail)}`;
}

const ROW_H = 22;
const SVG_W = 760;
const COL_L_END = 244;
const COL_R_START = 516;
const TOP_PAD = 34;
const LABEL_CHARS = 26;

/** The bipartite drawing: what links (left) against what it links to (right). Every colour is a theme token. */
function DependencyDiagram({ view }: { view: GraphView }): JSX.Element {
  const [hover, setHover] = useState<string | null>(null);
  const rows = Math.max(view.binaries.length, view.libs.length, 1);
  const height = TOP_PAD + rows * ROW_H + 14;
  const yOf = (i: number): number => TOP_PAD + i * ROW_H + ROW_H / 2;
  const binY = new Map(view.binaries.map((n, i) => [n.id, yOf(i)]));
  const libY = new Map(view.libs.map((n, i) => [n.id, yOf(i)]));
  const lit = (e: { from: string; to: string }): boolean => hover === null || hover === e.from || hover === e.to;

  return (
    <div className="cmap-canvas">
      <svg
        className="cmap-svg"
        viewBox={`0 0 ${SVG_W} ${height}`}
        role="img"
        aria-label="Rootfs link-dependency diagram: ELF files on the left, the sonames they name on the right"
      >
        <title>Rootfs link-dependency diagram</title>
        {/* "ELF file", not "binary": on a real rootfs the left column fills with `.so` files, because a shared
            object that names another one is itself an ELF the walk found. Labelling it "binary" made the drawing
            look wrong against the Tenda carve when it was in fact correct. */}
        <text className="cmap-colhead" x={COL_L_END} y={18} textAnchor="end">
          ELF file
        </text>
        <text className="cmap-colhead" x={COL_R_START} y={18}>
          DT_NEEDED
        </text>

        {view.edges.map((e) => {
          const y1 = binY.get(e.from);
          const y2 = libY.get(e.to);
          if (y1 === undefined || y2 === undefined) return null;
          const mid = (COL_L_END + COL_R_START) / 2;
          return (
            <path
              key={`${e.from}->${e.to}`}
              className={`cmap-edge ${e.unresolved ? 'is-unresolved' : ''} ${lit(e) ? '' : 'is-dim'}`}
              d={`M ${COL_L_END} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${COL_R_START} ${y2}`}
            />
          );
        })}

        {view.binaries.map((n, i) => (
          <g
            key={`b-${n.id}`}
            className={`cmap-node is-binary ${n.unresolved > 0 ? 'has-unresolved' : ''} ${
              hover === null || hover === n.id ? '' : 'is-dim'
            }`}
            onMouseEnter={() => setHover(n.id)}
            onMouseLeave={() => setHover(null)}
          >
            <title>{`${n.id} — links ${n.degree} shared object(s), ${n.unresolved} unresolved`}</title>
            <rect className="cmap-pill" x={8} y={yOf(i) - 9} width={COL_L_END - 8} height={18} rx={3} />
            <text className="cmap-label" x={COL_L_END - 8} y={yOf(i) + 3.5} textAnchor="end">
              {middleTruncate(n.id, LABEL_CHARS)}
            </text>
          </g>
        ))}

        {view.libs.map((n, i) => (
          <g
            key={`l-${n.id}`}
            className={`cmap-node is-lib ${n.unresolved ? 'is-unresolved' : ''} ${
              hover === null || hover === n.id ? '' : 'is-dim'
            }`}
            onMouseEnter={() => setHover(n.id)}
            onMouseLeave={() => setHover(null)}
          >
            <title>
              {`${n.id} — named by ${n.degree} binary/binaries, ${n.unresolved ? 'NOT present in the carve' : 'present in the carve'}`}
            </title>
            <rect
              className="cmap-pill"
              x={COL_R_START}
              y={yOf(i) - 9}
              width={SVG_W - COL_R_START - 8}
              height={18}
              rx={3}
            />
            <text className="cmap-label" x={COL_R_START + 8} y={yOf(i) + 3.5}>
              {middleTruncate(n.id, LABEL_CHARS)}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}

type Load = 'loading' | 'ready';

export function ComponentMap({ imageId }: { imageId: string }): JSX.Element {
  const [result, setResult] = useState<CompMapResult | null>(null);
  const [extraction, setExtraction] = useState<ExtractionBrowseView | null>(null);
  const [load, setLoad] = useState<Load>('loading');
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    // Both are reads of what has already run. The panel starts nothing on mount: a screen that silently launches a
    // job is a screen whose empty state you can never see.
    const [r, f] = await Promise.all([
      api.compmapResult(imageId).catch(() => null),
      api
        .files(imageId)
        .then((v) => v.extraction ?? null)
        .catch(() => null),
    ]);
    setResult(r);
    setExtraction(f);
    setLoad('ready');
  }, [imageId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      const { jobId } = await api.runAnalysis(imageId, 'compmap');
      const timer = window.setInterval(async () => {
        const j = await api.job(jobId);
        if (j.status === 'done' || j.status === 'error') {
          window.clearInterval(timer);
          setRunning(false);
          if (j.status === 'error') setError(j.error ?? 'The component map job failed.');
          await refresh();
        }
      }, 700);
    } catch (e) {
      // The POST refuses with a sentence when there is no rootfs to map. That sentence is the answer, not noise.
      setRunning(false);
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [imageId, refresh]);

  const graph = result?.graph;
  const state = compMapState(result, extraction);
  const view = useMemo(() => selectGraphView(graph), [graph]);
  const unresolved = useMemo(() => unresolvedSonames(graph), [graph]);
  const orphans = useMemo(() => orphanBinaries(graph), [graph]);

  // Who needs each unresolved soname — the row this section exists for, keyed off the edges rather than the nodes.
  const neededBy = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const e of graph?.edges ?? []) {
      if (typeof e.to !== 'string' || typeof e.from !== 'string' || !unresolved.has(e.to)) continue;
      const list = m.get(e.to) ?? [];
      list.push(e.from);
      m.set(e.to, list);
    }
    return [...m]
      .map(([soname, bins]) => ({ soname, bins: [...bins].sort((a, b) => a.localeCompare(b)) }))
      .sort((a, b) => b.bins.length - a.bins.length || a.soname.localeCompare(b.soname));
  }, [graph, unresolved]);

  const nodes = graph?.nodes ?? [];
  const binaryNodes = nodes.filter((n) => n.kind === 'binary').length;
  const filesWalked = result?.binaryCount ?? binaryNodes;
  const linkers = new Set((graph?.edges ?? []).map((e) => e.from));
  const linksNothing = nodes.filter((n) => n.kind === 'binary' && !linkers.has(n.id)).length;
  // An orphaned `.so` and an orphaned executable are different claims, and the real Tenda carve produces 55
  // orphans of which most are `.so` files. Calling those "top-level executables" was simply wrong.
  const orphanLibs = orphans.filter((o) => looksLikeSharedObject(o)).length;

  const runLabel = running ? <span className="spinner" /> : result ? 'Rebuild map' : 'Build component map';

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">Component map</div>
      <div className="panel-sub">
        Every ELF in the extracted rootfs mapped to the shared objects its <span className="mono">DT_NEEDED</span>{' '}
        entries name — what the <em>linker</em> recorded, read out of the bytes with{' '}
        <span className="mono">rabin2</span>. A library the program opens with <span className="mono">dlopen(3)</span>{' '}
        at runtime leaves no such entry and no edge here, so silence in this graph is silence about linking, not about
        loading. It is structure, not a security verdict.
      </div>

      {load === 'loading' && <div className="skeleton" style={{ height: 120, marginTop: 14 }} />}

      {load === 'ready' && state === 'not-run' && (
        <div className="cmap-nothing" data-state="not-run">
          <strong>No component map has been built for this image</strong>
          <span className="hint cmap-prose">
            Nothing has asked what this rootfs links against, so there is nothing to show — which is a statement about
            this workbench, not about the firmware. Build it and the answer, including an empty one, will say so.
          </span>
        </div>
      )}

      {load === 'ready' && state === 'no-rootfs' && (
        <div className="cmap-nothing" data-state="no-rootfs">
          <strong>There is no extracted rootfs to map</strong>
          <span className="hint cmap-prose">
            The map is built by walking the files extraction wrote to disk, and this image has none to walk. That is a
            gap in the extraction, not a firmware that links nothing — run extraction first from the Extraction section.
            {extraction?.verdict && (
              <>
                {' '}
                Extraction says: <em>{extraction.verdict}</em>
              </>
            )}
          </span>
        </div>
      )}

      {load === 'ready' && state === 'unavailable' && (
        <div className="banner banner-warn" style={{ marginTop: 14 }}>
          <div>
            <strong>The map could not be built — the question was not answered.</strong>
            <div className="hint cmap-prose" style={{ marginTop: 4 }}>
              {result?.reason ?? 'The provider reported itself unavailable and gave no reason.'} Nothing below is a
              finding about this firmware: an absent tool is an absent answer, not an absent dependency.
            </div>
          </div>
        </div>
      )}

      {load === 'ready' && state === 'empty' && (
        <div className="cmap-nothing" data-state="empty">
          <strong>The map was built and the graph is empty</strong>
          <span className="hint cmap-prose">
            The walk ran over the rootfs and came back with no ELF carrying a <span className="mono">DT_NEEDED</span>{' '}
            entry. That is a real answer, and a plausible one — a busybox-only or fully static rootfs links nothing
            dynamically. It is not the same as nobody having looked.
            {result?.reason && (
              <>
                {' '}
                Provider: <em>{result.reason}</em>
              </>
            )}
          </span>
        </div>
      )}

      {state === 'graph' && (
        <>
          <div className="grid grid-3" style={{ marginTop: 16 }}>
            <div className="stat">
              <div className="stat-label">ELF binaries walked</div>
              <div className="stat-value">{result?.binaryCount ?? binaryNodes}</div>
            </div>
            <div className="stat">
              <div className="stat-label">Link edges</div>
              <div className="stat-value">{(graph?.edges ?? []).length}</div>
            </div>
            <div className="stat">
              <div className="stat-label">Unresolved references</div>
              <div className="stat-value" style={{ color: unresolved.size > 0 ? 'var(--warn)' : undefined }}>
                {unresolved.size}
              </div>
            </div>
          </div>

          <p className="hint cmap-prose" style={{ marginTop: 10 }}>
            A node is a <strong>basename</strong>, because a <span className="mono">DT_NEEDED</span> reference is one —
            two files called <span className="mono">busybox</span> in different directories are one node.
            {/* Only when the two counts actually differ. The first version stated the discrepancy unconditionally
                and rendered "67 files walked can become 67 binary nodes" against the real Tenda carve — a sentence
                explaining something that had not happened. Caught by looking at the page, not by a test. */}
            {filesWalked !== binaryNodes && (
              <>
                {' '}
                Here that collapses {filesWalked} ELF files into {binaryNodes} nodes.
              </>
            )}
            {linksNothing > 0 && (
              <>
                {' '}
                {linksNothing} of them name no shared object at all — statically linked, or an ELF{' '}
                <span className="mono">rabin2</span> could not read.
              </>
            )}
          </p>

          {/* The point of the section, above the picture: a hairball is exactly where this row would be lost. */}
          <section style={{ marginTop: 20 }}>
            <div className="eyebrow" style={{ marginBottom: 8 }}>
              Unresolved libraries · {unresolved.size}
            </div>
            {neededBy.length > 0 ? (
              <>
                <div style={{ overflowX: 'auto' }}>
                  <table className="data">
                    <thead>
                      <tr>
                        <th>Soname referenced</th>
                        <th className="num">Count</th>
                        <th>Named by</th>
                      </tr>
                    </thead>
                    <tbody>
                      {neededBy.map((row) => (
                        <tr key={row.soname}>
                          <td className="mono cmap-unres">{row.soname}</td>
                          <td className="num mono">{row.bins.length}</td>
                          <td>
                            <span className="cmap-chips">
                              {row.bins.slice(0, NEEDED_BY_CAP).map((b) => (
                                <span key={b} className="cmap-chip mono">
                                  {b}
                                </span>
                              ))}
                              {row.bins.length > NEEDED_BY_CAP && (
                                <span className="hint">+{row.bins.length - NEEDED_BY_CAP} more</span>
                              )}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="hint cmap-prose" style={{ marginTop: 8 }}>
                  <strong>Unresolved is not missing.</strong> The walk does not follow symlinks — it must not — and a
                  soname is very often one (<span className="mono">libc.so.0 → libuClibc-0.9.33.so</span>), so a library
                  that is present appears here anyway. Resolution is by basename against what this carve recovered, and
                  a partial carve, a second partition or an overlay mounted at boot are all libraries the device has and
                  this image does not. Open the file browser before treating a row here as a missing library.
                </p>
              </>
            ) : (
              <p className="hint cmap-prose" style={{ margin: 0 }}>
                Every <span className="mono">DT_NEEDED</span> reference in this rootfs names a file the walk also found.
                That says the carve is self-consistent for the binaries it recovered — not that the carve is complete.
              </p>
            )}
          </section>

          <section style={{ marginTop: 22 }}>
            <div className="eyebrow" style={{ marginBottom: 8 }}>
              Dependency shape
            </div>
            <DependencyDiagram view={view} />
            <div className="legend" style={{ marginTop: 10 }}>
              <span className="legend-item">
                <span className="legend-swatch cmap-sw-bin" />
                ELF file in the carve
              </span>
              <span className="legend-item">
                <span className="legend-swatch cmap-sw-lib" />
                soname the carve has
              </span>
              <span className="legend-item">
                <span className="legend-swatch cmap-sw-unres" />
                soname it does not
              </span>
              <span className="legend-item" style={{ marginLeft: 'auto', color: 'var(--text-faint)' }}>
                {view.binaries.length} of {view.binaries.length + view.droppedBinaries} linking files ·{' '}
                {view.libs.length} of {view.libs.length + view.droppedLibs} referenced sonames
              </span>
            </div>
            <p className="hint cmap-prose" style={{ marginTop: 6 }}>
              {view.rule}
              {view.droppedBinaries + view.droppedLibs > 0 && (
                <>
                  {' '}
                  {view.droppedBinaries} ELF file{view.droppedBinaries === 1 ? '' : 's'} and {view.droppedLibs} soname
                  {view.droppedLibs === 1 ? '' : 's'} are not drawn; every unresolved reference is in the table above
                  regardless of what the drawing had room for.
                </>
              )}
            </p>
          </section>

          <section style={{ marginTop: 22 }}>
            <div className="eyebrow" style={{ marginBottom: 8 }}>
              Orphan binaries · {orphans.length}
            </div>
            {orphans.length > 0 ? (
              <>
                <span className="cmap-chips">
                  {orphans.slice(0, ORPHAN_CAP).map((o) => (
                    <span key={o} className="cmap-chip mono">
                      {o}
                    </span>
                  ))}
                  {orphans.length > ORPHAN_CAP && (
                    <span className="hint">+{orphans.length - ORPHAN_CAP} more, listed alphabetically</span>
                  )}
                </span>
                <p className="hint cmap-prose" style={{ marginTop: 8 }}>
                  No <span className="mono">DT_NEEDED</span> entry in this rootfs names these. For a program that is
                  ordinary and not a verdict — a daemon, a CLI tool and a helper called from an init script are all
                  legitimately orphans in a link graph; what the list gives you is the set of <em>top-level</em>{' '}
                  executables, the things something outside this graph has to start.
                  {orphanLibs > 0 && (
                    <>
                      {' '}
                      {orphanLibs} of them are shared objects, and for those it says something else: nothing{' '}
                      <em>links</em> them, which usually means they are loaded with{' '}
                      <span className="mono">dlopen(3)</span> — invisible to this graph — and occasionally that nothing
                      uses them at all. This section does not decide which.
                    </>
                  )}
                </p>
              </>
            ) : (
              <p className="hint cmap-prose" style={{ margin: 0 }}>
                Every binary in this graph is named by another one. In a rootfs of any size that is unusual and worth a
                second look at the walk's bounds before reading it as a fact about the firmware.
              </p>
            )}
          </section>
        </>
      )}

      {load === 'ready' && (
        <section style={{ marginTop: 20 }}>
          {result?.reason && state === 'graph' && (
            <p className="hint cmap-prose" style={{ margin: '0 0 10px' }}>
              Provider: {result.reason}
            </p>
          )}
          {error && (
            <div className="banner banner-warn" style={{ marginBottom: 10 }}>
              {error}
            </div>
          )}
          {/* Offered, but not while there is nothing to walk: the POST refuses that case, and a button whose only
              outcome is a refusal is a worse answer than the sentence already on screen. */}
          <button
            className="btn btn-sm"
            disabled={running || state === 'no-rootfs'}
            title={state === 'no-rootfs' ? 'Run extraction first — the map is built by walking the rootfs' : undefined}
            onClick={() => void run()}
          >
            {runLabel}
          </button>
        </section>
      )}
    </div>
  );
}
