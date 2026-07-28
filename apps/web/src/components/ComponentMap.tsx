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
 *   • the walk is BOUNDED — a file cap and an ELF cap stop it early on a large rootfs, and a library past the cut
 *     is reported unresolved by every binary that references it. Measured on the GL.iNet: the walk reached 4,000 of
 *     6,496 files, so a real 590 KB `lib/libc.so` that 298 binaries need was never seen. That is the dominant
 *     source of false entries here, and the result says so via its truncation flag;
 *   • resolution is by basename against what the carve recovered, and a partial carve, a second partition, or a
 *     vendor overlay mounted at boot are all libraries the device has and this image does not.
 * A missing library is a hypothesis to check in the file browser, never a finding.
 *
 * The symlink case USED to head this list and no longer does. The provider now reads a link's target name — never
 * following it, so loops and rootfs escapes stay impossible — and resolves it lexically inside the carve, which is
 * a weaker fact than a walked file and is labelled `link` rather than folded into `binary`. That alone took the
 * IMOU from 2 unresolved to 0 and the GL.iNet from 143 to 65, and the 65 that remain are the cap above.
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
 *
 * Sonames, `DT_NEEDED`, `rabin2`, `dlopen(3)` and every file name are identifiers: they render in `mono` and are
 * never translated. That is why several sentences arrive from the catalogue as the runs of prose either side of an
 * identifier — one key per run, in render order — and why the panel is what puts the identifier back between them.
 * The paragraph the section exists for, "unresolved is not missing", is the one that must survive that treatment
 * intact in every language: it explains a BOUND, and a bound rendered as an absence blames the firmware for a walk
 * that was cut short.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { type CompGraph, type CompMapResult, type ExtractionBrowseView, api } from '../api';
import { messages, useMessages } from '../i18n';

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
  /**
   * The sentence stating what was left out and by what rule. Rendered always, not only when something was cut.
   *
   * It travels with the selection rather than being assembled at the render site, because a bound that states what
   * it dropped is part of the answer — and a rule a test cannot call is a rule held on trust. It reads the active
   * catalogue through `messages()`, which is what that accessor exists for.
   */
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
    rule: messages().compmap.shape.rule,
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
  const t = useMessages();
  const [hover, setHover] = useState<string | null>(null);
  const rows = Math.max(view.binaries.length, view.libs.length, 1);
  const height = TOP_PAD + rows * ROW_H + 14;
  const yOf = (i: number): number => TOP_PAD + i * ROW_H + ROW_H / 2;
  const binY = new Map(view.binaries.map((n, i) => [n.id, yOf(i)]));
  const libY = new Map(view.libs.map((n, i) => [n.id, yOf(i)]));
  const lit = (e: { from: string; to: string }): boolean => hover === null || hover === e.from || hover === e.to;

  return (
    <div className="cmap-canvas">
      <svg className="cmap-svg" viewBox={`0 0 ${SVG_W} ${height}`} role="img" aria-label={t.compmap.shape.diagramLabel}>
        <title>{t.compmap.shape.diagramTitle}</title>
        {/* "ELF file", not "binary": on a real rootfs the left column fills with `.so` files, because a shared
            object that names another one is itself an ELF the walk found. Labelling it "binary" made the drawing
            look wrong against the Tenda carve when it was in fact correct. */}
        <text className="cmap-colhead" x={COL_L_END} y={18} textAnchor="end">
          {t.compmap.shape.colElf}
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
            <title>{t.compmap.shape.nodeTitle(n.id, n.degree, n.unresolved)}</title>
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
            <title>{t.compmap.shape.libTitle(n.id, n.degree, !n.unresolved)}</title>
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
  const t = useMessages();
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
          if (j.status === 'error') setError(j.error ?? t.compmap.jobFailed);
          await refresh();
        }
      }, 700);
    } catch (e) {
      // The POST refuses with a sentence when there is no rootfs to map. That sentence is the answer, not noise.
      setRunning(false);
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [imageId, refresh, t]);

  const graph = result?.graph;
  const state = compMapState(result, extraction);
  // `t` is a dependency because the view carries the rule SENTENCE: memoised on the graph alone, a locale switch
  // would leave the one line explaining what the drawing dropped in the language it was computed under.
  const view = useMemo(() => selectGraphView(graph), [graph, t]);
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

  const runLabel = running ? <span className="spinner" /> : result ? t.compmap.rebuild : t.compmap.build;

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">{t.compmap.title}</div>
      <div className="panel-sub">
        {t.compmap.sub.beforeNeeded} <span className="mono">DT_NEEDED</span> {t.compmap.sub.beforeLinker}{' '}
        <em>{t.compmap.sub.linker}</em> {t.compmap.sub.beforeRabin2} <span className="mono">rabin2</span>
        {t.compmap.sub.beforeDlopen} <span className="mono">dlopen(3)</span> {t.compmap.sub.afterDlopen}
      </div>

      {load === 'loading' && <div className="skeleton" style={{ height: 120, marginTop: 14 }} />}

      {load === 'ready' && state === 'not-run' && (
        <div className="cmap-nothing" data-state="not-run">
          <strong>{t.compmap.notRun.title}</strong>
          <span className="hint cmap-prose">{t.compmap.notRun.body}</span>
        </div>
      )}

      {load === 'ready' && state === 'no-rootfs' && (
        <div className="cmap-nothing" data-state="no-rootfs">
          <strong>{t.compmap.noRootfs.title}</strong>
          <span className="hint cmap-prose">
            {t.compmap.noRootfs.body}
            {/* The extraction's own verdict, quoted as it recorded it — this panel never re-words another's answer. */}
            {extraction?.verdict && (
              <>
                {' '}
                {t.compmap.noRootfs.extractionSays} <em>{extraction.verdict}</em>
              </>
            )}
          </span>
        </div>
      )}

      {load === 'ready' && state === 'unavailable' && (
        <div className="banner banner-warn" style={{ marginTop: 14 }}>
          <div>
            <strong>{t.compmap.unavailable.title}</strong>
            <div className="hint cmap-prose" style={{ marginTop: 4 }}>
              {result?.reason ?? t.compmap.unavailable.noReason} {t.compmap.unavailable.body}
            </div>
          </div>
        </div>
      )}

      {load === 'ready' && state === 'empty' && (
        <div className="cmap-nothing" data-state="empty">
          <strong>{t.compmap.empty.title}</strong>
          <span className="hint cmap-prose">
            {t.compmap.empty.beforeNeeded} <span className="mono">DT_NEEDED</span> {t.compmap.empty.afterNeeded}
            {result?.reason && (
              <>
                {' '}
                {t.compmap.providerLabel} <em>{result.reason}</em>
              </>
            )}
          </span>
        </div>
      )}

      {state === 'graph' && (
        <>
          <div className="grid grid-3" style={{ marginTop: 16 }}>
            <div className="stat">
              <div className="stat-label">{t.compmap.stat.walked}</div>
              <div className="stat-value">{result?.binaryCount ?? binaryNodes}</div>
            </div>
            <div className="stat">
              <div className="stat-label">{t.compmap.stat.edges}</div>
              <div className="stat-value">{(graph?.edges ?? []).length}</div>
            </div>
            <div className="stat">
              <div className="stat-label">{t.compmap.stat.unresolved}</div>
              <div className="stat-value" style={{ color: unresolved.size > 0 ? 'var(--warn)' : undefined }}>
                {unresolved.size}
              </div>
            </div>
          </div>

          <p className="hint cmap-prose" style={{ marginTop: 10 }}>
            {t.compmap.basename.lead} <strong>{t.compmap.basename.word}</strong>
            {t.compmap.basename.beforeNeeded} <span className="mono">DT_NEEDED</span> {t.compmap.basename.beforeExample}{' '}
            <span className="mono">busybox</span> {t.compmap.basename.afterExample}
            {/* Only when the two counts actually differ. The first version stated the discrepancy unconditionally
                and rendered "67 files walked can become 67 binary nodes" against the real Tenda carve — a sentence
                explaining something that had not happened. Caught by looking at the page, not by a test. */}
            {filesWalked !== binaryNodes && <> {t.compmap.basename.collapse(filesWalked, binaryNodes)}</>}
            {linksNothing > 0 && (
              <>
                {' '}
                {t.compmap.linksNothing.lead(linksNothing)} <span className="mono">rabin2</span>{' '}
                {t.compmap.linksNothing.tail}
              </>
            )}
          </p>

          {/* The point of the section, above the picture: a hairball is exactly where this row would be lost. */}
          <section style={{ marginTop: 20 }}>
            <div className="eyebrow" style={{ marginBottom: 8 }}>
              {t.compmap.unresolved.heading(unresolved.size)}
            </div>
            {neededBy.length > 0 ? (
              <>
                <div style={{ overflowX: 'auto' }}>
                  <table className="data">
                    <thead>
                      <tr>
                        <th>{t.compmap.unresolved.colSoname}</th>
                        <th className="num">{t.compmap.unresolved.colCount}</th>
                        <th>{t.compmap.unresolved.colNamedBy}</th>
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
                                <span className="hint">{t.common.andMore(row.bins.length - NEEDED_BY_CAP)}</span>
                              )}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {/* The bound, stated where the rows are, not in a legend: a reader who does not know the walk is
                    capped reads this table as a broken rootfs. */}
                <p className="hint cmap-prose" style={{ marginTop: 8 }}>
                  <strong>{t.compmap.unresolved.notMissing}</strong> {t.compmap.unresolved.caveat}{' '}
                  <em>{t.compmap.unresolved.bounds}</em>
                  {t.compmap.unresolved.caveatTail}
                </p>
              </>
            ) : (
              <p className="hint cmap-prose" style={{ margin: 0 }}>
                {t.compmap.unresolved.noneLead} <span className="mono">DT_NEEDED</span> {t.compmap.unresolved.noneTail}
              </p>
            )}
          </section>

          <section style={{ marginTop: 22 }}>
            <div className="eyebrow" style={{ marginBottom: 8 }}>
              {t.compmap.shape.heading}
            </div>
            <DependencyDiagram view={view} />
            <div className="legend" style={{ marginTop: 10 }}>
              <span className="legend-item">
                <span className="legend-swatch cmap-sw-bin" />
                {t.compmap.shape.legendBin}
              </span>
              <span className="legend-item">
                <span className="legend-swatch cmap-sw-lib" />
                {t.compmap.shape.legendLib}
              </span>
              <span className="legend-item">
                <span className="legend-swatch cmap-sw-unres" />
                {t.compmap.shape.legendUnres}
              </span>
              <span className="legend-item" style={{ marginLeft: 'auto', color: 'var(--text-faint)' }}>
                {t.compmap.shape.legendCounts(
                  view.binaries.length,
                  view.binaries.length + view.droppedBinaries,
                  view.libs.length,
                  view.libs.length + view.droppedLibs,
                )}
              </span>
            </div>
            <p className="hint cmap-prose" style={{ marginTop: 6 }}>
              {view.rule}
              {/* A string rather than a fragment, so the separating space survives without a wrapper element. */}
              {view.droppedBinaries + view.droppedLibs > 0 &&
                ` ${t.compmap.shape.dropped(view.droppedBinaries, view.droppedLibs)}`}
            </p>
          </section>

          <section style={{ marginTop: 22 }}>
            <div className="eyebrow" style={{ marginBottom: 8 }}>
              {t.compmap.orphans.heading(orphans.length)}
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
                    <span className="hint">{t.compmap.orphans.moreAlphabetical(orphans.length - ORPHAN_CAP)}</span>
                  )}
                </span>
                <p className="hint cmap-prose" style={{ marginTop: 8 }}>
                  {t.compmap.orphans.lead} <span className="mono">DT_NEEDED</span> {t.compmap.orphans.beforeTopLevel}{' '}
                  <em>{t.compmap.orphans.topLevel}</em> {t.compmap.orphans.afterTopLevel}
                  {orphanLibs > 0 && (
                    <>
                      {' '}
                      {t.compmap.orphans.libsLead(orphanLibs)} <em>{t.compmap.orphans.links}</em>{' '}
                      {t.compmap.orphans.beforeDlopen} <span className="mono">dlopen(3)</span>{' '}
                      {t.compmap.orphans.afterDlopen}
                    </>
                  )}
                </p>
              </>
            ) : (
              <p className="hint cmap-prose" style={{ margin: 0 }}>
                {t.compmap.orphans.none}
              </p>
            )}
          </section>
        </>
      )}

      {load === 'ready' && (
        <section style={{ marginTop: 20 }}>
          {result?.reason && state === 'graph' && (
            <p className="hint cmap-prose" style={{ margin: '0 0 10px' }}>
              {t.compmap.providerLabel} {result.reason}
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
            title={state === 'no-rootfs' ? t.compmap.needsRootfs : undefined}
            onClick={() => void run()}
          >
            {runLabel}
          </button>
        </section>
      )}
    </div>
  );
}
