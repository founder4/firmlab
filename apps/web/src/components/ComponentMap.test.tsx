import { render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type CompGraph, type CompMapResult, type ExtractionBrowseView, type FilesListing, api } from '../api';
import { setLocale } from '../i18n';
import { mockedApi } from '../test-api-mock';
import {
  ComponentMap,
  compMapState,
  looksLikeSharedObject,
  middleTruncate,
  orphanBinaries,
  selectGraphView,
  unresolvedSonames,
} from './ComponentMap';

vi.mock('../api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api')>();
  const { buildApiMock } = await import('../test-api-mock');
  return { ...actual, api: buildApiMock(actual.api) };
});

const mockApi = mockedApi(api);

const extraction = (state: ExtractionBrowseView['state'], verdict: string): ExtractionBrowseView => ({
  state,
  browsable: state === 'rootfs',
  verdict,
  ...(state === 'rootfs' ? { rootfsRel: 'squashfs-root' } : {}),
});

const filesFor = (e: ExtractionBrowseView): FilesListing => ({ extraction: e, listing: null, claim: '' });

const ROOTFS = extraction('rootfs', "Extraction recovered a rootfs at 'squashfs-root'.");
const NO_OUTPUT = extraction('no-output', 'Extraction ran and wrote nothing — binwalk recognised no filesystem.');

/**
 * A uClibc router rootfs of the shape compmap actually produces. Two properties of it matter and both are real:
 *
 *  • `libc.so.0` is UNRESOLVED even though every such rootfs has a libc. Two causes of that have since been fixed
 *    in the provider — the symlink case (a soname normally IS a link, and link targets are now read by name) and
 *    the walk's file cap (naming costs a `readdir`, so the walk is no longer capped; that alone took the GL.iNet
 *    from 65 unresolved to 0). The fixture stays unresolved on purpose, because the ROW did not go away with them:
 *    a library genuinely outside the carve reports exactly like this — the real Tenda still names
 *    `libcrypto.so.1.0.0` against a carve that ships `libcrypto.so.1.1` — and so does every result stored by an
 *    older build. A fixture that resolved it would agree with the current provider and stop exercising the caveat
 *    the panel exists to carry.
 *  • six ELF FILES become five binary nodes — `bin/busybox` and `sbin/busybox` collapse, since a node is a
 *    basename. That is what makes `binaryCount` and the node count legitimately disagree.
 */
const graph = (): CompGraph => ({
  nodes: [
    { id: 'httpd', kind: 'binary' },
    { id: 'busybox', kind: 'binary' },
    { id: 'dropbear', kind: 'binary' },
    { id: 'libgcc_s.so.1', kind: 'binary' },
    { id: 'init', kind: 'binary' },
    { id: 'libssl.so.1.1', kind: 'lib' },
    { id: 'libcrypto.so.1.1', kind: 'lib' },
    { id: 'libc.so.0', kind: 'lib' },
    { id: 'libutil.so.0', kind: 'lib' },
  ],
  edges: [
    { from: 'httpd', to: 'libssl.so.1.1' },
    { from: 'httpd', to: 'libcrypto.so.1.1' },
    { from: 'httpd', to: 'libc.so.0' },
    { from: 'httpd', to: 'libgcc_s.so.1' },
    { from: 'busybox', to: 'libc.so.0' },
    { from: 'dropbear', to: 'libc.so.0' },
    { from: 'dropbear', to: 'libutil.so.0' },
    { from: 'libgcc_s.so.1', to: 'libc.so.0' },
  ],
  unresolved: ['libssl.so.1.1', 'libcrypto.so.1.1', 'libc.so.0', 'libutil.so.0'],
});

const result = (o: Partial<CompMapResult> = {}): CompMapResult => ({
  available: true,
  graph: graph(),
  binaryCount: 6,
  findings: [],
  reason: 'Mapped 6 ELF binaries to their shared-library dependencies (4 external libraries, 4 unresolved).',
  ...o,
});

beforeEach(() => {
  // Reset BEFORE the render, never after it: the locale store notifies live subscribers, so switching back in an
  // `afterEach` re-renders a still-mounted tree and fills the suite with act(…) warnings.
  setLocale('en');
  mockApi.files.mockResolvedValue(filesFor(ROOTFS));
});

describe('compMapState — the several different nothings, kept apart', () => {
  it('separates "nobody built it" from "there is no rootfs" from "it was built and is empty"', () => {
    expect(compMapState(null, ROOTFS)).toBe('not-run');
    expect(compMapState(null, NO_OUTPUT)).toBe('no-rootfs');
    expect(compMapState({ available: true, graph: { nodes: [], edges: [], unresolved: [] } }, ROOTFS)).toBe('empty');
  });

  it('an unavailable tool over a real rootfs is its own state, not an empty graph', () => {
    const blocked = { available: false, reason: 'radare2 (rabin2) not installed — component map needs it.' };
    expect(compMapState(blocked, ROOTFS)).toBe('unavailable');
    // …and the same result over a rootfs-less image is the rootfs answer, which is the actionable one.
    expect(compMapState(blocked, NO_OUTPUT)).toBe('no-rootfs');
  });

  it('draws a stored graph whatever the extraction looks like now, and never guesses when it is unknown', () => {
    expect(compMapState(result(), NO_OUTPUT)).toBe('graph');
    // `null` extraction means the state could not be READ — which is not knowing there is no rootfs.
    expect(compMapState(null, null)).toBe('not-run');
  });
});

describe('unresolvedSonames / orphanBinaries — read defensively', () => {
  it('uses the provider’s own list when it is there', () => {
    expect([...unresolvedSonames(graph())].sort()).toEqual([
      'libc.so.0',
      'libcrypto.so.1.1',
      'libssl.so.1.1',
      'libutil.so.0',
    ]);
  });

  it('recovers the identical set from the lib nodes when a stored result predates the field', () => {
    const { unresolved: _absent, ...older } = graph();
    expect([...unresolvedSonames(older)].sort()).toEqual([...unresolvedSonames(graph())].sort());
  });

  it('returns empty rather than throwing for a graph, or a whole result, that carries nothing', () => {
    expect([...unresolvedSonames(undefined)]).toEqual([]);
    expect([...unresolvedSonames({})]).toEqual([]);
    expect(orphanBinaries(undefined)).toEqual([]);
    expect(orphanBinaries({})).toEqual([]);
  });

  it('names the binaries nothing links against, and only those', () => {
    // libgcc_s.so.1 is a binary node WITH an incoming edge, so it is not a top-level executable.
    expect(orphanBinaries(graph())).toEqual(['busybox', 'dropbear', 'httpd', 'init']);
  });
});

describe('selectGraphView — the bound states what it dropped, and never drops the point', () => {
  it('keeps every edge when nothing is over the cap', () => {
    const v = selectGraphView(graph());
    expect(v.edges).toHaveLength(8);
    expect(v.droppedBinaries).toBe(0);
    expect(v.droppedLibs).toBe(0);
  });

  it('ranks unresolved libraries ahead of resolved ones, then by in-degree', () => {
    const v = selectGraphView(graph());
    // libgcc_s.so.1 is the only resolved target, so it sorts last however many binaries name it.
    expect(v.libs.map((l) => l.id)).toEqual([
      'libc.so.0',
      'libcrypto.so.1.1',
      'libssl.so.1.1',
      'libutil.so.0',
      'libgcc_s.so.1',
    ]);
    expect(v.libs[v.libs.length - 1]?.unresolved).toBe(0);
  });

  it('a cap keeps the binaries that reference something unresolved, not the first ones off the walk', () => {
    // Six noisy binaries with many resolved links, and one with a single unresolved one. Arrival order puts the
    // interesting binary last; a cap of 2 that truncated by arrival would drop exactly the row worth drawing.
    const noisy: CompGraph = {
      nodes: [
        { id: 'quiet', kind: 'binary' },
        { id: 'libmissing.so.2', kind: 'lib' },
      ],
      edges: [
        ...['a', 'b', 'c'].flatMap((from) => [
          { from, to: 'libc.so.6' },
          { from, to: 'libm.so.6' },
          { from, to: 'libdl.so.2' },
        ]),
        { from: 'quiet', to: 'libmissing.so.2' },
      ],
      unresolved: ['libmissing.so.2'],
    };
    const v = selectGraphView(noisy, 2, 4);
    expect(v.binaries.map((b) => b.id)).toContain('quiet');
    expect(v.droppedBinaries).toBe(2);
    expect(v.rule).toMatch(/never by directory order/i);
  });
});

describe('looksLikeSharedObject', () => {
  it('matches a soname and rejects the `.socket` false neighbour, like parseNeeded does', () => {
    expect(looksLikeSharedObject('libc.so.0')).toBe(true);
    expect(looksLikeSharedObject('libplat_osal.so')).toBe(true);
    expect(looksLikeSharedObject('libstdc++.so.6.0.21')).toBe(true);
    expect(looksLikeSharedObject('dropbear')).toBe(false);
    expect(looksLikeSharedObject('foo.socket')).toBe(false);
  });
});

describe('middleTruncate', () => {
  it('keeps both ends of a soname, because the version is half its identity', () => {
    expect(middleTruncate('libcrypto.so.1.1', 32)).toBe('libcrypto.so.1.1');
    // Clipping the tail would leave `libreallyverylo…` — the same string for every version of that library.
    expect(middleTruncate('libreallyverylongname.so.1.1', 16)).toBe('libreall….so.1.1');
    expect(middleTruncate('libreallyverylongname.so.1.1', 16)).toHaveLength(16);
  });
});

describe('ComponentMap', () => {
  it('draws the graph — nodes, edges, and the two counts that legitimately disagree', async () => {
    mockApi.compmapResult.mockResolvedValue(result());
    const { container } = render(<ComponentMap imageId="447719f7" />);

    await screen.findByText('Link edges');
    // One path per edge, all eight inside the cap.
    expect(container.querySelectorAll('.cmap-edge')).toHaveLength(8);
    // Dashed/warn edges are the unresolved ones: httpd→ssl, httpd→crypto, httpd/busybox/dropbear/libgcc→libc, →util.
    expect(container.querySelectorAll('.cmap-edge.is-unresolved')).toHaveLength(7);
    expect(container.querySelector('.cmap-svg')).toBeTruthy();
    expect(screen.getByRole('img', { name: /link-dependency diagram/i })).toBeTruthy();
    // 6 ELF files, 5 binary nodes — the basename collapse, spelled out rather than left as an inconsistency.
    expect(screen.getByText(/collapses 6 ELF files into 5 nodes/i)).toBeTruthy();
    // A DT_NEEDED graph is not a runtime one, and the panel says so before it shows anything.
    expect(screen.getByText(/silence about linking, not about loading/i)).toBeTruthy();
  });

  it('puts the unresolved libraries in a table with who needs them, above the drawing', async () => {
    mockApi.compmapResult.mockResolvedValue(result());
    render(<ComponentMap imageId="447719f7" />);

    const table = within(await screen.findByRole('table'));
    expect(screen.getByText('Unresolved libraries · 4')).toBeTruthy();
    expect(table.getByText('libc.so.0')).toBeTruthy();
    expect(table.getByText('libssl.so.1.1')).toBeTruthy();
    expect(table.getByText('libutil.so.0')).toBeTruthy();
    // The row is only useful with its dependents named — that is what makes it actionable.
    expect(table.getAllByText('dropbear').length).toBeGreaterThan(0);
    // And the caveat that stops it being read as a broken rootfs: that a link-provided soname is resolved rather
    // than listed here, and that a bound can still put a library outside what this run opened. The walk's FILE cap
    // is no longer one of those bounds — it is uncapped, and the GL.iNet's 65 unresolved rows went to 0 with it —
    // so the catalogue sentence these two assertions read ("the file and ELF caps stop early on a large rootfs")
    // now overstates by exactly one cap. The wording lives in the message catalogue, not here.
    expect(screen.getByText(/Unresolved is not missing/i)).toBeTruthy();
    expect(screen.getByText(/refuses to follow a link/i)).toBeTruthy();
    expect(screen.getByText(/outside this extraction/i)).toBeTruthy();
  });

  it('lists orphan binaries as top-level executables, explicitly not as a verdict', async () => {
    mockApi.compmapResult.mockResolvedValue(result());
    render(<ComponentMap imageId="447719f7" />);

    expect(await screen.findByText('Orphan binaries · 4')).toBeTruthy();
    expect(screen.getByText(/legitimately orphans in a link graph/i)).toBeTruthy();
    // No orphan here is a `.so`, so the dlopen clause must not fire — it is a different claim about a different row.
    expect(screen.queryByText(/loaded with/i)).toBeNull();
  });

  /**
   * Caught by rendering the real Tenda-Camera carve: 55 of its orphans are `.so` files, and the first version of
   * this prose called all of them "top-level executables". Nothing links a `dlopen`ed plugin either.
   */
  it('does not call an orphaned shared object a top-level executable', async () => {
    mockApi.compmapResult.mockResolvedValue(
      result({
        graph: {
          nodes: [
            { id: 'httpd', kind: 'binary' },
            { id: 'libplat_osal.so', kind: 'binary' },
            { id: 'libc.so.0', kind: 'lib' },
          ],
          edges: [{ from: 'httpd', to: 'libc.so.0' }],
          unresolved: ['libc.so.0'],
        },
      }),
    );
    render(<ComponentMap imageId="tenda" />);

    expect(await screen.findByText('Orphan binaries · 2')).toBeTruthy();
    expect(screen.getByText(/1 of them are shared objects/i)).toBeTruthy();
    expect(screen.getByText(/This section does not decide which/i)).toBeTruthy();
  });

  /**
   * Also caught by looking: the basename note stated a discrepancy unconditionally and rendered "67 files walked
   * can become 67 binary nodes" for an image where nothing collapsed at all.
   */
  it('explains the basename collapse only when the two counts actually differ', async () => {
    mockApi.compmapResult.mockResolvedValue(result({ binaryCount: 5 }));
    render(<ComponentMap imageId="no-collapse" />);

    expect(await screen.findByText(/two files called/i)).toBeTruthy();
    expect(screen.queryByText(/collapses 5 ELF files into 5 nodes/i)).toBeNull();
  });

  it('a graph that was never built says nobody asked — never "nothing to show"', async () => {
    mockApi.compmapResult.mockResolvedValue(null);
    render(<ComponentMap imageId="fresh" />);

    expect(await screen.findByText(/No component map has been built for this image/i)).toBeTruthy();
    expect(screen.getByText(/a statement about this workbench, not about the firmware/i)).toBeTruthy();
    expect(screen.getByRole('button', { name: /Build component map/i })).not.toBeDisabled();
    // The other two nothings must not be on screen at the same time.
    expect(screen.queryByText(/There is no extracted rootfs to map/i)).toBeNull();
    expect(screen.queryByText(/the graph is empty/i)).toBeNull();
  });

  it('an image with no rootfs says so, quotes the extraction verdict, and offers no dead action', async () => {
    mockApi.compmapResult.mockResolvedValue(null);
    mockApi.files.mockResolvedValue(filesFor(NO_OUTPUT));
    render(<ComponentMap imageId="beanview" />);

    expect(await screen.findByText(/There is no extracted rootfs to map/i)).toBeTruthy();
    expect(screen.getByText(/binwalk recognised no filesystem/i)).toBeTruthy();
    expect(screen.getByText(/not a firmware that links nothing/i)).toBeTruthy();
    expect(screen.getByRole('button', { name: /Build component map/i })).toBeDisabled();
    expect(screen.queryByText(/No component map has been built/i)).toBeNull();
  });

  it('a map that ran and found nothing is a real answer, and reads as a third, different sentence', async () => {
    mockApi.compmapResult.mockResolvedValue(
      result({
        graph: { nodes: [], edges: [], unresolved: [] },
        binaryCount: 0,
        reason: 'Mapped 0 ELF binaries to their shared-library dependencies (0 external libraries, 0 unresolved).',
      }),
    );
    render(<ComponentMap imageId="static-rootfs" />);

    expect(await screen.findByText(/The map was built and the graph is empty/i)).toBeTruthy();
    expect(screen.getByText(/not the same as nobody having looked/i)).toBeTruthy();
    expect(screen.getByText(/Mapped 0 ELF binaries/)).toBeTruthy();
    expect(screen.queryByText(/No component map has been built/i)).toBeNull();
    expect(screen.queryByText(/There is no extracted rootfs to map/i)).toBeNull();
  });

  it('an absent tool is reported as an unanswered question, not as a rootfs that links nothing', async () => {
    mockApi.compmapResult.mockResolvedValue({
      available: false,
      graph: { nodes: [], edges: [], unresolved: [] },
      binaryCount: 0,
      findings: [],
      reason: 'radare2 (rabin2) not installed — component map needs it.',
    });
    render(<ComponentMap imageId="447719f7" />);

    expect(await screen.findByText(/could not be built — the question was not answered/i)).toBeTruthy();
    expect(screen.getByText(/an absent tool is an absent answer, not an absent dependency/i)).toBeTruthy();
  });

  /**
   * The crash this codebase already paid for once: a persisted result is data written by an OLDER build, and
   * `nvd.uncheckedIdentities.map` took the whole image view down for three of four images. Every one of these is a
   * result an older compmap could plausibly have stored.
   */
  it('renders a result written by an older build without throwing', async () => {
    const { unresolved: _gone, ...olderGraph } = graph();
    mockApi.compmapResult.mockResolvedValue({ available: true, graph: olderGraph });
    const { container, unmount } = render(<ComponentMap imageId="old-1" />);

    // The unresolved set is recovered from the lib nodes, so the point of the panel survives the missing field.
    expect(await screen.findByText('Unresolved libraries · 4')).toBeTruthy();
    // `binaryCount` is absent too — the node count stands in rather than rendering "undefined".
    expect(screen.queryByText(/undefined/)).toBeNull();
    expect(container.querySelectorAll('.cmap-edge')).toHaveLength(8);
    unmount();

    // A result with no graph at all, and one whose nodes carry no ids.
    mockApi.compmapResult.mockResolvedValue({ available: true, reason: 'stored before the graph was persisted' });
    const second = render(<ComponentMap imageId="old-2" />);
    expect(await screen.findByText(/The map was built and the graph is empty/i)).toBeTruthy();
    second.unmount();

    mockApi.compmapResult.mockResolvedValue({ available: true, graph: { nodes: [{}], edges: [{}] } });
    render(<ComponentMap imageId="old-3" />);
    await waitFor(() => expect(screen.getByRole('button', { name: /Rebuild map/i })).toBeTruthy());
  });
});

/**
 * "Unresolved is not missing" is the sentence this whole section exists to carry, and it is the one a translation
 * can silently invert: it explains a BOUND — the walk stopped, the library may well be there — and rendered as an
 * absence it blames the firmware for an analysis that was cut short. Both halves are asserted in Spanish, together
 * with the identifiers the prose is built around, which are never translated in any language.
 */
describe('ComponentMap — the unresolved caveat in Spanish', () => {
  it('keeps the caveat a statement about the walk, never about the rootfs', async () => {
    setLocale('es');
    mockApi.compmapResult.mockResolvedValue(result());
    const { container } = render(<ComponentMap imageId="447719f7" />);

    expect(await screen.findByText('Bibliotecas sin resolver · 4')).toBeTruthy();
    expect(screen.getByText(/Sin resolver no quiere decir ausente/i)).toBeTruthy();
    // The remaining honest cause: the row is outside THIS extraction, not missing from the device.
    expect(screen.getByText(/fuera de esta extracción/i)).toBeTruthy();
    const text = container.textContent ?? '';
    // The walk is no longer capped, so the caveat must no longer blame a cut for an unresolved row. What a cut
    // now costs is edges out of the file it skipped — an unopened ELF is still indexed by name and still
    // resolves. Both halves are asserted, because the first without the second reads as the old claim.
    expect(text).toContain('un fichero que no llegó a abrirse se indexa igualmente por nombre');
    expect(text).toContain('nunca un soname declarado ausente por error');
    // …and the drawing states its own bound and its rule, in Spanish, whether or not it cut anything.
    expect(text).toContain('nunca por el orden del directorio');

    // Identifiers survive translation: the soname, the linker record, and the tool that read it out of the bytes.
    expect(text).toContain('libc.so.0');
    expect(screen.getAllByText('DT_NEEDED').length).toBeGreaterThan(0);
    expect(screen.getAllByText('rabin2').length).toBeGreaterThan(0);
    expect(screen.getByText('dlopen(3)')).toBeTruthy();
  });

  it('keeps the several different nothings apart in Spanish too', async () => {
    setLocale('es');
    mockApi.compmapResult.mockResolvedValue(null);
    const { unmount } = render(<ComponentMap imageId="fresh" />);
    expect(await screen.findByText(/Nadie ha construido el mapa de componentes/i)).toBeTruthy();
    expect(screen.getByText(/sobre este banco de trabajo, no sobre el firmware/i)).toBeTruthy();
    expect(screen.queryByText(/el grafo está vacío/i)).toBeNull();
    unmount();

    mockApi.compmapResult.mockResolvedValue(
      result({ graph: { nodes: [], edges: [], unresolved: [] }, binaryCount: 0 }),
    );
    render(<ComponentMap imageId="static-rootfs" />);
    expect(await screen.findByText(/El mapa se construyó y el grafo está vacío/i)).toBeTruthy();
    // The distinction the whole panel is built on, and it has to hold in both languages.
    expect(screen.getByText(/No es lo mismo que si nadie hubiera mirado/i)).toBeTruthy();
  });
});
