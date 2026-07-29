/**
 * compmap — the rootfs link-dependency panel. English source of truth.
 *
 * **Why several keys make up one sentence.** A `DT_NEEDED`, a `rabin2`, a `dlopen(3)` and a soname are identifiers:
 * they render in `mono` and they are never translated. A sentence containing one is therefore stored as the runs of
 * prose AROUND it, in render order, and the panel puts the identifier back between them. The keys are named for the
 * token that follows, so a translator can see the shape at a glance — and each language still owns the whole of its
 * own wording, including where in the clause the identifier has to sit.
 *
 * **The sentence this namespace exists for** is `unresolved.notMissing` and the paragraph under it. "Unresolved" is
 * a statement about a BOUNDED walk, not about the firmware: the file and ELF caps stop early on a large rootfs, and
 * a library past the cut is reported unresolved by every binary that names it (measured on the GL.iNet: 4,000 of
 * 6,496 files walked, so a real 590 KB `lib/libc.so` that 298 binaries need was never seen). A rendering that turns
 * that bound into an absence tells the reader the rootfs is broken when it is the analysis that was cut short.
 */
export const compmap = {
  title: 'Component map',

  /** Around `DT_NEEDED` · `<em>linker</em>` · `rabin2` · `dlopen(3)`, in this order. */
  sub: {
    beforeNeeded: 'Every ELF in the extracted rootfs mapped to the shared objects its',
    beforeLinker: 'entries name — what the',
    linker: 'linker',
    beforeRabin2: 'recorded, read out of the bytes with',
    beforeDlopen: '. A library the program opens with',
    afterDlopen:
      'at runtime leaves no such entry and no edge here, so silence in this graph is silence about linking, not ' +
      'about loading. It is structure, not a security verdict.',
  },

  /** Each kind of nothing gets its own sentence — the conflation this codebase has already shipped once. */
  notRun: {
    title: 'No component map has been built for this image',
    body:
      'Nothing has asked what this rootfs links against, so there is nothing to show — which is a statement about ' +
      'this workbench, not about the firmware. Build it and the answer, including an empty one, will say so.',
  },
  noRootfs: {
    title: 'There is no extracted rootfs to map',
    body:
      'The map is built by walking the files extraction wrote to disk, and this image has none to walk. That is a ' +
      'gap in the extraction, not a firmware that links nothing — run extraction first from the Extraction section.',
    /** Precedes the extraction's own verdict, which is printed as the extraction recorded it. */
    extractionSays: 'Extraction says:',
  },
  unavailable: {
    title: 'The map could not be built — the question was not answered.',
    noReason: 'The provider reported itself unavailable and gave no reason.',
    body:
      'Nothing below is a finding about this firmware: an absent tool is an absent answer, not an absent ' +
      'dependency.',
  },
  empty: {
    title: 'The map was built and the graph is empty',
    beforeNeeded: 'The walk ran over the rootfs and came back with no ELF carrying a',
    afterNeeded:
      'entry. That is a real answer, and a plausible one — a busybox-only or fully static rootfs links nothing ' +
      'dynamically. It is not the same as nobody having looked.',
  },

  stat: {
    walked: 'ELF binaries walked',
    edges: 'Link edges',
    unresolved: 'Unresolved references',
  },

  /** Around `DT_NEEDED` and the `busybox` example; `<strong>basename</strong>` is the emphasised word. */
  basename: {
    lead: 'A node is a',
    word: 'basename',
    beforeNeeded: ', because a',
    beforeExample: 'reference is one — two files called',
    afterExample: 'in different directories are one node.',
    /** Rendered only when the two counts actually differ — see the test that pins that. */
    collapse: (files: number, nodes: number) => `Here that collapses ${files} ELF files into ${nodes} nodes.`,
  },
  /** Around `rabin2`. */
  linksNothing: {
    lead: (n: number) => `${n} of them name no shared object at all — statically linked, or an ELF`,
    tail: 'could not read.',
  },

  unresolved: {
    heading: (n: number) => `Unresolved libraries · ${n}`,
    colSoname: 'Soname referenced',
    colCount: 'Count',
    colNamedBy: 'Named by',
    notMissing: 'Unresolved is not missing.',
    caveat:
      'A soname provided by a symlink now resolves and is labelled as link-provided — the walk still refuses to ' +
      "follow a link, it reads the link's target name and matches that inside the carve, so a rootfs escape stays " +
      'impossible. What is left here is either genuinely absent or',
    bounds: 'outside this extraction',
    /**
     * Rewritten when the walk stopped being capped. It used to blame "the file and ELF caps", which was true and
     * is not any more: indexing a name costs a `readdir`, so the walk now covers the whole tree. Only the
     * `rabin2` pass is still bounded, and an ELF it did not open is INDEXED BY NAME and still resolves — so what
     * a cut costs is the edges out of that file, never a soname wrongly called absent. Saying otherwise blamed
     * the firmware for a bound of ours.
     */
    caveatTail:
      ': resolution is by basename against this carve alone, so a partial extraction, a second partition or an ' +
      'overlay mounted at boot are all libraries the device has and this image does not. The expensive pass is ' +
      'still bounded, but a file it did not open is still indexed by name and still resolves — a cut costs the ' +
      'libraries THAT file links, never a soname wrongly reported absent. Open the file browser before treating ' +
      'a row here as a missing library.',
    /** Around `DT_NEEDED`. Self-consistent is not complete, and the sentence has to say both. */
    noneLead: 'Every',
    noneTail:
      'reference in this rootfs names a file the walk also found. That says the carve is self-consistent for the ' +
      'binaries it recovered — not that the carve is complete.',
  },

  shape: {
    heading: 'Dependency shape',
    diagramTitle: 'Rootfs link-dependency diagram',
    diagramLabel: 'Rootfs link-dependency diagram: ELF files on the left, the sonames they name on the right',
    colElf: 'ELF file',
    nodeTitle: (id: string, degree: number, unresolved: number) =>
      `${id} — links ${degree} shared object(s), ${unresolved} unresolved`,
    libTitle: (id: string, degree: number, present: boolean) =>
      `${id} — named by ${degree} binary/binaries, ${present ? 'present in the carve' : 'NOT present in the carve'}`,
    legendBin: 'ELF file in the carve',
    legendLib: 'soname the carve has',
    legendUnres: 'soname it does not',
    legendCounts: (bins: number, binsAll: number, libs: number, libsAll: number) =>
      `${bins} of ${binsAll} linking files · ${libs} of ${libsAll} referenced sonames`,
    /** A bound is not an answer: it states what it dropped and by what rule, and it is rendered always. */
    rule: 'Ranked with unresolved references first, then by number of links, then by name — never by directory order.',
    dropped: (bins: number, libs: number) =>
      [
        `${bins} ELF file${bins === 1 ? '' : 's'} and ${libs} soname${libs === 1 ? '' : 's'} are not drawn;`,
        'every unresolved reference is in the table above regardless of what the drawing had room for.',
      ].join(' '),
  },

  orphans: {
    heading: (n: number) => `Orphan binaries · ${n}`,
    moreAlphabetical: (n: number) => `+${n} more, listed alphabetically`,
    /** Around `DT_NEEDED` and the emphasised `top-level`. An orphan is not a verdict, and the prose says so. */
    lead: 'No',
    beforeTopLevel:
      'entry in this rootfs names these. For a program that is ordinary and not a verdict — a daemon, a CLI tool ' +
      'and a helper called from an init script are all legitimately orphans in a link graph; what the list gives ' +
      'you is the set of',
    topLevel: 'top-level',
    afterTopLevel: 'executables, the things something outside this graph has to start.',
    /** An orphaned `.so` is a different claim from an orphaned program, and gets its own clause. */
    libsLead: (n: number) => `${n} of them are shared objects, and for those it says something else: nothing`,
    links: 'links',
    beforeDlopen: 'them, which usually means they are loaded with',
    afterDlopen:
      '— invisible to this graph — and occasionally that nothing uses them at all. This section does not decide ' +
      'which.',
    none:
      'Every binary in this graph is named by another one. In a rootfs of any size that is unusual and worth a ' +
      "second look at the walk's bounds before reading it as a fact about the firmware.",
  },

  providerLabel: 'Provider:',
  build: 'Build component map',
  rebuild: 'Rebuild map',
  needsRootfs: 'Run extraction first — the map is built by walking the rootfs',
  jobFailed: 'The component map job failed.',
};
