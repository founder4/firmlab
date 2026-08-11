/**
 * kmod — the kernel-module surface. English source of truth.
 *
 * Two load-bearing strings, and neither may soften in translation.
 *
 * `windowOnly` is the bound on every call-site row: the pass reads a fixed window of instructions before a sink,
 * so "no comparison appears" is a statement about what is IN VIEW and never about the program. A bound enforced
 * in the caller is invisible to it. Without that sentence above the table, a list of unchecked allocations reads
 * as a list of kernel bugs.
 *
 * `provenanceNote` is the other one, and it exists because the corpus forced it: the `intree` tag is absent from
 * every module on the image this provider was built for, so its absence decides nothing there. A panel that
 * silently ranked by a signal the image does not carry would be inventing an ordering.
 */
export const kmod = {
  title: 'Kernel-module surface',
  sub: 'Every .ko under the rootfs: who wrote it, which kernel API it binds, and — for the modules that rank — where a length read off the wire reaches an allocator. The userland sweep excludes relocatable objects by construction, so until this existed the modules in a rootfs were counted and never read.',
  run: 'Run the sweep',
  rerun: 'Re-run',
  running: 'Running…',
  windowOnly:
    'A call-site row reports what the instructions BEFORE the call do — nothing more. "No comparison appears" means none appears in the window that was read; a bound enforced in the caller, or further back than the window reaches, is invisible here. Every such row is a LEAD naming a call site worth opening, and proves nothing about reachability or exploitability.',
  leadMark: (severity: string) => `${severity} if true — not established`,
  field: {
    modules: 'Modules found',
    examined: 'Disassembled',
    sites: 'Sink references',
    chased: 'Argument chased',
    hoisted: 'Address parked, not a call',
    unreadable: 'Symbol table unreadable',
  },
  provenance: {
    heading: 'Provenance signal',
    tagInUse:
      'The intree tag is in use on this image, so a module lacking it was genuinely built outside the kernel tree and the ranking uses that.',
    tagUnused:
      'NOT ONE module on this image carries an intree tag, so this build does not emit it and the tag decides nothing here — its absence is not evidence that a module is out-of-tree. The ranking falls back to the declared licence.',
    noLicence: 'No module on this image declares a licence either, so neither provenance key is available.',
  },
  hoistedNote: (n: number) =>
    `${n} sink reference${n === 1 ? ' was' : 's were'} the place a sink's address is materialised rather than called — the compiler parked it in a register and calls it elsewhere, so the instructions above it are not that call's argument setup and were not read as one.`,
  modulesDropped: (n: number) =>
    `${n} eligible module${n === 1 ? '' : 's'} ranked in and did not fit the disassembly budget, so ${n === 1 ? 'it is' : 'they are'} named rather than counted:`,
  sitesDropped: (n: number) =>
    `${n} sink reference${n === 1 ? '' : 's'} exceeded the per-module safety limit and ${n === 1 ? 'was' : 'were'} not examined.`,
  col: { finding: 'Row', kind: 'Kind' },
  topRanked: 'Highest-ranked modules',
  rankCol: { module: 'Module', licence: 'Licence', score: 'Score', api: 'Kernel API', sites: 'Sites' },
  empty: {
    notRun: 'The sweep has not been run for this image, so no kernel module here has been read.',
    unavailable: (reason: string) =>
      `The sweep could not run${reason ? `: ${reason}` : '.'} No kernel module was read, which is not the same as the kernel carrying none.`,
    noModules:
      'The rootfs carries no .ko files. A monolithic kernel with everything compiled in produces exactly this result, and so does a carve that missed lib/modules — the two are not distinguished here.',
    noRows: (modules: number) =>
      `${modules} module${modules === 1 ? ' was' : 's were'} read and none produced a row. That bounds this sweep's questions only — a module that binds no socket API, and every bug class this pass does not ask about, are outside it.`,
    passUnavailable: (reason: string) =>
      `The call-site pass did not run: ${reason} The inventory below still stands; what is missing is where a wire-order length reaches an allocator, and its absence is a gap rather than a clean result.`,
  },
};
