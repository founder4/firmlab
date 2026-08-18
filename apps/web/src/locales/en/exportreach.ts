/**
 * exportreach — the export-reachability surface. English source of truth.
 *
 * Two strings carry the whole honesty contract and neither may soften in translation.
 *
 * `caveat` is the ceiling on every `reachable` row: a route through the RECOVERED call graph is not a feasible
 * path — nothing checks the branch conditions along it can hold together — so it is strictly weaker than
 * `symreach`'s `reached`, and it is never a proof of exploitability. Without it, a reachable-sink row reads as a
 * proven bug.
 *
 * `blockedBody` is the other: an empty graph is a FAILURE TO ANALYSE, not a clean object. 45% of this corpus's
 * shared objects are section-stripped and yield exactly this, and silent it would read identically to a library
 * that was analysed and found clean — which is the one distinction this surface exists to keep.
 */
export const exportreach = {
  title: 'Export reachability',
  sub: 'For a shared object or a kernel module — the targets symreach refuses, because neither has an entry point to explore from. It recovers the control-flow graph and asks whether a sink lies on a route from a function an outsider can invoke. A route in the code, not a feasible one: strictly weaker than symbolic reachability, and never a clean bill when it finds nothing.',
  binaryPlaceholder: 'lib/modules/…/NetUSB.ko or usr/lib/libfoo.so',
  sinksPlaceholder: 'sinks (blank ⇒ by target class)',
  sinksLabel: 'Sink symbols to ask about, comma or space separated',
  budget: 'budget',
  budgetLabel: 'Per-run budget in seconds',
  ask: 'Ask',
  probing: 'Recovering…',
  hint: 'A .ko is asked the kernel vocabulary (__kmalloc, copy_from_user), a .so the userland one (strcpy, system). Blank uses the set for the target class; an absent symbol costs microseconds, so a default set is cheaper than a guess.',
  probeFailed: 'The probe failed. Nothing was concluded about this object.',
  notAnswered: 'No reachability question was asked',
  notAnsweredHint: (binary?: string) =>
    `${binary ? `${binary}: ` : ''}this is a missing capability, not a statement that the object carries no reachable sink.`,
  unknownArch: 'arch unknown',
  summary: (fns: number, entries: number, reachable: number, asked: number) =>
    `${fns} function(s) recovered · ${entries} entry point(s) · ${reachable} of ${asked} sink(s) reachable`,
  cfgSeconds: (s: number) => `graph in ${s}s`,
  blockedHeading: 'Could not analyse',
  blockedBody:
    'The control-flow graph came back empty, so no reachability question could be asked. On this corpus that means the object carries no section headers — CFG recovery finds nothing without them, with or without a complete scan. This is a boundary of the tool, NOT a statement that the object is free of reachable sinks, and it must not be read as one.',
  outcome: {
    reachable: 'reachable',
    not_reached: 'not reached',
    absent: 'absent',
    no_call_site: 'no call site',
    budget_exhausted: 'budget spent',
  },
  reachableDetail: (from: number, entries: number, holders: number) =>
    `${from} of ${entries} entry point(s) reach one of ${holders} holder function(s)`,
  sample: (names: string, more: number) => `e.g. ${names}${more > 0 ? ` (+${more} more)` : ''}`,
  notReachedNote:
    'A sink not reached is NOT a sink that cannot be reached: CFGFast leaves indirect calls unresolved, and both shared objects and kernel modules are built on them.',
  caveat: {
    lead: 'A reachable sink here is a lead, held at',
    tail: '. A route exists in the code, but nothing checks the branch conditions along it can be satisfied together — strictly weaker than symreach, and never a proof of exploitability.',
  },
  runLabel: 'Export-reachability runs',
  notRun: 'No export-reachability probe has been run for this image, so no library or module here has been asked.',
};
