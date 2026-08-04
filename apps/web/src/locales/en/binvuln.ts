/**
 * binvuln — the binary-hardening sweep. English source of truth.
 *
 * `leadsOnly` is the load-bearing string and must not soften in translation. Every row this sweep produces is a
 * SYNTACTIC candidate — an import of an unsafe call plus no stack canary — and its findings carry
 * `needs_runtime_reproduction`. A table of red rows reads as a table of bugs unless something says otherwise
 * before it, so that sentence sits above the table rather than under it.
 *
 * `cutRule` states what the cap dropped and by what rule, because a bound that does not say what it cut is a bound
 * presented as an answer.
 */
export const binvuln = {
  title: 'Binary hardening sweep',
  sub: 'Every ELF under the rootfs, read for unsafe calls against the mitigations compiled into it. This is the second-largest source of rows in the ledger and, until it had a route, its own result reached no reader.',
  run: 'Run the sweep',
  rerun: 'Re-run',
  running: 'Running…',
  leadsOnly:
    'Every row here is a LEAD, not a bug. The sweep is syntactic — an unsafe call imported and no stack canary — so nothing below was executed and nothing was proven reachable from an input. Turning one into a verdict is symbolic reachability or a reproduced crash, and both live elsewhere.',
  leadMark: (severity: string) => `${severity} if true — not established`,
  field: {
    scanned: 'Binaries walked',
    candidates: 'Stack-overflow candidates',
    listed: 'Findings listed',
    relocatable: 'Relocatable, skipped',
    neutered: 'Cut by the extractor',
  },
  exposedDropped: (n: number) =>
    `${n} of them are network-exposed and still did not fit, so they are named rather than counted:`,
  col: { finding: 'Candidate', kind: 'Kind' },
  empty: {
    notRun: 'The sweep has not been run for this image, so no binary here has been examined.',
    unavailable: (reason: string) =>
      `The sweep could not run${reason ? `: ${reason}` : '.'} No binary was examined, which is not the same as no binary being weak.`,
    noCandidates: (scanned: number) =>
      `${scanned} binar${scanned === 1 ? 'y was' : 'ies were'} walked and none matched the sweep's precondition. That bounds this sweep's question only — an unsafe call with a canary present, and every bug class this sweep does not ask about, are outside it.`,
  },
};
