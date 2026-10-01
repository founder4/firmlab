/**
 * The function-level diff panel in the Diff section. The sentences carry the distinction the provider draws: an
 * EMPTY list can mean "identical", "nothing comparable", or "withheld because the builds differ everywhere", and
 * those three must never share a sentence.
 */
export const funcdiff = {
  textTitle: 'Decompiled comparison',
  textSub:
    'Before/after excerpts from saved diff hunks, not full functions or vendor source. Decompiled changes can include tool noise and do not prove a security fix.',
  textMissing: 'This older saved result did not record decompiled comparisons.',
  textEmpty:
    'No decompiled comparisons were saved. Text is attempted only for a bounded set of changed functions; both sides must decompile.',
  before: 'Before (older baseline)',
  after: 'After (newer image)',
  unified: 'Saved unified diff',
  textTruncated: 'The provider omitted further hunks. This comparison is partial.',
  textDisplayBound: 'Display limited to 60 comparisons and 24,000 characters per diff.',
  noHunks: 'No changed hunks were saved for this comparison.',
  title: 'Function diff against a baseline',
  sub: 'Pairs binaries at the same path in both rootfs, fingerprints every function with radare2 and reports what changed. This image is the NEWER build; the image picked above is the older baseline. Both need a finished extraction.',
  run: 'Diff functions',
  running: 'Diffing functions…',
  chooseBaseline: 'Baseline image: choose one in the picker above before running the function diff.',
  loading: 'Loading the last function diff against this baseline…',
  none: 'No function diff has been run against this baseline yet. That says nothing about the firmware — run it.',

  outcome: {
    blocked: 'The function diff could not run — this is not a negative result. The provider’s reason is below.',
    identicalBytes: (n: number) =>
      `Identical: all ${n} binaries shared by both builds are byte-identical, so there is no code change to localize.`,
    identicalFunctions:
      'Identical: every compared binary pair is structurally the same at function granularity — no code change is visible at this level.',
    nothingComparable:
      'Nothing comparable: no binary pair had enough matched functions to judge a change. This is NOT “identical” — read each binary’s reason below.',
    notLocalized:
      'The builds differ too broadly to localize a change — a rebuild, not a patch — so the provider withholds the function list. This is NOT “no change”.',
    changes: (fns: number, bins: number) =>
      `${fns} changed function(s) across ${bins} binary pair(s) with a small, localized delta. A changed function is a code fact; whether any is a security fix is not something this diff can tell you.`,
  },

  stats: { changed: 'Changed', added: 'Added', removed: 'Removed', unmatched: 'Unmatched' },
  scope: (p: { paired: number; identical: number; analyzed: number }) =>
    `${p.paired} binaries in both builds · ${p.identical} byte-identical · ${p.analyzed} pair(s) compared`,
  unmatchable: (n: number) =>
    n === 0
      ? 'No function was left unmatched: each was paired, or reported as added or removed.'
      : `${n} function(s) could not be matched: their structural fingerprint was shared by several functions on one side, so pairing them would have been guesswork. They are counted, not compared — a change inside them would not appear here.`,
  notAnalyzed: (n: number) =>
    `${n} differing binary pair(s) were NOT compared — the per-run cap was reached, so this diff is incomplete.`,
  walkTruncated:
    'A rootfs walk stopped at its entry budget, so the binary counts are a floor rather than the full set.',
  reasonLabel: 'The provider says:',

  binariesTitle: 'Binary pairs compared',
  verdict: {
    identical: 'identical',
    patched: 'localized change',
    recompiled: 'rebuilt — list withheld',
    incomparable: 'not comparable',
  },
  colBinary: 'Binary',
  colVerdict: 'Verdict',
  colMatched: 'Matched',
  colChanged: 'Changed',
  colUnmatched: 'Unmatched',

  changedTitle: 'Changed functions',
  changedSub: 'Smallest structural movement first by default: a security fix is usually a small change, not a rewrite.',
  colFunction: 'Function',
  colInstrs: 'Δ instructions',
  colBlocks: 'Δ blocks',
  colCc: 'Δ complexity',
  colSize: 'Δ size (bytes)',
  sortBy: (col: string) => `Sort by ${col}`,
};
