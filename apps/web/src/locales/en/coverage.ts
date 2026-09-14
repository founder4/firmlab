/**
 * coverage — the banner that answers the question a findings count silently begs. English source of truth.
 *
 * The status labels are the load-bearing part of this namespace. `not-run` and `ran-empty` produce the SAME empty
 * findings list and are opposite conclusions, so each label has to say which of the two it is. A rendering that
 * lets a stage nobody ran read as a stage that passed inverts the workbench's central claim, which is why the
 * Spanish file carries its own warning about exactly that.
 *
 * What is deliberately NOT here: the verdict sentence, the class rationale and each stage's reason. Those are
 * computed by the API from the same plan the autonomous scan executes and are printed as the record states them —
 * translating a stored measurement would be rewriting it.
 */
export const coverage = {
  /** The class code (`embedded-linux`, `rtos`…) is an identifier and is passed through untouched. */
  eyebrow: (firmwareClass: string) => `Coverage · ${firmwareClass}`,

  status: {
    found: 'found',
    'ran-empty': 'ran · nothing',
    degraded: 'degraded',
    'no-input': 'no input',
    'not-built': 'not built',
    'not-run': 'not run',
  },

  remedy: {
    label: 'Next move',
    action: {
      retry: 'Run this stage again; the previous execution failed before it answered.',
      'raise-bound': 'Raise the named cap before re-running; the same bound will truncate it again.',
      'install-tool': 'Install or repair the required tool/rule corpus, then re-run.',
      'escalate-full-system': 'Re-run with W9: it will route this qemu-user limit to one full-system boot.',
      'reacquire-input': 'Acquire a complete or different firmware artefact; these bytes do not contain the input.',
      settled: 'No re-run is needed: the stage exhausted the question it can answer for this image.',
      'unbounded-search': 'Treat this as inherently inconclusive; no finite search budget proves the negative.',
      defect: 'Fix FirmLab itself before re-running; this degradation is not caused by the image.',
    },
    undeclared: 'No structured next move was recorded. This run may predate remedy declarations.',
  },

  /**
   * The arithmetic, stated explicitly. A reader who sees more rows in the findings table than the count admits
   * will otherwise assume the count is simply wrong, rather than that the extra rows cover no stage at all.
   */
  assertions: (measured: number, asserted: number) =>
    [
      `The ${measured} above are measured.`,
      `${asserted} further row(s) are operator assertions — a named person's claim, covering no stage.`,
    ].join(' '),

  hide: 'Hide',
  whatCanRun: (executed: number, applicable: number) => `What can run on this image? (${executed}/${applicable})`,
};
