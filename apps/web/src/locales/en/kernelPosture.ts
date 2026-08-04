/**
 * kernelPosture — the kernel-posture table. English source of truth.
 *
 * The load-bearing words are the four class labels. `unknown` in the provider's payload is two incompatible facts —
 * a question that could not apply to this kernel version, and a question that applies and went unanswered — and the
 * labels are what keeps a reader from counting the first as a hardening failure. They must not soften in
 * translation: "not applicable" is a closed question, "unanswered" is an open one.
 *
 * Option names, version strings, evidence sources and the provider's own `detail` sentences are DATA and render
 * verbatim in both languages.
 */
export const kernelPosture = {
  title: 'Kernel posture',
  sub: 'Which hardening properties this kernel has, read from a shipped config, the kernel blob, the module set or a rootfs sysctl — and, for each question it could not settle, whether the option could even exist in this version.',
  run: 'Run kernel posture',
  rerun: 'Re-run',
  running: 'Running…',
  unknownValue: 'not recovered',
  unrecorded: 'not recorded',
  years: (n: number) => `${n} years`,
  modulesValue: (signed: number, inspected: number, total: number) =>
    `${signed} signed of ${inspected} inspected${inspected === total ? '' : ` (of ${total})`}`,
  class: {
    bad: 'weak',
    unanswered: 'unanswered',
    good: 'ok',
    'not-applicable': 'n/a here',
  },
  census: (c: { total: number; bad: number; unanswered: number; good: number; notApplicable: number }) =>
    `${c.total} question${c.total === 1 ? '' : 's'} — ${c.bad} weak, ${c.good} ok, ${c.unanswered} unanswered, ${c.notApplicable} not applicable to this kernel.`,
  legend:
    'Unanswered and not-applicable are different: the first is a question this image did not settle, the second a question that could not exist for this kernel version — an option that postdates it, or one upstream has removed. Neither is a statement that the hardening is off.',
  field: {
    version: 'Version',
    versionSource: 'Read from',
    age: 'Series age',
    configPath: 'Config',
    modules: 'Modules',
  },
  col: { state: 'State', question: 'Question', option: 'Option', evidence: 'Evidence' },
  empty: {
    notRun: 'Kernel posture has not been run for this image, so nothing here has been asked.',
    unavailable: (reason: string) =>
      `The questions were asked and this deployment could not answer them${reason ? `: ${reason}` : '.'} That is a gap in this workbench, not a property of the firmware.`,
    notLocated: (reason: string) =>
      `No kernel was located in this image${reason ? `: ${reason}` : '.'} That is a gap in coverage, never a statement that the image has no kernel or that its kernel is sound.`,
    searchedHeading: 'Looked in:',
    noQuestions: 'A kernel was located and no posture question was recorded against it.',
  },
};
