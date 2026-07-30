/**
 * The five capabilities that ran and could not be read, and the three sentences each of their states needs.
 *
 * The wording carries the distinction the panel exists for. `not-run` is silence about the WORKBENCH; `unavailable`
 * is silence about the DEPLOYMENT; only a stage that ran says anything about the firmware, and even then an empty
 * answer is bounded by whatever its coverage numbers report. Three different nothings, three different sentences —
 * one paraphrase shared between them is how this project has previously shipped a bound reading as an answer.
 */
export const capabilities = {
  heading: 'Capabilities with no reader',
  intro:
    'Each of these providers has a route, syncs findings under its own source, and until now had nowhere on screen to be read — so a stage that never ran was invisible rather than reported as not-run. The state of each is stated below, and the three states are deliberately not interchangeable.',

  states: {
    notRun: {
      label: 'has not run',
      body: 'Nothing has asked this question about this image, so there is nothing to show. That is a statement about this workbench, not about the firmware — run it and the answer, including an empty one, will say so.',
    },
    unavailable: {
      label: 'could not answer',
      body: 'The question WAS asked and this deployment could not answer it — the tool is absent or the input was not there. This is not a negative result and it is not the same as the stage never having run; the provider’s own reason is printed verbatim below.',
    },
    ran: {
      label: 'ran',
      body: 'This stage ran. An empty result here is a real measurement of what it covered — read the coverage numbers beside it before treating it as clean.',
    },
  },

  /** The denominator line. `—` where a capability carries no such number, with the reason said rather than implied. */
  coverage: {
    applied: (p: { applied: number; denominator: number; unit: string }) =>
      `${p.applied} of ${p.denominator} ${p.unit} applied`,
    appliedOnly: (p: { applied: number; unit: string }) => `${p.applied} ${p.unit} examined`,
    unknownDenominator: 'this provider reports no denominator, so what fraction of its input this covers is unknown',
    lost: (p: { lost: number; unit: string }) => `${p.lost} ${p.unit} never applied to this image`,
    partial: 'PARTIAL — part of its input was never examined',
  },

  findings: (n: number) => (n === 1 ? '1 finding' : `${n} findings`),
  reasonLabel: 'The provider says:',
  run: 'Run',
  running: 'Running…',

  /** funcdiff is the one that needs a second image, so its absence has a third cause worth naming. */
  needsBaseline:
    'Function-level diffing compares two images, and no baseline has been chosen for this one. That is a missing input, not a result.',
};
