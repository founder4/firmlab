/**
 * egressSection — the firmware's own outbound attempts, as a section. English source of truth.
 *
 * The three empty states are the whole reason this namespace is careful. "No boot has run", "boots ran and none
 * recorded a wire observation" and "a boot recorded one and the guest addressed nothing" are three different
 * facts, and only the last is a property of the firmware. Collapsing them would let a run stored before the
 * observation existed read as a device that contacts nobody.
 */
export const egressSection = {
  title: 'Firmware egress — what the booted image addressed',
  sub: "Read off the guest's own frames, so an attempt is recorded whether or not this run let it through. A destination here was ADDRESSED and is never reported as contacted: on the sending side, a SYN into a black hole and a completed handshake look the same.",
  noRuns: 'No emulation run has completed for this image, so there has been nothing on its wire to observe.',
  toSimulate: 'Go to emulation',
  runsWithoutCapture: (n: number) =>
    `${n} emulation run${n === 1 ? '' : 's'} completed and none carries a wire observation. That is NOT this firmware addressing nothing: a run stored before the observation existed, or a qemu without the filter-dump object, produces exactly this and says nothing about the guest.`,
  runLabel: (headline: string, when: string) => `${headline} · ${when}`,
};
