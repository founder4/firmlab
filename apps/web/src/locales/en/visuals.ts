/**
 * visuals — the hand-rolled SVG/DOM pictures: the entropy chart, the structure ribbon, the signal tape and the SBOM
 * graph. English source of truth. Adding a key here makes the Spanish file fail to compile until it is translated.
 *
 * **What a picture is allowed to claim.** Three of these four draw a measurement, and a measurement drawn boldly
 * reads as a verdict. Entropy is the case that matters: a band above 7.2 bits/byte is near-random, and compression,
 * packing, encryption, an embedded JPEG and a certificate blob all produce exactly that. The shading, the dashed
 * line and the trace are therefore a HYPOTHESIS to check against the structure map, and the sentence saying so is
 * part of the visual — not decoration a translation may quietly drop. The SBOM graph carries the mirror image of
 * the same error: a grey node is a component nothing MATCHED, which is not a component that is safe.
 *
 * **What is not translated, ever.** Axis units and notation (`bits/byte`, `0x…` offsets, byte counts), package names
 * and versions, CVE ids, grype's severity names, signature categories and file paths are data or identifiers. Every
 * one of them reaches these messages ALREADY FORMATTED, as a string, so a translation cannot restyle a number and
 * the two languages cannot end up disagreeing about what the axis says. `7.2` is written the same way in both for
 * the same reason: it is the threshold the code compares against and the docs quote, not a localisable quantity.
 */
export const visuals = {
  entropy: {
    ariaLabel: 'Entropy across the image offset',
    /** The scrub readout. Both values arrive pre-formatted — `0x…` and two decimals are notation, not prose. */
    readout: (offset: string, bits: string) => `offset ${offset} · H = ${bits} bits/byte`,
    summary: (mean: string, max: string) => `Mean ${mean} · Max ${max} · dashed line at 7.2 bits/byte`,
    /** The sentence the chart is meant to be read with: high entropy is a lead, and the structure map is where it is checked. */
    caveat: [
      'Above that line the bytes are near-random.',
      'Compression, packing and encryption all read that way — and so do an embedded JPEG and a certificate blob.',
      'The shaded bands are a hypothesis to check against the structure map, never a verdict.',
    ].join(' '),
  },

  structure: {
    hoverPrompt: 'Hover a segment to inspect it.',
    /** A carve is a claim a magic number makes about what follows it, and the gaps are unclaimed rather than empty. */
    caveat: [
      'Each band is a signature match at that offset — what a magic number claims starts there, not a verdict on',
      'what the bytes are. The stretch between two matches is unclaimed, not empty.',
    ].join(' '),
  },

  signal: {
    ariaLabel: 'Firmware signal tape',
    title: 'Firmware signal tape',
    /** Gender and number both agree in Spanish, which is why this is a function and not a placeholder. */
    marksPinned: (n: number) => `▲ ${n} finding${n === 1 ? '' : 's'} pinned to offsets`,
    caveat: [
      'The dashed line is 7.2 bits/byte: above it the bytes are near-random, which packing, compression, encryption',
      '— and a JPEG — all look like, so it is a lead to check against the structure band under it.',
      'A marker sits at the offset a finding recorded; a finding with no offset is not on the tape at all.',
    ].join(' '),
  },

  sbom: {
    ariaLabel: 'SBOM component graph',
    title: 'SBOM component graph',
    /** Drawn inside a 26 px radius circle, so it has to stay this short in every language. */
    pkgCount: (n: number) => `${n} pkgs`,
    noKnownCves: 'no known CVEs',
    legendNoCve: 'no CVE',
    affected: (vulnerable: number, total: number) =>
      `${vulnerable} of ${total} components affected · node size = CVE count`,
    /** The mirror of the entropy caveat: an unmatched component is not a cleared one. */
    caveat: [
      'A component nothing matched is drawn grey, and that is not the same as a safe one.',
      'The match is only as good as the version the SBOM fingerprinted and the vulnerability data this deployment',
      'had to query — absence of a CVE here is absence of a match, not evidence that none exists.',
    ].join(' '),
  },
};
