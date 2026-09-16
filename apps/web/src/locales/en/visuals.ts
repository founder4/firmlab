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
    /**
     * The denominator the marker count needs. Most findings on a real image carry no byte offset — a CVE match, a
     * leaked key in a file — so the tape draws a handful out of dozens, and `marksPinned` alone reads as the whole
     * ledger. The caveat states the RULE; this states how many the rule dropped, which is the part that changes
     * how the picture is read.
     */
    offTape: (n: number) => `${n} more carr${n === 1 ? 'ies' : 'y'} no offset and ${n === 1 ? 'is' : 'are'} not drawn`,
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
    /**
     * What replaces `affected` when no CVE query ran. «0 of 42 affected» is a measurement and there was none —
     * the ring is grey because nothing was asked, not because nothing answered.
     *
     * It states the OUTCOME and not the cause, deliberately. `grypeAvailable:false` covers three situations —
     * grype absent, grype installed with no vulnerability database, grype ran and failed — and since the SBOM
     * lane stopped downloading a database on its own the second is the commonest. Saying «no CVE matcher» here
     * would contradict the banner directly above, which names the grype that IS installed: the same conflation
     * that had three panels reporting "no device tree has been read" beside a banner saying one had.
     */
    notQueried: (total: number) => `${total} components inventoried · no CVE query ran: this is not a count of zero`,
    /**
     * A CVE whose component is not in the listing. The package list is capped and a name can differ between the
     * inventory and the matcher, so a match can land on nothing this ring draws — and it would then be missing
     * from the node, the tooltip AND the affected count, with the picture saying nothing.
     */
    offGraph: (cves: number, pkgs: number) =>
      `${cves} CVE${cves === 1 ? '' : 's'} match ${pkgs} component${pkgs === 1 ? '' : 's'} not in this listing — off the graph`,
    /** The mirror of the entropy caveat: an unmatched component is not a cleared one. */
    caveat: [
      'A component nothing matched is drawn grey, and that is not the same as a safe one.',
      'The match is only as good as the version the SBOM fingerprinted and the vulnerability data this deployment',
      'had to query — absence of a CVE here is absence of a match, not evidence that none exists.',
    ].join(' '),
  },
};
