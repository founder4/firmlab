/**
 * hardware — what the firmware DECLARES about the physical ways into the board. English source of truth.
 *
 * Every sentence here exists to stop an inference the screen would otherwise invite, and translating one loosely
 * puts the inference back:
 *
 *  - `console.caveat` — a declared console is a UART the kernel is told to bring up, and says nothing about pads,
 *    headers or a login prompt.
 *  - `flash.readOnlyStrong` / `flash.readOnlyBody` — `read-only` is a request to the kernel, not write protection.
 *  - `jtag.body` — a device tree cannot answer the JTAG question, so the row names the question instead of leaving
 *    a silence that reads as "no JTAG here".
 *  - `absence.ranNotParsed` vs `absence.neverRan` — a provider that looked and came back empty is a DIFFERENT claim
 *    from one that never ran. Collapsing the two is the defect this screen was rebuilt to fix.
 *  - `buses.dropped` / `buses.nested` — a cap states what it dropped and by what rule.
 *
 * Never translated: node paths, `compatible` strings, tty names, baud rates, the literal `bootdelay` and
 * `read-only` device-tree keys, and the raw `status` value a node carries.
 */
export const hardware = {
  /** Split around the two emphasised phrases; each fragment carries no edge whitespace, JSX supplies the spaces. */
  sub: {
    before: 'What this firmware',
    declares: 'declares',
    middle:
      'about the physical ways into the board — read from the device tree, the kernel command line and the U-Boot environment. FirmLab does not connect to hardware: everything here describes the board the image was',
    builtFor: 'built for',
    after: ', not the board on your bench.',
  },

  loadError: 'Could not read the stored provider results.',

  console: {
    heading: 'Console',
    at: 'at',
    baud: 'baud',
    fromCmdline: 'Kernel command line names',
    treeResolvesFirst: 'The device tree resolves',
    treeResolvesAfter: 'the tree resolves',
    to: 'to',
    noBaud: 'The kernel command line does not name a console, so the baud rate is not declared anywhere in this image.',
    /** Load-bearing: a declaration is not a fitted, reachable, unauthenticated port. */
    caveat:
      'A declared console is a UART the kernel is told to bring up. Whether the pads are populated, a header is fitted, or the console asks for a login are three further questions the image cannot answer.',
    noneFound: 'Neither the kernel command line nor the device tree names a console for this image.',
    noneParsed: 'The device tree was read and none could be parsed, so no console is known from it.',
    noneRead: 'No console known yet — the device tree has not been read.',
  },

  prompt: {
    heading: 'Bootloader prompt',
    open: 'interruptible',
    none: 'no window',
    disabled: 'prompt disabled',
    unknown: 'not determinable',
    noBootdelay: 'the env carries no bootdelay',
    noEnv: 'no U-Boot environment was decoded',
  },

  nothingRead: {
    title: 'Nothing has been read for this image yet',
    body: 'The buses, the flash map and the console all come from the device tree and the U-Boot environment, and neither has run. That is why this screen is empty — not because the firmware declares no interfaces.',
  },

  buses: {
    heading: 'Declared buses & debug interfaces',
    interface: 'Interface',
    node: 'Node',
    // The `Compatible` column heading names the device tree's own `compatible` property, so the component prints
    // the property name. The bus names themselves (`SPI`, `I²C`, `JTAG / SWD`, …) live there for the same reason.
    status: 'Status',
    console: 'console',
    enabled: 'enabled',
    disabled: 'disabled',
    none: 'The device tree declares no bus nodes this reader recognises.',
    dropped: (n: number, rule: string) => `${n} further node(s) were not listed — ${rule}.`,
    droppedDefaultRule: 'a cap applied',
    nested: (n: number) =>
      `${n} node(s) nested under another peripheral were excluded as driver chip-support tables rather than board hardware.`,
  },

  jtag: {
    /** Load-bearing: naming the unanswerable question, so its absence from the table is not read as a negative. */
    body: 'Not determinable from firmware. A device tree does not describe the debug port, and whether it is fused off, password-locked or open is a property of the silicon and the board — this row exists so its absence above is not read as a negative.',
  },

  flash: {
    heading: 'Declared flash map',
    partition: 'Partition',
    offset: 'Offset',
    size: 'Size',
    declaresReadOnly: 'Declares read-only',
    /** Load-bearing, and emphatic in the UI: the word does not mean what a reader assumes it means. */
    readOnlyStrong: '`read-only` is not write protection.',
    readOnlyBody:
      'It asks the kernel to withhold a writable mtd node. A bootloader, a recovery path or a direct SPI write ignores it, and nothing here says the region is protected in hardware.',
    readFrom: 'Read from',
    none: 'This device tree declares no partition map.',
  },

  absence: {
    ranNotParsed: 'The device tree was read for this image and none could be parsed — see the reason below.',
    neverRan: 'No device tree has been read for this image yet, so nothing is declared either way.',
  },

  provenance: {
    board: 'Board:',
    unnamed: 'unnamed',
    reachedVia: 'reached via',
    nodes: (n: number) => `${n} nodes`,
    trees: (n: number) => `${n} trees in this image`,
    selected: ', this one selected by the FIT configuration',
    notSelected: ', none declared as the choice',
    noneRead: 'No device tree could be read.',
    searched: 'Searched:',
    /**
     * The headers that validated and would not walk.
     *
     * The provider's own `reason` ends with "(see rejected)" — a sentence pointing at a field nothing rendered,
     * and on the one corpus image that produces them (`447719f7`) `found` is true, so that sentence was not on
     * screen either. One of its two entries is the SAME tree that reads fine once the UBI volume is
     * reassembled, seen from the raw image. That is information, and it was nowhere.
     */
    rejectedTitle: (n: number) => `${n} FDT header${n === 1 ? '' : 's'} validated but would not read`,
    rejectedMeaning:
      'The bytes at these offsets are a device tree by their header, and the tree could not be walked to the end. That is a limit of this reader or of how the blob is stored — not a finding that there is no tree there.',
    rejectedMore: (n: number) => `${n} more, in the run's stored result.`,
    rejectedSize: (n: number) => `${n} bytes`,
  },

  actions: {
    readTree: 'Read device tree',
    rereadTree: 'Re-read device tree',
    readUboot: 'Read U-Boot env',
    rereadUboot: 'Re-read U-Boot env',
  },
};
