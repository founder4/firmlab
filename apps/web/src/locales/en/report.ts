/**
 * report — the Findings & report stage. English source of truth.
 *
 * These strings are not only interface. The operator exports this document as HTML, Markdown or PDF and hands it to
 * someone who will never open the workbench, so the scaffolding IS the deliverable. Four sentences here are the
 * report's honesty rather than its boilerplate — that every finding carries an explicit proof state, that a stage
 * which has not run is reported as such rather than implied clean, that operator assertions are counted in neither
 * the finding total nor any analysis stage, and that zero findings is not the same as clean. A translation that
 * softens any of them ships a document making a claim the analysis never made.
 *
 * What is NOT here, deliberately: the proof-state gloss (`proofState.label`) and the section names that also name a
 * screen (`sections.structure`, `sections.entropy`, `sections.sbom`). This component used to carry private copies of
 * both, which is two places for one meaning to drift. `section.findings` is the one exception — `sections.findings`
 * names the SCREEN, "Findings & report", which is self-referential as a heading inside the report itself.
 *
 * Finding titles, rationales, offsets, sources, severities and SBOM package names are never translated. They are the
 * record the analysis wrote; this file only writes the frame around it.
 */
export const report = {
  panelTitle: 'Report',
  fieldTitle: 'Title',
  fieldPreparedBy: 'Prepared by',
  preparedByPlaceholder: 'analyst / team',
  fieldClassification: 'Classification',
  /** Seeds the editable field once, on mount — a later language switch must not overwrite what was typed. */
  classificationDefault: 'Confidential',
  sectionsHeading: 'Sections',
  moveUp: 'Move up',
  moveDown: 'Move down',
  // The two export buttons are labelled `HTML` and `Markdown` in the component: format names, not words.
  print: 'Print / Save as PDF',

  defaultTitle: (filename: string) => `${filename} — Firmware Security Assessment`,
  coverPreparedBy: (who: string) => `Prepared by ${who}`,
  /** The cover counts the MEASURED population, so it cannot disagree with the executive summary below it. */
  coverFindings: (n: number) => `${n} finding${n === 1 ? '' : 's'}`,

  /** Headings the document owns. The rest come from `sections` — see the note above. */
  section: {
    summary: 'Executive summary',
    identity: 'Firmware identity',
    coverage: 'Analysis coverage',
    findings: 'Findings',
    appendix: 'Appendix — artefacts',
  },

  summary: {
    scope: (filename: string, size: string, firmwareClass: string, arch: string, endianness: string) =>
      `This report covers the static firmware analysis of ${filename} (${size}), classified as ${firmwareClass} on ${arch}/${endianness}.`,
    severityNote: (critical: number, high: number) => ` — ${critical} critical, ${high} high`,
    recorded: (n: number, severityNote: string) =>
      `${n} finding${n === 1 ? ' was' : 's were'} recorded${severityNote}.`,
    /** Load-bearing: the proof-state discipline, stated where a reader of the exported PDF will meet it. */
    proofDiscipline:
      'Each finding carries an explicit proof state; a stage that has not run is reported as such rather than implied clean.',
    /** Load-bearing: an assertion is not a measurement, and the total above must never be read as including one. */
    assertionsExcluded: (n: number) =>
      `${n} operator assertion${n === 1 ? ' is' : 's are'} listed separately below and counted in neither that total nor any stage — FirmLab did not measure them.`,
  },

  identity: {
    firmwareClass: 'Class',
    arch: 'Architecture',
    filesystems: 'Filesystems',
    bootloader: 'Bootloader',
    vendorModel: 'Vendor / model',
  },

  entropy: {
    mean: 'Mean entropy',
    max: 'Max entropy',
    likelyEncrypted: 'Likely encrypted',
    likelyCompressed: 'Likely compressed',
    highEntropyRegions: 'High-entropy regions',
    bitsPerByte: (value: string) => `${value} bits/byte`,
    none: 'No entropy profile available.',
  },

  structure: {
    range: 'Range',
    category: 'Category',
    label: 'Label',
    none: 'No structural segments carved.',
  },

  coverage: {
    staticAnalysis: 'Static analysis',
    extraction: 'Extraction (rootfs)',
    secrets: 'Deep secret scan',
    binaries: 'Binary triage',
    emulation: 'Emulation',
  },

  findings: {
    heading: (label: string, n: number) => `${label} (${n})`,
    severity: 'Severity',
    finding: 'Finding',
    offset: 'Offset',
    source: 'Source',
    proof: 'Proof state',
    /** Load-bearing: an empty table is not a clean device, and the report says so in the table's own place. */
    none: 'No findings recorded. Note: zero findings is not the same as clean.',
  },

  assertions: {
    heading: (n: number) => `Operator assertions (${n}) — asserted, not measured.`,
    provenance: 'A person or an agent recorded these; FirmLab did not compute them.',
    excluded:
      'They carry no proof state, count towards no analysis stage, and are excluded from the finding count above.',
    claim: 'Claim',
    statement: 'Statement',
    assertedBy: 'Asserted by',
    recorded: 'Recorded',
    agentSuffix: ' (agent)',
    unrecorded: 'unrecorded',
  },

  sbom: {
    inventory: (packages: number, vulnerabilities: number) =>
      `${packages} components inventoried; ${vulnerabilities} known vulnerabilities.`,
    severity: 'Severity',
    component: 'Component',
    fixedIn: 'Fixed in',
    none: 'No SBOM generated (needs extraction + syft). Not run.',
  },

  // `SHA-256` and `CVE` label themselves; they are named in the component rather than translated here.
  appendix: {
    size: 'Size',
    imageId: 'Image id',
    sizeWithBytes: (human: string, bytes: number) => `${human} (${bytes} bytes)`,
  },
};
