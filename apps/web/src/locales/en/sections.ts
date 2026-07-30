/**
 * sections — the per-image analysis section names. English source of truth.
 *
 * The section IDs (`structure`, `compmap`, `testbench`…) are ROUTE segments and stay in English forever; a
 * translated URL would break every saved link and every screenshot in the docs. Only the labels move.
 *
 * One flat map on purpose: the shell's context header and `ImageDetail`'s step timeline both name the same
 * sections, and two maps would drift the moment one of them gained an entry.
 */
export const sections = {
  dossier: 'General',
  overview: 'General',
  structure: 'Structure',
  entropy: 'Entropy',
  filesystem: 'Extraction',
  files: 'File browser',
  secrets: 'Secrets',
  hardware: 'Hardware interfaces',
  bootloader: 'Bootloader',
  sbom: 'SBOM & CVEs',
  compmap: 'Component map',
  deepscans: 'Deep scans',
  binaries: 'Test bench',
  testbench: 'Test bench',
  findings: 'Findings & report',
  operator: 'Operator ledger',
  diff: 'Diff',
  simulate: 'Emulation recipes',
  opacidad: 'Autonomous scan',
  agent: 'Agent',
};
