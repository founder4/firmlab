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
  binvuln: 'Binary hardening',
  kernel: 'Kernel posture',
  egress: 'Firmware egress',
  simulate: 'Emulation recipes',
  opacidad: 'Autonomous scan',
  agent: 'Agent',
};

export const sectionIndex = {
  heading: 'All sections',
  intro:
    'Every analysis surface for this image, and every one of them reachable from here. Ten of these were reachable only by typing a URL — including Files, which is the surface that lets a finding’s evidence be checked instead of trusted. Nothing is hidden on a guess about which apply to this device class: that routing lives in the API and a second copy here would be one commit from disagreeing with it.',
  timelineNote: 'In the step timeline above',
  urlOnly: 'was reachable only by URL',
  notRun:
    'needs an extracted rootfs, and extraction has not run — a statement about this workbench, not about the firmware',
  noRootfs:
    'extraction RAN and produced no rootfs, so this section has nothing to read. That is a measured property of this image, not a stage nobody started.',
};
