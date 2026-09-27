/**
 * overview — the workspace-wide panorama (fleet, capacity, tool health, network posture). English source of truth.
 *
 * The posture words carry the weight here: `local-only` is a statement about where the API is bound, not a comfort
 * message, and a translation that reads as reassurance would claim something the workbench has not measured.
 * Firmware-class ids keep their identifier spelling in the class breakdown — they are data, not prose.
 */
export const overview = {
  eyebrow: 'Workspace',
  title: 'Dashboard',
  desc: 'Everything at a glance across your firmware images — fleet, capacity, and posture.',

  stats: {
    images: 'Images',
    imagesSub: (analyzing: number, errored: number) => `${analyzing} analyzing · ${errored} error`,
    onDisk: 'On disk',
    quotaOf: (quota: string) => `of ${quota}`,
    localStore: 'local store',
    tools: 'Tools',
    toolsSub: 'available in this deployment',
    posture: 'Network posture',
    postureLocal: 'local-only',
    postureProxied: 'auth-gated',
    postureExposed: 'bound to network',
  },

  recent: {
    title: 'Recent images',
    link: 'Local analysis',
    emptyTitle: 'No firmware yet',
    /** Split around the link: Spanish orders the destination and the purpose differently to English. */
    emptyLead: 'Head to',
    emptyTail: 'to upload your first image.',
    unexamined: 'unexamined',
    findings: (n: number): string => (n === 1 ? 'finding' : 'findings'),
    coverage: (executed: number, applicable: number) => `${executed}/${applicable} stages`,
  },

  byClass: {
    title: 'Fleet by class',
    empty: 'No images yet.',
  },

  next: {
    title: 'Next steps',
    none: 'Nothing is waiting. Upload another image to compare against this one.',
    upload: 'Upload a firmware image',
    uploadDesc: 'Nothing is on this bench yet. Analysis starts from an image.',
    unscanned: (n: number) => (n === 1 ? '1 image has not been scanned' : `${n} images have not been scanned`),
    unscannedDesc: 'Their findings, if any, come from stages run by hand. Run the autonomous scan to cover the rest.',
    partial: (n: number) => (n === 1 ? '1 image was scanned partially' : `${n} images were scanned partially`),
    partialDesc: 'Some applicable stages did not run, so an empty result there is not a clean one.',
    tools: (n: number) => (n === 1 ? '1 tool is missing' : `${n} tools are missing`),
    toolsDesc: 'The stages that need it will be blocked, not negative. See what this deployment can run.',
    corpus: 'Compare across images',
    corpusDesc: 'Every image has been scanned. Look for reused credentials and shared components.',
  },
};
