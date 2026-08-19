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
  desc: 'Everything at a glance across your firmware corpus — fleet, capacity, and posture.',

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

  jump: {
    title: 'Jump to',
    analysis: 'Local analysis',
    analysisDesc: 'Upload & read firmware as signal',
    agents: 'Agents',
    agentsDesc: 'Launch & monitor autonomous runs',
    capture: 'Proxy / Updates',
    captureDesc: 'Intercept & analyze OTA updates',
    corpus: 'Corpus',
    corpusDesc: 'Cross-image priors & reuse',
  },
};
