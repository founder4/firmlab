/**
 * settings — the Settings screen. English source of truth.
 *
 * The language control lives here rather than in the header beside the theme toggle: switching language is a
 * deliberate, rare act, while theme is a comfort setting people flip by time of day.
 */
export const settings = {
  eyebrow: 'System',
  title: 'Settings',
  desc: 'Appearance is yours to change here. Analysis, privacy, and agent limits reflect the deployment’s real configuration.',

  tabs: {
    appearance: 'Appearance',
    analysis: 'Analysis',
    tools: 'Tools',
    agent: 'AI & Agent',
    privacy: 'Privacy',
    storage: 'Storage',
    help: 'Help',
  },

  appearance: {
    title: 'Appearance',
    sub: 'Applied instantly and remembered on this device.',
    theme: 'Theme',
    themeLight: 'Light',
    themeSystem: 'System',
    themeDark: 'Dark',
    density: 'Density',
    densityComfortable: 'Comfortable',
    densityCompact: 'Compact',
    densityHint: 'Compact density tightens table rows and spacing for dense sessions on large monitors.',
  },

  language: {
    row: 'Language',
    /** Placed under the control so the consequence is read before the click, not discovered after it. */
    hint: 'Changes the workbench interface and the reports it generates. Applied instantly and remembered on this device.',
    /**
     * The honest boundary. Finding titles and rationales are written by the analysis providers at the moment they
     * run and stored with the image, so they stay in the language that produced them — translating a stored
     * measurement would be rewriting a record, not presenting it.
     */
    scope:
      'Findings keep the wording the analysis recorded for them. Those sentences are stored with the image as evidence, so they are shown as written rather than re-translated.',
  },

  /**
   * The lane switches in the privacy tab — the chrome AROUND the descriptions, not the descriptions themselves.
   *
   * What each lane turns on and what leaves the machine is composed by the API and arrives in the locale this page
   * asked for; those sentences are resolved on every read and describe this deployment, so they are not a record
   * and they are not frozen. What is here is the framing they sit in, and one distinction in it is load-bearing:
   * `leavingNow` is present tense because the lane is ON and the traffic is happening, while `ifEnabled` is
   * conditional. Collapsing the two would let a switched-on lane read as a hypothetical.
   */
  lanes: {
    title: 'Lanes',
    sub: [
      'Everything that can reach outside this process. Off is the default and the deterministic engine needs none',
      'of them. A change takes effect on the next run — no restart.',
    ].join(' '),
    loading: 'Loading lanes…',
    /** The lane is on and outward-facing: this is happening, not hypothetical. */
    leavingNow: 'Leaving this machine: ',
    ifEnabled: 'If enabled: ',
    followEnvironment: 'set here · follow environment',
    followEnvironmentHint: (environmentValue: boolean) =>
      `The container environment has this ${environmentValue ? 'on' : 'off'}. Follow it again.`,
    /** Around the `<code>` naming the lane this one depends on. */
    inertLead: 'On, but doing nothing — ',
    inertTail: ' is off, and this only acts inside that lane.',
  },

  /** The remaining tab bodies. Most of what these panels show is composed by the API and rendered as it arrives. */
  panels: {
    privacyTitle: 'Privacy & connectivity',
    externalAgent: 'External copilot / agent',
    humanApproval: 'Human approval required',
    storageTitle: 'Storage & retention',
    localAnalysis: 'Local analysis',
    helpSub: 'Learn your way around, or revisit the introduction.',
  },

  /**
   * On/off as a BADGE, shared by the privacy tab's copilot row and the agent tab's status row.
   *
   * Deliberately not in `common`: these two are the same claim about the same lane read from the same
   * `/agent/config`, and letting them drift would let one panel say the copilot is off while the other says it is
   * on. Every other on/off on this screen is a lane switch, and those words come from the API.
   */
  state: {
    enabled: 'Enabled',
    disabled: 'Disabled',
  },

  /**
   * The analysis tab. Nothing here is a preference — every value it names is a deployment setting read from the
   * environment, and the panel's own closing line says so. The variable names sit BESIDE these sentences in
   * `<span class="mono">`, never inside them: an operator greps a compose file for `FIRMLAB_MAX_UPLOAD`, and a
   * translation that bent it would be a translation of an identifier.
   */
  analysis: {
    title: 'Analysis',
    sub: [
      'The deterministic engine runs on every upload with no configuration. Depth comes from external tools and',
      'from deployment limits, which are set on the server.',
    ].join(' '),
    externalTools: 'External tools',
    viewTools: 'View detected tools',
    toolsHint: [
      'binwalk, radare2/Ghidra, syft/grype, gitleaks and QEMU unlock extraction, triage, SBOM/CVEs, deep secret',
      'scans and emulation when present.',
    ].join(' '),
    uploadLimit: 'Upload limit',
    uploadLimitLead: 'Max image size is set with',
    uploadLimitTail: '(default 500 MB).',
    jobConcurrency: 'Job concurrency',
    concurrencyLead: 'Heavy tools are throttled with',
    concurrencyTail: '(default 2) so a burst can’t exhaust the machine.',
    deploymentNote: [
      'These are deployment settings rather than per-session preferences, so they live in the environment, not here',
      '— this panel mirrors them honestly.',
    ].join(' '),
  },

  /**
   * The privacy tab's own chrome. The lane switches inside it are described by the API (see `lanes` above); what is
   * here is the bind posture, the copilot row and the closing banner.
   *
   * The posture words are a verdict about THIS deployment, recomputed from `/health` on every load — `Local-only`
   * is a claim that firmware never leaves the machine, and a translation that softened `Bound to network` into
   * something reassuring would invert it. `Unknown` is its own state on purpose: an unreachable API is not a
   * local-only one, and the panel must never guess in the safe direction.
   */
  privacy: {
    sub: 'FirmLab is designed to run locally. Firmware images are analyzed on this machine and are not uploaded.',
    networkPosture: 'Network posture',
    bindAddress: 'Bind address',
    posture: {
      unknown: 'Unknown',
      unknownNote: 'The API is unreachable.',
      proxy: 'Auth-gated proxy',
      proxyNote: 'Reached only through an authenticating reverse proxy.',
      exposed: 'Bound to network',
      exposedNote: 'The API is reachable beyond loopback. Consider restricting it.',
      local: 'Local-only',
      localNote: 'Bound to loopback — firmware never leaves this machine.',
    },
    /** Wraps the configured provider and model, which are identifiers and render verbatim. */
    agentSentTo: [
      'When you run the copilot or an agent session, the deterministic analysis context (findings, binary metadata,',
      'corpus cross-refs) is sent to',
    ].join(' '),
    agentNoBytes: 'No raw firmware bytes are sent. Emulation requires your approval.',
    agentOffLead: 'No external model is configured. Nothing is sent off-machine. Enable it with',
    agentOffTail: 'and an API key.',
    banner: [
      'The engine (@firmlab/core) is deterministic and needs no network. External tools and the optional copilot',
      'are the only things that can reach outside this process.',
    ].join(' '),
  },

  /** The AI & agent tab. Every budget it lists is enforced by the governor; this panel only mirrors them. */
  agent: {
    title: 'AI provider',
    sub: [
      "An LLM powers the copilot and the conscious agent's decision nodes. It is optional — with no key configured",
      'FirmLab stays fully deterministic and local. Provider and key are set on the server; this mirrors them.',
    ].join(' '),
    activeProvider: 'Active provider',
    noneConfigured: 'none configured',
    selectProvider: 'Select provider',
    providerKey: 'Provider key',
    keyLead: 'Set the matching key:',
    keyOrPoint: ', or point',
    keyTail: 'at a local server. Keys live in the server environment, never in the browser.',
    governorTitle: 'Agent governor',
    governorSub: [
      'The agent reasons within a deterministic skeleton and pauses for approval before emulation. These limits are',
      'enforced by the governor and set via environment variables.',
    ].join(' '),
    status: 'Status',
    model: 'Model',
    stepBudget: 'Step budget',
    tokenBudget: 'Token budget',
    costCeiling: 'Cost ceiling',
    /** No ceiling is configured. It is not "unlimited spending is fine" — it is that nothing is stopping it. */
    unbounded: 'unbounded',
    timeBudget: 'Time budget',
    emulation: 'Emulation',
    offLead: 'Set',
    offTail: [
      'and an LLM API key to enable the decision nodes. With the flag off, FirmLab stays local-only and',
      'deterministic.',
    ].join(' '),
  },

  /** The storage tab. Retention is enforced by the server; a limit that is not set says so rather than staying blank. */
  storage: {
    sub: 'Uploaded images and carved rootfs live under the data directory on this machine.',
    onDisk: 'On disk',
    quotaOf: (p: { used: string; quota: string }) => `${p.used} of ${p.quota} quota`,
    images: 'Images',
    retention: 'Retention',
    evictedAfter: (days: number) => `Images older than ${days} day(s) are evicted.`,
    noAgeLimit: 'No age limit set.',
    oldestFirst: 'Oldest images are evicted first when over quota.',
    noQuota: 'No size quota set.',
    manageLead: 'Manage or bulk-delete images from',
    manageMid: '. Retention limits are configured with',
    manageAnd: 'and',
  },

  /** The help tab. */
  help: {
    title: 'Help',
    tour: 'Product tour',
    restartTour: 'Restart tour',
    keyboard: 'Keyboard',
    keyboardHint: 'Navigate with Tab and Shift+Tab; activate with Enter/Space; dismiss overlays with Esc.',
    documentation: 'Documentation',
    documentationHint: 'See the project README and docs/ for architecture, the emulation ladder, and the agent design.',
    about: 'About',
    aboutHint: 'FirmLab — local-only firmware analysis workbench. Deterministic engine, optional tool-backed depth.',
  },
};
