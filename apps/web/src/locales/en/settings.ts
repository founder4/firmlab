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
};
