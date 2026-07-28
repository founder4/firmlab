/**
 * settings — the Settings screen. English source of truth.
 *
 * The language control lives here rather than in the header beside the theme toggle: switching language is a
 * deliberate, rare act, while theme is a comfort setting people flip by time of day.
 */
export const settings = {
  eyebrow: 'System',
  title: 'Settings',

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
};
