/** nav — the sidebar and the app shell. English source of truth. */
export const nav = {
  dashboard: 'Dashboard',
  localAnalysis: 'Local analysis',
  agents: 'Agents',
  proxyUpdates: 'Proxy / Updates',
  corpus: 'Corpus',
  settings: 'Settings',
  capabilities: 'Capabilities',
  system: 'System',
  firmware: 'Firmware',
  activeImage: 'Active image',
  allImages: 'All images',
  /**
   * The posture sentences, one per `/health` state. These replaced a single constant that read "Local-only.
   * Never expose to the internet." — which was both inaccurate on a proxied deployment and a policy the product
   * has outgrown, since the research and capture lanes are network work by design. Each states what is true and
   * stops; none of them tells the operator what to do about it.
   */
  posture: {
    ok: {
      label: 'Local-only — the API is bound to loopback.',
      title: 'Bound to 127.0.0.1: nothing outside this machine can reach the workbench.',
    },
    proxied: {
      label: 'Reachable through an authenticating proxy.',
      title:
        'The API is not on loopback, and this deployment declares a trusted authenticating reverse proxy in front of it (FIRMLAB_TRUSTED_PROXY).',
    },
    exposed: {
      label: 'On the network — no proxy authentication declared.',
      title:
        'The API is bound to a non-loopback address and no trusted proxy is declared. Anything that can route to this host can reach the workbench and everything extracted into it.',
    },
    down: {
      label: 'Network posture unknown — /health did not answer.',
      title: 'The API did not respond, so the posture could not be read. This is not a statement that it is local.',
    },
  },
  sectionNavAria: 'Analysis sections for this firmware',
  sectionNavOther: 'Other',
  toggleNav: 'Toggle navigation',
  help: 'Help & tour',
  helpAria: 'Help and tour',
  themeGroup: 'Theme',
  themeLight: 'Light theme',
  themeSystem: 'Match system theme',
  themeDark: 'Dark theme',
  densityToggle: 'Toggle density',
  densityToComfortable: 'Comfortable density',
  densityToCompact: 'Compact density',
  health: {
    unreachable: 'API unreachable',
    exposed: '⚠ bound to network',
    proxied: '🔒 auth-gated',
    proxiedTitle: 'Reachable only through an authenticating reverse proxy',
    local: '● local-only',
    localTitle: 'Bound to loopback — nothing leaves this machine',
  },
};
