/**
 * capture — the on-the-wire lane (Phase 6.0–6.6). English source of truth.
 *
 * This is the screen where softening a sentence has a consequence outside the browser. Every string here states
 * what leaves the machine, what is touched on somebody's network, and under whose acknowledgement — the
 * authorization checkbox, the "nothing is intercepted" of a discovery sweep, the pinned-TLS dead end. Where the
 * English is emphatic the translation stays emphatic; a milder Spanish would understate a real consequence.
 *
 * Untranslated on purpose: tool names (`arp-scan`, `nmap`, `mitmproxy`, Frida), the env var and the Docker flag,
 * transports and acquisition ceilings (`captured_plaintext`, `blocked_by_pinning` — identifiers the API returns),
 * backend ids, MACs, IPs and URLs.
 */
export const capture = {
  eyebrow: 'Acquisition',
  title: 'Proxy / Updates',
  desc: "Get on-path of a device, intercept its OTA update, carve the firmware from the captured traffic and ingest it — and track how its firmware versions change over time. FirmLab's second network-touching lane.",

  /** The lane-on banner, split around its two emphasised verbs so each language can order the clause its own way. */
  laneOn: {
    discover: 'Discover',
    mid: 'devices below, then',
    capture: 'Capture',
    tail: 'arms an on-path proxy for one target: trigger its OTA and FirmLab scores the captured flows for firmware and offers the carved blob for one-click ingest. Interactive request replay (a full HTTP repeater) is on the roadmap — it needs a server-side replay endpoint.',
  },

  /** The lane-off banner. The env var and the Docker flag are rendered beside these, never inside them. */
  laneOff: {
    lead: 'The capture lane is',
    word: 'off',
    set: 'Set',
    enable: 'to enable it (its own flag, like',
    detection: "Detection below still runs — it's read-only — but arming a scan is disabled until the lane is on.",
    docker: 'On Docker, discovery also needs',
  },

  backends: {
    title: 'Capture backends',
    sub: 'How this deployment could get on-path and what it could read. Plug hardware → a backend lights up. Capture ceiling right now:',
    none: 'nothing capturable yet',
    colBackend: 'Backend',
    colRole: 'Role',
    colUnlocks: "What it unlocks / what's needed",
  },

  /** The gloss for a backend's role. The role values themselves come from the API and are matched, not shown. */
  roles: {
    positioning: 'Positioning',
    interception: 'Interception',
    radio: 'Radio',
    physical: 'Physical',
  },

  discover: {
    title: 'Discover devices',
    sub: 'A passive host sweep (arp-scan / nmap) builds the inventory below. Nothing is intercepted — discovery only enumerates who is on the wire.',
    /** The gate on every outward action on this screen. It asserts ownership, and must read as an assertion. */
    ack: 'I confirm these are devices/networks I own or am authorized to test.',
    subnetPlaceholder: 'subnet (e.g. 192.168.1.0/24) — blank = auto-detect',
    subnetLabel: 'Subnet to scan',
    scan: 'Scan network',
    scanning: 'Scanning…',
    failed: 'Discovery failed',
  },

  radar: {
    title: 'Device radar',
    sub: (n: number) =>
      `${n} device(s) in the inventory. Type guesses are heuristic (phrased as questions), never asserted.`,
    scannedTitle: 'Scan complete — no devices responded',
    scannedBody:
      'The sweep ran but nothing answered. On Docker, discovery needs --network host; also confirm arp-scan or nmap is installed.',
    noScanTitle: 'No scan yet',
    noScanBody: 'Arm a discovery scan above to build the LAN inventory.',
    colVendor: 'Vendor',
    colGuess: 'Type guess',
    colSeen: 'Seen',
    preflight: 'Preflight',
    capture: 'Capture',
    captureReady: 'Arm an OTA capture for this device',
    captureBlocked: 'Acknowledge authorization first',
    seconds: (n: number) => `${n}s ago`,
    minutes: (n: number) => `${n}m ago`,
    hours: (n: number) => `${n}h ago`,
  },

  preflight: {
    ceiling: 'Ceiling:',
    unpin: 'download Frida unpin →',
  },

  session: {
    title: 'Capture session',
    target: 'Target',
    status: 'status',
    ceiling: 'ceiling',
    trigger: "Trigger the device's OTA now; firmware-looking flows are highlighted and can be ingested.",
    pinned:
      "The device pins TLS — the OTA can't be decrypted through the proxy. Run the bundled unpin script on a rooted phone:",
    stop: 'Stop & teardown',
    noFlows: 'No flows yet — waiting for traffic through the proxy.',
    colScore: 'Score',
    colType: 'Type',
    colSize: 'Size',
    ingest: 'Ingest',
    ingested: 'ingested →',
  },

  learning: {
    title: 'OTA learning',
    sub: 'What the corpus has learned across captured versions — a per-family OTA timeline, how each vendor ships, and which CDN serves whom. Capture the same device twice to unlock a cross-version diff.',
    emptyTitle: 'No captured versions yet',
    emptyBody: 'Ingest a capture (above) — its provenance seeds the OTA timeline here.',
    priors: 'Vendor priors:',
    ships: 'ships',
    fromCdns: (cdns: string) => `from ${cdns}`,
    versions: (n: number) => `${n} version(s)`,
    open: 'open →',
    diffPrev: 'diff prev',
  },
};
