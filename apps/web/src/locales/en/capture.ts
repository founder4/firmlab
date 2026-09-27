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
    colInspection: 'Body inspection',
    inspectionComplete: (n: string) => `${n} inspected`,
    inspectionPartial: (seen: string, total: string) => `${seen} of ${total} inspected — score is bounded`,
    inspectionUnavailable: 'Body not retained — score used metadata only',
    inspectionLegacy: 'Coverage was not recorded for this flow',
    ingest: 'Ingest',
    ingested: 'ingested →',
  },

  learning: {
    title: 'OTA learning',
    sub: 'What the cross-image corpus has learned across captured versions — a per-family OTA timeline, how each vendor ships, and which CDN serves whom. Capture the same device twice to unlock a cross-version diff.',
    emptyTitle: 'No captured versions yet',
    emptyBody: 'Ingest a capture (above) — its provenance seeds the OTA timeline here.',
    priors: 'Vendor priors:',
    ships: 'ships',
    fromCdns: (cdns: string) => `from ${cdns}`,
    versions: (n: number) => `${n} version(s)`,
    open: 'open →',
    diffPrev: 'diff prev',
  },

  wireless: {
    panelTitle: 'Reconstruct firmware from wireless capture',
    panelSub:
      'Reassemble firmware from Bluetooth Low Energy (Nordic DFU) DATA writes or Zigbee OTA (cluster 0x0019) Image-Blocks into an ingestable image.',
    tabBle: 'BLE DFU',
    tabZigbee: 'Zigbee OTA',
    ack: 'I acknowledge authorization to reconstruct firmware from these captured wireless frames.',
    ackRequired: 'Operator acknowledgement is required before creating a session or submitting captures.',
    disabledWarning:
      'Wireless reassembly requires the capture lane: set FIRMLAB_CAPTURE=1 to enable it (on Docker, also use --network host).',
    targetDevice: 'Target device (optional)',
    deviceSelectPlaceholder: 'Select device or leave unassigned',
    deviceIdLabel: 'Target Device ID',
    sessionTitle: 'Capture session',
    sessionIdLabel: 'Session ID',
    sessionIdPlaceholder: 'Session ID (create a new session or paste an existing one)',
    createSession: 'Create session',
    creatingSession: 'Creating session…',
    sessionCreated: (id: string) => `Session ${id} active`,
    sessionRequired: 'A valid session ID is required. Create or specify one above.',
    filenameLabel: 'Output firmware name',
    filenamePlaceholder: 'e.g. ble-dfu.bin or zigbee-ota.bin',
    filesLabel: 'Capture file(s)',
    filesHintBle:
      'Upload a JSON file ({ chunks: ["base64…"] }), text file (base64/hex lines), or multiple binary chunk files.',
    filesHintZigbee:
      'Upload a JSON file ({ blocks: ["base64…"] }), an OTA binary file, or multiple Image-Block chunk files.',
    filesRequired: 'At least one capture file or chunk payload is required.',
    initPacketLabel: 'Nordic DFU init packet (.dat, optional)',
    initPacketHint: 'Used to cross-check declared image size against reassembled byte stream.',
    autoIngest: 'Automatically ingest carved image into workbench',
    submitBle: 'Reassemble BLE DFU',
    submitZigbee: 'Reassemble Zigbee OTA',
    processing: 'Reassembling firmware…',
    readingFiles: 'Reading and parsing files…',
    resultsTitle: 'Reassembly result',
    statusComplete: 'Complete reassembly',
    statusIncomplete: 'Incomplete capture',
    statusUnknown: 'Expected size unknown',
    statusLegacy: 'Completeness verdict not provided by server (older server build)',
    statusError: 'Reassembly error',
    reconstructedBytes: 'Reconstructed bytes:',
    chunksCount: (n: number) => `${n} chunk(s)`,
    blocksCount: (n: number) => `${n} block(s)`,
    expectedBytes: 'Expected size:',
    expectedUnknown: 'Unknown',
    missingGaps: 'Missing blocks / gaps:',
    noGaps: 'None — byte stream is contiguous and complete',
    missingBytesCount: (missing: number, expected: number) =>
      `Missing ${missing} bytes (${((missing / expected) * 100).toFixed(1)}% missing of ${expected} declared bytes)`,
    missingChunksNamed: (chunks: string) => `Missing chunk sequence(s): ${chunks}`,
    integrity: 'Integrity verification:',
    integrityValidZigbee: (mfr: string, imgType: string, ver: string) =>
      `Valid Zigbee OTA header (0x0BEEF11E) · Mfr: ${mfr} · Image: ${imgType} · File version: ${ver}`,
    integrityValidBle: (size: string) => `Matches declared init packet size (${size})`,
    integrityNone: 'No init packet or container header provided for verification',
    flowStaged: (score: number) => `Carved firmware flow created (firmware score: ${score})`,
    ingestButton: 'Ingest into workbench',
    ingesting: 'Ingesting…',
    imageIngested: (id: string) => `Firmware ingested as image ${id}`,
    openOverview: 'Open image overview →',
    emptyTitle: 'No reassembly performed yet',
    emptyBody: 'Select a capture session, upload BLE DFU chunks or Zigbee OTA blocks, and start reassembly.',
  },
};
