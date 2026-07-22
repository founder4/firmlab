/**
 * Capture-backend registry (Phase 6, design §3). The extensibility promise — "plug a Zigbee dongle tomorrow and
 * FirmLab expands" — is solved exactly the way `tools.ts` solves tool detection: a registry of backends, each
 * auto-detected, each declaring what it can carry. New hardware present → its backend lights up → new transports
 * become available. This module answers "how could this deployment get on-path, and what could it read?".
 *
 * Backends split into two composable roles: a POSITIONING backend puts you where the bytes are (gateway, ARP
 * spoof); an INTERCEPTION/RADIO backend reads them (proxy, BLE/Zigbee sniffer). A capture plan is
 * (positioning?) + (interception|radio). Detection is READ-ONLY and harmless — it probes PATH, this process's
 * Linux capabilities, and attached USB — so it runs regardless of the `FIRMLAB_CAPTURE` flag; only *acting* is
 * gated. Every probe degrades honestly: absent tool / missing cap / no dongle → `available:false` with a reason
 * that says what would unlock it, never a fabricated capability.
 */
import fs from 'node:fs';
import path from 'node:path';

export type CaptureBackendId = 'network-proxy' | 'on-path-spoof' | 'on-path-gateway' | 'ble' | 'zigbee' | 'usb-serial';

export type CaptureRole = 'positioning' | 'interception' | 'radio' | 'physical';

export type Transport = 'http' | 'https' | 'ble-gatt' | 'zigbee-ota' | 'serial-dump';

/** Result of a backend's detect probe — mirrors the honest `available/reason` shape of a ToolStatus. */
export interface DetectResult {
  available: boolean;
  reason: string;
  detail?: Record<string, unknown>;
}

interface CaptureBackendSpec {
  id: CaptureBackendId;
  role: CaptureRole;
  /** What this backend can carry once positioned. */
  transports: Transport[];
  /** What enabling this backend gives the operator. */
  unlocks: string;
  capabilities: { decrypt?: boolean; needsHardware?: string; needsCaps?: string[] };
  /** Read-only probe: PATH / Linux caps / USB / operator declaration. Never touches the wire. */
  detect: () => DetectResult;
}

export interface CaptureBackendStatus {
  id: CaptureBackendId;
  role: CaptureRole;
  transports: Transport[];
  unlocks: string;
  available: boolean;
  reason: string;
  capabilities: CaptureBackendSpec['capabilities'];
  detail?: Record<string, unknown>;
}

// === Pure probe helpers (unit-tested; the fs/env-touching wrappers below call these) ===

/** Linux capability bit numbers (from linux/capability.h) the positioning backends need. */
export const CAP_NET_ADMIN = 12n;
export const CAP_NET_RAW = 13n;

/** Pure: extract the effective-capabilities bitmask from /proc/self/status text, or null if not present. */
export function parseCapEff(statusText: string): bigint | null {
  const m = statusText.match(/^CapEff:\s*([0-9a-fA-F]+)/m);
  if (!m?.[1]) return null;
  try {
    return BigInt(`0x${m[1]}`);
  } catch {
    return null;
  }
}

/** Pure: is a capability bit set in an effective-capabilities mask? */
export function capHeld(capEff: bigint, bit: bigint): boolean {
  return (capEff & (1n << bit)) !== 0n;
}

/** A USB device's vendor/product id, lowercased 4-hex-digit strings (as /sys exposes them). */
export interface UsbId {
  vid: string;
  pid: string;
}

// Known sniffer dongles → the transport they unlock. Kept deliberately small and specific so a random serial
// adapter never masquerades as a radio (honest detection over broad guesses). CP210x/CH340 UART bridges are
// intentionally NOT here — they're generic serial (see usb-serial), not proof of a Zigbee/BLE radio.
const KNOWN_BLE: { vid: string; pid?: string; label: string }[] = [
  { vid: '1915', label: 'Nordic nRF52840 (nRF Sniffer / Sniffle)' }, // Nordic Semiconductor
  { vid: '1366', label: 'SEGGER J-Link (nRF sniffer firmware)' },
];
const KNOWN_ZIGBEE: { vid: string; pid?: string; label: string }[] = [
  { vid: '0451', pid: '16a8', label: 'TI CC2531 Zigbee sniffer' },
  { vid: '1cf1', label: 'dresden elektronik ConBee / RaspBee' },
];

/** Pure: match attached USB ids against the known-radio tables. Returns the matched dongle label, or null. */
export function matchRadio(usbIds: UsbId[], table: { vid: string; pid?: string; label: string }[]): string | null {
  for (const known of table) {
    const hit = usbIds.find((u) => u.vid === known.vid && (known.pid === undefined || u.pid === known.pid));
    if (hit) return known.label;
  }
  return null;
}

// === System probes (side-effecting; kept thin so the pure helpers above hold the logic) ===

function onPath(bin: string): boolean {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    try {
      fs.accessSync(path.join(dir, bin), fs.constants.X_OK);
      return true;
    } catch {}
  }
  return false;
}

/** This process's effective Linux capabilities, or null on a platform/host that doesn't expose them. */
function effectiveCaps(): bigint | null {
  try {
    return parseCapEff(fs.readFileSync('/proc/self/status', 'utf8'));
  } catch {
    return null;
  }
}

/** Attached USB vendor/product ids from sysfs, or [] where sysfs isn't available (e.g. macOS, no USB passthrough). */
function usbIds(): UsbId[] {
  const out: UsbId[] = [];
  let entries: string[];
  try {
    entries = fs.readdirSync('/sys/bus/usb/devices');
  } catch {
    return out;
  }
  for (const e of entries) {
    try {
      const base = `/sys/bus/usb/devices/${e}`;
      const vid = fs.readFileSync(`${base}/idVendor`, 'utf8').trim().toLowerCase();
      const pid = fs.readFileSync(`${base}/idProduct`, 'utf8').trim().toLowerCase();
      if (vid && pid) out.push({ vid, pid });
    } catch {}
  }
  return out;
}

/** Serial adapters present as character devices (Linux naming). [] where none / not a Linux host. */
function serialPorts(): string[] {
  try {
    return fs
      .readdirSync('/dev')
      .filter((n) => /^tty(USB|ACM)\d+$/.test(n))
      .map((n) => `/dev/${n}`);
  } catch {
    return [];
  }
}

const BACKENDS: readonly CaptureBackendSpec[] = [
  {
    id: 'network-proxy',
    role: 'interception',
    transports: ['http', 'https'],
    unlocks: 'Intercept an HTTP OTA (or HTTPS when the device does not pin/validate) and carve the blob',
    capabilities: { decrypt: true },
    detect: () => {
      const have = onPath('mitmdump') || onPath('mitmproxy');
      return have
        ? {
            available: true,
            reason:
              'mitmproxy present — HTTP/HTTPS interception available (HTTPS needs the CA + a non-pinning device).',
          }
        : { available: false, reason: 'mitmproxy not installed — install it to intercept HTTP/HTTPS OTA flows.' };
    },
  },
  {
    id: 'on-path-spoof',
    role: 'positioning',
    transports: [],
    unlocks: 'Get on-path for one target without router config, via ARP/DNS spoof',
    capabilities: { needsCaps: ['NET_ADMIN', 'NET_RAW'] },
    detect: () => {
      const haveBin = onPath('bettercap');
      const caps = effectiveCaps();
      const netAdmin = caps !== null && capHeld(caps, CAP_NET_ADMIN);
      const netRaw = caps !== null && capHeld(caps, CAP_NET_RAW);
      if (haveBin && netAdmin && netRaw) {
        return {
          available: true,
          reason: 'bettercap present with NET_ADMIN + NET_RAW — ARP/DNS spoof positioning available.',
        };
      }
      const missing: string[] = [];
      if (!haveBin) missing.push('bettercap not installed');
      if (caps === null) missing.push('cannot read Linux capabilities (not a Linux host?)');
      else {
        if (!netAdmin) missing.push('missing NET_ADMIN cap');
        if (!netRaw) missing.push('missing NET_RAW cap');
      }
      return {
        available: false,
        reason: `${missing.join('; ')} — run with --cap-add=NET_ADMIN --cap-add=NET_RAW (and --network host on Docker) to enable spoof positioning.`,
      };
    },
  },
  {
    id: 'on-path-gateway',
    role: 'positioning',
    transports: [],
    unlocks: 'Cleanest capture: the target routes through FirmLab (default route / SPAN mirror), no spoofing',
    capabilities: {},
    detect: () => {
      const declared = process.env.FIRMLAB_CAPTURE_GATEWAY === '1';
      return declared
        ? {
            available: true,
            reason:
              'Operator declared gateway/mirror positioning (FIRMLAB_CAPTURE_GATEWAY=1) — confirmed once target traffic is seen.',
          }
        : {
            available: false,
            reason:
              'No gateway declared — set FIRMLAB_CAPTURE_GATEWAY=1 once FirmLab is the target route or a SPAN mirror feeds it.',
          };
    },
  },
  {
    id: 'ble',
    role: 'radio',
    transports: ['ble-gatt'],
    unlocks: 'Sniff a BLE OTA/DFU (Nordic DFU & friends) and reassemble the firmware',
    capabilities: { needsHardware: 'nRF52840 sniffer (nRF Sniffer / Sniffle)' },
    detect: () => {
      const label = matchRadio(usbIds(), KNOWN_BLE);
      return label
        ? { available: true, reason: `BLE sniffer detected: ${label}.`, detail: { dongle: label } }
        : {
            available: false,
            reason: 'No BLE sniffer attached — plug an nRF52840 (nRF Sniffer / Sniffle) to unlock ble-gatt capture.',
          };
    },
  },
  {
    id: 'zigbee',
    role: 'radio',
    transports: ['zigbee-ota'],
    unlocks: 'Capture the standard Zigbee OTA Upgrade cluster (0x0019)',
    capabilities: { needsHardware: 'CC2531 / ConBee Zigbee sniffer' },
    detect: () => {
      const label = matchRadio(usbIds(), KNOWN_ZIGBEE);
      return label
        ? { available: true, reason: `Zigbee sniffer detected: ${label}.`, detail: { dongle: label } }
        : {
            available: false,
            reason: 'No Zigbee sniffer attached — plug a CC2531 / ConBee to unlock zigbee-ota capture.',
          };
    },
  },
  {
    id: 'usb-serial',
    role: 'physical',
    transports: ['serial-dump'],
    unlocks: 'On-device dump over UART/serial when there is no OTA to intercept',
    capabilities: { needsHardware: 'USB-UART adapter' },
    detect: () => {
      const ports = serialPorts();
      return ports.length > 0
        ? { available: true, reason: `Serial adapter(s) present: ${ports.join(', ')}.`, detail: { ports } }
        : {
            available: false,
            reason: 'No USB-serial adapter present (/dev/ttyUSB*, /dev/ttyACM*) — attach one for a direct dump.',
          };
    },
  },
];

let cache: CaptureBackendStatus[] | null = null;

function probe(spec: CaptureBackendSpec): CaptureBackendStatus {
  const r = spec.detect();
  return {
    id: spec.id,
    role: spec.role,
    transports: spec.transports,
    unlocks: spec.unlocks,
    available: r.available,
    reason: r.reason,
    capabilities: spec.capabilities,
    ...(r.detail ? { detail: r.detail } : {}),
  };
}

/** Probe all capture backends. Cheap (fs/env only), but cached for the process lifetime like `detectTools`. */
export function detectCaptureBackends(force = false): CaptureBackendStatus[] {
  if (cache && !force) return cache;
  cache = BACKENDS.map(probe);
  return cache;
}

/**
 * Which transports the current backend mix can actually carry, given that a radio IS its own position but a
 * network transport (http/https) needs a positioning backend too. Used to state a target's honest capture ceiling.
 */
export function availableTransports(backends: CaptureBackendStatus[]): Transport[] {
  const positioned = backends.some((b) => b.role === 'positioning' && b.available);
  const out = new Set<Transport>();
  for (const b of backends) {
    if (!b.available) continue;
    for (const t of b.transports) {
      const needsPositioning = t === 'http' || t === 'https';
      if (needsPositioning && !positioned) continue;
      out.add(t);
    }
  }
  return [...out];
}
