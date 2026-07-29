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
 *
 * **Why `unlocks` is not on the spec below.** What a backend would let you acquire is prose an operator reads on
 * the Capture page, recomputed on every request from the hardware and the privileges actually on this box. It
 * describes THIS DEPLOYMENT, never a firmware image, and nothing about it is stored — so it follows `tools.ts`
 * exactly: it lives in `i18n/` keyed by `CaptureBackendId`, and `detectCaptureBackends` takes the locale as a
 * parameter. The cache therefore holds only what the probe LEARNED (available, reason, detail), and one cache
 * serves both languages.
 *
 * The probe's own `reason` deliberately stays where it is. It is not a fixed sentence about the backend: it is
 * built from what this box answered — the dongle's model line, the serial nodes present, the missing capability,
 * the layer-2 verdict — so it belongs with the probe, not with the catalogue. That leaves it English in a Spanish
 * render, which is a real seam: it is named here rather than papered over, because the honest fix is to compose
 * each reason from its parts in the catalogue, not to freeze today's English sentence into a lookup table.
 */
import fs from 'node:fs';
import path from 'node:path';
import { type Locale, messages } from '../i18n/index.js';

export type CaptureBackendId = 'network-proxy' | 'on-path-spoof' | 'on-path-gateway' | 'ble' | 'zigbee' | 'usb-serial';

/**
 * Every backend this build can probe, in table order. Exported so a test can check the gloss table and the
 * registry name exactly the same set — a backend added and never glossed would render as `undefined` in BOTH
 * languages, which is the one failure a catalogue typed against English cannot catch on its own.
 */
export const CAPTURE_BACKEND_IDS: readonly CaptureBackendId[] = [
  'network-proxy',
  'on-path-spoof',
  'on-path-gateway',
  'ble',
  'zigbee',
  'usb-serial',
];

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
  capabilities: { decrypt?: boolean; needsHardware?: string; needsCaps?: string[] };
  /** Read-only probe: PATH / Linux caps / USB / operator declaration. Never touches the wire. */
  detect: () => DetectResult;
}

export interface CaptureBackendStatus {
  id: CaptureBackendId;
  role: CaptureRole;
  transports: Transport[];
  /** What enabling this backend gives the operator — composed per request from `i18n/`, in the caller's language. */
  unlocks: string;
  available: boolean;
  reason: string;
  capabilities: CaptureBackendSpec['capabilities'];
  detail?: Record<string, unknown>;
}

/**
 * What a probe actually learned. No `unlocks`: this is what gets cached, and a cache holding a sentence in one
 * language would answer the second request in the wrong one.
 */
type BackendProbe = Omit<CaptureBackendStatus, 'unlocks'>;

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

/**
 * Pure: does this interface list belong to the HOST's network namespace rather than a container's own?
 *
 * A container on a Docker bridge network sees only `lo` and its own `eth0`. A container started with
 * `--network host` shares the host's namespace, so it sees the artefacts that only exist there: the `docker0`
 * bridge, the `br-<12 hex>` bridges of user-defined networks, and the `veth*` halves of other containers' pairs.
 * Any of those is proof the process is looking at the host's own interfaces.
 */
export function looksLikeHostNetns(ifaces: string[]): boolean {
  return ifaces.some((n) => n === 'docker0' || /^br-[0-9a-f]{12}$/.test(n) || n.startsWith('veth'));
}

/**
 * Pure: is this kernel a VM-backed container runtime (OrbStack, Docker Desktop's LinuxKit, Lima/Colima, WSL2)?
 *
 * These run Linux inside a VM on a macOS/Windows host, and the VM is itself NATed behind that host. `--network
 * host` there shares the **VM's** namespace, not the operator's LAN — so its interfaces look exactly like a real
 * Linux Docker host's (docker0, veth pairs) while still being one NAT away from any LAN device. Without this,
 * `--network host` on a Mac would be reported as spoof-capable and would silently reach nothing.
 */
export function looksLikeVmBackedRuntime(procVersion: string): boolean {
  return /orbstack|linuxkit|\blima\b|microsoft.*wsl|wsl2/i.test(procVersion);
}

/**
 * Pure: is this process on the LAN's own layer-2 segment — the precondition ARP spoofing cannot do without?
 *
 * This is the check that keeps the spoof backend from over-claiming once `bettercap` is actually in the image.
 * ARP poisoning works by answering for the gateway's MAC on the segment the target is on, so it needs the process
 * to sit on that segment. Two ways it does not:
 *
 *  - A container attached to a Docker bridge: its `eth0` lives on a private, NATed Docker subnet and its ARP
 *    frames never leave it.
 *  - A container under a VM-backed runtime, even with `--network host`: it shares the VM's namespace, and the VM
 *    is NATed behind the macOS/Windows host.
 *
 * In both cases the spoof is impossible no matter how many capabilities are granted or whether the binary is
 * installed — and reporting "missing NET_ADMIN" would point the operator at a fix that cannot work.
 * docs/CAPTURE-DESIGN.md §5b/§5c states this as prose; this makes it a machine-checked precondition, with the LAN
 * capture agent named as the path that does work.
 */
export function assessL2Reach(input: { containerized: boolean; hostNetns: boolean; vmBackedHost?: boolean }): {
  onLanSegment: boolean;
  reason: string;
} {
  if (!input.containerized) {
    return { onLanSegment: true, reason: 'running directly on the host — its interfaces are the LAN segment' };
  }
  // The remedy differs by WHY the segment is out of reach, and naming the wrong one is the same failure as
  // naming a missing capability: it sends the operator after something that cannot work. Under a VM-backed
  // runtime `--network host` is not a fix at any layer, so it is never offered as one.
  const remedy = input.vmBackedHost
    ? 'Run FirmLab on a real Linux host on the LAN, or deploy the LAN capture agent (CAPTURE-DESIGN §5c)'
    : 'Re-run with --network host, or deploy the LAN capture agent (CAPTURE-DESIGN §5c), which holds the privileges on the LAN and streams flows back';

  if (input.hostNetns) {
    if (input.vmBackedHost) {
      return {
        onLanSegment: false,
        reason: `container shares the host network namespace, but that host is a Linux VM (OrbStack / Docker Desktop / Lima / WSL) NATed behind macOS or Windows — --network host reaches the VM segment, not your LAN, so a spoof would poison nothing. ${remedy}`,
      };
    }
    return {
      onLanSegment: true,
      reason: 'container shares the host network namespace (--network host) — on the LAN segment',
    };
  }
  return {
    onLanSegment: false,
    reason: `container is on a Docker bridge network, not the LAN segment — its ARP frames never reach a LAN device, so spoof positioning is impossible here regardless of caps. ${remedy}`,
  };
}

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

/** Is this process inside a container? `/.dockerenv` plus the cgroup path cover Docker, containerd and k8s. */
function containerized(): boolean {
  try {
    if (fs.existsSync('/.dockerenv')) return true;
  } catch {}
  try {
    return /docker|containerd|kubepods|libpod/.test(fs.readFileSync('/proc/1/cgroup', 'utf8'));
  } catch {
    return false;
  }
}

/** Network interface names visible to this process. [] where sysfs isn't available (e.g. macOS). */
function interfaceNames(): string[] {
  try {
    return fs.readdirSync('/sys/class/net');
  } catch {
    return [];
  }
}

/** The running kernel's version string — how a VM-backed container runtime identifies itself. */
function procVersion(): string {
  try {
    return fs.readFileSync('/proc/version', 'utf8');
  } catch {
    return '';
  }
}

/** Whether this process can reach the LAN at layer 2 at all — the spoof backend's binding precondition. */
function l2Reach(): { onLanSegment: boolean; reason: string } {
  return assessL2Reach({
    containerized: containerized(),
    hostNetns: looksLikeHostNetns(interfaceNames()),
    vmBackedHost: looksLikeVmBackedRuntime(procVersion()),
  });
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
    capabilities: { needsCaps: ['NET_ADMIN', 'NET_RAW'] },
    detect: () => {
      const haveBin = onPath('bettercap');
      const caps = effectiveCaps();
      const netAdmin = caps !== null && capHeld(caps, CAP_NET_ADMIN);
      const netRaw = caps !== null && capHeld(caps, CAP_NET_RAW);
      const l2 = l2Reach();
      const detail = { bettercap: haveBin, netAdmin, netRaw, onLanSegment: l2.onLanSegment, l2: l2.reason };

      // Layer-2 reach is reported FIRST and on its own, because it is the one precondition no amount of tooling or
      // privilege can substitute for. Telling a bridge-networked deployment to add NET_ADMIN would send the
      // operator after a fix that cannot work — the honest answer names host networking or the LAN agent instead.
      if (!l2.onLanSegment) {
        return {
          available: false,
          reason: `Spoof positioning is not possible in this deployment: ${l2.reason}.`,
          detail,
        };
      }
      if (haveBin && netAdmin && netRaw) {
        return {
          available: true,
          reason: `bettercap present with NET_ADMIN + NET_RAW, and ${l2.reason} — ARP/DNS spoof positioning available.`,
          detail,
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
        reason: `${missing.join('; ')} — run with --cap-add=NET_ADMIN --cap-add=NET_RAW to enable spoof positioning (this process IS on the LAN segment: ${l2.reason}).`,
        detail,
      };
    },
  },
  {
    id: 'on-path-gateway',
    role: 'positioning',
    transports: [],
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

let cache: BackendProbe[] | null = null;

function probe(spec: CaptureBackendSpec): BackendProbe {
  const r = spec.detect();
  return {
    id: spec.id,
    role: spec.role,
    transports: spec.transports,
    available: r.available,
    reason: r.reason,
    capabilities: spec.capabilities,
    ...(r.detail ? { detail: r.detail } : {}),
  };
}

/**
 * Pure: dress a cached probe in one language. The id, the role, the transports and the probe's own reason are
 * what the rest of the system keys on or what this box answered — they pass through untouched; only the gloss is
 * localised.
 */
function describe(p: BackendProbe, locale: Locale): CaptureBackendStatus {
  return { ...p, unlocks: messages(locale).captureBackends.unlocks[p.id] };
}

/**
 * Probe all capture backends, then describe them in the requested language. Cheap (fs/env only), but cached for
 * the process lifetime like `detectTools` — and the cache is language-independent, so one probe serves both. The
 * locale defaults to English, so a caller that predates it (and a request with no `?lang`) is unaffected.
 */
export function detectCaptureBackends(force = false, locale: Locale = 'en'): CaptureBackendStatus[] {
  if (!cache || force) cache = BACKENDS.map(probe);
  return cache.map((p) => describe(p, locale));
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
