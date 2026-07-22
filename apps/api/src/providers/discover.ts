/**
 * Device discovery (Phase 6.0, design §6). Before you can pick a capture target you need to SEE the network. This
 * provider builds a live LAN inventory: a host sweep (arp-scan preferred — it yields the MAC directly — falling
 * back to `nmap -sn`), MAC → vendor via OUI, optional mDNS/DNS-SD enrichment (avahi-browse), and a light,
 * never-asserted device-type guess with a confidence.
 *
 * Discovery is PASSIVE/observational: it enumerates who is on the wire, it does not intercept anything. Every step
 * degrades honestly — no tool → `available:false` with the reason and what would unlock it; an unknown OUI → vendor
 * null; a weak signal → a low-confidence guess phrased as a question, never a claim. The parsers are pure and
 * unit-tested; the single side-effecting runner at the bottom shells out and never throws on a missing tool.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface ScannedHost {
  ip: string;
  mac: string;
  vendor?: string;
}

export type Confidence = 'low' | 'medium' | 'high';

export interface DiscoveredDevice {
  mac: string;
  ip: string | null;
  ouiVendor: string | null;
  /** Advertised mDNS/SSDP service types + instance name, or null when none were seen. */
  mdnsIdentity: string | null;
  openPorts: number[];
  typeGuess: string | null;
  typeConfidence: Confidence | null;
}

export interface DiscoveryResult {
  available: boolean;
  /** The sweep tool actually used, or null when none was available. */
  tool: 'arp-scan' | 'nmap' | null;
  subnet: string | null;
  devices: DiscoveredDevice[];
  reason: string;
}

// === Pure: MAC normalization + OUI vendor lookup ===

/** Pure: normalize a MAC to lowercase colon form, or null if it isn't a 6-octet MAC. */
export function normalizeMac(mac: string): string | null {
  const hex = mac
    .trim()
    .toLowerCase()
    .replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12) return null;
  return (hex.match(/.{2}/g) as string[]).join(':');
}

// A small, curated OUI → vendor table for common IoT makers. This is only a FALLBACK: arp-scan ships the full
// IEEE OUI file and its vendor column is authoritative when present; this fills nmap output and blank columns.
// Keys are the 6-hex-digit OUI prefix, uppercase, no separators. Unknown prefix → null (honest, never a guess).
const OUI_VENDORS: Record<string, string> = {
  '240AC4': 'Espressif',
  '246F28': 'Espressif',
  A4CF12: 'Espressif',
  '7C9EBD': 'Espressif',
  ECFABC: 'Espressif',
  '50C7BF': 'TP-Link',
  A42BB0: 'TP-Link',
  AC84C6: 'TP-Link',
  C46E1F: 'TP-Link',
  '10D561': 'Tuya Smart',
  D81F12: 'Tuya Smart',
  '680AB8': 'Tuya Smart',
  '546009': 'Google/Nest',
  F4F5E8: 'Google/Nest',
  '1CF29A': 'Google/Nest',
  '44650D': 'Amazon',
  '6837E9': 'Amazon',
  FC65DE: 'Amazon',
  A002DC: 'Amazon',
  '7811DC': 'Xiaomi',
  '640980': 'Xiaomi',
  '286C07': 'Xiaomi',
  '000E58': 'Sonos',
  '5CAAFD': 'Sonos',
  B8E937: 'Sonos',
  '001788': 'Philips Hue',
  ECB5FA: 'Philips Hue',
  B827EB: 'Raspberry Pi',
  DCA632: 'Raspberry Pi',
  E45F01: 'Raspberry Pi',
  '2CCF67': 'Raspberry Pi',
};

/** Pure: vendor for a MAC from the built-in OUI table, or null if the prefix isn't known. */
export function ouiVendor(mac: string): string | null {
  const norm = normalizeMac(mac);
  if (!norm) return null;
  const prefix = norm.replace(/:/g, '').slice(0, 6).toUpperCase();
  return OUI_VENDORS[prefix] ?? null;
}

// === Pure: sweep-output parsers ===

/**
 * Pure: parse `arp-scan` output. Data lines are `<ip>\t<mac>\t<vendor?>`; the banner/footer lines (Interface:,
 * Starting/Ending arp-scan, "N packets received") are skipped.
 */
export function parseArpScan(text: string): ScannedHost[] {
  const out: ScannedHost[] = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s*(.*)$/);
    if (!m) continue;
    const mac = normalizeMac(m[2] as string);
    if (!mac) continue;
    const vendor = (m[3] ?? '').trim();
    out.push({ ip: m[1] as string, mac, ...(vendor && vendor !== '(Unknown)' ? { vendor } : {}) });
  }
  return out;
}

/**
 * Pure: parse `nmap -sn` output. Each host is a "Nmap scan report for [name ](ip)" line optionally followed by a
 * "MAC Address: <mac> (<vendor>)" line; hosts without a MAC line (e.g. the scanning host itself) are dropped since
 * discovery keys on MAC.
 */
export function parseNmapSn(text: string): ScannedHost[] {
  const out: ScannedHost[] = [];
  let pendingIp: string | null = null;
  for (const line of text.split('\n')) {
    const rep = line.match(/^Nmap scan report for (?:.*\()?(\d{1,3}(?:\.\d{1,3}){3})\)?/);
    if (rep) {
      pendingIp = rep[1] as string;
      continue;
    }
    const macLine = line.match(/^MAC Address:\s*([0-9a-fA-F:]{17})\s*(?:\((.*)\))?/);
    if (macLine && pendingIp) {
      const mac = normalizeMac(macLine[1] as string);
      if (mac) {
        const vendor = (macLine[2] ?? '').trim();
        out.push({ ip: pendingIp, mac, ...(vendor && vendor !== 'Unknown' ? { vendor } : {}) });
      }
      pendingIp = null;
    }
  }
  return out;
}

/**
 * Pure: parse `avahi-browse -aprt` machine-readable output into IP → advertised service types + instance names.
 * Resolved records begin with `=`; fields are `;`-separated: =;iface;proto;name;type;domain;host;addr;port;txt.
 */
export function parseAvahiBrowse(text: string): Map<string, { services: Set<string>; names: Set<string> }> {
  const byIp = new Map<string, { services: Set<string>; names: Set<string> }>();
  for (const line of text.split('\n')) {
    if (!line.startsWith('=')) continue;
    const f = line.split(';');
    const name = f[3];
    const type = f[4];
    const addr = f[7];
    if (!addr || !/^\d{1,3}(\.\d{1,3}){3}$/.test(addr)) continue;
    const entry = byIp.get(addr) ?? { services: new Set<string>(), names: new Set<string>() };
    if (type) entry.services.add(type);
    if (name) entry.names.add(name);
    byIp.set(addr, entry);
  }
  return byIp;
}

/** Pure: pick the primary /24-ish subnet (CIDR) from `ip -o -4 addr show` output, skipping loopback. */
export function parsePrimarySubnet(ipAddrOutput: string): string | null {
  for (const line of ipAddrOutput.split('\n')) {
    if (/\blo\b/.test(line) && /127\.0\.0\.1/.test(line)) continue;
    const m = line.match(/inet\s+(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})/);
    if (!m) continue;
    const ip = m[1] as string;
    if (ip.startsWith('127.')) continue;
    // Normalize to the network address so arp-scan/nmap accept it (e.g. 192.168.1.34/24 → 192.168.1.0/24).
    const bits = Number(m[2]);
    const octets = ip.split('.').map(Number);
    if (bits === 24) return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
    return `${ip}/${bits}`;
  }
  return null;
}

// === Pure: device-type guess (heuristic, never asserted) ===

interface GuessInput {
  vendor: string | null;
  mdnsServices: string[];
  ports: number[];
}

/** Pure: a best-effort device-type guess with a confidence, or null when nothing corroborates. Phrased as a guess. */
export function guessDeviceType(input: GuessInput): { type: string; confidence: Confidence } | null {
  const services = input.mdnsServices.map((s) => s.toLowerCase());
  const has = (frag: string): boolean => services.some((s) => s.includes(frag));
  const vendor = (input.vendor ?? '').toLowerCase();

  // mDNS service types are the strongest signal — a device announcing what it is.
  if (has('_ipp') || has('_printer') || has('_pdl-datastream')) return { type: 'printer?', confidence: 'high' };
  if (has('_hap')) return { type: 'HomeKit accessory?', confidence: 'medium' };
  if (has('_googlecast')) return { type: 'Chromecast / smart display?', confidence: 'medium' };
  if (has('_spotify-connect') || has('_sonos') || has('_raop')) return { type: 'media speaker?', confidence: 'medium' };
  if (has('_amzn') || has('_amazon')) return { type: 'Amazon Echo / Fire device?', confidence: 'medium' };
  if (has('_axis') || has('_rtsp')) return { type: 'IP camera?', confidence: 'medium' };

  // Open ports are a weaker corroborating signal.
  if (input.ports.includes(554)) return { type: 'IP camera (RTSP)?', confidence: 'medium' };
  if (input.ports.includes(6668) || input.ports.includes(6667))
    return { type: 'Tuya smart device?', confidence: 'medium' };

  // Vendor alone is the weakest — a low-confidence lead only.
  if (vendor.includes('sonos')) return { type: 'Sonos speaker?', confidence: 'high' };
  if (vendor.includes('hue')) return { type: 'Philips Hue lighting?', confidence: 'high' };
  if (vendor.includes('tuya')) return { type: 'smart plug / bulb?', confidence: 'low' };
  if (vendor.includes('espressif')) return { type: 'ESP32/ESP8266 IoT device?', confidence: 'low' };
  if (vendor.includes('raspberry')) return { type: 'Raspberry Pi SBC?', confidence: 'medium' };
  if (vendor.includes('amazon')) return { type: 'Amazon device?', confidence: 'low' };
  if (vendor.includes('google') || vendor.includes('nest')) return { type: 'Google/Nest device?', confidence: 'low' };
  return null;
}

/**
 * Pure: merge the sweep hosts with optional mDNS enrichment into the device inventory. Dedupes by MAC, prefers the
 * sweep's own vendor string over the OUI-table fallback, and computes the type guess from all corroborating signals.
 */
export function buildDevices(
  hosts: ScannedHost[],
  mdnsByIp: Map<string, { services: Set<string>; names: Set<string> }> = new Map(),
): DiscoveredDevice[] {
  const byMac = new Map<string, DiscoveredDevice>();
  for (const h of hosts) {
    const mdns = h.ip ? mdnsByIp.get(h.ip) : undefined;
    const services = mdns ? [...mdns.services] : [];
    const names = mdns ? [...mdns.names] : [];
    const vendor = h.vendor ?? ouiVendor(h.mac);
    const guess = guessDeviceType({ vendor, mdnsServices: services, ports: [] });
    const identity = services.length || names.length ? [...names, ...services].join(' ') : null;
    const dev: DiscoveredDevice = {
      mac: h.mac,
      ip: h.ip || null,
      ouiVendor: vendor,
      mdnsIdentity: identity,
      openPorts: [],
      typeGuess: guess ? guess.type : null,
      typeConfidence: guess ? guess.confidence : null,
    };
    byMac.set(h.mac, dev);
  }
  return [...byMac.values()];
}

// === Side-effecting runner ===

async function tryExec(bin: string, args: string[], timeoutMs: number): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync(bin, args, { timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 });
    return stdout;
  } catch (e) {
    // A tool that ran but exited non-zero may still have written useful stdout (e.g. arp-scan with partial results).
    const withOut = e as { stdout?: string; code?: string };
    if (withOut?.code === 'ENOENT') return null; // tool not installed
    return typeof withOut?.stdout === 'string' && withOut.stdout.length > 0 ? withOut.stdout : null;
  }
}

async function resolveSubnet(explicit: string | null, timeoutMs: number): Promise<string | null> {
  if (explicit) return explicit;
  const out = await tryExec('ip', ['-o', '-4', 'addr', 'show'], timeoutMs);
  return out ? parsePrimarySubnet(out) : null;
}

/**
 * Run a passive host sweep + optional mDNS enrichment over the chosen subnet. Returns the device inventory, or an
 * honest `available:false` when no sweep tool is installed or no subnet could be determined. Never intercepts.
 */
export async function runDiscovery(opts: { subnet: string | null; timeoutMs: number }): Promise<DiscoveryResult> {
  const subnet = await resolveSubnet(opts.subnet, Math.min(opts.timeoutMs, 5000));
  if (!subnet) {
    return {
      available: false,
      tool: null,
      subnet: null,
      devices: [],
      reason: 'No subnet to scan — pass one (e.g. 192.168.1.0/24) or ensure `ip` can report the primary interface.',
    };
  }

  // arp-scan is preferred: it yields the MAC directly in one pass. Fall back to nmap -sn (which also reports MACs
  // when run with privilege on the local segment).
  let tool: 'arp-scan' | 'nmap' | null = null;
  let hosts: ScannedHost[] = [];
  const arp = await tryExec('arp-scan', ['--retry=2', subnet], opts.timeoutMs);
  if (arp !== null) {
    tool = 'arp-scan';
    hosts = parseArpScan(arp);
  } else {
    const nmap = await tryExec('nmap', ['-sn', subnet], opts.timeoutMs);
    if (nmap !== null) {
      tool = 'nmap';
      hosts = parseNmapSn(nmap);
    }
  }

  if (tool === null) {
    return {
      available: false,
      tool: null,
      subnet,
      devices: [],
      reason:
        'Neither arp-scan nor nmap is installed — install one to sweep the LAN. (On Docker, discovery also needs --network host.)',
    };
  }

  // Optional mDNS/DNS-SD enrichment; silently skipped if avahi-browse isn't present.
  const avahi = await tryExec('avahi-browse', ['-aprt'], Math.min(opts.timeoutMs, 8000));
  const mdns = avahi ? parseAvahiBrowse(avahi) : new Map();

  const devices = buildDevices(hosts, mdns);
  const typed = devices.filter((d) => d.typeGuess).length;
  return {
    available: true,
    tool,
    subnet,
    devices,
    reason: `Swept ${subnet} with ${tool}: ${devices.length} device(s)${mdns.size ? `, ${mdns.size} announcing over mDNS` : ''}, ${typed} with a type guess. Passive — nothing was intercepted.`,
  };
}
