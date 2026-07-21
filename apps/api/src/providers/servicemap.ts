/**
 * servicemap provider — a static network-SERVICE-ENUMERATION over an ALREADY-EXTRACTED Linux rootfs. Where
 * fsaudit reads the misconfiguration surface (credentials, init shells, permissive daemon configs), this track
 * answers a narrower, load-bearing question WITHOUT booting anything: which network services/daemons is the
 * firmware configured to START — i.e. the boot-time attack surface. It reads the four places a service is wired
 * up on an embedded Linux image — /etc/inittab (respawn/once), /etc/inetd.conf, the SysV/BusyBox rc scripts
 * (etc/init.d, etc/rc.d, etc/rc*.d), and systemd `*.service` units — maps each invocation to a binary, decides
 * whether it is a known network daemon, and infers an obvious default port.
 *
 * The parsers are PURE (each takes text and returns Service[]) and unit-tested against synthetic real-format
 * inputs. Proof states are HONEST: the inventory is a fact about the configuration (`static_confirmed`), while a
 * per-daemon "starts on boot" exposure is a LEAD (`needs_runtime_reproduction`) — whether the service is truly
 * listening and reachable depends on the interface being up, the daemon actually launching, and no firewall, so
 * it is never asserted as a device verdict. The runner tolerates every file being missing and degrades to
 * available:false when there is no rootfs — it never fabricates a service. Paths are confined to the rootfs base;
 * a symlink is never followed out of it.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings-normalize.js';

/** A network service/daemon the rootfs is statically configured to run, and where that configuration lives. */
export interface Service {
  /** Friendly name — the daemon/service basename (e.g. `telnetd`, `dropbear`, or the inetd service `telnet`). */
  name: string;
  /** The invoked binary as written in the config (a path like `/usr/sbin/dropbear`, or a bare `httpd`). */
  binary: string;
  /** Where the configuration was found (e.g. `/etc/inittab`, `/etc/inetd.conf`, `etc/init.d/S50telnet`). */
  source: string;
  /** True when the binary is a known network daemon (listens on the network). */
  network: boolean;
  /** True when the configuration starts it automatically (init respawn/once, inetd, rc `&`/start, systemd WantedBy). */
  autostart: boolean;
  /** An obvious default port for the daemon, when one can be inferred. */
  port?: number;
}

// ============================================================================
// Known network daemons + default ports
// ============================================================================

/**
 * Known network daemons → their obvious default port. Membership of this table IS the definition of "network
 * daemon" for `isNetworkDaemon`; a basename outside it is treated as a non-network local service.
 */
const PORTS: Record<string, number> = {
  // HTTP servers common in embedded firmware
  httpd: 80,
  lighttpd: 80,
  uhttpd: 80,
  mini_httpd: 80,
  goahead: 80,
  boa: 80,
  thttpd: 80,
  // telnet
  telnetd: 23,
  utelnetd: 23,
  // ssh
  dropbear: 22,
  sshd: 22,
  // ftp
  ftpd: 21,
  vsftpd: 21,
  // UPnP
  upnpd: 1900,
  miniupnpd: 1900,
  // DNS
  dnsmasq: 53,
  // TR-069 / CWMP remote management
  tr069: 7547,
  cwmpd: 7547,
};

/** Normalize a binary basename for daemon matching: lowercase, drop an inetd `in.` prefix and any leading dashes. */
function normalizeDaemon(basename: string): string {
  return basename.toLowerCase().replace(/^-+/, '').replace(/^in\./, '');
}

/** Pure: whether a binary basename names a known network daemon. */
export function isNetworkDaemon(binaryBasename: string): boolean {
  return normalizeDaemon(binaryBasename) in PORTS;
}

/** Pure: an obvious default port for a known network daemon basename, or undefined when not obvious/known. */
export function defaultPort(binaryBasename: string): number | undefined {
  return PORTS[normalizeDaemon(binaryBasename)];
}

/** The set of known daemon names the rc-script scanner greps for. */
const DAEMON_NAMES = Object.keys(PORTS);

/**
 * A small /etc/services-style table mapping an inetd service-name column to its well-known port. Kept deliberately
 * compact — the point is to resolve the common firmware services; an unknown name simply yields no port.
 */
const INETD_PORTS: Record<string, number> = {
  telnet: 23,
  ftp: 21,
  'ftp-data': 20,
  ssh: 22,
  http: 80,
  www: 80,
  https: 443,
  domain: 53,
  smtp: 25,
  tftp: 69,
  finger: 79,
  shell: 514,
  login: 513,
  exec: 512,
  discard: 9,
  daytime: 13,
  echo: 7,
  time: 37,
  chargen: 19,
  pop3: 110,
  imap: 143,
  snmp: 161,
};

// ============================================================================
// small pure helpers
// ============================================================================

/** POSIX-style basename that also strips inittab leading dashes (config text is always POSIX-pathed). */
function basenameOf(p: string): string {
  const parts = p.replace(/^-+/, '').split('/');
  return parts[parts.length - 1] ?? p;
}

/** Build a Service, only attaching `port` when defined (exactOptionalPropertyTypes-safe). */
function mk(
  name: string,
  binary: string,
  source: string,
  network: boolean,
  autostart: boolean,
  port: number | undefined,
): Service {
  return { name, binary, source, network, autostart, ...(port !== undefined ? { port } : {}) };
}

// ============================================================================
// /etc/inittab
// ============================================================================

/**
 * Pure: parse /etc/inittab `id:runlevels:action:process` lines. Only `respawn`/`once` actions start a long-lived
 * service, so those become Services (autostart true); the process command's first token is the binary. sysinit,
 * wait, shutdown, ctrlaltdel and friends are not service starts and are skipped.
 */
export function parseInittab(text: string): Service[] {
  const out: Service[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(':');
    if (parts.length < 4) continue;
    const action = (parts[2] ?? '').trim().toLowerCase();
    if (action !== 'respawn' && action !== 'once') continue;
    const process = parts.slice(3).join(':').trim();
    if (!process) continue;
    const first = process.split(/\s+/)[0] ?? '';
    const binary = first.replace(/^-+/, '');
    if (!binary) continue;
    const b = basenameOf(binary);
    out.push(mk(b, binary, '/etc/inittab', isNetworkDaemon(b), true, defaultPort(b)));
  }
  return out;
}

// ============================================================================
// /etc/inetd.conf
// ============================================================================

/** Pure: resolve an inetd service-name column (`[host:]service[/version]`, or a bare numeric port) to a port. */
function inetdPort(nameCol: string): number | undefined {
  let s = nameCol;
  if (s.includes(':')) s = s.slice(s.lastIndexOf(':') + 1); // drop a bind-address prefix
  s = s.split('/')[0] ?? s; // drop an RPC version suffix
  const n = Number(s);
  if (Number.isInteger(n) && n > 0) return n;
  return INETD_PORTS[s.toLowerCase()];
}

/**
 * Pure: parse /etc/inetd.conf `service socktype proto flags user server args` lines. Every inetd entry is a
 * network service the super-server is configured to launch on connect, so each becomes a network Service with
 * autostart true; the service-name column resolves to a port via the /etc/services-style table.
 */
export function parseInetd(text: string): Service[] {
  const out: Service[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const f = line.split(/\s+/);
    if (f.length < 6) continue; // need at least through the server column
    const nameCol = f[0] ?? '';
    const server = f[5] ?? '';
    let svcName = nameCol;
    if (svcName.includes(':')) svcName = svcName.slice(svcName.lastIndexOf(':') + 1);
    svcName = svcName.split('/')[0] ?? svcName;
    const binary = server === 'internal' ? 'internal' : server;
    const name = svcName || basenameOf(server);
    out.push(mk(name, binary, '/etc/inetd.conf', true, true, inetdPort(nameCol)));
  }
  return out;
}

// ============================================================================
// SysV / BusyBox rc scripts
// ============================================================================

/** Whether a script line looks like it actually STARTS a daemon (backgrounded, start-stop-daemon, or `… start`). */
function hasStartIndicator(line: string): boolean {
  if (/start-stop-daemon\b/.test(line)) return true;
  if (/&\s*$/.test(line)) return true; // backgrounded
  if (/\bstart\b/.test(line)) return true; // `daemon start` / `service X start` (not `restart`, no word-boundary)
  return false;
}

/** Find the token on `line` whose basename is exactly `daemon` (so `mini_httpd` never matches `httpd`). */
function findDaemonToken(line: string, daemon: string): string | null {
  for (const rawTok of line.split(/\s+/)) {
    const tok = rawTok.replace(/^[(){}"'`]+/, '').replace(/[;&|"'`(){}]+$/g, '');
    if (!tok) continue;
    if (normalizeDaemon(basenameOf(tok)) === daemon) return tok;
  }
  return null;
}

/**
 * Pure: scan a SysV/BusyBox init or rc script for invocations of a known network daemon that are actually started
 * (backgrounded with `&`, via `start-stop-daemon`, or a `… start` line). Each such invocation becomes a network
 * Service with autostart true, sourced to the script path. Comment lines are ignored.
 */
export function parseRcScript(scriptPath: string, text: string): Service[] {
  const out: Service[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (!hasStartIndicator(line)) continue;
    for (const daemon of DAEMON_NAMES) {
      const tok = findDaemonToken(line, daemon);
      if (!tok) continue;
      out.push(mk(daemon, tok, scriptPath, true, true, PORTS[daemon]));
    }
  }
  return out;
}

// ============================================================================
// systemd units
// ============================================================================

/**
 * Pure: parse a systemd `*.service` unit. The first `ExecStart=` value's leading token (with systemd's `-@+!:`
 * exec prefixes stripped) is the binary; an `[Install] WantedBy=` line means the unit is enabled to autostart.
 */
export function parseSystemdUnit(unitPath: string, text: string): Service[] {
  let binary: string | null = null;
  for (const raw of text.split('\n')) {
    const m = /^\s*ExecStart\s*=\s*(.+)$/.exec(raw);
    if (!m) continue;
    const first = (m[1] ?? '').trim().split(/\s+/)[0] ?? '';
    const cleaned = first.replace(/^[-@+!:]+/, '');
    if (cleaned) {
      binary = cleaned;
      break;
    }
  }
  if (!binary) return [];
  const autostart = /^\s*WantedBy\s*=\s*\S/m.test(text);
  const b = basenameOf(binary);
  return [mk(b, binary, unitPath, isNetworkDaemon(b), autostart, defaultPort(b))];
}

// ============================================================================
// aggregation + findings
// ============================================================================

/** Pure: dedupe services by (binary basename + source) and sort network-facing first, then by name. */
export function buildServiceMap(services: Service[]): Service[] {
  const seen = new Set<string>();
  const out: Service[] = [];
  for (const s of services) {
    const key = `${basenameOf(s.binary).toLowerCase()}::${s.source}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
  }
  out.sort((a, b) => {
    if (a.network !== b.network) return a.network ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
  return out;
}

/**
 * Pure: turn the service map into honest findings.
 *   - inventory              → `info` / `static_confirmed`: the factual list + counts of what is configured to run.
 *   - exposed network daemon → `low` / `needs_runtime_reproduction`: one lead per network daemon set to autostart
 *                              ("starts on boot — attack surface"). Reachability (interface up, actually listening,
 *                              not firewalled) is unproven, so each is a lead, never a device verdict.
 */
export function serviceFindings(services: Service[]): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  if (services.length === 0) return drafts;

  const networkServices = services.filter((s) => s.network);
  const autostartCount = services.filter((s) => s.autostart).length;
  drafts.push({
    kind: 'service-inventory',
    title: `Service map: ${services.length} configured service(s), ${networkServices.length} network-facing`,
    severity: 'info',
    proofState: 'static_confirmed',
    evidence: {
      total: services.length,
      network: networkServices.length,
      autostart: autostartCount,
      services: services.map((s) => ({
        name: s.name,
        binary: s.binary,
        source: s.source,
        network: s.network,
        autostart: s.autostart,
        ...(s.port !== undefined ? { port: s.port } : {}),
      })),
    },
    rationale:
      'Statically enumerated the services/daemons the extracted rootfs is configured to start (inittab, inetd, ' +
      'rc scripts, systemd) — a factual inventory of the boot-time attack surface. Proves the configuration, not ' +
      'that any service is running.',
  });

  for (const s of services.filter((x) => x.network && x.autostart)) {
    drafts.push({
      kind: 'network-daemon-autostart',
      title: `Network daemon ${s.name} starts on boot — attack surface`,
      severity: 'low',
      proofState: 'needs_runtime_reproduction',
      evidence: {
        name: s.name,
        binary: s.binary,
        source: s.source,
        ...(s.port !== undefined ? { port: s.port } : {}),
      },
      rationale: `network daemon ${s.name} starts on boot — attack surface, reachable if the interface is up. This is the static configuration only; runtime reproduction is needed to confirm the daemon actually launches, listens, and is reachable (not firewalled).`,
    });
  }
  return drafts;
}

// ============================================================================
// runner
// ============================================================================

export interface ServiceMapResult {
  available: boolean;
  services: Service[];
  findings: FindingDraft[];
  reason: string;
}

const FILE_CAP = 2000;
const READ_BYTES = 256 * 1024;
// Directory names under etc/ that hold rc/init start-up scripts: init.d, rc.d, rcS.d, rc0.d … rc6.d.
const RC_DIR_NAME_RE = /^(?:init\.d|rc\.d|rc\S*\.d)$/i;
const SYSTEMD_DIRS = ['etc/systemd/system', 'lib/systemd/system', 'usr/lib/systemd/system'];

/** Confine a rootfs-relative path to the rootfs; returns the absolute path, or null on traversal. */
function safeJoin(root: string, rel: string): string | null {
  const abs = path.resolve(root, rel);
  if (abs !== root && !abs.startsWith(root + path.sep)) return null;
  return abs;
}

/** Best-effort UTF-8 read of a rootfs-relative file (missing/unreadable/escaping → ''). */
function readInside(root: string, rel: string): string {
  const abs = safeJoin(root, rel);
  if (!abs) return '';
  try {
    return fs.readFileSync(abs, 'utf8');
  } catch {
    return '';
  }
}

/** Read at most `cap` bytes of a file as UTF-8 (a mis-sized script can't blow up the scan). */
function readBounded(abs: string, cap: number): string {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, cap);
      const buf = Buffer.allocUnsafe(size);
      fs.readSync(fd, buf, 0, size, 0);
      return buf.toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return '';
  }
}

/** Collect (bounded) the rc/init scripts under etc/init.d, etc/rc.d(/init.d) and any etc/rc*.d directory. */
function collectRcScripts(root: string, budget: { n: number }): { path: string; content: string }[] {
  const out: { path: string; content: string }[] = [];
  const dirs = new Set<string>(['etc/init.d', 'etc/rc.d', 'etc/rc.d/init.d']);
  const etcAbs = safeJoin(root, 'etc');
  if (etcAbs) {
    try {
      for (const e of fs.readdirSync(etcAbs, { withFileTypes: true })) {
        if (e.isDirectory() && RC_DIR_NAME_RE.test(e.name)) dirs.add(path.posix.join('etc', e.name));
      }
    } catch {
      // no etc/ — nothing to add
    }
  }
  for (const dir of dirs) {
    if (budget.n >= FILE_CAP) break;
    const abs = safeJoin(root, dir);
    if (!abs) continue;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (budget.n >= FILE_CAP) break;
      if (e.isSymbolicLink() || !e.isFile()) continue;
      const rel = path.posix.join(dir, e.name);
      const fileAbs = safeJoin(root, rel);
      if (!fileAbs) continue;
      budget.n++;
      out.push({ path: rel, content: readBounded(fileAbs, READ_BYTES) });
    }
  }
  return out;
}

/** Collect (bounded, symlink-safe) the `*.service` units under the systemd unit directories. */
function collectSystemdUnits(root: string, budget: { n: number }): { path: string; content: string }[] {
  const out: { path: string; content: string }[] = [];
  for (const base of SYSTEMD_DIRS) {
    const stack: string[] = [base];
    while (stack.length > 0 && budget.n < FILE_CAP) {
      const rel = stack.pop() as string;
      const abs = safeJoin(root, rel);
      if (!abs) continue;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(abs, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries) {
        if (budget.n >= FILE_CAP) break;
        if (e.isSymbolicLink()) continue; // never follow a symlink out of the rootfs (also skips .wants links)
        const childRel = path.posix.join(rel, e.name);
        if (e.isDirectory()) {
          stack.push(childRel);
        } else if (e.isFile() && e.name.endsWith('.service')) {
          const fileAbs = safeJoin(root, childRel);
          if (!fileAbs) continue;
          budget.n++;
          out.push({ path: childRel, content: readBounded(fileAbs, READ_BYTES) });
        }
      }
    }
  }
  return out;
}

/**
 * Run the static service-enumeration over an extracted rootfs. Reads /etc/inittab, /etc/inetd.conf, the rc/init
 * scripts and the systemd units (all best-effort — tolerate any missing), applies the pure parsers, dedupes and
 * builds the map, then derives the findings. Honest: a missing/unreadable rootfs → available:false with nothing
 * fabricated. Nothing is ever booted.
 */
export function runServiceMap(rootfsPath: string): ServiceMapResult {
  const root = path.resolve(rootfsPath);
  let isDir = false;
  try {
    isDir = fs.statSync(root).isDirectory();
  } catch {
    isDir = false;
  }
  if (!isDir) {
    return { available: false, services: [], findings: [], reason: 'No extracted rootfs — run extraction first.' };
  }

  const budget = { n: 0 };
  const raw: Service[] = [];
  raw.push(...parseInittab(readInside(root, 'etc/inittab')));
  raw.push(...parseInetd(readInside(root, 'etc/inetd.conf')));
  for (const f of collectRcScripts(root, budget)) raw.push(...parseRcScript(f.path, f.content));
  for (const f of collectSystemdUnits(root, budget)) raw.push(...parseSystemdUnit(f.path, f.content));

  const services = buildServiceMap(raw);
  const findings = serviceFindings(services);
  const networkCount = services.filter((s) => s.network).length;
  const reason = `Service map: ${services.length} configured service(s) across inittab/inetd/rc/systemd (${networkCount} network-facing). Network daemons set to autostart are attack-surface leads — reachability needs runtime reproduction. Nothing was booted.`;
  return { available: true, services, findings, reason };
}
