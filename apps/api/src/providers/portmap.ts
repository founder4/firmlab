/**
 * Which ports this firmware DECLARES it will listen on — read from the firmware's own configuration, before
 * anything is booted.
 *
 * The full-system boot forwarded exactly one port and hardcoded the guest side to 80 (`hostfwd=tcp::8080-:80`).
 * On the corpus that is right for HTTP and blind to everything else: the GL.iNet BE3600's own
 * `/etc/config/uhttpd` declares `listen_https 0.0.0.0:443` beside the HTTP listener, and its `/etc/config/dropbear`
 * declares `Port '22'` — neither ever reached the host, so an entire remote surface was unreachable in a rung the
 * workbench calls `confirmed_full_system`.
 *
 * **A declared port is not an open port.** Everything here is read from configuration files, so it says what the
 * firmware intends, never what a booted system actually does — the daemon may not start, the config may be
 * overridden at runtime from NVRAM, an interface may be down. That is precisely why this pairs with the post-boot
 * TCP probe: this module decides what is worth forwarding, and only the probe decides what answered. The gap
 * between the two lists is itself a result, not a failure.
 *
 * Parsers are written against REAL files pulled from the extracted corpus, not against the formats as remembered:
 * UCI writes `list listen_http\t0.0.0.0:80` with a tab and an IPv6 `[::]:80` variant, and quotes scalar values
 * (`option Port '22'`). Guessing any of that would have produced a parser that reads nothing and reports it as
 * "no ports declared", which is the failure mode this codebase refuses everywhere else.
 */

/** What a declared port is expected to speak. Drives which probe is meaningful, never a claim about the service. */
export type PortProtocol = 'http' | 'https' | 'ssh' | 'telnet' | 'unknown';

export interface PortHint {
  port: number;
  protocol: PortProtocol;
  /** The configuration file the declaration was read from, relative to the rootfs. */
  source: string;
  /** The line it was read from, so a reader can check the parse rather than trust it. */
  evidence: string;
}

const MAX_PORT = 65535;

function valid(port: number): boolean {
  return Number.isInteger(port) && port > 0 && port <= MAX_PORT;
}

/**
 * Pure: pull the port out of an address as UCI writes it — `0.0.0.0:80`, `[::]:80`, `:80`, or a bare `80`.
 * The IPv6 bracket form matters: splitting on the last colon is right, splitting on the first is not.
 */
export function portFromAddress(addr: string): number | null {
  const s = addr.trim().replace(/^['"]|['"]$/g, '');
  if (!s) return null;
  const bracket = /^\[[^\]]*\]:(\d+)$/.exec(s);
  if (bracket) {
    const n = Number(bracket[1]);
    return valid(n) ? n : null;
  }
  const idx = s.lastIndexOf(':');
  const tail = idx === -1 ? s : s.slice(idx + 1);
  const n = Number(tail);
  return valid(n) ? n : null;
}

/**
 * Pure: OpenWRT/UCI config. Handles both shapes the corpus actually contains — `list listen_http 0.0.0.0:80`
 * (uhttpd, repeated per address and per family) and `option Port '22'` (dropbear, quoted scalar).
 */
export function parseUciPorts(text: string, source: string): PortHint[] {
  const out: PortHint[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    const listen = /^list\s+(listen_https?|listen)\s+(\S+)/i.exec(line);
    if (listen) {
      const port = portFromAddress(listen[2] as string);
      if (port !== null) {
        out.push({
          port,
          protocol: /https/i.test(listen[1] as string) ? 'https' : 'http',
          source,
          evidence: line,
        });
      }
      continue;
    }

    const opt = /^option\s+(port|Port|listen_port)\s+(\S+)/i.exec(line);
    if (opt) {
      const port = portFromAddress(opt[2] as string);
      // The protocol comes from the file this was found in — `option Port` alone says nothing about what speaks
      // on it, and inferring http from a bare number would be a guess dressed as a reading.
      if (port !== null) out.push({ port, protocol: protocolForSource(source), source, evidence: line });
    }
  }
  return dedupe(out);
}

/** Pure: lighttpd — `server.port = 80`, optionally quoted, plus `$SERVER["socket"] == ":443"` blocks. */
export function parseLighttpdPorts(text: string, source: string): PortHint[] {
  const out: PortHint[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const simple = /^server\.port\s*=\s*(\S+)/i.exec(line);
    if (simple) {
      const port = portFromAddress(simple[1] as string);
      if (port !== null) out.push({ port, protocol: 'http', source, evidence: line });
      continue;
    }
    const socket = /\$SERVER\[\s*"socket"\s*\]\s*==\s*"([^"]+)"/i.exec(line);
    if (socket) {
      const port = portFromAddress(socket[1] as string);
      // A socket block that turns SSL on is https; the engine-enable line lives inside the block, so this only
      // reports http unless the address itself is the conventional 443.
      if (port !== null) out.push({ port, protocol: port === 443 ? 'https' : 'http', source, evidence: line });
    }
  }
  return dedupe(out);
}

/** Pure: boa/thttpd-style — a bare `Port 80` directive. */
export function parseBoaPorts(text: string, source: string): PortHint[] {
  const out: PortHint[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^Port\s+(\d+)\b/i.exec(line);
    if (m) {
      const port = Number(m[1]);
      if (valid(port)) out.push({ port, protocol: 'http', source, evidence: line });
    }
  }
  return dedupe(out);
}

/**
 * Pure: a port passed on a daemon's command line — `httpd -p 8080`, `dropbear -p 22`, `uhttpd --port 8080`.
 *
 * This is the one `servicemap` throws away: it keeps only `split(/\s+/)[0]`, the binary, so a vendor httpd started
 * on a non-default port looks identical to one started on 80 and then gets a default from a lookup table.
 */
export function parseArgPorts(cmdline: string, source: string): PortHint[] {
  const out: PortHint[] = [];
  const re = /(?:^|\s)(?:-p|--port|-P)[\s=]+(\d{1,5})\b/g;
  let m: RegExpExecArray | null = re.exec(cmdline);
  while (m !== null) {
    const port = Number(m[1]);
    if (valid(port)) out.push({ port, protocol: protocolForCommand(cmdline), source, evidence: cmdline.trim() });
    m = re.exec(cmdline);
  }
  return dedupe(out);
}

/** The protocol a config FILE implies, used when the directive itself carries none (`option Port '22'`). */
function protocolForSource(source: string): PortProtocol {
  const s = source.toLowerCase();
  if (s.includes('dropbear') || s.includes('sshd') || s.includes('ssh')) return 'ssh';
  if (s.includes('telnet')) return 'telnet';
  if (s.includes('uhttpd') || s.includes('httpd') || s.includes('lighttpd') || s.includes('boa')) return 'http';
  return 'unknown';
}

/** The protocol a COMMAND implies, from the daemon being invoked. */
function protocolForCommand(cmdline: string): PortProtocol {
  const c = cmdline.toLowerCase();
  if (/\bdropbear\b|\bsshd\b/.test(c)) return 'ssh';
  if (/\btelnetd?\b/.test(c)) return 'telnet';
  if (/\bhttpd\b|\buhttpd\b|\blighttpd\b|\bboa\b|\bgoahead\b|\bmini_httpd\b/.test(c)) return 'http';
  return 'unknown';
}

function dedupe(hints: PortHint[]): PortHint[] {
  const seen = new Set<string>();
  return hints.filter((h) => {
    const k = `${h.port}\u0000${h.protocol}\u0000${h.source}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** The configuration files worth reading, and which parser reads each. Matched on the rootfs-relative path. */
export const PORT_CONFIG_FILES: { match: RegExp; parse: (text: string, source: string) => PortHint[] }[] = [
  { match: /(^|\/)etc\/config\/(uhttpd|dropbear|nginx|telnet)$/i, parse: parseUciPorts },
  { match: /(^|\/)etc\/(lighttpd\/)?lighttpd\.conf$/i, parse: parseLighttpdPorts },
  { match: /(^|\/)etc\/(boa\/)?boa\.conf$/i, parse: parseBoaPorts },
  { match: /(^|\/)etc\/(thttpd|mini_httpd)\.conf$/i, parse: parseBoaPorts },
];

export interface PortMap {
  /** Every port the firmware's own configuration declares, deduplicated across sources. */
  declared: PortHint[];
  /** Files that were read. Named so "nothing declared" can be told apart from "nothing was looked at". */
  filesRead: string[];
  /** The honest sentence for a caller to show. Never implies a declared port is an open one. */
  reason: string;
}

/**
 * Pure: assemble the port map from already-read files.
 *
 * Kept pure and file-content-driven so the whole thing is testable against the real configs in the corpus; the
 * caller does the walking. An empty `declared` with a non-empty `filesRead` means the configs were read and say
 * nothing — materially different from having found no configs at all, and the reason says which.
 */
export function buildPortMap(
  files: { path: string; text: string }[],
  commandLines: { source: string; cmd: string }[] = [],
): PortMap {
  const declared: PortHint[] = [];
  const filesRead: string[] = [];
  for (const f of files) {
    const rule = PORT_CONFIG_FILES.find((r) => r.match.test(f.path));
    if (!rule) continue;
    filesRead.push(f.path);
    declared.push(...rule.parse(f.text, f.path));
  }
  for (const c of commandLines) declared.push(...parseArgPorts(c.cmd, c.source));

  const unique = dedupe(declared).sort((a, b) => a.port - b.port || a.source.localeCompare(b.source));
  const reason =
    unique.length > 0
      ? `${unique.length} port(s) declared by this firmware's own configuration: ${unique
          .map((h) => `${h.port}/${h.protocol}`)
          .join(', ')}. Declared is not open — only a booted system answers that.`
      : filesRead.length > 0
        ? `Read ${filesRead.length} service config(s) and none declares a listening port; the daemons here take their port from a built-in default or from NVRAM at runtime.`
        : 'No service configuration was found in this rootfs, so nothing states which ports it intends to serve. That is an absence of evidence, not evidence that nothing listens.';
  return { declared: unique, filesRead, reason };
}

/**
 * Pure: the host:guest forwards to give qemu, newest-relevant first and bounded.
 *
 * Port 80 is always included even when nothing declares it — most vendor httpds carry the default in the binary
 * and declare nothing at all, which is exactly the WR940N/DVRF case in this corpus, and dropping it would trade
 * one blind spot for another. Host ports are allocated from a base so two concurrent boots do not collide.
 */
/** Ports forwarded even when the firmware declares nothing — see the rationale in `planForwards`. */
const DEFAULT_FLOOR: [number, PortProtocol][] = [
  [443, 'https'],
  [80, 'http'],
];

export function planForwards(
  map: PortMap,
  basePort = 8080,
  cap = 8,
): { host: number; guest: number; protocol: PortProtocol }[] {
  const guests: { guest: number; protocol: PortProtocol }[] = [];
  const seen = new Set<number>();
  for (const h of map.declared) {
    if (seen.has(h.port)) continue;
    seen.add(h.port);
    guests.push({ guest: h.port, protocol: h.protocol });
  }
  // A floor of well-known firmware service ports, forwarded whether or not anything declares them. Most vendor
  // daemons carry their port in the binary and declare nothing at all — and the WR940N proved the cost: it boots,
  // its own console shows an HTTPS daemon loading a certificate and key, and its rootfs has no config file
  // anywhere that says 443. Forwarding a port nobody answers costs nothing; not forwarding one that would have
  // answered loses the result entirely.
  for (const [port, protocol] of DEFAULT_FLOOR) {
    if (!seen.has(port)) {
      seen.add(port);
      guests.unshift({ guest: port, protocol });
    }
  }
  return guests.slice(0, cap).map((g, i) => ({ host: basePort + i, guest: g.guest, protocol: g.protocol }));
}
