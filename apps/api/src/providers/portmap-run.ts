/**
 * The filesystem half of the port map: find the service configs in an extracted rootfs and hand their text to the
 * pure parsers. Split from `portmap.ts` so every parsing decision stays unit-testable against the real files.
 */
import fs from 'node:fs';
import path from 'node:path';
import { type PortMap, buildPortMap } from './portmap.js';

/** Config files worth reading, rootfs-relative. Cheap, bounded, and named so a miss is visible. */
const CANDIDATES = [
  'etc/config/uhttpd',
  'etc/config/dropbear',
  'etc/config/nginx',
  'etc/config/telnet',
  'etc/lighttpd.conf',
  'etc/lighttpd/lighttpd.conf',
  'etc/boa.conf',
  'etc/boa/boa.conf',
  'etc/thttpd.conf',
  'etc/mini_httpd.conf',
];

/** Startup files whose command lines may carry a `-p <port>` the config files never mention. */
const COMMAND_SOURCES = ['etc/inittab', 'etc/inetd.conf', 'etc/rc.local', 'etc/init.d/rcS'];

const READ_BYTES = 256 * 1024;

function readIfSmall(abs: string): string | null {
  try {
    const st = fs.statSync(abs);
    if (!st.isFile() || st.size > READ_BYTES) return null;
    return fs.readFileSync(abs, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Read the port map out of an extracted rootfs.
 *
 * Command lines are collected from the startup files AND from `etc/init.d/*`, because a vendor httpd is usually
 * started from a script with its port on the command line rather than from a config file — which is precisely the
 * declaration `servicemap` drops when it keeps only the binary name.
 */
export function readPortMap(rootfsPath: string | null): PortMap {
  if (!rootfsPath || !fs.existsSync(rootfsPath)) {
    return buildPortMap([], []);
  }
  const files: { path: string; text: string }[] = [];
  for (const rel of CANDIDATES) {
    const text = readIfSmall(path.join(rootfsPath, rel));
    if (text !== null) files.push({ path: rel, text });
  }

  const commandLines: { source: string; cmd: string }[] = [];
  const pushLines = (rel: string, text: string): void => {
    for (const raw of text.split('\n')) {
      const line = raw.trim();
      // Only lines that both invoke something and carry a port flag — everything else is noise for this question.
      if (line && !line.startsWith('#') && /(^|\s)(-p|--port|-P)[\s=]+\d/.test(line)) {
        commandLines.push({ source: rel, cmd: line.slice(0, 400) });
      }
    }
  };
  for (const rel of COMMAND_SOURCES) {
    const text = readIfSmall(path.join(rootfsPath, rel));
    if (text !== null) pushLines(rel, text);
  }
  try {
    const initDir = path.join(rootfsPath, 'etc/init.d');
    for (const name of fs.readdirSync(initDir).slice(0, 200)) {
      const text = readIfSmall(path.join(initDir, name));
      if (text !== null) pushLines(`etc/init.d/${name}`, text);
    }
  } catch {
    // no init.d — the other sources still stand
  }

  return buildPortMap(files, commandLines);
}
