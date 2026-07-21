import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  buildServiceMap,
  defaultPort,
  isNetworkDaemon,
  parseInetd,
  parseInittab,
  parseRcScript,
  parseSystemdUnit,
  runServiceMap,
  serviceFindings,
} from './servicemap.js';

describe('isNetworkDaemon / defaultPort', () => {
  it('recognizes known network daemons and their default ports', () => {
    expect(isNetworkDaemon('telnetd')).toBe(true);
    expect(isNetworkDaemon('dropbear')).toBe(true);
    expect(isNetworkDaemon('httpd')).toBe(true);
    expect(defaultPort('telnetd')).toBe(23);
    expect(defaultPort('dropbear')).toBe(22);
    expect(defaultPort('httpd')).toBe(80);
    expect(defaultPort('vsftpd')).toBe(21);
    expect(defaultPort('dnsmasq')).toBe(53);
    expect(defaultPort('miniupnpd')).toBe(1900);
  });

  it('normalizes an inetd `in.` prefix', () => {
    expect(isNetworkDaemon('in.telnetd')).toBe(true);
    expect(defaultPort('in.telnetd')).toBe(23);
  });

  it('treats an unknown/local binary as non-network with no port', () => {
    expect(isNetworkDaemon('getty')).toBe(false);
    expect(isNetworkDaemon('busybox')).toBe(false);
    expect(defaultPort('getty')).toBeUndefined();
  });
});

describe('parseInittab', () => {
  it('maps a respawn telnetd to an autostart network service with port 23', () => {
    const svcs = parseInittab('::sysinit:/etc/init.d/rcS\n::respawn:/sbin/telnetd\n');
    expect(svcs).toHaveLength(1); // sysinit is not a service start
    const t = svcs[0];
    expect(t?.name).toBe('telnetd');
    expect(t?.binary).toBe('/sbin/telnetd');
    expect(t?.source).toBe('/etc/inittab');
    expect(t?.network).toBe(true);
    expect(t?.autostart).toBe(true);
    expect(t?.port).toBe(23);
  });

  it('captures a non-network respawn process (getty) without a port', () => {
    const svcs = parseInittab('::respawn:/sbin/getty 115200 ttyS0\n');
    const g = svcs.find((s) => s.name === 'getty');
    expect(g?.autostart).toBe(true);
    expect(g?.network).toBe(false);
    expect(g?.port).toBeUndefined();
  });
});

describe('parseInetd', () => {
  it('maps a telnet inetd line to a network service on port 23', () => {
    const svcs = parseInetd('telnet stream tcp nowait root /usr/sbin/telnetd telnetd\n');
    expect(svcs).toHaveLength(1);
    const t = svcs[0];
    expect(t?.name).toBe('telnet');
    expect(t?.binary).toBe('/usr/sbin/telnetd');
    expect(t?.source).toBe('/etc/inetd.conf');
    expect(t?.network).toBe(true);
    expect(t?.autostart).toBe(true);
    expect(t?.port).toBe(23);
  });

  it('skips comments and short lines', () => {
    expect(parseInetd('# telnet disabled\ntelnet stream tcp\n')).toHaveLength(0);
  });
});

describe('parseRcScript', () => {
  it('detects a backgrounded httpd started from an rc script (port 80)', () => {
    const svcs = parseRcScript('etc/init.d/S80httpd', '#!/bin/sh\nhttpd -p 80 &\n');
    const h = svcs.find((s) => s.name === 'httpd');
    expect(h?.binary).toBe('httpd');
    expect(h?.source).toBe('etc/init.d/S80httpd');
    expect(h?.network).toBe(true);
    expect(h?.autostart).toBe(true);
    expect(h?.port).toBe(80);
  });

  it('detects a start-stop-daemon launch and does not confuse mini_httpd with httpd', () => {
    const viaSsd = parseRcScript('etc/init.d/dropbear', 'start-stop-daemon --start --exec /usr/sbin/dropbear\n');
    expect(viaSsd.find((s) => s.name === 'dropbear')?.binary).toBe('/usr/sbin/dropbear');

    const mini = parseRcScript('etc/init.d/web', 'mini_httpd -d /www &\n');
    expect(mini.some((s) => s.name === 'mini_httpd')).toBe(true);
    expect(mini.some((s) => s.name === 'httpd')).toBe(false);
  });

  it('ignores comment lines and daemons not actually started', () => {
    expect(parseRcScript('etc/init.d/x', '# httpd would go here\nHTTPD_BIN=/usr/sbin/httpd\n')).toHaveLength(0);
  });
});

describe('parseSystemdUnit', () => {
  it('reads ExecStart as the binary and WantedBy as autostart', () => {
    const unit = '[Service]\nExecStart=/usr/sbin/dropbear -F\n\n[Install]\nWantedBy=multi-user.target\n';
    const svcs = parseSystemdUnit('etc/systemd/system/dropbear.service', unit);
    expect(svcs).toHaveLength(1);
    const d = svcs[0];
    expect(d?.name).toBe('dropbear');
    expect(d?.binary).toBe('/usr/sbin/dropbear');
    expect(d?.network).toBe(true);
    expect(d?.autostart).toBe(true);
    expect(d?.port).toBe(22);
  });

  it('is not autostart when there is no [Install] WantedBy', () => {
    const svcs = parseSystemdUnit('lib/systemd/system/x.service', 'ExecStart=/usr/bin/foo\n');
    expect(svcs[0]?.autostart).toBe(false);
  });

  it('strips a systemd exec prefix from ExecStart', () => {
    const svcs = parseSystemdUnit('x.service', 'ExecStart=-/usr/sbin/sshd\nWantedBy=multi-user.target\n');
    expect(svcs[0]?.binary).toBe('/usr/sbin/sshd');
    expect(svcs[0]?.port).toBe(22);
  });
});

describe('buildServiceMap', () => {
  it('dedupes by (binary basename + source) and sorts network-first', () => {
    const raw = [
      ...parseInittab('::respawn:/sbin/telnetd\n::respawn:/sbin/getty ttyS0\n'),
      // duplicate telnetd from the same source should collapse
      ...parseInittab('::respawn:/sbin/telnetd\n'),
    ];
    const map = buildServiceMap(raw);
    expect(map.filter((s) => s.name === 'telnetd')).toHaveLength(1);
    // network daemon (telnetd) sorts ahead of the non-network getty
    expect(map[0]?.network).toBe(true);
    expect(map[map.length - 1]?.name).toBe('getty');
  });
});

describe('serviceFindings', () => {
  it('emits an inventory finding plus one lead per exposed autostart network daemon', () => {
    const services = buildServiceMap([...parseInittab('::respawn:/sbin/telnetd\n::respawn:/sbin/getty ttyS0\n')]);
    const drafts = serviceFindings(services);

    const inv = drafts.find((d) => d.kind === 'service-inventory');
    expect(inv?.severity).toBe('info');
    expect(inv?.proofState).toBe('static_confirmed');
    expect((inv?.evidence as { total: number }).total).toBe(2);
    expect((inv?.evidence as { network: number }).network).toBe(1);

    const leads = drafts.filter((d) => d.kind === 'network-daemon-autostart');
    expect(leads).toHaveLength(1); // telnetd is exposed; getty is not a network daemon
    expect(leads[0]?.severity).toBe('low');
    expect(leads[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(leads[0]?.title).toContain('telnetd');
    expect(leads[0]?.title).toMatch(/attack surface/i);
  });

  it('returns nothing for an empty service list', () => {
    expect(serviceFindings([])).toHaveLength(0);
  });
});

describe('runServiceMap', () => {
  it('degrades honestly to available:false on a nonexistent rootfs path', () => {
    const res = runServiceMap('/nonexistent/rootfs/path/does-not-exist');
    expect(res.available).toBe(false);
    expect(res.services).toHaveLength(0);
    expect(res.findings).toHaveLength(0);
    expect(res.reason).toMatch(/run extraction first/i);
  });

  it('enumerates services from a real extracted rootfs directory end-to-end', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-servicemap-'));
    try {
      fs.mkdirSync(path.join(dir, 'etc/init.d'), { recursive: true });
      fs.mkdirSync(path.join(dir, 'etc/systemd/system'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'etc/inittab'), '::respawn:/sbin/telnetd\n');
      fs.writeFileSync(path.join(dir, 'etc/inetd.conf'), 'ftp stream tcp nowait root /usr/sbin/ftpd ftpd\n');
      fs.writeFileSync(path.join(dir, 'etc/init.d/S80httpd'), '#!/bin/sh\nhttpd -p 80 &\n');
      fs.writeFileSync(
        path.join(dir, 'etc/systemd/system/dropbear.service'),
        '[Service]\nExecStart=/usr/sbin/dropbear\n[Install]\nWantedBy=multi-user.target\n',
      );

      const res = runServiceMap(dir);
      expect(res.available).toBe(true);
      const names = res.services.map((s) => s.name);
      expect(names).toContain('telnetd');
      expect(names).toContain('httpd');
      expect(names).toContain('dropbear');
      expect(res.services.some((s) => s.name === 'ftp' && s.port === 21)).toBe(true);

      // Every discovered daemon here is an exposed autostart network daemon → a lead each, plus the inventory.
      const leads = res.findings.filter((f) => f.kind === 'network-daemon-autostart');
      expect(leads.length).toBeGreaterThanOrEqual(4);
      expect(res.findings.some((f) => f.kind === 'service-inventory')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
