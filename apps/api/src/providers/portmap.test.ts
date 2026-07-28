import { describe, expect, it } from 'vitest';
import {
  buildPortMap,
  parseArgPorts,
  parseBoaPorts,
  parseLighttpdPorts,
  parseUciPorts,
  planForwards,
  portFromAddress,
} from './portmap.js';

// Verbatim from the GL.iNet BE3600 4.9.0 rootfs — tabs, IPv6 bracket form and comments as shipped.
const UHTTPD = `# Server configuration
config uhttpd main

	# HTTP listen addresses, multiple allowed
	list listen_http	0.0.0.0:80
	list listen_http	[::]:80

	# HTTPS listen addresses, multiple allowed
	list listen_https	0.0.0.0:443
	list listen_https	[::]:443

	option redirect_https	0
	option home		/www
`;

// Verbatim from the same rootfs: a quoted scalar, and a commented-out directive that must not be read.
const DROPBEAR = `config dropbear main
	option enable '1'
	option PasswordAuth 'on'
	option Port         '22'
#	option BannerFile   '/etc/banner'
`;

describe('portFromAddress — the shapes UCI actually writes', () => {
  it('reads IPv4, bare and port-only forms', () => {
    expect(portFromAddress('0.0.0.0:80')).toBe(80);
    expect(portFromAddress(':8080')).toBe(8080);
    expect(portFromAddress('443')).toBe(443);
    expect(portFromAddress("'22'")).toBe(22);
  });

  it('reads the IPv6 bracket form, which splitting on the FIRST colon would ruin', () => {
    expect(portFromAddress('[::]:80')).toBe(80);
    expect(portFromAddress('[fe80::1]:8443')).toBe(8443);
  });

  it('refuses anything that is not a port rather than inventing one', () => {
    expect(portFromAddress('')).toBeNull();
    expect(portFromAddress('0.0.0.0:')).toBeNull();
    expect(portFromAddress('0.0.0.0:99999')).toBeNull();
    expect(portFromAddress('/var/run/uhttpd.sock')).toBeNull();
  });
});

describe('parseUciPorts', () => {
  it('finds BOTH families and BOTH protocols on the real uhttpd config', () => {
    const hints = parseUciPorts(UHTTPD, 'etc/config/uhttpd');
    // 80 and 443 once each: the v4 and v6 lines are the same port and must not double-count.
    expect(hints.map((h) => `${h.port}/${h.protocol}`).sort()).toEqual(['443/https', '80/http']);
    // 443 is the port the hardcoded `hostfwd=tcp::8080-:80` could never reach.
    expect(hints.find((h) => h.port === 443)?.evidence).toContain('listen_https');
  });

  it('reads a quoted scalar port and takes the protocol from the file it is in', () => {
    const hints = parseUciPorts(DROPBEAR, 'etc/config/dropbear');
    expect(hints).toHaveLength(1);
    expect(hints[0]?.port).toBe(22);
    expect(hints[0]?.protocol).toBe('ssh');
  });

  it('ignores commented-out directives', () => {
    expect(parseUciPorts('#	option Port 2222\n', 'etc/config/dropbear')).toEqual([]);
  });
});

describe('parseLighttpdPorts / parseBoaPorts', () => {
  it('reads lighttpd server.port and an SSL socket block', () => {
    const hints = parseLighttpdPorts('server.port = 8080\n$SERVER["socket"] == ":443" {\n', 'etc/lighttpd.conf');
    expect(hints.map((h) => h.port).sort((a, b) => a - b)).toEqual([443, 8080]);
    expect(hints.find((h) => h.port === 443)?.protocol).toBe('https');
  });

  it('reads a boa Port directive', () => {
    expect(parseBoaPorts('Port 8080\n# Port 80\n', 'etc/boa.conf')[0]?.port).toBe(8080);
  });
});

describe('parseArgPorts — the port servicemap throws away', () => {
  it('reads the port off the command line, which is where a vendor httpd usually puts it', () => {
    // servicemap keeps only split(/\s+/)[0], so this daemon looked identical to one on 80 and then got a
    // default from a lookup table.
    const hints = parseArgPorts('/usr/sbin/httpd -p 8080 -h /www', 'etc/inittab');
    expect(hints[0]?.port).toBe(8080);
    expect(hints[0]?.protocol).toBe('http');
  });

  it('reads --port and infers ssh/telnet from the daemon, not from the number', () => {
    expect(parseArgPorts('uhttpd --port 8000', 'x')[0]?.port).toBe(8000);
    expect(parseArgPorts('/usr/sbin/dropbear -p 2222', 'x')[0]?.protocol).toBe('ssh');
    expect(parseArgPorts('telnetd -p 2323', 'x')[0]?.protocol).toBe('telnet');
  });

  it('does not mistake other numeric flags for a port', () => {
    expect(parseArgPorts('httpd -h /www -c 3', 'x')).toEqual([]);
  });
});

describe('buildPortMap', () => {
  it('assembles the real GL.iNet surface, which the single hardcoded forward could not reach', () => {
    const map = buildPortMap([
      { path: 'etc/config/uhttpd', text: UHTTPD },
      { path: 'etc/config/dropbear', text: DROPBEAR },
    ]);
    expect(map.declared.map((h) => h.port)).toEqual([22, 80, 443]);
    expect(map.reason).toContain('Declared is not open');
  });

  it('tells "read the configs, they say nothing" apart from "found no configs"', () => {
    // The distinction the whole module exists for: one is a fact about the firmware, the other is a fact about
    // our search, and collapsing them is how an absence of evidence becomes evidence of absence.
    const said = buildPortMap([{ path: 'etc/config/uhttpd', text: '# nothing here\n' }]);
    expect(said.declared).toEqual([]);
    expect(said.reason).toContain('none declares a listening port');

    const looked = buildPortMap([{ path: 'etc/passwd', text: 'root:x:0:0' }]);
    expect(looked.filesRead).toEqual([]);
    expect(looked.reason).toContain('absence of evidence, not evidence that nothing listens');
  });
});

describe('planForwards', () => {
  it('forwards every declared port, each on its own host port', () => {
    const map = buildPortMap([
      { path: 'etc/config/uhttpd', text: UHTTPD },
      { path: 'etc/config/dropbear', text: DROPBEAR },
    ]);
    const fwd = planForwards(map, 8080);
    expect(fwd.map((f) => `${f.host}->${f.guest}`)).toEqual(['8080->22', '8081->80', '8082->443']);
  });

  it('forwards the well-known floor even when the firmware declares nothing', () => {
    // Measured on a real WR940N boot: it comes all the way up, its own console shows an HTTPS daemon loading a
    // certificate and key, and its rootfs contains no config file anywhere that mentions 443. A vendor daemon
    // carries its port in the binary. Forwarding one nobody answers costs nothing; missing one that would have
    // answered loses the result.
    const fwd = planForwards(buildPortMap([]), 8080);
    expect(fwd.map((f) => f.guest).sort((a, b) => a - b)).toEqual([80, 443]);
  });

  it('does not duplicate a floor port the firmware also declares', () => {
    const map = buildPortMap([{ path: 'etc/config/uhttpd', text: UHTTPD }]);
    const guests = planForwards(map, 8080).map((f) => f.guest);
    expect(guests.filter((g) => g === 443)).toHaveLength(1);
    expect(guests.filter((g) => g === 80)).toHaveLength(1);
  });

  it('bounds the forward list rather than handing qemu an unbounded set', () => {
    const many = Array.from({ length: 20 }, (_, i) => ({
      path: 'etc/config/uhttpd',
      text: `list listen_http 0.0.0.0:${9000 + i}\n`,
    }));
    expect(planForwards(buildPortMap(many), 8080, 5)).toHaveLength(5);
  });
});
