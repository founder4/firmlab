import { describe, expect, it } from 'vitest';
import {
  buildDevices,
  guessDeviceType,
  normalizeMac,
  ouiVendor,
  parseArpScan,
  parseAvahiBrowse,
  parseNmapSn,
  parsePrimarySubnet,
} from './discover.js';

describe('normalizeMac', () => {
  it('lowercases and colon-separates a valid MAC', () => {
    expect(normalizeMac('A0:02:DC:11:22:33')).toBe('a0:02:dc:11:22:33');
    expect(normalizeMac('a0-02-dc-11-22-33')).toBe('a0:02:dc:11:22:33');
    expect(normalizeMac('a002dc112233')).toBe('a0:02:dc:11:22:33');
  });
  it('rejects a non-6-octet string', () => {
    expect(normalizeMac('a0:02:dc:11:22')).toBeNull();
    expect(normalizeMac('not a mac')).toBeNull();
  });
});

describe('ouiVendor', () => {
  it('maps a known IoT OUI prefix to its vendor (fallback table)', () => {
    expect(ouiVendor('24:0a:c4:aa:bb:cc')).toBe('Espressif');
    expect(ouiVendor('b8:27:eb:de:ad:be')).toBe('Raspberry Pi');
  });
  it('returns null for an unknown prefix — never a guess', () => {
    expect(ouiVendor('de:ad:be:ef:00:11')).toBeNull();
  });
});

describe('parseArpScan', () => {
  const sample = [
    'Interface: eth0, type: EN10MB, MAC: 02:42:ac:11:00:02, IPv4: 172.17.0.2',
    'Starting arp-scan 1.9.7 with 256 hosts',
    '192.168.1.1\ta0:02:dc:11:22:33\tAmazon Technologies Inc.',
    '192.168.1.42\t24:0a:c4:aa:bb:cc\tEspressif Inc.',
    '192.168.1.99\tb8:27:eb:de:ad:be\t(Unknown)',
    '',
    '3 packets received by filter, 0 packets dropped by kernel',
    'Ending arp-scan 1.9.7: 256 hosts scanned in 2.5 seconds. 3 responded',
  ].join('\n');

  it('extracts host ip/mac/vendor and skips banner/footer', () => {
    const hosts = parseArpScan(sample);
    expect(hosts).toHaveLength(3);
    expect(hosts[0]).toEqual({ ip: '192.168.1.1', mac: 'a0:02:dc:11:22:33', vendor: 'Amazon Technologies Inc.' });
    expect(hosts[1]?.vendor).toBe('Espressif Inc.');
  });
  it('drops the "(Unknown)" vendor placeholder rather than storing it', () => {
    const hosts = parseArpScan(sample);
    expect(hosts[2]).toEqual({ ip: '192.168.1.99', mac: 'b8:27:eb:de:ad:be' });
  });
});

describe('parseNmapSn', () => {
  const sample = [
    'Starting Nmap 7.93 ( https://nmap.org )',
    'Nmap scan report for 192.168.1.1',
    'Host is up (0.0020s latency).',
    'MAC Address: A0:02:DC:11:22:33 (Amazon Technologies)',
    'Nmap scan report for router.lan (192.168.1.254)',
    'Host is up.',
    'MAC Address: 00:11:22:33:44:55 (Some Vendor)',
    'Nmap scan report for 192.168.1.7',
    'Host is up.',
    'Nmap done: 256 IP addresses (3 hosts up) scanned in 3.20 seconds',
  ].join('\n');

  it('pairs each scan report with its MAC line', () => {
    const hosts = parseNmapSn(sample);
    expect(hosts).toHaveLength(2);
    expect(hosts[0]).toEqual({ ip: '192.168.1.1', mac: 'a0:02:dc:11:22:33', vendor: 'Amazon Technologies' });
    expect(hosts[1]?.ip).toBe('192.168.1.254');
  });
  it('drops a host with no MAC (e.g. the scanning host) since discovery keys on MAC', () => {
    const hosts = parseNmapSn(sample);
    expect(hosts.find((h) => h.ip === '192.168.1.7')).toBeUndefined();
  });
});

describe('parseAvahiBrowse', () => {
  const sample = [
    '+;eth0;IPv4;Living Room;_googlecast._tcp;local',
    '=;eth0;IPv4;Living\\032Room;_googlecast._tcp;local;livingroom.local;192.168.1.42;8009;"id=abc"',
    '=;eth0;IPv4;Brother HL;_ipp._tcp;local;printer.local;192.168.1.50;631;"txtvers=1"',
    '=;eth0;IPv6;IPv6 record;_ipp._tcp;local;printer.local;fe80::1;631;""',
  ].join('\n');

  it('maps resolved (=) records to IP → service types + names', () => {
    const map = parseAvahiBrowse(sample);
    expect(map.get('192.168.1.42')?.services.has('_googlecast._tcp')).toBe(true);
    expect(map.get('192.168.1.50')?.services.has('_ipp._tcp')).toBe(true);
  });
  it('ignores non-IPv4 address records', () => {
    const map = parseAvahiBrowse(sample);
    expect(map.has('fe80::1')).toBe(false);
  });
});

describe('parsePrimarySubnet', () => {
  it('picks the primary /24 and normalizes it to the network address, skipping loopback', () => {
    const out = [
      '1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever',
      '2: eth0    inet 192.168.1.34/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever',
    ].join('\n');
    expect(parsePrimarySubnet(out)).toBe('192.168.1.0/24');
  });
  it('returns null when only loopback is present', () => {
    expect(parsePrimarySubnet('1: lo    inet 127.0.0.1/8 scope host lo')).toBeNull();
  });
});

describe('guessDeviceType', () => {
  it('treats an mDNS service type as the strongest signal', () => {
    expect(guessDeviceType({ vendor: null, mdnsServices: ['_ipp._tcp'], ports: [] })).toEqual({
      type: 'printer?',
      confidence: 'high',
    });
    expect(guessDeviceType({ vendor: null, mdnsServices: ['_googlecast._tcp'], ports: [] })?.confidence).toBe('medium');
  });
  it('falls back to a low-confidence vendor lead when nothing else corroborates', () => {
    expect(guessDeviceType({ vendor: 'Espressif', mdnsServices: [], ports: [] })).toEqual({
      type: 'ESP32/ESP8266 IoT device?',
      confidence: 'low',
    });
  });
  it('returns null when there is nothing to go on', () => {
    expect(guessDeviceType({ vendor: null, mdnsServices: [], ports: [] })).toBeNull();
  });
});

describe('buildDevices', () => {
  it('merges sweep hosts with mDNS enrichment and computes a type guess', () => {
    const hosts = [{ ip: '192.168.1.42', mac: '24:0a:c4:aa:bb:cc', vendor: 'Espressif Inc.' }];
    const mdns = new Map([['192.168.1.42', { services: new Set(['_googlecast._tcp']), names: new Set(['Speaker']) }]]);
    const devices = buildDevices(hosts, mdns);
    expect(devices).toHaveLength(1);
    expect(devices[0]?.ouiVendor).toBe('Espressif Inc.');
    expect(devices[0]?.mdnsIdentity).toContain('_googlecast._tcp');
    // mDNS beats the vendor fallback: googlecast → smart display, not "ESP IoT device".
    expect(devices[0]?.typeGuess).toContain('Chromecast');
  });
  it('falls back to the OUI table when the sweep gives no vendor', () => {
    const devices = buildDevices([{ ip: '192.168.1.99', mac: 'b8:27:eb:de:ad:be' }]);
    expect(devices[0]?.ouiVendor).toBe('Raspberry Pi');
  });
});
