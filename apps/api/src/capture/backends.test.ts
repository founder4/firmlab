import { describe, expect, it } from 'vitest';
import {
  CAP_NET_ADMIN,
  CAP_NET_RAW,
  type CaptureBackendStatus,
  assessL2Reach,
  availableTransports,
  capHeld,
  detectCaptureBackends,
  looksLikeHostNetns,
  matchRadio,
  parseCapEff,
} from './backends.js';

describe('parseCapEff / capHeld', () => {
  it('extracts the effective-capabilities mask from /proc/self/status text', () => {
    // 0x3000 = bit 12 (NET_ADMIN) + bit 13 (NET_RAW) set.
    const caps = parseCapEff('Name:\tnode\nCapEff:\t0000000000003000\nCapBnd:\t000001ffffffffff\n');
    expect(caps).not.toBeNull();
    expect(capHeld(caps as bigint, CAP_NET_ADMIN)).toBe(true);
    expect(capHeld(caps as bigint, CAP_NET_RAW)).toBe(true);
  });
  it('reports a bit as unheld when the mask lacks it', () => {
    const caps = parseCapEff('CapEff:\t0000000000000000');
    expect(capHeld(caps as bigint, CAP_NET_ADMIN)).toBe(false);
  });
  it('returns null when the field is absent (not a Linux status file)', () => {
    expect(parseCapEff('some unrelated text')).toBeNull();
  });
});

describe('looksLikeHostNetns / assessL2Reach — the precondition no capability can substitute for', () => {
  it('reads a container-only interface set as NOT the host namespace', () => {
    expect(looksLikeHostNetns(['lo', 'eth0'])).toBe(false);
    expect(looksLikeHostNetns([])).toBe(false);
  });

  it('recognises the host namespace by artefacts that exist only there', () => {
    expect(looksLikeHostNetns(['lo', 'eth0', 'docker0'])).toBe(true);
    expect(looksLikeHostNetns(['lo', 'br-1a2b3c4d5e6f'])).toBe(true);
    expect(looksLikeHostNetns(['lo', 'veth9a1b2c3'])).toBe(true);
  });

  it('a bare host is on the LAN segment', () => {
    expect(assessL2Reach({ containerized: false, hostNetns: false }).onLanSegment).toBe(true);
  });

  it('a host-networked container is on the LAN segment', () => {
    expect(assessL2Reach({ containerized: true, hostNetns: true }).onLanSegment).toBe(true);
  });

  // The whole point of the gate: bettercap being installed and NET_ADMIN being granted still would not make ARP
  // poisoning work from a bridge network, so the reason must point at host networking / the LAN agent instead.
  it('a bridge-networked container is NOT, and is told what actually would work', () => {
    const r = assessL2Reach({ containerized: true, hostNetns: false });
    expect(r.onLanSegment).toBe(false);
    expect(r.reason).toContain('--network host');
    expect(r.reason).toContain('LAN');
    expect(r.reason).not.toContain('NET_ADMIN');
  });
});

describe('matchRadio', () => {
  const ble = [{ vid: '1915', label: 'Nordic nRF52840' }];
  const zigbee = [{ vid: '0451', pid: '16a8', label: 'TI CC2531' }];

  it('matches a BLE dongle by vendor id alone', () => {
    expect(matchRadio([{ vid: '1915', pid: '520f' }], ble)).toBe('Nordic nRF52840');
  });
  it('requires the exact vid+pid when the table specifies a pid', () => {
    expect(matchRadio([{ vid: '0451', pid: '16a8' }], zigbee)).toBe('TI CC2531');
    // A different TI product (not the sniffer) must NOT match — avoids a random adapter posing as a radio.
    expect(matchRadio([{ vid: '0451', pid: 'e001' }], zigbee)).toBeNull();
  });
  it('returns null when nothing attached matches', () => {
    expect(matchRadio([{ vid: '10c4', pid: 'ea60' }], ble)).toBeNull();
  });
});

describe('availableTransports', () => {
  const mk = (over: Partial<CaptureBackendStatus>): CaptureBackendStatus => ({
    id: 'network-proxy',
    role: 'interception',
    transports: ['http', 'https'],
    unlocks: '',
    available: true,
    reason: '',
    capabilities: {},
    ...over,
  });

  it('withholds http/https until a positioning backend is available (a proxy needs to be on-path)', () => {
    const proxyOnly = [mk({})];
    expect(availableTransports(proxyOnly)).toEqual([]);
  });
  it('surfaces http/https once positioning is present', () => {
    const positioned = [mk({}), mk({ id: 'on-path-gateway', role: 'positioning', transports: [], available: true })];
    expect(availableTransports(positioned).sort()).toEqual(['http', 'https']);
  });
  it('a radio IS its own position — ble-gatt needs no positioning backend', () => {
    const radio = [mk({ id: 'ble', role: 'radio', transports: ['ble-gatt'], available: true })];
    expect(availableTransports(radio)).toEqual(['ble-gatt']);
  });
});

describe('detectCaptureBackends', () => {
  it('probes all six backends read-only and returns the honest status shape', () => {
    const backends = detectCaptureBackends(true);
    expect(backends.map((b) => b.id).sort()).toEqual(
      ['ble', 'network-proxy', 'on-path-gateway', 'on-path-spoof', 'usb-serial', 'zigbee'].sort(),
    );
    for (const b of backends) {
      expect(typeof b.available).toBe('boolean');
      expect(b.reason.length).toBeGreaterThan(0);
    }
  });
});
