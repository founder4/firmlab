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
  looksLikeVmBackedRuntime,
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

  it('a host-networked container on a real Linux host is on the LAN segment', () => {
    expect(assessL2Reach({ containerized: true, hostNetns: true }).onLanSegment).toBe(true);
  });

  // Found while validating the positive branch on this machine: OrbStack's --network host shares the Linux VM's
  // namespace, which has docker0 and veth pairs and so looks exactly like a real Docker host — while still being
  // one NAT away from the Mac's LAN. Reporting it spoof-capable would be an over-claim that silently reaches
  // nothing, which is the failure this whole gate exists to prevent.
  it('recognises the VM-backed runtimes whose host namespace is still not the LAN', () => {
    expect(looksLikeVmBackedRuntime('Linux version 7.0.11-orbstack-00360 (orbstack@builder)')).toBe(true);
    expect(looksLikeVmBackedRuntime('Linux version 6.10.14-linuxkit (docker@buildkitsandbox)')).toBe(true);
    expect(looksLikeVmBackedRuntime('Linux version 5.15.0-microsoft-standard-WSL2')).toBe(true);
    expect(looksLikeVmBackedRuntime('Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org)')).toBe(false);
  });

  it('refuses --network host under a VM-backed runtime, and says a real Linux host is what is needed', () => {
    const r = assessL2Reach({ containerized: true, hostNetns: true, vmBackedHost: true });
    expect(r.onLanSegment).toBe(false);
    expect(r.reason).toContain('real Linux host');
    expect(r.reason).not.toContain('NET_ADMIN');
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

  // Naming the wrong remedy is the same failure as naming a missing capability. On a Mac, `--network host` only
  // gets you the VM's namespace, so a bridge-networked container there must not be told to try it.
  it('does not offer --network host as the escape when it cannot possibly be one', () => {
    const r = assessL2Reach({ containerized: true, hostNetns: false, vmBackedHost: true });
    expect(r.onLanSegment).toBe(false);
    expect(r.reason).not.toContain('--network host');
    expect(r.reason).toContain('real Linux host');
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
