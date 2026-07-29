import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  type EgressObservation,
  describeEgress,
  mergeEgress,
  parseDnsQName,
  parseEgress,
  sameSubnet,
  scopeOf,
} from './egress.js';

/**
 * Synthetic frames, built here rather than captured, so each test states exactly the one thing it is about. The
 * REAL bytes are the last describe in this file: a pcap qemu wrote during the measurement that decided this
 * module's design, which is the only evidence that the synthetic ones resemble anything.
 */

const GUEST_MAC = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const SLIRP_MAC = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

const ip = (a: string): number[] => a.split('.').map(Number);

/** One Ethernet+IPv4 frame. `payload` follows the transport header this builds for tcp/udp. */
function frame(o: {
  smac?: number[];
  src: string;
  dst: string;
  proto: 'tcp' | 'udp' | 'icmp';
  sport?: number;
  dport?: number;
  payload?: number[];
}): number[] {
  const protoNum = o.proto === 'tcp' ? 6 : o.proto === 'udp' ? 17 : 1;
  const transport =
    o.proto === 'icmp'
      ? [8, 0, 0, 0, 0, 0, 0, 0]
      : [
          ((o.sport ?? 1024) >> 8) & 0xff,
          (o.sport ?? 1024) & 0xff,
          ((o.dport ?? 80) >> 8) & 0xff,
          (o.dport ?? 80) & 0xff,
          0,
          8,
          0,
          0,
        ];
  const body = [...transport, ...(o.payload ?? [])];
  const ipHeader = [0x45, 0, 0, 20 + body.length, 0, 0, 0, 0, 64, protoNum, 0, 0, ...ip(o.src), ...ip(o.dst)];
  return [...GUEST_MAC.map(() => 0xff), ...(o.smac ?? GUEST_MAC), 0x08, 0x00, ...ipHeader, ...body];
}

/** A classic little-endian pcap of Ethernet frames. */
function pcap(frames: number[][]): Uint8Array {
  const header = [0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0];
  const out = [...header];
  for (const f of frames) {
    const n = f.length;
    out.push(0, 0, 0, 0, 0, 0, 0, 0, n & 0xff, (n >> 8) & 0xff, 0, 0, n & 0xff, (n >> 8) & 0xff, 0, 0, ...f);
  }
  return Uint8Array.from(out);
}

/** A DNS question payload: header, then the labels, then QTYPE/QCLASS. */
function dnsQuestion(name: string): number[] {
  const labels: number[] = [];
  for (const part of name.split('.')) {
    labels.push(part.length, ...[...part].map((c) => c.charCodeAt(0)));
  }
  return [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, 0, 0, 1, 0, 1];
}

const SLIRP = ['10.0.2.2', '10.0.2.3', '10.0.2.4'];

describe('scopeOf — what a destination means for this run', () => {
  it('separates the emulator from what lies beyond it', () => {
    expect(scopeOf('10.0.2.3', { emulatorAddresses: SLIRP })).toBe('emulator');
    expect(scopeOf('8.8.8.8', { emulatorAddresses: SLIRP })).toBe('external');
  });

  it('calls the guest’s own subnet local, so a firmware scanning its LAN is not counted as egress', () => {
    const opts = { emulatorAddresses: SLIRP, guestAddress: '192.168.0.1' };
    expect(scopeOf('192.168.0.55', opts)).toBe('local');
    expect(scopeOf('192.168.9.55', opts)).toBe('external');
  });

  it('counts announcements apart from connections', () => {
    expect(scopeOf('224.0.0.251')).toBe('multicast');
    expect(scopeOf('239.255.255.250')).toBe('multicast');
    expect(scopeOf('255.255.255.255')).toBe('multicast');
  });

  it('is external with no context, which is the conservative direction', () => {
    expect(scopeOf('93.184.216.34')).toBe('external');
  });
});

describe('sameSubnet', () => {
  it('masks by the prefix and refuses malformed input rather than guessing', () => {
    expect(sameSubnet('10.0.2.9', '10.0.2.15', 24)).toBe(true);
    expect(sameSubnet('10.0.3.9', '10.0.2.15', 24)).toBe(false);
    expect(sameSubnet('10.0.3.9', '10.0.2.15', 16)).toBe(true);
    expect(sameSubnet('not.an.ip', '10.0.2.15', 24)).toBe(false);
    expect(sameSubnet('10.0.2.9', '10.0.2.15', 99)).toBe(false);
  });
});

describe('parseDnsQName', () => {
  it('reads the name out of a question', () => {
    expect(parseDnsQName(Uint8Array.from(dnsQuestion('update.tplink.com')))).toBe('update.tplink.com');
  });

  it('lower-cases, because a hostname is not case-sensitive and two casings are not two hosts', () => {
    expect(parseDnsQName(Uint8Array.from(dnsQuestion('Update.TPLink.COM')))).toBe('update.tplink.com');
  });

  it('returns null when the name runs past the captured bytes — half a hostname is a different hostname', () => {
    const full = dnsQuestion('averylongvendorhostname.example.com');
    expect(parseDnsQName(Uint8Array.from(full.slice(0, 25)))).toBeNull();
  });

  it('refuses a compression pointer instead of following one into a truncated frame', () => {
    expect(parseDnsQName(Uint8Array.from([...Array(12).fill(0), 0xc0, 0x0c]))).toBeNull();
  });

  it('refuses a label that is not hostname-shaped, because this string came off the wire', () => {
    // A DNS label is LENGTH-PREFIXED, so its content is arbitrary bytes — a firmware can emit a question whose
    // "name" carries a NUL, a space or markup. That string is joined into a composite map key and rendered into
    // a panel, so it is refused here rather than sanitised at each of the places it would reach.
    const withByte = (b: number): Uint8Array =>
      Uint8Array.from([...Array(12).fill(0), 3, 0x61, b, 0x63, 3, 0x63, 0x6f, 0x6d, 0]);
    expect(parseDnsQName(withByte(0x00))).toBeNull(); // NUL — the separator the keys use
    expect(parseDnsQName(withByte(0x20))).toBeNull(); // space
    expect(parseDnsQName(withByte(0x3c))).toBeNull(); // '<'
    // …and a normal label still reads.
    expect(parseDnsQName(withByte(0x62))).toBe('abc.com');
  });
});

describe('parseEgress', () => {
  it('says why it read nothing rather than returning an empty observation', () => {
    expect(parseEgress(Uint8Array.from([])).problem).toMatch(/empty/i);
    expect(parseEgress(Uint8Array.from([1, 2, 3])).problem).toMatch(/too short/i);
    expect(parseEgress(Uint8Array.from(Array(40).fill(0))).problem).toMatch(/Not a classic pcap/);
  });

  it('records the destination, the port and the protocol the guest addressed', () => {
    const o = parseEgress(pcap([frame({ src: '10.0.2.15', dst: '93.184.216.34', proto: 'tcp', dport: 443 })]), {
      emulatorAddresses: SLIRP,
    });
    expect(o.problem).toBe('');
    expect(o.attempts).toEqual([
      { address: '93.184.216.34', protocol: 'tcp', port: 443, scope: 'external', frames: 1 },
    ]);
  });

  it('reads the name out of a DNS question and keeps the server it was asked of', () => {
    const o = parseEgress(
      pcap([
        frame({ src: '10.0.2.15', dst: '10.0.2.3', proto: 'udp', dport: 53, payload: dnsQuestion('ntp.pool.org') }),
      ]),
      { emulatorAddresses: SLIRP },
    );
    expect(o.dnsQueries).toEqual([{ name: 'ntp.pool.org', server: '10.0.2.3', frames: 1 }]);
    // The question went to the emulator's resolver, which is not egress — but the NAME is the point.
    expect(o.attempts[0]?.scope).toBe('emulator');
  });

  it('counts an unreadable DNS question instead of printing a truncated name', () => {
    const q = dnsQuestion('a-very-long-vendor-update-host.example.com');
    const f = frame({ src: '10.0.2.15', dst: '10.0.2.3', proto: 'udp', dport: 53, payload: q });
    const o = parseEgress(pcap([f.slice(0, 60)]), { emulatorAddresses: SLIRP });
    expect(o.dnsQueries).toEqual([]);
    expect(o.dnsTruncated).toBe(1);
  });

  it('does not attribute the emulator’s own frames to the firmware', () => {
    // slirp NATs, so a reply it puts on the wire bears a stranger's source address. Only its MAC identifies it,
    // and mistaking one for the guest is the over-claim `parseGuestWire` had to be fixed for.
    const o = parseEgress(
      pcap([
        frame({ src: '10.0.2.2', dst: '10.0.2.15', proto: 'icmp', smac: SLIRP_MAC }),
        frame({ src: '8.8.8.8', dst: '10.0.2.15', proto: 'icmp', smac: SLIRP_MAC }),
        frame({ src: '10.0.2.15', dst: '8.8.8.8', proto: 'icmp' }),
      ]),
      { emulatorAddresses: SLIRP },
    );
    expect(o.guestFrames).toBe(1);
    expect(o.attempts).toEqual([{ address: '8.8.8.8', protocol: 'icmp', scope: 'external', frames: 1 }]);
  });

  it('groups repeats and orders by frame count, never by the order they were walked', () => {
    const o = parseEgress(
      pcap([
        frame({ src: '10.0.2.15', dst: '1.1.1.1', proto: 'tcp', dport: 80 }),
        frame({ src: '10.0.2.15', dst: '8.8.8.8', proto: 'tcp', dport: 80 }),
        frame({ src: '10.0.2.15', dst: '8.8.8.8', proto: 'tcp', dport: 80 }),
      ]),
      { emulatorAddresses: SLIRP },
    );
    expect(o.attempts.map((a) => `${a.address}x${a.frames}`)).toEqual(['8.8.8.8x2', '1.1.1.1x1']);
  });

  it('keeps the same address on two ports as two attempts, because they are two questions', () => {
    const o = parseEgress(
      pcap([
        frame({ src: '10.0.2.15', dst: '1.1.1.1', proto: 'tcp', dport: 80 }),
        frame({ src: '10.0.2.15', dst: '1.1.1.1', proto: 'tcp', dport: 443 }),
      ]),
      { emulatorAddresses: SLIRP },
    );
    expect(o.attempts).toHaveLength(2);
  });
});

describe('mergeEgress', () => {
  it('sums the two passes rather than letting the later one replace the earlier', () => {
    const a = parseEgress(pcap([frame({ src: '10.0.2.15', dst: '8.8.8.8', proto: 'tcp', dport: 80 })]));
    const b = parseEgress(
      pcap([
        frame({ src: '10.0.2.15', dst: '8.8.8.8', proto: 'tcp', dport: 80 }),
        frame({ src: '10.0.2.15', dst: '1.1.1.1', proto: 'udp', dport: 123 }),
      ]),
    );
    const m = mergeEgress(a, b);
    expect(m?.attempts.find((x) => x.address === '8.8.8.8')?.frames).toBe(2);
    expect(m?.attempts).toHaveLength(2);
    expect(m?.guestFrames).toBe(3);
  });

  it('passes a lone observation through, since a run may take only one pass', () => {
    const a = parseEgress(pcap([frame({ src: '10.0.2.15', dst: '8.8.8.8', proto: 'icmp' })]));
    expect(mergeEgress(a, null)).toBe(a);
    expect(mergeEgress(null, a)).toBe(a);
    expect(mergeEgress(null, null)).toBeNull();
  });
});

describe('describeEgress', () => {
  const withExternal = (): EgressObservation =>
    parseEgress(pcap([frame({ src: '10.0.2.15', dst: '8.8.8.8', proto: 'udp', dport: 123 })]), {
      emulatorAddresses: SLIRP,
    });

  it('never says the firmware CONTACTED anything — only that it addressed it', () => {
    for (const isolated of [true, false]) {
      const s = describeEgress(withExternal(), isolated);
      expect(s).toMatch(/addressed/);
      expect(s).not.toMatch(/contacted|reached \d/i);
    }
  });

  it('states which of the two runs it was, because that is the whole difference', () => {
    expect(describeEgress(withExternal(), true)).toMatch(/blocked/i);
    expect(describeEgress(withExternal(), false)).toMatch(/NOT blocked/);
  });

  it('distinguishes a silent guest from an unread capture', () => {
    expect(describeEgress(parseEgress(pcap([])), false)).toMatch(/no IPv4 frame/);
    expect(describeEgress(parseEgress(Uint8Array.from([])), false)).toMatch(/empty/i);
  });
});

/**
 * The bytes qemu actually wrote — and the measurement this module exists because of.
 *
 * Both files come from one in-container run on 2026-07-29: a MIPS big-endian guest built from the WR940N's OWN
 * busybox on a FirmAE kernel, pinging 8.8.8.8, booted twice with nothing changed but `restrict`. They are here
 * because the synthetic frames above are written from the same assumptions as the parser, and a suite of those
 * proves the code is consistent with its fixtures rather than that it can read a capture.
 *
 * What the pair pins is the claim the whole design rests on: **isolating the guest does not hide what it tried
 * to do.** If a future qemu, or a future filter, ever stops capturing a frame slirp refuses to forward, the
 * isolated file stops carrying 8.8.8.8 and this test says so.
 */
describe('parseEgress against real qemu captures', () => {
  const fixture = (name: string): Uint8Array =>
    readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '__fixtures__', name));
  const SLIRP_REAL = ['10.0.2.2', '10.0.2.3', '10.0.2.4'];
  const read = (name: string): EgressObservation =>
    parseEgress(fixture(name), { emulatorAddresses: SLIRP_REAL, guestAddress: '10.0.2.15' });

  it('reads the guest’s outbound attempt with the door SHUT', () => {
    const o = read('qemu-guest-isolated.pcap');
    expect(o.problem).toBe('');
    expect(o.attempts.find((a) => a.address === '8.8.8.8')).toMatchObject({
      protocol: 'icmp',
      scope: 'external',
      frames: 3,
    });
  });

  it('reads the same attempt with the door OPEN, and only then are there replies', () => {
    const o = read('qemu-guest-open.pcap');
    expect(o.attempts.find((a) => a.address === '8.8.8.8')).toMatchObject({ scope: 'external', frames: 3 });
  });

  it('records the SAME attempt either way — the finding that made a permissive default defensible', () => {
    const shut = read('qemu-guest-isolated.pcap');
    const open = read('qemu-guest-open.pcap');
    const externalOf = (o: EgressObservation): string[] =>
      o.attempts
        .filter((a) => a.scope === 'external')
        .map((a) => `${a.address}/${a.protocol}x${a.frames}`)
        .sort();
    expect(externalOf(shut)).toEqual(externalOf(open));
    expect(externalOf(shut)).toEqual(['8.8.8.8/icmpx3']);
  });

  it('attributes the guest’s traffic to the guest and slirp’s to slirp, on bytes neither was written for', () => {
    const open = read('qemu-guest-open.pcap');
    // The open capture holds 3 replies FROM 8.8.8.8 that slirp NATed back in. Counting those as the guest
    // addressing itself is the exact over-claim this attribution exists to prevent.
    expect(open.attempts.some((a) => a.address === '10.0.2.15')).toBe(false);
    expect(open.guestFrames).toBe(read('qemu-guest-isolated.pcap').guestFrames);
  });
});
