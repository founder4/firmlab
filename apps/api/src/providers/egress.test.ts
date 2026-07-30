import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  EMPTY_EGRESS,
  type EgressObservation,
  describeEgress,
  describeEgressPolicy,
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

const SYN = 0x02;
const SYN_ACK = 0x12;
const ACK = 0x10;
const RST_ACK = 0x14;

/**
 * One Ethernet+IPv4 frame. `payload` follows the transport header this builds for tcp/udp.
 *
 * TCP gets a REAL twenty-byte header, flags included. It used to get the same eight bytes as UDP, which was
 * enough for the parser that only read ports — and the day the parser started reading flags, every one of these
 * fixtures fell into the "captured too short to decide" branch and the suite stayed green while testing nothing.
 * `flags` defaults to SYN because a fixture named "the guest addressed X" means the guest opened that flow.
 */
function frame(o: {
  smac?: number[];
  src: string;
  dst: string;
  proto: 'tcp' | 'udp' | 'icmp';
  sport?: number;
  dport?: number;
  flags?: number;
  payload?: number[];
}): number[] {
  const protoNum = o.proto === 'tcp' ? 6 : o.proto === 'udp' ? 17 : 1;
  const ports = [
    ((o.sport ?? 1024) >> 8) & 0xff,
    (o.sport ?? 1024) & 0xff,
    ((o.dport ?? 80) >> 8) & 0xff,
    (o.dport ?? 80) & 0xff,
  ];
  const transport =
    o.proto === 'icmp'
      ? [8, 0, 0, 0, 0, 0, 0, 0]
      : o.proto === 'tcp'
        ? // seq, ack, data-offset 5 << 4, flags, window, checksum, urgent
          [...ports, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, o.flags ?? SYN, 0xff, 0xff, 0, 0, 0, 0]
        : [...ports, 0, 8, 0, 0];
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

/**
 * Who opened the flow.
 *
 * Written from a screenshot: the MR3220's panel listed ~150 rows of `10.0.2.2:<ephemeral>` under a heading that
 * says "addresses it aimed at". Every one was the guest answering a port-forward this workbench opened to probe
 * it — the bench reading its own intervention back as the firmware's intent, with the two real rows buried under
 * it. Each case here asserts the number that must NOT move as much as the one that must.
 */
describe('parseEgress — the guest answering is not the guest asking', () => {
  const opts = { emulatorAddresses: SLIRP, guestAddress: '10.0.2.15' };

  it('keeps out the answers to a connection opened from outside the guest', () => {
    // Exactly the MR3220 shape: the bench connects through slirp, the guest's httpd refuses, and the RST is a
    // frame the guest emitted towards 10.0.2.2 — but not a place it chose to go.
    const o = parseEgress(
      pcap([
        frame({ src: '10.0.2.15', dst: '10.0.2.2', proto: 'tcp', sport: 80, dport: 50078, flags: RST_ACK }),
        frame({ src: '10.0.2.15', dst: '10.0.2.2', proto: 'tcp', sport: 80, dport: 50079, flags: RST_ACK }),
        frame({ src: '10.0.2.15', dst: '129.6.15.28', proto: 'tcp', sport: 1024, dport: 123, flags: SYN }),
      ]),
      opts,
    );
    expect(o.attempts.map((a) => a.address)).toEqual(['129.6.15.28']);
    expect(o.answeredFrames).toBe(2);
    // The denominator does not move: those frames existed and were the guest's.
    expect(o.guestFrames).toBe(3);
  });

  it('does not mistake an accept for an opening', () => {
    // SYN+ACK is the guest accepting what somebody else opened. Reading the SYN bit alone would call it egress.
    const o = parseEgress(
      pcap([frame({ src: '10.0.2.15', dst: '10.0.2.2', proto: 'tcp', sport: 23, dport: 41000, flags: SYN_ACK })]),
      opts,
    );
    expect(o.attempts).toEqual([]);
    expect(o.answeredFrames).toBe(1);
  });

  it('keeps every frame of a flow the guest DID open, not only its SYN', () => {
    const flow = { src: '10.0.2.15', dst: '8.8.8.8', proto: 'tcp' as const, sport: 4100, dport: 443 };
    const o = parseEgress(
      pcap([
        frame({ ...flow, flags: SYN }),
        frame({ ...flow, flags: ACK }),
        frame({ ...flow, flags: ACK, payload: [1, 2, 3] }),
      ]),
      opts,
    );
    expect(o.attempts).toHaveLength(1);
    expect(o.attempts[0]?.frames).toBe(3);
    expect(o.answeredFrames).toBe(0);
  });

  it('decides per flow, not per destination — the same host can be both', () => {
    const o = parseEgress(
      pcap([
        frame({ src: '10.0.2.15', dst: '10.0.2.2', proto: 'tcp', sport: 80, dport: 50078, flags: RST_ACK }),
        frame({ src: '10.0.2.15', dst: '10.0.2.2', proto: 'tcp', sport: 4200, dport: 8080, flags: SYN }),
      ]),
      opts,
    );
    expect(o.attempts.map((a) => a.port)).toEqual([8080]);
    expect(o.answeredFrames).toBe(1);
  });

  it('claims no direction for UDP, which carries nothing that says who spoke first', () => {
    const o = parseEgress(
      pcap([frame({ src: '10.0.2.15', dst: '10.0.2.3', proto: 'udp', sport: 1024, dport: 53 })]),
      opts,
    );
    expect(o.attempts).toHaveLength(1);
    expect(o.answeredFrames).toBe(0);
  });

  it('lists a frame whose flags were cut off, and says the direction is undecided', () => {
    // Losing a real attempt is the worse error, so an undecidable frame stays in the list — and is counted, so
    // the list is readable as the partly-undecided thing it is.
    const short = frame({ src: '10.0.2.15', dst: '1.1.1.1', proto: 'tcp', sport: 4300, dport: 80 }).slice(0, 42);
    const o = parseEgress(pcap([short]), opts);
    expect(o.attempts.map((a) => a.address)).toEqual(['1.1.1.1']);
    expect(o.undecidedFrames).toBe(1);
    expect(o.answeredFrames).toBe(0);
    expect(describeEgress(o, true)).toMatch(/too short to read the flags/);
  });

  it('says what the bound dropped, rather than ending the list where it ran out', () => {
    // A firmware scanning a /24 hits the cap. Rule: a bound that truncates states what it dropped and by what
    // rule — and never truncates by arrival order, which is why the kept ones are the most-addressed.
    const frames: number[][] = [];
    for (let i = 0; i < 260; i++) {
      const dst = `203.0.${Math.floor(i / 254)}.${(i % 254) + 1}`;
      frames.push(frame({ src: '10.0.2.15', dst, proto: 'tcp', sport: 5000 + i, dport: 80, flags: SYN }));
    }
    const o = parseEgress(pcap(frames), opts);
    expect(o.attempts).toHaveLength(200);
    expect(o.attemptsDropped).toBe(60);
    expect(describeEgress(o, true)).toMatch(/60 further distinct destination\(s\) went past this run's limit of 200/);
  });

  it('counts a dropped destination once, however many frames went to it', () => {
    const frames: number[][] = [];
    for (let i = 0; i < 201; i++) {
      const dst = `203.0.113.${(i % 201) + 1}`;
      frames.push(frame({ src: '10.0.2.15', dst, proto: 'tcp', sport: 5000 + i, dport: 80, flags: SYN }));
    }
    // The 201st destination, addressed five more times: still ONE destination dropped, not six.
    for (let k = 0; k < 5; k++) {
      frames.push(frame({ src: '10.0.2.15', dst: '203.0.113.201', proto: 'tcp', sport: 5200, dport: 80, flags: SYN }));
    }
    const o = parseEgress(pcap(frames), opts);
    expect(o.attemptsDropped).toBe(1);
  });

  it('says what the DNS bound dropped too', () => {
    const frames: number[][] = [];
    for (let i = 0; i < 106; i++) {
      frames.push(
        frame({
          src: '10.0.2.15',
          dst: '10.0.2.3',
          proto: 'udp',
          sport: 1024,
          dport: 53,
          payload: dnsQuestion(`h${i}.example.com`),
        }),
      );
    }
    const o = parseEgress(pcap(frames), opts);
    expect(o.dnsQueries).toHaveLength(100);
    expect(o.queriesDropped).toBe(6);
    expect(describeEgress(o, true)).toMatch(/6 further distinct name\(s\)/);
  });

  it('puts the answered count on the EMPTY verdict, which is the sentence it most changes', () => {
    // "It addressed nothing outside the emulator" is exactly the sentence that must not be read while 150 of the
    // guest's own frames sit uncounted behind it.
    const o = parseEgress(
      pcap([frame({ src: '10.0.2.15', dst: '10.0.2.2', proto: 'tcp', sport: 80, dport: 50078, flags: RST_ACK })]),
      opts,
    );
    expect(describeEgress(o, true)).toMatch(/addressed nothing outside the emulator/);
    expect(describeEgress(o, true)).toMatch(/1 frame\(s\) were this guest ANSWERING/);
  });

  it('sums the new counters across a merge instead of taking either side', () => {
    const a = parseEgress(
      pcap([frame({ src: '10.0.2.15', dst: '10.0.2.2', proto: 'tcp', sport: 80, dport: 50078, flags: RST_ACK })]),
      opts,
    );
    const b = parseEgress(
      pcap([frame({ src: '10.0.2.15', dst: '10.0.2.2', proto: 'tcp', sport: 80, dport: 50079, flags: RST_ACK })]),
      opts,
    );
    expect(mergeEgress(a, b)?.answeredFrames).toBe(2);
  });

  it('survives a merge with an observation stored before these counters existed', () => {
    // A stored result is data written by an OLDER build, and this module is handed one on every re-read.
    const old = { ...EMPTY_EGRESS, guestFrames: 4 } as EgressObservation;
    // biome-ignore lint/performance/noDelete: reproducing exactly what an older stored JSON does not carry.
    delete (old as { answeredFrames?: number }).answeredFrames;
    const fresh = parseEgress(
      pcap([frame({ src: '10.0.2.15', dst: '10.0.2.2', proto: 'tcp', sport: 80, dport: 1, flags: RST_ACK })]),
      opts,
    );
    expect(mergeEgress(old, fresh)?.answeredFrames).toBe(1);
  });
});

/**
 * The policy sentence, which is logged BEFORE any frame exists and is therefore the only thing a reader has to
 * tell a deliberately-opened guest from an unconfigured one. Three outcomes; the third used to be the default and
 * read like a footnote.
 */
describe('describeEgressPolicy — three outcomes, and the open one is now an act', () => {
  const F = 'FIRMLAB_EMU_ISOLATE';

  it('says the isolation is the default, and that nobody had to ask for it', () => {
    const s = describeEgressPolicy(F, { enabled: true, stated: false, byDefault: true });
    expect(s).toMatch(/the default, which nobody had to ask for/i);
    expect(s).toMatch(/restrict=on/);
    // It must not print `FLAG=1`, which would present a default as the operator's own setting.
    expect(s).not.toContain(`${F}=1`);
  });

  it('names the flag when the isolation WAS asked for — same policy, different provenance', () => {
    const asked = describeEgressPolicy(F, { enabled: true, stated: true, byDefault: false });
    const byDefault = describeEgressPolicy(F, { enabled: true, stated: false, byDefault: true });
    expect(asked).toContain(`${F}=1`);
    expect(asked).toMatch(/explicitly asked/i);
    // The pair is the point: both are isolated and the sentences are not interchangeable.
    expect(asked).not.toBe(byDefault);
  });

  it('reads an open guest as a decision, never as an absence of one', () => {
    const s = describeEgressPolicy(F, { enabled: false, stated: true, byDefault: false });
    expect(s).toMatch(/CAN reach the internet/i);
    expect(s).toMatch(/explicitly OFF/);
    // The load-bearing clause: this state is unreachable by default, so it cannot be read as "not configured".
    expect(s).toMatch(/Nothing arrives at this state by default/i);
  });

  it('keeps the recorded-either-way promise in every one of the three, since the panel relies on it', () => {
    for (const d of [
      { enabled: true, stated: false, byDefault: true },
      { enabled: true, stated: true, byDefault: false },
      { enabled: false, stated: true, byDefault: false },
    ]) {
      expect(describeEgressPolicy(F, d)).toMatch(/recorded either way|is recorded|still recorded/i);
    }
  });
});
