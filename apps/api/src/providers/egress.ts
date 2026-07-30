/**
 * What the emulated firmware tried to REACH — read off its own wire, and readable whether or not it was allowed.
 *
 * The rung that boots a firmware under `qemu-system` hands it `-netdev user`, which is unrestricted outbound. A
 * WDR3600 booted here has reached three public NTP servers. That sits against the workbench's own headline claim,
 * and the obvious answer — `restrict=on` — raised the question that decided this module's shape: does cutting the
 * egress also cut the *visibility* of the attempt?
 *
 * **It does not, and that was measured rather than assumed** (2026-07-29, in-container, MIPS BE guest built from
 * the WR940N's own busybox on a FirmAE kernel, pinging 8.8.8.8):
 *
 *   restrict=on   → 9 frames: the guest's ARP, its 3 ICMP to 8.8.8.8, and NO replies.
 *   restrict=off  → 12 frames: the same 3 ICMP, plus 3 replies from 8.8.8.8.
 *
 * `filter-dump` hangs off the netdev, so a frame the guest emits is captured before slirp decides whether to
 * forward it. The intent is fully observable with the door shut; only the answer disappears. That is why this
 * module records attempts unconditionally and the isolation is a separate switch — the observation is worth
 * having on every run, and it does not depend on the policy.
 *
 * **Why this is not folded into `parseGuestWire`.** That function answers "what address did the GUEST give
 * itself", so it excludes slirp's own addresses as a matter of correctness — attributing a reply that slirp NATed
 * to the guest was a real over-claim it had to be fixed for. This asks the opposite question, and for it slirp's
 * addresses are among the most interesting DESTINATIONS there are: a UDP/53 to `10.0.2.3` is the firmware asking
 * to resolve a name, which is exactly the thing an operator wants to see. Same capture, opposite polarity; one
 * function trying to be both would have to keep two contradictory exclusion rules straight.
 *
 * **The guest answering is not the guest asking.** A boot of the MR3220 rendered ~150 rows of
 * `10.0.2.2:<ephemeral port>` — one per probe the workbench itself sent through slirp's forwards. Every one of
 * them was the guest ANSWERING a connection this bench opened, presented under a heading that says the firmware
 * aimed there. That is the workbench reading its own intervention back as the subject's intent, which is the one
 * thing this module exists not to do, and it buried the two rows that were real. TCP direction is decided from
 * the flags: a SYN without ACK is the guest opening a connection; anything on a flow it never opened is an
 * answer, counted apart. UDP carries no such bit, so no direction is claimed for it — see `answeredFrames`.
 *
 * **What this refuses to claim.** A destination here is a destination the guest ADDRESSED, not one it reached: a
 * SYN into a black hole and a completed handshake look identical from the sending side, and under isolation
 * nothing is reached by construction. Nor does it claim anything about the physical device — a firmware phoning
 * home under qemu, with an emulated NIC and a kernel that is not its own, is `confirmed_in_emulation` at best.
 *
 * Pure and I/O-free: the runner reads the file, this reads the bytes.
 */

/** One destination the guest addressed, with how often and over what. */
export interface EgressAttempt {
  /** Where it was aimed. `scope` says what that address means here; the address itself is never rewritten. */
  address: string;
  protocol: 'tcp' | 'udp' | 'icmp' | 'other';
  /** Absent for ICMP and for a protocol with no port. */
  port?: number;
  /**
   * `external`   — outside the emulator and outside the guest's own subnet. THIS is egress.
   * `emulator`   — slirp itself: its gateway and its DNS. The firmware talking to the sandbox, not through it.
   * `local`      — the guest's own subnet. In this rung there is nobody else on it; a firmware scanning its LAN
   *                still shows up here rather than being silently dropped.
   * `multicast`  — mDNS, SSDP, all-routers. Announcements, not connections, and counted apart so they cannot
   *                inflate an egress total.
   */
  scope: 'external' | 'emulator' | 'local' | 'multicast';
  frames: number;
}

/** A name the guest asked to resolve. The single most legible thing in the whole capture. */
export interface DnsQuery {
  /** The QNAME as it was on the wire, lower-cased. Never a guess: a truncated question is counted, not printed. */
  name: string;
  /** Where the question was sent — usually slirp's resolver, but a firmware may hardcode 8.8.8.8. */
  server: string;
  frames: number;
}

export interface EgressObservation {
  attempts: EgressAttempt[];
  dnsQueries: DnsQuery[];
  /** Questions whose QNAME ran past the captured bytes. Counted rather than printed half-resolved. */
  dnsTruncated: number;
  /** Frames attributed to the guest. The denominator behind every count above. */
  guestFrames: number;
  /**
   * TCP frames the guest sent on a flow it never opened — its answers to connections opened from outside it,
   * which in this rung means the port-forwards this workbench made to probe it. Kept OUT of `attempts` and
   * counted here: they are a measurement of what the bench did, not of what the firmware chose. UDP is never
   * counted here, because a datagram carries nothing that decides who spoke first.
   */
  answeredFrames: number;
  /**
   * TCP frames whose flags ran past the captured bytes, so who opened the flow could not be decided. They stay
   * in `attempts` — dropping a real attempt is the worse error — and are counted so the list is readable as the
   * partly-undecided thing it is. With the capture length this rung uses this is normally 0.
   */
  undecidedFrames: number;
  /** Distinct destinations past `MAX_ATTEMPTS`. A bound that truncates says what it dropped. */
  attemptsDropped: number;
  /** Distinct questions past `MAX_QUERIES`. Same rule. */
  queriesDropped: number;
  /** True when the capture was longer than the caller read; every count is then a floor. */
  truncated: boolean;
  /** Empty when the bytes were a well-formed Ethernet capture; otherwise why nothing could be read. */
  problem: string;
}

export const EMPTY_EGRESS: EgressObservation = {
  attempts: [],
  dnsQueries: [],
  dnsTruncated: 0,
  guestFrames: 0,
  answeredFrames: 0,
  undecidedFrames: 0,
  attemptsDropped: 0,
  queriesDropped: 0,
  truncated: false,
  problem: '',
};

const MAX_FRAMES = 20_000;
/** Enough distinct destinations to characterise a boot; a firmware scanning a /24 must not grow the result. */
const MAX_ATTEMPTS = 200;
const MAX_QUERIES = 100;

/** The two TCP flags that decide who opened a flow. A SYN alone opens; a SYN+ACK accepts what someone else opened. */
const TCP_SYN = 0x02;
const TCP_ACK = 0x10;

/** Flow identity from the GUEST's side: what it is talking to, from which of its ports, to which of theirs. */
const flowKey = (dst: string, sport: number, dport: number): string => `${dst}\u0000${sport}\u0000${dport}`;

const ipv4 = (b: Uint8Array, o: number): string => `${b[o] ?? 0}.${b[o + 1] ?? 0}.${b[o + 2] ?? 0}.${b[o + 3] ?? 0}`;

const macAt = (b: Uint8Array, o: number): string => {
  const out: string[] = [];
  for (let i = 0; i < 6; i++) out.push((b[o + i] ?? 0).toString(16).padStart(2, '0'));
  return out.join(':');
};

const toInt = (addr: string): number | null => {
  const parts = addr.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n;
};

/** Is `addr` inside `network/prefix`? Used only to tell the guest's own subnet from everything beyond it. */
export function sameSubnet(addr: string, network: string, prefix: number): boolean {
  const a = toInt(addr);
  const n = toInt(network);
  if (a === null || n === null || prefix < 0 || prefix > 32) return false;
  if (prefix === 0) return true;
  const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
  return (a & mask) >>> 0 === (n & mask) >>> 0;
}

const isMulticastOrBroadcast = (addr: string): boolean => {
  const first = Number(addr.split('.')[0] ?? 0);
  return addr === '255.255.255.255' || (first >= 224 && first <= 239);
};

export interface EgressScopeInput {
  /** The addresses slirp itself answers on — its gateway and its DNS. */
  emulatorAddresses?: string[];
  /** The address the guest gave itself, if one is known; its /24 is then "local" rather than "external". */
  guestAddress?: string | null;
  guestPrefix?: number;
}

/** Pure: what a destination address means for this run. Exported because it is the whole editorial judgment. */
export function scopeOf(address: string, opts: EgressScopeInput = {}): EgressAttempt['scope'] {
  if (isMulticastOrBroadcast(address)) return 'multicast';
  if ((opts.emulatorAddresses ?? []).includes(address)) return 'emulator';
  if (opts.guestAddress && sameSubnet(address, opts.guestAddress, opts.guestPrefix ?? 24)) return 'local';
  return 'external';
}

/**
 * A label as a hostname may contain. Deliberately narrow: this string comes off the wire, it is rendered into a
 * panel, and it is joined into a map key — so a label carrying a separator, a control byte or markup is not a
 * hostname this will report. `_` is in because `_dmarc`/`_sip._tcp` are real names a firmware asks for.
 */
const HOSTNAME_LABEL = /^[a-zA-Z0-9_-]+$/;

/**
 * Read the QNAME of a DNS question.
 *
 * Returns `null` in three cases, all of them "a question was asked and its name is not readable", which the
 * caller counts as `dnsTruncated` rather than printing something that is not what was asked:
 *
 *  - the name runs past the bytes that were captured — `filter-dump` truncates every frame, and half a hostname
 *    is a DIFFERENT hostname;
 *  - it opens with a compression pointer, which is illegal in a question and cannot be followed in a truncated
 *    frame anyway;
 *  - a label is not hostname-shaped. A DNS label is length-prefixed, so its CONTENT is arbitrary bytes — a
 *    firmware can emit a question whose "name" carries a separator or a control character. That string would
 *    then be joined into a composite map key and rendered into the UI, so it is refused at the parser instead.
 */
export function parseDnsQName(payload: Uint8Array): string | null {
  // ID, flags, and the four counts — the question starts at 12.
  if (payload.length < 13) return null;
  const labels: string[] = [];
  let i = 12;
  for (let guard = 0; guard < 128; guard++) {
    const len = payload[i];
    if (len === undefined) return null; // ran off the captured bytes
    if (len === 0) return labels.length ? labels.join('.').toLowerCase() : null;
    if ((len & 0xc0) !== 0) return null;
    const end = i + 1 + len;
    if (end > payload.length) return null;
    const label = String.fromCharCode(...payload.subarray(i + 1, end));
    if (!HOSTNAME_LABEL.test(label)) return null;
    labels.push(label);
    i = end;
  }
  return null;
}

/**
 * Pure: the destinations the guest addressed, from a classic pcap of its own netdev.
 *
 * Attribution is by MAC, and it is done in two phases for the same reason `parseGuestWire` does it: slirp NATs, so
 * a frame it puts on the wire can bear a source address belonging to a stranger, and only its MAC identifies it.
 * Phase one learns slirp's MAC from the addresses it is known to answer on; phase two attributes everything else
 * to the guest. A capture in which slirp never spoke leaves every frame attributed to the guest, which is the
 * conservative direction here — it can only over-report what the firmware tried, never hide it.
 */
export function parseEgress(pcap: Uint8Array, opts: EgressScopeInput = {}): EgressObservation {
  if (pcap.length === 0) return { ...EMPTY_EGRESS, problem: 'The capture file is empty — no frame was ever written.' };
  if (pcap.length < 24) {
    return { ...EMPTY_EGRESS, problem: `The capture is ${pcap.length} bytes: too short even for a pcap header.` };
  }
  const view = new DataView(pcap.buffer, pcap.byteOffset, pcap.byteLength);
  const magic = view.getUint32(0, false);
  let little: boolean;
  if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d) little = false;
  else if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) little = true;
  else return { ...EMPTY_EGRESS, problem: `Not a classic pcap (magic 0x${magic.toString(16)}).` };
  if (view.getUint32(20, little) !== 1) {
    return { ...EMPTY_EGRESS, problem: `Capture link type ${view.getUint32(20, little)} is not Ethernet.` };
  }

  const emulatorOwn = new Set(opts.emulatorAddresses ?? []);
  const frames: { src: string; dst: string; smac: string; body: Uint8Array }[] = [];
  const emulatorMacs = new Set<string>();

  let off = 24;
  let count = 0;
  while (off + 16 <= pcap.length && count < MAX_FRAMES) {
    const incl = view.getUint32(off + 8, little);
    off += 16;
    const frame = pcap.subarray(off, Math.min(off + incl, pcap.length));
    off += incl;
    count++;
    if (frame.length < 14) continue;
    const ethertype = (frame[12] ?? 0) * 256 + (frame[13] ?? 0);
    // ARP is a request to the LOCAL segment, never egress; it is also where slirp announces itself, so the MAC
    // learning below reads it. IPv6 is skipped: the rung's networking is v4 and a partial v6 story would be worse
    // than none — recorded in the backlog rather than half-implemented.
    if (ethertype !== 0x0800 || frame.length < 34) continue;
    const src = ipv4(frame, 26);
    const dst = ipv4(frame, 30);
    const smac = macAt(frame, 6);
    if (emulatorOwn.has(src)) emulatorMacs.add(smac);
    frames.push({ src, dst, smac, body: frame });
  }

  // Which TCP flows the GUEST opened. Read in its own pass so the answer does not depend on capture order: a
  // retransmitted SYN arriving after the data it opened would otherwise decide the flow the wrong way.
  const opened = new Set<string>();
  for (const f of frames) {
    if (emulatorMacs.has(f.smac)) continue;
    const b = f.body;
    if ((b[23] ?? 0) !== 6) continue;
    const po = 14 + ((b[14] ?? 0) & 0x0f) * 4;
    if (b.length < po + 14) continue;
    const flags = b[po + 13] ?? 0;
    if ((flags & TCP_SYN) === 0 || (flags & TCP_ACK) !== 0) continue;
    const sport = (b[po] ?? 0) * 256 + (b[po + 1] ?? 0);
    const dport = (b[po + 2] ?? 0) * 256 + (b[po + 3] ?? 0);
    opened.add(flowKey(f.dst, sport, dport));
  }

  const attempts = new Map<string, EgressAttempt>();
  const queries = new Map<string, DnsQuery>();
  let dnsTruncated = 0;
  let guestFrames = 0;
  let answeredFrames = 0;
  let undecidedFrames = 0;
  let attemptsDropped = 0;
  let queriesDropped = 0;
  const droppedKeys = new Set<string>();
  const droppedQueryKeys = new Set<string>();

  for (const f of frames) {
    if (emulatorMacs.has(f.smac)) continue; // the emulator talking is not the firmware talking
    guestFrames++;
    const b = f.body;
    const ihl = ((b[14] ?? 0) & 0x0f) * 4;
    const proto = b[23] ?? 0;
    const po = 14 + ihl;
    let protocol: EgressAttempt['protocol'] = 'other';
    let port: number | undefined;
    if (proto === 1) protocol = 'icmp';
    else if (proto === 6 || proto === 17) {
      protocol = proto === 6 ? 'tcp' : 'udp';
      if (b.length >= po + 4) port = (b[po + 2] ?? 0) * 256 + (b[po + 3] ?? 0);
    }

    // The direction gate. Only TCP can be decided, and only from the flags; an undecidable frame is left in the
    // list rather than dropped, because losing a real attempt is worse than showing one that may be an answer.
    if (protocol === 'tcp') {
      if (b.length < po + 14) undecidedFrames++;
      else {
        const sport = (b[po] ?? 0) * 256 + (b[po + 1] ?? 0);
        if (!opened.has(flowKey(f.dst, sport, port ?? 0))) {
          answeredFrames++;
          continue;
        }
      }
    }

    const key = `${protocol}\u0000${f.dst}\u0000${port ?? ''}`;
    const existing = attempts.get(key);
    if (existing) existing.frames++;
    else if (attempts.size < MAX_ATTEMPTS) {
      attempts.set(key, {
        address: f.dst,
        protocol,
        ...(port === undefined ? {} : { port }),
        scope: scopeOf(f.dst, opts),
        frames: 1,
      });
    } else if (!droppedKeys.has(key)) {
      // Past the bound. Counted as DISTINCT destinations dropped, not frames: the sentence a reader needs is
      // "there were N more places", and a per-frame tally would read as a much larger loss than it is.
      droppedKeys.add(key);
      attemptsDropped++;
    }

    if (protocol === 'udp' && port === 53 && b.length >= po + 8) {
      const name = parseDnsQName(b.subarray(po + 8));
      if (name === null) dnsTruncated++;
      else {
        const qk = `${name}\u0000${f.dst}`;
        const q = queries.get(qk);
        if (q) q.frames++;
        else if (queries.size < MAX_QUERIES) queries.set(qk, { name, server: f.dst, frames: 1 });
        else if (!droppedQueryKeys.has(qk)) {
          droppedQueryKeys.add(qk);
          queriesDropped++;
        }
      }
    }
  }

  // Most-addressed first, then by name, so the ordering is a property of the traffic and never of walk order.
  const byFrames = <T extends { frames: number; address?: string; name?: string }>(a: T, b: T): number =>
    b.frames - a.frames || (a.address ?? a.name ?? '').localeCompare(b.address ?? b.name ?? '');

  return {
    attempts: [...attempts.values()].sort(byFrames),
    dnsQueries: [...queries.values()].sort(byFrames),
    dnsTruncated,
    guestFrames,
    answeredFrames,
    undecidedFrames,
    attemptsDropped,
    queriesDropped,
    truncated: count >= MAX_FRAMES,
    problem: '',
  };
}

/** Union of two observations — the rung boots twice and both passes are the same firmware. */
export function mergeEgress(a: EgressObservation | null, b: EgressObservation | null): EgressObservation | null {
  if (!a) return b;
  if (!b) return a;
  const attempts = new Map<string, EgressAttempt>();
  for (const x of [...a.attempts, ...b.attempts]) {
    const key = `${x.protocol}\u0000${x.address}\u0000${x.port ?? ''}`;
    const seen = attempts.get(key);
    if (seen) seen.frames += x.frames;
    else attempts.set(key, { ...x });
  }
  const queries = new Map<string, DnsQuery>();
  for (const q of [...a.dnsQueries, ...b.dnsQueries]) {
    const key = `${q.name}\u0000${q.server}`;
    const seen = queries.get(key);
    if (seen) seen.frames += q.frames;
    else queries.set(key, { ...q });
  }
  return {
    attempts: [...attempts.values()].sort((x, y) => y.frames - x.frames || x.address.localeCompare(y.address)),
    dnsQueries: [...queries.values()].sort((x, y) => y.frames - x.frames || x.name.localeCompare(y.name)),
    dnsTruncated: a.dnsTruncated + b.dnsTruncated,
    guestFrames: a.guestFrames + b.guestFrames,
    // Summed, not maxed: each is a count of frames or of destinations in ITS pass, and the merged observation
    // covers both passes. `??` because a merge can be handed an observation stored before these existed.
    answeredFrames: (a.answeredFrames ?? 0) + (b.answeredFrames ?? 0),
    undecidedFrames: (a.undecidedFrames ?? 0) + (b.undecidedFrames ?? 0),
    attemptsDropped: (a.attemptsDropped ?? 0) + (b.attemptsDropped ?? 0),
    queriesDropped: (a.queriesDropped ?? 0) + (b.queriesDropped ?? 0),
    truncated: a.truncated || b.truncated,
    // A problem on either side is a limit on the merged counts, so it is kept rather than averaged away.
    problem: [a.problem, b.problem].filter(Boolean).join(' '),
  };
}

/**
 * Pure: the sentence stating this run's egress POLICY, before any frame is captured.
 *
 * Three outcomes, not two, and the third is the one that used to be invisible. `isolated` alone cannot tell a
 * reader whether the guest is cut off because that is the policy of a deployment nobody configured, or because an
 * operator asked for it — and, far more importantly, an OPEN guest can now only happen because somebody explicitly
 * opened it. That used to be the silent default, so the sentence for it was written as a mild note; it is now a
 * deliberate act and reads like one.
 *
 * Structural parameter rather than the `FlagDecision` type, so this module keeps importing nothing at all.
 */
export function describeEgressPolicy(
  flag: string,
  d: { enabled: boolean; stated: boolean; byDefault: boolean },
): string {
  if (d.enabled && d.byDefault) {
    return 'The guest is cut off with restrict=on — the default, which nobody had to ask for. Host→guest forwards still work, so this rung still reaches its own services, and what the firmware tries to reach is recorded either way: blocking a frame does not hide the attempt.';
  }
  if (d.enabled) {
    return `${flag}=1: the guest is cut off with restrict=on, as this deployment explicitly asked. Host→guest forwards still work, and what the firmware tries to reach is still recorded.`;
  }
  return `${flag} is explicitly OFF, so this guest CAN reach the internet from this host — a firmware under analysis may phone home during this run. Nothing arrives at this state by default; it was set. Everything the guest addresses is recorded either way; clear it in Settings to keep the observation and drop the reachability.`;
}

/**
 * Pure: the sentence a reader gets. It never says "the firmware contacted X" — under isolation nothing was
 * reached, and without it a SYN into a black hole still looks exactly like this from the sending side.
 */
export function describeEgress(o: EgressObservation, isolated: boolean): string {
  if (o.problem) return o.problem;
  if (o.guestFrames === 0) return 'The guest put no IPv4 frame on the wire during this run.';
  const answered = answeredNote(o);
  const external = o.attempts.filter((a) => a.scope === 'external');
  const gate = isolated
    ? 'Outbound was blocked for this run, so nothing left the host; the attempt is what was recorded.'
    : 'Outbound was NOT blocked for this run: the emulated firmware could reach these.';
  if (external.length === 0) {
    return `The guest addressed nothing outside the emulator during this run (${o.guestFrames} frame(s)). ${
      isolated ? 'Outbound was blocked.' : 'Outbound was open and went unused.'
    }${answered}`;
  }
  const names = o.dnsQueries.length ? ` It asked to resolve ${o.dnsQueries.length} name(s).` : '';
  const lost = o.dnsTruncated ? ` ${o.dnsTruncated} DNS question(s) were captured too short to read the name.` : '';
  return `The guest addressed ${external.length} destination(s) beyond the emulator.${names} ${gate}${lost}${answered}`;
}

/**
 * The frames this bench provoked, and the bounds that truncated. Appended to every verdict `describeEgress`
 * returns, including the empty one — "it addressed nothing" is exactly the sentence that must not be read while
 * 150 of the guest's frames sit uncounted behind it.
 */
export function answeredNote(o: EgressObservation): string {
  const parts: string[] = [];
  if (o.answeredFrames > 0) {
    parts.push(
      `${o.answeredFrames} frame(s) were this guest ANSWERING connections opened from outside it — in this rung, the probes this workbench itself sent — and are not destinations the firmware chose.`,
    );
  }
  if (o.undecidedFrames > 0) {
    parts.push(
      `${o.undecidedFrames} TCP frame(s) were captured too short to read the flags, so who opened those flows is undecided; they are listed above rather than dropped.`,
    );
  }
  if (o.attemptsDropped > 0) {
    parts.push(
      `${o.attemptsDropped} further distinct destination(s) went past this run's limit of ${MAX_ATTEMPTS} and are not listed; the ones shown are those with the most frames, never the first to arrive.`,
    );
  }
  if (o.queriesDropped > 0) {
    parts.push(`${o.queriesDropped} further distinct name(s) went past this run's limit of ${MAX_QUERIES}.`);
  }
  return parts.length ? ` ${parts.join(' ')}` : '';
}
