/**
 * Emulation rungs 2 and 3 — the deeper, service-level bring-up that a static workbench doesn't reach, made
 * into deterministic providers (the fix for the parent platform's #1 fragility: hand-driven emulation that
 * hangs). The agent (later) only picks a rung and reads the result; the mechanics live here.
 *
 *   rung-2 "chroot service"  → start a network daemon under qemu-user in the rootfs with the libnvram shim.
 *   rung-3 "full-system"     → boot the rootfs under qemu-system + a firmadyne kernel, TWICE: once to learn what
 *                              network the firmware wants, once to give it one and see whether anything answers.
 *
 * Two invariants, always:
 *   1. Teardown is GUARANTEED (a stray qemu httpd is what stalls a whole run) — every boot kills its OWN qemu in a
 *      finally and waits for it to die, whatever happened, and the run then attempts a sweep for strays. The sweep
 *      is best-effort and says so: `pkill` is not installed in this deployment.
 *   2. Honesty — proof is capped by what actually ran: `confirmed_in_emulation` (rung-2, and rung-3 when something
 *      answered but no boot was ever printed) / `confirmed_full_system` (rung-3, boot printed AND a service
 *      answered); `blocked_by_platform` when the required assets/tools aren't present. qemu output is never
 *      inflated to device compromise.
 *
 * **The two-pass run, and why the rung needed one.** Full-system boot reached userspace and no service was ever
 * reachable, because the guest configures the network its own hardware implies and that hardware is not here. So
 * pass one is the boot that already existed, read for what the firmware configured (`guestNetwork` from the
 * console, `parseGuestWire` from the frames); a configuration is inferred from that and only from that
 * (`inferGuestNetwork`); pass two boots with it applied and the same TCP probe decides whether anything answered.
 * This is firmadyne/FirmAE's move: match the EMULATOR to the guest's own address rather than the other way round —
 * done with slirp instead of a TAP device, since the container has no privilege to make one — and where the guest
 * states no address at all, the kernel's own `ip=` autoconfiguration supplies one, which the console then confirms
 * or denies with `IP-Config:` lines of its own.
 *
 * **The console is not the guest, and this rung learned that the expensive way.** Its previous verdict said the
 * WR940N "configured ONLY loopback": true of the log — 305 KB of it, containing the string `192.168` exactly zero
 * times — and false of the machine, which was ARPing as **192.168.0.1** throughout. TP-Link's `/usr/bin/httpd` IS
 * the whole router program; it brings `br0` up and addresses it through ioctls from inside one process, and no
 * execve trace, no printk and not even firmadyne's own `__inet_insert_ifa` hook ever names the address. One qemu
 * argument (`-object filter-dump`) makes the frames readable, and the frames are the fact. A deployment whose qemu
 * has no such object degrades to console-only inference and SAYS so, rather than reporting a guest as address-less
 * because that is all it could see.
 *
 * **What the second pass may not do.** It may not turn an assumption into a claim. `inferGuestNetwork` returns
 * `none` — with the evidence quoted — whenever neither the console nor the wire names a usable interface, and a
 * `none` stops the run there: the question was asked and this deployment could not answer it. A pass that ran and
 * had nothing accept is reported as nothing accepting. Reachability is never read off a successful `ifconfig` line;
 * it is read off a socket that got bytes back — and when nothing does, the capture separates a REFUSED connection
 * (a live stack, no listener) from a swallowed one (a filter inside the guest), which the socket cannot.
 *
 * These rungs need the opt-in assets baked by Dockerfile.firmware (libnvram + firmadyne kernels). Without them
 * the runners return a blocked result rather than attempting a half-baked bring-up.
 */
import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { promisify } from 'node:util';
import type { Architecture, ProofState } from '@firmlab/core';
import { type LaneFlagName, effectiveEnv } from '../flags.js';
import { detectTools } from '../tools.js';
import { type BootDiagnosis, diagnoseUnreachable } from './boot-diagnose.js';
import { type EgressObservation, describeEgress, mergeEgress, parseEgress } from './egress.js';
import type { JobHandle } from './jobs.js';
import { readPortMap } from './portmap-run.js';
import { type PortProtocol, planForwards } from './portmap.js';
import {
  FIRMADYNE_KERNELS_DIR,
  LIBNVRAM_DIR,
  QEMU_MACHINE_BY_ARCH,
  QEMU_SYSTEM_BY_ARCH,
  QEMU_USER_BY_ARCH,
} from './preflight.js';

const execFileAsync = promisify(execFile);

/** How long to hold the box open waiting for the guest to come up, and how often to knock on its ports. */
const BOOT_TIMEOUT_MS = 120_000;
const PROBE_INTERVAL_MS = 2000;
/** Console output kept per stream. A chatty boot must not be able to grow this without bound. */
const CONSOLE_CAP = 256 * 1024;

export interface SystemEmulationResult {
  ran: boolean;
  strategy: 'chroot-service' | 'full-system';
  proofState: ProofState;
  reason: string;
  command: string;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** The host→guest forwards this run actually set up, so a reader can see what WAS reachable. */
  forwards?: { host: number; guest: number; protocol: PortProtocol }[];
  /** Of those, the ones that accepted a TCP connection. Empty is a real, readable result. */
  open?: { host: number; guest: number }[];
  /**
   * What pass one read out of the guest's own console — the evidence the inference was drawn from.
   *
   * Optional forever, like every field added to a persisted result type: a result stored by an older build has
   * none of this, and a required field would make the web types assert something they cannot know.
   */
  network?: GuestNetwork;
  /** What pass one saw the guest put on the WIRE, which on this corpus is where the address usually is. */
  wire?: WireObservation;
  /** What was inferred from that, whether it was applied, and what the kernel said about it in pass two. */
  inference?: {
    kind: NetworkInference['kind'];
    reason: string;
    evidence: string[];
    applied: boolean;
    plan?: QemuNetworkPlan | null;
    /** Pass two's own `IP-Config:` line, so "the kernel took it" is read rather than assumed. */
    ipConfig?: { applied: boolean; line: string | null } | null;
  };
  /** One entry per boot, so both passes stay readable after the fact. Consoles are not duplicated here. */
  passes?: SystemEmulationPass[];
  /**
   * Where the firmware tried to go, merged across both passes, and whether it was allowed to get there.
   *
   * `isolated` is not decoration: it is the difference between "it addressed three NTP servers" and "it reached
   * three NTP servers", and only the run knows which. Optional forever, like every field added to a persisted
   * result type — a result stored before this existed has neither, and a required field would make the web
   * types assert something they cannot know about it.
   */
  egress?: EgressObservation;
  /** True when this run was booted with `restrict=on`, so nothing below was reached. */
  isolated?: boolean;
  /**
   * Why nothing answered, when nothing did. Absent on a run where something answered — there is then nothing to
   * diagnose — and on results stored before this existed. Never changes `proofState`: it explains the empty
   * list, it does not reclassify it.
   */
  unreachable?: BootDiagnosis;
}

/** A single boot's outcome, summarised. The raw console of the pass the verdict came from is `stdout`. */
export interface SystemEmulationPass {
  pass: number;
  label: string;
  command: string;
  booted: boolean;
  marker: string | null;
  panicked: boolean;
  timedOut: boolean;
  forwards: { host: number; guest: number; protocol: PortProtocol }[];
  open: { host: number; guest: number }[];
  network: GuestNetwork;
  /** What this pass saw on the wire, when this qemu could capture it. */
  wire?: WireObservation;
  /** What this pass saw the guest ADDRESS. Per pass, because the two boots have different networks. */
  egress?: EgressObservation;
}

// === Pure command builders (unit-tested; no I/O) ===

/** The libnvram shim path for an arch, both on the host (asset check) and inside the chroot (copied in). */
export function libnvramHostPath(arch: Architecture): string {
  return `${LIBNVRAM_DIR}/libnvram-${arch}.so`;
}

/**
 * rung-2 argv: run the service under qemu-user inside the rootfs chroot, preloading the NVRAM shim. cwd is the
 * rootfs; the qemu-static binary and the shim are copied to the rootfs root first (see runChrootService).
 */
export function buildChrootServiceArgs(qemuStaticName: string, service: string): string[] {
  const svc = `/${service.replace(/^\/+/, '')}`;
  return ['.', `/${qemuStaticName}`, '-E', 'LD_PRELOAD=/libnvram.so', svc];
}

/**
 * rung-3 argv: boot the rootfs under qemu-system with a firmadyne kernel, forwarding every port the firmware
 * declares rather than the one this file used to assume.
 *
 * It was `hostfwd=tcp::8080-:80`, a single forward with the guest side hardcoded. On the GL.iNet BE3600 that
 * reaches the HTTP listener and nothing else, while the image's own `/etc/config/uhttpd` also declares
 * `listen_https 0.0.0.0:443` and `/etc/config/dropbear` declares `Port '22'` — an entire remote surface left
 * unreachable inside a rung called `confirmed_full_system`. `-netdev user` accepts repeated `hostfwd`, so the
 * cost of forwarding what the firmware actually asks for is nil; the work was knowing what to ask for.
 */
export function buildFullSystemArgs(
  machine: string,
  kernelPath: string,
  rootfsImage: string,
  forwards: { host: number; guest: number }[],
  /**
   * Pass two's network, inferred from pass one's console. Absent = pass one: qemu's defaults, exactly the
   * behaviour that existed before, so the LEARN boot is not perturbed by anything this file believes.
   */
  plan?: QemuNetworkPlan | null,
  /**
   * Where to dump every frame on the guest's netdev. Absent = no capture, which is what a qemu without the
   * `filter-dump` object gets — the run then degrades to console-only inference rather than refusing to boot.
   */
  dumpFile?: string | null,
  /**
   * `FIRMLAB_EMU_ISOLATE` — cut the guest off the internet. A PARAMETER, never read from the environment in here:
   * this function is the unit-tested one, and a builder that consulted `process.env` could not be asked what it
   * emits under either policy.
   */
  isolate = false,
): string[] {
  // An empty guest address is qemu's "whatever the guest is", which is right for pass one and wrong the moment
  // slirp has been moved onto the firmware's own subnet — there the forward has to name the address the firmware
  // gave itself, because slirp has no way to discover it.
  const guestAddr = plan?.guestAddress ?? '';
  const fwd = forwards.map((f) => `hostfwd=tcp::${f.host}-${guestAddr}:${f.guest}`).join(',');
  const netdev = ['user', 'id=n0'];
  // `restrict=on` isolates the guest from the host and from everything past it, and — qemu's own words — "does not
  // affect any explicitly set forwarding rules", so the `hostfwd` below still reaches the guest's services and the
  // rung keeps its verdict. It is appended before the forwards purely for readability of the command line.
  if (isolate) netdev.push('restrict=on');
  if (plan?.slirpNet) netdev.push(`net=${plan.slirpNet}`);
  if (plan?.slirpHost) netdev.push(`host=${plan.slirpHost}`);
  if (fwd) netdev.push(fwd);
  // `ip=` is the kernel's own boot-time autoconfiguration (CONFIG_IP_PNP, present in both firmadyne kernels this
  // deployment ships — verified by the `IP-Config:` strings inside the vmlinux, not assumed). It is the only way to
  // give an address to a guest whose init never asks for one, and it announces itself in the console, so pass two
  // can check that the kernel took it instead of believing it did.
  const append = `console=ttyS0 root=/dev/sda rootfstype=ext2 rw${plan?.kernelIp ? ` ip=${plan.kernelIp}` : ''}`;
  return [
    '-M',
    machine,
    '-kernel',
    kernelPath,
    // `-nodefaults` and an explicit serial are not tidiness — without them qemu instantiates its default VGA and
    // dies with `failed to find romfile "vgabios-cirrus.bin"` before executing a single guest instruction, which
    // is what this deployment did every time. A headless firmware boot wants no display at all, and the console
    // has to be a serial we can read: the whole boot verdict is drawn from what this stream prints.
    '-nodefaults',
    '-serial',
    'mon:stdio',
    '-append',
    append,
    '-drive',
    `file=${rootfsImage},format=raw`,
    '-netdev',
    netdev.join(','),
    // The frame capture, when this qemu has one. `maxlen` keeps only enough of each frame for its headers — the
    // capture exists to read addresses, flags and the ONE payload field that is a destination rather than content:
    // the QNAME of a DNS question. That is why it is 256 and no longer 128. A question's name starts 54 bytes in
    // (Ethernet 14 + IP 20 + UDP 8 + DNS header 12), so 128 left 74 bytes and cut real vendor hostnames in half —
    // and half a hostname is a different hostname, so `parseDnsQName` had to discard them. 256 leaves 202 bytes,
    // still nowhere near a body: a firmware that streams video for two minutes must not be able to fill a disk.
    ...(dumpFile ? ['-object', `filter-dump,id=fd0,netdev=n0,file=${dumpFile},maxlen=256`] : []),
    // `romfile=` (empty) disables the NIC's PXE option ROM. Without it qemu demands `efi-e1000.rom`, which the
    // Debian qemu packages do not ship, and refuses to start — the third romfile this rung tripped over. Nothing
    // is lost: the guest boots from `-kernel`, so a network boot ROM has no job here.
    '-device',
    'e1000,netdev=n0,romfile=',
    '-nographic',
  ];
}

/**
 * The addresses slirp itself speaks from, so the frame reader can tell the emulator apart from the guest.
 *
 * qemu's user network puts its gateway at `host=` (default net+2) and its DNS at net+3. Excluding them by address
 * rather than by subnet matters: when the kernel is handed an address, the GUEST is inside slirp's own subnet too,
 * and excluding the whole subnet would hide the very thing being looked for.
 */
export function emulatorAddressesFor(plan?: QemuNetworkPlan | null): string[] {
  if (!plan?.slirpNet || !plan.slirpHost) return [SLIRP_DEFAULT_GATEWAY, '10.0.2.3', '10.0.2.4'];
  const [base = '', prefixText = '24'] = plan.slirpNet.split('/');
  const network = ipToInt(base);
  if (network === null) return [plan.slirpHost];
  const prefix = Number(prefixText);
  const usable = Number.isInteger(prefix) && prefix >= 8 && prefix <= 30;
  return usable ? [plan.slirpHost, intToIp(network + 3), intToIp(network + 4)] : [plan.slirpHost];
}

/**
 * Pure: does the serial output show a kernel that actually came up?
 *
 * Needed because the previous verdict was drawn from a timeout: qemu still running after 120 s returned
 * `confirmed_full_system` with "booted and stayed up", and a kernel panic that hangs produces exactly the same
 * observation. The sibling provider already does this properly — `renode.ts` decides `booted` from real UART
 * captures — and this is the same discipline applied to qemu's console.
 *
 * Markers are deliberately drawn from what a Linux boot prints on the way up, and a panic is treated as evidence
 * AGAINST rather than merely as an absence.
 */
export function looksBooted(consoleOutput: string): { booted: boolean; marker: string | null; panicked: boolean } {
  const panic = /Kernel panic - not syncing|Attempted to kill init|VFS: Unable to mount root/i.exec(consoleOutput);
  if (panic) return { booted: false, marker: panic[0], panicked: true };
  const markers = [
    /Freeing unused kernel memory/i,
    /Please press Enter to activate this console/i,
    /init started:/i,
    /Starting kernel/i,
    /BusyBox v[\d.]+/i,
    /\blogin:\s*$/im,
  ];
  for (const re of markers) {
    const m = re.exec(consoleOutput);
    if (m) return { booted: true, marker: m[0].trim(), panicked: false };
  }
  return { booted: false, marker: null, panicked: false };
}

/**
 * How an interface came to our attention. Ordered by how much it tells us; `address` is the only one with an IP.
 *
 * `nic-registered` is the weakest and exists for a real case: the TP-Link MR3220's own router daemon SEGVs at 1.6 s
 * (`sending SIGSEGV to httpd for invalid read access` while reading `/proc/simple_config/system_mode`), so nothing
 * ever brings a link up and the console prints no ADDRCONF, no promiscuous mode and no bridge port. What it DOES
 * print is `e1000 0000:00:12.0 eth0: Intel(R) PRO/1000 Network Connection` — the kernel naming a NIC that exists.
 * Without that, the image reads as "no interface could be found", which is a fact about the vendor daemon dressed
 * up as a fact about the hardware.
 */
export type GuestInterfaceHow = 'address' | 'brought-up' | 'dhcp' | 'bridge-port' | 'link-up' | 'nic-registered';

export interface GuestInterfaceObservation {
  name: string;
  /** The IPv4 address the guest gave it, or null when the console shows the interface but never an address. */
  address: string | null;
  /** Prefix length, from an explicit netmask or a `/nn`. Null when the console stated none — never guessed here. */
  prefix: number | null;
  how: GuestInterfaceHow;
  /** The console text this was read from, verbatim, so a reader can check the parse rather than trust it. */
  evidence: string;
}

export interface GuestBridgeObservation {
  name: string;
  members: string[];
  evidence: string;
}

export interface GuestVlanObservation {
  parent: string;
  id: number;
  /** The VLAN device's own name where the console names it (`vconfig`/`ip link` do; the 8021q kernel line does not). */
  name: string | null;
  evidence: string;
}

/**
 * Everything the console says about the guest's network. `configured`/`loopbackOnly` keep their original meaning —
 * interfaces the guest gave an ADDRESS to — because the boot verdict is worded from them.
 */
export interface GuestNetwork {
  configured: string[];
  loopbackOnly: boolean;
  interfaces: GuestInterfaceObservation[];
  bridges: GuestBridgeObservation[];
  vlans: GuestVlanObservation[];
  /** Default gateways the guest asked for. */
  gateways: string[];
  /** Interfaces a DHCP client was pointed at — an intent to get an address, not an address. */
  dhcpClients: string[];
  /** What a cap dropped and by what rule. Empty when nothing was dropped. */
  boundNote: string;
}

/** Bound on each list, so a pathological console cannot make the observation unbounded. */
const NET_OBSERVATION_CAP = 32;
/** Evidence lines are quoted, so they are also capped — a firmadyne execve line carries the whole environment. */
const EVIDENCE_CAP = 200;

const RE_IFACE = '[a-z][a-z0-9._:-]*';
const RE_IPV4 = '(?:\\d{1,3}\\.){3}\\d{1,3}';

function ev(text: string): string {
  const s = text.trim().replace(/\s+/g, ' ');
  return s.length > EVIDENCE_CAP ? `${s.slice(0, EVIDENCE_CAP)}…` : s;
}

/** Pure: a dotted netmask as a prefix length, or null when it is not a contiguous mask. */
export function prefixFromNetmask(mask: string): number | null {
  const parts = mask.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  const bits =
    ((parts[0] as number) << 24) | ((parts[1] as number) << 16) | ((parts[2] as number) << 8) | (parts[3] as number);
  const u = bits >>> 0;
  // A netmask is a run of ones followed by a run of zeros; anything else is not one.
  const inverted = ~u >>> 0;
  if (((inverted + 1) & inverted) !== 0) return null;
  let n = 0;
  for (let i = 31; i >= 0; i--) {
    if ((u >>> i) & 1) n++;
    else break;
  }
  return n;
}

/** Pure: is this address the loopback net? `127.0.0.0/8` is loopback whatever interface carries it. */
export function isLoopbackAddress(addr: string): boolean {
  return /^127\./.test(addr);
}

function isUsableUnicast(addr: string): boolean {
  if (isLoopbackAddress(addr)) return false;
  const parts = addr.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (parts[0] === 0 || (parts[0] as number) >= 224) return false;
  return true;
}

/**
 * Pure: which interfaces the GUEST's own init actually configured, and everything else the console reveals about
 * the network it wanted — read from the console and from nothing else.
 *
 * The firmadyne kernels trace every `execve`, so the firmware's own network setup is right there in the boot log.
 * On the real WR940N it runs `ifconfig lo 127.0.0.1 up` and nothing else — the vendor's init brings up its LAN
 * through the Atheros switch path, which does not exist under `-M malta` with an e1000. So `eth0` has no address,
 * and NO forwarded port can answer however many daemons are listening.
 *
 * That distinction is worth stating rather than leaving inside "or they listen somewhere this run did not
 * forward": one reading sends an operator hunting for a port, the other tells them the guest has no network at
 * all and that this is a limit of the emulated hardware, not of the firmware.
 *
 * **The console carries more than the `ifconfig` calls, and the second pass needs it.** On the same WR940N boot the
 * KERNEL prints `device eth0 entered promiscuous mode`, `e1000: eth0 NIC Link is Up` and
 * `br0: port 1(eth0) entered forwarding state` — the vendor's bridge, built through ioctls that no `execve` trace
 * can show. That is the difference between "this guest has no network interface" (false) and "this guest has an
 * interface with no address" (true, and actionable). Everything below is a line the console actually prints; none
 * of it is a default filled in for a firmware that stayed silent.
 */
export function guestNetwork(consoleOutput: string): GuestNetwork {
  const ifaces = new Map<string, GuestInterfaceObservation>();
  const rank: Record<GuestInterfaceHow, number> = {
    address: 0,
    dhcp: 1,
    'brought-up': 2,
    'bridge-port': 3,
    'link-up': 4,
    'nic-registered': 5,
  };
  const note = (o: GuestInterfaceObservation): void => {
    const name = o.name.toLowerCase();
    const prev = ifaces.get(name);
    if (prev && rank[prev.how] <= rank[o.how]) return;
    ifaces.set(name, { ...o, name });
  };

  // --- addresses the guest assigned itself ---
  // `ifconfig <iface> <addr> [netmask <mask>]` — busybox's form, and the one the corpus actually shows.
  for (const m of consoleOutput.matchAll(
    new RegExp(`\\bifconfig\\s+(${RE_IFACE})\\s+(${RE_IPV4})(?:\\s+netmask\\s+(${RE_IPV4}))?`, 'gi'),
  )) {
    const mask = m[3];
    note({
      name: m[1] as string,
      address: m[2] as string,
      prefix: mask ? prefixFromNetmask(mask) : null,
      how: 'address',
      evidence: ev(m[0] as string),
    });
  }
  // `ip addr add 10.0.0.1/24 dev br0` — iproute2's form.
  for (const m of consoleOutput.matchAll(
    new RegExp(`\\bip\\s+addr(?:ess)?\\s+add\\s+(${RE_IPV4})(?:/(\\d{1,2}))?[^\\n]*?\\bdev\\s+(${RE_IFACE})`, 'gi'),
  )) {
    const p = m[2] ? Number(m[2]) : null;
    note({
      name: m[3] as string,
      address: m[1] as string,
      prefix: p !== null && p >= 0 && p <= 32 ? p : null,
      how: 'address',
      evidence: ev(m[0] as string),
    });
  }

  // --- interfaces the guest asked for without stating an address ---
  for (const m of consoleOutput.matchAll(new RegExp(`\\bifconfig\\s+(${RE_IFACE})\\s+up\\b`, 'gi'))) {
    note({ name: m[1] as string, address: null, prefix: null, how: 'brought-up', evidence: ev(m[0] as string) });
  }
  for (const m of consoleOutput.matchAll(new RegExp(`\\bifup\\s+(${RE_IFACE})`, 'gi'))) {
    note({ name: m[1] as string, address: null, prefix: null, how: 'brought-up', evidence: ev(m[0] as string) });
  }
  const dhcp = new Set<string>();
  for (const re of [
    new RegExp(`\\budhcpc\\b[^\\n]*?-i\\s+(${RE_IFACE})`, 'gi'),
    new RegExp(`\\bdhclient\\b\\s+(${RE_IFACE})`, 'gi'),
  ]) {
    for (const m of consoleOutput.matchAll(re)) {
      dhcp.add((m[1] as string).toLowerCase());
      note({ name: m[1] as string, address: null, prefix: null, how: 'dhcp', evidence: ev(m[0] as string) });
    }
  }

  // --- what the KERNEL says exists, which is the half an execve trace cannot see ---
  for (const re of [
    new RegExp(`ADDRCONF\\(NETDEV_(?:UP|CHANGE)\\):\\s*(${RE_IFACE}):`, 'gi'),
    new RegExp(`\\b(${RE_IFACE})\\s+NIC\\s+Link\\s+is\\s+Up`, 'gi'),
    new RegExp(`\\bdevice\\s+(${RE_IFACE})\\s+entered\\s+promiscuous\\s+mode`, 'gi'),
    new RegExp(`\\b(${RE_IFACE}):\\s*link\\s+up\\b`, 'gi'),
  ]) {
    for (const m of consoleOutput.matchAll(re)) {
      note({ name: m[1] as string, address: null, prefix: null, how: 'link-up', evidence: ev(m[0] as string) });
    }
  }
  // The NIC drivers this rung can actually attach, naming their interface at probe time. Deliberately a NAMED set
  // rather than a general "<word> <word>:" shape: a loose pattern over a firmadyne trace, where every line is
  // `subsystem: text`, would manufacture interfaces out of log prefixes.
  for (const m of consoleOutput.matchAll(
    /\b(?:e1000|e1000e|virtio_net|rtl8139cp?|ne2k_pci|pcnet32)\b[^\n]{0,40}?\b(eth\d+):/gi,
  )) {
    note({ name: m[1] as string, address: null, prefix: null, how: 'nic-registered', evidence: ev(m[0] as string) });
  }

  // --- bridges: the vendor's, built by ioctl and visible only in the kernel's port messages ---
  const bridges = new Map<string, GuestBridgeObservation>();
  const addBridge = (name: string, member: string | null, evidence: string): void => {
    const key = name.toLowerCase();
    const b = bridges.get(key) ?? { name: key, members: [], evidence };
    if (member && !b.members.includes(member.toLowerCase())) b.members.push(member.toLowerCase());
    bridges.set(key, b);
  };
  for (const m of consoleOutput.matchAll(new RegExp(`\\bbrctl\\s+addbr\\s+(${RE_IFACE})`, 'gi'))) {
    addBridge(m[1] as string, null, ev(m[0] as string));
  }
  for (const m of consoleOutput.matchAll(new RegExp(`\\bbrctl\\s+addif\\s+(${RE_IFACE})\\s+(${RE_IFACE})`, 'gi'))) {
    addBridge(m[1] as string, m[2] as string, ev(m[0] as string));
    // Enslaving an interface names it, and an interface the firmware names is one that exists.
    note({ name: m[2] as string, address: null, prefix: null, how: 'bridge-port', evidence: ev(m[0] as string) });
  }
  for (const m of consoleOutput.matchAll(
    new RegExp(
      `\\b(${RE_IFACE}):\\s*port\\s+\\d+\\((${RE_IFACE})\\)\\s+entered\\s+(?:forwarding|learning|listening|blocking|disabled)\\s+state`,
      'gi',
    ),
  )) {
    addBridge(m[1] as string, m[2] as string, ev(m[0] as string));
    note({ name: m[2] as string, address: null, prefix: null, how: 'bridge-port', evidence: ev(m[0] as string) });
  }

  // --- VLANs ---
  const vlans = new Map<string, GuestVlanObservation>();
  const addVlan = (v: GuestVlanObservation): void => {
    const key = `${v.parent.toLowerCase()}\u0000${v.id}`;
    if (!vlans.has(key)) vlans.set(key, { ...v, parent: v.parent.toLowerCase() });
  };
  for (const m of consoleOutput.matchAll(new RegExp(`\\bvconfig\\s+add\\s+(${RE_IFACE})\\s+(\\d{1,4})`, 'gi'))) {
    const id = Number(m[2]);
    addVlan({
      parent: m[1] as string,
      id,
      name: `${(m[1] as string).toLowerCase()}.${id}`,
      evidence: ev(m[0] as string),
    });
    // A VLAN is stacked on a device that exists; naming the parent is naming an interface.
    note({ name: m[1] as string, address: null, prefix: null, how: 'link-up', evidence: ev(m[0] as string) });
  }
  for (const m of consoleOutput.matchAll(
    new RegExp(
      `\\bip\\s+link\\s+add\\s+link\\s+(${RE_IFACE})\\s+name\\s+(${RE_IFACE})[^\\n]*?\\bid\\s+(\\d{1,4})`,
      'gi',
    ),
  )) {
    addVlan({
      parent: m[1] as string,
      id: Number(m[3]),
      name: (m[2] as string).toLowerCase(),
      evidence: ev(m[0] as string),
    });
  }
  for (const m of consoleOutput.matchAll(
    new RegExp(`8021q:\\s*adding VLAN (\\d{1,4}) to HW filter on device (${RE_IFACE})`, 'gi'),
  )) {
    // VLAN 0 is the 8021q core registering the priority-tag filter on every device it touches, not a VLAN the
    // firmware asked for. Reporting it as one would invent a network the firmware never described.
    const id = Number(m[1]);
    if (id > 0) addVlan({ parent: m[2] as string, id, name: null, evidence: ev(m[0] as string) });
  }

  // --- default routes ---
  const gateways = new Set<string>();
  for (const re of [
    new RegExp(`\\broute\\s+add\\s+default\\s+gw\\s+(${RE_IPV4})`, 'gi'),
    new RegExp(`\\bip\\s+route\\s+(?:add|replace)\\s+default\\s+via\\s+(${RE_IPV4})`, 'gi'),
  ]) {
    for (const m of consoleOutput.matchAll(re)) gateways.add(m[1] as string);
  }

  const configured = [...ifaces.values()]
    .filter((i) => i.address !== null)
    .map((i) => i.name)
    .sort();
  const nonLoopback = configured.filter((i) => i !== 'lo' && !i.startsWith('lo:'));

  // Every list is sorted before it is capped, so what survives a bound is never an artefact of the order the
  // console happened to print things in — the rule `selectFindings` exists for, applied here.
  const allIfaces = [...ifaces.values()].sort((a, b) => rank[a.how] - rank[b.how] || a.name.localeCompare(b.name));
  const allBridges = [...bridges.values()].sort((a, b) => a.name.localeCompare(b.name));
  const allVlans = [...vlans.values()].sort((a, b) => a.parent.localeCompare(b.parent) || a.id - b.id);
  const dropped =
    Math.max(0, allIfaces.length - NET_OBSERVATION_CAP) +
    Math.max(0, allBridges.length - NET_OBSERVATION_CAP) +
    Math.max(0, allVlans.length - NET_OBSERVATION_CAP);

  return {
    configured,
    loopbackOnly: configured.length > 0 && nonLoopback.length === 0,
    interfaces: allIfaces.slice(0, NET_OBSERVATION_CAP),
    bridges: allBridges.slice(0, NET_OBSERVATION_CAP),
    vlans: allVlans.slice(0, NET_OBSERVATION_CAP),
    gateways: [...gateways].sort(),
    dhcpClients: [...dhcp].sort(),
    boundNote:
      dropped > 0
        ? `${dropped} entr(ies) beyond the ${NET_OBSERVATION_CAP}-per-list cap were dropped; each list was sorted (addressed interfaces first, then by name) BEFORE the cap, so what survived is not an artefact of console order.`
        : '',
  };
}

/**
 * What the guest put ON THE WIRE, which is the half the console does not have.
 *
 * The WR940N settled this by measurement and it is worth stating plainly, because this module used to claim the
 * opposite: its console says `ifconfig lo 127.0.0.1 up` and nothing else, and its 305 KB of boot log contains the
 * string `192.168` exactly ZERO times — while the guest is, at that same moment, ARPing the network as
 * **192.168.0.1** and answering ARP for it. TP-Link's monolithic `/usr/bin/httpd` IS the router program: it brings
 * `br0` up and addresses it through ioctls, from inside one process, and no execve trace and no kernel printk ever
 * names the address. Even firmadyne's own `__inet_insert_ifa` hook — which does fire for the `ifconfig lo` — stays
 * silent for it.
 *
 * So "the firmware configured only loopback" was a reading of the console mistaken for a fact about the guest. The
 * frames are the fact. `-object filter-dump` costs one qemu argument and a temporary file, and it turns the
 * inference from a guess about what the firmware might want into a reading of what it actually did.
 */
export interface WireAddress {
  address: string;
  /** The MAC that used it. A vendor init frequently replaces the NIC's MAC, and that is worth seeing. */
  mac: string;
  /** `arp-sender` is the strongest: the guest claimed the address to the network. */
  how: 'arp-sender' | 'ip-source';
  frames: number;
}

export interface WireObservation {
  addresses: WireAddress[];
  frames: number;
  /** SYNs the emulator delivered into the guest, and what came back. Nothing back is itself a diagnosis. */
  synsToGuest: number;
  synAcksFromGuest: number;
  resetsFromGuest: number;
  /** True when the capture was longer than the bound this reads; the counts are then floors, not totals. */
  truncated: boolean;
  /** Empty when the file was a well-formed Ethernet capture; otherwise why nothing could be read from it. */
  problem: string;
}

const EMPTY_WIRE: WireObservation = {
  addresses: [],
  frames: 0,
  synsToGuest: 0,
  synAcksFromGuest: 0,
  resetsFromGuest: 0,
  truncated: false,
  problem: '',
};

/**
 * The lane flag that cuts the guest off. Named as the identifier it is — it is an environment variable an operator
 * greps a compose file for — and typed against the catalogue so a rename cannot leave this string behind.
 */
const EMU_ISOLATE_FLAG: LaneFlagName = 'FIRMLAB_EMU_ISOLATE';

/** Bounds on the capture this will read. A boot that talks for two minutes must not be able to grow the parse. */
const PCAP_MAX_BYTES = 8 * 1024 * 1024;
const PCAP_MAX_FRAMES = 20_000;

function ipv4(buf: Uint8Array, off: number): string {
  return `${buf[off] ?? 0}.${buf[off + 1] ?? 0}.${buf[off + 2] ?? 0}.${buf[off + 3] ?? 0}`;
}

function macAt(buf: Uint8Array, off: number): string {
  const out: string[] = [];
  for (let i = 0; i < 6; i++) out.push((buf[off + i] ?? 0).toString(16).padStart(2, '0'));
  return out.join(':');
}

/**
 * Pure: the addresses the guest used, read out of a classic pcap of its own netdev.
 *
 * `emulatorAddresses` are the ones slirp itself speaks from (its gateway, its DNS) — excluded because the emulator
 * talking is not the guest talking. Everything else that appears as an ARP sender or an IPv4 source came from the
 * other side of the wire, which is the firmware.
 */
export function parseGuestWire(pcap: Uint8Array, emulatorAddresses: string[] = []): WireObservation {
  if (pcap.length === 0) return { ...EMPTY_WIRE, problem: 'The capture file is empty — no frame was ever written.' };
  if (pcap.length < 24) {
    return { ...EMPTY_WIRE, problem: `The capture is ${pcap.length} bytes: too short even for a pcap header.` };
  }
  const view = new DataView(pcap.buffer, pcap.byteOffset, pcap.byteLength);
  const magic = view.getUint32(0, false);
  let little: boolean;
  if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d) little = false;
  else if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) little = true;
  else return { ...EMPTY_WIRE, problem: `Not a classic pcap (magic 0x${magic.toString(16)}).` };
  const linktype = view.getUint32(20, little);
  if (linktype !== 1) return { ...EMPTY_WIRE, problem: `Capture link type ${linktype} is not Ethernet.` };

  const skip = new Set([...emulatorAddresses, '0.0.0.0', '255.255.255.255']);
  const seen = new Map<string, WireAddress>();
  // Every frame the EMULATOR puts on this wire carries slirp's own MAC, whatever source address it bears. That
  // matters: slirp NATs the guest's outbound traffic, so a reply from a public NTP server arrives on this netdev
  // with a source address that is neither the guest's nor slirp's own. Attributing it to the guest would be an
  // over-claim with teeth — measured on the WDR3600, which listed 129.7.1.66, 133.100.9.2 and 192.36.144.22 as
  // "addresses the guest used", and any one of them could have sent pass two onto a subnet belonging to a stranger.
  const emulatorOwn = new Set(emulatorAddresses);
  const emulatorMacs = new Set<string>();
  const bump = (address: string, mac: string, how: WireAddress['how']): void => {
    // Only slirp's OWN addresses identify its MAC. `0.0.0.0` is skipped too, but a DHCP DISCOVER carries it and is
    // the GUEST talking — learning a MAC from that would blind the parser to the very machine it is watching.
    if (emulatorOwn.has(address)) emulatorMacs.add(mac);
    if (skip.has(address)) return;
    const first = Number(address.split('.')[0] ?? 0);
    // Multicast and above is never an interface address, and 127/8 is loopback wherever it appears.
    if (first === 0 || first >= 224 || isLoopbackAddress(address)) return;
    const key = `${address} ${how}`;
    const prev = seen.get(key);
    if (prev) prev.frames++;
    else seen.set(key, { address, mac, how, frames: 1 });
  };

  let off = 24;
  let frames = 0;
  let synsToGuest = 0;
  let synAcksFromGuest = 0;
  let resetsFromGuest = 0;
  let truncated = false;
  const limit = Math.min(pcap.length, PCAP_MAX_BYTES);
  while (off + 16 <= limit) {
    const incl = view.getUint32(off + 8, little);
    const start = off + 16;
    off = start + incl;
    if (start + incl > pcap.length) break;
    if (frames >= PCAP_MAX_FRAMES) {
      truncated = true;
      break;
    }
    frames++;
    if (incl < 14) continue;
    const etherType = (pcap[start + 12] as number) * 256 + (pcap[start + 13] as number);
    const srcMac = macAt(pcap, start + 6);
    if (etherType === 0x0806 && incl >= 42) {
      // ARP: sender protocol address at offset 28 for IPv4-over-Ethernet.
      bump(ipv4(pcap, start + 28), srcMac, 'arp-sender');
    } else if (etherType === 0x0800 && incl >= 34) {
      const ihl = ((pcap[start + 14] as number) & 0x0f) * 4;
      const proto = pcap[start + 23] as number;
      const src = ipv4(pcap, start + 26);
      bump(src, srcMac, 'ip-source');
      if (proto === 6 && incl >= 14 + ihl + 20) {
        const flags = pcap[start + 14 + ihl + 13] as number;
        const syn = (flags & 0x02) !== 0;
        const ack = (flags & 0x10) !== 0;
        const rst = (flags & 0x04) !== 0;
        const fromEmulator = emulatorAddresses.includes(src);
        if (syn && !ack && fromEmulator) synsToGuest++;
        if (syn && ack && !fromEmulator) synAcksFromGuest++;
        if (rst && !fromEmulator) resetsFromGuest++;
      }
    }
  }
  if (off + 16 <= pcap.length && pcap.length > PCAP_MAX_BYTES) truncated = true;

  // Dropped last rather than during the scan, because slirp's MAC may only become identifiable well after the first
  // frame it forwarded — the emulator's own address does not appear until something addresses it.
  const addresses = [...seen.values()]
    .filter((a) => !emulatorMacs.has(a.mac))
    .sort(
      (a, b) =>
        b.frames - a.frames ||
        (a.how === 'arp-sender' ? -1 : 1) - (b.how === 'arp-sender' ? -1 : 1) ||
        a.address.localeCompare(b.address),
    );
  return {
    addresses,
    frames,
    synsToGuest,
    synAcksFromGuest,
    resetsFromGuest,
    truncated,
    problem: '',
  };
}

/**
 * Pure: what the frames say about why nothing answered.
 *
 * The distinction this draws is the whole value of capturing at all. A SYN that gets a RST reached a live IP stack
 * with no listener; a SYN that gets NOTHING was dropped — by a firewall, a bridge filter, or a stack that never saw
 * it — and those are different findings that a silent socket cannot tell apart.
 */
export function describeWire(wire: WireObservation): string {
  if (wire.problem) return wire.problem;
  if (wire.frames === 0) return 'The guest emitted no frames at all: its network stack never reached the wire.';
  const claimed =
    wire.addresses.length > 0
      ? `The guest used ${wire.addresses.map((a) => `${a.address} (${a.how}, ${a.frames} frames, mac ${a.mac})`).join('; ')}.`
      : 'The guest emitted frames but never an IPv4 address of its own.';
  if (wire.synsToGuest === 0) return `${claimed} No connection attempt was delivered to it during this pass.`;
  if (wire.synAcksFromGuest > 0) {
    return `${claimed} ${wire.synsToGuest} SYN(s) were delivered and ${wire.synAcksFromGuest} were accepted.`;
  }
  if (wire.resetsFromGuest > 0) {
    return `${claimed} ${wire.synsToGuest} SYN(s) were delivered and the guest REFUSED them (${wire.resetsFromGuest} RST) — its IP stack is alive and nothing is listening on those ports.`;
  }
  const dropped =
    'not even a reset, which a live stack with no listener would send. The packets are being dropped inside the ' +
    'guest (a firewall, a bridge filter, or a stack that never received them), which is a different finding from ' +
    '"no service".';
  return `${claimed} ${wire.synsToGuest} SYN(s) were delivered and the guest answered NONE of them — ${dropped}`;
}

/**
 * Pure: did the kernel's own IP autoconfiguration run, and what did it say?
 *
 * The second pass may hand the kernel an `ip=` argument. Whether the kernel took it is not something to assume —
 * `CONFIG_IP_PNP` prints `IP-Config: Complete:` on success and an `IP-Config: …` diagnostic on every failure, and a
 * kernel built without it prints neither. All three are different results and only the console can tell them apart.
 */
export function readIpConfig(consoleOutput: string): { applied: boolean; line: string | null } {
  const ok = /IP-Config: Complete:[^\n]*/.exec(consoleOutput);
  if (ok) return { applied: true, line: ev(ok[0]) };
  const bad = /IP-Config: [^\n]*/.exec(consoleOutput);
  return { applied: false, line: bad ? ev(bad[0]) : null };
}

/**
 * The qemu side a guest configuration implies. Every field is something qemu is told; nothing here is a claim
 * about the firmware.
 */
export interface QemuNetworkPlan {
  /** A kernel `ip=` argument, when the guest states no address of its own and one has to be supplied. */
  kernelIp: string | null;
  /** slirp's own subnet, moved to meet the guest where the guest put itself. Null keeps qemu's 10.0.2.0/24. */
  slirpNet: string | null;
  /** slirp's host address inside that subnet. Null keeps qemu's default. */
  slirpHost: string | null;
  /** The address every `hostfwd` must be aimed at. Null keeps qemu's default guest (10.0.2.15). */
  guestAddress: string | null;
}

export interface NetworkInference {
  /**
   * `guest-address` — the firmware named an address, so move slirp to its subnet (firmadyne's move).
   * `kernel-assign` — the firmware brought an interface up and never addressed it, so the KERNEL is asked to.
   * `none`          — nothing in the console names a usable interface. A reportable outcome, not a failure.
   */
  kind: 'guest-address' | 'kernel-assign' | 'none';
  plan: QemuNetworkPlan | null;
  iface: string | null;
  reason: string;
  /** The console lines or frames this was decided from, verbatim. A `none` quotes what it DID see. */
  evidence: string[];
  /** True when no netmask was printed and a /24 was assumed. Stated because an assumption can be wrong. */
  assumedPrefix: boolean;
  /** Where the address came from. `wire` means the guest was seen using it, not seen configuring it. */
  observedOn?: 'console' | 'wire';
}

/** qemu's own user-networking defaults. Used unchanged when the kernel is the one being handed an address. */
const SLIRP_DEFAULT_GUEST = '10.0.2.15';
const SLIRP_DEFAULT_GATEWAY = '10.0.2.2';
const SLIRP_DEFAULT_NETMASK = '255.255.255.0';
/** The prefix assumed when the guest printed an address and no mask. Assumed, stated, never silent. */
const ASSUMED_PREFIX = 24;

function ipToInt(addr: string): number | null {
  const parts = addr.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (
    (((parts[0] as number) << 24) |
      ((parts[1] as number) << 16) |
      ((parts[2] as number) << 8) |
      (parts[3] as number)) >>>
    0
  );
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/**
 * Pure: the subnet an address sits in, and a host address inside it that is not the guest's.
 *
 * slirp needs both: `net=` places its network and `host=` places the address it answers on. Handing it the guest's
 * own address there would collide, so the host takes the first free host address in the subnet — `.2` where the
 * guest is the usual `.1`, which is also qemu's own default and therefore the least surprising choice.
 */
export function planSlirpSubnet(address: string, prefix: number): { net: string; host: string } | null {
  const ip = ipToInt(address);
  if (ip === null || prefix < 8 || prefix > 30) return null;
  const maskBits = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ip & maskBits) >>> 0;
  const broadcast = (network | (~maskBits >>> 0)) >>> 0;
  if (ip === network || ip === broadcast) return null;
  let host = 0;
  for (let candidate = network + 2; candidate < broadcast; candidate++) {
    if (candidate !== ip) {
      host = candidate;
      break;
    }
  }
  if (host === 0) {
    for (let candidate = network + 1; candidate < broadcast; candidate++) {
      if (candidate !== ip) {
        host = candidate;
        break;
      }
    }
  }
  if (host === 0) return null;
  return { net: `${intToIp(network)}/${prefix}`, host: intToIp(host) };
}

/**
 * Pure: what pass two should be booted with, decided from pass one's console and from nothing else.
 *
 * Two shapes of firmware, and they need opposite answers:
 *
 *  - The guest NAMES an address (`ifconfig br0 192.168.1.1`). Then the firmware is right and the emulator is in the
 *    wrong subnet: move slirp to meet it and aim every forward at that address. This is what firmadyne does with a
 *    TAP device; slirp reaches the same place without needing a privilege the container does not have.
 *  - The guest brings an interface UP and never addresses it, which is the WR940N: its LAN address arrives through
 *    an Atheros switch driver whose hardware is absent, so nothing in userspace ever calls `SIOCSIFADDR` on a real
 *    NIC. Then the address has to come from outside the firmware, and the honest place is the KERNEL's own boot-time
 *    autoconfiguration — `ip=` on the interface the console proves exists. That is a harness action and the verdict
 *    says so; it is never presented as the firmware having configured a network.
 *
 * And where the console names no usable interface at all, this returns `none` with what it did see. A guess dressed
 * as a reading is the one outcome forbidden here.
 */
export function inferGuestNetwork(net: GuestNetwork, wire?: WireObservation | null): NetworkInference {
  const bridgeNames = new Set(net.bridges.map((b) => b.name));
  const vlanNames = new Set(net.vlans.map((v) => v.name).filter((n): n is string => n !== null));

  // 1. An address the firmware itself stated.
  const addressed = net.interfaces
    .filter((i) => i.address !== null && i.name !== 'lo' && !i.name.startsWith('lo:') && isUsableUnicast(i.address))
    .sort((a, b) => {
      // A bridge is the LAN-facing device on every router in this corpus, so it outranks a raw NIC when both carry
      // an address. Beyond that, name order — deterministic rather than console order.
      const ab = bridgeNames.has(a.name) ? 0 : 1;
      const bb = bridgeNames.has(b.name) ? 0 : 1;
      return ab - bb || a.name.localeCompare(b.name);
    });
  const chosen = addressed[0];
  if (chosen?.address) {
    const assumedPrefix = chosen.prefix === null;
    const prefix = chosen.prefix ?? ASSUMED_PREFIX;
    const subnet = planSlirpSubnet(chosen.address, prefix);
    if (subnet) {
      const mask = assumedPrefix
        ? ` (no netmask was printed, so a /${ASSUMED_PREFIX} is ASSUMED — that assumption can be wrong)`
        : `/${prefix}`;
      const move = `pass two moves qemu's user network onto ${subnet.net} with the host at ${subnet.host}`;
      const closing = 'The guest keeps the network it asked for; the emulator is the side that moves.';
      return {
        kind: 'guest-address',
        iface: chosen.name,
        plan: {
          kernelIp: null,
          slirpNet: subnet.net,
          slirpHost: subnet.host,
          guestAddress: chosen.address,
        },
        reason: `The firmware addressed ${chosen.name} as ${chosen.address}${mask}, so ${move} and aims every forward at ${chosen.address}. ${closing}`,
        evidence: [chosen.evidence],
        assumedPrefix,
        observedOn: 'console',
      };
    }
  }

  // 2. An address the guest USED, even though it never said so.
  //
  // This is the WR940N and, on this corpus, the normal case: a monolithic vendor daemon addresses its bridge
  // through ioctls and the console never carries the number. The frames do. An ARP sender address is the guest
  // claiming that address to the network in its own words, which is stronger evidence than a config file and at
  // least as strong as an `ifconfig` line.
  const onWire = wire?.addresses.find((a) => isUsableUnicast(a.address) && !a.address.startsWith('169.254.'));
  if (onWire) {
    const subnet = planSlirpSubnet(onWire.address, ASSUMED_PREFIX);
    if (subnet) {
      const saw = `the guest USED ${onWire.address} on the wire (${onWire.how}, ${onWire.frames} frames, from MAC ${onWire.mac})`;
      const why =
        'a vendor daemon that addresses its bridge through ioctls leaves no trace in any execve or printk, and ' +
        'this is the only place the address exists';
      const move = `Pass two moves qemu's user network onto ${subnet.net} with the host at ${subnet.host}`;
      const assumed = `No netmask is knowable from a frame, so a /${ASSUMED_PREFIX} is ASSUMED.`;
      return {
        kind: 'guest-address',
        iface: null,
        plan: { kernelIp: null, slirpNet: subnet.net, slirpHost: subnet.host, guestAddress: onWire.address },
        reason: `The console never names an address, but ${saw} — ${why}. ${move} and aims every forward at ${onWire.address}. ${assumed}`,
        evidence: [`${onWire.how} ${onWire.address} from ${onWire.mac} (${onWire.frames} frames)`],
        assumedPrefix: true,
        observedOn: 'wire',
      };
    }
  }

  // 3. An interface the console proves exists, with no address anywhere.
  const nic = net.interfaces
    .filter(
      (i) =>
        i.name !== 'lo' &&
        !i.name.startsWith('lo:') &&
        !bridgeNames.has(i.name) &&
        !vlanNames.has(i.name) &&
        !i.name.includes('.'),
    )
    .sort((a, b) => {
      // `ip=` has to name the real NIC, and on this machine model that is the e1000 the kernel calls eth0.
      const ae = a.name.startsWith('eth') ? 0 : 1;
      const be = b.name.startsWith('eth') ? 0 : 1;
      return ae - be || a.name.localeCompare(b.name);
    })[0];
  if (nic) {
    const claimedBy = net.bridges.filter((b) => b.members.includes(nic.name)).map((b) => b.name);
    // A bridge that swallows the port could take the address out of reach again. Named here as a caveat on the
    // plan, never as a prediction: the probe decides, and on the real WR940N the address survived it.
    const bridgeWarning =
      claimedBy.length > 0
        ? `. Note that ${claimedBy.join(', ')} claims ${nic.name} as a bridge port after boot, which may take the address out of reach — the probe, not this plan, decides whether it did.`
        : '.';
    return {
      kind: 'kernel-assign',
      iface: nic.name,
      plan: {
        kernelIp: `${SLIRP_DEFAULT_GUEST}::${SLIRP_DEFAULT_GATEWAY}:${SLIRP_DEFAULT_NETMASK}::${nic.name}:off`,
        slirpNet: null,
        slirpHost: null,
        guestAddress: SLIRP_DEFAULT_GUEST,
      },
      reason: `The console shows ${nic.name} exists and came up, and no address anywhere for it — the firmware's own LAN arrives through hardware this machine model does not emulate. Pass two therefore asks the KERNEL to address ${nic.name} as ${SLIRP_DEFAULT_GUEST} at boot (ip=), which is the HARNESS supplying a network, not the firmware configuring one${bridgeWarning}`,
      evidence: [nic.evidence, ...net.bridges.filter((b) => b.members.includes(nic.name)).map((b) => b.evidence)],
      assumedPrefix: false,
      observedOn: 'console',
    };
  }

  // 4. Nothing usable. This is a result.
  const seen = net.interfaces.slice(0, 4).map((i) => i.evidence);
  const wireNote = wire ? ` On the wire: ${describeWire(wire)}` : '';
  return {
    kind: 'none',
    plan: null,
    iface: null,
    reason:
      (net.interfaces.length === 0
        ? 'The console names no network interface at all — not an `ifconfig`, not a link event, not a bridge port. Nothing can be inferred to configure, so no second pass was attempted and no reachability is claimed.'
        : `The only interfaces the console names are ${net.interfaces.map((i) => i.name).join(', ')}, none of which is a usable non-loopback NIC. Nothing can be inferred to configure, so no second pass was attempted and no reachability is claimed.`) +
      wireNote,
    evidence: seen,
    assumedPrefix: false,
  };
}

/**
 * Pure: the verdict for a full-system run, given what was actually observed.
 *
 * The ordering is the claim ladder. A port that accepted a TCP connection is the strongest evidence available
 * here — something inside the guest is serving — and it is the only observation that makes the forwarded surface
 * meaningful. A kernel that printed its way up is real but weaker: the system booted, its services may not have.
 * Everything else refuses `confirmed_full_system`, because "the process did not exit" is not a boot.
 */
export function classifyFullSystem(
  open: { host: number; guest: number }[],
  console: { booted: boolean; marker: string | null; panicked: boolean },
  timedOut: boolean,
  net?: { configured: string[]; loopbackOnly: boolean },
  /** What the two-pass run inferred and whether it was applied — wording only; it never raises the claim. */
  attempt?: {
    kind: NetworkInference['kind'];
    reason: string;
    applied: boolean;
    wire?: string;
    /**
     * An address was observed for the guest SOMEWHERE — including on the wire, where the console had none.
     *
     * This exists because the loopback-only sentence below is a diagnosis, and a diagnosis that the same paragraph
     * goes on to contradict is worse than no diagnosis at all. Measured on the WR940N: its console says `ifconfig
     * lo` and nothing more, so the old wording declared the guest had no network — while the frames from that very
     * boot show it live at 192.168.0.1. "The console named only loopback" is a fact about the log. "The guest has
     * no network" is a claim about the guest, and it was false.
     */
    guestAddressed?: boolean;
  } | null,
): { proofState: ProofState; reason: string } {
  // The strongest thing this rung can say, and it needs BOTH halves: a console that shows the system came up and a
  // socket that got bytes back. Requiring the boot is not pedantry — the port half alone is exactly what once
  // returned `confirmed_full_system` for a guest still at NR_IRQS, because a survivor from another run held the
  // port and answered for it. Fresh ports made that unlikely; needing the boot too makes it unclaimable.
  const supplied = attempt?.applied === true && attempt.kind === 'kernel-assign';
  if (open.length > 0 && console.booted) {
    const list = open.map((p) => `guest ${p.guest}`).join(', ');
    const whose = supplied
      ? ' The address it answered on was supplied by this harness at boot, not configured by the firmware — the SERVICE is the firmware’s, the network under it is ours.'
      : '';
    const ceiling = ' This proves the sandbox. It says nothing about the physical device.';
    return {
      proofState: 'confirmed_full_system',
      reason: `The system booted (${console.marker}) and answered TCP on ${list}. A service inside the guest accepted a connection and replied, which is what makes this rung a full-system result rather than a process that stayed alive.${whose}${ceiling}`,
    };
  }
  if (console.panicked) {
    return {
      proofState: 'blocked_by_platform',
      reason: `The guest kernel panicked (${console.marker}), so nothing about the firmware was exercised. This is the emulation failing to bring the image up — not a result about the firmware, and not evidence it is sound.`,
    };
  }
  if (open.length > 0) {
    const list = open.map((p) => `guest ${p.guest}`).join(', ');
    return {
      proofState: 'confirmed_in_emulation',
      reason: `Something answered TCP on ${list}, but this console never printed a recognisable boot — so what replied cannot be shown to be the firmware's system coming up. That combination is the shape of a stray emulator holding the port, and it is capped at "confirmed in emulation" until a boot marker backs it.`,
    };
  }
  if (console.booted) {
    const loopbackVerdict = net?.loopbackOnly === true && attempt?.guestAddressed !== true;
    const consoleOnlyLoopback = net?.loopbackOnly === true && attempt?.guestAddressed === true;
    const base = loopbackVerdict
      ? `The kernel booted (${console.marker}) and the firmware's own init configured ONLY loopback (${net?.configured.join(', ')}), so no forwarded port could answer however many daemons are listening. Vendor init brings its LAN up through switch hardware this machine model does not emulate — a limit of the emulated hardware, not a result about the firmware.`
      : consoleOnlyLoopback
        ? `The kernel booted (${console.marker}) and its console names only loopback (${net?.configured.join(', ')}) — but that is a fact about the LOG, not about the guest: an address was observed for it anyway, so this firmware did bring a network up and no forwarded port still accepted a connection.`
        : `The kernel booted (${console.marker}) but no forwarded port accepted a connection. The system came up; its network services did not, or they listen somewhere this run did not forward.`;
    const tail =
      attempt?.applied === true
        ? ` A second pass was run with a network inferred from this boot and still nothing answered: ${attempt.reason}`
        : attempt?.kind === 'none'
          ? ` No second pass was possible: ${attempt.reason}`
          : '';
    // The frames say more about a silence than the socket can: a refused connection and a swallowed one look the
    // same from the host and mean opposite things.
    const observed = attempt?.wire ? ` On the wire: ${attempt.wire}` : '';
    return { proofState: 'confirmed_full_system', reason: `${base}${tail}${observed}` };
  }
  return {
    proofState: 'needs_runtime_reproduction',
    reason: timedOut
      ? 'The emulator ran to the time box without printing a recognisable boot and without any forwarded port answering. That it did not exit is NOT a boot: a hung kernel looks the same from outside.'
      : 'The emulator exited without printing a recognisable boot and without any forwarded port answering.',
  };
}

/**
 * firmadyne's kernel filenames, which are NOT the architecture names this codebase uses.
 *
 * The path was built as `vmlinux.${arch}.4`, and that is right for exactly one architecture. firmadyne ships
 * `vmlinux.mipseb.4` for big-endian MIPS and `vmlinux.armel` (no `.4`) for ARM, so a TP-Link WR940N — plain
 * `mips` — was refused with "No firmadyne kernel at …/vmlinux.mips.4" while the kernel it needed sat in the same
 * directory under a different name. `mipsel` matched by coincidence, which is why this went unnoticed.
 *
 * Candidates are ordered most-specific first and every one is a real filename observed in the deployed image.
 */
export const FIRMADYNE_KERNEL_NAMES: Partial<Record<Architecture, string[]>> = {
  mipsel: ['vmlinux.mipsel.4', 'vmlinux.mipsel'],
  mips: ['vmlinux.mipseb.4', 'vmlinux.mipseb'],
  arm: ['vmlinux.armel', 'zImage.armel'],
};

/** The first firmadyne kernel that exists for an architecture, or null when this deployment ships none. */
export function firmadyneKernelFor(arch: Architecture, dir: string = FIRMADYNE_KERNELS_DIR): string | null {
  for (const name of FIRMADYNE_KERNEL_NAMES[arch] ?? []) {
    const p = `${dir}/${name}`;
    if (fs.existsSync(p)) return p;
  }
  return null;
}

/** The mandatory teardown: kill every emulator this provider could have spawned. */
export const TEARDOWN_PATTERNS = ['qemu-system-', 'qemu-mipsel-static', 'qemu-arm-static', 'qemu-aarch64-static'];

// === Runners (asset-gated; guaranteed teardown) ===

async function toolAvailable(id: string): Promise<boolean> {
  const tools = await detectTools();
  return tools.find((t) => t.id === id)?.available ?? false;
}

/** Best-effort kill of any emulator left running — the invariant that keeps a hung qemu from stalling the run. */
async function teardown(handle: JobHandle): Promise<void> {
  // `pkill` exits non-zero when nothing matched, which is the normal case — and it exits non-zero when it does
  // not EXIST, which is this deployment. Both landed in the same catch, and the log then said "emulators killed"
  // regardless. The module's first stated invariant is that teardown is guaranteed; it never was here, and the
  // message said otherwise. Strays then accumulated across runs holding their forwarded ports.
  let swept = false;
  for (const pat of TEARDOWN_PATTERNS) {
    try {
      await execFileAsync('pkill', ['-f', pat], { timeout: 5000 });
      swept = true;
    } catch (err) {
      // Exit 1 = matched nothing (fine). ENOENT = pkill is absent, and the sweep did not happen at all.
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') swept = true;
    }
  }
  handle.log(
    swept
      ? 'Teardown complete (emulators killed).'
      : 'Teardown: this run’s emulator was killed directly, but `pkill` is not installed here so no sweep for ' +
          'strays from earlier runs was possible. Each run takes a FRESH host port, so a survivor cannot be ' +
          'mistaken for this boot.',
  );
}

function blocked(strategy: SystemEmulationResult['strategy'], reason: string, command = ''): SystemEmulationResult {
  return {
    ran: false,
    strategy,
    proofState: 'blocked_by_platform',
    reason,
    command,
    stdout: '',
    stderr: '',
    timedOut: false,
  };
}

/**
 * rung-2: start a network service in a chroot with the NVRAM shim, bounded by a timeout, then always tear down.
 * Returns a blocked result if the arch has no qemu-user emulator installed or the libnvram asset is absent.
 */
export async function runChrootService(
  arch: Architecture,
  rootfsPath: string,
  service: string,
  handle: JobHandle,
): Promise<SystemEmulationResult> {
  const qemu = QEMU_USER_BY_ARCH[arch];
  if (!qemu || !(await toolAvailable(qemu))) {
    return blocked('chroot-service', `No qemu-user emulator for arch "${arch}" in this deployment.`);
  }
  if (!fs.existsSync(libnvramHostPath(arch))) {
    return blocked(
      'chroot-service',
      `libnvram shim missing (${libnvramHostPath(arch)}); enable it in Dockerfile.firmware to run rung-2.`,
    );
  }

  const qemuStaticName = `qemu-${arch}-static-firmlab`;
  const args = buildChrootServiceArgs(qemuStaticName, service);
  const command = `chroot ${args.join(' ')}`;
  handle.log(`Preparing chroot bring-up for ${service}`);
  try {
    // Stage the emulator + shim inside the rootfs so they resolve under chroot.
    fs.copyFileSync(`/usr/bin/${qemu}`, `${rootfsPath}/${qemuStaticName}`);
    fs.copyFileSync(libnvramHostPath(arch), `${rootfsPath}/libnvram.so`);
    handle.log(`Executing: ${command}`);
    const { stdout, stderr } = await execFileAsync('chroot', args, {
      cwd: rootfsPath,
      timeout: 30_000,
      maxBuffer: 4 * 1024 * 1024,
      killSignal: 'SIGKILL',
    });
    return {
      ran: true,
      strategy: 'chroot-service',
      proofState: 'confirmed_in_emulation',
      reason: 'Service started under qemu-user chroot with NVRAM shim.',
      command,
      stdout,
      stderr,
      timedOut: false,
    };
  } catch (err) {
    const e = err as { killed?: boolean; signal?: string; stdout?: string; stderr?: string };
    const timedOut = e.killed === true && e.signal === 'SIGKILL';
    // A daemon that keeps running until SIGKILL is the expected success shape for a long-lived service.
    return {
      ran: true,
      strategy: 'chroot-service',
      proofState: timedOut ? 'confirmed_in_emulation' : 'needs_runtime_reproduction',
      reason: timedOut ? 'Service ran until the timeout (long-lived daemon).' : 'Service exited early.',
      command,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
      timedOut,
    };
  } finally {
    await teardown(handle);
    try {
      fs.rmSync(`${rootfsPath}/${qemuStaticName}`, { force: true });
      fs.rmSync(`${rootfsPath}/libnvram.so`, { force: true });
    } catch {
      // Best-effort cleanup of the staged files.
    }
  }
}

/** Everything one boot produced. The orchestrator picks which of two of these the verdict is read from. */
interface BootOutcome {
  label: string;
  command: string;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  forwards: { host: number; guest: number; protocol: PortProtocol }[];
  open: { host: number; guest: number }[];
  consoleState: { booted: boolean; marker: string | null; panicked: boolean };
  network: GuestNetwork;
  wire: WireObservation | null;
  /** The same capture, read for the opposite question: what the firmware tried to REACH. */
  egress: EgressObservation | null;
}

/**
 * One boot, watched while it runs, killed when it is done with — whatever happened.
 *
 * Split out of `runFullSystem` so the second pass is the same code as the first rather than a variant of it, and so
 * each pass's qemu is guaranteed dead before the next one starts. `proc.kill` is not enough on its own: the kill is
 * asynchronous, and a pass-two boot racing a still-dying pass-one qemu is how this rung ends up measuring the wrong
 * process. So the finally waits for the exit it asked for, bounded.
 */
async function bootOnce(
  qemu: string,
  args: string[],
  forwards: { host: number; guest: number; protocol: PortProtocol }[],
  label: string,
  handle: JobHandle,
  /** The capture this boot was told to write, and the addresses slirp owns in it. Null = no capture was asked for. */
  capture: { file: string; emulatorAddresses: string[]; guestAddress: string | null } | null,
): Promise<BootOutcome> {
  const command = `${qemu} ${args.join(' ')}`;
  handle.log(`Executing (${label}): ${command}`);

  // Spawned rather than exec'd to completion: the previous version could only look at the run AFTER it ended,
  // which is why "did not exit" became the boot verdict. Watching it while it runs is what makes a TCP probe —
  // and therefore an evidenced answer — possible at all.
  const proc = spawn(qemu, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  // Keep the HEAD as well as the tail. Capping with `slice(-CAP)` evicted the earliest output first — which is
  // exactly where a kernel prints the markers the boot verdict is read from. The real WR940N boot proved it: the
  // firmware came all the way up (its own init printing `OPEN ALL PHY ETH!!`, its HTTPS daemon loading a
  // certificate) and was graded "no recognisable boot", because 262 KB of vendor chatter had pushed
  // `Freeing unused kernel memory` out of the window.
  const cap = (chunk: Buffer, which: 'o' | 'e'): void => {
    const s = chunk.toString('utf8');
    if (which === 'o') stdout = keepEnds(stdout + s);
    else stderr = keepEnds(stderr + s);
  };
  proc.stdout?.on('data', (c: Buffer) => cap(c, 'o'));
  proc.stderr?.on('data', (c: Buffer) => cap(c, 'e'));
  proc.on('error', () => undefined);

  let exited = false;
  proc.on('exit', () => {
    exited = true;
  });

  const open: { host: number; guest: number }[] = [];
  const deadline = Date.now() + BOOT_TIMEOUT_MS;
  try {
    while (Date.now() < deadline && !exited) {
      await new Promise((r) => setTimeout(r, PROBE_INTERVAL_MS));
      for (const f of forwards) {
        if (open.some((o) => o.host === f.host)) continue;
        if (await guestAnswers(f.host, f.protocol)) {
          open.push({ host: f.host, guest: f.guest });
          handle.log(
            `  [${label}] guest port ${f.guest} ANSWERED on host ${f.host} — a service inside the guest replied, not just qemu accepting.`,
          );
        }
      }
      // Every declared port answering is as much as this rung can establish; no reason to hold the box open.
      if (open.length === forwards.length) break;
    }
  } finally {
    if (!exited) {
      try {
        proc.kill('SIGKILL');
      } catch {}
      await new Promise<void>((resolve) => {
        if (exited) return resolve();
        const t = setTimeout(resolve, 5000);
        proc.once('exit', () => {
          clearTimeout(t);
          resolve();
        });
      });
    }
  }
  // Everything below runs with qemu already dead, which is deliberate: the capture is read after the writer has
  // stopped, so what is parsed is the whole of it rather than however much happened to be flushed.
  const timedOut = !exited;
  const consoleOutput = `${stdout}\n${stderr}`;
  return {
    label,
    command,
    stdout,
    stderr,
    timedOut,
    forwards,
    open,
    consoleState: looksBooted(consoleOutput),
    network: guestNetwork(consoleOutput),
    // A capture that could not be read is a null, never an invented empty observation.
    wire: capture ? readCapture(capture.file, capture.emulatorAddresses, handle) : null,
    egress: capture ? readEgress(capture.file, capture.emulatorAddresses, capture.guestAddress) : null,
  };
}

/**
 * The same file, read for destinations. Silent on failure by design: `readCapture` above already logs whatever is
 * wrong with this exact file, and saying it twice per pass would bury the boot log the verdict is read from.
 */
function readEgress(file: string, emulatorAddresses: string[], guestAddress: string | null): EgressObservation | null {
  try {
    if (!fs.existsSync(file)) return null;
    const size = fs.statSync(file).size;
    const fd = fs.openSync(file, 'r');
    try {
      const want = Math.min(size, PCAP_MAX_BYTES);
      const buf = Buffer.alloc(want);
      fs.readSync(fd, buf, 0, want, 0);
      const out = parseEgress(buf, { emulatorAddresses, guestAddress });
      return size > PCAP_MAX_BYTES ? { ...out, truncated: true } : out;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

/** Read a capture qemu wrote, bounded, and never throwing — an unreadable file is reported, not fatal. */
function readCapture(file: string, emulatorAddresses: string[], handle: JobHandle): WireObservation | null {
  try {
    if (!fs.existsSync(file)) {
      handle.log('No frame capture was written by this pass; the inference falls back to the console alone.');
      return null;
    }
    const size = fs.statSync(file).size;
    const fd = fs.openSync(file, 'r');
    try {
      const want = Math.min(size, PCAP_MAX_BYTES);
      const buf = Buffer.alloc(want);
      fs.readSync(fd, buf, 0, want, 0);
      const wire = parseGuestWire(buf, emulatorAddresses);
      return size > PCAP_MAX_BYTES ? { ...wire, truncated: true } : wire;
    } finally {
      fs.closeSync(fd);
    }
  } catch (err) {
    handle.log(`The frame capture could not be read (${(err as Error).message}); inference falls back to the console.`);
    return null;
  }
}

/**
 * Does this qemu have the `filter-dump` object at all?
 *
 * Asked rather than assumed, because passing an object a build does not have makes qemu refuse to start — which
 * would take a rung that works today and break it everywhere, to add an observation. `-object help` lists them.
 */
async function supportsFrameCapture(qemu: string): Promise<boolean> {
  try {
    const { stdout, stderr } = await execFileAsync(qemu, ['-object', 'help'], { timeout: 10_000 });
    return /filter-dump/.test(`${stdout}${stderr}`);
  } catch {
    return false;
  }
}

/** Pure: how much a pass established, so the verdict is read from the better of the two rather than the later. */
export function passScore(o: { open: { host: number }[]; booted: boolean; panicked: boolean }): number {
  if (o.open.length > 0 && o.booted) return 4;
  if (o.open.length > 0) return 3;
  if (o.booted) return 2;
  return o.panicked ? 0 : 1;
}

/**
 * rung-3: boot the rootfs image under qemu-system + a firmadyne kernel — twice — bounded by a timeout, always
 * tearing down. Returns blocked if the system emulator or the kernel assets are absent.
 *
 * Pass one is the boot that already existed and is left exactly as it was: qemu's own defaults, nothing this file
 * believes injected into it, so what the console shows is what the firmware does. Pass two runs only when pass one
 * booted, nothing answered, and the console named something to work with — and it is skipped entirely, honestly,
 * when it did not.
 */
export async function runFullSystem(
  arch: Architecture,
  rootfsImage: string,
  hostPort: number,
  handle: JobHandle,
  /**
   * The extracted rootfs DIRECTORY, read for the ports the firmware declares. Optional so an existing caller that
   * only has the disk image still works — it then falls back to forwarding port 80 alone, which is exactly the old
   * behaviour, stated rather than assumed.
   */
  rootfsDir?: string | null,
): Promise<SystemEmulationResult> {
  const qemu = QEMU_SYSTEM_BY_ARCH[arch];
  const machine = QEMU_MACHINE_BY_ARCH[arch];
  if (!qemu || !machine || !(await toolAvailable(qemu))) {
    return blocked('full-system', `No qemu-system emulator/machine for arch "${arch}" in this deployment.`);
  }
  if (!fs.existsSync(FIRMADYNE_KERNELS_DIR)) {
    return blocked(
      'full-system',
      `firmadyne kernels missing (${FIRMADYNE_KERNELS_DIR}); enable them in Dockerfile.firmware to run rung-3.`,
    );
  }
  const kernelPath = firmadyneKernelFor(arch);
  if (!kernelPath) {
    return blocked(
      'full-system',
      `No firmadyne kernel for arch "${arch}" in ${FIRMADYNE_KERNELS_DIR} (tried ${FIRMADYNE_KERNEL_NAMES[arch]?.join(', ') ?? 'nothing — this architecture has no mapping'}).`,
    );
  }

  // What the firmware itself says it will serve. Read before boot, so the forwards match the image rather than
  // an assumption about it.
  const portMap = readPortMap(rootfsDir ?? null);
  handle.log(portMap.reason);

  // The egress policy for THIS run, resolved once and logged, because it is the fact that tells a reader whether
  // an address below was merely addressed or actually reached. Read through `effectiveEnv` so the Settings toggle
  // reaches it without a restart, exactly as the other lanes do.
  const isolate = effectiveEnv()[EMU_ISOLATE_FLAG] === '1';
  handle.log(
    isolate
      ? `${EMU_ISOLATE_FLAG}=1: the guest is cut off with restrict=on. Host→guest forwards still work, and what the firmware tries to reach is still recorded.`
      : `${EMU_ISOLATE_FLAG} is off: this guest can reach the internet from this host. Everything it addresses is recorded either way; turn the flag on in Settings to keep the observation and drop the reachability.`,
  );

  // A FRESH host port per forward, asked of the OS EVERY pass, rather than a fixed 8080. This is not tidiness:
  // `pkill` is absent in this deployment so the stray sweep never ran, an earlier run's qemu could still hold 8080,
  // and the probe below would then connect to IT and report `confirmed_full_system` for a boot that never happened.
  // It did, once, with the guest kernel still at NR_IRQS. Two passes make it twice as easy to get wrong, so each
  // pass asks again and never reuses the previous pass's ports.
  // The frame capture lives in a temp directory of this run's own, never under the data root: it is scratch for
  // one inference, not evidence to keep, and the finally removes it on every path.
  const canCapture = await supportsFrameCapture(qemu);
  const captureDir = canCapture ? fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-emunet-')) : null;
  if (!canCapture) {
    handle.log(
      `${qemu} has no filter-dump object, so this run reads the guest's network from the console alone. A firmware that addresses its interfaces through ioctls will then be reported as having no address, because that is all this deployment can see.`,
    );
  }

  const planPass = async (
    plan: QemuNetworkPlan | null,
    pass: number,
  ): Promise<{
    args: string[];
    forwards: BootOutcome['forwards'];
    capture: { file: string; emulatorAddresses: string[]; guestAddress: string | null } | null;
  }> => {
    const basePort = await allocateHostPort(hostPort);
    const forwards = planForwards(portMap, basePort);
    handle.log(`Forwarding ${forwards.map((f) => `host ${f.host} → guest ${f.guest}/${f.protocol}`).join(', ')}.`);
    const capture = captureDir
      ? {
          file: path.join(captureDir, `pass${pass}.pcap`),
          emulatorAddresses: emulatorAddressesFor(plan),
          guestAddress: plan?.guestAddress ?? null,
        }
      : null;
    return {
      args: buildFullSystemArgs(machine, kernelPath, rootfsImage, forwards, plan, capture?.file ?? null, isolate),
      forwards,
      capture,
    };
  };

  const passes: SystemEmulationPass[] = [];
  const record = (n: number, o: BootOutcome): void => {
    passes.push({
      pass: n,
      label: o.label,
      command: o.command,
      booted: o.consoleState.booted,
      marker: o.consoleState.marker,
      panicked: o.consoleState.panicked,
      timedOut: o.timedOut,
      forwards: o.forwards,
      open: o.open,
      network: o.network,
      ...(o.wire ? { wire: o.wire } : {}),
      ...(o.egress ? { egress: o.egress } : {}),
    });
  };

  try {
    const first = await planPass(null, 1);
    const pass1 = await bootOnce(qemu, first.args, first.forwards, 'pass 1 — observe', handle, first.capture);
    record(1, pass1);
    describeObservation(pass1.network, handle);
    if (pass1.wire) handle.log(`On the wire (pass 1): ${describeWire(pass1.wire)}`);

    const inference = inferGuestNetwork(pass1.network, pass1.wire);
    handle.log(`Network inference: ${inference.reason}`);
    for (const e of inference.evidence) handle.log(`  evidence: ${e}`);

    // Pass two costs another full boot timeout, so it is only worth spending where it can change the answer. A
    // guest that already answered has nothing to gain; a panicked one will panic again; and `kernel-assign` needs a
    // boot behind it, because `eth0` appearing in the kernel's link messages happens on EVERY run that reaches
    // driver init — including ones that never reach userspace, where a second pass would only double the wait.
    const worthRetrying =
      pass1.open.length === 0 &&
      !pass1.consoleState.panicked &&
      inference.plan !== null &&
      (pass1.consoleState.booted || inference.kind === 'guest-address');

    let verdictPass = pass1;
    let applied = false;
    let ipConfig: { applied: boolean; line: string | null } | null = null;
    if (worthRetrying && inference.plan) {
      handle.log('Pass one reached userspace and nothing answered. Booting again with the inferred network applied.');
      const second = await planPass(inference.plan, 2);
      const pass2 = await bootOnce(qemu, second.args, second.forwards, 'pass 2 — reach', handle, second.capture);
      record(2, pass2);
      applied = true;
      if (pass2.wire) handle.log(`On the wire (pass 2): ${describeWire(pass2.wire)}`);
      if (inference.plan.kernelIp) {
        ipConfig = readIpConfig(`${pass2.stdout}\n${pass2.stderr}`);
        handle.log(
          ipConfig.applied
            ? `The kernel took the address: ${ipConfig.line}`
            : `The kernel did NOT report a completed IP configuration${ipConfig.line ? ` (${ipConfig.line})` : ' and printed no IP-Config line at all'}. Anything that answered did so for some other reason, and anything that did not may simply never have had an address.`,
        );
      }
      // The later pass is not automatically the better one. A second boot that panics, or that loses the boot
      // marker the first one printed, must not overwrite a result the first pass actually established.
      const s1 = passScore({ open: pass1.open, ...pass1.consoleState });
      const s2 = passScore({ open: pass2.open, ...pass2.consoleState });
      verdictPass = s2 >= s1 ? pass2 : pass1;
      if (verdictPass === pass1) {
        handle.log('Pass two established less than pass one, so the verdict is read from pass one. Both are recorded.');
      }
    }

    const { proofState, reason } = classifyFullSystem(
      verdictPass.open,
      verdictPass.consoleState,
      verdictPass.timedOut,
      pass1.network,
      {
        kind: inference.kind,
        reason: inference.reason,
        applied,
        guestAddressed: inference.kind === 'guest-address',
        ...(verdictPass.wire ? { wire: describeWire(verdictPass.wire) } : {}),
      },
    );
    handle.log(reason);
    if (verdictPass.open.length === 0 && portMap.declared.length > 0) {
      handle.log(
        `Declared but silent: ${portMap.declared.map((h) => `${h.port}/${h.protocol}`).join(', ')}. A port the firmware declares and no booted service answers is a gap worth reading, not a parse error.`,
      );
    }
    // An empty `open` covers at least five situations that want different work, and until this it rendered as one.
    // Read from the VERDICT pass, because that is the boot the result speaks for.
    const unreachable = diagnoseUnreachable({
      consoleOutput: `${verdictPass.stdout}\n${verdictPass.stderr}`,
      forwards: verdictPass.forwards.length,
      open: verdictPass.open.length,
      wire: verdictPass.wire,
    });
    if (unreachable.cause !== 'answered') {
      handle.log(`Why nothing answered: ${unreachable.summary}`);
      for (const e of unreachable.evidence) handle.log(`  evidence: ${e}`);
    }

    // Read from the recorded passes rather than from the two locals, so a run that took only pass one and a run
    // that took both go through the same merge.
    const egress = passes.reduce<EgressObservation | null>((acc, p) => mergeEgress(acc, p.egress ?? null), null);
    if (egress) {
      handle.log(describeEgress(egress, isolate));
      for (const q of egress.dnsQueries.slice(0, 12)) {
        handle.log(`  resolves: ${q.name} (asked of ${q.server}, ${q.frames} time(s))`);
      }
      for (const a of egress.attempts.filter((x) => x.scope === 'external').slice(0, 12)) {
        handle.log(`  addresses: ${a.address}${a.port ? `:${a.port}` : ''}/${a.protocol} — ${a.frames} frame(s)`);
      }
    }
    return {
      ran: true,
      strategy: 'full-system',
      proofState,
      reason,
      command: verdictPass.command,
      stdout: verdictPass.stdout,
      stderr: verdictPass.stderr,
      timedOut: verdictPass.timedOut,
      forwards: verdictPass.forwards,
      open: verdictPass.open,
      network: pass1.network,
      ...(pass1.wire ? { wire: pass1.wire } : {}),
      // Merged across both passes: the same firmware booted twice, and a name it resolved only on the pass that
      // had a working network is still a name this firmware asks for.
      ...(egress ? { egress } : {}),
      isolated: isolate,
      ...(unreachable.cause === 'answered' ? {} : { unreachable }),
      inference: {
        kind: inference.kind,
        reason: inference.reason,
        evidence: inference.evidence,
        applied,
        plan: inference.plan,
        ipConfig,
      },
      passes,
    };
  } finally {
    // Each boot already killed its own qemu and waited for it. This is the sweep for strays from OTHER runs, and it
    // says plainly when it could not happen at all.
    await teardown(handle);
    if (captureDir) {
      try {
        fs.rmSync(captureDir, { recursive: true, force: true });
      } catch (err) {
        handle.log(`The temporary frame capture at ${captureDir} could not be removed: ${(err as Error).message}`);
      }
    }
  }
}

/** Log what pass one read, so the inference that follows can be checked against it rather than taken on trust. */
function describeObservation(net: GuestNetwork, handle: JobHandle): void {
  if (net.interfaces.length === 0) {
    handle.log('The console names no network interface at all — no ifconfig, no link event, no bridge port.');
    return;
  }
  handle.log(
    `Guest network as the console shows it: ${net.interfaces
      .map((i) => `${i.name}${i.address ? `=${i.address}${i.prefix !== null ? `/${i.prefix}` : ''}` : ` (${i.how})`}`)
      .join(', ')}.`,
  );
  for (const b of net.bridges) handle.log(`  bridge ${b.name} ← ${b.members.join(', ') || '(no member named)'}`);
  for (const v of net.vlans) handle.log(`  vlan ${v.id} on ${v.parent}${v.name ? ` as ${v.name}` : ''}`);
  if (net.gateways.length > 0) handle.log(`  default gateway(s) requested: ${net.gateways.join(', ')}`);
  if (net.dhcpClients.length > 0) handle.log(`  DHCP client pointed at: ${net.dhcpClients.join(', ')}`);
  if (net.boundNote) handle.log(`  ${net.boundNote}`);
}

/**
 * Keep both ends of a long console: the head carries the boot markers, the tail carries what it is doing now.
 * The elision is stated in the text rather than silently swallowing the middle.
 */
export function keepEnds(text: string, cap = CONSOLE_CAP): string {
  if (text.length <= cap) return text;
  const half = Math.floor(cap / 2);
  const dropped = text.length - cap;
  return `${text.slice(0, half)}\n… [FirmLab: ${dropped} bytes of console elided here] …\n${text.slice(-half)}`;
}

/** Ask the OS for a free host port to base the forwards on, so no two runs can share one. */
async function allocateHostPort(preferred: number): Promise<number> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.on('error', () => resolve(preferred));
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : preferred;
      srv.close(() => resolve(port));
    });
  });
}

/**
 * Does a service inside the GUEST answer on this forwarded port?
 *
 * Accepting the connection is necessary and not sufficient. qemu's user networking completes the host-side
 * handshake before it knows whether anything in the guest will take it, so "connected" alone can mean the
 * emulator is listening rather than the firmware is serving — and that is the difference between the strongest
 * claim on this ladder and no claim at all. So the probe SENDS a byte and requires the guest to send something
 * back, or at least to hold the connection open past the point where a refused forward would have reset it.
 */
async function guestAnswers(port: number, protocol: PortProtocol, timeoutMs = 3000): Promise<boolean> {
  if (protocol === 'https') return tlsAnswers(port, timeoutMs);
  const plan = probePlanFor(protocol);
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    const done = (ok: boolean): void => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => {
      // Only speak first where speaking first is correct. SSH and telnet greet the client — an HTTP request sent
      // into an SSH server is noise that can get the connection dropped before its banner arrives.
      if (plan.send) sock.write(plan.send);
    });
    sock.once('data', () => done(true));
    sock.once('timeout', () => done(false));
    sock.once('error', () => done(false));
    // Silence is not an answer. A forward with nothing behind it can also close cleanly, so only data coming
    // back counts — the 'data' handler above is the sole path to `true`.
    sock.once('close', () => done(false));
    sock.connect(port, '127.0.0.1');
  });
}

/**
 * Does a TLS server answer on this forwarded port?
 *
 * The plain-text probe could never see one. It sent `HEAD / HTTP/1.0` at a TLS socket, which replies with an
 * alert or nothing at all, so a firmware whose only service is HTTPS read as "the system came up, its services
 * did not" — measured on the real WR940N, whose own console shows its HTTPS daemon loading a certificate and a
 * private key while 443 was reported silent.
 *
 * `rejectUnauthorized: false` is mandatory rather than lax: firmware ships self-signed certificates by
 * construction, and this probe asks whether something is SERVING, not whether it is trustworthy. A TLS-level
 * failure still answers that question — an alert means a TLS implementation is on the other end — so it counts,
 * while a connection-level failure does not.
 */
async function tlsAnswers(port: number, timeoutMs = 3000): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok: boolean): void => {
      if (settled) return;
      settled = true;
      try {
        sock.destroy();
      } catch {}
      resolve(ok);
    };
    const sock = tls.connect(
      { port, host: '127.0.0.1', rejectUnauthorized: false, servername: 'localhost', timeout: timeoutMs },
      () => done(true),
    );
    sock.once('timeout', () => done(false));
    sock.once('error', (err) => done(isTlsSpeaker(err as { code?: string; message?: string })));
  });
}

/**
 * Pure: does this connection error still prove a TLS implementation answered?
 *
 * A refused or reset connection means nothing was there. A protocol-level failure — an alert, an unsupported
 * version, a malformed record — means something spoke TLS badly, and something speaking badly is still something
 * serving. Firmware TLS stacks are old and frequently fail modern handshakes; treating that as "no service" would
 * discard the result on precisely the images most worth looking at.
 */
export function isTlsSpeaker(err: { code?: string | undefined; message?: string | undefined }): boolean {
  const connectionLevel = new Set(['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'EPIPE']);
  if (err.code && connectionLevel.has(err.code)) return false;
  // Node surfaces TLS failures with codes like ERR_SSL_*, ERR_TLS_*, or an OpenSSL library string.
  return /^ERR_(SSL|TLS)_/.test(err.code ?? '') || /ssl|tls|handshake|alert|wrong version/i.test(err.message ?? '');
}

/**
 * Pure: whether to speak first on this port, and what to say.
 *
 * SSH and telnet greet the client, so the right move is to listen; HTTP will wait forever for a request. Getting
 * this backwards is not harmless — an HTTP request written into an SSH server is protocol noise that can have the
 * connection dropped before the banner arrives, turning a live service into a silent one.
 */
export function probePlanFor(protocol: PortProtocol): { send: string | null } {
  switch (protocol) {
    case 'ssh':
    case 'telnet':
      return { send: null };
    default:
      return { send: 'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n' };
  }
}
