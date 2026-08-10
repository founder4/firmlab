import { describe, expect, it } from 'vitest';
import {
  FIRMADYNE_KERNEL_NAMES,
  type SystemEmulationResult,
  TEARDOWN_PATTERNS,
  buildChrootServiceArgs,
  buildConsolePassArgs,
  buildFullSystemArgs,
  buildSystemEmulationFindings,
  classifyFullSystem,
  describeWire,
  emulatorAddressesFor,
  guestNetwork,
  inferGuestNetwork,
  isLoopbackAddress,
  isTlsSpeaker,
  libnvramHostPath,
  looksBooted,
  parseGuestWire,
  passScore,
  planSlirpSubnet,
  prefixFromNetmask,
  probePlanFor,
  readIpConfig,
} from './emulate-system.js';
import type { ConsoleOutcome } from './guest-console.js';

describe('buildChrootServiceArgs', () => {
  it('chroots into the rootfs and preloads the NVRAM shim before the service', () => {
    const args = buildChrootServiceArgs('qemu-mipsel-static-firmlab', 'usr/sbin/httpd');
    expect(args).toEqual(['.', '/qemu-mipsel-static-firmlab', '-E', 'LD_PRELOAD=/libnvram.so', '/usr/sbin/httpd']);
  });

  it('normalizes a leading slash on the service path', () => {
    const args = buildChrootServiceArgs('q', '/bin/goahead');
    expect(args[args.length - 1]).toBe('/bin/goahead');
  });
});

describe('buildFullSystemArgs', () => {
  it('boots the rootfs image with the kernel and forwards the web port', () => {
    const args = buildFullSystemArgs('malta', '/opt/firmae/kernels/vmlinux.mipsel.4', '/data/rootfs.img', [
      { host: 8080, guest: 80 },
    ]);
    expect(args).toContain('-kernel');
    expect(args).toContain('/opt/firmae/kernels/vmlinux.mipsel.4');
    expect(args.join(' ')).toContain('hostfwd=tcp::8080-:80');
    expect(args.join(' ')).toContain('file=/data/rootfs.img,format=raw');
  });

  it('forwards EVERY declared port, which one hostfwd could never do', () => {
    // The real GL.iNet surface: 22 from /etc/config/dropbear and 443 from /etc/config/uhttpd were unreachable
    // for as long as the guest side of the forward was hardcoded to 80.
    const args = buildFullSystemArgs('malta', '/k', '/r.img', [
      { host: 8080, guest: 22 },
      { host: 8081, guest: 80 },
      { host: 8082, guest: 443 },
    ]).join(' ');
    expect(args).toContain('hostfwd=tcp::8080-:22');
    expect(args).toContain('hostfwd=tcp::8081-:80');
    expect(args).toContain('hostfwd=tcp::8082-:443');
  });

  it('still produces a valid netdev when there is nothing to forward', () => {
    expect(buildFullSystemArgs('malta', '/k', '/r.img', []).join(' ')).toContain('user,id=n0 ');
  });

  /**
   * `FIRMLAB_EMU_ISOLATE`. The default is PERMISSIVE, deliberately and for now: this rung has always given the
   * guest an open netdev, and flipping that silently would change boot behaviour on every image already measured.
   * The flag exists so the choice is the operator's, and the guard that makes the default defensible is that the
   * attempt is captured either way (see `egress.ts` and its real-capture tests).
   */
  it('leaves the guest reachable by default, and says so by omission', () => {
    expect(buildFullSystemArgs('malta', '/k', '/r.img', [{ host: 8080, guest: 80 }]).join(' ')).not.toContain(
      'restrict',
    );
  });

  it('cuts the guest off when asked, WITHOUT dropping the forwards the verdict is read through', () => {
    // qemu's own contract: `restrict` "does not affect any explicitly set forwarding rules". If it did, turning
    // isolation on would silently disable the rung's only way of establishing that a service answered — an
    // honesty fix that quietly destroys the measurement it was protecting.
    const args = buildFullSystemArgs('malta', '/k', '/r.img', [{ host: 8080, guest: 80 }], null, null, true).join(' ');
    expect(args).toContain('restrict=on');
    expect(args).toContain('hostfwd=tcp::8080-:80');
  });

  it('keeps restrict inside the netdev when slirp has been moved onto the firmware’s subnet', () => {
    const args = buildFullSystemArgs(
      'malta',
      '/k',
      '/r.img',
      [{ host: 8080, guest: 80 }],
      { guestAddress: '192.168.0.1', slirpNet: '192.168.0.0/24', slirpHost: '192.168.0.2', kernelIp: null },
      null,
      true,
    ).join(' ');
    expect(args).toMatch(/-netdev user,id=n0,restrict=on,net=192\.168\.0\.0\/24,host=192\.168\.0\.2,hostfwd=/);
  });

  it('captures enough of a frame to read a DNS question’s name', () => {
    // 128 left 74 bytes after Ethernet+IP+UDP+the DNS header, which cuts real vendor hostnames in half — and
    // `parseDnsQName` discards a truncated name rather than print a different host.
    expect(buildFullSystemArgs('malta', '/k', '/r.img', [], null, '/tmp/p.pcap').join(' ')).toContain('maxlen=256');
  });

  it('boots headless with a readable serial console, which qemu needs to start at all', () => {
    // Measured in-container: without these qemu instantiates its default VGA and dies with
    // `failed to find romfile "vgabios-cirrus.bin"` before executing one guest instruction. The serial is also
    // the only stream the boot verdict can be read from.
    const args = buildFullSystemArgs('malta', '/k', '/r.img', [{ host: 8080, guest: 80 }]).join(' ');
    expect(args).toContain('-nodefaults');
    expect(args).toContain('-serial mon:stdio');
    expect(args).toContain('console=ttyS0');
    // And the NIC's PXE option ROM is disabled: qemu otherwise demands `efi-e1000.rom`, which the Debian
    // packages do not ship. The guest boots from -kernel, so a network boot ROM has no job here.
    expect(args).toContain('e1000,netdev=n0,romfile=');
  });
});

describe('looksBooted — a boot is read from the console, never from survival', () => {
  it('reads the markers a Linux kernel prints on the way up', () => {
    expect(looksBooted('…\nFreeing unused kernel memory: 128K\n').booted).toBe(true);
    expect(looksBooted('Please press Enter to activate this console.').marker).toContain('press Enter');
  });

  it('treats a panic as evidence AGAINST, not as an absence of evidence', () => {
    const r = looksBooted('VFS: Unable to mount root fs on unknown-block(0,0)\nKernel panic - not syncing: x');
    expect(r.panicked).toBe(true);
    expect(r.booted).toBe(false);
  });

  it('says nothing when the console shows nothing', () => {
    expect(looksBooted('')).toEqual({ booted: false, marker: null, panicked: false });
  });
});

describe('classifyFullSystem — what may be claimed, in order of strength', () => {
  const quiet = { booted: false, marker: null, panicked: false };
  const booted = { booted: true, marker: 'Freeing unused kernel memory', panicked: false };

  it('an answered TCP port ON TOP OF a printed boot is the strongest result this rung can produce', () => {
    const r = classifyFullSystem([{ host: 8081, guest: 80 }], booted, true);
    expect(r.proofState).toBe('confirmed_full_system');
    expect(r.reason).toContain('answered TCP');
    // And it still refuses the device: the rung proves the sandbox.
    expect(r.reason).toContain('nothing about the physical device');
  });

  it('REFUSES to call a timeout a boot — the defect this replaces', () => {
    // Previously: qemu still alive after 120s → confirmed_full_system, "booted and stayed up". A hung kernel
    // produces exactly that observation.
    const r = classifyFullSystem([], quiet, true);
    expect(r.proofState).toBe('needs_runtime_reproduction');
    expect(r.reason).toContain('is NOT a boot');
  });

  it('grades a guest kernel panic as blocked, not as a negative about the firmware', () => {
    const r = classifyFullSystem([], { booted: false, marker: 'Kernel panic - not syncing', panicked: true }, true);
    expect(r.proofState).toBe('blocked_by_platform');
    expect(r.reason).toContain('not evidence it is sound');
  });

  it('separates "the system came up" from "its services came up"', () => {
    const r = classifyFullSystem([], { booted: true, marker: 'Freeing unused kernel memory', panicked: false }, true);
    expect(r.proofState).toBe('confirmed_full_system');
    expect(r.reason).toContain('its network services did not');
  });
});

describe('libnvramHostPath', () => {
  it('names the shim per arch under the libnvram dir', () => {
    expect(libnvramHostPath('mipsel')).toBe('/opt/libnvram/libnvram-mipsel.so');
    expect(libnvramHostPath('arm64')).toBe('/opt/libnvram/libnvram-arm64.so');
  });
});

describe('TEARDOWN_PATTERNS', () => {
  it('covers every emulator the system rungs can spawn', () => {
    expect(TEARDOWN_PATTERNS).toContain('qemu-system-');
    expect(TEARDOWN_PATTERNS).toContain('qemu-mipsel-static');
  });
});

describe('FIRMADYNE_KERNEL_NAMES — firmadyne does not name kernels the way we name architectures', () => {
  it('maps big-endian MIPS to mipseb, which `vmlinux.${arch}.4` never found', () => {
    // A TP-Link WR940N is plain `mips` and was refused with "No firmadyne kernel at …/vmlinux.mips.4" while
    // vmlinux.mipseb.4 sat in the same directory. `mipsel` matched by coincidence, hiding this.
    expect(FIRMADYNE_KERNEL_NAMES.mips?.[0]).toBe('vmlinux.mipseb.4');
    expect(FIRMADYNE_KERNEL_NAMES.mipsel?.[0]).toBe('vmlinux.mipsel.4');
  });

  it('knows ARM kernels carry no .4 suffix at all', () => {
    expect(FIRMADYNE_KERNEL_NAMES.arm).toEqual(['vmlinux.armel', 'zImage.armel']);
  });

  it('has no mapping for an architecture firmadyne ships nothing for, rather than a guessed filename', () => {
    expect(FIRMADYNE_KERNEL_NAMES.arm64).toBeUndefined();
  });
});

describe('classifyFullSystem — an answered port is the claim, an accepted one is not', () => {
  it('will NOT call an answered port a full-system result when no boot was ever printed', () => {
    // The distinction cost a false `confirmed_full_system`: qemu's user networking completes the host-side
    // handshake before it knows whether the guest will take it, and a stray emulator from an earlier run —
    // never swept, because `pkill` is not installed here — held the fixed port and answered the probe while the
    // guest kernel was still at NR_IRQS. Fresh ports made that unlikely; needing a boot marker too makes the
    // claim unreachable from that observation, which is the point.
    const r = classifyFullSystem([{ host: 41234, guest: 80 }], { booted: false, marker: null, panicked: false }, true);
    expect(r.proofState).toBe('confirmed_in_emulation');
    expect(r.reason).toContain('stray emulator');
  });

  it('a panic outranks a bare answer — a panicked guest is not serving anything', () => {
    const r = classifyFullSystem(
      [{ host: 41234, guest: 80 }],
      { booted: false, marker: 'Kernel panic - not syncing', panicked: true },
      true,
    );
    expect(r.proofState).toBe('blocked_by_platform');
  });

  it('says the network was OURS when the harness supplied the address the service answered on', () => {
    const r = classifyFullSystem(
      [{ host: 41234, guest: 80 }],
      { booted: true, marker: 'BusyBox v1.01', panicked: false },
      true,
      undefined,
      {
        kind: 'kernel-assign',
        reason: 'x',
        applied: true,
      },
    );
    expect(r.proofState).toBe('confirmed_full_system');
    expect(r.reason).toContain('supplied by this harness');
  });
});

describe('probePlanFor — speak first only where speaking first is correct', () => {
  it('listens on ssh and telnet, which greet the client', () => {
    // An HTTP request written into an SSH server is protocol noise that can get the connection dropped before
    // its banner arrives — turning a live service into a silent one.
    expect(probePlanFor('ssh').send).toBeNull();
    expect(probePlanFor('telnet').send).toBeNull();
  });

  it('sends a request on http, which waits for one', () => {
    expect(probePlanFor('http').send).toContain('HEAD / HTTP/1.0');
    expect(probePlanFor('unknown').send).toContain('HEAD /');
  });
});

describe('isTlsSpeaker — a bad TLS answer is still an answer', () => {
  it('counts a protocol-level failure, because something spoke TLS', () => {
    // Firmware TLS stacks are old and routinely fail modern handshakes. Reading that as "no service" would
    // discard the result on exactly the images most worth looking at.
    expect(isTlsSpeaker({ code: 'ERR_SSL_WRONG_VERSION_NUMBER', message: 'wrong version number' })).toBe(true);
    expect(isTlsSpeaker({ code: 'ERR_TLS_HANDSHAKE_TIMEOUT', message: 'x' })).toBe(true);
    expect(isTlsSpeaker({ message: 'sslv3 alert handshake failure' })).toBe(true);
  });

  it('does not count a connection-level failure, where nothing was there at all', () => {
    expect(isTlsSpeaker({ code: 'ECONNREFUSED', message: 'connect ECONNREFUSED' })).toBe(false);
    expect(isTlsSpeaker({ code: 'ECONNRESET', message: 'socket hang up' })).toBe(false);
    expect(isTlsSpeaker({ code: 'ETIMEDOUT', message: 'timeout' })).toBe(false);
  });
});

describe('guestNetwork — read the firmware’s own network setup out of the boot log', () => {
  it('sees loopback-only, which is why no forwarded port can ever answer', () => {
    // Verbatim shape from the real WR940N: firmadyne kernels trace every execve, and its rcS runs exactly this.
    const log = 'firmadyne: do_execve[PID: 55 (rcS)]: argv: ifconfig lo 127.0.0.1 up, envp: USER=root';
    const net = guestNetwork(log);
    expect(net.configured).toEqual(['lo']);
    expect(net.loopbackOnly).toBe(true);
  });

  it('does not call it loopback-only when a real interface was configured too', () => {
    const net = guestNetwork('ifconfig lo 127.0.0.1 up\nifconfig eth0 192.168.1.1 up\n');
    expect(net.configured).toEqual(['eth0', 'lo']);
    expect(net.loopbackOnly).toBe(false);
  });

  it('reads the iproute2 form as well as busybox ifconfig', () => {
    expect(guestNetwork('ip addr add 10.0.0.1/24 dev br0').configured).toEqual(['br0']);
  });

  it('claims nothing when the console shows no network setup at all', () => {
    // Silence is not "loopback only" — it is not knowing, and the verdict must not read a diagnosis into it.
    expect(guestNetwork('[ 0.0 ] booting').loopbackOnly).toBe(false);
  });
});

describe('classifyFullSystem — a loopback-only guest is diagnosed, not left ambiguous', () => {
  it('names the real reason nothing answered instead of offering two possibilities', () => {
    const r = classifyFullSystem([], { booted: true, marker: 'Freeing unused kernel memory', panicked: false }, true, {
      configured: ['lo'],
      loopbackOnly: true,
    });
    expect(r.proofState).toBe('confirmed_full_system');
    expect(r.reason).toContain('ONLY loopback');
    expect(r.reason).toContain('not a result about the firmware');
  });

  it('states that a second pass ran and still nothing answered, rather than repeating pass one', () => {
    const r = classifyFullSystem(
      [],
      { booted: true, marker: 'Freeing unused kernel memory', panicked: false },
      true,
      { configured: ['lo'], loopbackOnly: true },
      { kind: 'kernel-assign', reason: 'eth0 was addressed by the kernel.', applied: true },
    );
    expect(r.reason).toContain('A second pass was run');
    expect(r.reason).toContain('eth0 was addressed by the kernel.');
  });

  it('states WHY no second pass was possible when nothing could be inferred', () => {
    const r = classifyFullSystem([], { booted: true, marker: 'init started:', panicked: false }, true, undefined, {
      kind: 'none',
      reason: 'The console names no network interface at all.',
      applied: false,
    });
    expect(r.reason).toContain('No second pass was possible');
    expect(r.reason).toContain('no network interface at all');
  });
});

// === The two-pass run: learn, infer, reach ===

/**
 * Verbatim from the real WR940N boot stored on the deployment (job 486be04e), trimmed to the lines that carry
 * network facts. The `execve` traces are firmadyne's; the bridge and link lines are the KERNEL's, which is the
 * half no execve trace can show and the half that makes this image inferable at all.
 */
const WR940N_CONSOLE = [
  '[    0.242042] e1000: Intel(R) PRO/1000 Network Driver - version 7.3.21-k8-NAPI',
  '[    0.577920] e1000 0000:00:12.0 eth0: (PCI:33MHz:32-bit) 52:54:00:12:34:56',
  '[    0.219000] 8021q: 802.1Q VLAN Support v1.8',
  'firmadyne: do_execve[PID: 55 (rcS)]: argv: ifconfig lo 127.0.0.1 up, envp: USER=root SHELL=/bin/sh',
  'exec_Cmd: **insmod /lib/modules/2.6.31/net/ag7240_mod.ko ru_br=0 g_lan_mode=0 g_igmp_snooping_enable=1',
  '[    1.817915] device eth0 entered promiscuous mode',
  '[    1.874225] IPv6: ADDRCONF(NETDEV_UP): eth0: link is not ready',
  '[    1.874738] 8021q: adding VLAN 0 to HW filter on device eth0',
  '[    1.875927] e1000: eth0 NIC Link is Up 1000 Mbps Full Duplex, Flow Control: RX',
  '[    2.180578] br0: port 1(eth0) entered forwarding state',
  '[    2.180725] br0: port 1(eth0) entered forwarding state',
  'exec_Cmd: OPEN ALL PHY ETH!!',
].join('\n');

describe('guestNetwork — the console carries more than the ifconfig calls', () => {
  it('reads an interface the KERNEL brought up that no execve ever mentions', () => {
    const net = guestNetwork(WR940N_CONSOLE);
    // The original reading — only `lo` was ever addressed — is unchanged, because the verdict is worded from it.
    expect(net.configured).toEqual(['lo']);
    expect(net.loopbackOnly).toBe(true);
    // And the new reading: eth0 exists, is up, and is a bridge port. "No address" is not "no interface".
    expect(net.interfaces.map((i) => i.name)).toContain('eth0');
    expect(net.bridges).toEqual([expect.objectContaining({ name: 'br0', members: ['eth0'] })]);
  });

  it('does not invent a VLAN out of the 8021q core registering vid 0', () => {
    // `adding VLAN 0 to HW filter` is the 8021q module touching every device it sees, not a VLAN the firmware
    // asked for. Reporting it would describe a network the firmware never described.
    expect(guestNetwork(WR940N_CONSOLE).vlans).toEqual([]);
  });

  it('reads the VLANs that ARE the firmware’s, from vconfig and from iproute2', () => {
    const net = guestNetwork('vconfig add eth0 2\nip link add link eth1 name eth1.7 type vlan id 7\n');
    expect(net.vlans).toEqual([
      expect.objectContaining({ parent: 'eth0', id: 2, name: 'eth0.2' }),
      expect.objectContaining({ parent: 'eth1', id: 7, name: 'eth1.7' }),
    ]);
  });

  it('keeps the netmask when the firmware prints one, and refuses to invent one when it does not', () => {
    const withMask = guestNetwork('ifconfig br0 192.168.1.1 netmask 255.255.255.0 up');
    expect(withMask.interfaces[0]).toMatchObject({ name: 'br0', address: '192.168.1.1', prefix: 24 });
    const without = guestNetwork('ifconfig br0 192.168.1.1 up');
    expect(without.interfaces[0]?.prefix).toBeNull();
  });

  it('reads gateways and DHCP intent, which are network facts and not addresses', () => {
    const net = guestNetwork('route add default gw 10.0.0.1\nudhcpc -i eth1 -b\n');
    expect(net.gateways).toEqual(['10.0.0.1']);
    expect(net.dhcpClients).toEqual(['eth1']);
  });

  it('claims nothing at all from a console with no network in it', () => {
    const net = guestNetwork('[    0.000000] Linux version 4.1.17+\nNR_IRQS:256\n');
    expect(net.interfaces).toEqual([]);
    expect(net.bridges).toEqual([]);
    expect(net.loopbackOnly).toBe(false);
    expect(net.boundNote).toBe('');
  });

  it('states what a bound dropped, and sorts before it caps so the survivors are not console order', () => {
    // 40 link-up lines, printed in an order that would otherwise decide which 32 survive.
    const lines: string[] = [];
    for (let i = 39; i >= 0; i--)
      lines.push(`[    0.1] device zz${String(i).padStart(2, '0')} entered promiscuous mode`);
    const net = guestNetwork(lines.join('\n'));
    expect(net.interfaces).toHaveLength(32);
    expect(net.interfaces[0]?.name).toBe('zz00');
    expect(net.boundNote).toContain('8 entr(ies)');
    expect(net.boundNote).toContain('BEFORE the cap');
  });
});

describe('prefixFromNetmask / planSlirpSubnet — the arithmetic the second pass rests on', () => {
  it('converts the masks firmware actually writes', () => {
    expect(prefixFromNetmask('255.255.255.0')).toBe(24);
    expect(prefixFromNetmask('255.255.0.0')).toBe(16);
    expect(prefixFromNetmask('255.255.255.252')).toBe(30);
  });

  it('refuses a mask that is not one, instead of returning a number that looks like an answer', () => {
    expect(prefixFromNetmask('255.0.255.0')).toBeNull();
    expect(prefixFromNetmask('not.a.mask.at.all')).toBeNull();
  });

  it('puts the host beside the guest without ever colliding with it', () => {
    expect(planSlirpSubnet('192.168.1.1', 24)).toEqual({ net: '192.168.1.0/24', host: '192.168.1.2' });
    // Guest sitting on the address slirp would normally take: the host has to move, not the guest.
    expect(planSlirpSubnet('192.168.1.2', 24)).toEqual({ net: '192.168.1.0/24', host: '192.168.1.3' });
  });

  it('refuses a network or broadcast address, and a subnet with no room for two hosts', () => {
    expect(planSlirpSubnet('192.168.1.0', 24)).toBeNull();
    expect(planSlirpSubnet('192.168.1.255', 24)).toBeNull();
    expect(planSlirpSubnet('192.168.1.1', 31)).toBeNull();
  });

  it('knows loopback when it sees it anywhere in 127/8', () => {
    expect(isLoopbackAddress('127.0.0.1')).toBe(true);
    expect(isLoopbackAddress('127.1.2.3')).toBe(true);
    expect(isLoopbackAddress('10.0.2.15')).toBe(false);
  });
});

describe('inferGuestNetwork — what pass two should be booted with, from pass one and nothing else', () => {
  it('moves the EMULATOR when the firmware named an address (firmadyne’s move)', () => {
    const inf = inferGuestNetwork(guestNetwork('ifconfig br0 192.168.1.1 netmask 255.255.255.0 up'));
    expect(inf.kind).toBe('guest-address');
    expect(inf.plan).toEqual({
      kernelIp: null,
      slirpNet: '192.168.1.0/24',
      slirpHost: '192.168.1.2',
      guestAddress: '192.168.1.1',
    });
    expect(inf.assumedPrefix).toBe(false);
    expect(inf.evidence[0]).toContain('192.168.1.1');
  });

  it('says out loud that a /24 was ASSUMED when the firmware printed no netmask', () => {
    const inf = inferGuestNetwork(guestNetwork('ifconfig eth0 10.7.7.1 up'));
    expect(inf.assumedPrefix).toBe(true);
    expect(inf.reason).toContain('ASSUMED');
    expect(inf.plan?.slirpNet).toBe('10.7.7.0/24');
  });

  it('prefers the bridge over a raw NIC when both carry an address, deterministically', () => {
    const inf = inferGuestNetwork(
      guestNetwork('brctl addbr br0\nifconfig eth0 10.0.0.9 up\nifconfig br0 192.168.0.1 up\n'),
    );
    expect(inf.iface).toBe('br0');
    expect(inf.plan?.guestAddress).toBe('192.168.0.1');
  });

  it('asks the KERNEL for an address when the guest brought a NIC up and never addressed it — the WR940N', () => {
    const inf = inferGuestNetwork(guestNetwork(WR940N_CONSOLE));
    expect(inf.kind).toBe('kernel-assign');
    expect(inf.iface).toBe('eth0');
    expect(inf.plan?.kernelIp).toBe('10.0.2.15::10.0.2.2:255.255.255.0::eth0:off');
    expect(inf.plan?.guestAddress).toBe('10.0.2.15');
    // And it says who supplied the address, and warns about the bridge that may take it away again.
    expect(inf.reason).toContain('HARNESS supplying a network');
    expect(inf.reason).toContain('br0 claims eth0');
  });

  it('never proposes loopback as the interface to reach a service on', () => {
    const inf = inferGuestNetwork(guestNetwork('ifconfig lo 127.0.0.1 up'));
    expect(inf.kind).toBe('none');
    expect(inf.plan).toBeNull();
  });

  it('returns "none" with the console quoted when nothing usable is there — a result, not a failure', () => {
    const inf = inferGuestNetwork(guestNetwork('[    0.0] Linux version 4.1.17+\nNR_IRQS:256\n'));
    expect(inf.kind).toBe('none');
    expect(inf.plan).toBeNull();
    expect(inf.reason).toContain('no network interface at all');
    expect(inf.reason).toContain('no reachability is claimed');
  });

  it('does not offer a bridge or a VLAN device to the kernel’s ip=, which needs the real NIC', () => {
    const inf = inferGuestNetwork(guestNetwork('brctl addbr br0\nbrctl addif br0 eth0\nvconfig add eth0 2\n'));
    expect(inf.kind).toBe('kernel-assign');
    expect(inf.iface).toBe('eth0');
  });
});

describe('buildFullSystemArgs — pass two’s network, and pass one left untouched', () => {
  it('is byte-for-byte the old boot when no plan is given', () => {
    const args = buildFullSystemArgs('malta', '/k', '/r.img', [{ host: 8080, guest: 80 }]).join(' ');
    expect(args).toContain('-append console=ttyS0 root=/dev/sda rootfstype=ext2 rw -drive');
    expect(args).toContain('user,id=n0,hostfwd=tcp::8080-:80');
  });

  it('hands the kernel an ip= and aims the forward at the address it will get', () => {
    const args = buildFullSystemArgs('malta', '/k', '/r.img', [{ host: 41000, guest: 80 }], {
      kernelIp: '10.0.2.15::10.0.2.2:255.255.255.0::eth0:off',
      slirpNet: null,
      slirpHost: null,
      guestAddress: '10.0.2.15',
    }).join(' ');
    expect(args).toContain('ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off');
    expect(args).toContain('hostfwd=tcp::41000-10.0.2.15:80');
  });

  it('moves slirp onto the firmware’s own subnet when the firmware named one', () => {
    const args = buildFullSystemArgs('malta', '/k', '/r.img', [{ host: 41000, guest: 80 }], {
      kernelIp: null,
      slirpNet: '192.168.1.0/24',
      slirpHost: '192.168.1.2',
      guestAddress: '192.168.1.1',
    }).join(' ');
    expect(args).toContain('user,id=n0,net=192.168.1.0/24,host=192.168.1.2,hostfwd=tcp::41000-192.168.1.1:80');
    // No ip= — the guest configures itself and is right to; it is the emulator that moved.
    expect(args).not.toContain('ip=');
  });

  it('appends the console pass’s cmdline last, so the two boots differ in exactly that string', () => {
    const base = buildFullSystemArgs('malta', '/k', '/r.img', [{ host: 8080, guest: 80 }], null, null, false);
    const driven = buildFullSystemArgs(
      'malta',
      '/k',
      '/r.img',
      [{ host: 8080, guest: 80 }],
      null,
      null,
      false,
      'init=/bin/sh',
    );
    expect(driven.join(' ')).toContain('-append console=ttyS0 root=/dev/sda rootfstype=ext2 rw init=/bin/sh');
    // Same argv otherwise: an intervened boot that also changed the machine, the drive or the netdev would be
    // comparing two things at once, which is the confound this rung has already been burned by.
    expect(driven.filter((a) => !a.startsWith('console=ttyS0'))).toEqual(
      base.filter((a) => !a.startsWith('console=ttyS0')),
    );
  });

  it('leaves the un-driven boot without an init= at all, rather than spelling out the default', () => {
    expect(buildFullSystemArgs('malta', '/k', '/r.img', [{ host: 8080, guest: 80 }]).join(' ')).not.toContain('init=');
  });
});

/**
 * The pass-three builder, pinned because its first wiring was wrong on real bytes in a way no fixture would show:
 * the flush ran and the forwards pointed at a guest address nothing held, so the pass tore the firewall down and
 * then knocked on the wrong door.
 */
describe('buildConsolePassArgs — pass three differs from pass two in the init and nothing else', () => {
  const plan = {
    kernelIp: null,
    slirpNet: '192.168.0.0/24',
    slirpHost: '192.168.0.2',
    guestAddress: '192.168.0.1',
  };

  it('aims the forwards at the guest’s own address, exactly as pass two did', () => {
    const args = buildConsolePassArgs('malta', '/k', '/r.img', [{ host: 39301, guest: 80 }], plan, true).join(' ');
    expect(args).toContain('hostfwd=tcp::39301-192.168.0.1:80');
    expect(args).toContain('net=192.168.0.0/24,host=192.168.0.2');
    expect(args).toContain('init=/bin/sh');
  });

  it('is pass two’s argv plus init=/bin/sh — the ONE difference the comparison rests on', () => {
    const forwards = [{ host: 39301, guest: 80 }];
    const two = buildFullSystemArgs('malta', '/k', '/r.img', forwards, plan, null, true);
    const three = buildConsolePassArgs('malta', '/k', '/r.img', forwards, plan, true);
    const strip = (a: string[]) => a.map((x) => x.replace(' init=/bin/sh', ''));
    expect(strip(three)).toEqual(strip(two));
  });

  it('takes no frame capture, so an intervened boot cannot enter the egress observation', () => {
    const args = buildConsolePassArgs('malta', '/k', '/r.img', [{ host: 39301, guest: 80 }], plan).join(' ');
    expect(args).not.toContain('filter-dump');
  });

  it('falls back to qemu’s own network when pass one inferred none, rather than inventing an address', () => {
    const args = buildConsolePassArgs('malta', '/k', '/r.img', [{ host: 39301, guest: 80 }], null).join(' ');
    expect(args).toContain('hostfwd=tcp::39301-:80');
    expect(args).toContain('init=/bin/sh');
  });
});

describe('readIpConfig — whether the kernel took the address is read, not assumed', () => {
  it('reads the completion line the kernel prints on success', () => {
    const r = readIpConfig(
      '[    1.2] IP-Config: Complete:\n     device=eth0, hwaddr=52:54:00:12:34:56, ipaddr=10.0.2.15',
    );
    expect(r.applied).toBe(true);
    expect(r.line).toContain('IP-Config: Complete:');
  });

  it('reports a kernel that tried and failed differently from one that never mentioned it', () => {
    const failed = readIpConfig("IP-Config: Device `eth9' not found");
    expect(failed.applied).toBe(false);
    expect(failed.line).toContain('not found');
    const silent = readIpConfig('[    0.0] Linux version 4.1.17+');
    expect(silent).toEqual({ applied: false, line: null });
  });
});

describe('passScore — the later pass is not automatically the better one', () => {
  it('ranks a boot with an answered port above everything, and a panic below everything', () => {
    expect(passScore({ open: [{ host: 1 }], booted: true, panicked: false })).toBe(4);
    expect(passScore({ open: [{ host: 1 }], booted: false, panicked: false })).toBe(3);
    expect(passScore({ open: [], booted: true, panicked: false })).toBe(2);
    expect(passScore({ open: [], booted: false, panicked: false })).toBe(1);
    expect(passScore({ open: [], booted: false, panicked: true })).toBe(0);
  });

  it('will not let a second pass that panicked overwrite a first pass that booted', () => {
    const first = passScore({ open: [], booted: true, panicked: false });
    const second = passScore({ open: [], booted: false, panicked: true });
    expect(second >= first).toBe(false);
  });
});

describe('a pass that observed no accept never reports reachability', () => {
  it('reports the empty open list as empty, whatever the console promised', () => {
    // The console says the guest configured a real interface. That is an intent, not a service. Only the socket
    // decides, and here it got nothing.
    const net = guestNetwork('ifconfig br0 192.168.1.1 netmask 255.255.255.0 up');
    expect(net.loopbackOnly).toBe(false);
    const r = classifyFullSystem([], { booted: true, marker: 'BusyBox v1.01', panicked: false }, true, net, {
      kind: 'guest-address',
      reason: 'slirp was moved onto 192.168.1.0/24.',
      applied: true,
    });
    expect(r.proofState).not.toBe('confirmed_in_emulation');
    expect(r.reason).toContain('no forwarded port accepted a connection');
    expect(r.reason).toContain('A second pass was run');
  });
});

// === The frames, which on this corpus are where the address actually is ===

/** A classic little-endian Ethernet pcap, built frame by frame — the exact shape qemu's filter-dump writes. */
function pcap(frames: Uint8Array[]): Uint8Array {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(128, 16);
  header.writeUInt32LE(1, 20); // LINKTYPE_ETHERNET
  const parts: Buffer[] = [header];
  for (const f of frames) {
    const rec = Buffer.alloc(16);
    rec.writeUInt32LE(1, 0);
    rec.writeUInt32LE(0, 4);
    rec.writeUInt32LE(f.length, 8);
    rec.writeUInt32LE(f.length, 12);
    parts.push(rec, Buffer.from(f));
  }
  return new Uint8Array(Buffer.concat(parts));
}

const mac = (s: string): number[] => s.split(':').map((b) => Number.parseInt(b, 16));
const ip = (s: string): number[] => s.split('.').map(Number);

function arpFrame(senderIp: string, senderMac: string, targetIp: string, op = 1): Uint8Array {
  const f = Buffer.alloc(42);
  Buffer.from(mac('ff:ff:ff:ff:ff:ff')).copy(f, 0);
  Buffer.from(mac(senderMac)).copy(f, 6);
  f.writeUInt16BE(0x0806, 12);
  f.writeUInt16BE(1, 14);
  f.writeUInt16BE(0x0800, 16);
  f[18] = 6;
  f[19] = 4;
  f.writeUInt16BE(op, 20);
  Buffer.from(mac(senderMac)).copy(f, 22);
  Buffer.from(ip(senderIp)).copy(f, 28);
  Buffer.from(ip(targetIp)).copy(f, 38);
  return new Uint8Array(f);
}

function tcpFrame(src: string, dst: string, srcMac: string, flags: number): Uint8Array {
  const f = Buffer.alloc(54);
  Buffer.from(mac('00:11:22:33:44:55')).copy(f, 0);
  Buffer.from(mac(srcMac)).copy(f, 6);
  f.writeUInt16BE(0x0800, 12);
  f[14] = 0x45;
  f[23] = 6;
  Buffer.from(ip(src)).copy(f, 26);
  Buffer.from(ip(dst)).copy(f, 30);
  f.writeUInt16BE(45000, 34);
  f.writeUInt16BE(80, 36);
  f[46] = 0x50;
  f[47] = flags;
  return new Uint8Array(f);
}

const SYN = 0x02;
const SYN_ACK = 0x12;
const RST = 0x04;

describe('parseGuestWire — the guest’s own address, read from its own frames', () => {
  it('reads the address the guest claims by ARP, and ignores the emulator claiming its own', () => {
    // Verbatim shape from the real WR940N: it ARPs for its DHCP pool from 192.168.0.1 with a MAC its vendor init
    // set, while qemu's slirp gateway speaks from 10.0.2.2. Only one of those is the firmware.
    const buf = pcap([
      arpFrame('192.168.0.1', '00:0a:eb:13:7b:00', '192.168.0.100'),
      arpFrame('192.168.0.1', '00:0a:eb:13:7b:00', '192.168.0.100'),
      arpFrame('10.0.2.2', '52:55:0a:00:02:02', '10.0.2.15'),
    ]);
    const wire = parseGuestWire(buf, ['10.0.2.2', '10.0.2.3', '10.0.2.4']);
    expect(wire.frames).toBe(3);
    expect(wire.addresses).toEqual([
      { address: '192.168.0.1', mac: '00:0a:eb:13:7b:00', how: 'arp-sender', frames: 2 },
    ]);
  });

  it('never counts loopback, multicast or a broadcast address as an interface address', () => {
    const buf = pcap([
      tcpFrame('127.0.0.1', '127.0.0.1', 'aa:bb:cc:dd:ee:ff', SYN),
      tcpFrame('239.255.255.250', '1.2.3.4', 'aa:bb:cc:dd:ee:ff', SYN),
      tcpFrame('0.0.0.0', '1.2.3.4', 'aa:bb:cc:dd:ee:ff', SYN),
    ]);
    expect(parseGuestWire(buf, []).addresses).toEqual([]);
  });

  it('counts what was delivered and what came back, which is what tells a refusal from a drop', () => {
    const buf = pcap([
      tcpFrame('10.0.2.2', '10.0.2.15', '52:55:0a:00:02:02', SYN),
      tcpFrame('10.0.2.2', '10.0.2.15', '52:55:0a:00:02:02', SYN),
      tcpFrame('10.0.2.15', '10.0.2.2', '52:54:00:12:34:56', RST),
    ]);
    const wire = parseGuestWire(buf, ['10.0.2.2']);
    expect(wire.synsToGuest).toBe(2);
    expect(wire.resetsFromGuest).toBe(1);
    expect(wire.synAcksFromGuest).toBe(0);
  });

  it('sees an accepted connection as an accepted connection', () => {
    const buf = pcap([
      tcpFrame('10.0.2.2', '10.0.2.15', '52:55:0a:00:02:02', SYN),
      tcpFrame('10.0.2.15', '10.0.2.2', '52:54:00:12:34:56', SYN_ACK),
    ]);
    const wire = parseGuestWire(buf, ['10.0.2.2']);
    expect(wire.synAcksFromGuest).toBe(1);
  });

  it('says WHY it read nothing instead of returning an empty observation that looks like a fact', () => {
    expect(parseGuestWire(new Uint8Array(0)).problem).toContain('empty');
    // A short file is not an empty one, and saying so keeps a truncated capture from reading as "the guest was silent".
    expect(parseGuestWire(new Uint8Array(8)).problem).toContain('too short');
    expect(parseGuestWire(new Uint8Array(40)).problem).toContain('Not a classic pcap');
    const wrongLink = Buffer.from(pcap([]));
    wrongLink.writeUInt32LE(101, 20); // LINKTYPE_RAW
    expect(parseGuestWire(new Uint8Array(wrongLink)).problem).toContain('not Ethernet');
  });
});

describe('describeWire — a silence and a refusal are different findings', () => {
  const base = {
    addresses: [],
    frames: 10,
    synsToGuest: 3,
    synAcksFromGuest: 0,
    resetsFromGuest: 0,
    truncated: false,
    problem: '',
  };

  it('calls a reset what it is: a live stack with nothing listening', () => {
    expect(describeWire({ ...base, resetsFromGuest: 3 })).toContain('REFUSED');
  });

  it('calls a total silence a drop inside the guest, not an absent service', () => {
    const s = describeWire(base);
    expect(s).toContain('not even a reset');
    expect(s).toContain('different finding from "no service"');
  });

  it('does not read a diagnosis into a pass where nothing was ever knocked on', () => {
    expect(describeWire({ ...base, synsToGuest: 0 })).toContain('No connection attempt was delivered');
  });
});

describe('emulatorAddressesFor — telling the emulator’s voice from the guest’s', () => {
  it('knows qemu’s own defaults when slirp has not been moved', () => {
    expect(emulatorAddressesFor(null)).toEqual(['10.0.2.2', '10.0.2.3', '10.0.2.4']);
  });

  it('follows slirp onto the firmware’s subnet', () => {
    expect(
      emulatorAddressesFor({
        kernelIp: null,
        slirpNet: '192.168.0.0/24',
        slirpHost: '192.168.0.2',
        guestAddress: '192.168.0.1',
      }),
    ).toEqual(['192.168.0.2', '192.168.0.3', '192.168.0.4']);
  });
});

describe('inferGuestNetwork with the wire — the WR940N, whose console does not carry its address', () => {
  const wireWithLan = parseGuestWire(pcap([arpFrame('192.168.0.1', '00:0a:eb:13:7b:00', '192.168.0.100')]), [
    '10.0.2.2',
    '10.0.2.3',
    '10.0.2.4',
  ]);

  it('uses an address the guest USED when the console shows only loopback', () => {
    // Measured: 305 KB of WR940N boot log contains the string `192.168` zero times, while the guest ARPs as
    // 192.168.0.1 throughout. The console-only reading called this firmware "loopback only", which was a fact
    // about the log rather than about the guest.
    const inf = inferGuestNetwork(guestNetwork(WR940N_CONSOLE), wireWithLan);
    expect(inf.kind).toBe('guest-address');
    expect(inf.observedOn).toBe('wire');
    expect(inf.plan).toEqual({
      kernelIp: null,
      slirpNet: '192.168.0.0/24',
      slirpHost: '192.168.0.2',
      guestAddress: '192.168.0.1',
    });
    expect(inf.assumedPrefix).toBe(true);
    expect(inf.reason).toContain('ASSUMED');
  });

  it('still prefers what the firmware SAID when the console names an address', () => {
    const inf = inferGuestNetwork(guestNetwork('ifconfig br0 10.9.9.1 netmask 255.255.255.0 up'), wireWithLan);
    expect(inf.observedOn).toBe('console');
    expect(inf.plan?.guestAddress).toBe('10.9.9.1');
  });

  it('falls back to the kernel when neither the console nor the wire carries an address', () => {
    const silent = parseGuestWire(pcap([]), []);
    const inf = inferGuestNetwork(guestNetwork(WR940N_CONSOLE), silent);
    expect(inf.kind).toBe('kernel-assign');
  });

  it('quotes the wire in the "nothing could be inferred" reason, so the empty answer is evidenced', () => {
    const inf = inferGuestNetwork(guestNetwork('[ 0.0 ] booting'), parseGuestWire(pcap([]), []));
    expect(inf.kind).toBe('none');
    expect(inf.reason).toContain('On the wire');
    expect(inf.reason).toContain('no frames at all');
  });
});

describe('classifyFullSystem — a console that names only loopback is not a guest without a network', () => {
  it('keeps the loopback diagnosis when nothing anywhere shows an address', () => {
    const r = classifyFullSystem([], { booted: true, marker: 'init started:', panicked: false }, true, {
      configured: ['lo'],
      loopbackOnly: true,
    });
    expect(r.reason).toContain('configured ONLY loopback');
  });

  it('withdraws it the moment an address WAS observed, instead of contradicting itself a sentence later', () => {
    // Measured on the WR940N: the same boot whose console says only `ifconfig lo` puts 192.168.0.1 on the wire.
    // The old wording asserted the guest had no network while quoting the frames that disprove it.
    const r = classifyFullSystem(
      [],
      { booted: true, marker: 'init started:', panicked: false },
      true,
      { configured: ['lo'], loopbackOnly: true },
      { kind: 'guest-address', reason: 'the guest used 192.168.0.1', applied: true, guestAddressed: true },
    );
    expect(r.reason).not.toContain('configured ONLY loopback');
    expect(r.reason).toContain('a fact about the LOG');
    expect(r.reason).toContain('did bring a network up');
  });
});

describe('guestNetwork — a NIC the kernel named is a NIC that exists', () => {
  const MR3220_CONSOLE = [
    '[    0.248519] e1000: Intel(R) PRO/1000 Network Driver - version 7.3.21-k8-NAPI',
    '[    0.637287] e1000 0000:00:12.0 eth0: (PCI:33MHz:32-bit) 52:54:00:12:34:56',
    '[    0.637513] e1000 0000:00:12.0 eth0: Intel(R) PRO/1000 Network Connection',
    'firmadyne: do_execve[PID: 56 (rcS)]: argv: ifconfig lo 127.0.0.1 up, envp: USER=root',
    'do_page_fault(): sending SIGSEGV to httpd for invalid read access from 00000038',
  ].join('\n');

  it('finds eth0 on an image whose router daemon died before touching the network', () => {
    // Measured on the MR3220: its httpd SEGVs at 1.6 s, so there is no ADDRCONF, no promiscuous mode and no bridge
    // port anywhere in the log. Reading only those left the image as "no interface", which blames the hardware for
    // a crash in the vendor's daemon.
    const net = guestNetwork(MR3220_CONSOLE);
    expect(net.interfaces.map((i) => i.name)).toContain('eth0');
    expect(net.interfaces.find((i) => i.name === 'eth0')?.how).toBe('nic-registered');
    expect(inferGuestNetwork(net).kind).toBe('kernel-assign');
  });

  it('does not manufacture an interface out of a log prefix', () => {
    // Every firmadyne line is `subsystem: text`. A general "<word> <word>:" shape would read `firmadyne: close` and
    // `8021q: adding` as network devices.
    const net = guestNetwork('firmadyne: close[PID: 1 (init)]: fd:3\nSCSI subsystem initialized\nusbcore: eth9:\n');
    expect(net.interfaces).toEqual([]);
  });

  it('lets a real link event outrank a bare registration for the same interface', () => {
    const net = guestNetwork(
      '[0.6] e1000 0000:00:12.0 eth0: Intel(R) PRO/1000 Network Connection\n[1.8] device eth0 entered promiscuous mode\n',
    );
    expect(net.interfaces).toHaveLength(1);
    expect(net.interfaces[0]?.how).toBe('link-up');
  });
});

describe('parseGuestWire — a remote host slirp forwarded is not the guest', () => {
  it('drops addresses that arrived under the emulator’s own MAC', () => {
    // Measured on the WDR3600's second pass: once it had an address it reached out to NTP, and the replies came
    // back through slirp — same MAC as slirp's gateway, source addresses on the public internet. The parser listed
    // 129.7.1.66 as "an address the guest used", and the inference would happily have moved qemu's network onto a
    // stranger's subnet on the strength of it.
    const buf = pcap([
      arpFrame('10.0.2.2', '52:55:0a:00:02:02', '10.0.2.15'),
      tcpFrame('129.7.1.66', '10.0.2.15', '52:55:0a:00:02:02', SYN_ACK),
      tcpFrame('10.0.2.15', '10.0.2.2', '52:54:00:12:34:56', RST),
    ]);
    const wire = parseGuestWire(buf, ['10.0.2.2', '10.0.2.3', '10.0.2.4']);
    expect(wire.addresses.map((a) => a.address)).toEqual(['10.0.2.15']);
  });

  it('still hears a guest that speaks from 0.0.0.0, which is what a DHCP client does', () => {
    // The exclusion must come from slirp's OWN addresses only. Learning a MAC from a 0.0.0.0 source would blind
    // the parser to the machine it exists to watch.
    const buf = pcap([
      tcpFrame('0.0.0.0', '255.255.255.255', '52:54:00:12:34:56', SYN),
      arpFrame('192.168.1.1', '52:54:00:12:34:56', '192.168.1.2'),
    ]);
    expect(parseGuestWire(buf, ['10.0.2.2']).addresses.map((a) => a.address)).toEqual(['192.168.1.1']);
  });
});

describe('buildSystemEmulationFindings — every outcome earns a row, and none of them is a device claim', () => {
  function result(over: Partial<SystemEmulationResult> = {}): SystemEmulationResult {
    return {
      ran: true,
      strategy: 'full-system',
      proofState: 'confirmed_full_system',
      reason: 'The image booted and two forwarded ports accepted a connection in the sandbox.',
      command: 'qemu-system-mips -M malta -kernel /opt/firmae/kernels/vmlinux.mipseb.4 …',
      stdout: '',
      stderr: '',
      timedOut: false,
      ...over,
    };
  }

  it('a booted image with two answering ports is confirmed in the sandbox, not on the device', () => {
    const [draft] = buildSystemEmulationFindings('rootfs', {
      ...result(),
      open: [
        { host: 8080, guest: 80 },
        { host: 8081, guest: 443 },
      ],
    });
    expect(draft?.kind).toBe('system-boot-confirmed');
    expect(draft?.proofState).toBe('confirmed_full_system');
    expect(draft?.evidenceChannel).toBe('emulated_run');
    expect(draft?.title).toContain('2 forwarded port(s) answered');
    expect(draft?.title).toContain('in the sandbox, not on the device');
  });

  it('a rung that could not run says so and refuses to be read as a negative', () => {
    const [draft] = buildSystemEmulationFindings('rootfs', {
      ...result(),
      ran: false,
      proofState: 'blocked_by_platform',
      reason: 'No firmadyne kernel is installed for mipseb in this deployment.',
    });
    expect(draft?.kind).toBe('system-boot-blocked');
    expect(draft?.proofState).toBe('blocked_by_platform');
    expect(draft?.title).toContain('this is not a negative result');
  });

  // The channel says HOW this was learned; a boot that never started learned nothing.
  it('keeps no evidence channel on the blocked row, because nothing ran', () => {
    const [draft] = buildSystemEmulationFindings('rootfs', {
      ...result(),
      ran: false,
      proofState: 'blocked_by_platform',
    });
    expect(draft && 'evidenceChannel' in draft).toBe(false);
  });

  // Both rows are `blocked_by_platform`; only `ran` tells a kernel that died from a kernel that never booted.
  it('a panic is a blocked run that DID execute, and carries the channel the unrun one does not', () => {
    const [draft] = buildSystemEmulationFindings('rootfs', {
      ...result(),
      ran: true,
      proofState: 'blocked_by_platform',
      reason: 'The guest kernel panicked before init.',
    });
    expect(draft?.kind).toBe('system-boot-panicked');
    expect(draft?.evidenceChannel).toBe('emulated_run');
    expect(draft?.title).toContain('could not be answered here');
  });

  it('a boot with no marker and nothing answering is not a verdict about the firmware', () => {
    const [draft] = buildSystemEmulationFindings('rootfs', {
      ...result(),
      proofState: 'needs_runtime_reproduction',
      reason: 'No boot marker appeared within the time box and no forwarded port accepted a connection.',
    });
    expect(draft?.kind).toBe('system-boot-unconfirmed');
    expect(draft?.proofState).toBe('needs_runtime_reproduction');
    expect(draft?.title).toContain('this is not a verdict about the firmware');
  });

  it('a port that answered without a recognisable boot is filed as the service answering, not as a boot', () => {
    const [draft] = buildSystemEmulationFindings('rootfs', {
      ...result(),
      proofState: 'confirmed_in_emulation',
      open: [{ host: 8080, guest: 80 }],
    });
    expect(draft?.kind).toBe('system-service-answered');
    expect(draft?.title).toContain('without a recognisable boot marker');
  });

  it('a chroot service that came up is emulation-confirmed under its own kind', () => {
    const [draft] = buildSystemEmulationFindings('usr/sbin/httpd', {
      ...result(),
      strategy: 'chroot-service',
      proofState: 'confirmed_in_emulation',
      reason: 'The daemon stayed up under qemu-user in the chroot.',
    });
    expect(draft?.kind).toBe('service-started-in-emulation');
    expect(draft?.evidenceChannel).toBe('emulated_run');
    expect(draft?.title).toContain('in the sandbox, not on the device');
  });

  it('a chroot service that died early is a lead, and says it is not a verdict about the firmware', () => {
    const [draft] = buildSystemEmulationFindings('usr/sbin/httpd', {
      ...result(),
      strategy: 'chroot-service',
      proofState: 'needs_runtime_reproduction',
      reason: 'The daemon exited 1 within a second of starting.',
    });
    expect(draft?.kind).toBe('service-exited-early');
    expect(draft?.proofState).toBe('needs_runtime_reproduction');
    expect(draft?.title).toContain('this is not a verdict about the firmware');
  });

  // An n=1 boot supports no causal claim, and the verdict's own sentence is what the reader gets — verbatim,
  // because a composer that paraphrased it would be a second opinion about evidence it never saw.
  it('folds the reproducibility verdict’s own sentence into the rationale, unedited', () => {
    const reason = 'This is the only comparable boot of this image, so nothing here is known to repeat.';
    const [draft] = buildSystemEmulationFindings('rootfs', {
      ...result(),
      reproducibility: {
        kind: 'single',
        n: 1,
        incomparable: 0,
        distribution: [],
        supportsCausalClaim: false,
        reason,
      },
    });
    expect(draft?.rationale).toContain(reason);
    expect(draft?.evidence?.reproducibility).toMatchObject({ supportsCausalClaim: false, n: 1, kind: 'single' });
  });

  it('still says nothing is known to repeat when no reproducibility verdict was computed at all', () => {
    const [draft] = buildSystemEmulationFindings('rootfs', result());
    expect(draft?.rationale).toContain('nothing here is known to repeat');
    expect(draft?.evidence?.reproducibility).toBeUndefined();
  });

  it('travels the interventions with the finding and says the repaired firmware is what answered', () => {
    const interventions = ['Appended one line to /etc/rc.d/rcS that runs the firmware’s own /etc/rc.d/iptables-stop.'];
    const [draft] = buildSystemEmulationFindings('rootfs', {
      ...result(),
      open: [{ host: 8080, guest: 80 }],
      repair: {
        attempted: true,
        interventions,
        skipped: [],
        note: 'FIRMLAB_EMU_REPAIR is on and this image was MODIFIED for the boot.',
      },
    });
    expect(draft?.interventions).toEqual(interventions);
    expect(draft?.rationale).toContain('The guest was modified before it was asked');
    expect(draft?.rationale).toContain('the repaired firmware, not the firmware as shipped');
    expect(draft?.evidence?.repair).toMatchObject({ attempted: true, interventions });
  });

  // Presence is the signal, so an examined-and-left-alone image must not carry an empty list that reads as one.
  it('sets no interventions field at all when the firmware was examined and left as shipped', () => {
    const [draft] = buildSystemEmulationFindings('rootfs', {
      ...result(),
      repair: {
        attempted: true,
        interventions: [],
        skipped: ['This firmware ships no /etc/rc.d/iptables-stop.'],
        note: 'FIRMLAB_EMU_REPAIR is on and this firmware was examined; no repair was applied.',
      },
    });
    expect(draft && 'interventions' in draft).toBe(false);
    expect(draft?.rationale).not.toContain('The guest was modified');
  });
});

describe('buildSystemEmulationFindings — the console pass is a second row, never a caveat on the first', () => {
  function result(over: Partial<SystemEmulationResult> = {}): SystemEmulationResult {
    return {
      ran: true,
      strategy: 'full-system',
      proofState: 'confirmed_full_system',
      reason: 'The kernel booted and no forwarded port accepted a connection.',
      command: 'qemu-system-mips …',
      stdout: '',
      stderr: '',
      timedOut: false,
      open: [],
      ...over,
    };
  }

  const outcome = (over: Partial<ConsoleOutcome> = {}): ConsoleOutcome => ({
    shellAnswered: true,
    rcsCompleted: true,
    policyBefore: 'DROP',
    policyAfter: 'ACCEPT',
    teardownRan: true,
    listening: [22, 80, 443],
    listenersRead: true,
    ...over,
  });

  /** The branch that must find nothing — every image whose firmware answers, and every deployment with the flag off. */
  it('composes exactly one row when the console pass was never attempted', () => {
    const drafts = buildSystemEmulationFindings('rootfs', {
      ...result(),
      console: { attempted: false, reason: 'FIRMLAB_EMU_CONSOLE is off, so the guest was not asked anything.' },
    });
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('system-boot-confirmed');
  });

  it('composes one row when the result predates the console pass entirely', () => {
    expect(buildSystemEmulationFindings('rootfs', result())).toHaveLength(1);
  });

  it('adds a second row when the guest was asked, and leaves the first one untouched', () => {
    const drafts = buildSystemEmulationFindings('rootfs', {
      ...result(),
      console: {
        attempted: true,
        reason: 'Nothing answered on a guest that booted, so the guest is asked directly.',
        command: 'qemu-system-mips … init=/bin/sh',
        outcome: outcome(),
        note: 'A shell answered and the vendor init script ran to completion.',
        interventions: ['Booted with init=/bin/sh …', "The firmware's own /etc/rc.d/iptables-stop was run …"],
        open: [{ host: 41000, guest: 80 }],
      },
    });
    expect(drafts).toHaveLength(2);
    // The un-intervened row must be exactly what it was before the pass existed.
    expect(drafts[0]?.kind).toBe('system-boot-confirmed');
    expect(drafts[0] && 'interventions' in drafts[0]).toBe(false);
    expect(drafts[1]?.kind).toBe('system-console-answered');
    expect(drafts[1]?.proofState).toBe('confirmed_full_system');
    expect(drafts[1]?.interventions).toHaveLength(2);
    expect(drafts[1]?.evidence).toMatchObject({ policyBefore: 'DROP', policyAfter: 'ACCEPT', teardownRan: true });
  });

  /**
   * The run's own `open` is the un-intervened one and stays empty; the console pass's ports live on its own row.
   * Folding them together is what would put an intervened boot into the reproducibility history as a repeat.
   */
  it('never merges the console pass’s answering ports into the run’s own', () => {
    const drafts = buildSystemEmulationFindings('rootfs', {
      ...result(),
      console: {
        attempted: true,
        reason: 'asked',
        outcome: outcome(),
        interventions: ['Booted with init=/bin/sh …'],
        open: [{ host: 41000, guest: 80 }],
      },
    });
    expect(drafts[0]?.evidence?.open).toEqual([]);
    expect(drafts[1]?.evidence?.open).toEqual([{ host: 41000, guest: 80 }]);
  });

  it('carries a shell that never answered as blocked, with no interventions to claim', () => {
    const drafts = buildSystemEmulationFindings('rootfs', {
      ...result(),
      console: {
        attempted: true,
        reason: 'asked',
        outcome: outcome({ shellAnswered: false, policyBefore: null, policyAfter: null, teardownRan: false }),
        interventions: [],
        open: [],
      },
    });
    expect(drafts[1]?.kind).toBe('system-console-blocked');
    expect(drafts[1]?.proofState).toBe('blocked_by_platform');
    expect(drafts[1] && 'interventions' in drafts[1]).toBe(false);
  });

  // `listening: []` means the guest held no socket; without the flag beside it, it also means nobody read the table.
  it('carries both halves of the listener reading, so an empty list is never read as a fact on its own', () => {
    const drafts = buildSystemEmulationFindings('rootfs', {
      ...result(),
      console: {
        attempted: true,
        reason: 'asked',
        outcome: outcome({ listening: [], listenersRead: false }),
        interventions: ['Booted with init=/bin/sh …'],
        open: [],
      },
    });
    expect(drafts[1]?.evidence).toMatchObject({ listening: [], listenersRead: false });
  });
});
