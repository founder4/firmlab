import { describe, expect, it } from 'vitest';
import {
  FIRMADYNE_KERNEL_NAMES,
  TEARDOWN_PATTERNS,
  buildChrootServiceArgs,
  buildFullSystemArgs,
  classifyFullSystem,
  guestNetwork,
  isTlsSpeaker,
  libnvramHostPath,
  looksBooted,
  probePlanFor,
} from './emulate-system.js';

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

  it('an answered TCP port is the strongest result this rung can produce', () => {
    const r = classifyFullSystem([{ host: 8081, guest: 80 }], quiet, true);
    expect(r.proofState).toBe('confirmed_full_system');
    expect(r.reason).toContain('answered TCP');
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
  it('reports what ANSWERED, and the wording says a reply rather than an accept', () => {
    // The distinction cost a false `confirmed_full_system`: qemu's user networking completes the host-side
    // handshake before it knows whether the guest will take it, and a stray emulator from an earlier run —
    // never swept, because `pkill` is not installed here — held the fixed port and answered the probe while the
    // guest kernel was still at NR_IRQS.
    const r = classifyFullSystem([{ host: 41234, guest: 80 }], { booted: false, marker: null, panicked: false }, true);
    expect(r.proofState).toBe('confirmed_full_system');
    expect(r.reason).toContain('accepted a connection');
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
});
