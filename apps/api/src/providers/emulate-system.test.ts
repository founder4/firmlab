import { describe, expect, it } from 'vitest';
import {
  TEARDOWN_PATTERNS,
  buildChrootServiceArgs,
  buildFullSystemArgs,
  classifyFullSystem,
  libnvramHostPath,
  looksBooted,
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
