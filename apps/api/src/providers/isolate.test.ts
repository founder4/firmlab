import { describe, expect, it } from 'vitest';
import { type IsolationLimits, buildIsolatedInvocation, loadIsolationLimits } from './isolate.js';

const limits: IsolationLimits = {
  cpuSeconds: 30,
  addressSpaceBytes: 512 * 1024 * 1024,
  fileSizeBytes: 64 * 1024 * 1024,
  openFiles: 256,
  wallMs: 45000,
};

describe('buildIsolatedInvocation', () => {
  const argv = ['qemu-arm-static', '-L', '/rootfs', '/rootfs/bin/httpd'];

  it('full: wraps prlimit in a network namespace (no shell in the chain)', () => {
    const { file, args } = buildIsolatedInvocation(argv, limits, 'full');
    expect(file).toBe('unshare');
    expect(args[0]).toBe('-n');
    expect(args).toContain('prlimit');
    expect(args).toContain('--cpu=30');
    // the inner argv is passed verbatim after `--`, never through a shell
    expect(args.slice(-4)).toEqual(argv);
  });

  it('full: applies address-space, file-size, fd and core caps', () => {
    const { args } = buildIsolatedInvocation(argv, limits, 'full');
    expect(args).toContain(`--as=${512 * 1024 * 1024}`);
    expect(args).toContain(`--fsize=${64 * 1024 * 1024}`);
    expect(args).toContain('--nofile=256');
    expect(args).toContain('--core=0');
  });

  it('full: uses the rootless netns flag (-rn) when the probe found that works, no CAP_SYS_ADMIN needed', () => {
    const { file, args } = buildIsolatedInvocation(argv, limits, 'full', ['-rn']);
    expect(file).toBe('unshare');
    expect(args[0]).toBe('-rn');
    expect(args).toContain('prlimit');
    expect(args.slice(-4)).toEqual(argv);
  });

  it('partial: prlimit only, no unshare', () => {
    const { file, args } = buildIsolatedInvocation(argv, limits, 'partial');
    expect(file).toBe('prlimit');
    expect(args).not.toContain('unshare');
    expect(args).toContain('--cpu=30');
    expect(args.slice(-4)).toEqual(argv);
  });

  it('none: runs the argv unwrapped (caller must decide if acceptable)', () => {
    const { file, args } = buildIsolatedInvocation(argv, limits, 'none');
    expect(file).toBe('qemu-arm-static');
    expect(args).toEqual(['-L', '/rootfs', '/rootfs/bin/httpd']);
  });
});

describe('loadIsolationLimits', () => {
  it('conservative defaults', () => {
    const l = loadIsolationLimits({} as NodeJS.ProcessEnv);
    expect(l.cpuSeconds).toBe(30);
    expect(l.addressSpaceBytes).toBe(512 * 1024 * 1024);
    expect(l.wallMs).toBe(45000);
  });

  it('reads overrides and converts MB / seconds', () => {
    const l = loadIsolationLimits({
      FIRMLAB_ISOLATE_CPU: '10',
      FIRMLAB_ISOLATE_MEM_MB: '128',
      FIRMLAB_ISOLATE_WALL_SECONDS: '20',
    } as unknown as NodeJS.ProcessEnv);
    expect(l.cpuSeconds).toBe(10);
    expect(l.addressSpaceBytes).toBe(128 * 1024 * 1024);
    expect(l.wallMs).toBe(20000);
  });
});
