import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { describe, expect, it } from 'vitest';
import { type IsolationLimits, buildIsolatedInvocation, loadIsolationLimits, runIsolated } from './isolate.js';

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

  it('omits the address-space cap when addressSpaceBytes <= 0 (managed runtimes abort under --as)', () => {
    const { args } = buildIsolatedInvocation(argv, { ...limits, addressSpaceBytes: 0 }, 'full');
    expect(args.some((a) => a.startsWith('--as='))).toBe(false);
    // the other caps still apply
    expect(args).toContain('--cpu=30');
    expect(args).toContain('--nofile=256');
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

  it('partial: preserves a usable network namespace without claiming full containment', () => {
    const { file, args } = buildIsolatedInvocation(argv, limits, 'partial', ['-rn']);
    expect(file).toBe('unshare');
    expect(args.slice(0, 2)).toEqual(['-rn', 'prlimit']);
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

describe.skipIf(process.platform === 'win32')('runIsolated process cleanup', () => {
  it('kills a background descendant on timeout before it can write outside the workdir', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-isolation-test-'));
    const marker = path.join(dir, 'escaped-child');
    try {
      const result = await runIsolated(
        ['/bin/sh', '-c', '(sleep 0.8; touch "$1") & echo started; wait', 'test', marker],
        { limits: { ...limits, wallMs: 300 } },
      );
      expect(result.stdout).toContain('started');
      expect(result.timedOut).toBe(true);
      expect(result.signal).toBe('SIGKILL');
      await delay(700);
      expect(fs.existsSync(marker)).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
