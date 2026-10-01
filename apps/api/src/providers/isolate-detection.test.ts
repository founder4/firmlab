import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { probe } = vi.hoisted(() => ({ probe: vi.fn() }));
vi.mock('node:child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:child_process')>()),
  execFile: probe,
}));

describe('isolation capability detection', () => {
  beforeEach(() => {
    vi.resetModules();
    probe.mockReset();
    vi.stubGlobal('process', { ...process, platform: 'linux' });
  });
  afterEach(() => vi.unstubAllGlobals());

  function availableWhen(available: (file: string, args: string[]) => boolean) {
    probe.mockImplementation((file, args, _options, callback) => {
      callback(available(file, args) ? null : new Error('operation not permitted'), '', '');
    });
  }

  it('never promotes network and resource restrictions to full containment', async () => {
    availableWhen(() => true);
    const { detectIsolation, detectIsolationPosture } = await import('./isolate.js');
    expect(await detectIsolation()).toBe('partial');
    expect(await detectIsolationPosture()).toEqual({ level: 'partial', netns: '-n', resourceLimits: true });
    expect(probe.mock.calls.map((call) => call.slice(0, 2))).toEqual([
      ['prlimit', ['--cpu=1', '--', 'true']],
      ['unshare', ['-n', 'true']],
    ]);
  });

  it('rootless network namespaces also remain partial', async () => {
    availableWhen((file, args) => file === 'prlimit' || args[0] === '-rn');
    const { detectIsolation, detectIsolationPosture } = await import('./isolate.js');
    expect(await detectIsolation()).toBe('partial');
    expect(await detectIsolationPosture()).toEqual({ level: 'partial', netns: '-rn', resourceLimits: true });
    expect(probe).toHaveBeenCalledTimes(3);
  });

  it('does not treat a failed resource-limit probe as available', async () => {
    availableWhen(() => false);
    const { detectIsolation } = await import('./isolate.js');
    expect(await detectIsolation()).toBe('none');
    expect(probe).toHaveBeenCalledTimes(1);
  });
  it('reports host networking when only prlimit is usable', async () => {
    availableWhen((file) => file === 'prlimit');
    const { detectIsolationPosture } = await import('./isolate.js');
    expect(await detectIsolationPosture()).toEqual({ level: 'partial', netns: null, resourceLimits: true });
  });

  it('coalesces simultaneous probes and protects the cached result from callers', async () => {
    availableWhen(() => true);
    const { detectIsolationPosture } = await import('./isolate.js');
    const [first, second] = await Promise.all([detectIsolationPosture(), detectIsolationPosture()]);
    expect(probe).toHaveBeenCalledTimes(2);
    first.netns = null;
    expect(second.netns).toBe('-n');
    expect((await detectIsolationPosture()).netns).toBe('-n');
  });

  it('reports no restrictions off Linux without probing binaries', async () => {
    vi.stubGlobal('process', { ...process, platform: 'darwin' });
    const { detectIsolationPosture } = await import('./isolate.js');
    expect(await detectIsolationPosture()).toEqual({ level: 'none', netns: null, resourceLimits: false });
    expect(probe).not.toHaveBeenCalled();
  });
});
