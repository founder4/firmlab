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
    const { detectIsolation } = await import('./isolate.js');
    expect(await detectIsolation()).toBe('partial');
    expect(probe.mock.calls.map((call) => call.slice(0, 2))).toEqual([
      ['prlimit', ['--cpu=1', '--', 'true']],
      ['unshare', ['-n', 'true']],
    ]);
  });

  it('rootless network namespaces also remain partial', async () => {
    availableWhen((file, args) => file === 'prlimit' || args[0] === '-rn');
    const { detectIsolation } = await import('./isolate.js');
    expect(await detectIsolation()).toBe('partial');
    expect(probe).toHaveBeenCalledTimes(3);
  });

  it('does not treat a failed resource-limit probe as available', async () => {
    availableWhen(() => false);
    const { detectIsolation } = await import('./isolate.js');
    expect(await detectIsolation()).toBe('none');
    expect(probe).toHaveBeenCalledTimes(1);
  });
});
