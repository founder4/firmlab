/** Provider compatibility: binary stdout and error metadata must survive cancellation-aware execution. */
import { promisify } from 'node:util';
import { describe, expect, it, vi } from 'vitest';
import { JobCancellation, jobCancellation } from './job-cancellation.js';
import { execFile } from './job-process.js';

const exec = promisify(execFile);
const owned = async <T>(work: () => Promise<T>) => {
  const owner = new JobCancellation();
  try {
    return await jobCancellation.run(owner, work);
  } finally {
    await owner.cleanup();
  }
};

describe('owned execFile compatibility', () => {
  it('preserves binary bytes for buffer and null encodings', async () => {
    const script = 'process.stdout.write(Buffer.from([0, 255, 128, 65]))';
    for (const encoding of ['buffer', null] as const) {
      const { stdout } = await owned(() => exec(process.execPath, ['-e', script], { encoding }));
      expect(Buffer.isBuffer(stdout)).toBe(true);
      expect([...(stdout as Buffer)]).toEqual([0, 255, 128, 65]);
    }
  });
  it('decodes multibyte output once rather than corrupting split chunks', async () => {
    const script =
      'process.stdout.write(Buffer.from([0xe2])); setTimeout(() => process.stdout.write(Buffer.from([0x82, 0xac])), 30)';
    const { stdout } = await owned(() => exec(process.execPath, ['-e', script], {}));
    expect(stdout).toBe('€');
  });
  it('keeps original spawn, exit, timeout and maxBuffer error codes', async () => {
    await expect(owned(() => exec('/firmlab-nonexistent-tool', [], {}))).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(
      owned(() => exec(process.execPath, ['-e', 'console.error("detail"); process.exit(7)'], {})),
    ).rejects.toMatchObject({ code: 7, stderr: 'detail\n' });
    await expect(
      owned(() => exec(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { timeout: 100 })),
    ).rejects.toMatchObject({ code: 'ETIMEDOUT', killed: true });
    await expect(
      owned(() => exec(process.execPath, ['-e', 'process.stdout.write("123456789")'], { maxBuffer: 4 })),
    ).rejects.toMatchObject({ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', stdout: '1234' });
  });
});

it('records a timeout kill failure without throwing from the timer callback', async () => {
  const owner = new JobCancellation();
  const denied = Object.assign(new Error('kill denied'), { code: 'EPERM' });
  const kill = vi.spyOn(process, 'kill').mockImplementationOnce(() => {
    throw denied;
  });
  const timer = setTimeout(() => owner.cancel(), 250);
  try {
    const promise = jobCancellation.run(owner, () =>
      exec(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { timeout: 100 }),
    );
    await expect(promise).rejects.toMatchObject({ code: 'EPERM' });
    await owner.cleanup();
  } finally {
    clearTimeout(timer);
    kill.mockRestore();
    owner.cancel();
    await owner.cleanup();
  }
});

it.skipIf(process.platform === 'win32')(
  'keeps isolated and group-runner timer kill errors out of event callbacks',
  async () => {
    const { runIsolated, loadIsolationLimits } = await import('./providers/isolate.js');
    const { execFileProcessGroup } = await import('./exec-process-group.js');
    for (const isolated of [false, true]) {
      const owner = new JobCancellation();
      const denied = Object.assign(new Error('kill denied'), { code: 'EPERM' });
      const kill = vi.spyOn(process, 'kill').mockImplementationOnce(() => {
        throw denied;
      });
      try {
        const promise = jobCancellation.run(owner, () =>
          isolated
            ? runIsolated([process.execPath, '-e', 'setInterval(() => {}, 1000)'], {
                limits: { ...loadIsolationLimits(), wallMs: 100 },
              })
            : execFileProcessGroup(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
                timeout: 100,
                maxBuffer: 1024,
              }),
        );
        if (isolated) expect(await promise).toMatchObject({ timedOut: true });
        else await expect(promise).rejects.toMatchObject({ code: 'ETIMEDOUT' });
        await expect(owner.cleanup()).rejects.toMatchObject({ code: 'EPERM' });
      } finally {
        kill.mockRestore();
        owner.cancel();
        await owner.cleanup().catch(() => undefined);
      }
    }
  },
);
