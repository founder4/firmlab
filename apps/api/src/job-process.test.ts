/** Provider compatibility: binary stdout and error metadata must survive cancellation-aware execution. */
import { promisify } from 'node:util';
import { describe, expect, it, vi } from 'vitest';
import { classifyGroupSignalRefusal, psGroupMembers } from './group-signal-refusal.js';
import { JobCancellation, jobCancellation } from './job-cancellation.js';
import { execFile } from './job-process.js';

const exec = promisify(execFile);
const owned = async <T>(work: () => Promise<T>, owner = new JobCancellation()) => {
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

  it('preserves the provider error when a restricted procfs prevents socket discovery', async () => {
    const denied = new JobCancellation(() => {
      throw Object.assign(new Error('permission denied, scandir /proc/123/fd'), { code: 'EACCES' });
    });
    await expect(
      owned(() => exec(process.execPath, ['-e', 'process.stdout.write("123456789")'], { maxBuffer: 4 }), denied),
    ).rejects.toMatchObject({ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', stdout: '1234' });
  });
});

describe('group signal refusal', () => {
  it('discharges EPERM only for a group whose every listed member, leader included, is a zombie', () => {
    const zombieLeader = [{ pid: 40, live: false }];
    expect(classifyGroupSignalRefusal('EPERM', 40, zombieLeader)).toBe('exited_unreaped');
    expect(classifyGroupSignalRefusal('EPERM', 40, [...zombieLeader, { pid: 41, live: false }])).toBe(
      'exited_unreaped',
    );
    // A live member the kernel refused to signal is a denial, whatever state the leader is in.
    expect(classifyGroupSignalRefusal('EPERM', 40, [...zombieLeader, { pid: 41, live: true }])).toBe('denied');
    expect(classifyGroupSignalRefusal('EPERM', 40, [{ pid: 40, live: true }])).toBe('denied');
    // The listing must show the group still holding its unreaped leader. Anything less proves nothing.
    expect(classifyGroupSignalRefusal('EPERM', 40, [{ pid: 41, live: false }])).toBe('denied');
    expect(classifyGroupSignalRefusal('EPERM', 40, [])).toBe('denied');
    expect(classifyGroupSignalRefusal('EPERM', 40, null)).toBe('denied');
    // Only the kernel's EPERM has the zombie reading. Every other refusal stays visible.
    expect(classifyGroupSignalRefusal('EACCES', 40, zombieLeader)).toBe('denied');
    expect(classifyGroupSignalRefusal(undefined, 40, zombieLeader)).toBe('denied');
  });

  it('reads group members from ps and refuses a listing it cannot parse', () => {
    const listing = '  40    40 Z\n  41    40 Z+\n  42    40 S+\n  43    99 R\n\n';
    expect(psGroupMembers(listing, 40)).toEqual([
      { pid: 40, live: false },
      { pid: 41, live: false },
      { pid: 42, live: true },
    ]);
    expect(psGroupMembers(listing, 7)).toEqual([]);
    expect(psGroupMembers('  40    40\n', 40)).toBeNull();
    expect(psGroupMembers('  40  pgid  Z\n', 40)).toBeNull();
  });
});

it.skipIf(process.platform === 'win32')(
  'keeps the maxBuffer error when the group kill lands on an exited but unreaped leader',
  async () => {
    // Holding the event loop lets the child write and exit before its stdout is read. The maxBuffer kill then
    // lands before libuv's SIGCHLD reap, and macOS answers EPERM for a group whose only member is a zombie.
    // That was the 2026-11-08 failure, which happened every time on this path before the fix.
    for (let attempt = 0; attempt < 3; attempt++) {
      await expect(
        owned(async () => {
          const pending = exec(process.execPath, ['-e', 'process.stdout.write("123456789")'], { maxBuffer: 4 });
          const until = Date.now() + 300;
          while (Date.now() < until) {}
          return pending;
        }),
      ).rejects.toMatchObject({ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', stdout: '1234' });
    }
  },
);

it.skipIf(process.platform === 'win32')('keeps a maxBuffer kill denial visible while the group is alive', async () => {
  const owner = new JobCancellation();
  const denied = Object.assign(new Error('kill denied'), { code: 'EPERM' });
  const kill = vi.spyOn(process, 'kill').mockImplementationOnce(() => {
    throw denied;
  });
  const timer = setTimeout(() => owner.cancel(), 250);
  try {
    const promise = jobCancellation.run(owner, () =>
      exec(process.execPath, ['-e', 'process.stdout.write("123456789"); setInterval(() => {}, 1000)'], {
        maxBuffer: 4,
      }),
    );
    await expect(promise).rejects.toBe(denied);
    await owner.cleanup();
  } finally {
    clearTimeout(timer);
    kill.mockRestore();
    owner.cancel();
    await owner.cleanup();
  }
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
                // Managed runtimes reserve large virtual/file mappings at startup; this test targets the wall timer.
                limits: { ...loadIsolationLimits(), addressSpaceBytes: 0, fileSizeBytes: 0, wallMs: 100 },
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
