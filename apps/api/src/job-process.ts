/** Owned tools get private process groups. Cancellation targets those groups, never process names. */
import {
  type ChildProcess,
  type ExecFileOptions,
  type SpawnOptions,
  execFile as nativeExecFile,
  spawn as nativeSpawn,
} from 'node:child_process';
import { promisify } from 'node:util';
import { jobCancellation } from './job-cancellation.js';

export const spawn: typeof nativeSpawn = ((file: string, args: string[], options: SpawnOptions = {}) => {
  const owner = jobCancellation.getStore();
  owner?.check();
  const child = nativeSpawn(file, args, { ...options, ...(owner ? { detached: process.platform !== 'win32' } : {}) });
  owner?.track(child);
  return child;
}) as typeof nativeSpawn;

export function terminateJobProcess(child: ChildProcess): void {
  const owner = jobCancellation.getStore();
  if (owner) owner.terminate(child);
  else child.kill('SIGKILL');
}

export const execFile: typeof nativeExecFile = ((...args: Parameters<typeof nativeExecFile>) =>
  nativeExecFile(...args)) as typeof nativeExecFile;
Object.defineProperty(execFile, promisify.custom, {
  value: (file: string, args: string[], options: ExecFileOptions = {}) => {
    if (!jobCancellation.getStore()) return promisify(nativeExecFile)(file, args, options);
    return new Promise((resolve, reject) => {
      const child = spawn(file, args, { ...options, timeout: 0, stdio: ['ignore', 'pipe', 'pipe'] });
      const output: Record<'stdout' | 'stderr', Buffer[]> = { stdout: [], stderr: [] };
      const sizes = { stdout: 0, stderr: 0 };
      let failure: Error | null = null;
      const kill = () => {
        const owner = jobCancellation.getStore();
        if (owner) {
          try {
            owner.terminate(child);
          } catch (error) {
            failure = error as Error;
          }
          return;
        }
        if (!child.pid) return;
        try {
          process.kill(process.platform === 'win32' ? child.pid : -child.pid, 'SIGKILL');
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ESRCH') failure = error as Error;
        }
      };
      const timer = options.timeout
        ? setTimeout(() => {
            failure = Object.assign(new Error(`${file} timed out`), { killed: true, code: 'ETIMEDOUT' });
            kill();
          }, options.timeout)
        : null;
      const append = (chunk: Buffer, stream: 'stdout' | 'stderr') => {
        const max = options.maxBuffer ?? 1024 * 1024;
        const remaining = Math.max(0, max - sizes[stream]);
        if (remaining > 0) output[stream].push(chunk.subarray(0, remaining));
        sizes[stream] += chunk.length;
        if (sizes[stream] > max) {
          failure = Object.assign(new Error(`${stream} exceeded maxBuffer`), {
            code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER',
          });
          kill();
        }
      };
      child.stdout?.on('data', (chunk: Buffer) => append(chunk, 'stdout'));
      child.stderr?.on('data', (chunk: Buffer) => append(chunk, 'stderr'));
      child.once('error', (error) => {
        failure = error;
      });
      child.once('close', (code, signal) => {
        if (timer) clearTimeout(timer);
        const decode = (stream: 'stdout' | 'stderr') => {
          const bytes = Buffer.concat(output[stream]);
          return options.encoding === 'buffer' || options.encoding === null
            ? bytes
            : bytes.toString((options.encoding ?? 'utf8') as BufferEncoding);
        };
        const stdout = decode('stdout');
        const stderr = decode('stderr');
        if (failure || code !== 0)
          reject(
            Object.assign(failure ?? new Error(`${file} exited with ${code}`), {
              stdout,
              stderr,
              ...(failure ? {} : { code }),
              signal,
              killed: signal !== null,
            }),
          );
        else resolve({ stdout, stderr });
      });
    });
  },
});
