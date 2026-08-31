import { spawn } from 'node:child_process';

export interface ExecProcessGroupOptions {
  timeout: number;
  maxBuffer: number;
}

export interface ExecProcessGroupResult {
  stdout: string;
  stderr: string;
}

/**
 * Run a command under a wall-clock bound and kill its whole Unix process group on timeout.
 *
 * Node's built-in `execFile({ timeout })` only signals the direct child.  Tools such as the
 * FwHunt Python wrapper start rizin below that child, so killing Python alone leaves rizin
 * consuming CPU.  A detached child becomes the leader of a fresh process group; a negative
 * PID then targets the leader and every descendant in that group.
 */
export function execFileProcessGroup(
  file: string,
  args: readonly string[],
  options: ExecProcessGroupOptions,
): Promise<ExecProcessGroupResult> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const grouped = process.platform !== 'win32';
    const child = spawn(file, [...args], { detached: grouped, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    };

    const killGroup = () => {
      if (!child.pid) return;
      try {
        if (grouped) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== 'ESRCH') child.kill('SIGKILL');
      }
    };

    const append = (stream: 'stdout' | 'stderr', chunk: Buffer) => {
      if (settled) return;
      if (stream === 'stdout') stdout += chunk.toString('utf8');
      else stderr += chunk.toString('utf8');
      const length = Buffer.byteLength(stream === 'stdout' ? stdout : stderr);
      if (length <= options.maxBuffer) return;
      killGroup();
      finish(
        Object.assign(new Error(`${stream} exceeded maxBuffer of ${options.maxBuffer} bytes`), {
          code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER',
          killed: true,
          signal: 'SIGKILL',
        }),
      );
    };

    child.stdout.on('data', (chunk: Buffer) => append('stdout', chunk));
    child.stderr.on('data', (chunk: Buffer) => append('stderr', chunk));
    child.once('error', (error) => finish(Object.assign(error, { killed: false })));
    child.once('close', (code, signal) => {
      if (code === 0) finish();
      else
        finish(
          Object.assign(new Error(`${file} exited with code ${code ?? 'null'}${signal ? ` (${signal})` : ''}`), {
            code,
            killed: signal !== null,
            signal,
          }),
        );
    });

    const timer = setTimeout(() => {
      killGroup();
      finish(
        Object.assign(new Error(`${file} timed out after ${options.timeout} ms`), {
          code: 'ETIMEDOUT',
          killed: true,
          signal: 'SIGKILL',
        }),
      );
    }, options.timeout);
  });
}
