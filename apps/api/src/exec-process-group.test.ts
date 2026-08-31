import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { execFileProcessGroup } from './exec-process-group.js';

async function processDisappeared(pid: number): Promise<boolean> {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') return true;
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return false;
}

describe('execFileProcessGroup', () => {
  it.skipIf(process.platform === 'win32')('kills descendants as well as the direct child on timeout', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'firmlab-process-group-'));
    const pidFile = path.join(dir, 'grandchild.pid');
    const script = [
      "const { spawn } = require('node:child_process');",
      "const { writeFileSync } = require('node:fs');",
      "const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });",
      `writeFileSync(${JSON.stringify(pidFile)}, String(child.pid));`,
      'setInterval(() => {}, 1000);',
    ].join('\n');

    try {
      await expect(
        execFileProcessGroup(process.execPath, ['-e', script], { timeout: 150, maxBuffer: 1024 * 1024 }),
      ).rejects.toMatchObject({ killed: true, signal: 'SIGKILL' });
      const grandchildPid = Number(readFileSync(pidFile, 'utf8'));
      expect(await processDisappeared(grandchildPid)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
