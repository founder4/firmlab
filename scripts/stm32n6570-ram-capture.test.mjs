import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const repo = path.resolve(import.meta.dirname, '..');
const script = path.join(repo, 'apps/api/scripts/stm32n6570-ram-capture.sh');

test('STM32N6570 capture dry-run disables listeners and preserves explicit bounds', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-stm32n6-test-'));
  try {
    const target = path.join(directory, 'stm32n6.cfg');
    fs.writeFileSync(target, '# fixture only\n');
    const output = path.join(directory, 'capture.bin');
    const result = spawnSync(
      script,
      ['--dry-run', '--target', target, '--base', '0x34180000', '--size', '0x40000', '--output', output],
      { encoding: 'utf8' },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /gdb\\ port\\ disabled/);
    assert.match(result.stdout, /telnet\\ port\\ disabled/);
    assert.match(result.stdout, /dump_image/);
    assert.match(result.stdout, /0x34180000/);
    assert.match(result.stdout, /0x40000/);
    assert.equal(fs.existsSync(output), false);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test('STM32N6570 capture refuses guessed or unsafe inputs before hardware access', () => {
  const missing = spawnSync(script, ['--dry-run'], { encoding: 'utf8' });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /will not guess/);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-stm32n6-test-'));
  try {
    const target = path.join(directory, 'stm32n6.cfg');
    fs.writeFileSync(target, '# fixture only\n');
    const unsafe = spawnSync(
      script,
      [
        '--dry-run',
        '--target',
        target,
        '--base',
        '0x34180000;shutdown',
        '--size',
        '4096',
        '--output',
        path.join(directory, 'capture.bin'),
      ],
      { encoding: 'utf8' },
    );
    assert.equal(unsafe.status, 2);
    assert.match(unsafe.stderr, /hexadecimal address/);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});
