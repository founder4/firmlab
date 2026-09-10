import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readCapturedBodyBounded } from './body-inspection.js';

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function fixture(bytes: number[]): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-capture-body-'));
  dirs.push(dir);
  const file = path.join(dir, 'body.bin');
  fs.writeFileSync(file, Uint8Array.from(bytes));
  return file;
}

describe('readCapturedBodyBounded', () => {
  it('reports a complete read when the captured body fits', () => {
    const result = readCapturedBodyBounded(fixture([1, 2, 3, 4]), 8);
    expect([...result.body]).toEqual([1, 2, 3, 4]);
    expect(result).toMatchObject({ bodyBytes: 4, bodyBytesInspected: 4, bodyInspectionComplete: true });
  });

  it('scores a prefix without presenting it as the whole captured body', () => {
    const result = readCapturedBodyBounded(fixture([1, 2, 3, 4, 5, 6]), 4);
    expect([...result.body]).toEqual([1, 2, 3, 4]);
    expect(result).toMatchObject({ bodyBytes: 6, bodyBytesInspected: 4, bodyInspectionComplete: false });
  });

  it('reports an unavailable body instead of treating an I/O failure as an empty body', () => {
    const result = readCapturedBodyBounded('/definitely/not/a/capture-body.bin', 4);
    expect(result).toMatchObject({ bodyBytes: null, bodyBytesInspected: 0, bodyInspectionComplete: false });
  });
});
