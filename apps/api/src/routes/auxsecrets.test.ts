import { describe, expect, it } from 'vitest';
import { latestExtractionInputs } from './auxsecrets.js';

describe('auxsecrets extraction input selection', () => {
  it('uses the newest readable completed extraction and preserves a missing rootfs', () => {
    expect(
      latestExtractionInputs([
        { kind: 'extract', status: 'done', resultJson: '{broken' },
        { kind: 'extract', status: 'error', resultJson: JSON.stringify({ outputDir: '/wrong' }) },
        { kind: 'extract', status: 'done', resultJson: JSON.stringify({ outputDir: '/carved', rootfsPath: null }) },
        { kind: 'extract', status: 'done', resultJson: JSON.stringify({ outputDir: '/old' }) },
      ]),
    ).toEqual({ outputDir: '/carved', rootfsPath: null });
  });

  it('returns null rather than inventing an extraction directory', () => {
    expect(latestExtractionInputs([{ kind: 'extract', status: 'done', resultJson: '{}' }])).toBeNull();
  });
});
