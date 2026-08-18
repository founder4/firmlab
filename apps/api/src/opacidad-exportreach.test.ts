import { describe, expect, it } from 'vitest';
import { selectExportReachTargets } from './opacidad-exportreach.js';

describe('selectExportReachTargets', () => {
  it('selects only shared objects/modules and prioritizes dangerous imports deterministically', () => {
    const selected = selectExportReachTargets(
      [
        { path: 'usr/bin/httpd', size: 10, networkFacing: 1, importsSummary: 'system' },
        { path: 'lib/libquiet.so', size: 5, networkFacing: 0, importsSummary: null },
        { path: 'lib/libdanger.so.1', size: 200, networkFacing: 0, importsSummary: 'strcpy,memcpy' },
        { path: 'lib/modules/net.ko', size: 300, networkFacing: 0, importsSummary: 'copy_from_user' },
      ],
      2,
    );
    expect(selected).toEqual(['lib/modules/net.ko', 'lib/libdanger.so.1']);
  });

  it('uses size then path as stable tie-breakers and respects a zero cap', () => {
    const candidates = [
      { path: 'lib/b.so', size: 20, networkFacing: 0, importsSummary: null },
      { path: 'lib/a.so', size: 20, networkFacing: 0, importsSummary: null },
      { path: 'lib/c.so', size: 10, networkFacing: 0, importsSummary: null },
    ];
    expect(selectExportReachTargets(candidates, 2)).toEqual(['lib/c.so', 'lib/a.so']);
    expect(selectExportReachTargets(candidates, 0)).toEqual([]);
  });
});
