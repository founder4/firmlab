import { describe, expect, it } from 'vitest';
import { selectExportReachTargets } from './opacidad-exportreach.js';

describe('selectExportReachTargets', () => {
  it('selects only shared objects/modules and prioritizes dangerous imports deterministically', () => {
    const selection = selectExportReachTargets(
      [
        { path: 'usr/bin/httpd', size: 10, networkFacing: 1, importsSummary: 'system' },
        { path: 'lib/libquiet.so', size: 5, networkFacing: 0, importsSummary: null },
        { path: 'lib/libdanger.so.1', size: 200, networkFacing: 0, importsSummary: 'strcpy,memcpy' },
        { path: 'lib/modules/net.ko', size: 300, networkFacing: 0, importsSummary: 'copy_from_user' },
      ],
      2,
    );
    expect(selection.targets).toEqual(['lib/modules/net.ko', 'lib/libdanger.so.1']);
  });

  it('reports the real .so/.ko pool the cap is drawn from, not the whole inventory', () => {
    const selection = selectExportReachTargets(
      [
        { path: 'usr/bin/httpd', size: 10, networkFacing: 1, importsSummary: 'system' }, // not an object
        { path: 'lib/a.so', size: 5, networkFacing: 0, importsSummary: null },
        { path: 'lib/b.so', size: 6, networkFacing: 0, importsSummary: null },
        { path: 'lib/c.so', size: 7, networkFacing: 0, importsSummary: null },
      ],
      2,
    );
    // Pool counts only the three objects, not httpd; dropped and rule declare the cut so the set is not a silent artifact.
    expect(selection.total).toBe(3);
    expect(selection.dropped).toBe(1);
    expect(selection.rule).toContain('2 of 3');
    expect(selection.rule).toMatch(/not selected/);
  });

  it('uses size then path as stable tie-breakers and respects a zero cap', () => {
    const candidates = [
      { path: 'lib/b.so', size: 20, networkFacing: 0, importsSummary: null },
      { path: 'lib/a.so', size: 20, networkFacing: 0, importsSummary: null },
      { path: 'lib/c.so', size: 10, networkFacing: 0, importsSummary: null },
    ];
    expect(selectExportReachTargets(candidates, 2).targets).toEqual(['lib/c.so', 'lib/a.so']);
    expect(selectExportReachTargets(candidates, 0).targets).toEqual([]);
  });
});
