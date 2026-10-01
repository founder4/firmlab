import { expect, it } from 'vitest';
import { procGroupMember } from './process-group.js';
it('reads process group and distinguishes live processes from zombie-only groups', () => {
  expect(procGroupMember('12 (name with ) spaces) S 1 12 12 0')).toEqual({ group: 12, live: true });
  expect(procGroupMember('13 (child) Z 1 12 12 0')).toEqual({ group: 12, live: false });
  expect(procGroupMember('13 (child) X 1 12 12 0')).toEqual({ group: 12, live: false });
  expect(procGroupMember('unreadable')).toBeNull();
});
