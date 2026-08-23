import { describe, expect, it } from 'vitest';
import { AGENT_PREAPPROVE_KEY, approvedTargets, resolveAgentApproval } from './approval.js';

describe('agent approval policy', () => {
  it('keeps manual approval as the default and reports environment provenance', () => {
    expect(resolveAgentApproval({})).toEqual({
      key: AGENT_PREAPPROVE_KEY,
      preapproveAll: false,
      source: 'default',
      environmentValue: false,
    });
    expect(resolveAgentApproval({ [AGENT_PREAPPROVE_KEY]: '1' })).toMatchObject({
      preapproveAll: true,
      source: 'environment',
      environmentValue: true,
    });
  });

  it('lets the persisted override win without hiding the environment value', () => {
    expect(resolveAgentApproval({ [AGENT_PREAPPROVE_KEY]: '1' }, '0')).toMatchObject({
      preapproveAll: false,
      source: 'override',
      environmentValue: true,
    });
  });

  it('selects one target or every unique proposed target in proposal order', () => {
    const plan = [
      { binary: 'bin/busybox', rung: 'qemu-user' },
      { binary: 'usr/bin/hostapd', rung: 'full-system' },
      { binary: 'bin/busybox', rung: 'full-system' },
    ];
    expect(approvedTargets(plan, { binary: 'usr/bin/hostapd' })).toEqual([plan[1]]);
    expect(approvedTargets(plan, { all: true })).toEqual([plan[0], plan[1]]);
    expect(approvedTargets(plan, { binary: 'missing' })).toEqual([]);
  });
});
