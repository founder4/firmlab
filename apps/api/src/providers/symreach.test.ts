import { describe, expect, it } from 'vitest';
import {
  MAX_SINKS,
  buildReachFindings,
  buildSpec,
  manualSource,
  parseReachOutput,
  pickSinks,
  validateSinkNames,
} from './symreach.js';

describe('pickSinks — which questions are worth asking', () => {
  it('keeps only real unbounded-copy imports and orders them by directness', () => {
    const { asked } = pickSinks(['sprintf', 'gets', 'malloc', 'strcpy']);
    expect(asked).toEqual(['gets', 'strcpy', 'sprintf']); // malloc is not an unbounded-copy sink
  });

  it('caps the asked set and reports what was dropped rather than discarding it silently', () => {
    const { asked, dropped } = pickSinks(['gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf', 'scanf']);
    expect(asked).toHaveLength(MAX_SINKS);
    expect(dropped).toEqual(['vsprintf', 'scanf']);
  });

  it('asks nothing when the binary imports no unbounded-copy function', () => {
    expect(pickSinks(['memcpy', 'snprintf']).asked).toEqual([]);
  });

  // The autonomous path is settling a W5 candidate, so it filters. The manual route is an operator asking a
  // question of their own — "is system reachable in this CGI?" is the same question, and refusing it would be the
  // prober protecting its own framing rather than answering.
  it('keeps an operator’s own sink names verbatim under the as-given policy', () => {
    const { asked } = pickSinks(['system', 'memcpy', 'doSystem'], 'as-given');
    expect(asked).toEqual(['system', 'memcpy', 'doSystem']);
  });

  it('still spends the budget on the sharpest sink first in a mixed manual list', () => {
    expect(pickSinks(['memcpy', 'gets', 'system'], 'as-given').asked).toEqual(['gets', 'memcpy', 'system']);
  });

  it('dedupes a repeated manual sink instead of asking the same question twice', () => {
    expect(pickSinks(['system', 'system', ' system '], 'as-given').asked).toEqual(['system']);
  });
});

describe('validateSinkNames — a typo is reported, never silently answered as a smaller question', () => {
  it('separates symbol names from things that are not', () => {
    const { valid, rejected } = validateSinkNames(['strcpy', 'os.execute', '', '  system ', 'rm -rf']);
    expect(valid).toEqual(['strcpy', 'system']);
    expect(rejected).toEqual(['os.execute', 'rm -rf']);
  });
});

describe('manualSource — a second question must not delete the first answer', () => {
  // Caught in in-container validation on the real DVRF_v03: `system` proven reachable in usr/sbin/generate_pin
  // disappeared from the ledger when a later probe on the same binary asked about `sprintf` instead, because
  // findings sync by source and the source was the binary alone.
  it('keys a manual probe by the question, so different sinks accumulate', () => {
    expect(manualSource('usr/sbin/generate_pin', ['system'])).not.toBe(
      manualSource('usr/sbin/generate_pin', ['sprintf']),
    );
  });

  it('re-asking the same question re-syncs rather than duplicating, whatever the order', () => {
    expect(manualSource('bin/x', ['strcpy', 'system'])).toBe(manualSource('bin/x', ['system', 'strcpy']));
  });

  it('keeps the bare per-binary key when sinks are derived — that is the question W9 asks', () => {
    expect(manualSource('bin/x', [])).toBe('symreach:bin/x');
  });
});

describe('buildSpec', () => {
  it('carries the absolute binary, the sinks and the budgets', () => {
    const spec = buildSpec('/rootfs/bin/httpd', ['strcpy'], 30);
    expect(spec.binary).toBe('/rootfs/bin/httpd');
    expect(spec.sinks).toEqual(['strcpy']);
    expect(spec.budgetSeconds).toBe(30);
    expect(spec.maxSteps).toBeGreaterThan(0);
    expect(spec.maxActive).toBeGreaterThan(0);
  });
});

describe('parseReachOutput', () => {
  it('normalizes a successful probe run', () => {
    const p = parseReachOutput({
      ok: true,
      arch: 'MIPS32',
      entry: '0x400610',
      results: [
        {
          sink: 'strcpy',
          outcome: 'reached',
          addresses: ['0x4008a0'],
          steps: 12,
          pruned: false,
          errors: 0,
          argv1: 'AAAA',
          path: ['0x400700', '0x4008a0'],
        },
      ],
    });
    expect(p.ok).toBe(true);
    expect(p.arch).toBe('MIPS32');
    expect(p.sinks[0]?.outcome).toBe('reached');
    expect(p.sinks[0]?.argv1).toBe('AAAA');
    expect(p.sinks[0]?.path).toEqual(['0x400700', '0x4008a0']);
  });

  it('reports a probe failure rather than an empty success', () => {
    expect(parseReachOutput({ ok: false, error: 'angr not importable' })).toMatchObject({
      ok: false,
      error: 'angr not importable',
    });
    expect(parseReachOutput(null).ok).toBe(false);
  });

  it('treats an unrecognised outcome as inconclusive, never as a clean sink', () => {
    const p = parseReachOutput({ ok: true, results: [{ sink: 'gets', outcome: 'weird' }] });
    expect(p.sinks[0]?.outcome).toBe('not_reached_in_budget');
    expect(p.sinks[0]?.reason).toContain('unrecognised');
  });
});

describe('buildReachFindings — the honesty contract', () => {
  it('a reached sink is static_confirmed and phrased as reachability, not exploitability', () => {
    const drafts = buildReachFindings('bin/pwn', [
      {
        sink: 'strcpy',
        outcome: 'reached',
        addresses: ['0x4008a0'],
        steps: 9,
        pruned: false,
        errors: 0,
        argv1: 'AAAA',
      },
    ]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('sink-reachable');
    expect(drafts[0]?.proofState).toBe('static_confirmed');
    expect(drafts[0]?.evidence?.concreteInput).toContain('AAAA');
    expect(drafts[0]?.rationale).toContain('not exploitability');
  });

  it('an exhausted budget stays needs_runtime_reproduction and is never called unreachable', () => {
    const drafts = buildReachFindings('bin/pwn', [
      {
        sink: 'gets',
        outcome: 'not_reached_in_budget',
        addresses: ['0x400900'],
        steps: 400,
        pruned: true,
        errors: 0,
        reason: 'step budget (400 steps) reached',
      },
    ]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('sink-reachability-inconclusive');
    expect(drafts[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(drafts[0]?.rationale).toContain('NOT evidence they are unreachable');
    expect(drafts[0]?.evidence?.statesPruned).toBe(true);
  });

  it('attributes angr-internal crashes to the tool, not to the firmware', () => {
    // angr 9.2's sscanf SimProcedure raises a raw TypeError on a symbolic position. Those are paths never walked,
    // and the report must say so rather than let a reader infer the binary is quiet.
    const drafts = buildReachFindings('usr/sbin/bpalogin', [
      {
        sink: 'strcpy',
        outcome: 'not_reached_in_budget',
        addresses: ['0x5000c0'],
        steps: 40,
        pruned: false,
        errors: 13,
        reason: 'angr-internal errors dominated the search (13)',
      },
    ]);
    expect(drafts[0]?.title).not.toContain('budget ran out');
    expect(drafts[0]?.evidence?.toolErrors).toBe(13);
    expect(drafts[0]?.rationale).toContain('lost to angr-internal errors');
    expect(drafts[0]?.proofState).toBe('needs_runtime_reproduction');
  });

  it('a sink whose symbol is absent produces no claim at all', () => {
    const drafts = buildReachFindings('bin/pwn', [
      {
        sink: 'gets',
        outcome: 'absent',
        addresses: [],
        steps: 0,
        pruned: false,
        errors: 0,
        reason: 'no PLT/symbol address',
      },
    ]);
    expect(drafts).toEqual([]);
  });

  it('mixes a confirmed reachability with an inconclusive note in one run', () => {
    const drafts = buildReachFindings('bin/pwn', [
      { sink: 'strcpy', outcome: 'reached', addresses: ['0x1'], steps: 5, pruned: false, errors: 0 },
      { sink: 'gets', outcome: 'not_reached_in_budget', addresses: ['0x2'], steps: 400, pruned: false, errors: 0 },
    ]);
    expect(drafts.map((d) => d.kind)).toEqual(['sink-reachable', 'sink-reachability-inconclusive']);
  });
});
