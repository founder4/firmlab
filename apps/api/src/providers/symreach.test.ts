import { describe, expect, it } from 'vitest';
import { MAX_SINKS, buildReachFindings, buildSpec, parseReachOutput, pickSinks } from './symreach.js';

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
      { sink: 'strcpy', outcome: 'reached', addresses: ['0x4008a0'], steps: 9, pruned: false, argv1: 'AAAA' },
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
        reason: 'step budget (400 steps) reached',
      },
    ]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('sink-reachability-inconclusive');
    expect(drafts[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(drafts[0]?.rationale).toContain('NOT evidence they are unreachable');
    expect(drafts[0]?.evidence?.statesPruned).toBe(true);
  });

  it('a sink whose symbol is absent produces no claim at all', () => {
    const drafts = buildReachFindings('bin/pwn', [
      { sink: 'gets', outcome: 'absent', addresses: [], steps: 0, pruned: false, reason: 'no PLT/symbol address' },
    ]);
    expect(drafts).toEqual([]);
  });

  it('mixes a confirmed reachability with an inconclusive note in one run', () => {
    const drafts = buildReachFindings('bin/pwn', [
      { sink: 'strcpy', outcome: 'reached', addresses: ['0x1'], steps: 5, pruned: false },
      { sink: 'gets', outcome: 'not_reached_in_budget', addresses: ['0x2'], steps: 400, pruned: false },
    ]);
    expect(drafts.map((d) => d.kind)).toEqual(['sink-reachable', 'sink-reachability-inconclusive']);
  });
});
