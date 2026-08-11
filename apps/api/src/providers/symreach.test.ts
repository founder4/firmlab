import { describe, expect, it } from 'vitest';
import type { BinAssessment } from './binvuln.js';
import type { JobHandle } from './jobs.js';
import {
  MAX_SINKS,
  buildReachFindings,
  buildSpec,
  manualSource,
  nothingToAsk,
  parseReachOutput,
  pickSinks,
  runSymReach,
  unavailable,
  validateSinkNames,
} from './symreach.js';

/** The runner only ever calls `log` on its handle, and these cases return before it does. */
const silentHandle = { log: () => {} } as unknown as JobHandle;

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

  /**
   * Why W9's command-exec specs MUST carry `policy: 'as-given'`, pinned here because the first wiring of them did
   * not and the failure was silent-shaped. Under the default policy a command-exec sink set survives as NOTHING,
   * `runSymReach` returns `unavailable('no sink to ask about')`, and that composes a `blocked_by_platform` row
   * reading *"the deployment could not answer it"*. Measured: the WR940N's `usr/bin/httpd` came back blocked from
   * an autonomous scan minutes after the manual route proved `system` reachable in that same binary in 11 s.
   */
  it('deletes an entire command-exec question under the DEFAULT policy, which is why the caller must say', () => {
    expect(pickSinks(['system', 'popen', 'execve']).asked).toEqual([]);
    expect(pickSinks(['system', 'popen', 'execve'], 'as-given').asked).toEqual(['system', 'popen', 'execve']);
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

/**
 * The conflation `a20f2850` paid for, pinned at the constructor.
 *
 * That commit fixed the CALLER — W9 now says `as-given` for a command-exec question — and left the provider still
 * willing to blame the deployment for anything at all that went wrong. `blocked_by_platform` means *"the question
 * was asked and this deployment could not answer it"*, and a row saying that is read as a real limit: it is
 * counted by coverage, composed into the narrative, and outlives the caller that produced it. A malformed request
 * is not that, and `dynprobe-run.ts` had already drawn the same line one provider earlier.
 */
describe('unavailable — a caller error must not be reported as a capability limit', () => {
  it('writes NO finding when the question could not be posed', () => {
    const r = unavailable('usr/bin/httpd', "the 'unsafe-copy' policy kept none of the 3 name(s) requested", 'request');
    expect(r.available).toBe(false);
    expect(r.blockedBy).toBe('request');
    // The whole fix: nothing reaches the ledger. The reason still travels on the result.
    expect(r.findings).toEqual([]);
    expect(r.reason).toContain('unsafe-copy');
  });

  it('still records a genuine platform limit, because absence of a tool is not absence of a problem', () => {
    const r = unavailable('usr/bin/httpd', 'angr not installed in this deployment');
    expect(r.blockedBy).toBe('platform');
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]?.kind).toBe('sink-reachability-blocked');
    expect(r.findings[0]?.proofState).toBe('blocked_by_platform');
    expect(r.findings[0]?.rationale).toContain('missing capability');
  });

  it('separates a broken attempt from a missing capability, since only one is worth retrying', () => {
    const r = unavailable('usr/bin/httpd', 'angr probe produced no output', 'harness');
    expect(r.blockedBy).toBe('harness');
    // Both keep `blocked_by_platform` — the vocabulary has no third state and inventing one here would be worse.
    expect(r.findings[0]?.proofState).toBe('blocked_by_platform');
    expect(r.findings[0]?.rationale).toContain('retry may');
  });

  it('refuses a run with no rootfs as a request defect, not as something this deployment cannot do', async () => {
    const r = await runSymReach(null, 'usr/bin/httpd', ['strcpy'], silentHandle);
    expect(r.blockedBy).toBe('request');
    expect(r.findings).toEqual([]);
  });
});

describe('nothingToAsk — a binary with no unbounded-copy symbol is ANSWERED, not blocked', () => {
  const assess = (over: Partial<BinAssessment> = {}): BinAssessment => ({
    path: 'usr/sbin/tiny',
    size: 4096,
    runnable: true,
    unsafeCopy: [],
    cmdExec: [],
    hasCanary: true,
    symbolSource: 'dynsym',
    ...over,
  });

  it('is a bounded negative about the bytes, and says what it does not cover', () => {
    const r = nothingToAsk('usr/sbin/tiny', assess());
    expect(r.available).toBe(true);
    expect(r.asked).toEqual([]);
    const d = r.findings[0];
    expect(d?.kind).toBe('sink-reachability-not-applicable');
    expect(d?.proofState).toBe('static_confirmed');
    // The claim is about symbols, and the row has to say so itself — an inlined copy leaves nothing to read.
    expect(d?.rationale).toContain('does NOT say the binary contains no unbounded copy');
    expect(d?.rationale).toContain('inlined');
  });

  it('names the weaker evidence when there was no symbol table to read', () => {
    const r = nothingToAsk('usr/sbin/tiny', assess({ symbolSource: 'strings' }));
    expect(r.reason).toContain('printable-string superset');
    expect(r.findings[0]?.evidence).toMatchObject({ symbolSource: 'strings' });
  });

  it('points at the sinks the binary DOES name, so the answer is not read as "uninteresting"', () => {
    const r = nothingToAsk('usr/sbin/tiny', assess({ cmdExec: ['system', 'popen'] }));
    expect(r.findings[0]?.rationale).toContain('system, popen');
  });
});
