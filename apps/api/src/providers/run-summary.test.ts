import { describe, expect, it } from 'vitest';
import { type RunInput, groupRunsByTarget, summarizeRun } from './run-summary.js';

const job = (over: Partial<RunInput>): RunInput => ({
  id: 'j1',
  kind: 'dynprobe',
  status: 'done',
  createdAt: 1000,
  updatedAt: 2000,
  params: null,
  resultJson: null,
  error: null,
  ...over,
});

describe('summarizeRun — status is the process, outcome is what was learned', () => {
  it('never lets a finished process read as a clean result', () => {
    // The whole point of two fields. Both of these are `done`; one proved a bug and one proved nothing.
    const crash = summarizeRun(
      job({
        params: JSON.stringify({ binary: 'pwnable/Intro/stack_bof_01', sink: 'strcpy', patternLength: 400 }),
        resultJson: JSON.stringify({ probe: { verdict: 'crash_input_controlled', controlOffset: { offset: 204 } } }),
      }),
    );
    expect(crash.status).toBe('done');
    expect(crash.outcome).toBe('proven');
    expect(crash.headline).toContain('offset 204');

    const nothing = summarizeRun(
      job({ params: JSON.stringify({ binary: 'a' }), resultJson: JSON.stringify({ probe: { verdict: 'ran_clean' } }) }),
    );
    expect(nothing.status).toBe('done');
    expect(nothing.outcome).toBe('empty');
  });

  it('grades a sandbox shortfall as BLOCKED, which is not a negative result', () => {
    // Real DVRF: diag_tracertbutton dies for want of /dev/nvram. The question was asked and could not be answered.
    const r = summarizeRun(
      job({
        params: JSON.stringify({ binary: 'sbin/diag_tracertbutton', sink: 'sprintf' }),
        resultJson: JSON.stringify({ probe: { verdict: 'emulation_artifact' } }),
      }),
    );
    expect(r.outcome).toBe('blocked');
    expect(r.outcome).not.toBe('empty');
    expect(r.question).toBe('sprintf');
  });

  it('carries the bound the run operated under, so a result is never read as unbounded', () => {
    const r = summarizeRun(
      job({
        params: JSON.stringify({ binary: 'a', sink: 'strcpy', patternLength: 400 }),
        resultJson: JSON.stringify({ probe: { verdict: 'sink_executed' } }),
      }),
    );
    expect(r.bound).toBe('400-byte cyclic input');
    expect(r.outcome).toBe('lead');
  });

  it('reads a reachability proof, and refuses to call a spent budget a negative', () => {
    const reached = summarizeRun(
      job({
        kind: 'symreach',
        params: JSON.stringify({ binary: 'sbin/diag_tracertbutton', budgetSeconds: 180 }),
        resultJson: JSON.stringify({ sinks: [{ sink: 'sprintf', outcome: 'reached' }] }),
      }),
    );
    expect(reached.outcome).toBe('proven');
    expect(reached.bound).toBe('180s budget');

    const expired = summarizeRun(
      job({
        kind: 'symreach',
        params: JSON.stringify({ binary: 'x' }),
        resultJson: JSON.stringify({ sinks: [{ sink: 'strcpy', outcome: 'not_reached_in_budget' }] }),
      }),
    );
    expect(expired.outcome).toBe('empty');
    expect(expired.headline).toContain('not proven unreachable');
  });

  it('states that a fuzz run finding nothing is not "no bug"', () => {
    const r = summarizeRun(
      job({ kind: 'fuzz', resultJson: JSON.stringify({ binary: 'x', crashes: 0, seconds: 60, harness: 'stdin' }) }),
    );
    expect(r.outcome).toBe('empty');
    expect(r.headline).toContain('not "no bug"');
    expect(r.bound).toBe('60s');
  });

  it('separates a missing tool from an empty answer, for every kind that has one', () => {
    for (const kind of ['dynprobe', 'symreach', 'fuzz', 'decompile', 'renode', 'webprobe']) {
      const r = summarizeRun(job({ kind, resultJson: JSON.stringify({ available: false, reason: 'tool absent' }) }));
      expect(r.outcome, kind).toBe('blocked');
    }
  });

  it('is honest about a job that finished and stored nothing', () => {
    const r = summarizeRun(job({ resultJson: null }));
    expect(r.outcome).toBe('failed');
    expect(r.headline).toContain('stored no result');
  });

  it('reports a still-running job as running, never as an empty result', () => {
    expect(summarizeRun(job({ status: 'running' })).outcome).toBe('running');
    expect(summarizeRun(job({ status: 'queued' })).outcome).toBe('running');
  });

  it('surfaces the error text when the harness broke', () => {
    const r = summarizeRun(job({ status: 'error', error: 'gdb produced no output' }));
    expect(r.outcome).toBe('failed');
    expect(r.headline).toBe('gdb produced no output');
  });

  it('does not invent a reading for a kind it does not know', () => {
    const r = summarizeRun(job({ kind: 'gitleaks', resultJson: JSON.stringify({ anything: 1 }) }));
    expect(r.headline).toContain('open the run for its full result');
  });

  it('survives malformed stored JSON rather than throwing mid-listing', () => {
    const r = summarizeRun(job({ params: '{not json', resultJson: '{also not' }));
    expect(r.outcome).toBe('failed');
  });
});

describe('groupRunsByTarget', () => {
  const runs = [
    summarizeRun(job({ id: 'a', createdAt: 10, params: JSON.stringify({ binary: 'bin/one' }), resultJson: '{}' })),
    summarizeRun(job({ id: 'b', createdAt: 30, params: JSON.stringify({ binary: 'bin/two' }), resultJson: '{}' })),
    summarizeRun(job({ id: 'c', createdAt: 20, params: JSON.stringify({ binary: 'bin/one' }), resultJson: '{}' })),
    summarizeRun(job({ id: 'd', createdAt: 40, kind: 'extract', resultJson: '{}' })),
  ];

  it('groups by target and orders each target newest first', () => {
    const g = groupRunsByTarget(runs);
    const one = g.find((x) => x.target === 'bin/one');
    expect(one?.runs.map((r) => r.jobId)).toEqual(['c', 'a']);
  });

  it('keeps image-wide runs instead of dropping them, and puts them last as context', () => {
    const g = groupRunsByTarget(runs);
    expect(g[g.length - 1]?.target).toBeNull();
    expect(g[g.length - 1]?.runs.map((r) => r.jobId)).toEqual(['d']);
    // Nothing is lost in the grouping — four runs in, four runs out.
    expect(g.reduce((n, x) => n + x.runs.length, 0)).toBe(runs.length);
  });

  it('orders targets by their most recent activity', () => {
    const g = groupRunsByTarget(runs).filter((x) => x.target !== null);
    expect(g.map((x) => x.target)).toEqual(['bin/two', 'bin/one']);
  });
});
