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

  /**
   * `blocked` tells an operator the deployment is short a capability, and that is a claim. Two of the three ways a
   * reachability run comes back unavailable are not that: the attempt broke (`harness`) or the question could not
   * be posed at all (`request`). Both are cleared by a corrected retry, and grading them `blocked` sends the
   * operator off to fix a deployment that is working — which is how `a20f2850` hid.
   */
  it('grades a symreach non-answer by WHOSE limit it was', () => {
    const grade = (blockedBy?: string) =>
      summarizeRun(
        job({
          kind: 'symreach',
          resultJson: JSON.stringify({
            available: false,
            reason: 'no sink to ask about',
            ...(blockedBy ? { blockedBy } : {}),
          }),
        }),
      ).outcome;
    expect(grade('platform')).toBe('blocked');
    expect(grade('harness')).toBe('failed');
    expect(grade('request')).toBe('failed');
    // A result stored by an older build carries no discriminant and keeps the conservative reading.
    expect(grade()).toBe('blocked');
  });

  it('lets a run that asked nothing say why, instead of implying the caller forgot', () => {
    const r = summarizeRun(
      job({
        kind: 'symreach',
        resultJson: JSON.stringify({
          available: true,
          sinks: [],
          reason: 'usr/sbin/tiny names none of the 8 unbounded-copy functions in the binary’s dynamic symbol table',
        }),
      }),
    );
    expect(r.outcome).toBe('empty');
    expect(r.headline).toContain('names none of the 8');
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

  it('summarizes every boot/platform provider from its stored reason instead of the generic completion text', () => {
    const kinds = [
      'uboot',
      'devicetree',
      'kernel',
      'fsaudit',
      'certs',
      'services',
      'updatepath',
      'compmap',
      'rtos',
      'fcc',
    ];
    for (const kind of kinds) {
      const r = summarizeRun(
        job({
          kind,
          resultJson: JSON.stringify({ available: true, findings: [], reason: `${kind} inspected its input.` }),
        }),
      );
      expect(r.headline, kind).toBe(`${kind} inspected its input.`);
      expect(r.outcome, kind).toBe('empty');
    }
  });

  it('grades deep-analysis answers by evidence, while keeping capability limits separate', () => {
    const summarize = (result: object) =>
      summarizeRun(
        job({ kind: 'kernel', resultJson: JSON.stringify({ reason: 'Kernel posture recorded.', ...result }) }),
      );

    expect(summarize({ available: false, findings: [] }).outcome).toBe('blocked');
    expect(summarize({ available: true, findings: [{ proofState: 'blocked_by_platform' }] }).outcome).toBe('blocked');
    expect(summarize({ available: true, findings: [{ proofState: 'needs_runtime_reproduction' }] }).outcome).toBe(
      'lead',
    );
    expect(summarize({ available: true, findings: [{ proofState: 'static_confirmed' }] }).outcome).toBe('proven');
    expect(
      summarize({
        available: true,
        findings: [{ proofState: 'blocked_by_platform' }, { proofState: 'static_confirmed' }],
      }).outcome,
    ).toBe('proven');
  });

  it('treats measured provider inventory as an established fact even when it emits no security finding', () => {
    const uboot = summarizeRun(
      job({
        kind: 'uboot',
        resultJson: JSON.stringify({
          available: true,
          found: true,
          varCount: 1,
          vars: { bootcmd: 'run boot_normal' },
          findings: [],
          reason: 'Parsed 1 U-Boot environment variable from the image.',
        }),
      }),
    );
    const services = summarizeRun(
      job({
        kind: 'services',
        resultJson: JSON.stringify({
          available: true,
          services: [{ name: 'httpd' }],
          findings: [],
          reason: 'Service map: 1 configured service.',
        }),
      }),
    );

    expect(uboot.outcome).toBe('proven');
    expect(services.outcome).toBe('proven');
  });

  it('leads an RTOS summary with the fact it established instead of only the unavailable Cortex-M reading', () => {
    const r = summarizeRun(
      job({
        kind: 'rtos',
        resultJson: JSON.stringify({
          available: true,
          isCortexM: false,
          rtosKernel: 'ThreadX',
          findings: [{ proofState: 'static_confirmed' }],
          reason: 'No ARM Cortex-M vector table at offset 0 (not a raw Cortex-M image).',
        }),
      }),
    );

    expect(r.outcome).toBe('proven');
    expect(r.headline).toBe(
      'RTOS kernel detected: ThreadX. No ARM Cortex-M vector table at offset 0 (not a raw Cortex-M image).',
    );
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

describe('summarizeRun — the three emulation rungs share one job kind', () => {
  const emulate = (result: unknown, params: unknown = {}): ReturnType<typeof summarizeRun> =>
    summarizeRun(job({ kind: 'emulate', params: JSON.stringify(params), resultJson: JSON.stringify(result) }));

  /**
   * The defect: a boot that returned the strongest verdict the ladder can produce rendered as the WEAKEST rung
   * failing to report an exit code — `lead` / "Ran under user-mode emulation, exit ?" — because this case read
   * `ran`/`exitCode` and nothing else.
   */
  it('reads a confirmed full-system boot as proven, not as a user-mode run', () => {
    const s = emulate(
      {
        ran: true,
        strategy: 'full-system',
        proofState: 'confirmed_full_system',
        reason:
          'The kernel booted (Freeing unused kernel memory) and two forwarded ports answered. It proves the sandbox.',
        open: [
          { host: 43441, guest: 80 },
          { host: 43442, guest: 443 },
        ],
        timedOut: false,
      },
      { rung: 'full-system' },
    );
    expect(s.outcome).toBe('proven');
    expect(s.question).toBe('full-system');
    expect(s.headline).toContain('Full-system boot confirmed');
    expect(s.headline).toContain('2 forwarded port');
    expect(s.headline).not.toContain('user-mode');
  });

  // The corpus's own case: booted, and not one of 158 SYNs answered. Still `confirmed_full_system` — the runner
  // decided that, and this summary carries it rather than second-guessing it — but the line must not imply a
  // service answered.
  it('says so when a confirmed boot had nothing answer on a forwarded port', () => {
    const s = emulate({
      ran: true,
      strategy: 'full-system',
      proofState: 'confirmed_full_system',
      reason: 'The kernel booted and its console names only loopback.',
      open: [],
      timedOut: false,
    });
    expect(s.outcome).toBe('proven');
    expect(s.headline).toContain('nothing answered');
  });

  it('reads a blocked rung as blocked, carrying the reason the runner gave', () => {
    const s = emulate({
      ran: false,
      strategy: 'full-system',
      proofState: 'blocked_by_platform',
      reason: 'No firmadyne kernel for arch "arm64" in /opt/firmae/kernels. Nothing was attempted.',
      timedOut: false,
    });
    expect(s.outcome).toBe('blocked');
    expect(s.headline).toContain('No firmadyne kernel');
    // One sentence, not the whole paragraph the runner wrote for a reader.
    expect(s.headline).not.toContain('Nothing was attempted');
  });

  it('reads an unconfirmed boot as empty — it ran, and it settled nothing', () => {
    const s = emulate({
      ran: true,
      strategy: 'full-system',
      proofState: 'needs_runtime_reproduction',
      reason: 'The emulator exited without printing a recognisable boot.',
      open: [],
      timedOut: false,
    });
    expect(s.outcome).toBe('empty');
  });

  it('reads a chroot service by its own rung name', () => {
    const s = emulate({
      ran: true,
      strategy: 'chroot-service',
      proofState: 'confirmed_in_emulation',
      reason: 'The service started under the libnvram shim.',
      timedOut: false,
    });
    expect(s.outcome).toBe('proven');
    expect(s.question).toBe('chroot-service');
    expect(s.headline).toContain('Chroot service confirmed');
  });

  // A user-mode result carries neither field, and its reading is unchanged — that rung really does report an
  // exit code and nothing else.
  it('still reads a user-mode run from its exit code', () => {
    const s = emulate({ ran: true, exitCode: 0, timedOut: false, stdout: '', stderr: '', command: 'qemu…' });
    expect(s.outcome).toBe('lead');
    expect(s.headline).toContain('user-mode emulation, exit 0');
  });
});
