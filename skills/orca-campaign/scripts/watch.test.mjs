import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const WATCH = fileURLToPath(new URL('./watch.mjs', import.meta.url));
import test from 'node:test';
import { decide, hasActiveTurn, ownerState, parseArgs, runWatch, staleWorking, superviseStep } from './watch.mjs';

const NOW = 1_800_000_000_000;
const options = { run: 'run_test', until: NOW + 600_000, intervalMs: 1000, idleMs: 1000, execute: true };
const idle = {
  owner: 'term_owner',
  generation: 2,
  connected: true,
  liveness: 'live',
  liveStatus: 'fresh',
  observedAt: NOW,
  activity: 'done',
  incarnation: 'inc_owner',
};
const waiting = { owner: 'term_owner', generation: 2, idleSince: NOW - 10_000 };

function harness(extra = {}) {
  let time = NOW;
  const commands = [];
  const saved = [];
  const snapshot = { ...idle, ...extra };
  const deps = {
    now: () => time,
    context: 'Original user mandate. Synthetic fixtures only.',
    persist: async (state) => saved.push(structuredClone(state)),
    call: async (args) => {
      commands.push(args);
      if (args[1] === 'run-show')
        return { run: { coordinator_handle: snapshot.owner, consumer_generation: snapshot.generation } };
      if (args[1] === 'worker-list')
        return {
          workers: [
            {
              agentTerminalHandle: snapshot.owner,
              dispatchStatus: 'completed',
              projection: {
                stage: { activity: snapshot.activity },
                liveness: { verdict: snapshot.liveness, observedAt: snapshot.observedAt },
                evidence: { liveStatus: snapshot.liveStatus },
              },
            },
          ],
          page: { hasMore: false },
        };
      if (args[1] === 'ps') return { worktrees: [] };
      if (args[1] === 'read') return { terminal: { source: 'screen', tail: ['>'] } };
      if (args[1] === 'run-list') return { runs: [], page: { hasMore: false } };
      if (args[1] === 'show')
        return { terminal: { connected: true, agentIdentity: 'claude', incarnationId: 'inc_owner' } };
      if (args[1] === 'wait') return { error: 'timeout' };
      if (args[1] === 'send') {
        assert.equal(saved.at(-1)?.pending?.target, args[args.indexOf('--terminal') + 1]);
        return { send: { accepted: true, prompt: { requestId: 'req_1', stages: ['input_accepted'] } } };
      }
      throw new Error(`Unexpected command ${args.join(' ')}`);
    },
  };
  return {
    deps,
    commands,
    saved,
    snapshot,
    tick: (ms) => {
      time += ms;
    },
  };
}

test('connected PTY and recent output never prove a working or idle model', () => {
  assert.equal(ownerState({ owner: 'term_owner', connected: true, lastOutputAt: NOW }, NOW), 'unknown');
  assert.equal(ownerState({ ...idle, observedAt: NOW - 180_001 }, NOW), 'unknown');
  assert.equal(ownerState({ ...idle, liveness: 'unverifiable' }, NOW), 'unknown');
  assert.equal(ownerState({ ...idle, observedAt: NOW + 1 }, NOW), 'unknown');
});

test('native idle wait is positive evidence; permission/interruption is not resumable', () => {
  assert.equal(ownerState({ owner: 'term_owner', connected: true, idleProven: true }, NOW), 'idle');
  for (const activity of ['interrupted', 'permission', 'waiting', 'unknown']) {
    assert.equal(ownerState({ ...idle, activity, idleProven: true }, NOW), 'unknown');
  }
});

test('deadline overrides pending sends, idle proof and positive exit', () => {
  for (const snapshot of [idle, { ...idle, liveness: 'exited' }]) {
    assert.equal(decide(snapshot, { pending: { target: 'term_owner' } }, options, options.until).kind, 'deadline');
  }
});

test('fresh done owner must remain idle through the grace period', () => {
  assert.equal(decide(idle, {}, options, NOW).kind, 'idle');
  assert.equal(decide(idle, { ...waiting, idleSince: NOW - 500 }, options, NOW).kind, 'idle');
  assert.equal(decide(idle, waiting, options, NOW).kind, 'resume');
  assert.equal(decide({ ...idle, generation: 3 }, waiting, options, NOW).kind, 'idle');
});

test('working owner, backward clock and absence do not cause injection', async () => {
  for (const extra of [{ activity: 'working' }, { liveness: 'unverifiable' }, { liveStatus: 'stale' }]) {
    const h = harness(extra);
    await superviseStep(waiting, options, h.deps);
    assert.equal(
      h.commands.some((a) => a[1] === 'send'),
      false,
    );
  }
  assert.equal(decide(idle, { checkedAt: NOW + 1 }, options, NOW).kind, 'unknown');
});

test('read-only mode records the required resume without delivering it', async () => {
  const h = harness();
  const result = await superviseStep(waiting, { ...options, execute: false }, h.deps);
  assert.equal(result.phase, 'resume');
  assert.equal(
    h.commands.some((a) => a[1] === 'send'),
    false,
  );
});

test('idle regression: intent persists before the one resume, ambiguous acceptance stays sticky', async () => {
  const h = harness();
  const first = await superviseStep(waiting, options, h.deps);
  assert.equal(first.pending.accepted, true);
  assert.equal(first.pending.started, false);
  assert.equal(first.pending.requestId, 'req_1');
  h.tick(30_000);
  const second = await superviseStep(structuredClone(first), options, h.deps);
  assert.equal(second.phase, 'pending');
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 1);
  assert.equal(JSON.stringify(second).includes('Original user mandate'), false);
});

test('lost transport cannot result in a duplicate send even after supervisor restart', async () => {
  const h = harness();
  const base = h.deps.call;
  h.deps.call = async (args) => (args[1] === 'send' ? { error: 'command_timeout' } : base(args));
  const first = await superviseStep(waiting, options, h.deps);
  assert.equal(first.reason, 'command_timeout');
  const restored = JSON.parse(JSON.stringify(h.saved.at(-1)));
  let deliveries = 0;
  h.deps.call = async (args) => {
    if (args[1] === 'send') deliveries++;
    return base(args);
  };
  await superviseStep(restored, options, h.deps);
  assert.equal(deliveries, 0);
});

test('a started short turn can be confirmed after it already returned idle', () => {
  const state = { pending: { target: 'term_owner', generation: 2, sentAt: NOW - 500, started: true } };
  assert.equal(decide(idle, state, options, NOW).kind, 'confirmed');
  assert.equal(decide(idle, { pending: { ...state.pending, started: false } }, options, NOW).kind, 'pending');
});

test('fresh working proves unobserved submission, ownership changes fence old pending prompts', () => {
  const state = { pending: { target: 'term_owner', generation: 2, sentAt: NOW - 500 } };
  assert.equal(decide({ ...idle, activity: 'working' }, state, options, NOW).kind, 'confirmed');
  assert.equal(decide({ ...idle, owner: 'term_new', generation: 3 }, state, options, NOW).kind, 'superseded');
  assert.equal(decide({ ...idle, liveness: 'exited' }, state, options, NOW).kind, 'failed-exited');
});

test('ownership revalidation catches a coordinator swap before mutation', async () => {
  const h = harness();
  const base = h.deps.call;
  let runs = 0;
  h.deps.call = async (args) => {
    if (args[1] === 'run-show' && ++runs === 2) h.snapshot.generation++;
    return base(args);
  };
  assert.equal((await superviseStep(waiting, options, h.deps)).phase, 'deferred');
  assert.equal(
    h.commands.some((a) => a[1] === 'send'),
    false,
  );
});

test('deadline crossed during snapshot read refuses delivery', async () => {
  const h = harness();
  const base = h.deps.call;
  h.deps.call = async (args) => {
    h.tick(100_000);
    return base(args);
  };
  await superviseStep(waiting, options, h.deps);
  assert.equal(
    h.commands.some((a) => a[1] === 'send'),
    false,
  );
});

test('long observation gaps are reported, never credited as executed time', async () => {
  const h = harness({ activity: 'working' });
  const state = await superviseStep({ checkedAt: NOW - 23_000_000 }, options, h.deps);
  assert.deepEqual(state.gaps, [{ from: NOW - 23_000_000, to: NOW, reason: 'unverified_observation_gap' }]);
  assert.equal(state.workedMs, undefined);
});

test('standby must be ready, Claude/Antigravity, and not an active dispatched worker', async () => {
  const h = harness({ liveness: 'exited' });
  h.deps.standbys = ['term_codex', 'term_ready'];
  const base = h.deps.call;
  h.deps.call = async (args) => {
    if (args[1] === 'show' && args.includes('term_codex'))
      return { terminal: { connected: true, agentIdentity: 'codex' } };
    if (args[1] === 'wait' && args.includes('term_ready')) return { wait: { satisfied: true } };
    return base(args);
  };
  const state = await superviseStep({}, options, h.deps);
  assert.equal(state.pending.kind, 'handoff');
  assert.equal(state.pending.target, 'term_ready');
  const send = h.commands.find((a) => a[1] === 'send');
  assert.match(send[send.indexOf('--text') + 1], /full coordinator handoff now/);
});

test('no proven standby is a visible block, not a claim all services exhausted', async () => {
  const h = harness({ liveness: 'exited' });
  const state = await superviseStep({}, options, h.deps);
  assert.equal(state.reason, 'no_proven_ready_standby');
  assert.equal(
    h.commands.some((a) => a[1] === 'send'),
    false,
  );
});

test('standalone coordinator is matched by pane identity without persisting sensitive status payloads', async () => {
  const h = harness();
  const base = h.deps.call;
  h.deps.call = async (args) => {
    if (args[1] === 'worker-list') return { workers: [], page: { hasMore: false } };
    if (args[1] === 'show') return { terminal: { connected: true, worktreeId: 'wt', tabId: 'tab', leafId: 'leaf' } };
    if (args[1] === 'ps')
      return {
        worktrees: [
          {
            worktreeId: 'wt',
            agents: [
              { paneKey: 'wrong:leaf', state: 'done', updatedAt: NOW },
              { paneKey: 'tab:leaf', state: 'working', updatedAt: NOW, toolInput: 'dcap_SECRET' },
            ],
          },
        ],
      };
    return base(args);
  };
  const state = await superviseStep({}, options, h.deps);
  assert.equal(state.phase, 'working');
  assert.equal(JSON.stringify(state).includes('SECRET'), false);
});

test('arguments require a fixed future deadline and explicit execution/context', () => {
  const args = ['--run', 'run_test', '--until', new Date(NOW + 60_000).toISOString(), '--journal', '/tmp/test.json'];
  assert.equal(parseArgs(args, NOW).execute, false);
  assert.throws(() => parseArgs([...args, '--execute'], NOW), /context/);
  assert.throws(() => parseArgs(args, NOW + 60_000), /future/);
  assert.throws(() => parseArgs([...args, '--interval-ms', '70000'], NOW), /between/);
  assert.throws(() => parseArgs([...args, '--model', 'other'], NOW), /Unknown option/);
});

test('journal from another Run/deadline is refused before any CLI mutation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'firmlab-watch-test-'));
  const journal = join(directory, 'state.json');
  try {
    await writeFile(journal, JSON.stringify({ run: 'run_other', until: NOW }));
    await assert.rejects(runWatch({ ...options, journal, execute: false, orca: '/nonexistent' }), /different Run/);
    assert.match(await readFile(journal, 'utf8'), /run_other/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function nativeHarness(tail = ['>'], age = 600_000) {
  const h = harness();
  const base = h.deps.call;
  h.deps.call = async (args) => {
    if (args[1] === 'worker-list') return { workers: [], page: { hasMore: false } };
    if (args[1] === 'show')
      return { terminal: { connected: true, worktreeId: 'wt', tabId: 't', leafId: 'l', incarnationId: 'inc_owner' } };
    if (args[1] === 'read') return { terminal: { source: 'screen', tail } };
    if (args[1] === 'ps')
      return {
        worktrees: [
          {
            worktreeId: 'wt',
            agents: [{ paneKey: 't:l', state: 'done', updatedAt: NOW - age, stateStartedAt: NOW - age }],
          },
        ],
      };
    return base(args);
  };
  return h;
}

test('Antigravity stale native done plus visible input resumes despite unsupported idle wait', async () => {
  const h = nativeHarness();
  const state = await superviseStep(waiting, options, h.deps);
  assert.equal(state.pending.accepted, true);
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 1);
});

test('Claude footer tail is resumable and native transition confirms a short unobserved turn', async () => {
  const h = nativeHarness([
    '────────────────',
    '❯',
    '────────────────',
    '⏵⏵ bypass permissions on (shift+tab to cycle) · ← 1 agent',
  ]);
  assert.equal((await superviseStep(waiting, options, h.deps)).phase, 'pending');
  const pending = { pending: { target: 'term_owner', generation: 2, sentAt: NOW - 500, started: false } };
  assert.equal(decide({ ...idle, stateStartedAt: NOW - 100 }, pending, options, NOW).kind, 'confirmed');
});

test('unreadable screen fails closed even if native idle wait succeeds', async () => {
  const h = harness();
  const base = h.deps.call;
  h.deps.call = async (a) =>
    a[1] === 'read' ? { error: 'command_timeout' } : a[1] === 'wait' ? { wait: { satisfied: true } } : base(a);
  assert.equal((await superviseStep(waiting, options, h.deps)).phase, 'unknown');
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
});

test('quota and selectors never receive Enter; quota positively blocks with reason and gaps', async () => {
  for (const tail of [
    ["You've hit your usage limit", '>'],
    ['Usage limit reached · limit resets 14:50', 'Continuing automatically'],
    ['Session limit reached · please wait', 'Continuing automatically'],
  ]) {
    const h = nativeHarness(tail, 0);
    const step = await superviseStep(waiting, options, h.deps);
    assert.equal(step.phase, 'blocked');
    assert.equal(step.reason, 'capacity_blocked');
    assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
    assert.equal(
      step.gaps.some((g) => g.reason === 'capacity_blocked'),
      true,
    );
  }

  for (const tail of [
    ['Do you trust the files in this folder?', '>'],
    ['Do you want to make this edit to x?', '>'],
    ['Do you want to create x?', '>'],
    ['❯ 1. Yes, proceed'],
  ]) {
    const h = nativeHarness(tail, 0);
    assert.equal((await superviseStep(waiting, options, h.deps)).phase, 'unknown');
    assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
  }
});

test('captured Claude usage limit footer positively records capacity_blocked and durable gaps', async () => {
  const tail = [
    '❯',
    '────────────────────────────────────────',
    'Usage limit reached · limit resets 14:50 (Madrid)',
    'Continuing automatically',
  ];
  const h = nativeHarness(tail, 0);
  const step = await superviseStep(waiting, options, h.deps);
  assert.equal(step.phase, 'blocked');
  assert.equal(step.reason, 'capacity_blocked');
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
  assert.deepEqual(step.gaps, [{ from: NOW, to: NOW, reason: 'capacity_blocked' }]);
});

test('normal text mention of limits in prose is not a capacity blockade and resumes', async () => {
  const tail = [
    'We should ensure that usage limit is not reached during the campaign.',
    '────────────────',
    '>',
    '────────────────',
    '? for shortcuts   Claude 3.7 Sonnet',
  ];
  const h = nativeHarness(tail, 0);
  const step = await superviseStep(waiting, options, h.deps);
  assert.equal(step.phase, 'pending');
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 1);
});

test('transitions and recovery gap accounting for capacity_blocked', async () => {
  const tail = ['Usage limit reached · limit resets 14:50', 'Continuing automatically'];
  const h = nativeHarness(tail, 0);
  // Step 1: Initial observation of capacity blockade from working state
  const t0 = NOW;
  const t1 = NOW + 1000;
  h.tick(1000);
  const step1 = await superviseStep(
    { checkedAt: t0, phase: 'working', owner: 'term_owner', generation: 2 },
    options,
    h.deps,
  );
  assert.equal(step1.phase, 'blocked');
  assert.equal(step1.reason, 'capacity_blocked');
  assert.deepEqual(step1.gaps, [{ from: t0, to: t1, reason: 'capacity_blocked' }]);

  // Step 2: Continued capacity blockade extends the existing gap bound
  const t2 = NOW + 2000;
  h.tick(1000);
  const step2 = await superviseStep(step1, options, h.deps);
  assert.equal(step2.phase, 'blocked');
  assert.equal(step2.reason, 'capacity_blocked');
  assert.deepEqual(step2.gaps, [{ from: t0, to: t2, reason: 'capacity_blocked' }]);

  // Step 3: Recovery (e.g. owner resumed working) bounds the gap up to recovery time
  const t3 = NOW + 3000;
  h.tick(1000);
  const prevCall = h.deps.call;
  h.deps.call = async (args) => {
    if (args[1] === 'ps')
      return {
        worktrees: [{ worktreeId: 'wt', agents: [{ paneKey: 't:l', state: 'working', updatedAt: t3 }] }],
      };
    return prevCall(args);
  };
  const step3 = await superviseStep(step2, options, h.deps);
  assert.equal(step3.phase, 'working');
  assert.deepEqual(step3.gaps, [{ from: t0, to: t3, reason: 'capacity_blocked' }]);
});

test('quota screen never equates to process death and never auto takeovers live owner', async () => {
  const tail = ['Usage limit reached · limit resets 14:50', 'Continuing automatically'];
  const h = nativeHarness(tail, 0);
  h.deps.standbys = ['term_ready'];
  const base = h.deps.call;
  h.deps.call = async (args) => {
    if (args[1] === 'wait' && args.includes('term_ready')) return { wait: { satisfied: true } };
    return base(args);
  };
  const step = await superviseStep(waiting, options, h.deps);
  assert.equal(step.phase, 'blocked');
  assert.equal(step.reason, 'capacity_blocked');
  assert.equal(step.pending, undefined);
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
});

test('standby menu, other coordinator, paginated or active fleet is refused', async () => {
  for (const scenario of ['menu', 'coordinator', 'pagination', 'worker']) {
    const h = harness({ liveness: 'exited' });
    h.deps.standbys = ['term_ready'];
    const base = h.deps.call;
    h.deps.call = async (a) => {
      if (a[1] === 'run-list')
        return {
          runs:
            scenario === 'worker'
              ? [{ id: 'run_other' }]
              : scenario === 'coordinator'
                ? [{ coordinator_handle: 'term_ready' }]
                : [],
          nextCursor: scenario === 'pagination' ? 'next' : null,
        };
      if (a[1] === 'worker-list' && a.includes('run_other'))
        return { workers: [{ agentTerminalHandle: 'term_ready', dispatchStatus: 'active' }], page: { hasMore: false } };
      if (a[1] === 'read' && a.includes('term_ready') && scenario === 'menu')
        return { terminal: { source: 'screen', tail: ['Do you trust the files in this folder?', '>'] } };
      if (a[1] === 'wait') return { wait: { satisfied: true } };
      return base(a);
    };
    assert.equal((await superviseStep({}, options, h.deps)).reason, 'no_proven_ready_standby');
    assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
  }
});

test('resume budget and exponential grace bound churn', async () => {
  const h = harness();
  assert.equal(
    (await superviseStep({ ...waiting, resumeCount: 1 }, { ...options, maxResumes: 1 }, h.deps)).reason,
    'resume_budget_reached',
  );
  assert.equal(decide(idle, { ...waiting, idleSince: NOW - 1500, consecutiveResumes: 1 }, options, NOW).kind, 'idle');
  assert.equal(decide(idle, { ...waiting, idleSince: NOW - 3000, consecutiveResumes: 1 }, options, NOW).kind, 'resume');
});

test('unobserved submission becomes a visible block without a second send', async () => {
  const h = harness();
  const first = await superviseStep(waiting, options, h.deps);
  h.tick(180_000);
  const last = await superviseStep(first, options, h.deps);
  assert.equal(last.phase, 'blocked');
  assert.equal(last.reason, 'submission_not_observed_do_not_resend');
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 1);
});

test('observation gap restarts idle grace instead of immediately delivering', async () => {
  const h = harness();
  const result = await superviseStep({ ...waiting, checkedAt: NOW - 4000 }, options, h.deps);
  assert.equal(result.phase, 'idle');
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
});

test('independent supervisors share one Run lock across journals and release it on normal stop', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'firmlab-watch-process-'));
  const run = `run_lock_${process.pid}`;
  const context = join(directory, 'context.txt');
  const cli = join(directory, 'fake-orca');
  let first;
  try {
    await writeFile(context, 'Isolated test; no real Orca calls.');
    await writeFile(cli, '#!/usr/bin/env node\nconsole.log(JSON.stringify({ok:true,result:{error:"no_owner"}}));\n');
    await chmod(cli, 0o700);
    const until = new Date(Date.now() + 30_000).toISOString();
    const args = [
      WATCH,
      '--run',
      run,
      '--until',
      until,
      '--execute',
      '--context',
      context,
      '--orca',
      cli,
      '--interval-ms',
      '1000',
    ];
    const firstTemp = join(directory, 'tmp-one');
    const secondTemp = join(directory, 'tmp-two');
    await mkdir(firstTemp);
    await mkdir(secondTemp);
    first = spawn(process.execPath, [...args, '--journal', join(directory, 'one.json')], {
      env: { ...process.env, TMPDIR: firstTemp },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stopped = once(first, 'close');
    await once(first.stdout, 'data'); // Positive successful first tick, not merely lock presence.
    const second = spawn(process.execPath, [...args, '--journal', join(directory, 'two.json')], {
      env: { ...process.env, TMPDIR: secondTemp },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let error = '';
    second.stderr.on('data', (data) => {
      error += data;
    });
    const [code] = await once(second, 'close');
    assert.equal(code, 1);
    assert.match(error, /EEXIST/);
    const observer = spawn(
      process.execPath,
      [...args.filter((a) => a !== '--execute'), '--journal', join(directory, 'one.json'), '--once'],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );
    assert.equal((await once(observer, 'close'))[0], 1);
    first.kill('SIGTERM');
    assert.equal((await stopped)[0], 0);
    first = null;
    const third = spawn(process.execPath, [...args, '--journal', join(directory, 'two.json'), '--once'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    assert.equal((await once(third, 'close'))[0], 0); // Success path proves the prior lock was removed.
  } finally {
    first?.kill('SIGTERM');
    await rm(directory, { recursive: true, force: true });
  }
});

test('a standalone closed coordinator with the real Orca exitCause can hand off', async () => {
  const h = harness();
  h.deps.standbys = ['term_ready'];
  const base = h.deps.call;
  h.deps.call = async (a) => {
    if (a[1] === 'worker-list') return { workers: [], page: { hasMore: false } };
    if (a[1] === 'show' && a.includes('term_owner'))
      return {
        terminal: {
          connected: false,
          orphaned: true,
          writable: false,
          exitCause: { kind: 'operator_close' },
          incarnationId: 'inc_owner',
        },
      };
    if (a[1] === 'wait' && a.includes('term_ready')) return { wait: { satisfied: true } };
    return base(a);
  };
  const state = await superviseStep({ ...waiting, incarnation: 'inc_owner' }, options, h.deps);
  assert.equal(state.pending.kind, 'handoff');
  assert.equal(state.pending.target, 'term_ready');
});

test('a missing standalone owner without positive exit evidence never transfers ownership', async () => {
  const h = harness();
  const base = h.deps.call;
  h.deps.standbys = ['term_ready'];
  h.deps.call = async (a) =>
    a[1] === 'worker-list'
      ? { workers: [], page: { hasMore: false } }
      : a[1] === 'show'
        ? { terminal: { connected: false } }
        : base(a);
  assert.equal((await superviseStep({}, options, h.deps)).phase, 'unknown');
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
});

test('an idle prose report above the input box is not a quota or permission menu', async () => {
  for (const prose of [
    'Do you want to continue?',
    "You've hit your usage limit on the other worker",
    'switch to another model',
    '> 1. proposed work',
  ]) {
    const h = nativeHarness([
      prose,
      '────────────────',
      '>',
      '────────────────',
      '? for shortcuts   Gemini 3.8 Flash · high',
    ]);
    assert.equal((await superviseStep(waiting, options, h.deps)).phase, 'pending');
  }
});

test('gap grace is measured from the new observation through the whole idle delay', async () => {
  const h = harness();
  const longGrace = { ...options, intervalMs: 30_000, idleMs: 60_000 };
  const first = await superviseStep({ ...waiting, checkedAt: NOW - 200_000 }, longGrace, h.deps);
  assert.equal(first.idleSince, NOW);
  h.tick(30_000);
  const second = await superviseStep(first, longGrace, h.deps);
  assert.equal(second.phase, 'idle');
  h.tick(30_000);
  assert.equal((await superviseStep(second, longGrace, h.deps)).phase, 'pending');
});

test('one failed observation retains backoff and the original incarnation fence', async () => {
  const h = harness();
  const base = h.deps.call;
  h.deps.call = async (a) => (a[1] === 'read' ? { error: 'timeout' } : base(a));
  const state = await superviseStep(
    { ...waiting, consecutiveResumes: 4, workVersion: 'prior', incarnation: 'inc_owner' },
    options,
    h.deps,
  );
  assert.equal(state.consecutiveResumes, 4);
  h.deps.call = async (a) => (a[1] === 'show' ? { terminal: { connected: true, incarnationId: 'other' } } : base(a));
  const changed = await superviseStep(state, options, h.deps);
  assert.equal(changed.phase, 'unknown');
  assert.equal(changed.incarnation, 'inc_owner');
  assert.equal((await superviseStep(changed, options, h.deps)).phase, 'unknown');
});

test('empty repeated cursor fails closed instead of looping without a row bound', async () => {
  const h = harness();
  const base = h.deps.call;
  let pages = 0;
  h.deps.call = async (a) => {
    if (a[1] === 'worker-list') {
      pages++;
      return { workers: [], page: { hasMore: true, nextCursor: 'same' } };
    }
    return base(a);
  };
  assert.equal((await superviseStep(waiting, options, h.deps)).phase, 'unknown');
  assert.equal(pages, 2);
});

test('an unsent operator draft is not an empty input prompt even when idle wait succeeds', async () => {
  const h = nativeHarness(['────────────────', '❯ operator draft', '────────────────']);
  const base = h.deps.call;
  h.deps.call = async (a) => (a[1] === 'wait' ? { wait: { satisfied: true } } : base(a));
  assert.equal((await superviseStep(waiting, options, h.deps)).phase, 'unknown');
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
});

test('a native interrupted standby is refused even with a satisfied idle wait', async () => {
  const h = harness({ liveness: 'exited' });
  h.deps.standbys = ['term_ready'];
  const base = h.deps.call;
  h.deps.call = async (a) => {
    if (a[1] === 'show' && a.includes('term_ready'))
      return { terminal: { connected: true, agentIdentity: 'claude', worktreeId: 'wt', tabId: 't', leafId: 'l' } };
    if (a[1] === 'ps')
      return {
        worktrees: [
          { worktreeId: 'wt', agents: [{ paneKey: 't:l', state: 'done', interrupted: true, updatedAt: NOW }] },
        ],
      };
    if (a[1] === 'wait') return { wait: { satisfied: true } };
    return base(a);
  };
  assert.equal((await superviseStep({}, options, h.deps)).reason, 'no_proven_ready_standby');
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
});

test('complete paginated Run enumeration permits a dedicated fresh standby', async () => {
  const h = harness({ liveness: 'exited' });
  h.deps.standbys = ['term_ready'];
  const base = h.deps.call;
  let pages = 0;
  h.deps.call = async (a) => {
    if (a[1] === 'run-list') {
      pages++;
      return a.includes('--cursor')
        ? { runs: [], nextCursor: null }
        : { runs: [{ id: 'run_other', coordinator_handle: 'term_other' }], nextCursor: 'page2' };
    }
    if (a[1] === 'wait' && a.includes('term_ready')) return { wait: { satisfied: true } };
    return base(a);
  };
  assert.equal((await superviseStep({}, options, h.deps)).pending.target, 'term_ready');
  assert.equal(pages, 2);
});

test('the journal retains the definitive submission error after a bounded block', async () => {
  const h = harness();
  const base = h.deps.call;
  h.deps.call = async (a) => (a[1] === 'send' ? { error: 'terminal_not_writable' } : base(a));
  const first = await superviseStep(waiting, options, h.deps);
  h.tick(180_000);
  const final = await superviseStep(first, options, h.deps);
  assert.equal(final.phase, 'blocked');
  assert.equal(final.pending.error, 'terminal_not_writable');
  assert.equal(final.lastSubmission.error, 'terminal_not_writable');
});

test('captured Codex composer and Claude edit/plan modes resume; a draft or selector does not', async () => {
  const tails = [
    ['› Ask Codex to do anything', 'gpt-6.1-sol xhigh · ~/other-project · coordinator', '? for shortcuts'],
    ['❯', '────────────', '⏵⏵ accept edits on (shift+tab to cycle)'],
    ['❯', '────────────', '⏸ plan mode on (shift+tab to cycle)'],
  ];
  for (const tail of tails)
    assert.equal((await superviseStep(waiting, options, nativeHarness(tail).deps)).phase, 'pending');
  for (const tail of [
    ['› Ask Codex to do anything else', '? for shortcuts'],
    ['› 1. Yes, allow', '? for shortcuts'],
  ]) {
    assert.equal((await superviseStep(waiting, options, nativeHarness(tail).deps)).phase, 'unknown');
  }
});

test('deadline requires an explicit offset instead of host-dependent local-time parsing', () => {
  assert.throws(
    () => parseArgs(['--run', 'run_test', '--until', '2027-01-01T12:00', '--journal', '/tmp/unused'], NOW),
    /offset/,
  );
});

test(
  'invalid live context or standbys block safely, recover without exiting, and cancellation records stopped',
  { timeout: 30_000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'orca-live-input-'));
    const context = join(directory, 'context.txt');
    const standbys = join(directory, 'standbys.json');
    const journal = join(directory, 'journal.json');
    const cli = join(directory, 'fake-orca');
    let child;
    let closed;
    try {
      await writeFile(context, 'Authorized isolated fixture; no actual Orca calls.');
      await writeFile(standbys, '[]');
      await writeFile(
        cli,
        `#!/usr/bin/env node
const a=process.argv.slice(2); let result={error:'unexpected'};
if(a[1]==='run-show') result={run:{coordinator_handle:'term_owner',consumer_generation:1}};
if(a[1]==='worker-list') result={workers:[],page:{hasMore:false}};
if(a[1]==='show') result={terminal:{connected:true,worktreeId:'wt',tabId:'t',leafId:'l',incarnationId:'inc'}};
if(a[1]==='ps') result={worktrees:[{worktreeId:'wt',agents:[{paneKey:'t:l',state:'working',updatedAt:Date.now()}]}]};
console.log(JSON.stringify({ok:true,result}));
`,
      );
      await chmod(cli, 0o700);
      child = spawn(
        process.execPath,
        [
          WATCH,
          '--run',
          `run_input_${process.pid}`,
          '--until',
          new Date(Date.now() + 25_000).toISOString(),
          '--journal',
          journal,
          '--execute',
          '--context',
          context,
          '--standbys',
          standbys,
          '--orca',
          cli,
          '--interval-ms',
          '1000',
        ],
        { stdio: 'ignore' },
      );
      closed = once(child, 'close');
      const observed = async (predicate) => {
        const limit = Date.now() + 8000;
        while (Date.now() < limit) {
          try {
            const state = JSON.parse(await readFile(journal, 'utf8'));
            if (predicate(state)) return state;
          } catch {}
          assert.equal(child.exitCode, null, 'supervisor must stay alive during input repair');
          await new Promise((r) => setTimeout(r, 50));
        }
        assert.fail('expected journal observation');
      };
      await observed((s) => s.phase === 'working');
      for (const invalid of ['', 'x'.repeat(80_001)]) {
        await writeFile(context, invalid);
        const blocked = await observed((s) => s.phase === 'blocked' && s.reason === 'context_invalid');
        assert.equal(blocked.resumeCount, undefined);
        await writeFile(context, 'Repaired valid authorized context.');
        await observed((s) => s.phase === 'working');
      }
      await writeFile(standbys, '["term_x",');
      await observed((s) => s.phase === 'blocked' && s.reason === 'standbys_invalid');
      await writeFile(standbys, '[]');
      await observed((s) => s.phase === 'working');
      child.kill('SIGTERM');
      assert.equal((await closed)[0], 0);
      child = null;
      assert.equal(JSON.parse(await readFile(journal, 'utf8')).phase, 'stopped');
    } finally {
      if (child) {
        child.kill('SIGTERM');
        await closed;
      }
      await rm(directory, { recursive: true, force: true });
    }
  },
);

// Captured 2026-10-02 from a native-done Antigravity CLI 1.2.14 coordinator (prose shortened).
// The stream read ends in its report; only the rendered screen shows the composer.
const ANTIGRAVITY_STREAM = [
  '  • Compromiso en git: 8900751 feat(rtos): wire renode ram capture into web ui and add route contract tests.',
  '',
  '  #### 4. Documentación y Backlog',
  '  • Compromiso en git: 7d3698a docs(campaign): record renode ram capture and supervisor quota fixes in campaign and',
  '  backlog.',
];
const ANTIGRAVITY_SCREEN = [
  '      • context.md y status.md actualizados atómicamente.',
  '  4. API Sintética Local:',
  '      • PID 92345 continúa ejecutándose en 127.0.0.1:8911 para soporte de pruebas de interfaz; será detenida de forma',
  '      verificada antes del cierre final de la campaña.',
  '──────────────────────────────────────────────────────────────────────────────',
  '>',
  '──────────────────────────────────────────────────────────────────────────────',
  '? for shortcuts                                          Gemini 3.8 Flash · high',
];

function screenHarness(terminal) {
  const h = nativeHarness(ANTIGRAVITY_STREAM);
  const base = h.deps.call;
  h.deps.call = async (a) => {
    if (a[1] !== 'read' || !a.includes('--screen')) return base(a);
    h.commands.push(a);
    return { terminal };
  };
  return h;
}

test('real Antigravity done owner: stream tail is unrecognized, the rendered screen proves an empty composer', async () => {
  const legacy = nativeHarness(ANTIGRAVITY_STREAM);
  const stuck = await superviseStep(waiting, options, legacy.deps);
  assert.equal(stuck.phase, 'unknown');
  assert.equal(stuck.reason, 'input_prompt_unrecognized');

  const h = screenHarness({ source: 'screen', tail: ANTIGRAVITY_SCREEN });
  const state = await superviseStep(waiting, options, h.deps);
  assert.equal(state.phase, 'pending');
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 1);
  assert.equal(h.commands.find((a) => a[1] === 'read').includes('--screen'), true);
});

test('a reported composer draft blocks input even though the rendered prompt looks empty', async () => {
  for (const draft of ['continue with the deploy', '  x  ']) {
    const h = screenHarness({ source: 'screen', tail: ANTIGRAVITY_SCREEN, draft });
    const base = h.deps.call;
    h.deps.call = async (a) => (a[1] === 'wait' ? { wait: { satisfied: true } } : base(a));
    const state = await superviseStep(waiting, options, h.deps);
    assert.equal(state.phase, 'unknown');
    assert.equal(state.reason, 'composer_draft_present');
    assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
    assert.equal(JSON.stringify(state).includes(draft.trim()), false);
  }
  for (const draft of ['   ', '\n', { text: '' }, [], 0, false]) {
    const h = screenHarness({ source: 'screen', tail: ANTIGRAVITY_SCREEN, draft });
    const state = await superviseStep(waiting, options, h.deps);
    assert.equal(state.phase, 'unknown', `draft ${JSON.stringify(draft)} is present, not verified empty`);
    assert.equal(state.reason, 'composer_draft_present');
    assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
  }
  for (const draft of ['', null]) {
    const h = screenHarness({ source: 'screen', tail: ANTIGRAVITY_SCREEN, draft });
    assert.equal((await superviseStep(waiting, options, h.deps)).phase, 'pending');
  }
});

test('done plus blank tail or an unrecognized screen is journaled uncertainty, never idle or gap-free', async () => {
  for (const tail of [[], ['', '   '], ANTIGRAVITY_STREAM]) {
    const h = nativeHarness(tail);
    const state = await superviseStep({ ...waiting, checkedAt: NOW - 500 }, options, h.deps);
    assert.equal(state.phase, 'unknown');
    assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
    assert.deepEqual(state.gaps, [{ from: NOW - 500, reason: 'input_prompt_unrecognized', to: NOW, phase: 'unknown' }]);
  }
});

test('uncertainty intervals extend, split on reason change, close on recovery and stay bounded', async () => {
  const h = nativeHarness(ANTIGRAVITY_STREAM);
  const t0 = NOW;
  h.tick(1000);
  const s1 = await superviseStep(
    { checkedAt: t0, phase: 'working', owner: 'term_owner', generation: 2 },
    options,
    h.deps,
  );
  assert.deepEqual(s1.uncertainty, { from: t0, reason: 'input_prompt_unrecognized' });
  h.tick(1000);
  const s2 = await superviseStep(s1, options, h.deps);
  assert.deepEqual(s2.gaps, [{ from: t0, reason: 'input_prompt_unrecognized', to: NOW + 2000, phase: 'unknown' }]);
  assert.deepEqual(s1.gaps[0].to, NOW + 1000, 'the previous journal object is not mutated');

  const base = h.deps.call;
  h.deps.call = async (a) => (a[1] === 'read' ? { error: 'command_timeout' } : base(a));
  h.tick(1000);
  const s3 = await superviseStep(s2, options, h.deps);
  assert.deepEqual(s3.gaps, [
    { from: t0, reason: 'input_prompt_unrecognized', to: NOW + 3000, phase: 'unknown' },
    { from: NOW + 2000, reason: 'screen_unreadable', to: NOW + 3000, phase: 'unknown' },
  ]);

  h.deps.call = async (a) =>
    a[1] === 'read' && a.includes('--screen') ? { terminal: { source: 'screen', tail: ANTIGRAVITY_SCREEN } } : base(a);
  h.tick(1000);
  const s4 = await superviseStep(s3, options, h.deps);
  assert.equal(s4.phase, 'idle');
  assert.equal(s4.uncertainty, null);
  assert.equal(s4.gaps.at(-1).to, NOW + 4000);
  h.tick(1000);
  const s5 = await superviseStep(s4, options, h.deps);
  assert.deepEqual(s5.gaps, s4.gaps, 'a closed interval is not reopened by later healthy observations');

  const many = Array.from({ length: 100 }, (_, i) => ({ from: i, to: i, reason: 'unverified_observation_gap' }));
  h.deps.call = base;
  h.tick(1000);
  const s6 = await superviseStep({ ...s5, gaps: many }, options, h.deps);
  assert.equal(s6.gaps.length, 100);
  assert.equal(s6.gaps.at(-1).reason, 'input_prompt_unrecognized');
});

test('an unrecognized screen while a submission is pending keeps the receipt and records uncertainty', async () => {
  const h = nativeHarness(ANTIGRAVITY_STREAM);
  const pending = { target: 'term_owner', generation: 2, sentAt: NOW - 1000, requestId: 'req_9', accepted: true };
  const state = await superviseStep({ ...waiting, checkedAt: NOW - 1000, pending }, options, h.deps);
  assert.equal(state.phase, 'pending');
  assert.deepEqual(state.pending, pending);
  assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
  assert.equal(state.gaps.at(-1).reason, 'input_prompt_unrecognized');
});

test('a stream fallback or an older host without a source never proves an empty composer', async () => {
  for (const terminal of [
    { source: 'stream', tail: ['>'] },
    { source: 'screen-unavailable', tail: ['>'] },
    { tail: ['>'] },
  ]) {
    const h = screenHarness(terminal);
    const base = h.deps.call;
    h.deps.call = async (a) => (a[1] === 'wait' ? { wait: { satisfied: true } } : base(a));
    const state = await superviseStep(waiting, options, h.deps);
    assert.equal(state.phase, 'unknown');
    assert.equal(state.reason, 'screen_not_rendered');
    assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
    assert.equal(state.gaps.at(-1).reason, 'screen_not_rendered');
  }
});

test('a rendered selector or quota screen still blocks the real Antigravity frame', async () => {
  // A selector replaces the composer; text above an empty composer is assistant prose.
  const menu = screenHarness({
    source: 'screen',
    tail: [...ANTIGRAVITY_SCREEN.slice(0, 5), 'Do you want to proceed?', '❯ 1. Yes', '  2. No'],
  });
  assert.equal((await superviseStep(waiting, options, menu.deps)).phase, 'unknown');
  assert.equal(menu.commands.filter((a) => a[1] === 'send').length, 0);
  const quota = screenHarness({
    source: 'screen',
    tail: [...ANTIGRAVITY_SCREEN.slice(0, -1), 'Usage limit reached · limit resets 14:50'],
  });
  assert.equal((await superviseStep(waiting, options, quota.deps)).reason, 'capacity_blocked');
  assert.equal(quota.commands.filter((a) => a[1] === 'send').length, 0);
});

test('historical quota text in a stream fallback is uncertainty, not a current capacity block', async () => {
  const oldQuota = ['Usage limit reached · limit resets 14:50', 'Continuing automatically', '>'];
  for (const terminal of [
    { source: 'screen-unavailable', tail: oldQuota },
    { source: 'stream', tail: oldQuota },
    { tail: oldQuota },
  ]) {
    const h = screenHarness(terminal);
    const state = await superviseStep({ ...waiting, checkedAt: NOW - 500 }, options, h.deps);
    assert.equal(state.phase, 'unknown');
    assert.equal(state.reason, 'screen_not_rendered');
    assert.equal(h.commands.filter((a) => a[1] === 'send').length, 0);
    assert.equal(
      state.gaps.some((g) => g.reason === 'capacity_blocked'),
      false,
    );
    assert.deepEqual(state.gaps, [{ from: NOW - 500, reason: 'screen_not_rendered', to: NOW, phase: 'unknown' }]);
  }
  const rendered = screenHarness({ source: 'screen', tail: oldQuota });
  assert.equal((await superviseStep(waiting, options, rendered.deps)).reason, 'capacity_blocked');
});

// === Stale native `working` (2026-10-02 incident) =========================================================

const RULE = '─'.repeat(40);
/** CAPTURED 2026-10-02T17:38Z from a working Claude Code pane (prose lines trimmed): empty composer, live spinner. */
const CLAUDE_WORKING_FRAME = [
  '⏺ Capturing my rendered screen tail and native state while working',
  '✳ Clauding… (1m 27s · ↓ 6.9k tokens · thought for 14s)',
  '  ⎿ \u00a0Tip: Use /permissions to pre-approve and pre-deny bash, edit, and MCP tools',
  RULE,
  '❯',
  RULE,
  '  ⏵⏵ bypass permissions on (shift+tab to cycle) · ← 1 agent',
];
/**
 * RECONSTRUCTED from the root operator's 17:37Z description of the stuck pane (not a byte capture): final
 * "Worked 20m22s" line, empty composer, bypass-permissions footer with one background shell.
 */
const CLAUDE_STALE_IDLE_FRAME = [
  '⏺ Delivered four commits; arming the controlled idle test.',
  '✻ Worked for 20m 22s',
  RULE,
  '❯',
  RULE,
  '  ⏵⏵ bypass permissions on (shift+tab to cycle) · 1 shell',
];
const STALE_AGE = 25 * 60_000;

function staleHarness(tail, { age = STALE_AGE, satisfied = true, draft, source = 'screen', connected = true } = {}) {
  const h = harness();
  const base = h.deps.call;
  const local = (args) => {
    if (args[1] === 'worker-list') return { workers: [], page: { hasMore: false } };
    if (args[1] === 'show')
      return { terminal: { connected, worktreeId: 'wt', tabId: 't', leafId: 'l', incarnationId: 'inc_owner' } };
    if (args[1] === 'read') return { terminal: { source, tail, ...(draft === undefined ? {} : { draft }) } };
    if (args[1] === 'wait') return satisfied ? { wait: { satisfied: true } } : { error: 'timeout' };
    if (args[1] === 'ps')
      return {
        worktrees: [
          {
            worktreeId: 'wt',
            agents: [{ paneKey: 't:l', state: 'working', updatedAt: NOW - age, stateStartedAt: NOW - age - 60_000 }],
          },
        ],
      };
    return undefined;
  };
  h.deps.call = async (args) => {
    const result = local(args);
    if (result === undefined) return base(args); // base records its own commands
    h.commands.push(args);
    return result;
  };
  return h;
}
const sends = (h) => h.commands.filter((a) => a[1] === 'send').length;
const ran = (h, verb) => h.commands.some((a) => a[1] === verb);

test('staleWorking is only a working row older than the freshness bound, or one with no usable timestamp', () => {
  assert.equal(staleWorking('working', NOW - 1000, NOW), false);
  assert.equal(staleWorking('working', NOW - STALE_AGE, NOW), true);
  assert.equal(staleWorking('working', undefined, NOW), true);
  assert.equal(staleWorking('done', NOW - STALE_AGE, NOW), false);
});

test('hasActiveTurn reads a live spinner or esc hint, never a finished turn summary or prose', () => {
  assert.equal(hasActiveTurn(CLAUDE_WORKING_FRAME), true);
  assert.equal(hasActiveTurn(['• Working (5s • esc to interrupt)']), true);
  assert.equal(hasActiveTurn(['✻ Thinking… (2m 3s · ↑ 1.2k tokens)']), true);
  assert.equal(hasActiveTurn(CLAUDE_STALE_IDLE_FRAME), false);
  assert.equal(hasActiveTurn(['The build took (12s) and finished.']), false);
});

test('stale native working plus a rendered idle frame AND a satisfied idle wait resumes', async () => {
  const h = staleHarness(CLAUDE_STALE_IDLE_FRAME);
  const state = await superviseStep(waiting, options, h.deps);
  assert.equal(state.phase, 'pending');
  assert.equal(sends(h), 1);
  assert.equal(ran(h, 'read') && ran(h, 'wait'), true);
});

test('stale native working with the same idle frame but no satisfied wait stays unknown and sends nothing', async () => {
  const h = staleHarness(CLAUDE_STALE_IDLE_FRAME, { satisfied: false });
  const state = await superviseStep(waiting, options, h.deps);
  assert.equal(state.phase, 'unknown');
  assert.equal(sends(h), 0);
});

test('a stale working row over a visible spinner is a turn in progress: no wait, no resume', async () => {
  const h = staleHarness(CLAUDE_WORKING_FRAME);
  const state = await superviseStep(waiting, options, h.deps);
  assert.equal(state.phase, 'unknown');
  assert.equal(state.reason, 'stale_native_working_turn_visible');
  assert.equal(ran(h, 'wait'), false);
  assert.equal(sends(h), 0);
});

test('a stale working row never overrides a draft, menu, quota, stream fallback or unknown liveness', async () => {
  const cases = [
    [staleHarness(CLAUDE_STALE_IDLE_FRAME, { draft: 'half-typed' }), 'unknown'],
    [staleHarness([...CLAUDE_STALE_IDLE_FRAME.slice(0, 2), '❯ 1. Yes, allow', '? for shortcuts']), 'unknown'],
    [staleHarness(["You've hit your usage limit", '>']), 'blocked'],
    [staleHarness(CLAUDE_STALE_IDLE_FRAME, { source: 'screen-unavailable' }), 'unknown'],
    [staleHarness(CLAUDE_STALE_IDLE_FRAME, { connected: false }), 'unknown'],
  ];
  for (const [h, phase] of cases) {
    assert.equal((await superviseStep(waiting, options, h.deps)).phase, phase);
    assert.equal(sends(h), 0);
  }
});

test('fresh native working with an empty composer stays working: no screen read, no wait, no send', async () => {
  const h = staleHarness(CLAUDE_STALE_IDLE_FRAME, { age: 5_000 });
  const state = await superviseStep(waiting, options, h.deps);
  assert.equal(state.phase, 'working');
  assert.equal(ran(h, 'read'), false);
  assert.equal(ran(h, 'wait'), false);
  assert.equal(sends(h), 0);
});
