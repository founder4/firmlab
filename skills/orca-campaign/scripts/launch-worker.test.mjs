import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { exitStatusFor, launchWorker, loadPolicy, parseArgs, savePolicy } from './launch-worker.mjs';
import { createEmptyPolicy, recordBlock, serializePolicy } from './policy.mjs';

const exec = promisify(execFile);
const SCRIPT_PATH = fileURLToPath(new URL('./launch-worker.mjs', import.meta.url));
const NOW = 1_700_000_000_000;
const ISO_NOW = new Date(NOW).toISOString();

test('parseArgs: parses options and separates forwarded arguments', () => {
  const parsed = parseArgs([
    '--policy',
    '/tmp/policy.json',
    '--agent',
    'claude',
    '--model',
    'claude-3-5-sonnet',
    '--capacity-domain',
    'custom-domain',
    '--orca',
    '/usr/local/bin/orca',
    '--',
    '--task',
    'task_123',
    '--worktree',
    'current',
  ]);

  assert.equal(parsed.policy, '/tmp/policy.json');
  assert.equal(parsed.agent, 'claude');
  assert.equal(parsed.model, 'claude-3-5-sonnet');
  assert.equal(parsed.capacityDomain, 'custom-domain');
  assert.equal(parsed.orca, '/usr/local/bin/orca');
  assert.deepEqual(parsed.forward, ['--task', 'task_123', '--worktree', 'current']);

  // Missing required options throw
  assert.throws(() => parseArgs(['--agent', 'claude']), /--policy is required/);
  assert.throws(() => parseArgs(['--policy', '/tmp/p']), /--agent is required/);
});

test('launchWorker: missing policy text is refused with zero calls and exit code 3', async () => {
  let callCount = 0;
  const fakeRun = async () => {
    callCount++;
    return { exitCode: 0 };
  };

  const resNull = await launchWorker({ policyText: null, agent: 'claude' }, { run: fakeRun });
  assert.equal(resNull.launched, false);
  assert.equal(resNull.reason, 'policy_missing');
  assert.equal(resNull.domain, null);
  assert.equal(resNull.exitCode, 3);
  assert.equal(callCount, 0);

  const resUndefined = await launchWorker({ policyText: undefined, agent: 'claude' }, { run: fakeRun });
  assert.equal(resUndefined.launched, false);
  assert.equal(resUndefined.reason, 'policy_missing');
  assert.equal(resUndefined.exitCode, 3);
  assert.equal(callCount, 0);
});

test('launchWorker: malformed policy text is refused with zero calls and exit code 3', async () => {
  let callCount = 0;
  const fakeRun = async () => {
    callCount++;
    return { exitCode: 0 };
  };

  const resJson = await launchWorker({ policyText: '{ not valid json', agent: 'claude' }, { run: fakeRun });
  assert.equal(resJson.launched, false);
  assert.equal(resJson.reason, 'policy_invalid');
  assert.equal(resJson.domain, null);
  assert.equal(resJson.exitCode, 3);
  assert.equal(callCount, 0);

  const resSchema = await launchWorker(
    { policyText: JSON.stringify({ version: 999 }), agent: 'claude' },
    { run: fakeRun },
  );
  assert.equal(resSchema.launched, false);
  assert.equal(resSchema.reason, 'policy_invalid');
  assert.equal(resSchema.exitCode, 3);
  assert.equal(callCount, 0);
});

test('launchWorker: blocked launch results in fake run called 0 times, exit code 3, and failure details', async () => {
  let policy = createEmptyPolicy();
  policy = recordBlock(policy, {
    domain: 'provider:anthropic',
    scope: 'provider',
    provider: 'anthropic',
    status: 'blocked',
    reason: 'org_exhaustion',
    evidence: 'quota exceeded',
    observedAt: ISO_NOW,
  });
  const policyText = serializePolicy(policy);

  let callCount = 0;
  const fakeRun = async () => {
    callCount++;
    return { exitCode: 0 };
  };

  const res = await launchWorker(
    {
      policyText,
      agent: 'claude',
      model: 'claude-3-5-sonnet',
      forward: ['--task', 'task_1'],
      now: NOW,
    },
    { run: fakeRun },
  );

  assert.equal(res.launched, false);
  assert.equal(res.reason, 'org_exhaustion');
  assert.equal(res.domain, 'provider:anthropic');
  assert.equal(res.exitCode, 3);
  assert.equal(callCount, 0, 'run must be called 0 times on blocked launch');
});

test('launchWorker: allowed launch invokes run once with exact ordered argv', async () => {
  const policy = createEmptyPolicy();
  const policyText = serializePolicy(policy);

  const calls = [];
  const fakeRun = async (argv) => {
    calls.push(argv);
    return { exitCode: 0, stdout: 'worker started: task_42\n' };
  };

  // With explicit model
  const resWithModel = await launchWorker(
    {
      policyText,
      agent: 'claude',
      model: 'claude-3-5-sonnet',
      forward: ['--task', 'task_42', '--worktree', 'current', '--json'],
      now: NOW,
    },
    { run: fakeRun },
  );

  assert.equal(resWithModel.launched, true);
  assert.equal(resWithModel.exitCode, 0);
  assert.equal(resWithModel.stdout, 'worker started: task_42\n');
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], [
    'orchestration',
    'worker-start',
    '--agent',
    'claude',
    '--model',
    'claude-3-5-sonnet',
    '--task',
    'task_42',
    '--worktree',
    'current',
    '--json',
  ]);

  // Without model (preserves default model when omitted)
  const resNoModel = await launchWorker(
    {
      policyText,
      agent: 'claude',
      forward: ['--task', 'task_99'],
      now: NOW,
    },
    { run: fakeRun },
  );

  assert.equal(resNoModel.launched, true);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1], ['orchestration', 'worker-start', '--agent', 'claude', '--task', 'task_99']);
});

test('launchWorker: rejects forwarded argument overrides of agent/model or terminal reuse', async () => {
  const policy = createEmptyPolicy();
  const policyText = serializePolicy(policy);

  let callCount = 0;
  const fakeRun = async () => {
    callCount++;
    return { exitCode: 0 };
  };

  // Attempting to override --agent in forwarded args
  const resAgent = await launchWorker(
    {
      policyText,
      agent: 'claude',
      forward: ['--agent', 'codex'],
      now: NOW,
    },
    { run: fakeRun },
  );
  assert.equal(resAgent.launched, false);
  assert.equal(resAgent.reason, 'conflicting_forwarded_args');
  assert.equal(resAgent.exitCode, 3);
  assert.equal(callCount, 0);

  // Attempting to override --agent=codex
  const resAgentEq = await launchWorker(
    {
      policyText,
      agent: 'claude',
      forward: ['--agent=codex'],
      now: NOW,
    },
    { run: fakeRun },
  );
  assert.equal(resAgentEq.launched, false);
  assert.equal(resAgentEq.reason, 'conflicting_forwarded_args');
  assert.equal(resAgentEq.exitCode, 3);
  assert.equal(callCount, 0);

  // Attempting to override --model
  const resModel = await launchWorker(
    {
      policyText,
      agent: 'claude',
      model: 'claude-3-5-sonnet',
      forward: ['--model=claude-3-opus'],
      now: NOW,
    },
    { run: fakeRun },
  );
  assert.equal(resModel.launched, false);
  assert.equal(resModel.reason, 'conflicting_forwarded_args');
  assert.equal(resModel.exitCode, 3);
  assert.equal(callCount, 0);

  // Attempting to pass --terminal
  const resTerminal = await launchWorker(
    {
      policyText,
      agent: 'claude',
      forward: ['--terminal', 'term_foreign'],
      now: NOW,
    },
    { run: fakeRun },
  );
  assert.equal(resTerminal.launched, false);
  assert.equal(resTerminal.reason, 'terminal_reuse_disallowed');
  assert.equal(resTerminal.exitCode, 3);
  assert.equal(callCount, 0);
});

test('loadPolicy and savePolicy: atomic write with mode 0o600', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'firmlab-policy-test-'));
  try {
    const policyPath = join(dir, 'policy.json');
    const policy = createEmptyPolicy({ currentProvider: 'anthropic' });

    // Missing policy returns policy_missing
    const missing = await loadPolicy(policyPath);
    assert.equal(missing.error, 'policy_missing');

    // Save policy
    await savePolicy(policyPath, policy);
    const stats = await stat(policyPath);
    // Mode should be 0o600 (owner read/write only)
    assert.equal(stats.mode & 0o777, 0o600);

    // Load policy
    const loaded = await loadPolicy(policyPath);
    assert.equal(loaded.policy.version, 1);
    assert.equal(loaded.policy.currentProvider, 'anthropic');

    // Invalid policy
    await writeFile(policyPath, '{ bad json');
    const invalid = await loadPolicy(policyPath);
    assert.equal(invalid.error, 'policy_invalid');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('CLI: blocked policy exits with code 3 and prints single JSON line to stdout', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'firmlab-cli-test-'));
  try {
    const policyPath = join(dir, 'policy.json');
    let policy = createEmptyPolicy();
    policy = recordBlock(policy, {
      domain: 'provider:anthropic',
      scope: 'provider',
      provider: 'anthropic',
      status: 'blocked',
      reason: 'credits_zero',
      evidence: 'balance 0',
      observedAt: ISO_NOW,
    });
    await writeFile(policyPath, serializePolicy(policy));

    try {
      await exec(process.execPath, [
        SCRIPT_PATH,
        '--policy',
        policyPath,
        '--agent',
        'claude',
        '--model',
        'claude-3-5-sonnet',
      ]);
      assert.fail('CLI should have exited with code 3');
    } catch (err) {
      assert.equal(err.code, 3);
      const parsed = JSON.parse(err.stdout.trim());
      assert.equal(parsed.launched, false);
      assert.equal(parsed.reason, 'credits_zero');
      assert.equal(parsed.domain, 'provider:anthropic');
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('CLI: missing policy file exits with code 3 and policy_missing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'firmlab-cli-test-'));
  try {
    const missingPath = join(dir, 'does_not_exist.json');
    try {
      await exec(process.execPath, [SCRIPT_PATH, '--policy', missingPath, '--agent', 'claude']);
      assert.fail('CLI should have exited with code 3');
    } catch (err) {
      assert.equal(err.code, 3);
      const parsed = JSON.parse(err.stdout.trim());
      assert.equal(parsed.launched, false);
      assert.equal(parsed.reason, 'policy_missing');
      assert.equal(parsed.domain, null);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('CLI: allowed launch invokes mock orca executable propagating output and exit code', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'firmlab-cli-test-'));
  try {
    const policyPath = join(dir, 'policy.json');
    const policy = createEmptyPolicy();
    await writeFile(policyPath, serializePolicy(policy));

    const mockOrcaPath = join(dir, 'mock-orca.mjs');
    const logPath = join(dir, 'orca-calls.json');
    const mockOrcaScript = `#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
writeFileSync(${JSON.stringify(logPath)}, JSON.stringify(process.argv.slice(2)));
process.stdout.write('mock orca launched successfully\\n');
process.exit(0);
`;
    await writeFile(mockOrcaPath, mockOrcaScript);
    await chmod(mockOrcaPath, 0o755);

    const { stdout } = await exec(process.execPath, [
      SCRIPT_PATH,
      '--policy',
      policyPath,
      '--agent',
      'claude',
      '--model',
      'claude-3-5-sonnet',
      '--orca',
      mockOrcaPath,
      '--',
      '--task',
      'task_777',
      '--worktree',
      'current',
    ]);

    assert.match(stdout, /mock orca launched successfully/);

    const recorded = JSON.parse(await readFile(logPath, 'utf8'));
    assert.deepEqual(recorded, [
      'orchestration',
      'worker-start',
      '--agent',
      'claude',
      '--model',
      'claude-3-5-sonnet',
      '--task',
      'task_777',
      '--worktree',
      'current',
    ]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

/** A raw registry holding one domain entry, the way a hand-edited file would carry it. */
function rawRegistry(entry) {
  return JSON.stringify({
    version: 1,
    currentProvider: null,
    domains: [
      {
        status: 'blocked',
        reason: 'usage_limit',
        evidence: 'rendered usage-limit screen',
        observedAt: ISO_NOW,
        resetAt: null,
        ...entry,
      },
    ],
    handoffs: [],
  });
}

test('launchWorker: every malformed identity refuses the launch as policy_invalid with zero run calls', async () => {
  const malformed = {
    'unknown provider': { domain: 'shared-pool', scope: 'provider', provider: 'anthropic-ai' },
    'agent id as provider': { domain: 'shared-pool', scope: 'provider', provider: 'claude' },
    'missing provider': { domain: 'shared-pool', scope: 'provider' },
    'model scope with null model': { domain: 'shared-pool', scope: 'model', provider: 'anthropic', model: null },
    'model scope with blank model': { domain: 'shared-pool', scope: 'model', provider: 'anthropic', model: '  ' },
    'provider scope naming a model': {
      domain: 'provider:anthropic',
      scope: 'provider',
      provider: 'anthropic',
      model: 'x',
    },
    'reserved domain contradicting identity': { domain: 'provider:openai', scope: 'provider', provider: 'anthropic' },
  };
  for (const [label, entry] of Object.entries(malformed)) {
    let callCount = 0;
    const fakeRun = async () => {
      callCount++;
      return { exitCode: 0 };
    };
    const res = await launchWorker(
      { policyText: rawRegistry(entry), agent: 'claude', model: 'x', now: NOW },
      { run: fakeRun },
    );
    assert.equal(res.launched, false, label);
    assert.equal(res.reason, 'policy_invalid', label);
    assert.equal(res.exitCode, 3, label);
    assert.equal(callCount, 0, `${label}: run must not be called`);
  }
});

test('launchWorker: a capitalised provider is canonicalised and refuses the launch, never allows it', async () => {
  let callCount = 0;
  const res = await launchWorker(
    {
      policyText: rawRegistry({ domain: 'provider:anthropic', scope: 'provider', provider: 'Anthropic' }),
      agent: 'claude',
      model: 'x',
      now: NOW,
    },
    {
      run: async () => {
        callCount++;
        return { exitCode: 0 };
      },
    },
  );
  assert.equal(res.launched, false);
  assert.equal(res.reason, 'usage_limit');
  assert.equal(res.domain, 'provider:anthropic');
  assert.equal(callCount, 0);
});

test('launchWorker: a launch naming no model is refused while a model of that provider is blocked', async () => {
  let callCount = 0;
  const res = await launchWorker(
    {
      policyText: rawRegistry({
        domain: 'model:anthropic/claude-opus-5-5',
        scope: 'model',
        provider: 'anthropic',
        model: 'claude-opus-5-5',
      }),
      agent: 'claude',
      now: NOW,
    },
    {
      run: async () => {
        callCount++;
        return { exitCode: 0 };
      },
    },
  );
  assert.equal(res.launched, false);
  assert.equal(res.reason, 'model_unspecified_with_model_block');
  assert.equal(callCount, 0);
});

test('exitStatusFor: a code passes through; a signal is 128 + its number; nothing else is ever 0', () => {
  assert.equal(exitStatusFor(0, null), 0);
  assert.equal(exitStatusFor(2, null), 2);
  assert.equal(exitStatusFor(null, 'SIGTERM'), 143);
  assert.equal(exitStatusFor(null, 'SIGKILL'), 137);
  assert.equal(exitStatusFor(null, 'SIGINT'), 130);
  assert.equal(exitStatusFor(null, 9), 137);
  assert.equal(exitStatusFor(null, 'SIGNOTREAL'), 1);
  assert.equal(exitStatusFor(null, null), 1);
  assert.equal(exitStatusFor(undefined, undefined), 1);
  assert.equal(exitStatusFor(Number.NaN, null), 1);
});

test('launchWorker: a run terminated by a signal or reporting no status never exits 0', async () => {
  const policyText = serializePolicy(createEmptyPolicy());
  const statusOf = async (result) =>
    (await launchWorker({ policyText, agent: 'claude', now: NOW }, { run: async () => result })).exitCode;
  assert.equal(await statusOf({ exitCode: null, signal: 'SIGTERM' }), 143);
  assert.equal(await statusOf({ exitCode: null, signal: 'SIGKILL' }), 137);
  assert.equal(await statusOf({ exitCode: null, signal: null }), 1);
  assert.equal(await statusOf({}), 1);
  assert.equal(await statusOf(undefined), 1);
  assert.equal(await statusOf({ exitCode: 0 }), 0);
  assert.equal(await statusOf({ status: 4 }), 4);
  assert.equal(await statusOf(5), 5);
});

test('CLI: an orca process killed by a signal exits 128 + the signal number', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'firmlab-cli-test-'));
  try {
    const policyPath = join(dir, 'policy.json');
    await writeFile(policyPath, serializePolicy(createEmptyPolicy()));
    const mockOrcaPath = join(dir, 'mock-orca.mjs');
    await writeFile(mockOrcaPath, "#!/usr/bin/env node\nprocess.kill(process.pid, 'SIGTERM');\n");
    await chmod(mockOrcaPath, 0o755);
    try {
      await exec(process.execPath, [SCRIPT_PATH, '--policy', policyPath, '--agent', 'claude', '--orca', mockOrcaPath]);
      assert.fail('CLI must not exit 0 when worker-start was killed');
    } catch (err) {
      assert.equal(err.code, 143);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('CLI: an orca executable that cannot be spawned exits non-zero', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'firmlab-cli-test-'));
  try {
    const policyPath = join(dir, 'policy.json');
    await writeFile(policyPath, serializePolicy(createEmptyPolicy()));
    try {
      await exec(process.execPath, [
        SCRIPT_PATH,
        '--policy',
        policyPath,
        '--agent',
        'claude',
        '--orca',
        join(dir, 'no-such-orca'),
      ]);
      assert.fail('CLI must not exit 0 when worker-start could not be spawned');
    } catch (err) {
      assert.equal(err.code, 1);
      assert.match(err.stderr, /worker-start could not be run/);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
