import assert from 'node:assert/strict';
import test from 'node:test';
import {
  PolicyValidationError,
  capacityDomain,
  createEmptyPolicy,
  evaluateLaunch,
  parsePolicy,
  providerOf,
  recordBlock,
  recordHandoff,
  recordRecovery,
  serializePolicy,
  setCurrentProvider,
} from './policy.mjs';

const NOW = 1_700_000_000_000;
const ISO_NOW = new Date(NOW).toISOString();

test('providerOf: maps known agents and rejects unknown ones', () => {
  assert.equal(providerOf('claude'), 'anthropic');
  assert.equal(providerOf('Claude'), 'anthropic');
  assert.equal(providerOf(' codex '), 'openai');
  assert.equal(providerOf('antigravity'), 'google');
  assert.equal(providerOf('unknown_bot'), null);
  assert.equal(providerOf(''), null);
  assert.equal(providerOf(null), null);
  assert.equal(providerOf(undefined), null);
});

test('capacityDomain: explicit wins, then model-scoped, then provider-scoped', () => {
  assert.equal(
    capacityDomain({ agent: 'claude', model: 'claude-3-5-sonnet', capacityDomain: 'shared-pool' }),
    'shared-pool',
  );
  assert.equal(capacityDomain({ agent: 'claude', model: 'claude-3-5-sonnet' }), 'model:anthropic/claude-3-5-sonnet');
  assert.equal(capacityDomain({ agent: 'claude' }), 'provider:anthropic');
  assert.equal(capacityDomain({ agent: 'unknown' }), null);
  assert.equal(capacityDomain({ agent: 'unknown', capacityDomain: 'custom' }), 'custom');
});

test('parsePolicy and serializePolicy: roundtrip and schema validation', () => {
  const policy = createEmptyPolicy({ currentProvider: 'anthropic' });
  const serialized = serializePolicy(policy);
  const parsed = parsePolicy(serialized);
  assert.equal(parsed.version, 1);
  assert.equal(parsed.currentProvider, 'anthropic');
  assert.deepEqual(parsed.domains, []);
  assert.deepEqual(parsed.handoffs, []);

  // Fails closed on invalid inputs
  assert.throws(() => parsePolicy('{ bad json'), PolicyValidationError);
  assert.throws(() => parsePolicy(JSON.stringify({ version: 2, domains: [] })), PolicyValidationError);
  assert.throws(() => parsePolicy(JSON.stringify({ version: 1, domains: [{ domain: '' }] })), PolicyValidationError);
  assert.throws(
    () =>
      parsePolicy(
        JSON.stringify({
          version: 1,
          domains: [
            {
              domain: 'test',
              scope: 'invalid-scope',
              provider: 'anthropic',
              status: 'blocked',
              reason: 'quota',
              evidence: 'err',
              observedAt: ISO_NOW,
            },
          ],
        }),
      ),
    PolicyValidationError,
  );
});

test('recordBlock: creates new immutable policy validating entries', () => {
  const base = createEmptyPolicy();
  const blocked = recordBlock(base, {
    domain: 'provider:anthropic',
    scope: 'provider',
    provider: 'anthropic',
    status: 'blocked',
    reason: 'credit_exhaustion',
    evidence: '429 credit balance too low',
    observedAt: ISO_NOW,
  });

  assert.notEqual(base, blocked);
  assert.equal(base.domains.length, 0);
  assert.equal(blocked.domains.length, 1);
  assert.equal(blocked.domains[0].domain, 'provider:anthropic');

  // Fails on invalid fields
  assert.throws(
    () =>
      recordBlock(base, {
        domain: 'provider:anthropic',
        scope: 'invalid',
        provider: 'anthropic',
        status: 'blocked',
        reason: 'r',
        evidence: 'e',
      }),
    PolicyValidationError,
  );
});

test('recordRecovery: requires canary evidence; lifts block when provided', () => {
  const base = createEmptyPolicy();

  // Recovery without canary evidence throws
  assert.throws(
    () => recordRecovery(base, { domain: 'provider:anthropic' }),
    PolicyValidationError,
    'recovery without canary evidence throws',
  );
  assert.throws(
    () => recordRecovery(base, { domain: 'provider:anthropic', recoveredBy: '   ' }),
    PolicyValidationError,
    'recovery with empty canary evidence throws',
  );

  // Recovery with evidence creates recovery entry
  const recovered = recordRecovery(base, {
    domain: 'provider:anthropic',
    recoveredBy: 'canary probe run_test passed with exit 0',
    observedAt: ISO_NOW,
  });
  assert.equal(recovered.domains.length, 1);
  assert.equal(recovered.domains[0].status, 'recovered');
  assert.equal(recovered.domains[0].recoveredBy, 'canary probe run_test passed with exit 0');
});

test('recordHandoff: reason validation and forced_test opt-in requirement', () => {
  const base = createEmptyPolicy();

  // Invalid reason throws
  assert.throws(
    () =>
      recordHandoff(base, {
        fromHandle: 'term_1',
        toHandle: 'term_2',
        generation: 1,
        reason: 'bogus_reason',
      }),
    PolicyValidationError,
  );

  // forced_test without explicitUserOptIn throws
  assert.throws(
    () =>
      recordHandoff(base, {
        fromHandle: 'term_1',
        toHandle: 'term_2',
        generation: 1,
        reason: 'forced_test',
      }),
    PolicyValidationError,
    'forced_test without opt-in throws',
  );

  assert.throws(
    () =>
      recordHandoff(base, {
        fromHandle: 'term_1',
        toHandle: 'term_2',
        generation: 1,
        reason: 'forced_test',
        explicitUserOptIn: false,
      }),
    PolicyValidationError,
  );

  // forced_test with opt-in accepted
  const handoff = recordHandoff(base, {
    fromHandle: 'term_1',
    toHandle: 'term_2',
    generation: 1,
    reason: 'forced_test',
    explicitUserOptIn: true,
  });
  assert.equal(handoff.handoffs.length, 1);
  assert.equal(handoff.handoffs[0].reason, 'forced_test');
  assert.equal(handoff.handoffs[0].explicitUserOptIn, true);

  // Other valid reasons succeed
  const handoffExhausted = recordHandoff(base, {
    fromHandle: 'term_1',
    toHandle: 'term_2',
    generation: 2,
    reason: 'capacity_exhausted',
  });
  assert.equal(handoffExhausted.handoffs[0].reason, 'capacity_exhausted');
});

test('setCurrentProvider: preserves policy and updates current provider', () => {
  const base = createEmptyPolicy();
  const updated = setCurrentProvider(base, 'anthropic');
  assert.equal(updated.currentProvider, 'anthropic');
  assert.equal(base.currentProvider, null);
});

test('evaluateLaunch: unknown agent is refused', () => {
  const policy = createEmptyPolicy();
  const res = evaluateLaunch(policy, { agent: 'mystery-bot' }, NOW);
  assert.equal(res.allowed, false);
  assert.equal(res.reason, 'unknown_provider');
});

test('evaluateLaunch: unknown capacity allowed with no_recorded_block', () => {
  const policy = createEmptyPolicy();
  const res = evaluateLaunch(policy, { agent: 'claude', model: 'claude-3-5-sonnet' }, NOW);
  assert.equal(res.allowed, true);
  assert.equal(res.reason, 'no_recorded_block');
  assert.equal(res.domain, 'model:anthropic/claude-3-5-sonnet');
});

test('evaluateLaunch: blocked provider refuses every model of that provider', () => {
  let policy = createEmptyPolicy();
  policy = recordBlock(policy, {
    domain: 'provider:anthropic',
    scope: 'provider',
    provider: 'anthropic',
    status: 'blocked',
    reason: 'account_rate_limited',
    evidence: 'HTTP 429',
    observedAt: ISO_NOW,
  });

  const modelA = evaluateLaunch(policy, { agent: 'claude', model: 'claude-3-5-sonnet' }, NOW);
  assert.equal(modelA.allowed, false);
  assert.equal(modelA.reason, 'account_rate_limited');
  assert.equal(modelA.domain, 'provider:anthropic');

  const modelB = evaluateLaunch(policy, { agent: 'claude', model: 'claude-3-opus' }, NOW);
  assert.equal(modelB.allowed, false);
  assert.equal(modelB.reason, 'account_rate_limited');

  const defaultModel = evaluateLaunch(policy, { agent: 'claude' }, NOW);
  assert.equal(defaultModel.allowed, false);
  assert.equal(defaultModel.reason, 'account_rate_limited');

  // Different provider is unaffected
  const codex = evaluateLaunch(policy, { agent: 'codex', model: 'o3' }, NOW);
  assert.equal(codex.allowed, true);
});

test('evaluateLaunch: blocked model allows another model of same provider only without provider block', () => {
  let policy = createEmptyPolicy();
  policy = recordBlock(policy, {
    domain: 'model:anthropic/claude-3-opus',
    scope: 'model',
    provider: 'anthropic',
    model: 'claude-3-opus',
    status: 'blocked',
    reason: 'model_capacity_exhausted',
    evidence: '503 overloaded',
    observedAt: ISO_NOW,
  });

  // Blocked model refused
  const opus = evaluateLaunch(policy, { agent: 'claude', model: 'claude-3-opus' }, NOW);
  assert.equal(opus.allowed, false);
  assert.equal(opus.reason, 'model_capacity_exhausted');
  assert.equal(opus.domain, 'model:anthropic/claude-3-opus');

  // Another model of same provider is allowed
  const sonnet = evaluateLaunch(policy, { agent: 'claude', model: 'claude-3-5-sonnet' }, NOW);
  assert.equal(sonnet.allowed, true);
  assert.equal(sonnet.reason, 'no_recorded_block');

  // If a provider-level block is now added, both models are refused
  policy = recordBlock(policy, {
    domain: 'provider:anthropic',
    scope: 'provider',
    provider: 'anthropic',
    status: 'blocked',
    reason: 'account_suspended',
    evidence: 'billing hold',
    observedAt: new Date(NOW + 1000).toISOString(),
  });

  const sonnetAfter = evaluateLaunch(policy, { agent: 'claude', model: 'claude-3-5-sonnet' }, NOW + 2000);
  assert.equal(sonnetAfter.allowed, false);
  assert.equal(sonnetAfter.reason, 'account_suspended');

  const opusAfter = evaluateLaunch(policy, { agent: 'claude', model: 'claude-3-opus' }, NOW + 2000);
  assert.equal(opusAfter.allowed, false);
  assert.equal(opusAfter.reason, 'account_suspended');
});

test('evaluateLaunch: shared domain via --capacity-domain blocks both models naming it', () => {
  let policy = createEmptyPolicy();
  policy = recordBlock(policy, {
    domain: 'anthropic-tier-1',
    scope: 'model',
    provider: 'anthropic',
    model: null,
    status: 'blocked',
    reason: 'tier_quota_depleted',
    evidence: 'rate limit pool empty',
    observedAt: ISO_NOW,
  });

  const launchA = evaluateLaunch(
    policy,
    { agent: 'claude', model: 'claude-3-5-sonnet', capacityDomain: 'anthropic-tier-1' },
    NOW,
  );
  assert.equal(launchA.allowed, false);
  assert.equal(launchA.reason, 'tier_quota_depleted');
  assert.equal(launchA.domain, 'anthropic-tier-1');

  const launchB = evaluateLaunch(
    policy,
    { agent: 'claude', model: 'claude-3-opus', capacityDomain: 'anthropic-tier-1' },
    NOW,
  );
  assert.equal(launchB.allowed, false);
  assert.equal(launchB.reason, 'tier_quota_depleted');
  assert.equal(launchB.domain, 'anthropic-tier-1');
});

test('evaluateLaunch: capacity-domain is accounting metadata only, cannot bypass provider or model block', () => {
  let policy = createEmptyPolicy();
  policy = recordBlock(policy, {
    domain: 'provider:anthropic',
    scope: 'provider',
    provider: 'anthropic',
    status: 'blocked',
    reason: 'provider_down',
    evidence: 'gateway timeout',
    observedAt: ISO_NOW,
  });

  // Attempting to bypass provider block with an unblocked capacity-domain fails
  const launch = evaluateLaunch(
    policy,
    { agent: 'claude', model: 'claude-3-5-sonnet', capacityDomain: 'clean-custom-domain' },
    NOW,
  );
  assert.equal(launch.allowed, false);
  assert.equal(launch.reason, 'provider_down');
  assert.equal(launch.domain, 'provider:anthropic');
});

test('evaluateLaunch: elapsed resetAt is still refused (reset_elapsed_requires_viable_canary)', () => {
  let policy = createEmptyPolicy();
  const pastReset = new Date(NOW - 60_000).toISOString(); // 1 minute in the past
  policy = recordBlock(policy, {
    domain: 'provider:anthropic',
    scope: 'provider',
    provider: 'anthropic',
    status: 'blocked',
    reason: 'rate_limit_exceeded',
    evidence: 'retry-after header elapsed',
    observedAt: new Date(NOW - 120_000).toISOString(),
    resetAt: pastReset,
  });

  const res = evaluateLaunch(policy, { agent: 'claude' }, NOW);
  assert.equal(res.allowed, false);
  assert.equal(res.reason, 'reset_elapsed_requires_viable_canary');

  // Future resetAt keeps the original reason
  const futureReset = new Date(NOW + 60_000).toISOString();
  let futurePolicy = createEmptyPolicy();
  futurePolicy = recordBlock(futurePolicy, {
    domain: 'provider:anthropic',
    scope: 'provider',
    provider: 'anthropic',
    status: 'blocked',
    reason: 'rate_limit_exceeded',
    evidence: 'retry-after 60s',
    observedAt: ISO_NOW,
    resetAt: futureReset,
  });
  const resFuture = evaluateLaunch(futurePolicy, { agent: 'claude' }, NOW);
  assert.equal(resFuture.allowed, false);
  assert.equal(resFuture.reason, 'rate_limit_exceeded');
});

test('evaluateLaunch: recovery with evidence allows launch', () => {
  let policy = createEmptyPolicy();
  policy = recordBlock(policy, {
    domain: 'provider:anthropic',
    scope: 'provider',
    provider: 'anthropic',
    status: 'blocked',
    reason: 'outage',
    evidence: '500 service unavailable',
    observedAt: new Date(NOW - 10_000).toISOString(),
  });

  const blockedRes = evaluateLaunch(policy, { agent: 'claude' }, NOW);
  assert.equal(blockedRes.allowed, false);

  policy = recordRecovery(policy, {
    domain: 'provider:anthropic',
    recoveredBy: 'canary probe prompt succeeded at 2026-10-02T19:00:00Z',
    observedAt: new Date(NOW).toISOString(),
  });

  const recoveredRes = evaluateLaunch(policy, { agent: 'claude' }, NOW + 1000);
  assert.equal(recoveredRes.allowed, true);
  assert.equal(recoveredRes.reason, 'recovered');
  assert.equal(recoveredRes.domain, 'provider:anthropic');
});

test('evaluateLaunch: fresh terminal or handle is irrelevant to the decision', () => {
  let policy = createEmptyPolicy();
  policy = recordBlock(policy, {
    domain: 'provider:anthropic',
    scope: 'provider',
    provider: 'anthropic',
    status: 'blocked',
    reason: 'quota_exhausted',
    evidence: 'out of tokens',
    observedAt: ISO_NOW,
  });

  // Decisions are identical regardless of terminal handle
  const res1 = evaluateLaunch(policy, { agent: 'claude', handle: 'term_1111' }, NOW);
  const res2 = evaluateLaunch(policy, { agent: 'claude', handle: 'term_fresh_9999' }, NOW);
  const res3 = evaluateLaunch(policy, { agent: 'claude' }, NOW);

  assert.equal(res1.allowed, false);
  assert.equal(res2.allowed, false);
  assert.equal(res3.allowed, false);
  assert.equal(res1.reason, res2.reason);
  assert.equal(res1.domain, res2.domain);
});

test('evaluateLaunch: deterministic latest domain resolution', () => {
  const domain = 'model:anthropic/claude-3-5-sonnet';
  const policy = {
    version: 1,
    currentProvider: null,
    domains: [
      {
        domain,
        scope: 'model',
        provider: 'anthropic',
        model: 'claude-3-5-sonnet',
        status: 'blocked',
        reason: 'first_block',
        evidence: 'err1',
        observedAt: '2026-10-02T10:00:00.000Z',
      },
      {
        domain,
        scope: 'model',
        provider: 'anthropic',
        model: 'claude-3-5-sonnet',
        status: 'blocked',
        reason: 'latest_block',
        evidence: 'err2',
        observedAt: '2026-10-02T12:00:00.000Z',
      },
      {
        domain,
        scope: 'model',
        provider: 'anthropic',
        model: 'claude-3-5-sonnet',
        status: 'blocked',
        reason: 'intermediate_block',
        evidence: 'err3',
        observedAt: '2026-10-02T11:00:00.000Z',
      },
    ],
    handoffs: [],
  };

  const res = evaluateLaunch(
    policy,
    { agent: 'claude', model: 'claude-3-5-sonnet' },
    Date.parse('2026-10-02T13:00:00Z'),
  );
  assert.equal(res.allowed, false);
  assert.equal(res.reason, 'latest_block');
});

test('a launch naming no model is refused while any model of that provider is blocked', () => {
  const policy = recordBlock(createEmptyPolicy(), {
    domain: 'model:anthropic/claude-opus-5-5',
    scope: 'model',
    provider: 'anthropic',
    model: 'claude-opus-5-5',
    reason: 'usage_limit',
    evidence: 'rendered usage-limit footer',
    observedAt: '2026-10-02T18:00:00Z',
  });
  const unnamed = evaluateLaunch(policy, { agent: 'claude' }, Date.parse('2026-10-02T18:01:00Z'));
  assert.equal(unnamed.allowed, false);
  assert.equal(unnamed.reason, 'model_unspecified_with_model_block');
  assert.equal(evaluateLaunch(policy, { agent: 'claude', model: 'claude-sonnet-5-5' }).allowed, true);
  assert.equal(evaluateLaunch(policy, { agent: 'codex' }).allowed, true);
});
