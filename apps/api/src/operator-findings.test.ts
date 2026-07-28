import { describe, expect, it } from 'vitest';
import {
  CLAIM_MEANING,
  NOT_A_MEASUREMENT,
  amendAssertion,
  assertionToDraft,
  describeAssertion,
  isOperatorSource,
  operatorSourceFor,
  partitionByProvenance,
  validateAssertion,
  withdrawAssertion,
} from './operator-findings.js';

const good = {
  assertedBy: 'aaron',
  title: 'Telnet root shell reachable on the shipped unit',
  claim: 'asserted_from_device',
  rationale: 'Logged in over telnet on hardware rev B with the label password; session transcript in ticket 412.',
};

function assertOk(input: Parameters<typeof validateAssertion>[0]) {
  const r = validateAssertion(input);
  if (!r.ok) throw new Error(`expected valid, got: ${r.error}`);
  return r.value;
}

describe('validateAssertion — the ladder is not the operator’s to write on', () => {
  it('refuses a proof state in the claim field, and says why rather than listing valid values', () => {
    const r = validateAssertion({ ...good, claim: 'static_confirmed' });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toMatch(/PROOF STATE/);
    expect(r.error).toMatch(/only code may decide one/);
  });

  it('refuses every rung of the ladder, not just the tempting one', () => {
    for (const rung of [
      'needs_runtime_reproduction',
      'static_confirmed',
      'confirmed_in_emulation',
      'confirmed_full_system',
      'blocked_by_platform',
      'blocked_by_security',
      'false_positive',
    ]) {
      expect(validateAssertion({ ...good, claim: rung }).ok).toBe(false);
    }
  });

  it('refuses a body that carries a proofState at all, instead of silently dropping it', () => {
    const r = validateAssertion({ ...good, proofState: 'static_confirmed' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/Operator findings never do/);
  });

  it('refuses the sentinel itself — it is stamped by FirmLab, not chosen', () => {
    const r = validateAssertion({ ...good, claim: 'operator_assertion' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/stamps on your row automatically/);
  });

  it('requires an author — an assertion with no one behind it is not an assertion', () => {
    const r = validateAssertion({ ...good, assertedBy: '   ' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/assertedBy is required/);
  });

  it('requires a stated basis, because a later reader cannot evaluate a bare claim', () => {
    const r = validateAssertion({ ...good, rationale: '' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/rationale is required/);
  });

  it('defaults an unstated severity to info rather than to a middle rung it did not earn', () => {
    expect(assertOk(good).severity).toBe('info');
    expect(assertOk({ ...good, severity: 'critical' }).severity).toBe('critical');
  });

  it('makes a dispute name its target, and refuses a target on any other claim', () => {
    expect(validateAssertion({ ...good, claim: 'disputes_finding' }).ok).toBe(false);
    expect(validateAssertion({ ...good, claim: 'disputes_finding', disputesFindingId: 'abc123' }).ok).toBe(true);
    expect(validateAssertion({ ...good, disputesFindingId: 'abc123' }).ok).toBe(false);
  });

  it('rejects an author that slugs to nothing, so no row can end up sourced at operator:', () => {
    const r = validateAssertion({ ...good, assertedBy: '!!!' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/at least one letter or digit/);
  });
});

describe('the operator source namespace', () => {
  it('is recognised by prefix, so a provider source can never fall into it by accident', () => {
    expect(isOperatorSource(operatorSourceFor('Aarón G.'))).toBe(true);
    expect(isOperatorSource('sbom')).toBe(false);
    expect(isOperatorSource('binary:usr/sbin/httpd')).toBe(false);
    // The near-miss that would matter: a provider legitimately named "operator" with no colon.
    expect(isOperatorSource('operator')).toBe(false);
  });

  it('is stable per author, so one person’s rows group without ever colliding with another’s', () => {
    expect(operatorSourceFor('Aarón G.')).toBe(operatorSourceFor('aaron g'));
    expect(operatorSourceFor('aaron')).not.toBe(operatorSourceFor('claude'));
  });
});

describe('assertionToDraft', () => {
  it('stamps the non-ladder sentinel, never a proof state', () => {
    const draft = assertionToDraft(assertOk(good), 'human', 1_700_000_000_000);
    expect(draft.proofState).toBe('operator_assertion');
  });

  it('copies the caveat into the evidence, so a raw JSON dump still carries it', () => {
    const draft = assertionToDraft(assertOk(good), 'human', 1_700_000_000_000);
    expect(draft.evidence?.notAMeasurement).toBe(NOT_A_MEASUREMENT);
    expect(draft.evidence?.claimMeaning).toBe(CLAIM_MEANING.asserted_from_device);
    expect(draft.evidence?.assertedBy).toBe('aaron');
  });

  it('records the author kind the transport decided, not one the payload asked for', () => {
    expect(assertionToDraft(assertOk(good), 'agent', 1).assertion.authorKind).toBe('agent');
    expect(assertionToDraft(assertOk(good), 'human', 1).assertion.authorKind).toBe('human');
  });
});

describe('withdrawal is first-class', () => {
  const base = assertionToDraft(assertOk(good), 'human', 1_700_000_000_000).assertion;

  it('keeps the claim, its author and its original basis while retracting it', () => {
    const r = withdrawAssertion(base, 'aaron', 'Wrong unit — the shell was on the dev board, not the shipped one.', 2);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.status).toBe('withdrawn');
    expect(r.value.assertedBy).toBe('aaron');
    expect(r.value.rationale).toBe(base.rationale);
    expect(r.value.withdrawnReason).toMatch(/dev board/);
  });

  it('refuses a bare retraction — the reason is the part worth keeping', () => {
    const r = withdrawAssertion(base, 'aaron', '   ', 2);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/needs a reason/);
  });

  it('refuses to withdraw twice, so the first reason cannot be overwritten', () => {
    const first = withdrawAssertion(base, 'aaron', 'wrong unit', 2);
    if (!first.ok) throw new Error('setup');
    expect(withdrawAssertion(first.value, 'someone', 'again', 3).ok).toBe(false);
  });

  it('records who retracted it separately from who asserted it', () => {
    const r = withdrawAssertion(base, 'reviewer', 'Could not reproduce on three units.', 2);
    if (!r.ok) throw new Error('setup');
    expect(describeAssertion(r.value)).toMatch(/WITHDRAWN by reviewer/);
    expect(describeAssertion(r.value)).toMatch(/originally asserted by aaron/);
  });
});

describe('amendAssertion', () => {
  it('cannot reassign authorship or backdate the original assertion', () => {
    const base = assertionToDraft(assertOk(good), 'human', 1_000).assertion;
    const amended = amendAssertion(
      base,
      assertOk({ ...good, assertedBy: 'someone-else', claim: 'asserted_unverified' }),
      9_000,
    );
    expect(amended.assertedBy).toBe('aaron');
    expect(amended.assertedAt).toBe(1_000);
    expect(amended.amendedAt).toBe(9_000);
    expect(amended.claim).toBe('asserted_unverified');
  });
});

describe('partitionByProvenance — the three populations that must never be summed', () => {
  const measuredRow = { proofState: 'static_confirmed' as const };
  const activeRow = {
    proofState: 'operator_assertion' as const,
    assertion: assertionToDraft(assertOk(good), 'human', 1).assertion,
  };
  const withdrawnRow = {
    proofState: 'operator_assertion' as const,
    assertion: { ...activeRow.assertion, status: 'withdrawn' as const },
  };

  it('splits by the sentinel, not by source, so a hand-set source cannot launder a claim', () => {
    const r = partitionByProvenance([measuredRow, activeRow, withdrawnRow]);
    expect(r.measured).toEqual([measuredRow]);
    expect(r.asserted).toEqual([activeRow]);
    expect(r.withdrawn).toEqual([withdrawnRow]);
  });

  it('never counts a withdrawn assertion as active — otherwise retraction would be cosmetic', () => {
    expect(partitionByProvenance([withdrawnRow]).asserted).toHaveLength(0);
  });

  it('treats a row with no assertion record as measured, which is what every pre-existing row is', () => {
    expect(partitionByProvenance([{ proofState: 'needs_runtime_reproduction' }]).measured).toHaveLength(1);
  });
});

/**
 * The survival property, tested at the only layer a unit test can reach.
 *
 * `deleteFindingsBySource` enforces it in SQL and `syncFindings` throws before it — neither is loadable here,
 * because both import the store and vitest cannot resolve `node:sqlite`. What IS testable is the predicate both
 * of them are built from, so this exercises it against every source string actually present in the deployed
 * ledger. The SQL itself is proven on real bytes in-container: record an assertion, re-run a provider, confirm
 * the row is still there.
 */
describe('a provider re-run cannot erase an operator row', () => {
  // Every source in the deployed DVRF ledger (a2c03536, 101 findings), plus the shapes other providers use.
  const REAL_PROVIDER_SOURCES = [
    'binvuln',
    'sbom',
    'certs',
    'compmap',
    'compcve',
    'secrets',
    'gitleaks',
    'fsaudit',
    'servicemap',
    'uboot',
    'nvram',
    'chipsec',
    'fcc',
    'rtos',
    'binary:usr/sbin/httpd',
    'dynprobe:pwnable/Intro/stack_bof_01#strcpy',
    'symreach:sbin/diag_tracertbutton#sprintf',
    'symreach:usr/sbin/generate_pin#system',
  ];

  it('classifies no real provider source as an operator source', () => {
    for (const s of REAL_PROVIDER_SOURCES) {
      expect(isOperatorSource(s), `${s} must not be treated as hand-authored`).toBe(false);
    }
  });

  it('classifies every author’s source as operator, whatever their name looks like', () => {
    for (const who of ['aaron', 'Aarón G. Filgueira', 'claude/triage-session', 'sbom', 'binary:x', 'operator']) {
      expect(isOperatorSource(operatorSourceFor(who)), `${who} must be protected`).toBe(true);
    }
  });

  it('survives a sync whose source string is an operator source verbatim — the delete is filtered, not matched', () => {
    // The subtle case: a provider that somehow passes `operator:aaron` as its own source. Source equality would
    // match the row; the prefix guard is what still refuses the delete.
    const mine = operatorSourceFor('aaron');
    const ledger = [{ source: mine }, { source: 'sbom' }];
    const applyDelete = (syncSource: string) =>
      ledger.filter((r) => !(r.source === syncSource && !isOperatorSource(r.source)));
    expect(applyDelete(mine)).toHaveLength(2);
    expect(applyDelete('sbom')).toHaveLength(1);
  });
});

describe('describeAssertion', () => {
  it('names the author and marks an agent as one, so a reader never reads it as a person', () => {
    const human = assertionToDraft(assertOk(good), 'human', 1_700_000_000_000).assertion;
    const agent = assertionToDraft(assertOk({ ...good, assertedBy: 'claude' }), 'agent', 1_700_000_000_000).assertion;
    expect(describeAssertion(human)).toMatch(/Asserted by aaron on 2023-11-14/);
    expect(describeAssertion(agent)).toMatch(/claude \(agent\)/);
  });

  it('carries the claim’s meaning, so the caveat travels with the attribution', () => {
    const a = assertionToDraft(assertOk(good), 'human', 1).assertion;
    expect(describeAssertion(a)).toContain('FirmLab cannot measure that at all');
  });
});
