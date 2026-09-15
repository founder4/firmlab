import type { OperatorAssertion } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import {
  AUTHOR_KIND_HEADER,
  CLAIM_MEANING,
  NOT_A_MEASUREMENT,
  amendAssertion,
  amendmentAuthor,
  assertionToDraft,
  authorKindOf,
  describeAssertion,
  isOperatorSource,
  operatorSourceFor,
  partitionByProvenance,
  revisionsOf,
  validateAssertion,
  withdrawAssertion,
  withdrawalAuthor,
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

/** An amendment that is expected to be accepted, unwrapped — the refusals are asserted on explicitly below. */
function amendOk(...args: Parameters<typeof amendAssertion>) {
  const r = amendAssertion(...args);
  if (!r.ok) throw new Error(`expected a valid amendment, got: ${r.error}`);
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
    const r = withdrawAssertion(
      base,
      'aaron',
      'human',
      'Wrong unit — the shell was on the dev board, not the shipped one.',
      2,
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.status).toBe('withdrawn');
    expect(r.value.assertedBy).toBe('aaron');
    expect(r.value.rationale).toBe(base.rationale);
    expect(r.value.withdrawnReason).toMatch(/dev board/);
  });

  it('refuses a bare retraction — the reason is the part worth keeping', () => {
    const r = withdrawAssertion(base, 'aaron', 'human', '   ', 2);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/needs a reason/);
  });

  it('refuses to withdraw twice, so the first reason cannot be overwritten', () => {
    const first = withdrawAssertion(base, 'aaron', 'human', 'wrong unit', 2);
    if (!first.ok) throw new Error('setup');
    expect(withdrawAssertion(first.value, 'someone', 'human', 'again', 3).ok).toBe(false);
  });

  it('records who retracted it separately from who asserted it', () => {
    const r = withdrawAssertion(base, 'reviewer', 'human', 'Could not reproduce on three units.', 2);
    if (!r.ok) throw new Error('setup');
    expect(describeAssertion(r.value)).toMatch(/WITHDRAWN by reviewer/);
    expect(describeAssertion(r.value)).toMatch(/originally asserted by aaron/);
  });

  it('stamps the retractor kind from the transport, the way creation and amendment do', () => {
    const byHuman = withdrawAssertion(base, 'reviewer', 'human', 'Could not reproduce on three units.', 2);
    const byAgent = withdrawAssertion(base, 'opacidad', 'agent', 'Re-ran the probe; the port was never open.', 2);
    if (!byHuman.ok || !byAgent.ok) throw new Error('setup');
    expect(byHuman.value.withdrawnByKind).toBe('human');
    expect(byAgent.value.withdrawnByKind).toBe('agent');
    // The kind reaches the sentence, or "an agent retracted a person's claim" renders as a person doing it.
    expect(describeAssertion(byAgent.value)).toMatch(/WITHDRAWN by opacidad \(agent\)/);
    expect(describeAssertion(byHuman.value)).toMatch(/WITHDRAWN by reviewer:/);
    // A human retractor gets no suffix at all — the bare name is what "a person did it" looks like here.
    expect(describeAssertion(byHuman.value)).not.toMatch(/reviewer \(/);
  });

  it('reads a row retracted before the field existed as a kind NOBODY recorded, never as a human', () => {
    // Exactly what an older build wrote: a name, a time, a reason, and no kind. `withdrawnBy` predates
    // `withdrawnByKind`, so this row is ordinary history rather than a corrupt one.
    const legacy: OperatorAssertion = {
      ...base,
      status: 'withdrawn',
      withdrawnBy: 'reviewer',
      withdrawnAt: 2,
      withdrawnReason: 'Could not reproduce.',
    };
    expect(withdrawalAuthor(legacy)).toEqual({ by: 'reviewer', kind: null });
    expect(describeAssertion(legacy)).toMatch(/WITHDRAWN by reviewer \(author kind not recorded\)/);
    expect(describeAssertion(legacy)).not.toMatch(/\(agent\)/);
  });

  it('reports nothing at all rather than a name for a withdrawn row that carries no retractor', () => {
    const nameless: OperatorAssertion = { ...base, status: 'withdrawn', withdrawnReason: 'gone' };
    expect(withdrawalAuthor(nameless)).toBeNull();
    expect(withdrawalAuthor({ ...nameless, withdrawnBy: '   ' })).toBeNull();
    expect(describeAssertion(nameless)).toMatch(/WITHDRAWN by unknown/);
  });

  it('keeps three actors apart across an amendment and a retraction, kinds included', () => {
    const asserted = assertionToDraft(assertOk(good), 'human', 1_000).assertion;
    const amended = amendOk(
      asserted,
      assertOk({ ...good, claim: 'asserted_unverified', rationale: 'second' }),
      'nadia',
      'agent',
      2_000,
    );
    const r = withdrawAssertion(amended, 'reviewer', 'agent', 'Neither reading held up.', 3_000);
    if (!r.ok) throw new Error('setup');
    // Six fields, three actors, and no pair of them collapsed onto another.
    expect([r.value.assertedBy, r.value.authorKind]).toEqual(['aaron', 'human']);
    expect([r.value.amendedBy, r.value.amendedByKind]).toEqual(['nadia', 'agent']);
    expect([r.value.withdrawnBy, r.value.withdrawnByKind]).toEqual(['reviewer', 'agent']);
    expect(revisionsOf(r.value)).toHaveLength(1);
    const sentence = describeAssertion(r.value);
    expect(sentence).toMatch(/WITHDRAWN by reviewer \(agent\)/);
    expect(sentence).toMatch(/originally asserted by aaron/);
    expect(sentence).toMatch(/Amended .* by nadia \(agent\)/);
  });
});

describe('amendAssertion — an amendment appends, it never overwrites', () => {
  it('cannot reassign authorship or backdate the original assertion', () => {
    const base = assertionToDraft(assertOk(good), 'human', 1_000).assertion;
    const amended = amendOk(
      base,
      assertOk({ ...good, assertedBy: 'someone-else', claim: 'asserted_unverified' }),
      'someone-else',
      'human',
      9_000,
    );
    expect(amended.assertedBy).toBe('aaron');
    expect(amended.assertedAt).toBe(1_000);
    expect(amended.amendedAt).toBe(9_000);
    expect(amended.claim).toBe('asserted_unverified');
  });

  it('keeps the claim it replaced, with the basis and the title that stood with it', () => {
    const base = assertionToDraft(assertOk(good), 'human', 1_000).assertion;
    const amended = amendOk(
      base,
      assertOk({
        ...good,
        title: 'It was the dev board',
        claim: 'asserted_unverified',
        rationale: 'Re-read the label.',
      }),
      'aaron',
      'human',
      9_000,
    );
    expect(revisionsOf(amended)).toHaveLength(1);
    const [prior] = revisionsOf(amended);
    expect(prior?.claim).toBe('asserted_from_device');
    expect(prior?.rationale).toBe(good.rationale);
    expect(prior?.title).toBe(good.title);
    expect(prior?.from).toBe(1_000);
    expect(prior?.supersededAt).toBe(9_000);
    // And the current state is the new claim, not a merge of the two.
    expect(amended.claim).toBe('asserted_unverified');
    expect(amended.rationale).toBe('Re-read the label.');
    expect(amended.title).toBe('It was the dev board');
  });

  it('accumulates revisions oldest-first, so a chain of edits stays readable end to end', () => {
    const base = assertionToDraft(assertOk(good), 'human', 1_000).assertion;
    const once = amendOk(
      base,
      assertOk({ ...good, claim: 'asserted_unverified', rationale: 'second' }),
      'aaron',
      'human',
      2_000,
    );
    const twice = amendOk(
      once,
      assertOk({ ...good, claim: 'asserted_from_external_evidence', rationale: 'third' }),
      'aaron',
      'human',
      3_000,
    );
    expect(revisionsOf(twice).map((r) => r.rationale)).toEqual([good.rationale, 'second']);
    expect(revisionsOf(twice).map((r) => r.from)).toEqual([1_000, 2_000]);
    expect(twice.rationale).toBe('third');
  });

  it('survives a withdrawal — retracting an amended claim keeps every earlier one', () => {
    const base = assertionToDraft(assertOk(good), 'human', 1_000).assertion;
    const amended = amendOk(
      base,
      assertOk({ ...good, claim: 'asserted_unverified', rationale: 'second' }),
      'nadia',
      'human',
      2_000,
    );
    const r = withdrawAssertion(amended, 'aaron', 'human', 'Both readings were wrong.', 3_000);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(revisionsOf(r.value)).toHaveLength(1);
    expect(r.value.status).toBe('withdrawn');
    // Three actors, three fields. A withdrawal does not absorb the amendment's author, and neither one becomes
    // the asserter: the row has to be able to say that A claimed it, B rewrote it and C retracted it.
    expect(r.value.assertedBy).toBe('aaron');
    expect(r.value.amendedBy).toBe('nadia');
    expect(r.value.withdrawnBy).toBe('aaron');
  });

  it('drops a dispute target the new claim no longer makes, and keeps it on the revision that did', () => {
    const disputing = assertionToDraft(
      assertOk({ ...good, claim: 'disputes_finding', disputesFindingId: 'f0001' }),
      'human',
      1_000,
    ).assertion;
    const amended = amendOk(disputing, assertOk({ ...good, claim: 'asserted_unverified' }), 'aaron', 'human', 2_000);
    expect(amended.disputesFindingId).toBeUndefined();
    expect(revisionsOf(amended)[0]?.disputesFindingId).toBe('f0001');
  });

  it('reads no history off a row written before amendments were preserved, rather than throwing', () => {
    const legacy = { ...assertionToDraft(assertOk(good), 'human', 1_000).assertion, amendedAt: 5_000 };
    expect(revisionsOf(legacy)).toEqual([]);
    // The same tolerance for a column holding a shape this build does not know.
    expect(revisionsOf({ ...legacy, supersedes: 'nonsense' } as unknown as OperatorAssertion)).toEqual([]);
    expect(revisionsOf({ ...legacy, supersedes: [null, { claim: 7 }] } as unknown as OperatorAssertion)).toEqual([]);
  });

  it('says an amendment happened in the attribution line every surface already shows', () => {
    const base = assertionToDraft(assertOk(good), 'human', 1_700_000_000_000).assertion;
    const amended = amendOk(
      base,
      assertOk({ ...good, claim: 'asserted_unverified' }),
      'aaron',
      'human',
      1_700_086_400_000,
    );
    expect(describeAssertion(amended)).toMatch(/Amended 2023-11-15 by aaron; 1 earlier claim is kept/);
    expect(describeAssertion(base)).not.toMatch(/Amended/);
  });
});

describe('amendAssertion — who amended is recorded, and is not who asserted', () => {
  const base = () => assertionToDraft(assertOk(good), 'human', 1_000).assertion;

  it('refuses an unsigned amendment, the way a withdrawal refuses an unnamed retraction', () => {
    for (const nobody of ['', '   ', undefined as unknown as string, 42 as unknown as string]) {
      const r = amendAssertion(base(), assertOk({ ...good, claim: 'asserted_unverified' }), nobody, 'human', 2_000);
      expect(r.ok).toBe(false);
      if (r.ok) return;
      expect(r.error).toMatch(/amendedBy is required/);
    }
  });

  it('refuses an author name longer than the bound a validated assertion applies', () => {
    const r = amendAssertion(base(), assertOk(good), 'n'.repeat(81), 'human', 2_000);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toMatch(/longer than 80/);
  });

  it('records a different person editing someone else’s claim as THEIR edit, with the claim still theirs', () => {
    const amended = amendOk(
      base(),
      assertOk({ ...good, claim: 'asserted_unverified', rationale: 'It was the dev board, not the shipped unit.' }),
      'nadia',
      'human',
      2_000,
    );
    expect(amended.assertedBy).toBe('aaron');
    expect(amended.authorKind).toBe('human');
    expect(amended.amendedBy).toBe('nadia');
    expect(amended.amendedByKind).toBe('human');
    // And the sentence every surface renders says both, in that order.
    expect(describeAssertion(amended)).toMatch(/Asserted by aaron/);
    expect(describeAssertion(amended)).toMatch(/Amended [\d-]+ by nadia/);
  });

  it('stamps the amender’s kind from the transport, marking an agent’s edit of a human’s claim as an agent’s', () => {
    const amended = amendOk(base(), assertOk({ ...good, claim: 'asserted_unverified' }), 'claude', 'agent', 2_000);
    expect(amended.authorKind).toBe('human');
    expect(amended.amendedByKind).toBe('agent');
    expect(describeAssertion(amended)).toMatch(/Amended [\d-]+ by claude \(agent\)/);
    // The reverse case: a human editing an agent's row leaves the agent's own authorship marked as an agent's.
    const agentRow = assertionToDraft(assertOk({ ...good, assertedBy: 'claude' }), 'agent', 1_000).assertion;
    const byHuman = amendOk(agentRow, assertOk({ ...good, claim: 'asserted_unverified' }), 'aaron', 'human', 2_000);
    expect(byHuman.authorKind).toBe('agent');
    expect(byHuman.amendedByKind).toBe('human');
    expect(describeAssertion(byHuman)).toMatch(/Asserted by claude \(agent\)/);
  });

  it('keeps each link of a chain attributed to whoever made it, not to whoever amended last', () => {
    const once = amendOk(base(), assertOk({ ...good, rationale: 'second' }), 'nadia', 'human', 2_000);
    const twice = amendOk(once, assertOk({ ...good, rationale: 'third' }), 'claude', 'agent', 3_000);
    const [first, second] = revisionsOf(twice);
    // The claim aaron asserted carries no editor: nobody amended it into being.
    expect(first?.rationale).toBe(good.rationale);
    expect(first?.amendedBy).toBeUndefined();
    // The middle claim is nadia's, and stays nadia's after claude amends over it.
    expect(second?.rationale).toBe('second');
    expect(second?.amendedBy).toBe('nadia');
    expect(second?.amendedByKind).toBe('human');
    expect(twice.amendedBy).toBe('claude');
    expect(twice.amendedByKind).toBe('agent');
  });

  it('says an editor is unrecorded on a legacy row rather than crediting the original author', () => {
    // Exactly the shape a build before this feature persisted: amended, with no editor on the row.
    const legacy: OperatorAssertion = { ...base(), amendedAt: 5_000 };
    expect(amendmentAuthor(legacy)).toBeNull();
    expect(describeAssertion(legacy)).toMatch(/Amended [\d-]+ by an author the amending build did not record/);
    expect(describeAssertion(legacy)).not.toMatch(/Amended [\d-]+ by aaron/);
    // A blank or non-string editor degrades the same way rather than rendering an empty name.
    expect(amendmentAuthor({ ...legacy, amendedBy: '  ' })).toBeNull();
    expect(amendmentAuthor({ ...legacy, amendedBy: 7 as unknown as string })).toBeNull();
    // An unknown kind reads as human rather than promoting the edit to an agent's or printing a bare code.
    expect(amendmentAuthor({ ...legacy, amendedBy: 'nadia' })).toEqual({ by: 'nadia', kind: 'human' });
  });

  it('carries an amended legacy row forward without inventing an editor for the claim it replaces', () => {
    const legacy: OperatorAssertion = { ...base(), amendedAt: 5_000, rationale: 'the legacy wording' };
    const amended = amendOk(legacy, assertOk({ ...good, rationale: 'fourth' }), 'nadia', 'human', 6_000);
    expect(revisionsOf(amended)[0]?.rationale).toBe('the legacy wording');
    expect(revisionsOf(amended)[0]?.amendedBy).toBeUndefined();
    expect(revisionsOf(amended)[0]?.from).toBe(5_000);
    expect(amended.amendedBy).toBe('nadia');
  });
});

describe('authorKindOf — the one field a writer cannot state about itself', () => {
  it('stamps an agent only on the header the MCP server sets, and reads the body not at all', () => {
    expect(authorKindOf({ [AUTHOR_KIND_HEADER]: 'agent' })).toBe('agent');
    expect(authorKindOf({ [AUTHOR_KIND_HEADER]: 'AGENT' })).toBe('agent');
    // Fastify hands a repeated header over as an array; it still resolves to the kind it names.
    expect(authorKindOf({ [AUTHOR_KIND_HEADER]: ['agent'] })).toBe('agent');
  });

  it('defaults to human for a missing, empty or unrecognised header', () => {
    expect(authorKindOf({})).toBe('human');
    expect(authorKindOf({ [AUTHOR_KIND_HEADER]: '' })).toBe('human');
    expect(authorKindOf({ [AUTHOR_KIND_HEADER]: 'robot' })).toBe('human');
    expect(authorKindOf({ [AUTHOR_KIND_HEADER]: undefined })).toBe('human');
  });

  it('cannot be forged from a payload field — only the header is consulted', () => {
    // The shape a request would take if it tried: every plausible body key naming a kind, and no header.
    expect(
      authorKindOf({
        authorKind: 'agent',
        amendedByKind: 'agent',
        withdrawnByKind: 'agent',
        body: { authorKind: 'agent' },
      }),
    ).toBe('human');
    // And the reverse: a body claiming `human` cannot weaken the header an agent's transport set.
    expect(authorKindOf({ [AUTHOR_KIND_HEADER]: 'agent', authorKind: 'human' })).toBe('agent');
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
