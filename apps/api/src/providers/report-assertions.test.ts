import type { OperatorAssertion } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import { type StoredAssertion, amendAssertion, assertionToDraft, validateAssertion } from '../operator-findings.js';
import { MAX_MEASURED_ROWS, type ReportFinding, indexDisputes, renderLedgerSections } from './report-assertions.js';

const DAY = 1_700_000_000_000; // 2023-11-14

function valid(over: Record<string, unknown> = {}): ReturnType<typeof assertionToDraft> {
  const r = validateAssertion({
    assertedBy: 'aaron',
    title: 'Telnet root shell reachable on the shipped unit',
    claim: 'asserted_from_device',
    rationale: 'Logged in over telnet on hardware rev B; transcript in ticket 412.',
    ...over,
  });
  if (!r.ok) throw new Error(`fixture invalid: ${r.error}`);
  return assertionToDraft(r.value, 'human', DAY);
}

/** A stored operator row, shaped as the store hands it back after `rowToFinding`. */
function assertedRow(id: string, over: Record<string, unknown> = {}, assertion?: OperatorAssertion): ReportFinding {
  const draft = valid(over);
  return {
    id,
    source: 'operator:aaron',
    kind: draft.kind,
    title: draft.title,
    severity: draft.severity,
    proofState: 'operator_assertion',
    rationale: draft.rationale,
    evidence: draft.evidence,
    assertion: assertion ?? draft.assertion,
  };
}

const measuredRow: ReportFinding = {
  id: 'f0001',
  source: 'binvuln',
  kind: 'unsafe-call',
  title: 'strcpy reachable from the CGI entry point',
  severity: 'high',
  proofState: 'static_confirmed',
  rationale: 'The call is present in the bytes; reachability from network input is not established.',
};

const otherMeasured: ReportFinding = {
  id: 'f0002',
  source: 'sbom',
  kind: 'cve',
  title: 'CVE-2019-0000 — busybox 1.20',
  severity: 'medium',
  proofState: 'needs_runtime_reproduction',
};

describe('an assertion is rendered as testimony, never as a measurement', () => {
  const html = renderLedgerSections([measuredRow, assertedRow('a1')]);

  it('gives assertions their own section, and never lets one into the measured table', () => {
    expect(html.measured).toContain('Findings — measured (1)');
    expect(html.measured).toContain('strcpy reachable');
    expect(html.measured).not.toContain('Telnet root shell');
    expect(html.operator).toContain('Telnet root shell');
    expect(html.operator).not.toContain('strcpy reachable');
  });

  it('emits no proof-state badge in the operator section — the ladder does not appear there at all', () => {
    expect(html.measured).toContain('class="proof"');
    expect(html.operator).not.toContain('class="proof"');
    expect(html.operator).toContain('asserted · not measured');
  });

  it('states the author, the date and the claim on the row itself', () => {
    expect(html.operator).toContain('Asserted by aaron on 2023-11-14');
    expect(html.operator).toContain('asserted_from_device');
    expect(html.operator).toContain('Stated basis:');
    expect(html.operator).toContain('ticket 412');
  });

  it('carries the sentence saying it counts towards no analysis stage', () => {
    expect(html.operator).toContain('counts towards no analysis stage');
    expect(html.operator).toContain('none of it is included in the measured count');
  });

  it('marks an agent author as one, so a reader never takes it for a person', () => {
    const draft = valid({ assertedBy: 'claude' });
    const agentRow: ReportFinding = {
      ...assertedRow('a2'),
      assertion: { ...draft.assertion, assertedBy: 'claude', authorKind: 'agent' },
    };
    expect(renderLedgerSections([agentRow]).operator).toContain('claude (agent)');
  });

  it('escapes what an author typed — the report is opened in a browser', () => {
    const row = assertedRow('a3', { title: '<img src=x onerror=alert(1)>' });
    const out = renderLedgerSections([row]).operator;
    expect(out).not.toContain('<img src=x');
    expect(out).toContain('&lt;img src=x');
  });
});

describe('a dispute annotates the computed row without overriding it', () => {
  const dispute = assertedRow(
    'd1',
    {
      claim: 'disputes_finding',
      title: 'That strcpy is in dead code — the CGI never links this object',
      rationale: 'Checked the linked symbols on the shipped binary; the object is not in the image.',
      disputesFindingId: 'f0001',
    },
    undefined,
  );
  const html = renderLedgerSections([measuredRow, otherMeasured, dispute]);

  it('says so where the finding is rendered', () => {
    expect(html.measured).toContain('CONTESTED BY AN OPERATOR');
    expect(html.measured).toContain('aaron asserts on 2023-11-14');
    expect(html.measured).toContain('dead code');
    expect(html.measured).toContain('class="contested"');
  });

  it('leaves the computed proof state exactly as code decided it', () => {
    expect(html.measured).toContain('<code class="proof">static_confirmed</code>');
    // Stated in the annotation, not only implied by the badge still being there.
    expect(html.measured).toContain('the proof state of this row is still <code>static_confirmed</code>');
    expect(html.measured).toContain('neither changes it, downgrades it nor removes the row');
  });

  it('does not delete or hide the disputed row, and still counts it as measured', () => {
    expect(html.measured).toContain('Findings — measured (2)');
    expect(html.measured).toContain('strcpy reachable from the CGI entry point');
  });

  it('leaves an undisputed row completely unannotated', () => {
    const rowHtml = html.measured.slice(html.measured.indexOf('CVE-2019-0000'));
    expect(rowHtml).not.toContain('CONTESTED');
    const plain = renderLedgerSections([measuredRow, otherMeasured]);
    expect(plain.measured).not.toContain('CONTESTED');
    expect(plain.measured).not.toContain('class="contested"');
    expect(plain.operator).toBe('');
  });

  it('names the finding it contests from the assertion side too', () => {
    expect(html.operator).toContain('Contests finding <code>f0001</code>');
    expect(html.operator).toContain('That row stands exactly as code decided it');
  });

  it('says plainly when the contested row is no longer in the ledger', () => {
    const orphan = assertedRow('d2', {
      claim: 'disputes_finding',
      title: 'Disputes a row a provider re-run has since replaced',
      rationale: 'The binary was rebuilt; this id no longer exists.',
      disputesFindingId: 'gone-9999',
    });
    const out = renderLedgerSections([measuredRow, orphan]).operator;
    expect(out).toContain('no longer in this image');
    expect(out).toContain('replaces its rows with new ids');
  });

  it('stops annotating once the dispute is withdrawn, but keeps the withdrawn claim visible', () => {
    const retracted: ReportFinding = {
      ...dispute,
      assertion: {
        ...(dispute.assertion as OperatorAssertion),
        status: 'withdrawn',
        withdrawnBy: 'aaron',
        withdrawnAt: DAY,
        withdrawnReason: 'I read the wrong map file; the object IS linked.',
      },
    };
    const out = renderLedgerSections([measuredRow, retracted]);
    expect(out.measured).not.toContain('CONTESTED');
    expect(out.operator).toContain('Withdrawn assertions (1)');
    expect(out.operator).toContain('wrong map file');
    expect(indexDisputes([retracted]).size).toBe(0);
  });
});

describe('an amended assertion shows what it superseded', () => {
  it('renders the current claim and the one it replaced, with both bases', () => {
    const first = valid().assertion;
    const secondInput = validateAssertion({
      assertedBy: 'aaron',
      title: 'Telnet root shell reachable on the DEV BOARD, not the shipped unit',
      claim: 'asserted_unverified',
      rationale: 'Re-checked the label: the unit I logged into was an engineering sample.',
    });
    if (!secondInput.ok) throw new Error('fixture');
    const amended = amendAssertion(first, secondInput.value, DAY + 86_400_000);
    const row: ReportFinding = {
      ...assertedRow('a4'),
      title: secondInput.value.title,
      rationale: secondInput.value.rationale,
      assertion: amended,
    };
    const out = renderLedgerSections([row]).operator;

    expect(out).toContain('DEV BOARD');
    expect(out).toContain('superseding 1 earlier claim');
    expect(out).toContain('An amendment appends; it never overwrites');
    // The predecessor, verbatim: its claim, its window and the basis originally given for it.
    expect(out).toContain('asserted_from_device');
    expect(out).toContain('stood from 2023-11-14 to 2023-11-15');
    expect(out).toContain('ticket 412');
  });

  it('says so, rather than pretending nothing was replaced, when an older build lost the predecessor', () => {
    const legacy: StoredAssertion = { ...valid().assertion, amendedAt: DAY + 1, supersedes: [] };
    const out = renderLedgerSections([{ ...assertedRow('a5'), assertion: legacy }]).operator;
    expect(out).toContain('The claim it replaced was not preserved');
  });

  it('renders nothing about amendment for a claim that was never amended', () => {
    expect(renderLedgerSections([assertedRow('a6')]).operator).not.toContain('Amended');
  });
});

describe('a withdrawn assertion stays visible as withdrawn', () => {
  const withdrawn: ReportFinding = {
    ...assertedRow('w1'),
    assertion: {
      ...valid().assertion,
      status: 'withdrawn',
      withdrawnBy: 'reviewer',
      withdrawnAt: DAY,
      withdrawnReason: 'Could not reproduce on three further units.',
    },
  };

  it('is shown, not dropped, with who retracted it and why', () => {
    const out = renderLedgerSections([withdrawn]).operator;
    expect(out).toContain('Withdrawn assertions (1)');
    expect(out).toContain('WITHDRAWN by reviewer');
    expect(out).toContain('Could not reproduce on three further units.');
    expect(out).toContain('withdrawn · not measured');
  });

  it('is excluded from the active count, so a retraction is not cosmetic', () => {
    const out = renderLedgerSections([withdrawn, assertedRow('a7')]).operator;
    expect(out).toContain('Operator assertions (1)');
    expect(out).toContain('Withdrawn assertions (1)');
  });

  it('is still shown when it is the only operator row left standing', () => {
    const out = renderLedgerSections([measuredRow, withdrawn]).operator;
    expect(out).toContain('Operator assertions (0)');
    expect(out).toContain('No assertion currently stands');
    expect(out).toContain('Could not reproduce');
  });
});

describe('the empty cases', () => {
  it('renders no operator section at all when there are no assertions', () => {
    expect(renderLedgerSections([measuredRow]).operator).toBe('');
    expect(renderLedgerSections([]).operator).toBe('');
  });

  it('renders the measured section even when empty, saying an empty ledger is not a clean image', () => {
    const out = renderLedgerSections([]).measured;
    expect(out).toContain('Findings — measured (0)');
    expect(out).toContain('not evidence that the image is clean');
    expect(out).not.toContain('<table>');
  });
});

describe('the population split cannot be gamed, and the cap cannot hide a contest', () => {
  it('classifies by the provenance sentinel, not by the source string', () => {
    const laundered: ReportFinding = { ...assertedRow('l1'), source: 'sbom' };
    const out = renderLedgerSections([laundered]);
    expect(out.measured).toContain('Findings — measured (0)');
    expect(out.operator).toContain('Telnet root shell');
  });

  it('cuts by severity with the rule stated, and never drops a contested row', () => {
    const many: ReportFinding[] = Array.from({ length: MAX_MEASURED_ROWS + 40 }, (_, i) => ({
      id: `bulk${String(i).padStart(4, '0')}`,
      source: 'sbom',
      kind: 'cve',
      title: `CVE-2020-${1000 + i} — filler`,
      severity: 'medium',
      proofState: 'needs_runtime_reproduction',
    }));
    const lowAndContested: ReportFinding = {
      id: 'quiet1',
      source: 'fsaudit',
      kind: 'world-writable',
      title: 'World-writable /etc/passwd',
      severity: 'info',
      proofState: 'static_confirmed',
    };
    const dispute = assertedRow('d9', {
      claim: 'disputes_finding',
      title: 'That path is a symlink into /tmp on the running device',
      rationale: 'Observed on the unit; the extracted tree does not reflect the runtime overlay.',
      disputesFindingId: 'quiet1',
    });
    const out = renderLedgerSections([...many, lowAndContested, dispute]).measured;

    expect(out).toContain(`Showing ${MAX_MEASURED_ROWS} of ${many.length + 1}`);
    expect(out).toContain('ordered by severity');
    expect(out).toContain('never by the order the rows were written');
    // The info-severity row would have been cut on severity alone; the contest keeps it in.
    expect(out).toContain('World-writable /etc/passwd');
    expect(out).toContain('CONTESTED BY AN OPERATOR');
  });
});
