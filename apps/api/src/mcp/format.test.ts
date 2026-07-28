import type { OperatorAssertion } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import type { StoredAssertion } from '../operator-findings.js';
import {
  HONESTY_INSTRUCTIONS,
  type McpCoverage,
  type McpDirListing,
  type McpExtraction,
  type McpFileRead,
  type McpFinding,
  coverageHeadline,
  fileListingPayload,
  fileReadPayload,
  findingsPayload,
  reachabilityPayload,
  readHeadline,
  scanPayload,
  toolError,
  toolResult,
} from './format.js';

const coverage = (o: Partial<McpCoverage> = {}): McpCoverage => ({
  firmwareClass: 'embedded-linux',
  applicable: 12,
  executed: 12,
  findingCount: 0,
  verdict: 'All 12 applicable stages ran and recorded nothing.',
  ambiguous: false,
  stages: [],
  ...o,
});

const finding = (o: Partial<McpFinding> = {}): McpFinding => ({
  kind: 'binary-pwnable-candidate',
  title: 'Stack-overflow candidate',
  severity: 'medium',
  proofState: 'needs_runtime_reproduction',
  source: 'binvuln',
  ...o,
});

describe('coverageHeadline — the sentence a model is about to skim into its answer', () => {
  it('leads with UNEXAMINED and forbids the clean reading when nothing ran', () => {
    const h = coverageHeadline(coverage({ executed: 0, verdict: 'Nothing has analyzed this image yet.' }));
    expect(h.startsWith('UNEXAMINED')).toBe(true);
    expect(h).toContain('Do not characterise this image as clean');
  });

  // Caught driving the real bench over MCP: DVRF has 28 findings from individually-run stages and no autonomous
  // run, so it read "UNEXAMINED — … The 28 finding(s) here are real results" — a headline contradicting the
  // verdict it introduces, which is the same defect the coverage verdict itself was fixed for one layer up.
  it('does not call an image unexamined when it is holding real findings', () => {
    const h = coverageHeadline(
      coverage({ executed: 0, findingCount: 28, verdict: 'No autonomous scan has run, so coverage is UNKNOWN.' }),
    );
    expect(h).not.toContain('UNEXAMINED');
    expect(h).toContain('COVERAGE UNKNOWN');
    expect(h).toContain('do not present this as a complete analysis');
  });

  it('scopes the conclusion when only some stages ran', () => {
    const h = coverageHeadline(coverage({ executed: 5, verdict: '5 of 12 ran.' }));
    expect(h).toContain('PARTIAL COVERAGE');
    expect(h).toContain('scoped to the stages that ran');
  });

  it('a full run is still only what THIS deployment can check', () => {
    expect(coverageHeadline(coverage())).toContain('WHAT THIS DEPLOYMENT CAN CHECK');
  });
});

describe('findingsPayload — a findings list is never handed over bare', () => {
  it('puts the coverage verdict before the list and names what produced no result', () => {
    const c = coverage({
      executed: 4,
      applicable: 12,
      stages: [
        { worker: 'W1 · Extraction', reason: '', status: 'found' },
        { worker: 'W3 · Credentials', reason: '', status: 'no-input' },
        { worker: 'W5 · Binary-vuln', reason: '', status: 'not-run' },
        { worker: 'W6 · ESP', reason: '', status: 'not-built' },
      ],
    });
    const p = findingsPayload(c, []);
    expect(Object.keys(p)[0]).toBe('coverageVerdict');
    expect(p.coverageVerdict).toContain('PARTIAL COVERAGE');
    expect(p.notCovered).toEqual(['W3 · Credentials', 'W5 · Binary-vuln', 'W6 · ESP']);
  });

  // The single most important behaviour here: an empty list plus missing coverage must not read as "clean".
  it('treats unavailable coverage as a caveat, not as permission to call the list complete', () => {
    const p = findingsPayload(null, []);
    expect(p.coverageVerdict).toContain('COVERAGE UNKNOWN');
    expect(p.coverageVerdict).toContain('Do not treat this list as complete');
    expect(p.findingCount).toBe(0);
  });

  it('counts proof states so leads cannot be silently read as confirmed bugs', () => {
    const p = findingsPayload(coverage(), [
      finding(),
      finding(),
      finding({ proofState: 'static_confirmed', severity: 'high' }),
      finding({ proofState: 'blocked_by_platform', severity: 'info' }),
    ]);
    expect(p.proofStateCounts).toEqual({
      needs_runtime_reproduction: 2,
      static_confirmed: 1,
      blocked_by_platform: 1,
    });
  });
});

describe('scanPayload — what did not happen is lifted out of the step list', () => {
  it('surfaces incomplete workers separately from the 15-entry trace', () => {
    const p = scanPayload({
      firmwareClass: 'embedded-linux',
      arch: 'mipsel',
      steps: [
        { worker: 'W1', status: 'ran', summary: 'ok', findingCount: 3 },
        { worker: 'W2', status: 'degraded', summary: 'sbom', note: 'syft not installed' },
        { worker: 'W6', status: 'not-built', summary: 'esp' },
      ],
      findings: { total: 3 },
      attackPath: [],
      narrative: 'a narrative',
      honestGaps: ['no dynamic reproduction'],
    });
    expect(p.workersRun).toBe(1);
    expect(p.workersTotal).toBe(3);
    expect(p.workersThatDidNotComplete).toEqual([
      { worker: 'W2', status: 'degraded', why: 'syft not installed' },
      { worker: 'W6', status: 'not-built', why: 'esp' },
    ]);
    // The bounds must precede the story they bound.
    const keys = Object.keys(p);
    expect(keys.indexOf('workersThatDidNotComplete')).toBeLessThan(keys.indexOf('narrative'));
    expect(keys.indexOf('honestGaps')).toBeLessThan(keys.indexOf('narrative'));
  });
});

describe('reachabilityPayload — an absent result must not read as a negative one', () => {
  it('spells out what each outcome does and does not license', () => {
    const p = reachabilityPayload({
      available: true,
      reason: 'r',
      binary: 'bin/x',
      sinks: [
        { sink: 'strcpy', outcome: 'reached', argv1: 'AAAA' },
        { sink: 'gets', outcome: 'not_reached_in_budget', reason: 'step budget reached' },
        { sink: 'system', outcome: 'absent' },
      ],
    });
    const sinks = p.sinks as { sink: string; meaning: string }[];
    expect(sinks[0]?.meaning).toContain('does not establish');
    expect(sinks[1]?.meaning).toContain('NOT evidence the sink is unreachable');
    expect(sinks[1]?.meaning).toContain('NO RESULT');
    expect(sinks[2]?.meaning).toContain('Nothing was learned');
  });

  it('degrades an unrecognised outcome to no-result rather than dropping it', () => {
    const p = reachabilityPayload({ available: true, reason: 'r', binary: 'b', sinks: [{ sink: 'x', outcome: '??' }] });
    expect((p.sinks as { meaning: string }[])[0]?.meaning).toContain('treat as no result');
  });
});

describe('HONESTY_INSTRUCTIONS', () => {
  it('states the two inferences that are always wrong, since both are easy to make', () => {
    expect(HONESTY_INSTRUCTIONS).toContain('empty findings list does NOT mean the firmware is clean');
    expect(HONESTY_INSTRUCTIONS).toContain('not evidence of absence');
  });

  it('binds every proof state a finding can carry', () => {
    for (const state of [
      'static_confirmed',
      'confirmed_in_emulation',
      'confirmed_full_system',
      'needs_runtime_reproduction',
      'blocked_by_platform',
      'blocked_by_security',
      'false_positive',
    ]) {
      expect(HONESTY_INSTRUCTIONS).toContain(state);
    }
  });
});

const extraction = (o: Partial<McpExtraction> = {}): McpExtraction => ({
  state: 'rootfs',
  browsable: true,
  verdict: "Extraction recovered a rootfs at 'squashfs-root'. You are browsing the WHOLE carve.",
  ...o,
});

const listing = (o: Partial<McpDirListing> = {}): McpDirListing => ({
  path: 'squashfs-root/etc',
  entries: [],
  totalEntries: 0,
  fileCount: 0,
  dirCount: 0,
  symlinkCount: 0,
  truncated: false,
  ...o,
});

describe('fileListingPayload', () => {
  it('leads with the extraction verdict, so entries cannot be reached without it', () => {
    const p = fileListingPayload(extraction(), listing());
    expect(Object.keys(p)[0]).toBe('extractionVerdict');
  });

  it('answers a null listing with the reason instead of an empty array read as "nothing here"', () => {
    const p = fileListingPayload(
      extraction({ state: 'never-run', browsable: false, verdict: 'No extraction has run for this image.' }),
      null,
    );
    expect(p.entries).toEqual([]);
    expect(p.note).toMatch(/NOT an empty filesystem/);
    expect(p.extractionVerdict).toMatch(/No extraction has run/);
  });

  it('lifts escaping symlinks out of the entry array and says they cannot be read', () => {
    const p = fileListingPayload(
      extraction(),
      listing({
        entries: [
          {
            name: 'passwd',
            path: 'x/etc/passwd',
            type: 'symlink',
            size: 0,
            modeString: 'lrwxrwxrwx',
            symlinkTarget: '/dev/null',
            symlinkEscapes: true,
          },
          { name: 'group', path: 'x/etc/group', type: 'file', size: 12, modeString: '-rw-r--r--' },
        ],
        totalEntries: 2,
        fileCount: 1,
        symlinkCount: 1,
      }),
    );
    const escaping = p.symlinksLeavingTheExtraction as { path: string; meaning: string }[];
    expect(escaping).toHaveLength(1);
    expect(escaping[0]?.path).toBe('x/etc/passwd');
    expect(escaping[0]?.meaning).toMatch(/CANNOT be read/);
  });

  it('carries the truncation rule when the listing was capped', () => {
    const p = fileListingPayload(
      extraction(),
      listing({ truncated: true, truncationRule: '6497 entries, 2000 shown.' }),
    );
    expect(p.truncation).toBe('6497 entries, 2000 shown.');
  });
});

const read = (o: Partial<McpFileRead> = {}): McpFileRead => ({
  path: 'jffs2-root/private_key.pem',
  size: 451,
  offset: 0,
  bytesRead: 451,
  truncated: false,
  unreadBefore: 0,
  unreadAfter: 0,
  classification: { kind: 'text', reason: 'Text: no NUL bytes. Decided from the bytes.' },
  view: 'text',
  viewReason: 'Text: no NUL bytes. Decided from the bytes.',
  text: '-----BEGIN PUBLIC KEY-----\n',
  adjustments: [],
  claim: 'These bytes are what the extractor wrote to disk.',
  ...o,
});

describe('readHeadline', () => {
  it('licenses a whole-file quote only when the whole file was read', () => {
    expect(readHeadline(read())).toMatch(/^COMPLETE FILE/);
  });

  it('calls a window a window, naming both unread sides', () => {
    const h = readHeadline(read({ size: 5000, bytesRead: 100, truncated: true, unreadBefore: 0, unreadAfter: 4900 }));
    expect(h).toMatch(/^PARTIAL READ/);
    expect(h).toMatch(/4900 unread after/);
    expect(h).toMatch(/do not characterise what you have not read/);
  });

  it('treats a tail window as partial too — bytes skipped before the offset are still unread', () => {
    const h = readHeadline(
      read({ size: 5000, offset: 4900, bytesRead: 100, truncated: true, unreadBefore: 4900, unreadAfter: 0 }),
    );
    expect(h).toMatch(/^PARTIAL READ/);
    expect(h).toMatch(/4900 skipped before/);
  });

  it('reports an empty file as a result rather than as missing content', () => {
    expect(readHeadline(read({ size: 0, bytesRead: 0 }))).toMatch(/^EMPTY FILE/);
  });
});

describe('fileReadPayload', () => {
  it('puts the bound and the claim before the content', () => {
    const keys = Object.keys(fileReadPayload(extraction(), read()));
    expect(keys[0]).toBe('readVerdict');
    expect(keys[1]).toBe('claim');
    expect(keys.indexOf('text')).toBeGreaterThan(keys.indexOf('readVerdict'));
  });

  it('keeps the classification REASON, since "binary from the bytes" and "binary from the name" differ', () => {
    const p = fileReadPayload(extraction(), read());
    expect(p.classificationReason).toMatch(/Decided from the bytes/);
  });

  it('is the surface that would have caught the withdrawn backlog entry', () => {
    // `private_key.pem` holding a PUBLIC key: the payload hands over the bytes, not the filename's implication.
    const p = fileReadPayload(extraction(), read());
    expect(p.text).toContain('BEGIN PUBLIC KEY');
  });
});

describe('toolResult / toolError', () => {
  it('carries the payload as both text and structured content', () => {
    const r = toolResult({ a: 1 });
    expect(r.structuredContent).toEqual({ a: 1 });
    expect(JSON.parse(r.content[0]?.text as string)).toEqual({ a: 1 });
  });

  it('marks a failure as an error instead of returning an empty success', () => {
    expect(toolError('nope')).toMatchObject({ isError: true });
  });
});

/**
 * The seam this feature is riskiest at: an agent can now WRITE a finding, and the read-back must not let it treat
 * its own sentence as the workbench agreeing with it.
 */
describe('findingsPayload — an assertion is never returned as a measurement', () => {
  const assertion = (authorKind: 'human' | 'agent'): NonNullable<McpFinding['assertion']> => ({
    assertedBy: authorKind === 'agent' ? 'claude' : 'aaron',
    authorKind,
    assertedAt: 1_700_000_000_000,
    claim: 'asserted_from_device',
    rationale: 'Logged in on hardware rev B.',
    status: 'active',
  });

  const asserted = (authorKind: 'human' | 'agent' = 'human'): McpFinding =>
    finding({
      kind: 'asserted_from_device',
      title: 'Telnet root shell on the shipped unit',
      proofState: 'operator_assertion',
      source: 'operator:aaron',
      rationale: 'Logged in on hardware rev B.',
      assertion: assertion(authorKind),
    });

  it('lifts assertions out of `findings` entirely', () => {
    const p = findingsPayload(coverage(), [finding(), asserted()]);
    expect(p.findings).toHaveLength(1);
    expect(p.findings[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(p.operatorAssertionCount).toBe(1);
    expect(p.operatorAssertions?.[0]?.title).toBe('Telnet root shell on the shipped unit');
  });

  it('keeps assertions out of the proof-state histogram the model judges evidence strength by', () => {
    const p = findingsPayload(coverage(), [finding(), asserted()]);
    expect(p.proofStateCounts).toEqual({ needs_runtime_reproduction: 1 });
    expect(p.proofStateCounts.operator_assertion).toBeUndefined();
    expect(p.findingCount).toBe(1);
  });

  it('leads every asserted row with the reading, before anything that looks like a result', () => {
    const p = findingsPayload(coverage(), [asserted()]);
    const row = p.operatorAssertions?.[0];
    expect(Object.keys(row ?? {})[0]).toBe('notAMeasurement');
    expect(row?.notAMeasurement).toMatch(/asserted by a named author, not measured/);
    expect(row?.claimMeaning).toMatch(/FirmLab cannot measure that at all/);
  });

  it('marks an agent-authored row as self-authored, and warns about the circularity', () => {
    const p = findingsPayload(coverage(), [asserted('agent')]);
    expect(p.operatorAssertions?.[0]?.selfAuthored).toBe(true);
    expect(p.operatorAssertions?.[0]?.attribution).toMatch(/claude \(agent\)/);
    expect(p.operatorAssertionsNotice).toMatch(/recorded BY YOU/);
    expect(p.operatorAssertionsNotice).toMatch(/not evidence for the claim/);
  });

  it('separates withdrawn assertions, so a retracted claim is never counted as active', () => {
    const withdrawn: McpFinding = {
      ...asserted(),
      assertion: { ...assertion('human'), status: 'withdrawn', withdrawnBy: 'aaron', withdrawnReason: 'wrong unit' },
    };
    const p = findingsPayload(coverage(), [withdrawn]);
    expect(p.operatorAssertionCount).toBe(0);
    expect(p.operatorAssertions).toBeUndefined();
    expect(p.withdrawnAssertions?.[0]?.withdrawn).toBe(true);
    expect(p.withdrawnAssertions?.[0]?.attribution).toMatch(/WITHDRAWN by aaron/);
  });

  it('adds no operator noise at all when the ledger holds none', () => {
    const p = findingsPayload(coverage(), [finding()]);
    expect(p.operatorAssertionCount).toBe(0);
    expect(p.operatorAssertionsNotice).toBeUndefined();
    expect(p.operatorAssertions).toBeUndefined();
    expect(p.withdrawnAssertions).toBeUndefined();
  });

  it('still leads with the coverage verdict — assertions did not displace the original caveat', () => {
    const p = findingsPayload(coverage({ executed: 0, findingCount: 0 }), [asserted()]);
    expect(Object.keys(p)[0]).toBe('coverageVerdict');
    expect(p.coverageVerdict).toContain('UNEXAMINED');
  });
});

describe('HONESTY_INSTRUCTIONS — the briefing covers the write path', () => {
  it('tells the model an assertion it recorded is not evidence for the claim it contains', () => {
    expect(HONESTY_INSTRUCTIONS).toContain('OPERATOR ASSERTIONS');
    expect(HONESTY_INSTRUCTIONS).toMatch(/restatement of your own claim, never evidence for it/);
    expect(HONESTY_INSTRUCTIONS).toMatch(/count towards NO analysis stage/);
  });

  it('binds the two fields that carry the ledger’s history', () => {
    expect(HONESTY_INSTRUCTIONS).toContain('`amendmentHistory`');
    expect(HONESTY_INSTRUCTIONS).toMatch(/They are retired/);
    expect(HONESTY_INSTRUCTIONS).toContain('`disputedByOperator`');
    expect(HONESTY_INSTRUCTIONS).toMatch(/proof state stays exactly as code decided it/);
  });
});

/**
 * The report could show all of this and the agent surface could not, which meant the consumer least able to ask a
 * follow-up question was the one shown least. These cover the two halves of closing that: an amendment's history
 * reaching an agent as history, and a contest reaching it without moving the row it contests.
 */
describe('findingsPayload — amendment history is exposed, and never as a second live claim', () => {
  const amended: StoredAssertion = {
    assertedBy: 'aaron',
    authorKind: 'human',
    assertedAt: 1_700_000_000_000,
    amendedAt: 1_700_500_000_000,
    claim: 'asserted_unverified',
    rationale: 'Only reproducible on the dev board, not the shipped unit.',
    title: 'Telnet root shell on the DEV BOARD',
    status: 'active',
    supersedes: [
      {
        claim: 'asserted_from_device',
        rationale: 'Logged in on hardware rev B.',
        title: 'Telnet root shell on the shipped unit',
        from: 1_700_000_000_000,
        supersededAt: 1_700_500_000_000,
      },
    ],
  };

  const amendedRow = (a: StoredAssertion = amended): McpFinding =>
    finding({
      id: 'op-1',
      kind: a.claim,
      title: a.title ?? 'Telnet root shell on the DEV BOARD',
      proofState: 'operator_assertion',
      source: 'operator:aaron',
      rationale: a.rationale,
      assertion: a,
    });

  it('returns what the claim replaced, labelled as history, with the current claim on the row itself', () => {
    const row = findingsPayload(coverage(), [amendedRow()]).operatorAssertions?.[0];
    // The live claim is the row's own, and it is the amended one.
    expect(row?.claim).toBe('asserted_unverified');
    expect(row?.title).toBe('Telnet root shell on the DEV BOARD');

    const history = row?.amendmentHistory;
    expect(history?.note).toMatch(/^HISTORY, NOT A LIVE CLAIM/);
    expect(history?.note).toMatch(/no longer asserted/);
    expect(history?.amendedOn).toBe('2023-11-20');
    expect(history?.supersededClaimCount).toBe(1);
    expect(history?.supersededClaims[0]).toEqual({
      supersededClaim: 'asserted_from_device',
      supersededTitle: 'Telnet root shell on the shipped unit',
      supersededBasis: 'Logged in on hardware rev B.',
      stoodFrom: '2023-11-14',
      supersededOn: '2023-11-20',
    });
  });

  // The retired sentence must not be reachable under the key a reader uses for the live one.
  it('names no history field `claim`, `title` or `rationale`', () => {
    const row = findingsPayload(coverage(), [amendedRow()]).operatorAssertions?.[0];
    const keys = Object.keys(row?.amendmentHistory?.supersededClaims[0] ?? {});
    expect(keys).not.toContain('claim');
    expect(keys).not.toContain('title');
    expect(keys).not.toContain('rationale');
  });

  it('says the attribution mentions the amendment too, so the sentence and the array agree', () => {
    const row = findingsPayload(coverage(), [amendedRow()]).operatorAssertions?.[0];
    expect(row?.attribution).toMatch(/Amended 2023-11-20/);
    expect(row?.attribution).toMatch(/1 earlier claim is kept in the record/);
  });

  // A stored assertion is data written by an OLDER build (CLAUDE.md): absence is the answer, not a throw.
  it('reads a row from a build with no `supersedes` as no history rather than throwing', () => {
    const old: StoredAssertion = {
      assertedBy: 'aaron',
      authorKind: 'human',
      assertedAt: 1_700_000_000_000,
      claim: 'asserted_from_device',
      rationale: 'Logged in on hardware rev B.',
      status: 'active',
    };
    const p = findingsPayload(coverage(), [amendedRow(old)]);
    expect(p.operatorAssertions?.[0]?.amendmentHistory).toBeUndefined();
    expect(p.operatorAssertions?.[0]?.claim).toBe('asserted_from_device');
  });

  it('reports an amendment whose predecessor was overwritten as a hole, not as "never amended"', () => {
    const { supersedes: _lost, ...lossy } = { ...amended, amendedAt: 1_700_500_000_000 };
    const h = findingsPayload(coverage(), [amendedRow(lossy)]).operatorAssertions?.[0]?.amendmentHistory;
    expect(h?.note).toMatch(/^HISTORY UNAVAILABLE/);
    expect(h?.supersededClaimCount).toBe(0);
    expect(h?.supersededClaims).toEqual([]);
  });

  it('degrades a `supersedes` column of the wrong shape instead of failing the whole payload', () => {
    const junk = { ...amended, supersedes: 'not an array' } as unknown as StoredAssertion;
    expect(() => findingsPayload(coverage(), [amendedRow(junk)])).not.toThrow();
    const h = findingsPayload(coverage(), [amendedRow(junk)]).operatorAssertions?.[0]?.amendmentHistory;
    expect(h?.note).toMatch(/^HISTORY UNAVAILABLE/);
  });

  it('keeps a withdrawn assertion visible as withdrawn, with its history intact', () => {
    const retracted: StoredAssertion = {
      ...amended,
      status: 'withdrawn',
      withdrawnBy: 'aaron',
      withdrawnReason: 'the dev board was not the shipped firmware',
      withdrawnAt: 1_701_000_000_000,
    };
    const p = findingsPayload(coverage(), [amendedRow(retracted)]);
    expect(p.operatorAssertionCount).toBe(0);
    expect(p.withdrawnAssertions?.[0]?.withdrawn).toBe(true);
    expect(p.withdrawnAssertions?.[0]?.attribution).toMatch(/WITHDRAWN by aaron/);
    expect(p.withdrawnAssertions?.[0]?.amendmentHistory?.supersededClaimCount).toBe(1);
  });
});

describe('findingsPayload — a contested measurement carries the contest, and keeps its proof state', () => {
  const target = (): McpFinding =>
    finding({
      id: 'f-1',
      title: 'Hardcoded root password in /etc/shadow',
      severity: 'high',
      proofState: 'static_confirmed',
      source: 'secrets',
    });

  const dispute = (over: Partial<OperatorAssertion> = {}, targetId = 'f-1'): McpFinding =>
    finding({
      id: 'op-9',
      kind: 'disputes_finding',
      title: 'That hash is a placeholder, not a credential',
      severity: 'info',
      proofState: 'operator_assertion',
      source: 'operator:aaron',
      rationale: 'The field is the string "x" on the shipped unit; the hash never ships.',
      assertion: {
        assertedBy: 'aaron',
        authorKind: 'human',
        assertedAt: 1_700_000_000_000,
        claim: 'disputes_finding',
        rationale: 'The field is the string "x" on the shipped unit; the hash never ships.',
        status: 'active',
        disputesFindingId: targetId,
        ...over,
      },
    });

  it('annotates the row without touching its proof state or removing it', () => {
    const p = findingsPayload(coverage(), [target(), dispute()]);
    expect(p.findingCount).toBe(1);
    expect(p.proofStateCounts).toEqual({ static_confirmed: 1 });
    const row = p.findings[0];
    expect(row?.proofState).toBe('static_confirmed');
    const note = row?.disputedByOperator?.[0];
    expect(note?.meaning).toMatch(/still `static_confirmed`/);
    expect(note?.meaning).toMatch(/neither changes it, downgrades it nor removes the row/);
    expect(note?.disputedBy).toBe('aaron');
    expect(note?.authorKind).toBe('human');
    expect(note?.assertedOn).toBe('2023-11-14');
    expect(note?.assertionTitle).toBe('That hash is a placeholder, not a credential');
    expect(note?.assertionId).toBe('op-9');
    expect(note?.statedBasis).toMatch(/never ships/);
  });

  it('puts the contested count and its caveat before the list they bound', () => {
    const p = findingsPayload(coverage(), [target(), dispute()]);
    expect(p.contestedFindingCount).toBe(1);
    expect(p.contestedFindingsNotice).toMatch(/testimony about a measurement/);
    expect(p.contestedFindingsNotice).toMatch(/no row was removed or downgraded/);
    const keys = Object.keys(p);
    expect(keys.indexOf('contestedFindingsNotice')).toBeLessThan(keys.indexOf('findings'));
  });

  it('names the contested row back from the assertion, and says the row still stands', () => {
    const p = findingsPayload(coverage(), [target(), dispute()]);
    const contests = p.operatorAssertions?.[0]?.contestsFinding;
    expect(contests?.findingId).toBe('f-1');
    expect(contests?.stillInLedger).toBe(true);
    expect(contests?.note).toMatch(/stands exactly as code decided it/);
  });

  it('says so when the disputed row is no longer in the ledger, instead of dangling silently', () => {
    const p = findingsPayload(coverage(), [target(), dispute({}, 'f-gone')]);
    expect(p.contestedFindingCount).toBeUndefined();
    expect(p.findings[0]?.disputedByOperator).toBeUndefined();
    const contests = p.operatorAssertions?.[0]?.contestsFinding;
    expect(contests?.stillInLedger).toBe(false);
    expect(contests?.note).toMatch(/no longer in this image/);
  });

  it('leaves an undisputed finding exactly as it arrived — no empty array, no `disputed: false`', () => {
    const p = findingsPayload(coverage(), [target()]);
    expect(p.findings[0]).not.toHaveProperty('disputedByOperator');
    expect(p.contestedFindingCount).toBeUndefined();
    expect(p.contestedFindingsNotice).toBeUndefined();
  });

  it('stops annotating once the contest is withdrawn, but still shows the withdrawal', () => {
    const retracted = dispute({
      status: 'withdrawn',
      withdrawnBy: 'aaron',
      withdrawnReason: 'I was reading the wrong build',
    });
    const p = findingsPayload(coverage(), [target(), retracted]);
    expect(p.findings[0]?.disputedByOperator).toBeUndefined();
    expect(p.contestedFindingCount).toBeUndefined();
    expect(p.withdrawnAssertions?.[0]?.withdrawn).toBe(true);
    const contests = p.withdrawnAssertions?.[0]?.contestsFinding;
    expect(contests?.findingId).toBe('f-1');
    // Caught by rendering a payload rather than by a fixture: the live wording promises the target row "carries
    // the annotation", and a retracted dispute deliberately annotates nothing.
    expect(contests?.note).toMatch(/objection has been retracted/);
    expect(contests?.note).not.toMatch(/carries the annotation/);
  });
});
