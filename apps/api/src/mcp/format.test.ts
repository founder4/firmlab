import { describe, expect, it } from 'vitest';
import {
  HONESTY_INSTRUCTIONS,
  type McpCoverage,
  type McpFinding,
  coverageHeadline,
  findingsPayload,
  reachabilityPayload,
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
