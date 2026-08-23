import type { Finding } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import {
  type OpacidadContext,
  buildAttackPath,
  buildLlmPrompt,
  composeDeterministicNarrative,
  honestGaps,
  summarizeFindings,
} from './opacidad-narrative.js';

function finding(over: Partial<Finding>): Finding {
  return {
    id: 'x',
    imageId: 'img',
    source: 'fsaudit',
    kind: 'weak-cred',
    title: 'default',
    severity: 'info',
    proofState: 'needs_runtime_reproduction',
    createdAt: 0,
    ...over,
  };
}

describe('summarizeFindings', () => {
  it('counts by severity + proof state and ranks the top by severity then proof', () => {
    const s = summarizeFindings([
      finding({ severity: 'low', proofState: 'static_confirmed' }),
      finding({ severity: 'critical', proofState: 'confirmed_in_emulation', title: 'root RCE' }),
      finding({ severity: 'critical', proofState: 'needs_runtime_reproduction', title: 'cmdi lead' }),
    ]);
    expect(s.total).toBe(3);
    expect(s.bySeverity.critical).toBe(2);
    expect(s.byProofState.confirmed_in_emulation).toBe(1);
    // The confirmed critical outranks the merely-suspected critical.
    expect(s.top[0]?.title).toBe('root RCE');
  });

  it('splits each severity into exhaustive semantic categories, so a bare count cannot stand alone', () => {
    const s = summarizeFindings([
      finding({ severity: 'critical', proofState: 'static_confirmed' }),
      finding({ severity: 'critical', proofState: 'needs_runtime_reproduction' }),
      finding({ severity: 'critical', proofState: 'blocked_by_platform' }),
    ]);
    expect(s.census).toEqual([
      {
        severity: 'critical',
        total: 3,
        established: 1,
        leads: 1,
        blocked: 1,
        dismissed: 0,
        asserted: 0,
        other: 0,
        unproven: 2,
      },
    ]);
  });
});

describe('the narrative severity line', () => {
  const ctx = (findings: Finding[]): OpacidadContext => ({
    filename: 'fw.bin',
    firmwareClass: 'embedded-linux',
    arch: 'mips',
    plan: [],
    steps: [],
    findings,
  });

  it('qualifies every count with how much of it was established', () => {
    const md = composeDeterministicNarrative(
      ctx([
        finding({ severity: 'critical', proofState: 'static_confirmed' }),
        finding({ severity: 'critical', proofState: 'needs_runtime_reproduction' }),
      ]),
    );
    expect(md).toContain('2 critical (1 established, 1 lead)');
    // The bare count is exactly what this replaces; it must not survive anywhere in the line.
    expect(md).not.toMatch(/·\s*2 critical\s*·/);
  });

  it('does not call a blocked question a lead when both share one severity band', () => {
    const md = composeDeterministicNarrative(
      ctx([
        finding({ severity: 'high', proofState: 'needs_runtime_reproduction' }),
        finding({ severity: 'high', proofState: 'blocked_by_platform' }),
      ]),
    );
    expect(md).toContain('2 high (1 lead, 1 blocked)');
  });

  it('marks a fully-established band as such rather than leaving it ambiguous', () => {
    const md = composeDeterministicNarrative(ctx([finding({ severity: 'medium', proofState: 'static_confirmed' })]));
    expect(md).toContain('1 medium (established)');
  });
});

describe('buildAttackPath', () => {
  it('renders a source→sink→privilege chain from evidence and tags the proof state', () => {
    const path = buildAttackPath([
      finding({
        severity: 'critical',
        proofState: 'confirmed_in_emulation',
        evidence: { source: 'countries param', sink: 'os.execute', privilege: 'root' },
      }),
    ]);
    expect(path[0]).toBe('[critical/confirmed_in_emulation] countries param → os.execute → root');
  });

  it('excludes low-severity and false-positive findings', () => {
    expect(buildAttackPath([finding({ severity: 'low' })])).toEqual([]);
    expect(buildAttackPath([finding({ severity: 'critical', proofState: 'false_positive' })])).toEqual([]);
  });
});

describe('honestGaps + narrative', () => {
  const ctx: OpacidadContext = {
    filename: 'fw.bin',
    firmwareClass: 'esp-soc',
    arch: 'xtensa',
    classRationale: 'ESP SoC flash dump — not Linux.',
    plan: [{ worker: 'W6 · ESP / IoT-SoC', reason: 'NVS keys + eFuse posture' }],
    steps: [
      {
        worker: 'W6 · ESP / IoT-SoC',
        status: 'not-built',
        summary: 'NVS keys + eFuse posture',
        note: 'worker not built',
      },
    ],
    findings: [],
  };

  it('surfaces not-built workers and the "0 findings ≠ clean" caveat', () => {
    const gaps = honestGaps(ctx);
    expect(gaps.some((g) => g.includes('W6') && g.includes('not built'))).toBe(true);
    expect(gaps.some((g) => /does NOT mean/i.test(g))).toBe(true);
  });

  it('deterministic narrative includes class, rationale, workers, and honest gaps', () => {
    const md = composeDeterministicNarrative(ctx);
    expect(md).toContain('esp-soc');
    expect(md).toContain('ESP SoC flash dump');
    expect(md).toContain('W6 · ESP / IoT-SoC');
    expect(md).toContain('Honest gaps');
  });

  it('LLM prompt forbids invention and carries the structured facts', () => {
    const { system, user } = buildLlmPrompt(ctx);
    expect(system).toMatch(/never invent/i);
    expect(system).toMatch(/proof state/i);
    expect(user).toContain('esp-soc');
    expect(user).toContain('W6 · ESP / IoT-SoC');
  });
});
