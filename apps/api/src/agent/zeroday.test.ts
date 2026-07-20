import { describe, expect, it } from 'vitest';
import { parseZerodayDecision } from './zeroday.js';

describe('parseZerodayDecision', () => {
  it('coerces a well-formed candidate', () => {
    const d = parseZerodayDecision(
      JSON.stringify({
        candidates: [
          {
            sink: 'system',
            source: 'nvram_get(lan_ipaddr)',
            vulnClass: 'command-injection',
            reachability: 'likely',
            severity: 'critical',
            trigger: 'set NVRAM lan_ipaddr to `;telnetd;`',
            rationale: 'unsanitized nvram value flows into system()',
          },
        ],
        rationale: 'one strong command-injection candidate',
      }),
    );
    expect(d.candidates).toHaveLength(1);
    expect(d.candidates[0]?.vulnClass).toBe('command-injection');
    expect(d.candidates[0]?.reachability).toBe('likely');
    expect(d.candidates[0]?.severity).toBe('critical');
  });

  it('defaults invalid reachability/severity conservatively and drops sink-less entries', () => {
    const d = parseZerodayDecision(
      JSON.stringify({
        candidates: [
          { sink: 'strcpy', reachability: 'definitely', severity: 'apocalyptic', source: 'recv' },
          { source: 'recv', trigger: 'x' }, // no sink → dropped
        ],
      }),
    );
    expect(d.candidates).toHaveLength(1);
    expect(d.candidates[0]?.reachability).toBe('possible');
    expect(d.candidates[0]?.severity).toBe('medium');
    expect(d.candidates[0]?.vulnClass).toBe('other');
  });

  it('an empty candidate list is valid — the node must not invent a bug', () => {
    const d = parseZerodayDecision('{"candidates": [], "rationale": "no sink/source coexistence"}');
    expect(d.candidates).toHaveLength(0);
  });

  it('caps the candidate list at 8', () => {
    const many = { candidates: Array.from({ length: 20 }, (_, i) => ({ sink: `s${i}`, source: 'recv' })) };
    expect(parseZerodayDecision(JSON.stringify(many)).candidates).toHaveLength(8);
  });
});
