import { describe, expect, it } from 'vitest';
import type { OpacidadStep } from '../opacidad-narrative.js';
import type { PlanSpec } from '../opacidad-plan.js';
import { buildCoverage } from './coverage.js';

const spec = (worker: string, built = true): PlanSpec => ({
  worker,
  reason: `why ${worker}`,
  needsRootfs: true,
  built,
});
const step = (worker: string, status: OpacidadStep['status'], findingCount = 0, note?: string): OpacidadStep => ({
  worker,
  status,
  summary: `${worker} summary`,
  findingCount,
  ...(note ? { note } : {}),
});

describe('buildCoverage — zero findings is never the same sentence twice', () => {
  it('with nothing executed, an empty findings list reads as UNEXAMINED', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [spec('W1 · Extraction'), spec('W3 · Credentials')],
      steps: null,
      findingCount: 0,
    });
    expect(r.executed).toBe(0);
    expect(r.applicable).toBe(2);
    expect(r.stages.every((s) => s.status === 'not-run')).toBe(true);
    expect(r.verdict).toContain('UNEXAMINED');
    expect(r.ambiguous).toBe(true);
  });

  // Seen on the real DVRF_v03: 28 findings from individually-run stages and manual symreach probes, but no
  // autonomous run — so the row showed "Nothing has analyzed this image yet" beside its own finding count.
  it('does not claim nothing has run when findings exist from individually-run stages', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [spec('W1 · Extraction'), spec('W3 · Credentials')],
      steps: null,
      findingCount: 28,
    });
    expect(r.executed).toBe(0);
    expect(r.verdict).not.toContain('Nothing has analyzed');
    expect(r.verdict).toContain('UNKNOWN');
    expect(r.verdict).toContain('28 finding(s)');
    expect(r.ambiguous).toBe(true);
  });

  it('with every stage run and empty, it is a real negative — and says it is not proof of security', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [spec('A'), spec('B')],
      steps: [step('A', 'ran', 0), step('B', 'ran', 0)],
      findingCount: 0,
    });
    expect(r.executed).toBe(2);
    expect(r.verdict).toContain('All 2 applicable stages ran');
    expect(r.verdict).toContain('not proof the firmware is secure');
  });

  it('with a rootfs-less run, it names the stages the zero does NOT cover', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [spec('W1 · Extraction'), spec('W3 · Credentials'), spec('W5 · Binary-vuln')],
      steps: [
        step('W1 · Extraction', 'degraded', 0, 'no rootfs'),
        step('W3 · Credentials', 'skipped', 0, 'no extracted rootfs available'),
        step('W5 · Binary-vuln', 'skipped', 0, 'no extracted rootfs available'),
      ],
      findingCount: 0,
    });
    expect(r.executed).toBe(1); // only the degraded extraction actually executed
    expect(r.verdict).toContain('never ran');
    expect(r.verdict).toContain('W3 · Credentials');
    expect(r.stages.filter((s) => s.status === 'no-input')).toHaveLength(2);
  });

  it('marks a class-applicable but unbuilt worker as not-built, not as a clean stage', () => {
    const r = buildCoverage({
      firmwareClass: 'esp-soc',
      specs: [spec('W6 · ESP', false)],
      steps: null,
      findingCount: 0,
    });
    expect(r.stages[0]?.status).toBe('not-built');
  });
});

describe('buildCoverage — findings present', () => {
  it('flags an incomplete picture when findings exist but stages were missed', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [spec('A'), spec('B')],
      steps: [step('A', 'ran', 3)],
      findingCount: 3,
    });
    expect(r.verdict).toContain('picture is incomplete');
    expect(r.ambiguous).toBe(true);
  });

  it('is unambiguous only when every applicable stage ran and something was found', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [spec('A')],
      steps: [step('A', 'ran', 2)],
      findingCount: 2,
    });
    expect(r.ambiguous).toBe(false);
    expect(r.verdict).toBe('2 finding(s) across all 1 applicable stages.');
  });

  it('surfaces dynamically re-planned workers as coverage the class plan never named', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [spec('W5 · Binary-vuln sweep')],
      steps: [
        step('W5 · Binary-vuln sweep', 'ran', 4),
        {
          worker: 'W5 · Reachability (httpd)',
          status: 'ran',
          summary: 'strcpy reachable',
          findingCount: 1,
          origin: 'replan',
          trigger: 'stack-overflow candidate',
        },
      ],
      findingCount: 5,
    });
    expect(r.applicable).toBe(2);
    expect(r.stages[1]?.worker).toBe('W5 · Reachability (httpd)');
    expect(r.stages[1]?.reason).toBe('stack-overflow candidate');
  });
});

describe('buildCoverage — a degraded stage must not be absorbed by "all stages ran"', () => {
  // Seen on a real OVMF scan: FwHunt ran 17 of 108 rules and reported itself degraded, yet the verdict read
  // "3 finding(s) across all 2 applicable stages" — the headline quietly absorbing the caveat its own table shows.
  it('names the degraded stages even when every applicable stage executed', () => {
    const r = buildCoverage({
      firmwareClass: 'uefi-bios',
      specs: [spec('UEFI · chipsec'), spec('UEFI · FwHunt implant scan')],
      steps: [
        step('UEFI · chipsec', 'ran', 2),
        step('UEFI · FwHunt implant scan', 'degraded', 1, '91 rule(s) never applied to this image'),
      ],
      findingCount: 3,
    });
    expect(r.executed).toBe(2);
    expect(r.verdict).toContain('DEGRADED');
    expect(r.verdict).toContain('UEFI · FwHunt implant scan');
    // The count alone still misleads, so the banner must stay prominent.
    expect(r.ambiguous).toBe(true);
  });

  it('says nothing about degradation when there is none', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [spec('A'), spec('B')],
      steps: [step('A', 'ran', 1), step('B', 'ran', 2)],
      findingCount: 3,
    });
    expect(r.verdict).not.toContain('DEGRADED');
    expect(r.ambiguous).toBe(false);
  });
});
