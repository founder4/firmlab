import { describe, expect, it } from 'vitest';
import type { OpacidadStep } from '../opacidad-narrative.js';
import { type PlanSpec, specsForClass } from '../opacidad-plan.js';
import { buildCoverage } from './coverage.js';

const CROSS_CHECK = 'Cross-check · Kernel command line';

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

/**
 * The kernel-command-line cross-check used to fold into the U-Boot and device-tree steps: the arithmetic balanced,
 * and there was no row anywhere saying whether the question had been asked. That is the conflation this whole
 * report exists to prevent, so it now has a stage — and it has it by being in `specsForClass`, the same plan W9
 * executes, rather than by anything here knowing the check exists.
 */
describe('buildCoverage — the cross-check is a stage an operator can see going unasked', () => {
  it('gets a row for a class that routes to it, taken straight from the plan', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: specsForClass('embedded-linux'),
      steps: null,
      findingCount: 0,
    });
    const stage = r.stages.find((s) => s.worker === CROSS_CHECK);
    expect(stage).toBeDefined();
    expect(stage?.status).toBe('not-run');
    expect(stage?.reason).toContain('do they agree');
  });

  it('gets no row for a plan that does not route to it — coverage never invents a stage', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [spec('W1 · Extraction'), spec('W3 · Credentials')],
      steps: null,
      findingCount: 0,
    });
    expect(r.stages.some((s) => s.worker === CROSS_CHECK)).toBe(false);
    expect(r.applicable).toBe(2);
  });

  it('keeps the executed/applicable arithmetic balanced once it runs', () => {
    const specs = [spec('Static · U-Boot env'), spec('Static · Device tree'), spec(CROSS_CHECK)];
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs,
      steps: [
        step('Static · U-Boot env', 'ran', 2),
        step('Static · Device tree', 'ran', 1),
        step(CROSS_CHECK, 'ran', 1),
      ],
      findingCount: 4,
    });
    expect(r.applicable).toBe(3);
    expect(r.executed).toBe(3);
    expect(r.verdict).toBe('4 finding(s) across all 3 applicable stages.');
    expect(r.ambiguous).toBe(false);
  });

  // The half that mattered: a scan where one feeding stage never ran must leave the cross-check visibly unanswered
  // rather than counted as a stage that looked and found nothing.
  it('names the cross-check among the stages a zero does NOT cover when it could not be made', () => {
    const specs = [spec('Static · U-Boot env'), spec('Static · Device tree'), spec(CROSS_CHECK)];
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs,
      steps: [
        step('Static · U-Boot env', 'ran', 0),
        step('Static · Device tree', 'ran', 0),
        step(CROSS_CHECK, 'degraded', 0, 'the device-tree stage did not run in this scan'),
      ],
      findingCount: 0,
    });
    expect(r.executed).toBe(3);
    expect(r.applicable).toBe(3);
    expect(r.verdict).toContain('DEGRADED');
    expect(r.verdict).toContain(CROSS_CHECK);
    expect(r.ambiguous).toBe(true);
  });
});

/**
 * The property that matters: writing an assertion must not move a single number in the stage arithmetic. If it
 * could, the ledger would become a way to make an unexamined image look examined — which is the exact conflation
 * this whole report exists to prevent, arriving through a door it did not previously have.
 */
describe('buildCoverage — operator assertions are counted apart, never as coverage', () => {
  const unscanned = (): { firmwareClass: string; specs: PlanSpec[]; steps: null } => ({
    firmwareClass: 'embedded-linux',
    specs: [spec('A'), spec('B')],
    steps: null,
  });

  it('leaves an image with three assertions and no analysis reading UNEXAMINED', () => {
    const r = buildCoverage({ ...unscanned(), findingCount: 0, operatorAssertions: 3 });
    expect(r.executed).toBe(0);
    expect(r.findingCount).toBe(0);
    expect(r.operatorAssertions).toBe(3);
    expect(r.verdict).toContain('UNEXAMINED');
    expect(r.verdict).toContain('Nothing has analyzed this image yet');
  });

  it('names them as statements by an author rather than letting them pass as results', () => {
    const r = buildCoverage({ ...unscanned(), findingCount: 0, operatorAssertions: 2 });
    expect(r.verdict).toContain('2 operator assertion(s)');
    expect(r.verdict).toContain('not measurements');
    expect(r.verdict).toContain('cover no stage');
  });

  it('changes no number and no clause of the stage arithmetic, whatever the assertion count', () => {
    const base = { ...unscanned(), steps: [step('A', 'ran', 3), step('B', 'skipped')], findingCount: 3 };
    const without = buildCoverage(base);
    const with7 = buildCoverage({ ...base, operatorAssertions: 7 });
    expect(with7.executed).toBe(without.executed);
    expect(with7.applicable).toBe(without.applicable);
    expect(with7.findingCount).toBe(without.findingCount);
    expect(with7.ambiguous).toBe(without.ambiguous);
    // The pre-existing sentence survives verbatim; the assertion clause is strictly appended.
    expect(with7.verdict.startsWith(without.verdict)).toBe(true);
  });

  it('appends the clause in the fully-covered branch too, so a reader never learns to stop looking for it', () => {
    const r = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [spec('A')],
      steps: [step('A', 'ran', 2)],
      findingCount: 2,
      operatorAssertions: 1,
    });
    expect(r.verdict).toContain('2 finding(s) across all 1 applicable stages');
    expect(r.verdict).toContain('1 operator assertion(s)');
  });

  it('reports zero, and stays silent about them, when nobody has asserted anything', () => {
    const r = buildCoverage({ ...unscanned(), findingCount: 0 });
    expect(r.operatorAssertions).toBe(0);
    expect(r.verdict).not.toContain('operator assertion');
  });
});

/**
 * The verdict is the one sentence a Spanish operator reads above the findings list, and until now it arrived in
 * English inside Spanish chrome. It is composed here rather than in the browser because it reads the same class
 * plan the autonomous scan executes — that makes it server-side prose, not a stored record: nothing about it is
 * written at measurement time, and what it describes is the analysis RUN, not the firmware.
 *
 * Two properties, and the second is the one that would ship looking finished: the prose has to change, and the
 * stage ids inside it must NOT, because the reader compares the sentence against the stage table printed directly
 * underneath it and the two have to name the same things.
 */
describe('buildCoverage — the verdict is composed in the caller’s language, the ids in nobody’s', () => {
  const base = {
    firmwareClass: 'embedded-linux',
    specs: [spec('W1 · Extraction'), spec('W3 · Credentials'), spec('W5 · Binary-vuln')],
    steps: [
      step('W1 · Extraction', 'degraded', 0, 'no rootfs'),
      step('W3 · Credentials', 'skipped', 0, 'no extracted rootfs available'),
      step('W5 · Binary-vuln', 'skipped', 0, 'no extracted rootfs available'),
    ],
    findingCount: 0,
  };

  it('answers in English when no locale is given — the request that omits ?lang gets what it always got', () => {
    expect(buildCoverage(base).verdict).toBe(buildCoverage({ ...base, locale: 'en' }).verdict);
    expect(buildCoverage(base).verdict).toContain('Zero findings covers only the stages that ran');
  });

  it('translates the prose of every branch, and never reuses an English one', () => {
    const branches: Parameters<typeof buildCoverage>[0][] = [
      { ...base, steps: null }, // nothing ran
      { ...base, steps: null, findingCount: 28 }, // rows exist, no scan
      base, // partial, empty
      { ...base, steps: [step('W1 · Extraction', 'ran', 0)], specs: [spec('W1 · Extraction')] }, // all ran, empty
      { ...base, findingCount: 3, steps: [step('W1 · Extraction', 'ran', 3)] }, // partial, with findings
    ];
    for (const input of branches) {
      const es = buildCoverage({ ...input, locale: 'es' }).verdict;
      const en = buildCoverage({ ...input, locale: 'en' }).verdict;
      expect(es).not.toBe(en);
      expect(es).not.toMatch(/stage\(s\)|finding\(s\)|never ran/);
    }
  });

  it('keeps every stage id verbatim inside the Spanish sentence', () => {
    const r = buildCoverage({ ...base, locale: 'es' });
    expect(r.verdict).toContain('Sin cubrir:');
    expect(r.verdict).toContain('W3 · Credentials');
    expect(r.verdict).toContain('W5 · Binary-vuln');
    expect(r.verdict).toContain('W1 · Extraction'); // named again as the degraded one
    // The stage table itself is untouched: ids are data, and the class rationale is not this module's to translate.
    expect(r.stages.map((s) => s.worker)).toEqual(buildCoverage(base).stages.map((s) => s.worker));
  });

  it('moves no number: a Spanish reader gets the same arithmetic, not a softer one', () => {
    const es = buildCoverage({ ...base, operatorAssertions: 2, locale: 'es' });
    const en = buildCoverage({ ...base, operatorAssertions: 2, locale: 'en' });
    expect(es.applicable).toBe(en.applicable);
    expect(es.executed).toBe(en.executed);
    expect(es.findingCount).toBe(en.findingCount);
    expect(es.operatorAssertions).toBe(en.operatorAssertions);
    expect(es.ambiguous).toBe(en.ambiguous);
    expect(es.stages.map((s) => s.status)).toEqual(en.stages.map((s) => s.status));
  });

  it('says in Spanish that an unexamined image is UNEXAMINED, never that it looks clean', () => {
    const r = buildCoverage({ ...base, steps: null, locale: 'es' });
    expect(r.verdict).toContain('SIN EXAMINAR');
    expect(r.verdict).not.toMatch(/sin problemas|todo correcto|nada que reportar/i);
  });

  it('keeps a DEGRADED stage shouting in Spanish, so the headline cannot absorb its own caveat', () => {
    const r = buildCoverage({
      firmwareClass: 'uefi-bios',
      specs: [spec('UEFI · chipsec'), spec('UEFI · FwHunt implant scan')],
      steps: [step('UEFI · chipsec', 'ran', 2), step('UEFI · FwHunt implant scan', 'degraded', 1, '91 rules unused')],
      findingCount: 3,
      locale: 'es',
    });
    expect(r.verdict).toContain('DEGRADADAS');
    expect(r.verdict).toContain('UEFI · FwHunt implant scan');
    expect(r.ambiguous).toBe(true);
  });

  it('counts operator assertions apart in Spanish too, as statements rather than results', () => {
    const r = buildCoverage({ ...base, operatorAssertions: 2, locale: 'es' });
    expect(r.verdict).toContain('2 afirmación(es) de operador');
    expect(r.verdict).toContain('no mediciones');
    expect(r.verdict).toContain('no cubren ninguna etapa');
  });

  it('localises the fallback reason for a dynamically-planned worker, but not a recorded trigger', () => {
    const withTrigger = buildCoverage({
      firmwareClass: 'embedded-linux',
      specs: [],
      steps: [
        { worker: 'W5 · Reachability (httpd)', status: 'ran', summary: 's', trigger: 'stack-overflow candidate' },
        { worker: 'W5 · Reachability (telnetd)', status: 'ran', summary: 's' },
      ],
      findingCount: 0,
      locale: 'es',
    });
    // The trigger was recorded by the run and is printed as recorded; only the sentence this build composes moves.
    expect(withTrigger.stages[0]?.reason).toBe('stack-overflow candidate');
    expect(withTrigger.stages[1]?.reason).toBe('planificada sobre la marcha a partir de una pista');
  });
});
