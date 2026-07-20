import { describe, expect, it } from 'vitest';
import {
  clampRung,
  extractJsonObject,
  maxRungFor,
  parseTargetSelectionDecision,
  parseTriageDecision,
} from './nodes.js';

describe('extractJsonObject', () => {
  it('parses a bare JSON object', () => {
    expect(extractJsonObject('{"a": 1}')).toEqual({ a: 1 });
  });

  it('strips ```json fences and surrounding prose', () => {
    const text = 'Here is my decision:\n```json\n{"shouldExtract": true}\n```\nHope that helps.';
    expect(extractJsonObject(text)).toEqual({ shouldExtract: true });
  });

  it('throws when there is no object', () => {
    expect(() => extractJsonObject('no json here')).toThrow();
  });
});

describe('maxRungFor / clampRung — the preflight ceiling', () => {
  it('static-only and unsupported-arch permit nothing above none', () => {
    expect(maxRungFor('static-only')).toBe('none');
    expect(maxRungFor('unsupported-arch')).toBe('none');
    expect(clampRung('full-system', 'static-only')).toBe('none');
    expect(clampRung('qemu-user', 'unsupported-arch')).toBe('none');
  });

  it('clamps a too-high rung down to the ceiling', () => {
    expect(clampRung('full-system', 'qemu-user')).toBe('qemu-user');
    expect(clampRung('full-system', 'chroot-service')).toBe('chroot-service');
  });

  it('keeps a rung at or below the ceiling', () => {
    expect(clampRung('qemu-user', 'full-system')).toBe('qemu-user');
    expect(clampRung('full-system', 'full-system')).toBe('full-system');
  });

  it('treats the RTOS track as separate — no crossover with the Linux ceiling', () => {
    expect(clampRung('rtos-renode', 'qemu-user')).toBe('none');
    expect(clampRung('full-system', 'rtos-renode')).toBe('none');
    expect(clampRung('rtos-renode', 'rtos-renode')).toBe('rtos-renode');
  });
});

describe('parseTriageDecision', () => {
  it('coerces a well-formed decision', () => {
    const d = parseTriageDecision(
      JSON.stringify({
        resolvedClass: 'embedded-linux',
        classConfidence: 'high',
        shouldExtract: true,
        extractionCascade: ['unsquashfs', 'binwalk'],
        attackSurface: ['network-facing daemons'],
        rationale: 'squashfs present, not encrypted',
      }),
    );
    expect(d.shouldExtract).toBe(true);
    expect(d.extractionCascade).toEqual(['unsquashfs', 'binwalk']);
    expect(d.classConfidence).toBe('high');
  });

  it('drops the cascade when extraction is not warranted', () => {
    const d = parseTriageDecision(
      JSON.stringify({ shouldExtract: false, extractionCascade: ['unsquashfs'], rationale: 'likely encrypted' }),
    );
    expect(d.shouldExtract).toBe(false);
    expect(d.extractionCascade).toEqual([]);
  });

  it('applies safe defaults for missing/invalid fields', () => {
    const d = parseTriageDecision('{"shouldExtract": "yes"}'); // non-boolean → false
    expect(d.shouldExtract).toBe(false);
    expect(d.resolvedClass).toBe('unknown');
    expect(d.classConfidence).toBe('low');
    expect(d.rationale).toContain('no rationale');
  });
});

describe('parseTargetSelectionDecision — clamps rungs to the strategy', () => {
  const raw = JSON.stringify({
    targets: [
      { path: 'sbin/httpd', rung: 'full-system', priority: 'high', reason: 'network-facing, weak hardening' },
      { path: 'bin/busybox', rung: 'qemu-user', priority: 'medium', reason: 'multi-call binary' },
      { path: '', rung: 'qemu-user', priority: 'low', reason: 'no path' },
    ],
    rationale: 'focus on the http daemon',
  });

  it('clamps every requested rung to a qemu-user ceiling and derives the approval-gated plan', () => {
    const d = parseTargetSelectionDecision(raw, 'qemu-user');
    expect(d.targets.map((t) => t.path)).toEqual(['sbin/httpd', 'bin/busybox']); // empty-path dropped
    expect(d.targets[0]?.rung).toBe('qemu-user'); // full-system clamped down
    expect(d.emulationPlan).toHaveLength(2);
    expect(d.emulationPlan.every((p) => p.requiresApproval === true)).toBe(true);
  });

  it('a static-only ceiling drops all emulation to none — empty plan', () => {
    const d = parseTargetSelectionDecision(raw, 'static-only');
    expect(d.targets.every((t) => t.rung === 'none')).toBe(true);
    expect(d.emulationPlan).toHaveLength(0);
  });
});
