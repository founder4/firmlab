import { describe, expect, it } from 'vitest';
import { mapFindings, redactMatch } from './gitleaks.js';

describe('redactMatch', () => {
  it('passes short matches through (collapsing whitespace)', () => {
    expect(redactMatch('admin123')).toBe('admin123');
    expect(redactMatch('  foo\tbar\n')).toBe('foo bar');
  });

  it('fingerprints long key material instead of exposing it', () => {
    const key = `AKIA${'X'.repeat(60)}`;
    const out = redactMatch(key);
    expect(out).not.toContain('XXXXXXXXXX');
    expect(out).toContain('…');
    expect(out).toContain(`(${key.length} chars)`);
    expect(out.length).toBeLessThanOrEqual(120);
  });

  it('handles nullish input', () => {
    expect(redactMatch(undefined)).toBe('');
    expect(redactMatch(null)).toBe('');
  });
});

describe('mapFindings', () => {
  it('makes file paths rootfs-relative and maps fields', () => {
    const rows = [
      { RuleID: 'generic-api-key', Description: 'API key', File: '/x/rootfs/etc/passwd', StartLine: 3, Secret: 'abc' },
    ];
    const out = mapFindings(rows, '/x/rootfs');
    expect(out[0]).toEqual({
      rule: 'generic-api-key',
      description: 'API key',
      file: 'etc/passwd',
      line: 3,
      match: 'abc',
    });
  });

  it('falls back to the rule id for a missing description and caps at 500', () => {
    const rows = Array.from({ length: 600 }, (_, i) => ({ RuleID: 'r', File: `/r/f${i}`, StartLine: i }));
    const out = mapFindings(rows, '/r');
    expect(out).toHaveLength(500);
    expect(out[0]?.description).toBe('r');
  });
});
