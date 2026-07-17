import { describe, expect, it } from 'vitest';
import { CATEGORY_COLORS, categoryColor, fmtBytes, fmtHex } from './api';

describe('fmtBytes', () => {
  it('formats bytes under 1 KiB as plain bytes', () => {
    expect(fmtBytes(0)).toBe('0 B');
    expect(fmtBytes(512)).toBe('512 B');
    expect(fmtBytes(1023)).toBe('1023 B');
  });

  it('scales into KB / MB / GB', () => {
    expect(fmtBytes(1024)).toBe('1.0 KB');
    expect(fmtBytes(1536)).toBe('1.5 KB');
    expect(fmtBytes(5 * 1024 * 1024)).toBe('5.00 MB');
    expect(fmtBytes(3 * 1024 * 1024 * 1024)).toBe('3.00 GB');
  });
});

describe('fmtHex', () => {
  it('renders a 0x-prefixed lowercase hex offset', () => {
    expect(fmtHex(0)).toBe('0x0');
    expect(fmtHex(255)).toBe('0xff');
    expect(fmtHex(4096)).toBe('0x1000');
  });
});

describe('categoryColor', () => {
  it('returns the mapped color for a known category', () => {
    expect(categoryColor('filesystem')).toBe(CATEGORY_COLORS.filesystem);
    expect(categoryColor('crypto')).toBe(CATEGORY_COLORS.crypto);
  });

  it('falls back to the "other" color for an unknown category', () => {
    expect(categoryColor('nonsense')).toBe(CATEGORY_COLORS.other);
  });
});
