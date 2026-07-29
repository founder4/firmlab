import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CATEGORY_COLORS, api, categoryColor, fmtBytes, fmtHex } from './api';

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

/**
 * `?lang` on the three endpoints whose answer is prose the server composes.
 *
 * The property worth pinning is the ABSENT case, not the present one. A caller that has not been threaded through
 * yet must issue exactly the request it always issued — no `?lang=undefined`, no empty parameter — because the
 * server's rule is that an absent or unrecognised value is English, and a client that sends a malformed one is
 * relying on that fallback to hide it.
 */
describe('the locale is a request parameter on the endpoints that compose prose', () => {
  let urls: string[] = [];

  beforeEach(() => {
    urls = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => {
        urls.push(url);
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ tools: [], groups: {}, flags: [] }) });
      }),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it('sends no lang parameter at all when the caller passes no locale', async () => {
    await api.coverage('img1');
    await api.coverageAll();
    await api.tools();
    await api.flags();
    expect(urls).toEqual(['/api/images/img1/coverage', '/api/coverage', '/api/tools', '/api/settings/flags']);
    for (const u of urls) expect(u).not.toContain('lang');
  });

  it('carries the active locale on every verb that returns a lane description, reads and writes alike', async () => {
    await api.flags('es');
    await api.setFlag('FIRMLAB_RESEARCH', true, 'es');
    await api.clearFlag('FIRMLAB_RESEARCH', 'es');
    expect(urls).toEqual([
      '/api/settings/flags?lang=es',
      '/api/settings/flags/FIRMLAB_RESEARCH?lang=es',
      '/api/settings/flags/FIRMLAB_RESEARCH?lang=es',
    ]);
  });

  it('asks for the coverage verdict and the tool table in the locale it is rendering', async () => {
    await api.coverage('img1', 'es');
    await api.coverageAll('es');
    await api.tools('es');
    expect(urls).toEqual(['/api/images/img1/coverage?lang=es', '/api/coverage?lang=es', '/api/tools?lang=es']);
  });
});
