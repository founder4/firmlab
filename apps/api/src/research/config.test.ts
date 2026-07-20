import { describe, expect, it } from 'vitest';
import { isAllowed, loadResearchConfig } from './config.js';

describe('loadResearchConfig — the local-only gate', () => {
  it('returns null when FIRMLAB_RESEARCH is unset (no network path exists)', () => {
    expect(loadResearchConfig({} as NodeJS.ProcessEnv)).toBeNull();
    expect(loadResearchConfig({ FIRMLAB_RESEARCH: '0' } as unknown as NodeJS.ProcessEnv)).toBeNull();
  });

  it('enables with the default allowlist when the flag is set', () => {
    const c = loadResearchConfig({ FIRMLAB_RESEARCH: '1' } as unknown as NodeJS.ProcessEnv);
    expect(c?.allowlist).toContain('api.osv.dev');
  });

  it('merges extra allowlist hosts without duplicating', () => {
    const c = loadResearchConfig({
      FIRMLAB_RESEARCH: '1',
      FIRMLAB_RESEARCH_ALLOWLIST: 'api.osv.dev, nvd.nist.gov',
    } as unknown as NodeJS.ProcessEnv);
    expect(c?.allowlist.filter((h) => h === 'api.osv.dev')).toHaveLength(1);
    expect(c?.allowlist).toContain('nvd.nist.gov');
  });
});

describe('isAllowed — the egress choke point', () => {
  const allow = ['api.osv.dev'];
  it('permits an allowlisted host', () => {
    expect(isAllowed('https://api.osv.dev/v1/query', allow)).toBe(true);
  });
  it('blocks any other host', () => {
    expect(isAllowed('https://evil.example.com/x', allow)).toBe(false);
    expect(isAllowed('http://api.osv.dev.evil.com/', allow)).toBe(false);
  });
  it('blocks a malformed URL', () => {
    expect(isAllowed('not a url', allow)).toBe(false);
  });
});
