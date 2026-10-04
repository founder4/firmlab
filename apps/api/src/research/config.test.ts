import { describe, expect, it } from 'vitest';
import { effectiveEnv, setFlagOverrideProvider } from '../flags.js';
import { RESEARCH_DISABLED, isAllowed, loadResearchConfig } from './config.js';

describe('loadResearchConfig — the research gate', () => {
  /**
   * The inverse of what this test pinned until 2026-10-04, when the operator decided trusted outbound research is
   * habitually authorised. Absence now means the operator's standing decision, so it means ON — and what keeps
   * that bounded is asserted alongside it rather than assumed.
   */
  it('is ON when FIRMLAB_RESEARCH is unset, with only the default allowlist and no hash lookup', () => {
    const c = loadResearchConfig({} as NodeJS.ProcessEnv);
    expect(c).not.toBeNull();
    expect(c?.allowlist).toEqual(['api.osv.dev', 'services.nvd.nist.gov', 'www.cisa.gov']);
    expect(c?.hashLookup).toBe(false);
  });

  it('returns null for any stated value other than 1 (no network path exists)', () => {
    expect(loadResearchConfig({ FIRMLAB_RESEARCH: '0' } as unknown as NodeJS.ProcessEnv)).toBeNull();
    // A typo is a stated value and reads as off — the opt-out must not depend on spelling it the one right way.
    expect(loadResearchConfig({ FIRMLAB_RESEARCH: 'false' } as unknown as NodeJS.ProcessEnv)).toBeNull();
    expect(loadResearchConfig({ FIRMLAB_RESEARCH: '' } as unknown as NodeJS.ProcessEnv)).toBeNull();
  });

  /**
   * The merged environment is what the lane reads (`effectiveEnv`: process env with stored overrides on top), so
   * these are the precedence rules as the gate sees them: a stored override beats the environment, and either one
   * beats the default.
   */
  it('lets a stored override of 0 beat an environment of 1, and a stored 1 beat an environment of 0', () => {
    setFlagOverrideProvider(() => ({ FIRMLAB_RESEARCH: '0' }));
    expect(loadResearchConfig(effectiveEnv({ FIRMLAB_RESEARCH: '1' } as unknown as NodeJS.ProcessEnv))).toBeNull();
    expect(loadResearchConfig(effectiveEnv({} as NodeJS.ProcessEnv))).toBeNull();
    setFlagOverrideProvider(() => ({ FIRMLAB_RESEARCH: '1' }));
    expect(loadResearchConfig(effectiveEnv({ FIRMLAB_RESEARCH: '0' } as unknown as NodeJS.ProcessEnv))).not.toBeNull();
    setFlagOverrideProvider(() => ({}));
  });

  it('names the switch in its refusal and says the lane was switched off rather than never enabled', () => {
    expect(RESEARCH_DISABLED).toContain('Settings › Privacy');
    expect(RESEARCH_DISABLED).toContain('FIRMLAB_RESEARCH=1');
    expect(RESEARCH_DISABLED).toMatch(/on by default/);
  });

  it('enables with the default allowlist (OSV + NVD + CISA KEV) when the flag is set', () => {
    const c = loadResearchConfig({ FIRMLAB_RESEARCH: '1' } as unknown as NodeJS.ProcessEnv);
    expect(c?.allowlist).toEqual(expect.arrayContaining(['api.osv.dev', 'services.nvd.nist.gov', 'www.cisa.gov']));
    expect(c?.nvdApiKey).toBeUndefined();
  });

  it('picks up an optional NVD API key from the environment', () => {
    const c = loadResearchConfig({ FIRMLAB_RESEARCH: '1', NVD_API_KEY: 'abc-123' } as unknown as NodeJS.ProcessEnv);
    expect(c?.nvdApiKey).toBe('abc-123');
  });

  it('keeps hash lookup OFF (and its hosts off the allowlist) unless FIRMLAB_HASH_LOOKUP is set', () => {
    const c = loadResearchConfig({ FIRMLAB_RESEARCH: '1' } as unknown as NodeJS.ProcessEnv);
    expect(c?.hashLookup).toBe(false);
    expect(c?.allowlist).not.toContain('www.nitrxgen.net');
    expect(c?.allowlist).not.toContain('weakpass.com');
  });

  it('arms hash lookup and allowlists its hosts only under the second opt-in FIRMLAB_HASH_LOOKUP', () => {
    const c = loadResearchConfig({
      FIRMLAB_RESEARCH: '1',
      FIRMLAB_HASH_LOOKUP: '1',
    } as unknown as NodeJS.ProcessEnv);
    expect(c?.hashLookup).toBe(true);
    expect(c?.allowlist).toEqual(expect.arrayContaining(['www.nitrxgen.net', 'weakpass.com']));
  });

  it('does not arm hash lookup when the research track itself is off', () => {
    expect(
      loadResearchConfig({ FIRMLAB_RESEARCH: '0', FIRMLAB_HASH_LOOKUP: '1' } as unknown as NodeJS.ProcessEnv),
    ).toBeNull();
  });

  it('holds hash lookup beside a DEFAULT-on track: the default is not the first consent', () => {
    // Before the default flipped, this environment was inert (research unset = off). It must stay inert: the track
    // runs, but no hash leaves and the lookup hosts stay off the allowlist until FIRMLAB_RESEARCH is stated.
    const held = loadResearchConfig({ FIRMLAB_HASH_LOOKUP: '1' } as unknown as NodeJS.ProcessEnv);
    expect(held).not.toBeNull();
    expect(held?.hashLookup).toBe(false);
    expect(held?.hashLookupHeld).toBe(true);
    expect(held?.allowlist).not.toContain('www.nitrxgen.net');
    expect(held?.allowlist).not.toContain('weakpass.com');
    // Not held when the hash flag itself is unstated or off: there is nothing waiting for a second consent.
    expect(
      loadResearchConfig({ FIRMLAB_HASH_LOOKUP: '0' } as unknown as NodeJS.ProcessEnv)?.hashLookupHeld,
    ).toBeUndefined();
    expect(loadResearchConfig({} as unknown as NodeJS.ProcessEnv)?.hashLookupHeld).toBeUndefined();
    // Stated research arms it, and the held marker goes.
    const armed = loadResearchConfig({
      FIRMLAB_HASH_LOOKUP: '1',
      FIRMLAB_RESEARCH: '1',
    } as unknown as NodeJS.ProcessEnv);
    expect([armed?.hashLookup, armed?.hashLookupHeld]).toEqual([true, undefined]);
  });

  it('reads the second consent through the Settings override exactly as through the environment', () => {
    // Settings › Privacy stores `1` for research: that IS a statement, even though it equals the default value.
    setFlagOverrideProvider(() => ({ FIRMLAB_RESEARCH: '1' }));
    try {
      expect(loadResearchConfig(effectiveEnv({ FIRMLAB_HASH_LOOKUP: '1' } as NodeJS.ProcessEnv))?.hashLookup).toBe(
        true,
      );
    } finally {
      setFlagOverrideProvider(() => ({}));
    }
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
