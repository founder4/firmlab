import { describe, expect, it } from 'vitest';
import { hasActiveFwHuntJob, hasActiveOpacidadJob } from '../providers/fwhunt.js';

describe('FwHunt route campaign guard', () => {
  it('rejects a second queued/running FwHunt batch but ignores terminal and unrelated jobs', () => {
    expect(hasActiveFwHuntJob([{ kind: 'fwhunt', status: 'running' }])).toBe(true);
    expect(hasActiveFwHuntJob([{ kind: 'fwhunt', status: 'queued' }])).toBe(true);
    expect(
      hasActiveFwHuntJob([
        { kind: 'fwhunt', status: 'done' },
        { kind: 'fwhunt', status: 'error' },
        { kind: 'chipsec', status: 'running' },
      ]),
    ).toBe(false);
  });

  it('treats an autonomous job as a separate owner of the inline FwHunt stage', () => {
    expect(hasActiveOpacidadJob([{ kind: 'opacidad', status: 'running' }])).toBe(true);
    expect(hasActiveOpacidadJob([{ kind: 'opacidad', status: 'done' }])).toBe(false);
  });
});
