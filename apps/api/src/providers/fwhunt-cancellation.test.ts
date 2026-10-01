import { expect, it } from 'vitest';
import { hasActiveFwHuntJob, hasActiveOpacidadJob } from './fwhunt.js';
it('retains findings namespace ownership during cancellation teardown', () => {
  expect(hasActiveFwHuntJob([{ kind: 'fwhunt', status: 'cancelling' }])).toBe(true);
  expect(hasActiveOpacidadJob([{ kind: 'opacidad', status: 'cancelling' }])).toBe(true);
  expect(hasActiveFwHuntJob([{ kind: 'fwhunt', status: 'cancelled' }])).toBe(false);
});
