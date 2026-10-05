import { describe, expect, it } from 'vitest';
import { loadResearchConfig } from './config.js';
import { projectResearchStatus } from './status.js';

const env = (values: Record<string, string>): NodeJS.ProcessEnv => values as NodeJS.ProcessEnv;

describe('research status — pre-flight hash-lookup posture', () => {
  it('reports default-on research without arming or holding an unstated hash lookup', () => {
    expect(projectResearchStatus(loadResearchConfig(env({})))).toMatchObject({
      enabled: true,
      hashLookupArmed: false,
      hashLookupHeld: false,
    });
  });

  it('reports both research and hash lookup disabled when research is explicitly off', () => {
    expect(projectResearchStatus(loadResearchConfig(env({ FIRMLAB_RESEARCH: '0', FIRMLAB_HASH_LOOKUP: '1' })))).toEqual(
      {
        enabled: false,
        hashLookupArmed: false,
        hashLookupHeld: false,
      },
    );
  });

  it('reports hash lookup held when its opt-in is set beside default-on research', () => {
    expect(projectResearchStatus(loadResearchConfig(env({ FIRMLAB_HASH_LOOKUP: '1' })))).toMatchObject({
      enabled: true,
      hashLookupArmed: false,
      hashLookupHeld: true,
    });
  });

  it('reports hash lookup armed only when both flags are explicitly on', () => {
    expect(
      projectResearchStatus(loadResearchConfig(env({ FIRMLAB_RESEARCH: '1', FIRMLAB_HASH_LOOKUP: '1' }))),
    ).toMatchObject({
      enabled: true,
      hashLookupArmed: true,
      hashLookupHeld: false,
    });
  });
});
