/**
 * The pre-flight posture exposed before an external-intelligence run starts. Keeping this projection separate from
 * the store-bound route makes the three consent states testable without importing SQLite or starting a job.
 */
import type { ResearchConfig } from './config.js';

export interface ResearchStatus {
  enabled: boolean;
  allowlist?: string[];
  hashLookupArmed: boolean;
  hashLookupHeld: boolean;
}

/** Pure: describe authorization posture only; this does not start research or claim that hash lookup ran. */
export function projectResearchStatus(config: ResearchConfig | null): ResearchStatus {
  if (!config) {
    return { enabled: false, hashLookupArmed: false, hashLookupHeld: false };
  }
  return {
    enabled: true,
    allowlist: config.allowlist,
    hashLookupArmed: config.hashLookup,
    hashLookupHeld: config.hashLookupHeld === true,
  };
}
