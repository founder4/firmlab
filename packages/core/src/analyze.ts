/**
 * One-shot static analysis of a firmware image buffer: run the entropy profile, signature scan, structure
 * map, identity inference, and secret extraction, and return a single bundle. This is what the API calls the
 * moment an image is uploaded — no external tool required — to populate every deterministic view.
 */
import { type EntropyOptions, computeEntropyProfile } from './entropy.js';
import { scanSignatures } from './signatures.js';
import { extractSecrets } from './strings.js';
import { buildStructureSegments, inferIdentity } from './structure.js';
import type { EntropyProfile, ImageIdentity, SignatureHit, StringHit, StructureSegment } from './types.js';

export interface StaticAnalysis {
  size: number;
  identity: ImageIdentity;
  entropy: EntropyProfile;
  signatures: SignatureHit[];
  structure: StructureSegment[];
  secrets: StringHit[];
}

export interface AnalyzeOptions {
  entropy?: EntropyOptions;
  /** Minimum length for secret-string extraction. Default 6. */
  secretMinLength?: number;
}

export function analyzeBuffer(buf: Uint8Array, options: AnalyzeOptions = {}): StaticAnalysis {
  const entropy = computeEntropyProfile(buf, options.entropy);
  const signatures = scanSignatures(buf);
  const structure = buildStructureSegments(buf.length, signatures, entropy);
  const identity = inferIdentity(buf, signatures, entropy);
  const secrets = extractSecrets(buf, { minLength: options.secretMinLength ?? 6 }).slice(0, 500);
  return { size: buf.length, identity, entropy, signatures, structure, secrets };
}
