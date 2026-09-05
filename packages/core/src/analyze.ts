/**
 * One-shot static analysis of a firmware image buffer: run the entropy profile, signature scan, structure
 * map, identity inference, and secret extraction, and return a single bundle. This is what the API calls the
 * moment an image is uploaded — no external tool required — to populate every deterministic view.
 */
import { type EntropyOptions, computeEntropyProfile } from './entropy.js';
import { scanSignatures } from './signatures.js';
import { type SecretScan, scanSecrets } from './strings.js';
import { buildStructureSegments, inferIdentity } from './structure.js';
import type { EntropyProfile, ImageIdentity, SignatureHit, StringHit, StructureSegment } from './types.js';

/** How many secrets the bundle lists. Bounds the payload, never the count — `secretScan.matched` keeps that. */
const SECRET_LIST_CAP = 500;

export interface StaticAnalysis {
  size: number;
  identity: ImageIdentity;
  entropy: EntropyProfile;
  signatures: SignatureHit[];
  structure: StructureSegment[];
  secrets: StringHit[];
  /**
   * What the secret scan actually covered, and how much it had to leave out.
   *
   * OPTIONAL FOREVER, and not because the analysis might omit it — every build from here on writes it. This
   * bundle is persisted as JSON on the image row and re-read for as long as the image exists, so a stored
   * analysis is data written by an OLDER build and cannot be made to carry a field it never had. Declaring it
   * required is the mistake `nvd.uncheckedIdentities` already paid for, where a result stored two commits
   * earlier took down the whole image view. A reader that finds it absent knows only that the coverage was not
   * recorded — which is itself the honest answer, and never that the scan was complete.
   */
  secretScan?: SecretScan;
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
  // The listing cap moves INTO the scan so the count survives it. `.slice(0, 500)` here threw away the one
  // number that distinguishes "no secrets in this image" from "more secrets than the bundle carries".
  const secretScan = scanSecrets(buf, { minLength: options.secretMinLength ?? 6 }, SECRET_LIST_CAP);
  return { size: buf.length, identity, entropy, signatures, structure, secrets: secretScan.secrets, secretScan };
}
