/**
 * Key-material provenance (Phase 5.2, deterministic) — the honest read on cryptographic material baked into a
 * firmware. The core insight needs no external service: a PRIVATE key embedded in a firmware image is extractable
 * from any device running it, so it is *effectively public* — shared across the whole product line. Corpus reuse
 * (the same key hash in other images) confirms that directly. This is provenance and citation, never a cracking
 * service.
 *
 * The summarizer is pure (values redacted); run.ts enriches each entry with corpus cross-references.
 */
import type { StringHit } from '@firmlab/core';

/** Secret kinds that are cryptographic key material (vs. passwords/tokens, which the secrets tab already covers). */
const KEY_KINDS = new Set([
  'private-key',
  'ssh-private-key',
  'rsa-private-key',
  'ec-private-key',
  'certificate',
  'pgp-private-key',
]);
const PRIVATE_KEYISH = /private-key|ssh-private|rsa-private|ec-private|pgp-private/;

export interface KeyMaterial {
  kind: string;
  redacted: string;
  offset?: number;
  /** Embedded private keys are extractable from any device → effectively public / shared across the product line. */
  effectivelyPublic: boolean;
  /** How many OTHER corpus images carry this exact key (filled by run.ts) — direct proof of cross-device reuse. */
  sharedInImages?: number;
}

function redact(value: string): string {
  const v = value.replace(/\s+/g, ' ').trim();
  return v.length > 28 ? `${v.slice(0, 28)}…` : v;
}

/** Pure: pick out cryptographic key material from the classified secrets, redacted. */
export function summarizeKeyMaterial(secrets: StringHit[]): KeyMaterial[] {
  const out: KeyMaterial[] = [];
  for (const s of secrets) {
    const kind = s.secretKind ?? '';
    if (!KEY_KINDS.has(kind)) continue;
    out.push({
      kind,
      redacted: redact(s.value),
      ...(typeof s.offset === 'number' ? { offset: s.offset } : {}),
      effectivelyPublic: PRIVATE_KEYISH.test(kind),
    });
  }
  return out;
}
