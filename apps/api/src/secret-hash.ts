/**
 * The one-line content hash that keys the persistent corpus's credential reuse — extracted from `corpus.ts` so
 * the PURE providers that produce credential material (`pem-scan`, `nvram`) can compute the SAME key without
 * importing the SQLite-bound store, which vitest cannot resolve. It is a SHA-1 of the secret value: exactly what
 * `credential_occurrence` stores (the raw value never persists) and what `flagKnownCredentials` matches against
 * the watchlist, so both sides — recording and flagging — must agree on this function byte for byte.
 */
import { createHash } from 'node:crypto';

/** Content hash of a secret value — the cross-image key for credential reuse. The value itself is never stored. */
export function hashSecret(value: string): string {
  return createHash('sha1').update(value).digest('hex');
}
