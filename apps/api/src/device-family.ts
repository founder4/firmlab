import type { Architecture, FirmwareClass } from '@firmlab/core';

/**
 * Scope corpus priors to an evidenced vendor, or to one image when no vendor was established.
 *
 * `unknown:class:arch` is not a family: it grouped unrelated devices solely because the classifier could not name
 * their manufacturer. Requiring an image id for the fallback makes that uncertainty non-transitive. A later,
 * evidenced vendor can deliberately reconnect versions without migrating speculative history.
 */
export function deviceFamilyKey(
  identity: { vendor?: string | undefined; firmwareClass: FirmwareClass; arch: Architecture },
  imageId: string,
): string {
  const vendor = identity.vendor?.trim();
  const scope = vendor
    ? vendor
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
    : `image-${imageId.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
  return `${scope || `image-${imageId}`}:${identity.firmwareClass}:${identity.arch}`;
}
