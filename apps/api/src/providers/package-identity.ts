/**
 * A conservative package-URL reader for measured SBOM identities, not an ecosystem guess from a package name.
 * Components are decoded once; malformed input returns null. npm scope and PyPI name semantics follow the
 * primary sources recorded in docs/VEX-PACKAGE-IDENTITY-20261108.md. Versions remain opaque exact strings.
 * Qualifiers and subpaths are retained so matching cannot silently erase a more specific package identity.
 */
export interface PackageIdentity {
  type: string;
  namespace: string;
  name: string;
  version: string | null;
  qualifiers: string;
  subpath: string;
}

function decode(raw: string): string | null {
  if (!/^[A-Za-z0-9._~%:-]*$/.test(raw)) return null;
  try {
    const value = decodeURIComponent(raw);
    return [...value].some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127) ? null : value;
  } catch {
    return null;
  }
}

function pypiName(name: string): string | null {
  return /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/i.test(name) ? name.toLowerCase().replace(/[-_.]+/g, '-') : null;
}

/** Pure, nonthrowing, deliberately refuses ambiguous/noncanonical component boundaries. */
export function parsePackageIdentity(raw: unknown): PackageIdentity | null {
  if (typeof raw !== 'string' || !/^[A-Za-z0-9.\-_~%:/@?=&#]+$/.test(raw)) return null;
  const match = /^pkg:\/*([a-z][a-z0-9.-]*)\/([^?#]+)(?:\?([^#]+))?(?:#(.+))?$/i.exec(raw);
  if (!match) return null;
  const type = (match[1] as string).toLowerCase();
  let body = match[2] as string;
  let version: string | null = null;
  const at = body.indexOf('@');
  if (at >= 0) {
    // A scope's @ is encoded as %40; an unencoded @ is exclusively the version delimiter.
    if (body.indexOf('@', at + 1) >= 0) return null;
    version = decode(body.slice(at + 1));
    if (!version) return null;
    body = body.slice(0, at);
  }
  const segments = body.split('/').map(decode);
  if (segments.some((s) => !s || s.includes('/'))) return null;
  let name = segments.at(-1) as string;
  const namespace = segments.slice(0, -1).join('/');
  if (type === 'npm') {
    if (!/^[a-z0-9_~][a-z0-9._~-]*$/i.test(name)) return null;
    if (namespace && !/^@[a-z0-9_~][a-z0-9._~-]*$/i.test(namespace)) return null;
  }
  if (type === 'pypi') {
    if (namespace) return null;
    const normalized = pypiName(name);
    if (!normalized) return null;
    name = normalized;
  }
  const qualifiers = new Map<string, string>();
  for (const pair of match[3]?.split('&') ?? []) {
    const eq = pair.indexOf('=');
    if (eq <= 0 || pair.indexOf('=', eq + 1) >= 0) return null;
    const key = pair.slice(0, eq);
    const value = decode(pair.slice(eq + 1));
    if (!/^[a-z][a-z0-9._-]*$/.test(key) || !value || qualifiers.has(key)) return null;
    qualifiers.set(key, value);
  }
  const subpath = match[4]?.split('/').map(decode) ?? [];
  if (subpath.some((s) => !s || s === '.' || s === '..' || s.includes('/'))) return null;
  return {
    type,
    namespace,
    name,
    version,
    qualifiers: JSON.stringify([...qualifiers].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))),
    subpath: subpath.join('/'),
  };
}

/** Pure: a purl is measured identity only when it agrees with the row that actually carried it. */
export function measuredPackageIdentity(name: string, version: string, purl: unknown): PackageIdentity | null {
  const identity = parsePackageIdentity(purl);
  if (!identity || !identity.version || identity.version === '*' || identity.version === '-') return null;
  const artifactName = identity.type === 'pypi' ? pypiName(name) : name;
  const expectedName =
    identity.type === 'npm' && identity.namespace ? `${identity.namespace}/${identity.name}` : identity.name;
  return artifactName === expectedName && version === identity.version ? identity : null;
}

/** Pure: exact identity, including any qualifiers/subpath; an unversioned assertion cannot erase a version. */
export function samePackageIdentity(a: PackageIdentity, b: PackageIdentity): boolean {
  return (
    a.type === b.type &&
    a.namespace === b.namespace &&
    a.name === b.name &&
    a.version === b.version &&
    a.qualifiers === b.qualifiers &&
    a.subpath === b.subpath
  );
}
