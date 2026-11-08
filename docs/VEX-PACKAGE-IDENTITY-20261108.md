# Measured package identity for vendor VEX — 2026-11-08

The SBOM provider now retains Grype's `matches[].artifact.purl` as optional-forever
`SbomVuln.packagePurl`, and the normalizer passes it to the package product matcher.
It is also retained on finding evidence. This closes the documented conservative
npm/PyPI miss without inferring an ecosystem from a name.

## Primary-source contract

- [Grype v0.119.0 JSON Package model](https://github.com/anchore/grype/blob/v0.119.0/grype/presenter/models/package.go)
  exposes `name`, `version`, and `purl` together, copying the package PURL without reconstructing it.
  The [Match model](https://github.com/anchore/grype/blob/v0.119.0/grype/presenter/models/match.go)
  places this package under `artifact`.
- [Syft v1.32.0 JavaScript package construction](https://github.com/anchore/syft/blob/v1.32.0/syft/pkg/cataloger/javascript/package.go)
  retains scoped artifact names such as `@acme/widget` and splits the scope into
  the PURL namespace. The [npm PURL definition](https://github.com/package-url/purl-spec/blob/master/types/npm-definition.json)
  makes scope/name case-sensitive and encodes the scope's leading `@` as `%40`.
- [Syft v1.32.0 Python package construction](https://github.com/anchore/syft/blob/v1.32.0/syft/pkg/cataloger/python/package.go)
  normalizes distribution names before constructing a namespace-free PyPI PURL.
  [PyPA name normalization](https://packaging.python.org/en/latest/specifications/name-normalization/)
  lowercases names and collapses runs of `-`, `_`, and `.` to `-`.
- [PURL v1.0.0 specification](https://github.com/package-url/purl-spec/blob/v1.0.0/docs/standard/specification.md)
  separates type, namespace, name, version, qualifiers and subpath. Type is
  case-insensitive; versions are opaque strings; percent-decoded namespace and
  subpath segments cannot contain `/`, and qualifier keys must be unique.

These source versions establish the field and naming contract; the test fixture
does not claim that Grype confirms the presence of vulnerable executable code.

## Matching decisions

`parsePackageIdentity`, `measuredPackageIdentity`, `samePackageIdentity`, and
`grypeMatchVulnerability` are pure exported helpers. No dependency was added.

A supplied PURL must parse and agree with its own artifact name and exact version.
Scoped npm uses the full artifact name (`@scope/name`); PyPI compares normalized
distribution names. npm scopes and names preserve case. No version ranges,
SemVer coercion, or PyPI version equivalence are inferred (`1.0` differs from
`1.0.0`). A missing, empty, `*`, or `-` measured version cannot establish identity.

Once identity is supplied, a vendor assertion must itself be a versioned PURL with
equal ecosystem, namespace, name, version, qualifier map, and subpath. Qualifier
order is immaterial. No plain name, generic PURL, distro PURL, or CPE can stand in
for a measured npm/PyPI package. Unversioned assertions deliberately do not match
versioned measured identities.

Malformed escapes, invalid UTF-8, control characters, conflicting name/version,
ambiguous component boundaries, duplicate qualifier keys, and invalid npm/PyPI
structure all refuse matching without throwing. Malformed raw PURL strings remain
recorded so they cannot accidentally become legacy name-only matching. Non-string
values are retained as `null` (an explicit unusable identity). Missing upstream
PURLs and Grype's empty-string PURL become an absent field. Old persisted results
without the field retain the existing conservative name/version matching contract.

This is deliberately not a full PURL conformance library: noncanonical redundant
namespace/subpath slashes and empty qualifiers are refused rather than repaired,
and ecosystem-specific artifact-name conversions beyond the documented npm/PyPI/Go/Composer contracts are not inferred.
This can miss an assertion; it does not authorize a cross-package attachment.
Legacy name/CPE matching and discovery's legacy unreadable-identity accounting
are unchanged. Each measured matcher carries a runtime-only refusal reader, so
row omission accounting uses the same parsing rules as matching: a same-CVE
malformed qualifier/subpath is counted as `unmatchable_identity` and the verdict
says `Not a complete reading`. It is never promoted to an affected assertion.
Readable identities that name a different package/version are ordinary nonmatches,
and unreadable identities for a different CVE do not affect this row. The existing
persisted `omissions` field remains optional forever; no persisted field or reason
was added. Discovery's aggregate counters still use their legacy reader, so they
may count fewer unreadable identities than a particular measured row's verdict.

VEX remains vendor assertion metadata. Neither a match nor a refusal changes the
number of findings, their severity, proof state, evidence channel, or source.
No route/store/source binding changed; no existing result is rewritten.

## Validation

Focused tests exercise actual `runSbom` JSON mapping with mocked subprocess output,
then JSON persistence round-trip and `normalizeSbom`. npm unscoped/scoped and PyPI
positives are paired with different ecosystem/scope/version, conflicting artifact
identity, malformed escapes and unsupported fallback negatives. All four vendor
statuses preserve row count/severity/proof/channel. Legacy absent-identity and
empty upstream identity cases preserve old behavior. Pure matching tests also
cover qualifier/subpath equality and malformed firmware-controlled input.

Executed from the assigned worktree based on `304e663`:

- `pnpm --filter @firmlab/core build` passed before API consumption.
- `pnpm --filter @firmlab/api test sbom vendor-vex-discover findings-normalize`:
  8 files, 252 tests passed.
- `pnpm --filter @firmlab/api test vendor-vex findings-normalize routes/sbom-vex`:
  4 files, 172 tests passed (overlaps the preceding command; not an additional 172 unique tests).
- `pnpm --filter @firmlab/api check`, API build, and `pnpm biome` passed.

Two disposable `docker run --rm --network none` checks used the existing
`firmlab-firmware:latest` image, the built checkout mounted read-only, synthetic
input mounted read-only, and a fresh `/tmp` data root. They published no port,
mounted no live data/corpus, and started no application server:

1. Built `runSbom` executed real subprocesses serving controlled Syft/Grype JSON
   fixture output, followed by actual filesystem VEX discovery and normalization.
   Six High rows stayed `needs_runtime_reproduction` / `external_advisory`, with
   annotation presence `[true,true,true,false,false,true]`: npm, scoped npm, PyPI,
   conflicting artifact name, malformed PURL, legacy missing identity respectively.
2. Real Syft `1.55.0-security20261022` and Grype `0.121.0-security20261022` scanned
   synthetic `package-lock.json` and Python distribution metadata through built
   `runSbom`. Syft catalogued four packages; Grype returned 11 advisory rows with
   the expected distinct identities `pkg:npm/lodash@4.17.15`,
   `pkg:npm/%40babel/traverse@7.23.0`, and `pkg:pypi/requests@2.19.1`. This used the
   image's existing Grype DB schema `v6.1.10`, built `2026-11-04T06:20:59Z`.
   These counts describe this synthetic input and dated database, not firmware
   cleanliness or confirmed exploitation. The first fixture attempt omitted the
   lockfile, so directory-mode Syft catalogued only Python and the npm assertion
   failed; adding a real lockfile exercised the default JavaScript lock cataloger.

This validates the output field contract with real tools and the annotation path
with controlled CVE fixtures. It does not validate a real vendor advisory against
production firmware, refresh a stored result, or replace coordinator integration
gates. Temporary evidence scripts were under `/tmp/firmlab-vex-20261108`; no
container/database output was written into the repository or live corpus.

## Review follow-up: unread half of a possible disagreement

The original deferred row-accounting issue was reproduced as a correctness defect:
one fixed `pkg:npm/busybox@1.36.1` plus same-CVE affected PURL ending in
`?arch=%zz`, `#%zz`, or `#%2E%2E` returned `vendor_states_fixed` with no omission.
The new focused tests failed on the absent `omissions` before the fix. The row
now retains only the readable fixed assertion as its source and explicitly names
the unread assertion as an omission; it does not claim complete agreement.
Regression coverage also checks no double-counting when both readers reject an
identity, CVE scoping, readable ecosystem/version nonmatches, and legacy verdicts
persisted without `omissions`.

Follow-up validation: `pnpm --filter @firmlab/api test sbom vendor-vex findings-normalize`
passes 9 files / 264 tests; API typecheck/build and Biome pass. The offline
subprocess/discovery/normalizer fixture also checks that malformed qualifier and
subpath assertions contribute two omissions on the unchanged fixed row.


## Independent review disposition and namespace follow-up

The review reproduced an actual naming mismatch for Go modules and Composer:
Syft artifact names contain the complete module path or vendor/name, whereas the
PURL divides the final segment from its namespace. The matcher now joins these
components for these two documented types, including Go module `/v2` suffixes.
Composer vendor/name is case-insensitive and requires exactly one vendor segment;
versions remain exact (`v8.0.0` is different from `8.0.0`). Go paths remain exact
rather than introducing a new case folding assumption.

Primary implementation sources are Syft v1.55.0's
[Go package constructor](https://github.com/anchore/syft/blob/v1.55.0/syft/pkg/cataloger/golang/package.go)
and [Composer package constructor](https://github.com/anchore/syft/blob/v1.55.0/syft/pkg/cataloger/php/package.go),
plus the [Composer PURL definition](https://github.com/package-url/purl-spec/blob/main/types/composer-definition.json).

The review also identified a compatibility difference for newly measured distro
and generic PURLs. This is an explicit conservative decision: a new Debian row
with `arch=arm64&distro=debian-13` requires the same qualifiers, and a measured
generic BusyBox identity does not become an Alpine identity through its name.
Qualifier-free, CPE or plain assertions can consequently attach to an older row
without a recorded PURL but remain unattached to a newer, more specific row.
This can miss vendor annotations; it never changes CVE count/severity/proof or
claims the vendor cleared an unmatched package. Supporting qualifier subsets or
explicit cross-identifier equivalence needs a separately justified contract.
Raw unencoded `+` is still refused and counted in row omissions when relevant;
properly percent-encoded `%2B` works. Full PURL conformance remains out of scope.

Follow-up validation: nine focused SBOM/VEX/normalizer files, **271 tests**, and
API build passed. An offline disposable container pinned to
`sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42`
ran real Syft 1.55.0 on synthetic `go.mod` and `composer.lock` and fed the measured
artifacts to the actual built mapper/matcher. The fixtures contain
`github.com/golang/protobuf@v1.5.2` and `laravel/framework@v8.0.0`, with no fetched
package code. The replay script also runs real Grype 0.121.0 against that SBOM;
its actual advisory count and exact measured PURLs are retained in campaign
`vex-namespace-built-real.json`. A separately labelled synthetic advisory envelope
checks both ecosystems even if the installed advisory database has no match.
All checks require exact identity and refuse a plain name or changed version.
Only API/core build outputs are mounted read-only; temporary input and output
stay inside the disposable network-none container. No live database/corpus is mounted.
