# Direct OpenVEX product identifiers — 2026-11-08

`parseVendorVex` reads direct product `identifiers` maps containing readable,
concrete versioned `purl`, `cpe22`, and `cpe23` values. These are literal aliases
explicitly supplied by the author for one component. They annotate existing
findings as vendor assertions; they never set proof states, suppress rows, change
severity, resolve a disagreement by order, or establish exploitability.

## Pinned primary contract

Before implementation, `git ls-remote` and the GitHub tree/raw endpoints resolved
and retrieved the spec and official Go implementation/example bytes below. The
mutable `main` URL from the task was resolved to the immutable commit shown.
SHA-256 values identify source bytes, not firmware or runtime evidence.

| Source | Immutable primary URL | SHA-256 |
| --- | --- | --- |
| OpenVEX spec, `main` resolved to `93139bd2c65390b504e47f82f11c50451289f93a`, title **OpenVEX Specification v0.2.0** | <https://github.com/openvex/spec/blob/93139bd2c65390b504e47f82f11c50451289f93a/OPENVEX-SPEC.md> | `9375415ccb351260a998864cbeebbaff1808d1b09a306919b79cc75e5519f884` |
| Official schema at the same spec commit | <https://github.com/openvex/spec/blob/93139bd2c65390b504e47f82f11c50451289f93a/openvex_json_schema.json> | `9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238` |
| Released spec tag `v0.2.0`, tag object `bced7e303759d6348a6f2892af6d2f440b3c4c74`, peeled commit `7667061835da09300f913e26be10ee03c05e784d` | <https://github.com/openvex/spec/blob/7667061835da09300f913e26be10ee03c05e784d/OPENVEX-SPEC.md> | `2abdc5d06f2254fea39830e23e482c65d1631e9564a259dd884559a4a21ce330` |
| Official Go component identity implementation, `579e3014a67a8ca9c682828572daf51c03b0d719` | <https://github.com/openvex/go-vex/blob/579e3014a67a8ca9c682828572daf51c03b0d719/pkg/vex/component.go> | `24733f2eee722a9ebb8e6cca2fb7438d78236177ca7ba30506f130bccfa7030a` |
| Official Go parent/subcomponent implementation, same commit | <https://github.com/openvex/go-vex/blob/579e3014a67a8ca9c682828572daf51c03b0d719/pkg/vex/product.go> | `1a6dc10ede2d0c84245e1e3a03f82a85f15296cdd94f55fc3700d63eeee90a3b` |
| Official Go v0.2.0 sample, same commit | <https://github.com/openvex/go-vex/blob/579e3014a67a8ca9c682828572daf51c03b0d719/pkg/vex/testdata/v0.2.0.json> | `b4bd86d5855f94bcac0a92d3100ae7b85d050bd2e5fb9037a200e5f5f0b073a2` |
| Supplemental official examples tutorial, `a44fe226829823309e62cb949f306b5a47b8f8f3` (read after the initial implementation) | <https://github.com/openvex/examples/blob/a44fe226829823309e62cb949f306b5a47b8f8f3/tutorials/tutorial01-create.md> | `f4529ba92fb82714b457b208ffdcb0149c6477fd9582bd14b0b93b1c6fbbacc4` |

The **Product Data Structure**, **Component Fields**, and **Appendix B** sections
establish that the map describes the component using the three recognized
identifier labels. `@id` is optional and makes the component referenceable; it
can itself be a PURL. The schema's `$defs.identifiers` allows those three string
properties, rejects additional properties, and requires at least one recognized
key. `$defs.component` permits `identifiers` without `@id`. This supports the
identifiers-only product shape that the old parser missed.

Versions must be distinguished: `version: 1` is document revision metadata;
`v0.2.0` is the OpenVEX contract; the schema's `draft/2020-12` is its **JSON Schema
dialect**, not another OpenVEX release. The schema was retrieved from the pinned
current spec commit and identifies itself as `openvex_json_schema_0.2.0.json`;
there is no schema file in the released v0.2.0 tag's tree. We do not claim that
the current schema shipped with that tag, or that this reader validates the
complete schema, all specification prose, drafts, or arbitrary JSON-LD contexts.
The released tag's product example mixes an APK `@id` with unrelated Maven
identifiers; the current pinned spec corrects that example and nests the Log4j
component. The contradictory same-scheme tag example is deliberately refused.

Go `Component.Matches` supplies independent confirmation that explicit identifiers
are alternative ways to identify the same component. Its generic PURL subset and
hash matching are **not** adopted here. `Product.Matches` checks the parent before
a subcomponent. The official Go sample has OCI-parent assertions about nested
Alpine libssl/libcrypto components; the tests retain only that parent and count
the nested group as unread context. The supplemental examples tutorial supplies
an official `@id`-only PURL shape whose legacy behavior stays available.

## Identity decisions

The exported pure `readOpenVexProductIdentity` decision is used only for direct
entries in `statement.products`.

- With no `identifiers` property, existing strings and `@id`/`id` aliases retain
  their legacy trimming/selection behavior. No name, version field, branch label,
  hash, or external resource supplies identity data.
- With an explicit map, **every** entry must have a recognized, case-sensitive
  label and a string in the bounded concrete-version PURL/CPE subset already used
  by CSAF. Values are passed through unchanged, including case, ecosystem,
  namespace, name, version, qualifiers and subpath. Leading/trailing whitespace
  is refused. `cpe22` cannot carry CPE 2.3 syntax, or vice versa.
- Empty maps, wrong types, unknown keys, nested map values, malformed escapes,
  unsupported helper syntax, or any unversioned helper refuse **all aliases of
  that product**, including a usable-looking raw ID. The product contributes one
  `openvex_product_identifiers` omission, not one omission per bad key.
- An opaque/plain `@id`/`id` accompanying a valid map is a reference token only;
  it contributes no matching alias. Thus `@id: busybox` plus a 1.36.1 helper cannot
  make the statement match an older BusyBox artifact. Helper-shaped IDs must
  themselves be readable and versioned; an unversioned `pkg:` ID, malformed
  `cpe:` ID, explicit empty/non-string ID, or unequal `@id` and `id` refuses the
  whole identity with the same omission evidence.
- A versioned helper-shaped ID in the same scheme must exactly equal that map
  entry. Even differences that a richer parser might normalize are refused.
  A readable versioned ID in a different scheme remains an explicit literal
  alias. Repeating the identical ID/map value spends only one product slot.
- Several properly versioned map aliases are supported because the primary
  contract explicitly names them as identifiers of one component. We neither
  derive a missing alias nor compare version strings across PURL/CPE vendor
  vocabularies. Explicit cross-scheme aliases remain the author's claims; the
  reader cannot prove their consistency or invent equivalence for other rows.
- Hashes are not matched or validated. Their presence beside a readable alias
  does not create another alias. A hash-only product has no readable identity
  and contributes an unread identity omission.

The existing API matcher consumes the original strings. Measured SBOM PURLs
still require the same ecosystem, namespace/name, concrete version, complete
qualifiers and subpath under the existing package normalization rules. These
changes introduce no CPE/PURL/name conversion and no relaxed distro qualifier
rule. Existing legacy matching for rows **without** a recorded PURL remains as
implemented, including its narrower available identity information and existing
CPE/name/distro policies; this task does not redesign those matchers. Raw
`@id`/`id`-only and nonstandard statement-level subcomponent paths retain their
prior semantics, so they do not acquire the stricter direct-map contract.

## Context, bounds and omission evidence

`product.subcomponents` is never flattened, traversed, or matched independently.
The SBOM matcher has no binding between a firmware/product parent and a package,
so the nested claim cannot safely become an unconditional package assertion.
A nonempty or malformed nested group contributes one
`openvex_nested_subcomponents` omission per parent, separately from any unread
parent identity. Empty nested arrays contribute none. The parent can still
provide a direct assertion when its own identity is readable. Deep and 10,001-child
fixtures produce the same single group omission; no recursive walk or new tree
budget is introduced. The existing CSAF depth/node walk and validated helper
behavior are unchanged.

Existing nonstandard `statement.subcomponents` strings/IDs are still read by the
legacy path. Identifier maps there remain unread, even when the direct-product
reader could understand them. This preserves existing behavior rather than
extending a semantics that is absent from the pinned statement schema.

Empty/malformed direct product arrays and malformed/unidentified product nodes
are counted deterministically using the existing unread kind. A wholly absent
product list also counts as unread unless the legacy statement-level collection
is present and nonempty. The reader does not infer products from an encapsulating
document. A direct node with several bad keys counts once; an independent nested
group may add one more omission. Examples retain the first 10 references in
document order, clipped to 128 characters. Counts are recorded before statement
and product retention, so a zero retention cap cannot make unread content vanish.

The existing 4 MiB document bound precedes JSON parsing; 2,000 statement and 2,000
product defaults continue to bound retained output. Distinct map aliases use
product slots in map/document order, followed by any distinct versioned ID alias.
Existing dropped counters and verdict bounds describe truncation. No required
persisted field, new status, or omission enum was introduced. Old documents
without the optional unread counters/examples/rule remain readable; missing
counters never become a measured zero. Existing API row omissions and persisted
search summaries carry the evidence, including when one readable assertion
coexists with a possible unread disagreement. Readable status disagreements
remain `conflicting`.

## Validation

The initial 62-case new suite ran against the unchanged `eab54cc` parser: **57
failed / 5 passed** (`pnpm --filter @firmlab/core test
vendor-vex-openvex-identifiers`, diagnostic `/tmp/openvex-baseline-red.log`).
Later additions cover the exported decision, pinned official product/sample
shapes, malformed nested groups, depth/width without flattening, byte boundaries,
and measured case/scope/subpath boundaries. Final executed commands:

- `pnpm --filter @firmlab/core test vendor-vex`: 4 files / 153 tests passed,
  including the unchanged 35-case CSAF branch suite and 70 new OpenVEX cases.
- `pnpm --filter @firmlab/core check`: passed.
- `pnpm --filter @firmlab/core test`: 22 files / 683 tests passed.
- `pnpm --filter @firmlab/core build`: passed before API consumption.
- `pnpm --filter @firmlab/api test vendor-vex findings-normalize sbom`:
  9 files / 321 tests passed.
- `pnpm --filter @firmlab/api check`: passed.
- `pnpm --filter @firmlab/api build`: passed.
- `pnpm biome`: passed, 711 files checked; the agent-surface audit reported
  0 errors / 0 warnings, and all NUL/comment/API-mock/slice-denominator checks passed.
- `git diff --check`: passed.

An initial API test incorrectly expected the discovery prose to aggregate unread
product counters. Its assertion was corrected to inspect the actual persisted
search summary, which retains those existing per-document counters; no production
API change was needed.

These are JSON identity-contract fixtures. The Debian OpenSSL PURL in the API
tests was measured by real Syft in the preceding CSAF acceptance documented in
`CSAF-BRANCH-IDENTITIES-20261108.md`; here it is used as a fixed input to actual
core parsing, JSON persistence, `packageProductMatcher`, `vendorVexVerdictFor`
and `normalizeSbom`. No new Syft/Grype or firmware tool execution is claimed.

Deferred: nested product/subcomponent binding, relationship semantics, version
ranges, hashes as matchable evidence, external JSON-LD retrieval, wider syntax,
new statuses, automatic suppression, cross-scheme conversion and relaxed distro
qualifiers. The coordinator owns backlog updates, integration and final campaign
gates. No deployment, push, publication, firmware acquisition/execution, live
corpus/database write, lane/settings/account/permission change, listener,
isolation or host network change was performed.

## Coordinator acceptance on real tool output

After integration, the compiled parser and API normalizer were also run with real
Syft `1.55.0-security20261022` and Grype `0.121.0-security20261022` in the existing
local immutable image `sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42`.
The container used `--network none --read-only --tmpfs /tmp`, disabled update
checks/database updates, and mounted only the built checkout and acceptance script
read-only. Its writable fixture directory contained inert Debian 12 package
metadata for `openssl 3.0.9-1`, architecture `arm64`; no firmware/package binary
was fetched or executed.

The 53 actual cached-database advisory rows passed through the real mapper, core
OpenVEX parser, JSON round trip, exact package matcher and `normalizeSbom`.
Synthetic direct identifier maps annotated all four statuses. Another version,
architecture or distribution qualifier annotated none; the plain `openssl` ID
did not bypass the versioned map. Malformed helpers and disagreeing same-scheme
IDs retained 53 unread omissions, mixed readable/unreadable products kept those
omissions, and readable status disagreement remained `conflicting`. A matching
identifier nested under an unrelated parent never became an unconditional package
assertion. Every case retained row count, severity, proof state and evidence
channel. The assertion's truth and firmware applicability remain unproved.

The script and final JSON/stderr are retained as `openvex-built-real*` in the
campaign state directory. Integrated core/API focused suites passed 153/321 tests
and the whole repository typecheck passed; final full campaign gates and the
separate independent review remain coordinator responsibilities.
