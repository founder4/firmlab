# Exact CSAF branch product identities — 2026-11-08

`parseVendorVex` now reads an explicit full product name under a CSAF branch when
it has one unique product ID and a readable versioned PURL or CPE helper. The
helper remains intact; neither the branch labels nor the product name/ID become
aliases for a versioned identity. Vendor assertions still only annotate findings.

## Pinned primary sources

Fetched and read before implementation. SHA-256 values below describe the exact
source bytes retrieved, not a firmware image or a runtime validation result.

| Source/version | Primary URL | SHA-256 |
| --- | --- | --- |
| OASIS CSAF 2.0, OASIS Standard, 18 November 2022, authoritative Markdown | <https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.md> | `5bc757cc8dcf1a48a73c50de8100b0437bda1f9b5b860afd051c585749f568be` |
| Same standard's JSON schema | <https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json> | `29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262` |
| Official OASIS example, commit `c8047c87e8ccef8abe3352e8e4cd78dcaaf8f869` | <https://raw.githubusercontent.com/oasis-tcs/csaf/c8047c87e8ccef8abe3352e8e4cd78dcaaf8f869/csaf_2.0/examples/csaf/rhsa-2022_0011.json> | `09a88603125f06f5ff65b99355e856192facdea6391bf74b66439873ba1ea396` |
| Official OASIS VEX example, same commit | <https://raw.githubusercontent.com/oasis-tcs/csaf/c8047c87e8ccef8abe3352e8e4cd78dcaaf8f869/csaf_2.0/examples/csaf/csaf_vex/2022-evd-uc-03-ms-001.json> | `44cecfd8f465c8d6c88775420df61651ad76dd741605ee400c92ce30cab4f8a9` |
| PURL specification v1.0.0, supplemental helper syntax contract | <https://raw.githubusercontent.com/package-url/purl-spec/v1.0.0/docs/standard/specification.md> | `2c1d1d20912b7258339cad1b994ff1f9eb1fb6b5d009831f982d89012e28756c` |

CSAF sections 3.1.2 and 3.1.3, and schema definitions `branches_t` and
`full_product_name_t`, establish that a branch's `product` is a full product name
with `name` and `product_id`; `product_identification_helper` carries the external
identity. Sections 3.1.3.3.1 and 3.1.3.3.4 define CPE/PURL helpers. Section 3.1.8
makes the ID a document-local reference token. Mandatory tests 6.1.1 and 6.1.2
require referenced definitions to exist and product IDs to have only one definition,
including across branches, top-level names and relationships.

The RHSA example supplies the positive nested-branch CPE fixture
`cpe:/o:redhat:rhel_aus:7.6::server`. Only its product shape is reused inside a
synthetic VEX envelope; the original example is a security advisory. The official
VEX example supplies branch products without identification helpers: those remain
unread under this deliberately narrower contract. Synthetic exact PURL fixtures
exercise the same schema field and the pinned PURL component contract.

## Reading contract and bounds

- Only explicit branch `product` objects with a nonempty full name and ID plus a
  readable concrete versioned PURL/CPE become matchable. Free branch/category/name
  text never supplies an identity or version. The original helper strings are
  passed to existing matchers, preserving ecosystem, namespace and version scope.
- Unknown references, malformed helpers and relationship products cannot fall
  back to a raw ID, even when the ID looks like a package name or PURL. Explicit
  malformed top-level helpers also refuse aliases. Valid top-level unversioned
  products retain the established legacy ID/name/helper behavior.
- Any repeated definition refuses that ID, even identical repeated definitions.
  Collisions between branches, top-level products and relationship products obey
  the same rule. A later definition cannot overwrite an earlier one.
- The tree walk visits top-level `full_product_names`, branches in depth-first
  document order, then relationship entries. Cursor frames avoid queuing every
  sibling. Root entries have depth 1. At most 32 levels and 10,000 entries are
  read; every entry, including malformed entries and top-level/relationship
  entries, consumes one node. A branch's explicit product is part of that node.
- Optional `maxCsafTreeDepth`/`maxCsafTreeNodes` parser limits may lower those
  budgets, including to zero. Finite values are floored and clamped; nonfinite
  values use the defaults. They can never widen the hard ceilings. Effective
  limits are recorded in the existing optional `unreadStructureRule` string.
- A truncated walk refuses **every** product reference, including already-read
  top-level definitions: an unseen definition could duplicate any of them. This
  deliberately trades matches for an honest incomplete reading. An exact boundary
  without remaining entries is complete; no extra entry is inspected to decide.
- Existing document (4 MiB), statement (2,000), product (2,000), and example (10)
  limits remain. Unread references count once per CVE/status group/unique ID,
  independently of statement/product retention. They are not also emitted as
  unreadable identity strings, so the API does not count the same omission twice.

Existing optional omission counters/examples/rules carry the durable evidence;
no persisted required field was added. Unread branches retain
`csaf_unindexed_product`. New kinds distinguish ambiguous IDs
(`csaf_ambiguous_product`), unknown references (`csaf_unknown_product`) and malformed
top-level identities (`csaf_unread_product_identity`). Previously persisted
statements still resolve without the optional omission fields.

The helper reader is a conservative syntax subset, not a complete schema or
PURL/CPE conformance validator. Malformed escapes, qualifiers/subpaths, wildcard
versions, incomplete formatted CPEs, and unsupported CPE escaping/patterns are
refused rather than repaired. Existing API package/ecosystem matching rules are
unchanged. Relationships, version ranges, boundary status interpretation, other
helper schemes, and OpenVEX nested identifier/subcomponent semantics remain deferred.
The coordinator owns any backlog update; this worker did not edit the backlog.

## Validation

The new 35-case core branch suite fails against isolated source from base
`fb1e765`: 17 failed / 18 passed. The original checkout was not overwritten.
The earlier 32-case version also failed before implementation (14 failed).

Executed in this writing worktree:

- Focused core VEX tests: 3 files / 83 tests passed.
- Full core suite: 20 files / 597 tests passed.
- Core build passed before API consumption.
- Focused API VEX/SBOM/normalization tests: 9 files / 287 tests passed.
- API typecheck and build passed.
- Repository `pnpm biome` passed, including NUL, comment, API mock, slice-denominator
  and agent-surface checks (0 audit errors/warnings).

Fixtures cover nested versioned PURL/CPE positives, sibling versions with distinct
statuses, ecosystem/namespace/version negatives, malformed/unversioned helpers,
duplicate IDs in each location, mixed read/unread references without double
counting, tiny statement/product/tree caps, actual depth 32/33 and node
10,000/10,001 boundaries, and persisted JSON round trips. Actual core parsing
feeds `vendorVexVerdictFor` and `normalizeSbom`; all four statuses preserve row
count, severity, proof state and evidence channel, with incomplete-reading
rationale for mixed assertions.

These are JSON/parser fixtures and mocked SBOM subprocess-output tests. No external
firmware tool, firmware acquisition/execution, deployment, live corpus/database,
stored lane setting, listener, isolation or host network configuration was touched.
Coordinator integration and repository-wide validation remain separate acceptance.

## Coordinator offline tool-output acceptance

The integrated built code was also exercised with real Syft
`1.55.0-security20261022` and Grype `0.121.0-security20261022`, using the existing
local image `sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42`.
The disposable container used `--network none --read-only --tmpfs /tmp`, with the
built checkout and acceptance script mounted read-only. Update checks and Grype
database updates were disabled. No package or firmware binary was acquired or run.

Its temporary root contained only Debian 12 `os-release` and a synthetic dpkg
status entry for `openssl 3.0.9-1`, architecture `arm64`. Syft measured
`pkg:deb/debian/openssl@3.0.9-1?arch=arm64&distro=debian-12`; the local cached
Grype database returned 53 advisory rows. Synthetic CSAF branch assertions about
that exact measured identity passed through the actual built core parser,
JSON persistence round trip, API matcher and `normalizeSbom`:

- Each of the four supported status groups annotated all 53 rows as requested.
- Different version, architecture or distribution qualifiers annotated no row.
- Malformed duplicate qualifiers and duplicate product IDs annotated no row and
  retained 53 unread-reference omissions each.
- A mixture of readable and undefined references retained the matching assertion
  plus explicit incomplete-reading omissions in every row and the persisted
  document summary.
- Every case preserved row count, severity, proof state and evidence channel.

The assertions are synthetic; the tool/database output is real. This validates
identity and evidence transport, not the truth of a vendor assertion, firmware
presence, reachability or exploitability. An initial acceptance-script assertion
used the wrong verdict enum spelling; correcting the fixture to the existing
`vendor_states_*` names required no product change. The script, final JSON and
initial diagnostic are retained as `csaf-branch-built-real*` in the campaign's
external state directory. All four repository gates passed at integrated commit
`744b3ae` (5,196 tests); later integrations require their own final gates.
