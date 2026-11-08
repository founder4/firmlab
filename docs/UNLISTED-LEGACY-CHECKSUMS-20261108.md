# Omitted TRX and TP-Link v1 checksum work — 2026-11-08

This bounded follow-up adds cheap omitted-hit checks only for `trx` (HDR0) and `tplink-v1`, using the existing
`verifyUnlisted` contract. It leaves the previously accepted uImage implementation and scanner listing decision
unchanged, including legacy `maxHits: NaN` behavior. It adds no format, checksum algorithm, salt, runtime import,
option, global budget, proof state, provider, or network behavior.

For HDR0, the omitted-hit hook calls the same `trxVerify` that the full verifier calls before its CRC. Every length,
partition, and unavailable-byte decision is therefore shared. For TP-Link v1, the existing verifier gains a private
switch after all its original header, 256 MiB length cap, kernel/rootfs bounds, and actual-buffer bounds decisions.
Only the firmware-length copy and salted MD5 are skipped. Registry full callbacks are two-argument wrappers, so an
extra JavaScript argument cannot disable verification. The full checksum algorithms, salts, positive results and
mismatch behavior are unchanged.

The scanner still fully checks every listed hit and the first surviving hit of a new ID, even after the cap.
The cheap check's non-rejected tier and rationale never enter the output. All candidate rejection decisions still
run; omitted hits retain their contribution to matching/rejection counts and the complete ID set. There is no
claim of integrity, authenticity, execution, or global cleanliness for omitted rows.

## Reproduction and compiled acceptance

Evidence directory (outside Git):
`/Users/agfil/orca/campaign-evidence/unlisted-legacy-checksums-20261108`.

The baseline is Git commit `b2929063c7f6b2e6de5e940710e5a36cb6b994f5`. All baseline core source files were extracted
from Git and compiled, rather than copying a standalone `signatures.js` with missing dependencies. The complete
current compiled core is copied separately. Both trees, scripts, and inert fixture files are mounted read-only
at `/proof`; the only writable external bind is the evidence output directory at `/out`. The existing local image
is pinned by ID, with no pull, build, tag, provider, HTTP, firmware, corpus, or database execution:

```bash
E=/Users/agfil/orca/campaign-evidence/unlisted-legacy-checksums-20261108
docker run --rm --network none --read-only --entrypoint node \
  --mount type=bind,src="$E/input",dst=/proof,readonly \
  --mount type=bind,src="$E/output",dst=/out --workdir /proof \
  sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42 \
  /proof/probe.mjs
```

`baseline.sh`, `red-checks.sh`, and `validate.sh` record exact execution commands; `PREPARATION.md` records source
extraction, fixture creation, and compilation. Raw logs and JSON are under `output/`. `input-sha256.json` hashes
the complete source/compiled inputs, probe, fixtures and command scripts. `output/initial.diff` preserves the
uncommitted implementation and draft tests already present on entry; this task preserved and completed them.
The checksum fixtures use Node's standard zlib CRC32 and crypto MD5 as independent test/probe oracles; no new
algorithm facts or producer claims were introduced.

The baseline-only probe first reproduced amplification. Separate RED invocations then apply the new work bound
to compiled old code and both fail with the expected assertion and exit 1. The normal old/new invocation passes
on Node **v22.23.4**. Each work fixture is **128 KiB**, with **32** inert headers declaring the rest of its buffer:

| Work measurement at `maxHits: 0` | Old | New |
| --- | ---: | ---: |
| HDR0 indexed input reads | 2,411,641 | 380,149 |
| TP-Link firmware-length subarray requests | 32 | 1 |
| TP-Link bytes in those requests | 2,162,688 | 131,072 |

Instrumentation is confined to tests/probe. The proxy counts indexed accesses for the JavaScript CRC loop. For
TP-Link it binds typed-array methods to the real target and records the lengths of requested `subarray` spans
of at least 512 bytes, used by the unchanged `Uint8Array.from` copy before MD5. These are requested copy spans,
not a claim that indexed proxy reads observe native copying or MD5's reads of its private copy. The raw output
also retains all subarray spans and descriptive elapsed milliseconds; no test asserts a timing threshold and no
performance ratio is inferred from a single elapsed-time measurement.

The actual compiled old/new comparison passes **432** whole-result JSON and inferred-identity equalities across
18 non-work fixtures, eight caps (default, 0, 1, 0.5, -1, Infinity, NaN, 5000), and three confidence settings
(absent, false, true). Each scan also compares counters and complete IDs to its uncapped counterpart and verifies
that source bytes remain unchanged. Fixtures include mixed/late first IDs, checksum positives and mismatches,
truncated headers/payloads, zero/huge lengths, invalid partitions, HDR1 fallback, and unchanged uImage behavior.
The focused unit suite additionally checks normal and boot salts, both partition bounds, the 256 MiB boundary,
full registry callbacks with extra arguments, and that a rule without a hook still executes its verifier on every
omitted candidate. Full row equality covers tier, score, rationale, metadata and ordering as well as counters.

## Validation and remaining limits

- Focused signature tests: **162 passed**; full core tests: **813 passed / 24 files**.
- Core typecheck and build passed; scoped Biome passed; manual owned-file diff review and whitespace check passed.
- An initial scoped Biome run rejected a test-only `delete`; it was replaced with an undefined assignment and all
  required core checks reran successfully. The failed log is retained as `output/scoped-biome-initial.log`.
- Repository-wide gates, independent review, integration, and BACKLOG follow-up belong to the coordinator.
  The earlier independent uImage review does not review these new hooks.

**Deferred:** Sercomm checksum work, other formats, and checksum work for every listed/default-within-cap or
unbounded hit. This is an omitted-row optimization for two existing formats, not a global work budget or a
universal complexity claim. No live firmware, corpus, external tool behavior, deployed UI, or device was tested.
