# Candidate validator hardening — 2026-11-08

Scope: `run_4723fc97d2d6`, task `task_3615aa7c4022`, isolated clean checkout starting at
`e8a7bd712cf63524f0db5c1a3913c0d3fbc3d114`. Only the candidate script, its shared library, the shell-shim
suite and this report change. `deploy.sh` is unchanged; integration and backlog ownership remain with the
coordinator. No promotion, deployment, shared-tag overwrite, firmware acquisition or live data change is part
of this work.

## Source defects and corrected contract

The baseline must exist locally before building. Resolve its full image ID once, then read OS metadata,
last layer and all 28 ordered probe results using that ID. A missing baseline, unreadable/unsupported Debian
version (the supported recipes are Debian 12 and 13), invalid/empty layer ID, failed/incomplete inventory or
unknown probe status refuses the build. A complete inventory can contain explicit degradation; acceptance
means no lost `ok`/`present` capability relative to that measured baseline, not that every tool works.

After Docker successfully builds, any validation failure records `rejected` and exits 4, including missing
bash/timeout, failed OS reads, incomplete/invalid inventories, malformed/missing iidfile, failed Grype checks,
invalid/unchanged final layer, moved candidate/input aliases and source changes during the build. Unexpected
shell command failures use the same rejection path. A report directory must be fresh: existing directories
are explicitly refused, and new explicit directories are created exclusively. Verdict publication uses a
same-directory temporary file and rename. As with any filesystem report, loss of write access/storage cannot
be guaranteed to produce a durable verdict; such failures never constitute acceptance.

`--allow-dirty` remains supported. Its revision label is now `HEAD-dirty-<sha256 fingerprint>`, including the
Git binary diff (tracked contents, modes, symlinks and deletions), and nonignored untracked names, contents,
executable modes and symlink targets. Source stability is checked before and after building. Ignored build
outputs are outside this source fingerprint; use an external/ignored report directory so generated evidence
does not enter the source/context. This is source identity, not a guarantee that mutable apt/pip/downloads
or caches are reproducible. Clean builds also record their source fingerprint separately.

Every local `FROM` ARG is resolved once to its full ID, including recipe defaults. Docker cannot directly
consume those IDs as `FROM` on the tested builder, so the script creates fresh task-unique private aliases
from those IDs and records both original and actual build refs. It refuses existing alias names, checks each
alias immediately, checks again before and after building, and passes the frozen aliases explicitly as build
arguments. The aliases remain for inspection/targeted cleanup. No existing ref is intentionally overwritten.
Docker lacks a transactional create-if-absent tag/build operation: these consistency checks assume exclusive,
non-hostile ownership of the private names during the build and cannot prove a transient external retag that
is restored before inspection. They do not claim immutable registry digests or raw-ID `FROM` support.

Candidate builds require a positively identified `docker` driver and named builder, and explicitly select
that builder with `--builder` and `--pull=false`. Unknown drivers/failed inspection refuse the build. The
shared deploy helper keeps its prior unknown-driver compatibility behavior; candidate strictness does not
change that existing deployment path. Candidate recipes must express `FROM` sources as local ARGs, known
stages, scratch or digest-pinned external images; unsupported expressions/unpinned literal bases refuse.
This means the legacy unpinned `Dockerfile.tools` is not accepted by the candidate path until its external
base is pinned; deploy behavior is unchanged. Public pinned recipe dependencies can still be resolved from
registries, and recipe RUN instructions can use their ordinary authorized dependency network access.

Docker Hub aliases `index.docker.io/` and `registry-1.docker.io/` now receive the same reserved repository
checks as `docker.io/`. Shared repositories remain refused even when their tag contains `candidate`.

The candidate Grype check now runs under `--network none`, with auto/app updates disabled and a 30-second
TERM budget plus a 2-second KILL grace. Its JSON must report `valid: true`, a numeric schema version, a known
UTC build-date shape and an existing database file larger than 100 MiB. The validator checks database status
and file presence, not a vulnerability scan; the synthetic Syft/Grype check below is separate evidence.

## Corrections to the external wave-one review

The Findings 2–4 leads in `review-wave1.md` matched actual defects. Its PASS checklist is not authoritative:

- No `--overwrite-candidate`, `--retained-image`, `--renode-image` or `--report-dir` flags exist. Actual flags
  are `--retained`, `--renode`, `--report`, and existing candidate tags are always refused.
- The old source recorded mutable input tags' IDs but built from the tags; it did not pass immutable IDs.
- Probe budgets are 4 seconds normally, 30 for angr and 15 for FwHunt, with 2-second kill grace. They were not
  uniformly 10 seconds.
- The old source had no `verify_candidate_grype` helper, 30-second Grype bound, JSON metadata validation or
  offline `grype dir:/var/lib/dpkg` scan. The new helper provides bounded status validation; a synthetic scan
  is recorded separately and is not silently claimed by an accepted validator verdict.
- The original script accepted a missing baseline and could exit 1 without a rejected verdict after building.
  The original real candidate remains bounded evidence for its measured inputs, not proof those guards worked.

## Executed BuildKit identity canaries

OrbStack Docker 29.8.2, BuildKit v0.33.1, builder `orbstack`, driver `docker`, ARM64. Tiny disposable recipe:

```dockerfile
ARG BASE
FROM ${BASE}
LABEL firmlab.canary="raw-id"
```

`BASE=sha256:5e73a0e69f7e6c9855b3f8a8af94212103631ae9d1b747cb5b6992d6f1d301ba` with
`--network none --pull=false` failed: BuildKit interpreted it as `docker.io/library/sha256:<hex>` and attempted
registry resolution. `--network none` governs RUN networking, not the builder's base resolution. Therefore raw
image IDs must not be used as the solution or claimed safe based on fake-ID shell tests.

The same recipe with fresh local alias `firmlab-campaign-20261108/hardening-canary:local-20261108-0450`
(same input ID), explicit `--builder orbstack --network none --pull=false`, succeeded from the local image
store. Its untagged output is `sha256:f7bb362e61dadd24c71fd3b5df7751eff6595e660bf03b8dfd02de025368c3f6`.
Canary logs are in the external evidence directory; no shared tag changed.

## Validation checkpoint

Seven focused new shell-shim regressions failed against the original source: missing baseline, unknown
baseline OS, empty baseline layer, absent timeout after build, both Docker Hub host aliases and unknown builder
metadata. The first red run was 38 passed / 7 failed. A second isolated copy of the exact original scripts,
using the finalized fixture harness, failed all eight focused regressions, including report-directory reuse
(`red-final-fixtures.log`); no original-source files were restored over the writing checkout. Additional coverage exercises missing bash, failed OS
reads, incomplete/unknown inventory results, iidfile errors, layer metadata, source/input/tag drift, frozen ARG
identities, distinct tracked/untracked dirty contents and actual JSON parsing through the validation shell.

The focused implementation checkpoint passed 27/27 relevant cases. The full shell suite passed 71/71,
including all 26 existing deploy tests; the full `pnpm biome` check passed. `/bin/bash` is macOS Bash 3.2.57;
its syntax checks and the actual shell suite pass. Clean-source real candidate results are recorded in the
follow-up evidence section when executed. The coordinator owns the
repository-wide typecheck/test/build integration gate. Expensive integration/FreeRTOS/security runtime smoke
from the first wave is retained as historical bounded evidence and will not be repeated absent a material reason.

## Clean-source real rerun

Executed successfully from clean `c6e4fbb1b7e22d0fe5e625338cd5e685578df086`:

```bash
GRYPE_DB_REFRESH=campaign-20261108-script-run /bin/bash scripts/tools-candidate.sh \
  --tag firmlab-campaign-20261108/tools:hardening-c6e4fbb \
  --retained firmlab-campaign-20261108/retained-src:2d0aba372d9d \
  --renode firmlab-campaign-20261108/renode-src:2d0aba372d9d \
  --report /Users/agfil/.local/state/orca-campaign/firmlab-20261108-034811/tools-hardening/candidate-c6e4fbb
```

Exit 0 and `accepted`. Baseline and candidate each returned 27 `ok` and one `analyzeHeadless present` across
28 bounded offline probes. Debian 13; Grype schema `v6.1.10`, built `2026-11-07T06:18:48Z`, `valid: true`.
The candidate final layer is `sha256:f46c06218786dd82d545f7bb035f58ccc7193c63e7144ba97c3a5f7320d86e9e`,
different from baseline `sha256:871427efcbb34cff773a9719657fcaf59511095da71f7d7a576be77b439c0de6`.

The refresh key deliberately reuses the first-wave cache: this rerun proves the changed input-resolution and
validation path, not a new database download or fresh apt/pip/dependency rebuild. All 27 filesystem layers
match `firmlab-campaign-20261108/tools:trixie-caf2355` exactly; the sole image-config difference is the source
revision label. Therefore there was no material reason to repeat its expensive integration/FreeRTOS/security
runtime smoke. The new image ID differs because its revision metadata differs.

The source delta fingerprint is SHA256(empty) for this clean checkout; the recorded HEAD identifies all
committed sources. For a dirty checkout the combined HEAD plus delta fingerprint identifies changed tracked
and nonignored untracked content. The fingerprint does not claim to be a full image/dependency digest.

A separate disposable `--rm --network none` scan ran against the new candidate by immutable ID, with no host
mounts and all Anchore auto/app updates disabled. A synthetic Debian 12 fixture supplied only `/etc/os-release`
and one dpkg status entry: `openssl 3.0.9-1`, architecture `arm64`. Real Syft emitted exactly that package with
`pkg:deb/debian/openssl@3.0.9-1?arch=arm64&distro=debian-12`; real Grype scanned its SBOM offline and returned
53 advisory matches with the bundled valid database. Each tool had a 90-second TERM budget and 2-second KILL
grace. These are matches on synthetic package metadata, not firmware findings, exploitability or device proof.
An earlier npm-only fixture attempt emitted no matching Syft artifact and failed its assertion; it is retained
as failed fixture evidence and supplies no npm coverage claim.

Before/after shared state remained unchanged:

| Shared state | Full immutable ID / observation |
|---|---|
| `firmlab-tools:latest` | `sha256:2d0aba372d9dfb32b9221df153622d9b70fbc7d278dcf876bf1c8f0d0a13e5f2` |
| `firmlab-firmware:latest` | `sha256:76f8e015d2f06334a7c803f506dc0915406213cc021ef93e23132e9d8424ed0c` |
| Live `firmlab` | same firmware ID, same start `2026-11-07T16:06:08.622560876Z`, healthy |

## Retained artifacts and exact cleanup boundary

Keep these new artifacts until coordinator review; no cleanup was executed:

| New ref | Full image ID |
|---|---|
| `firmlab-campaign-20261108/tools:hardening-c6e4fbb` | `sha256:4d35e3ef0cc6d7101743098d8ae05e5d004448f24a55d3f9ce82616097702eac` |
| `firmlab-candidate-input/firmlab-candidate-input.jv4ebljg-58871:retained_image` | `sha256:2d0aba372d9dfb32b9221df153622d9b70fbc7d278dcf876bf1c8f0d0a13e5f2` |
| `firmlab-candidate-input/firmlab-candidate-input.jv4ebljg-58871:renode_image` | `sha256:5e73a0e69f7e6c9855b3f8a8af94212103631ae9d1b747cb5b6992d6f1d301ba` |
| `firmlab-campaign-20261108/hardening-canary:local-20261108-0450` | `sha256:5e73a0e69f7e6c9855b3f8a8af94212103631ae9d1b747cb5b6992d6f1d301ba` |
| Untagged tiny canary output | `sha256:f7bb362e61dadd24c71fd3b5df7751eff6595e660bf03b8dfd02de025368c3f6` |

Later cleanup is limited to removing the four exact new refs above (without force) and the untagged canary
output if still unreferenced. Removing the retained alias by ID would target a shared image: use its exact
alias ref instead. Preserve first-wave retained/Renode/candidate refs and all shared tags; never global-prune.

Evidence root: `/Users/agfil/.local/state/orca-campaign/firmlab-20261108-034811/tools-hardening/` contains
`raw.log`, `alias.log`, red/green shell-suite logs, `biome.log`, the complete `candidate-c6e4fbb.log` and report
directory, both synthetic fixture logs, `image-identities.json`, `config-differences.json` and
`retained-image-refs.txt`. The coordinator still owns integration, the repository-wide check/test/build gate,
and any future operator decision about promotion, dependency refresh or deferred legacy recipe pinning.
