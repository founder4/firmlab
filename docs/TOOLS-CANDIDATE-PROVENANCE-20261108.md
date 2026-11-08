# Tools candidate recipe provenance — 2026-11-08

Run `run_4723fc97d2d6`, task `task_dbe178c7a6b0`, isolated writing checkout based on `2046e15`.
Scope is the candidate script, shared helper, recording-shim suite and the two candidate reports.
`deploy.sh`, API/core/web, deployment, corpus/database, stored lanes and host/network configuration are unchanged.

## Independently reproduced defects

Read the external `review-tools-integrated.md` before changing source. Against the original `2046e15`
scripts, isolated fixtures independently reproduced:

- External, Git-ignored and HEAD-tracked symlink recipes could change during the mocked build and still receive
  `accepted`, an unqualified clean HEAD revision and SHA256(empty) as their source delta. The recorded recipe
  hash no longer matched the file. These reproductions omitted `--allow-dirty`.
- Failure of the second private `docker tag` left the first alias present with no `inputs.tsv`. The original
  propagated tag exit 18; the fixed refusal exits 1 and preserves the evidence. A nonignored in-repo report
  created both aliases and then aborted on its own report files entering the source fingerprint.
- An incomplete candidate inventory published two rejection messages and replaced the specific `1 de 28
  sondeos` reason with a generic final verdict.
- The original pure name helper returned no refusal for `firmlab-candidate-input/tok:retained_image`,
  `docker.io/myorg/input:v1` with input `myorg/input:v1`, `firmlab-campaign/tools:` and `:v1`.

The normalized-input name gap is distinct from Docker's existing-ref protection: a real local input also
exists under its supported Docker Hub aliases, and the existing `docker image inspect "$TAG"` guard refuses
it. A pure helper result or a shim with incomplete alias resolution does **not** demonstrate a real overwrite.
Both the name check and actual existing-ref inspection remain in place.

The initial focused red run had 26 cases: 4 passed and 22 failed. Tracked recipe mutation checks already
passed against the original source; the missing protection concerned recipe bytes outside the fingerprint.
The separate original-source reproduction initially expected exit 1 for the failed tag; correcting that
expectation to its observed exit 18 allowed verification of the missing manifest and duplicate verdict.
The failed attempt and corrected evidence are retained.

## Recipe contract and identity

`--recipe` must designate a regular file tracked in HEAD inside the physical worktree. External files,
untracked recipes (including ignored files), recipe symlinks and HEAD-tracked symlinks are refused before
any Docker mutation, even with `--allow-dirty`. A new recipe must first be committed. Absolute paths to the
original tracked `Dockerfile.trixie` remain supported; its physical parent is canonicalized and the build
receives the stable worktree-relative path.

Modified tracked regular recipes remain supported with `--allow-dirty`. The script records their raw Git
blob hash using `git hash-object --no-filters`, includes that path/hash in the SHA-256 source fingerprint,
and compares the raw hash with the HEAD blob independently of `git status`. Thus Git filters or an
`assume-unchanged` hint cannot silently turn changed recipe bytes into a clean HEAD label. A dirty revision
is `HEAD-dirty-<fingerprint>`; a clean revision remains HEAD with the recipe hash recorded separately.
The new clean fingerprint includes recipe identity and is no longer necessarily SHA256(empty).

Recipe eligibility and raw bytes are checked after baseline inventory, immediately before source-known
validation, immediately before build, and after build. The complete source fingerprint is also compared
before/after build. A persistent change before build refuses with exit 1; a detected change during build
produces one atomic `rejected` verdict and exit 4. Ignored non-recipe outputs remain outside the general
source fingerprint, and ordinary non-recipe symlinks contribute their link text, not external target bytes.

These are consistency checks, not a filesystem transaction or an immutable recipe snapshot. Another process
can temporarily mutate and restore a recipe between observations; an undetected transient mutation is a
known nontransactional limit. This limit does not excuse omitting raw-byte checks at the documented boundaries.
Run with exclusive ownership of the checkout, candidate name and private input names. The identity does not
pin mutable package repositories, downloads or build caches.

## Durable mutation evidence and refusals

The fresh report header and original ref/ID rows now exist before any private alias creation. For each
alias, `ARG_build_ref_intent` records its exact ref and expected full ID **before** `docker tag` runs.
`ARG_build_ref_actual` records the subsequently inspected ID or `unknown`; `ARG_build_ref_status` records
`tag_succeeded` or `tag_failed` as the command receipt. A successful command receipt alone does not verify
identity: only a matching actual ID yields the existing `ARG_build_ref` row and permits building.
A failed command can still have created an alias, so inspection is attempted even after tag failure.
Intent survives an ambiguous receipt or interruption before observation. The candidate build likewise has
a `candidate_intent` row, and the chosen Grype refresh key is recorded before build.

The temporary token directory is removed immediately after allocating its name, before alias creation.
Aliases remain for inspection; there is no automatic removal, shared-ID removal or global cleanup.
As before, Docker supplies no atomic create-if-absent tag operation; a concurrent hostile daemon mutation
cannot be made transactional by before/after inspection. Disk loss/write failure can prevent further receipts;
a preexisting durable intent must not be mistaken for verified creation.

A report must be fresh and either outside the worktree or Git-ignored. Physical parent resolution handles
symlinked parents, and the default TMPDIR is checked too. Nonignored in-repo paths refuse before Docker
queries/mutations, so evidence cannot trigger a self-induced source-change refusal after creating aliases.
External reports are recommended: a Git-ignored path is not automatically excluded by Docker's build context;
use a path also excluded by `.dockerignore` if storing reports inside the worktree.

The name guard reserves `firmlab-candidate-input` and its descendants, validates nonempty repository and
explicit tag syntax, normalizes `docker.io`, `index.docker.io`, `registry-1.docker.io`, implicit library/latest
spelling, and compares baseline, overrides and recipe defaults. Lowercase repository components, uppercase
or lowercase tags and registry host/port forms are supported; IPv6-literal registry names are not supported
by this conservative candidate guard. The actual Docker inspection still refuses any existing candidate ref.

The shared inventory helper now returns a failure with its stderr diagnostic instead of invoking the caller's
`die` from a command substitution. The candidate parent alone publishes the final verdict, including missing
timeout/bash, incomplete inventory and unknown-status diagnostics. Baseline failures exit 1 before build;
built failures exit 4. Deploy's existing callers already use `|| exit 1`, preserving their fail-closed behavior.
Subshell error handlers also cannot publish a second verdict. Verdict replacement remains a temporary-file
rename within the fresh report directory.

## Validation evidence and limits

The recording shim executes the actual scripts and probe loop under macOS `/bin/bash` 3.2.57. The 97-test
checkpoint passed, including all 26 existing deploy tests; the initial 26 focused provenance cases passed.
Additional cases cover hidden raw-byte edits, recipe-default name collisions, prompt token-directory removal,
in-repo TMPDIR refusal and valid name spellings. Full Biome and Bash syntax checks passed at the checkpoint.
The final full suite passed 106/106, including all 26 existing deploy tests. A strengthened pre-second-tag
manifest assertion then passed its focused 2/2 rerun. Full `pnpm biome`, `/bin/bash -n` and `git diff --check`
passed; the coordinator owns the repository-wide typecheck/test/build gate. The supported real-build rerun
is recorded below.

Five real no-build invocations refused with exit 1: private input namespace, empty tag, empty repository,
nonignored in-repo report, and external recipe. These calls introduced no image refs. Real Docker snapshots
and logs are retained externally. No fake-ID shell test establishes BuildKit resolution behavior: the prior
[real BuildKit canaries](TOOLS-CANDIDATE-HARDENING-20261108.md) remain the evidence for private local aliases,
explicit `docker` driver/builder selection and `--pull=false`; those Docker flags and recipe build inputs did
not change in this task.

The prior accepted image `sha256:4d35e3ef0cc6d7101743098d8ae05e5d004448f24a55d3f9ce82616097702eac`
has the same 27 layers as the first-wave `sha256:210f1165…` image, differing only in its revision label.
The coordinator independently verified this. The final filesystem layer is `sha256:f46c0621…`, not image ID
`210f…`; the first-wave report now distinguishes those and labels its 37-test/no-`docker tag` statements as
historical. Existing expensive functional smoke is historical bounded evidence, not a new smoke claim.

Evidence root: `/Users/agfil/.local/state/orca-campaign/firmlab-20261108-034811/tools-provenance/`.
It contains original-source recipe/alias/verdict/tag reproductions, red/green suite logs, no-build refusals
and before/after Docker snapshots. The coordinator owns integration and the repository-wide check/test/build
gate. Promotion, deployment, dependency refresh and cleanup remain outside this task.

## Clean-source real cached rerun and retained refs

Built successfully from clean `62a2c7c88b93f16ea69710ede004f114c43d963a`, explicitly using the absolute path
of the original tracked recipe:

```bash
GRYPE_DB_REFRESH=campaign-20261108-script-run /bin/bash scripts/tools-candidate.sh \
  --tag firmlab-campaign-20261108/tools:provenance-62a2c7c \
  --recipe /Users/agfil/orca/workspaces/firmlab/campaign-tools-provenance-20261108/Dockerfile.trixie \
  --retained firmlab-campaign-20261108/retained-src:2d0aba372d9d \
  --renode firmlab-campaign-20261108/renode-src:2d0aba372d9d \
  --report /Users/agfil/.local/state/orca-campaign/firmlab-20261108-034811/tools-provenance/candidate-62a2c7c
```

Exit 0, `accepted`, approximately 11 seconds. Baseline and candidate each returned 27 `ok` and one
`analyzeHeadless present` across the 28 bounded offline probes. Debian 13; offline Grype status was valid.
The raw recipe blob is `ab290d87a3340d4f7e36e959a29c2783cdcbaa3a`, and the clean source fingerprint is
`e11aed882642a7bca12159d3cfec76506a484ea1c8417b5afb82034a5d091798`.

The refresh key deliberately reuses the prior cached Grype layer; this validates the changed recipe/path,
mutation-manifest and acceptance path, not a new database download or dependency refresh. All 27 filesystem
layers exactly match accepted `hardening-c6e4fbb` (`sha256:4d35e3ef…`). The sole difference within Docker
inspect's `.Config` is `Labels.org.opencontainers.image.revision`, now `62a2c7c…`. The final layer remains
`sha256:f46c06218786dd82d545f7bb035f58ccc7193c63e7144ba97c3a5f7320d86e9e`.
No expensive functional smoke was repeated because the filesystem layers are identical.

Only these three new refs were created by this task; all are retained, and no cleanup was executed:

| New ref | Full image ID |
|---|---|
| `firmlab-campaign-20261108/tools:provenance-62a2c7c` | `sha256:df539ca29174f734100a209619fc1e58e5869c4ee9e4325b5bc71a15cbd4d311` |
| `firmlab-candidate-input/firmlab-candidate-input.httwsynq-66617:retained_image` | `sha256:2d0aba372d9dfb32b9221df153622d9b70fbc7d278dcf876bf1c8f0d0a13e5f2` |
| `firmlab-candidate-input/firmlab-candidate-input.httwsynq-66617:renode_image` | `sha256:5e73a0e69f7e6c9855b3f8a8af94212103631ae9d1b747cb5b6992d6f1d301ba` |

Any later cleanup must target only these exact refs, never their shared image IDs or a global prune. The
retained alias shares the live tools image ID. Before/after inspections confirmed `firmlab-tools:latest`
(`sha256:2d0aba37…`), `firmlab-firmware:latest` (`sha256:76f8e015…`), the previous accepted candidate and the
live container's identity/image/start time unchanged; its observed Docker health was `healthy`. This is
local container evidence, not a new claim about external remote-access availability.

`candidate-62a2c7c.log`, its complete report directory, `candidate-result.json`, `real-verification.json`,
`new-image.json`, `retained-image-refs.tsv` and before/after snapshots persist in the external evidence root.
The documentation-only follow-up does not alter the source script validated by this rerun.
