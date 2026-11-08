# MediaTek BootROM local SHA-256 integrity — 2026-11-08

This completes the digest check explicitly deferred by [the BootROM envelope subset](MEDIATEK-BOOTROM-20261108.md).
It applies only to **listed** `mediatek-brom-nor`, `mediatek-brom-emmc` and `mediatek-brom-sdmmc` hits in a new
analysis. It changes neither the parser/scanner's structural acceptance nor LK/other formats, signature counts,
classification, confidence, row counts or `ProofState`. No deployment or persisted-result migration was performed.

## Boundary and integrity claim

`analyzeBuffer` runs `verifySignatureDigests` before structure and identity are built. The pure core module
`signature-digests.ts` exports the byte-validation plan and bounded verification decision; it contains no crypto
implementation, Node import, network access or algorithm selector. `AnalyzeOptions.signatureDigests.sha256` is
an **internal function capability**, never an HTTP field, Settings value or model input. The existing API intake
wrapper supplies only `createHash('sha256').update(bytes).digest()` from `node:crypto`; the capability contract
requires a synchronous, nonmutating function returning exactly a 32-byte `Uint8Array` (Node Buffer accepted).
A copied submission also protects the source from accidental mutation; `Buffer.slice()` is deliberately avoided.
No provider-supplied verified flag chooses a state.

Every supported listed hit is reparsed from the actual view and hit offset with `parseMediaTekBromHeader`.
The id must agree with the parser's declared media. Existing hit metadata, offsets/sizes within metadata,
previous tiers and raw expected/computed hash metadata are not trusted. Known metadata is rebuilt from that
parse. Invalid/truncated/id-disagreeing candidates are retained with `invalid_candidate`, an explicit revalidation
failure and no verified tier; no digest is called. Scanner acceptance/rejection counts remain untouched.

For a valid envelope at offset `H`, with parser-declared total size `T`, the capability receives exactly
`[H + 0x600, H + T - 32)`. Its 32 returned bytes are compared with the actual field at `[H + T - 32, H + T)`.
Both nonzero embedded offsets and `Uint8Array.byteOffset` are honored; trailing bytes are ignored.

- Match: `digest: verified`, tier `verified`, score 99 under the existing `SignatureTier` rubric.
- Mismatch: `digest: mismatch`, tier `consistent`, score 85. The structurally consistent row remains visible.
- Missing/wrong-type capability, thrown exception or malformed result: explicit `unavailable`, tier `consistent`,
  score 85; never a mismatch or a negative result. Exception text and returned hash values are not emitted.
- Budget refusal: `skipped_budget` with its execution/byte reason, tier `consistent`, score 85.

A match proves only **local integrity of the covered GFH/payload relative to the colocated unkeyed digest**.
The first `0x600` device/BRLYT bytes, the digest field and trailing bytes are outside that hash. A valid change
from NOR to eMMC/SD in that unhashed header can still match. Every candidate rationale states this limit and
refuses authenticity, device, boot, execution or whole-image clean proof. The metadata carries statuses,
reasons and absolute covered/unhashed ranges, plus the existing reparsed header fields; no actual expected or
computed digest value is added to signature/structure metadata or sent to research. Hash lookup, capture,
research settings and egress behavior are untouched.

Standalone `scanSignaturesDetailed` and `parseMediaTekBromHeader` retain their previous unverified semantics.
Standalone `analyzeBuffer` supplies no digest primitive by default: it reports capability unavailable and retains
`consistent`/85. The API wrapper has the native capability. `analysis.signatures` and `signatureScan.hits` share
the updated list; structure metadata is built from that same list.

## Work and coverage bounds

Hard ceilings are **8 executions and 64 MiB total bytes submitted per analysis**. Internal options may only
lower them; larger values and positive infinity clamp to the ceilings, negative/nonfinite-invalid limits fail
closed, and fractional limits round down. Execution and byte budgets are checked before calling the primitive.
Candidates are scheduled by offset then id using code-unit order; output rows keep their original order.
An oversized earlier candidate is skipped without preventing a later small candidate. A throwing/malformed
call still consumes its execution and submitted-byte budget.

The new optional-forever `StaticAnalysis.signatureDigests` coverage records:

| Field | Meaning |
| --- | --- |
| `scope`, `capability` | Listed supported hits only; function provided or unavailable, not successful proof. |
| `listed` | Supported ids in the scanner's bounded hit listing. Not all scanner matches or corpus coverage. |
| `planned`, `invalidCandidates` | Actual-byte eligible candidates versus failed revalidation. Their sum is `listed`. |
| `attempted`, `completed` | Primitive calls versus calls returning valid 32-byte digests. A throw/malformed return is not completed. |
| `matched`, `mismatched` | Outcomes of completed comparisons; sum equals `completed`. |
| `unavailable`, `skipped` | Eligible candidates without a valid result versus budget refusals. `completed + unavailable + skipped = planned`. |
| `skippedExecutionBudget`, `skippedByteBudget` | Explicit budget-refusal counts. |
| `bytesPlanned`, `bytesSubmitted`, `bytesCompleted` | Eligible covered bytes, actual submitted bytes (including throws), and covered bytes with valid returned digests. No claim of actual hash work on a throw. |
| `maxExecutions`, `maxBytes`, `note` | Applied limits and explicit listed-only/partial/zero-result limitations. |

Per-hit notes and ranges are bounded by the existing hit listing; no independent unbounded result list is added.
A zero candidate count or zero mismatches never means clean. Existing scanner listing caps are preserved and
can omit additional matches; digest coverage never extends to those unlisted hits. On older persisted JSON,
absence means **not recorded**. Old analyses are not automatically reverified, and no stored database/corpus
was opened or rewritten for this task.

## Validation and evidence

Base: `f650b3d84c8c058b1c6ac2b45ee4cc81417a73af`. Before implementation, an API test using the complete independently
packaged mkimage NOR fixture failed: expected `verified`/99, got `consistent`/85 and `not_verified`.
The fixture is the same inert 257-byte payload/envelope pinned in the BootROM parser tests, with full-file
SHA-256 `e90664dda0beec0b9af8e8dfc17a693407e711128caef3e75f0059815464c9e9`; this is fixture provenance,
not a hash emitted by analysis metadata. No hand-built fixture claiming a mocked digest match supplies the
positive acceptance evidence.

Evidence outputs: `/Users/agfil/orca/campaign-evidence/mediatek-digest-20261108/` (baseline-red, core/API tests,
checks/builds, full Biome, offline container acceptance, fresh generated files, coverage summary and manifest).
Inputs: existing `/Users/agfil/orca/campaign-evidence/mediatek-bootrom-20261108/`, mounted read-only and unmodified.
The source pin, packaged-tool provenance and input manifest remain documented there and in the BootROM document.

Commands executed in this worktree, with core validation/build before API validation:

```sh
pnpm --filter @firmlab/core test
pnpm --filter @firmlab/core check
pnpm --filter @firmlab/core build
pnpm --filter @firmlab/api run test src/analysis.test.ts src/routes/analysis.test.ts
pnpm --filter @firmlab/api check
pnpm --filter @firmlab/api build
pnpm biome
git diff --check
```

Focused tests exercise real Node crypto, actual generated bytes, payload/GFH/digest mutation, changed valid
unhashed media declarations, source/view/embedded/trailing bounds, forged/stale metadata and tiers, invalid and
truncated candidates, absent/throwing/wrong-type/wrong-length capability results, zero/one execution budgets,
byte-budget boundaries, total hard caps, deterministic scheduling, later small candidates, source immutability,
analysis/scan/structure coherence, unchanged counts/classification, listed-only coverage and legacy JSON.
Host runtime: Node **26.13.0**, pnpm **11.23.0**. Full core: **768 tests / 23 files**, including **46** new digest
tests; focused API analysis/route mocks: **13 tests / 2 files**. Core/API checks/builds and full Biome passed.
Core has no existing `test/analyze.test.ts`; analysis integration coverage lives in the new digest test file.

The real container check uses only the existing local image, with no pull/build/tag:

```sh
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount type=bind,src=/Users/agfil/orca/workspaces/firmlab/campaign-mtk-digest-20261108,dst=/work,readonly \
  --mount type=bind,src=/Users/agfil/orca/campaign-evidence/mediatek-bootrom-20261108,dst=/input,readonly \
  --mount type=bind,src=/Users/agfil/orca/campaign-evidence/mediatek-digest-20261108,dst=/output \
  --entrypoint node sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42 \
  /output/acceptance.mjs /work /input /output
```

Node **22.23.4**, packaged `mkimage` **2026.10-rc5**. The external acceptance script invokes the existing host
image-generation tool (never generated firmware) with `-T mtk_image -a 0x201000 -n media=nor|emmc|sdmmc -d
/input/fixtures/payload.bin /output/fresh-<media>.bin`. All three fresh outputs equal the prior real fixtures
byte-for-byte and verify through the actual compiled API native binding. All **20 accepted generator cases**
(including duplicates/options; 17 distinct accepted layouts from the prior task) verify at 99, stay consistent
at 85 in default core, verify in embedded byte views, and become visible mismatches after payload/digest
mutation with counts unchanged. All **8 unsupported/refused outputs** produce no BootROM digest attempt.
A valid changed unhashed media declaration still matches with the limitation attached. A native ten-envelope
analysis reports ten listed/planned, eight attempted/completed/matched and two execution-budget skips.
No server/listener, real analysis POST, store, database, corpus, firmware acquisition/execution or deployment
was involved. These are inert generated-byte and host-tool checks, not real-device, real-firmware or deployed
acceptance. All pre-existing unsupported format variants remain deferred to the coordinator-owned backlog.
