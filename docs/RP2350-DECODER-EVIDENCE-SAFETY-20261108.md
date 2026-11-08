# RP2350 decoder evidence safety — 2026-11-08

This correction addresses Findings 1 and 3 in the independent integrated review
`review-rp2350-integrated.md`. The separate writing checkout was clean at
`7f1d1ff98c9711de937173c119e0484564f9c5db` before edits. Ownership is limited to
the two PICOBIN RISC-V provider modules, their tests, and this report. No helper
workers were used. Mapping/core, RTOS selection, runtime, web, VEX, backlog and
integration gates belong to the coordinator or their separately assigned workers.

## Reproduction before changes

The first regression run against actual source failed 13 tests. It included
real radare2 reproduction of the cross-boundary corruption, the synthetic
129-block restoration failure, source mismatch and overlapping replacements,
lost original calls, irrelevant substitutions, out-of-map/indirect continuations,
and a stopped path hidden by another path's operation cap. Additional baseline
source execution verifies that an uncapped missing block tail was previously
credited as complete; the focused regressions now prevent that claim.
A subsequent focused regression also failed before adding source instruction-width
validation: a reported two-byte RET with bytes `6780` incorrectly matched the
prefix of the four-byte source encoding `67800000`.

The real Finding 1A fixture is exactly 64 bytes: at offset zero,
`11a00300130533100128b316a0288280`; at offset `0x28`, `8280`; remaining bytes
are zero. Entry is `0x10000000`. The linear view proposes replacements at offsets
6 and 10. Offset 6 spans the high parcel of ADDI and the compressed call.
Before correction, the returned ADDI bytes were `13051380` instead of
`13053310`; the call bytes `0128` were lost. After correction the complete view
result is refused, the original ADDI and call survive, and coverage stays incomplete.

One review detail did not reproduce: with the pinned decoder, `0128` at
`0x10000008` resolves to **`0x10000018`**, not `0x10000028`. The test preserves
that actual source-decode edge. The fixture's RET at `0x28` is retained as supplied;
it is not relocated to make the helper decode succeed. Thus both the entry's BSET
stop and the unsuccessful helper target remain incomplete evidence.

The 129-block fixture contains 128 four-byte `j +4` instructions followed by
BSET and RET. The replacement in block 129 is still among the listed operations.
Previously the block display cap prevented restoring it; now it is reported as
`bset x13, x0, x10`, source bytes `b316a028`, with one exact substitution.
The 128-block display cap and incomplete function accounting remain visible.

## Recovery acceptance

The linear scan remains a bounded candidate generator. Its encoded-width walk
cannot distinguish inline data from instructions or establish control-flow
boundaries after arbitrary jumps. This supersedes any implication in the earlier
boundary/recovery reports that width stepping alone proves every scanned match
is an instruction start, or that restoration should require listed-block containment.

`acceptPicobinDecoderRecovery` is a pure, exported whole-result decision:

- Every reported instruction must have complete available source bytes, a halfword
  aligned address and source-consistent 16/32-bit encoded width. Its reported bytes
  must exactly match the temporary view. Unchanged instructions must also match
  the source. Missing byte strings, overlapping instructions, source mismatches
  and any partial replacement overlap refuse the complete candidate.
- Every reported replacement must be an exact four-byte instruction at the
  substitution address, with exact source bytes and no invented jump/fallthrough.
  All listed replacements are restored, including instructions whose blocks were
  omitted by the block display cap. Discarding metadata never leaves changed
  instructions in an accepted result.
- Listed block starts, ends and continuation addresses may not bisect a replacement
  or another listed instruction. Existing block jump/fallthrough attribution must
  survive, as must every valid original instruction's size, mnemonic, type, bytes
  when present, and call/branch targets. Invalid original rows may improve.
- A non-null source decode can be replaced only when a recovered substitution
  addresses an actual missing/invalid continuation and adds a decoded instruction
  there. No substitutions, unrelated substitutions and unchanged prefixes cannot
  replace the source result. A null source decode requires an exact substitution
  at the declared entry.

The runner avoids a retry when no stopped in-map address has a relevant exact
candidate. Refused or nonprogressing recovery retains the original prefix and
its call edges with explicit incomplete coverage. A failed retry or temporary-file
operation likewise retains a non-null source prefix and records the tool error.
The view is never executed and provides no register/data-flow semantics.

Conservative refusal is intentional. This does not implement a new control-flow
or embedded-data decoder. A valid program may remain partially decoded when the
linear view loses phase, source corroboration is unavailable, a tool changes
original attribution, or a bounded candidate cannot preserve the known prefix.

## Completion and byte availability

`picobinDecodeCoverage` separates completion accounting from recovery eligibility.
Out-of-map jumps and conditional fallthroughs, unresolved indirect jumps, invalid
or unknown operations, missing uncapped block tails, interior gaps, instruction
count mismatches and contradictory block/operation attribution prevent a function
from completing this static scope. A plain RET can complete this decoder scope;
it never proves execution, peripheral behavior or whole-image coverage.

Every listed block is checked independently. Another path's operation cap cannot
hide an actual stopped continuation. Conversely, a target present only in omitted
operation rows is a display omission rather than a newly asserted decode failure.
The optional `instructionDisplayOmissions` field retains only membership for bounded
continuation queries: at most 128 blocks times four addresses plus 256 operations
times three addresses (1,280 addresses before deduplication). Inspecting omitted
row metadata does not emit more instructions, discover extra call targets or run
another process. Missing suffixes are attributed solely to display truncation only
when the first omitted address is corroborated by such a valid tool row. A cap
always prevents completion regardless of those memberships. All applicable cap,
unknown/out-of-map, inconsistent-output and tool failure reasons remain recorded.
The prose now counts `decode failure(s)/stopped continuation(s)` rather than
mislabeling every internal stop as a failed reachable function target.

A larger supplied byte buffer is sliced to declared `fileSize` for the view.
A shorter prefix never supplies imaginary bytes: recovery requires the complete
declared file, while source disassembly and call evidence remain available.
Optional `sourceBytesAvailable`, `sourceBytesDeclared` and
`decoderRecoveryUnavailableReason` fields and the reason text expose the bound,
including unavailable entry results. These new fields, like prior provider fields,
remain optional forever for persisted output. Startup-copy input remains clamped
to actual supplied bytes and declared file size.

Budgets remain eight admitted targets including failures, sixteen executor calls,
depth four, 128 displayed blocks, 256 displayed operations, a 4 KiB view scan and
64 replacements per view (and the existing 64-row substitution evidence display).
The 32-edge display cap remains independent of discovery. Process ownership,
executor isolation, listener configuration and lane authorization are unchanged.

## Validation

Real-tool acceptance uses the existing local immutable image
`sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42`.
Each radare2 process runs with `--network none --read-only --tmpfs /tmp` and only
its disposable synthetic-fixture directory mounted read-only. No image was
acquired, built or retagged, and no firmware was executed or fetched.

```sh
FIRMLAB_TEST_RADARE2_IMAGE=sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42 \
  pnpm --filter @firmlab/api run test rtos.test.ts picobin
pnpm --filter @firmlab/api check
pnpm --filter @firmlab/api build
pnpm biome
git diff --check
```

Final results: focused suites **157 passed**, including all 12 original real
radare2 cases plus the new exact 64-byte inline-data reproduction; API check
(core built first), API build, repository-wide Biome/static audits and diff
whitespace validation passed. Ordinary runs skip the 13 external-tool cases.
The original entry/mid-block Zba/Zbs recovery cases, conditional/direct target
recovery, backward-edge uniqueness, unsupported-tail degradation and substitution
cap behavior remain covered.

The coordinator still owns repository-wide integration/final gates and backlog
triage. These results establish bounded static decoder evidence only. No deployment,
push, publication, live database/corpus/stored-lane mutation, host administration,
network/listener/isolation change or arbitrary firmware acquisition occurred.
