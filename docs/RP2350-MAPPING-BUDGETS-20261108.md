# RP2350 mapping bounds and decoder budgets — 2026-11-08

Scope: review sections 3–4 of the campaign's independent RP2350 review, inspected
against clean worker base `ad6b55b63f3407f99a99b5302be5169855981ba0` before editing.
The base already includes core commit `4789875`, whose optional fifth startup-copy
argument supplies a selected source window. Only `picobin-riscv.ts`, its test,
and this report change. No helper workers were used.

## Mapping decisions

An entry must be halfword aligned and have at least two bytes within its selected
runtime region and file. Absolute LOAD_MAP storage must fit entirely within
`[0x10000000, 0x11000000)`. The selected LOAD_MAP runtime span is refused if any
other positive region overlaps anywhere in that span, including away from entry.
No precedence or copy order is invented for overlapping metadata.

Rolling mappings retain their affine base, but their usable runtime window is the
intersection of XIP and the file-backed affine range. Positive deltas therefore
cannot map addresses below XIP; negative deltas cannot invent preceding bytes.
Stored unsigned 32-bit deltas remain normalized as signed words. Invalid coordinate
values and negative affine bases are refused.

Startup-copy parsing now receives the exact selected primary window and no bytes
beyond the supplied file size. The core helper bounds its startup-code scan,
table entries/terminator, and complete source spans to that window. Secondary
runtime resolution rejects partial destination overlaps throughout the selected
span, overlaps with the primary runtime span, and sources that do not agree with
and fit the primary affine mapping and file. The optional `sourceBounds` field
remains optional for old stored tables.

## Finite scheduling and honest accounting

Review recommendation 3.1 was **not** applied as a refill-until-eight-successes
scheduler. The existing eight admitted targets, including entry, remain a hard
attempt budget: a failed target retains its slot. Each target can invoke at most
one original decode and one decoder-view retry, for a maximum of 16 subprocess
attempts. The existing eight-function, depth-four, 128-block, 256-instruction,
4 KiB decoder-view, and 64-substitution limits remain.

The scheduler processes callers breadth first by depth and runtime address and
admits ascending distinct target addresses within each caller. Edge display is
separate: all calls in the already bounded listed instructions can discover
eligible targets, even after 32 display edges. The edge display keeps the lowest
caller, callsite, then target addresses. Its temporary candidate collection is
bounded by eight decoded functions times 256 listed instructions; it does not
trigger additional whole-image analysis or increase target/depth/attempt budgets.

New result fields remain optional forever:

- `functionTargetsQueuedTotal` counts all admitted targets including entry;
  `functionTargetsPendingTotal` counts admitted targets still awaiting an attempt.
- `functionsAttemptedTotal` counts targets tried, `functionsDecodedTotal` counts
  non-null bounded function decodes (including retained partial prefixes), and
  `functionsCompletedTotal` counts decodes with no observed stop or block/op cap.
  Completion describes this static decoder scope, never execution or whole-image
  completeness. `decoderAttemptsTotal` counts actual executor calls, including
  retries and thrown tool errors; both attempt caps are recorded.
- `droppedFunctionTargetsTotal` counts distinct in-map targets excluded by depth
  or attempt budgets. `functionTargetSelection` records the admission rule.
- `callEdgesTotal`, `droppedCallEdgesTotal`, `droppedOutOfMapCallEdgesTotal`, and
  `callEdgeSelection` expose display omissions and the deterministic selection.
  The existing out-of-map total and listed sample remain available.
- `graphStopReasons` retains every applicable limit, incomplete-decode,
  unparsed-output, and tool-error reason. A decode failure cannot overwrite a cap
  reason; prose explicitly retains both configured limits and incomplete coverage.

Null, malformed, or out-of-window decoder output is `incomplete-decode`, never
proof of an unsupported instruction. Tool errors remain `tool-error`. Historical
`unsupported-instruction` enum values remain readable. Failure samples contain
at most eight bytes and are clamped to the selected runtime span, supplied file
size, and actual available byte array. Stopped continuations retain no sample:
a stop can be the mapping boundary or a tool/noreturn uncertainty.

Finding kind, severity, count policy, and static proof ceiling are preserved.
Executor ownership, isolation, and decoder-view implementation are unchanged.

## Validation and limits

The first regression run before production changes failed 12 cases, including
mapping bounds, delayed distinct target discovery, failure accounting, byte
sampling, and caller-supplied startup-copy bounds. Further cases verify the full
16-executor-call ceiling with every admitted helper failing recovery, stable
selection under reversed instruction arrival, combined instruction-cap/decode
failure reasons, depth limits, and short-byte-array samples.

Final validation:

- `pnpm --filter @firmlab/api run test picobin-riscv.test`: 40 passed, 12 opt-in
  external-tool cases skipped in the ordinary run.
- `FIRMLAB_TEST_RADARE2_IMAGE=sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42 pnpm --filter @firmlab/api run test picobin`:
  **70 passed**, including all 12 existing real-radare2 cases.
- `pnpm --filter @firmlab/api check` and `pnpm --filter @firmlab/api build`: passed;
  core was built before API validation.
- `pnpm biome`: passed repository-wide, including the static safety audits.
- `git diff --check`: passed.

The acceptance image already existed locally and was inspected by immutable ID;
no image was built, fetched, or retagged. Real-tool tests use disposable containers
with `--network none --read-only --tmpfs /tmp` and read-only mounts containing
only independent synthetic fixtures. They exercise bounded static disassembly,
not arbitrary firmware execution or runtime/peripheral proof. No deployment,
push, firmware acquisition, corpus/database/stored-lane write, listener, host,
network, or isolation configuration change occurred. Repository-wide integration
validation and any core/runtime/RTOS/web/backlog follow-up belong to the coordinator.
