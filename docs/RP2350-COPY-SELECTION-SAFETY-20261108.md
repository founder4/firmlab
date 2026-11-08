# PICOBIN copy-table and image selection safeguards — 2026-11-08

The independent integrated review found that a referenced XIP pointer array could
satisfy the structural startup-copy pattern. Its interpreted destination overlapped
the primary mapping, causing the API to reject even normal calls within primary
flash. The core helper now refuses positive destinations overlapping its selected
source window. This is conservative mapping evidence, not a claim that every
other pointer triple is an executed CRT0 copy operation.

The table address must be word aligned in runtime memory. Alignment of the file
offset is independent: a halfword-shifted affine base can legitimately put a
word-aligned runtime table at a non-word-aligned file offset. Tests retain that
case instead of blindly requiring both coordinates to be word aligned.

When the provider knows the file size, executable RISC-V image selection now
prefers candidates whose entries actually resolve through the same mapping
validator the disassembler uses. An earlier zero-fill, noncovering or out-of-file
LOAD_MAP no longer hides a later usable declaration. Older two-argument callers
retain their ordering. If no candidate maps, a declared candidate remains selected
so the disassembler reports its refusal; an invalid declaration is not silence.
All image declarations are still retained as optional persisted evidence.

Validation: two new MCU and two selector regressions failed before the fixes.
Afterward all 46 MCU tests and 37 RTOS provider tests pass; API typecheck/build
also pass, building core first. Existing counts, severities and proof ceilings
are unchanged. No new required persisted field or dependency was added.

A real radare2 check ran the actual built provider and core under immutable image
`sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42`,
with `--rm --network none --read-only --tmpfs /tmp`. API/core outputs and the
validation script were mounted read-only. A synthetic 512-byte image materialized
a pointer array at file `0x60`, called XIP `0x10000080` from entry `0x10000020`,
and returned. The pointer array was refused as a copy table; the valid XIP helper
and direct edge were preserved, with zero out-of-map calls. The built selector
also chose a usable declaration over a zero-fill map and retained an all-invalid
declaration for an explicit refusal. Temporary bytes stayed in the container.
Campaign evidence: `copy-selector-real.mjs`, `copy-selector-real.json`, red/green
focused logs and API check/build logs.

Decoder-view source integrity and incomplete/indirect control-flow completion are
separate review findings assigned to another worker. This evidence does not close
them, prove device execution, or expand analysis to secondary LOAD_MAP regions.
