# RP2350 decoder recovery — 2026-11-08

Scope: independently verify and repair review findings 1.2–1.4 from
`review-rp2350.md`, based on clean editing worktree commit `6f35be5`.
The existing instruction-width stepping and actual `bytesExamined` fix is retained.
Only the two PICOBIN RISC-V provider modules, their tests, and this report change.

## Real decoder observations

Acceptance containers used `--network none --read-only --tmpfs /tmp`; each radare2
process received only the directory containing synthetic byte fixtures, mounted
read-only. Initial diagnostic probes also used disposable network-none containers
and synthetic bytes, created inside their temporary filesystems. No firmware, live database/corpus, lane override, deployment, listener,
isolation setting, shared image tag, or host configuration was changed.

Acceptance image, pinned by local immutable ID:
`sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42`
(`firmlab-campaign-20261108/firmware:trixie-304e663` at inspection time).
It reports radare2 **6.2.4 +1**, ABI 152, commit
`485e5e205b190fc297a2a95a6f982ff5d9f54039`, linux-arm_64.
The existing firmware image ID
`sha256:76f8e015d2f06334a7c803f506dc0915406213cc021ef93e23132e9d8424ed0c`
reported the same decoder and reproduced the initial entry/mid-block failures.

Observed with explicit `af` at runtime address `0x10000000`, with no whole-image
autoanalysis:

| Synthetic input | Original radare2 result | Recovered result |
| --- | --- | --- |
| `b316a028; ret` (BSET at entry) | `afbj=[]`, no `pdfj` function | Starts at the declared entry |
| `130101ff; b316a028; ef008001; ret` | One 4-byte block containing only ADDI; no error indicating the dropped call | One 16-byte block, four unique instructions, direct call to `0x10000020` followed |
| Leading BSET/SH1ADD/SH2ADD/SH3ADD, then direct call and RET | No entry function for each encoding | One 12-byte block, three instructions, plus one one-instruction helper |
| ADDI then each supported encoding, direct call and RET | One-instruction ADDI prefix for each encoding | One 16-byte block, four instructions, plus the helper |
| `bset; bnez a0, entry; ret` in a reachable helper | Leading NOP plus shifted `af` already returns the earlier loop-entry block and instruction | Original-entry MOV view returns exactly two blocks and three unique instructions |
| Conditional target, conditional fallthrough, or direct jump target starts with BSET | Destination block is absent while another prefix/path decodes | Missing mapped continuation triggers recovery |
| Unsupported near-match `b316a02a` at entry / after ADDI | No function / one-instruction prefix | Unavailable entry / retained prefix with explicit incomplete coverage |
| 65 BSETs followed by RET | No entry function | 64 substitutions retained; remaining tail explicitly incomplete |

The opt-in tests reproduce the original `afbj`/`pdfj` truncation before asserting
recovery. The backward-edge test also executes the former shifted NOP view and
asserts that radare2 itself already returns the substituted entry address.

## Implementation and evidence boundaries

`picobinDecodeStops` is an exported pure decision function. It recognizes missing
mapped branch continuations and nonterminal blocks with no decoded fallthrough;
a non-null prefix alone cannot establish complete coverage. It is conservative
for call-ending blocks because this lane has no independent noreturn proof.

Both the declared entry and reachable helper functions use the same recovery
path. Exact supported non-control-flow instructions are replaced in a temporary
same-length view with `0x00008013` (`mv zero, ra`). The discarded destination
keeps the analysis anchor acceptable to this radare2 release. The view is never
executed and supplies no register/data-flow or runtime proof. Recovery starts
at the original address; it never prepends instructions or rewrites an earlier
block after shifting the anchor.

Reported substitutions require an exact 4-byte decoded instruction and containment
in a listed decoded block. A scanned match after RET or in an unreached window is
excluded. Entry instructions retain original bytes and restored mnemonics; helper
substitution evidence retains original bytes and an optional `mnemonic` field.
That field remains optional for persisted older output. The rationale describes
these two evidence locations accurately.

A recovered function is checked again for stopped continuations. A failed/partial
fallback cannot clear incomplete coverage. New stopped-continuation reports use
`incomplete-decode`, which does not claim that an instruction at the stop address
was proved unsupported. They retain the address and reason without sampling bytes:
a stop may be a mapping boundary, tool limit, or unknown noreturn behavior.
The existing null-target/tool-error paths retain their previous classification
and sampling behavior, pending the separately scoped medium-priority review.

All existing mapping choices, process executor ownership, block/instruction,
function/depth/edge, 4 KiB view, and 64-substitution caps remain. Reaching a view
cap does not claim coverage of the discarded tail. This is bounded static decoder
evidence, never proof of execution, instruction semantics, peripheral behavior,
indirect-target coverage, or whole-image completeness.

## Reproduction and validation

Run the real offline acceptance suite from this worktree:

```sh
FIRMLAB_TEST_RADARE2_IMAGE=sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42 \
  pnpm --filter @firmlab/api run test picobin
```

The image must already exist locally; the command does not build or retag it.
Ordinary unit runs omit the environment variable and skip external-tool cases.

Validation at the settled change:

- All focused PICOBIN tests, including 12 opt-in real radare2 cases: **49 passed**.
- `pnpm --filter @firmlab/api check`: passed, including core build first.
- `pnpm --filter @firmlab/api build`: passed.
- `pnpm biome`: passed across the repository, including safety/static audits.
- `git diff --check`: passed.

Repository-wide integration tests/build remain the coordinator's final campaign
validation responsibility. Review sections 3–4 (mapping and scheduler accounting),
RTOS aggregation, runtime planning, core parsing, web changes, and backlog edits
are outside this worker's ownership and are left for their separately scoped work.
