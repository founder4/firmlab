# RP2350 source-anchored decoder candidates — 2026-11-08

Target: the remaining BACKLOG limitation that the PICOBIN RISC-V temporary decoder view picks its exact
Zba/Zbs candidates by one linear width walk, which cannot tell inline data from code. Clean writing worktree at
`eab54cc`; ownership limited to `apps/api/src/providers/picobin-riscv{,-decoder-view}.ts`, their tests, and
this report. No helper workers. Backlog triage, integration and final gates belong to the coordinator.

The `2046e15` safety contract (`RP2350-DECODER-EVIDENCE-SAFETY-20261108.md`) is unchanged: the whole-result
acceptor `acceptPicobinDecoderRecovery` was not edited, and neither were source byte/width/overlap checks,
graph and call preservation, refusal of irrelevant/nonprogressing views, restoration beyond the block display
cap, or completion/failure/source-availability accounting. This change only decides **which proposals reach the
view**, before the external retry.

## Reproduction before changes

The real Finding 1A fixture (64 zero bytes; offset 0 `11a00300130533100128b316a0288280`, offset `0x28`
`8280`, entry `0x10000000`) was run against the pinned local radare2 image
`sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42`, offline (`--network none`,
`--read-only`, `--tmpfs /tmp`, only the synthetic-fixture directory mounted read-only).

- Unpatched decode: `j 0x10000004` (0), `addi a0, t1, 259` (4, `13053310`), `jal 0x10000018` (8, `0128`),
  then a missing continuation at `0x1000000a`. The c.jal target is `0x10000018`, as the safety report found.
- The legacy linear walk proposes offsets 6 and 10. Offset 6 is phase-lost: the walk read the inline halfword
  `0300` at 2 as a 32-bit start, so `33100128` straddles the ADDI's high parcel and the compressed call.
- At `eab54cc` the whole acceptor correctly refuses that view: no substitution, ADDI and call retained, entry
  function not completed (`functionsCompletedTotal: 0`).
- A hand-built view replacing **only** offset 10, run through the same pinned radare2, decodes
  `j`, `addi` (`13053310`), `jal 0x10000018` (`0128`), the anchor at `0x0a` and `ret` at `0x0e`, with block
  `0x10000000+2 → 0x10000004` intact. So a safe exact view existed, and the generator was what lost it.

## Change

`selectPicobinDecoderCandidates` (pure, exported, in `picobin-riscv-decoder-view.ts`) is the candidate
selection decision. Without evidence it is exactly the legacy walk, and the existing view tests pin that. With
`PicobinDecoderSourceEvidence` from the unpatched decode of the same function:

- **Known instructions** are authoritative. These are valid original rows whose bytes match the source
  (`picobinDecoderSourceEvidence` in `picobin-riscv.ts`), and whose width matches the source length encoding
  (checked by the selection). The walk steps over them and never proposes inside or across one.
- **Boundaries** cover the declared/function entry, known instruction starts/ends, block starts/ends/jump/fail,
  instruction jump/fail (call targets included), and `missing-continuation` stops. A 32-bit parcel whose
  second halfword is a boundary is not proposed. The walk resynchronizes at that boundary instead.
- An unsupported longer/reserved parcel **at** a boundary stops the walk, as before. One that is not at a
  boundary resumes at the next reported boundary inside the window, or stops if there is none.
- If a known row contradicts the source (bytes, width, misalignment, mutual overlap, outside the file), no
  candidate is selected and **no retry runs**: the acceptor could never preserve that row.
- Budgets are unchanged: the 4 KiB view window and 64 substitutions per view.

Every legacy proposal the anchored walk does not keep is recorded, with one of three reasons:

| reason | meaning |
| --- | --- |
| `known-instruction-overlap` | proved conflict: overlaps a valid, source-consistent original instruction |
| `known-boundary-bisected` | proved conflict: a reported boundary falls inside its 4 bytes |
| `unanchored-phase` | **not** a conflict: the legacy walk only reached it after an earlier proved phase loss |

Each kept substitution carries `candidateBasis`. `corroborated-boundary` means its start is the entry or a
boundary the source decode reported. `linear-scan` means it was reached only by width stepping from one.
Neither label proves code, and neither does an exclusion prove data.

New optional-forever fields: `PicobinDecoderSubstitution.candidateBasis`,
`PicobinRiscvDisassembly.decoderCandidateExclusionsTotal` and `decoderCandidateExclusions` (at most 64 rows,
keyed per function, because the same bytes can conflict with one function's evidence and not another's), and
the optional `exclusions`/`stop` on an evidence-anchored `PicobinDecoderView`. No required field, persisted
shape, reason sentence or finding-evidence key changed. One clause was added to the finding rationale.

## Result on the real fixture (pinned radare2, offline)

Offset 6 is withheld before the retry as `known-instruction-overlap` against `0x10000004`. Offset 10 is
selected as `corroborated-boundary` (it is the stopped continuation). The whole acceptor admits the view and
restores `bset x13, x0, x10` with source bytes `b316a028`. ADDI `13053310`, c.jal `0128` with jump
`0x10000018`, and the call edge `0x10000000/0x10000008 → 0x10000018` are byte-identical to the unpatched
decode. The entry function now completes this static scope (`ret` at `0x0e`).

The helper at `0x10000018` holds zero bytes and no RET in the original fixture. It stays a decode failure
(`unparsed-output`, sample `0000000000000000`), so `callGraphTruncated: true` and the reason still says
`coverage incomplete`. The RET at `0x28` was not relocated and is not claimed. Subprocesses: 3 (entry, one
view retry, helper; the helper's zero bytes offer no candidate, so it gets no retry).

A **separately labelled synthetic variant** adds `8280` at `0x18`. Only then do both functions complete, with
no decode failures and `callGraphTruncated: false`. It exists to show that completion follows the bytes. It is
not part of the Finding 1A fixture.

## Cases covered

Baseline-red against `eab54cc` sources (14 cases fail there; all pass after):

- real S1: whole view previously refused, now admitted with offset 6 withheld; real labelled synthetic variant;
- mock S1 using the pinned tool's rows: the view must leave bytes 0–9 untouched and replace only `0x0a`;
- **no retry** when the only stop candidate is bisected by a reported branch target (`beqz → 0x06`, fallthrough
  `0x04`). The legacy path spent a second subprocess for a view the acceptor had to refuse;
- **no retry** when a valid original row contradicts the source width (two C.NOP parcels reported as one
  four-byte instruction);
- pure selection: adjacency at exact known starts/ends (kept) against a real straddle (overlap or bisection,
  excluded); unanchored-phase labelling with no conflict address; unsupported non-boundary parcel resumed only
  at a later boundary, and stopping when there is none or the parcel is itself a reported start; inconsistent
  evidence refusal; 64-substitution cap and 4 KiB window under evidence; evidence derivation, including null on
  a byte contradiction; a null original decode anchored only at the declared entry.

Retained unchanged in meaning: the 159 previously integrated focused cases, including the 13 real-tool cases:
entry/mid-block Zba/Zbs, direct branch/fallthrough recovery, backward-edge uniqueness, unsupported entry and
mid-block tails, the replacement cap, 129-block restoration, no-relevant-candidate/no-retry, subprocess failure,
short-prefix unavailability, graph-attribution refusal and operation-cap stops. The real S1 case keeps its
ADDI, call, edge and no-corruption assertions. Its completion assertion changed from 0 to 1 because the
improvement makes the entry function complete. The helper still fails and coverage stays incomplete.

## Limits

This is a filter plus a better-anchored walk, not a code/data classifier. It removes proposals that
**contradict** source decoder output. Beyond the last reported boundary, the walk is still linear stepping that
can lose phase in uncorroborated bytes, so a `linear-scan` candidate remains provisional and the whole acceptor
still decides. An `unanchored-phase` exclusion may drop a proposal that was actually code. That is deliberate:
its phase was already disproved upstream, and an accepted view must not rest on it. Boundaries are radare2
claims about the unpatched view, not runtime facts. Contradictory evidence (a boundary inside a known
instruction) keeps the known instruction and is otherwise left to the acceptor. Nothing here proves execution,
semantics, a global region, or whole-image coverage. Secondary `LOAD_MAP` regions and corroborated code/data
distinction stay open in the BACKLOG item, which this report does not edit.

## Validation

```sh
pnpm --filter @firmlab/core build
FIRMLAB_TEST_RADARE2_IMAGE=sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42 \
  pnpm --filter @firmlab/api run test rtos.test.ts picobin       # 172 passed (14 real-tool)
pnpm --filter @firmlab/api run test rtos.test.ts picobin          # 158 passed, 14 skipped
pnpm --filter @firmlab/api check
pnpm --filter @firmlab/api build
pnpm biome
git diff --check
```

All passed. Only the existing local image was used. Nothing was built, pulled, retagged, deployed or pushed.
No firmware was fetched or executed, and no corpus, database, lane, setting, listener, isolation or host network
state was touched. Process ownership, executor isolation, the eight-target, sixteen-call, depth-four,
128-block, 256-operation and 32-edge budgets are unchanged.
