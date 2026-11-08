# RP2350 decoder-view instruction boundaries

The bounded radare2 compatibility view previously checked every two-byte offset for exact
32-bit Zba/Zbs opcodes. Halfword alignment does not establish an instruction start: a match
could combine the upper half of a 32-bit instruction with the following 16-bit instruction.
The synthetic bytes `b316a0286f00b316a0280100b316a028` reproduced substitutions at offsets
0, 6 and 12. Offset 6 lies inside the JAL word `6f00b316` at offset 4, so the view changed a
control-flow instruction despite only intending to replace non-control-flow encodings.

The view now advances by the encoded 16/32-bit instruction length from its declared entry.
A longer/reserved prefix or incomplete instruction ends the walk, and invalid numeric or
odd runtime entry boundaries are refused. The 4 KiB window and 64-substitution cap remain.
`bytesExamined` records the actual completed prefix when a cap or unsupported length stops
the scan. Source firmware bytes remain unchanged. This linear walk does not prove that
embedded data is code, recover instruction semantics or establish runtime execution.

Primary basis: RISC-V International's ratified unprivileged ISA,
[Base Instruction-Length Encoding, table 1](https://docs.riscv.org/reference/isa/v20240411/unpriv/intro.html#_base_instruction_length_encoding).
The first parcel distinguishes compressed instructions from 32-bit instructions; longer
encodings require additional length bits and are outside this compatibility view.

Validation on 8 November 2026:

- Focused tests cover the crossing JAL, a legitimate 32-bit instruction after a compressed
  instruction, unsupported/incomplete lengths, the substitution cap and invalid mappings.
- A disposable `--network none` container using local image
  `sha256:76f8e015d2f06334a7c803f506dc0915406213cc021ef93e23132e9d8424ed0c`
  ran real radare2 against the synthetic source and corrected view. At address `0x10000004`,
  both decoded `j 0x1003096e`, with unchanged bytes `6f00b316` and the same jump target.
  The fixture mount was read-only; no corpus or database was accessed.

This checks the specific static decoder boundary. It is not a new run of the official Pico
firmware samples, a boot, peripheral coverage or a claim about a physical RP2350.
