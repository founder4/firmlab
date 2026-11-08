# RP2350 startup copy mapping — 2026-11-08

The core PICOBIN parser now interprets `ROLLING_WINDOW_DELTA` as signed 32-bit.
Raspberry Pi's [picotool metadata definition](https://github.com/raspberrypi/picotool/blob/master/bintool/metadata.h)
stores `rolling_window_delta_item.addr` as `int32_t`, serializing its raw word as `uint32_t`.
Existing stored unsigned numbers remain readable; API mapping already normalizes the raw word with `| 0`.

`parseRiscvStartupCopyTable` accepts an optional selected file-backed runtime window.
It requires entry bytes, the scanned AUIPC/ADDI pair, every table entry and terminator,
and each source span to fit both that window and the input file. Entry address and
file offset must agree with the affine base, and the entry must be halfword aligned.
Long/reserved or truncated instruction prefixes stop the scan. Overlapping positive
copy destinations are conservatively ambiguous and refused. These checks do not
prove the startup code executed or that a refused table is invalid firmware.

The fifth argument and returned `sourceBounds` field are optional. Existing callers
retain their whole-file affine window, and old persisted results need no migration.
A new caller supplying a selected window gets that exact bound recorded in its result.

Focused validation: 44 MCU tests and core build passed, including negative/zero/positive
deltas, bounded source/table/terminator/code, inconsistent and odd entry mappings,
and overlapping destination ranges. All inputs are synthetic local byte arrays.

Integration boundary: the API decoder worker owns `picobin-riscv.ts` concurrently.
The coordinator must pass its validated primary mapping to this helper after that
worker settles; this core change alone does not close the provider's mapping bounds.
Secondary LOAD_MAP regions and broader instruction decoding remain separate work.
