# Recorded signature digest coverage UI — 2026-11-08

`StructurePanel` now renders the optional persisted `StaticAnalysis.signatureDigests` beside the existing
structure map. The map, proportional ribbon, native segment inspector and per-hit metadata are unchanged.
The added flat ledger reports recorded work for **listed supported MediaTek BootROM hits only**, never the
whole scanner result, corpus or firmware.

## Presentation contract

- The visible ledger preserves listed/planned, attempts/completed, matches/mismatches, unavailable results,
  invalid candidates and total budget skips as separate raw integer counts. There is no coverage/progress bar.
- A native disclosure contains execution-budget and byte-budget skips, planned/submitted/completed bytes,
  applied limits and recorded capability. The hard ceilings are 8 executions and 64 MiB (67108864 bytes);
  lower core-provided limits render unchanged, including zero.
- Capability being provided does not imply execution or completion. Submitted bytes consume budget even if
  the primitive throws or returns an invalid digest; completed bytes count only valid digest results.
- Missing old persisted fields say **not recorded**, without fabricated counters or a request to rerun.
  Malformed/wrong-scope records say unknown. Partial records retain individually valid raw values, mark
  missing/invalid fields unknown and state that completion cannot be inferred. Complete but inconsistent
  records retain raw values with that same warning; no missing count is derived from other counts or rows.
- The listed-hit scope and the unkeyed, colocated GFH/payload digest caveat remain visible with details closed.
  The first `0x600` device/BRLYT bytes, digest field and trailing bytes are unhashed. A match establishes no
  authenticity, boot, runtime, physical-device behavior or proof-state upgrade; zero never means clean.
- English/Spanish interface copy lives only in the `imageDetail` namespace. Provider notes remain verbatim,
  including their original language and line breaks, under an explicitly labelled disclosure section.

The exported pure `presentSignatureDigestCoverage` owns defensive presentation decisions. It accepts unknown
persisted data, requires the known scope before associating counts with this lane, accepts only nonnegative
safe integers, checks complete-record relationships, and refuses impossible applied limits rather than clamping.
`ImageDetail` adds only an import and a component binding. No API export or production core/API change was needed.

## Validation

Core was built before consumers; the API was compiled solely to import the byte-only analysis wrapper for QA.
The focused web run passed **113 tests across 3 files**, including **41 new coverage tests**, existing
`StructureMap` tests and existing `ImageDetail` tests. Web typecheck/build and the full `pnpm biome` check passed.
The manual diff review confirmed only the assigned component, tests/QA, two locale files, two-line page
integration, appended scoped CSS and this document changed. Repository-wide final integration belongs to the
coordinator; this is a bounded UI validation report.

Production Chromium QA uses a temporary `127.0.0.1` server on an ephemeral port, serving built web assets and
GET-only in-memory responses. It never starts the real API, imports a store, opens SQLite or writes the corpus.
The input is the existing inert U-Boot `mkimage` fixture `mediatek-bootrom-20261108/fixtures/nor.bin` (2593 bytes,
SHA-256 `e90664dda0beec0b9af8e8dfc17a693407e711128caef3e75f0059815464c9e9`). It is read-only;
no firmware is fetched or executed. All outer image metadata is explicitly synthetic.

The compiled API's `analyzeImageBuffer` produces full-listed-work, repeated-hit partial, mismatch and zero
analyses offline. Core produces no-capability, lower byte-budget and thrown-capability cases. Old-field
absence and malformed saved JSON are explicitly synthetic compatibility mutations. The persisted analysis
snapshots and provenance are retained as external artifacts.

| Fixture state | Listed / planned | Attempts / completed | Matches / mismatches | Unavailable / skipped | Submitted / completed bytes |
| --- | --- | --- | --- | --- | --- |
| Full listed work | 1 / 1 | 1 / 1 | 1 / 0 | 0 / 0 | 1025 / 1025 |
| Execution cap | 10 / 10 | 8 / 8 | 8 / 0 | 0 / 2 | 8200 / 8200 |
| No capability | 1 / 1 | 0 / 0 | 0 / 0 | 1 / 0 | 0 / 0 |
| Mismatch | 1 / 1 | 1 / 1 | 0 / 1 | 0 / 0 | 1025 / 1025 |
| Byte cap (1024) | 1 / 1 | 0 / 0 | 0 / 0 | 0 / 1 | 0 / 0 |
| Capability throws | 1 / 1 | 1 / 0 | 0 / 0 | 1 / 0 | 1025 / 0 |

The final browser run passed **68 cases**: full-listed-work, partial, unavailable and legacy absence at
320/390/1440 widths × EN/ES × dark/light (48 cases), plus malformed, zero, mismatch, byte-budget and thrown
capability at desktop in both locales/themes (20 cases). It recorded **1224 GET requests**, zero console/page
errors, zero failed/HTTP-error requests, zero document/component horizontal overflow, minimum measured text
contrast **6.39:1**, and disclosure targets of at least **44 px**. Assertions also check unchanged ribbon
percentages, native inspector focus/change handling, every raw counter and the visible scope/caveat.

Real Chromium keyboard focus and Enter open/close the native disclosure. Mobile contexts use synthesized
Chromium taps to open/close it. `selectOption` tests only the existing inspector's change handler: native
keyboard menu commitment is not proven on this Mac Chromium automation. No physical touch/device access or
screen-reader test is claimed.

All 92 final screenshots were inspected directly or through 20 contact sheets covering every capture.
Document-top full-page clipping avoids the workbench sticky header obscuring component captures. No blank,
wrong-state or clipped final capture was accepted. The layout uses incumbent text/border/accent tokens,
13 px body/12 px labels/14 px heading, a 72ch maximum measure, three desktop metric columns and two mobile
columns, with wrapping and no nested cards, eyebrows or extra badges.

## Evidence and reproduction

External evidence root:
`/Users/agfil/.local/state/orca-campaign/firmlab-20261108-034811/digest-coverage-ui/`.
It contains `focused-tests.log`, `web-check.log`, `web-build.log`, `api-build.log`, `biome.log`,
`browser-qa.log`, `fixture-analyses.json`, `fixture-provenance.json`, `requests.json`, `results.json`,
`impeccable-detect.json`, `finish-review.md`, 92 source captures and 20 inspection contact sheets.

```sh
pnpm --filter @firmlab/core build
pnpm --filter @firmlab/api build
pnpm --filter @firmlab/web test SignatureDigestCoverage StructureMap ImageDetail
pnpm --filter @firmlab/web check
pnpm --filter @firmlab/web build
pnpm biome
node apps/web/src/components/SignatureDigestCoverage.qa.mjs \
  /Users/agfil/.local/state/orca-campaign/firmlab-20261108-034811/digest-coverage-ui \
  /Users/agfil/orca/campaign-evidence/mediatek-bootrom-20261108/fixtures/nor.bin
```

Impeccable review was performed inline because this Dispatch explicitly forbids helpers; no independent
reviewer verdict is claimed. Disposition: **ship at this bounded surface scope**. The detector found no issue
in the new component; its four existing side-stripe warnings and one grid advisory are in unrelated earlier
CSS and were preserved. No design-system files were created or rewritten: this is an incumbent Operate-mode
extension, using the existing tokens and typography. No deployment, push, DB/corpus mutation, lane change,
firmware egress or host/network configuration change occurred.
