# Remaining scanner integrity walks: Sercomm and every other rule — 2026-11-23

This unit closes the measurement the backlog item *"Acotar el coste total de comprobaciones de integridad del
escáner"* left open after the [uImage](UIMAGE-UNLISTED-WORK-20261108.md) and
[TRX HDR0 / TP-Link v1](UNLISTED-LEGACY-CHECKSUMS-20261108.md) follow-ups. It uses the same contract: for a match
the scanner will not list, skip only payload-sized checksum or copy work, and keep every header, structural and
survival decision, every counter, the complete id set, and full verification of every listed row and first id.

**Outcome: no scanner behaviour changed.** The inventory found no remaining rule that does payload-sized integrity
work for an unlisted match. Sercomm's complete-image sum is payload-sized, but it can never run for an unlisted
match. Every other check reads a window of fixed size. The one large fixed window, RKFW's 16 KiB search, is the
rejection decision itself, so the contract forbids skipping it. The source diff adds two comments that record
why. The tests now pin all of this, so a future rule that walks its payload for unlisted matches fails them.

This is not a global work budget, and it is not a complexity claim for listed or uncapped scans. Listed rows are
still fully verified, and so they still cost O(declared payload) each, by design.

## Inventory

Every rule in `SIGNATURE_RULES` (`packages/core/src/signatures.ts`, line numbers at this commit), sorted by what
its check reads per match. "Unlisted cost" is what a match beyond the cap pays.

| rule(s) | check | reads per match | decides rejection? | unlisted cost |
|---|---|---|---|---|
| `uimage` | `uimageVerify` :253 — 64-byte copy + header CRC :259, then payload CRC | header 64 B; payload CRC only if listed | header: no (tier only); payload: no | bounded since 2026-11-08 (`verifyUnlisted` :634) |
| `trx` | `trxCrcVerify` :375 → `trxVerify` :386, then CRC over `len` | header; CRC only if listed | `trxVerify`: yes; CRC: no | bounded since 2026-11-08 (:646) |
| `tplink-v1` | `tplinkV1Verify` :343 — layout, then `len`-byte copy + MD5 ×≤2 | header; copy/MD5 only if listed | layout: yes; MD5: no | bounded since 2026-11-08 (:1140) |
| **`sercomm-prefix`** | `parseSercommPrefixHeader` :186 — 512-byte header, then **complete-image 8-bit sum** :207 | 512 B + whole buffer, in `verify` **and again in `decode`** | header: yes; sum: no (tier only) | **none can exist** — `atOffset: 0` (:980) |
| `rkfw` | `containsAt(…'RKAF', off, off + 0x4000)` :1175 | ≤ 16 KiB search | **yes, the search is the decision** | full window, kept by contract |
| `mediatek-brom-*` (3) | `parseMediaTekBromHeader` (`mediatek-image.ts` :181) — `DataView` of `min(remaining, 0x900)` :189, 32-byte digest copied as hex, never verified | ≤ 0x900 B | yes | constant |
| `mediatek-lk` | `parseMediaTekLkHeader` (`mediatek-image.ts` :26) — 512-byte `DataView` :32 | 512 B | yes | constant |
| `netgear-dni` | `containsAt(…'version:', off, off + 256)` :1076 | ≤ 256 B | yes | constant |
| `netgear-chk`, `wrgg`, `rkaf`, `pem-cert`, `uefi-fv` | `printableAscii` :1057 (≤ 0xd7 B), `asciiRun` :1035/:1187 (≤ 32/0x38 B), 64-byte label, 16-byte zero vector :724 | ≤ 0xd7 B | yes | constant |
| `realtek-cvimg-*` (2) | `parseRealtekCvimgHeader` (`realtek-image.ts` :68) — 16-byte `DataView`; checksum located, never verified | 16 B | yes | constant |
| all others with `verify` (`jffs2-*`, `gzip`, `lzma`, `elf`, `seama`, `ubnt-fw-*` :1311, `trx-v2`, `tplink-safeloader`, `imx-ivt`, `bflt`, `avb-vbmeta`, `android-dt-table`, `fmap`, `intel-fpt`) | fixed fields | ≤ 0x104 B | yes | constant |
| rules without `verify` | magic only | magic length | — | constant |

`decode` runs only for listed rows, so its cost belongs to listing, not to the cap.

### Why Sercomm gets no `verifyUnlisted`

The listing predicate is `!(hits.length >= maxHits && seenIds.has(rule.id))`. `seenIds` gains a rule id only when
a hit is listed. A rule with `atOffset: 0` can match only at offset 0, so it matches at most once per scan, and
that match runs before the rule id can be in `seenIds`. So it is always listable, under every cap, including `0`,
negative values, fractions, `Infinity` and the legacy `NaN`. A cheap form would be dead code. Its only effect
would be to make the next reader think it runs. The comment at :980 says so.

The sum's actual cost is a fixed walk per scan: once in `verify` and once more in `decode` for the listed row, so
2 × length. That cost is the same whatever the cap is and however many other matches follow. It is a constant
factor on one listed row, not the O(N × length) amplification that the hook removes. Removing the duplicate walk
in `decode` would change listed-row work. That is outside this contract, so it is left as an optional follow-up.

### Why RKFW keeps its window

`verify` for `rkfw` returns `consistent` when `RKAF` occurs within 16 KiB, and `rejected` otherwise. A cheaper
unlisted form would have to reach the same answer, and the only way to reach that answer is to search. Skipping
the search would change `rejected`, `rejectedByRule` and, through the id set, `inferIdentity`. The contract forbids
that. The window is fixed in size, not payload-sized. But it is large, and dense `RKFW` magics make it expensive
(see the measurements below). **A follow-up that preserves the decision is possible but is not done here:** find
the `RKAF` positions once per scan, then answer each window by binary search. That gives the same verdicts at
O(length + matches · log). It is recorded for the coordinator. Nothing in this unit claims it.

## Measurements

Instrumentation is test- and harness-only. It counts indexed reads through a transparent `Proxy` (typed-array
methods are bound to the real target), bytes yielded through `Symbol.iterator` (the Sercomm sum is a `for…of`,
which a read proxy cannot see), requested `subarray` spans, and the byte length of every `DataView` window (the
MediaTek and Realtek parsers read natively through one). The inputs are synthetic inert bytes generated in
process. No firmware, database, corpus, HTTP, provider or network was used. Node v26.13.1 (host). The scanner
output is identical before and after this change, so every number below holds for both builds.

**Per-match work on raw magic** (every rule, 16 copies, `maxHits: 0`, with the filler baseline subtracted; the
total of the four counters). The numbers are the same at 64 KiB and 256 KiB for every rule except `rkfw`, whose
last windows are clipped at the end of the 64 KiB buffer:

| rule | 64 KiB | 256 KiB |
|---|---:|---:|
| `rkfw` | 14,977 | 16,520 |
| `mediatek-brom-nor` / `-emmc` / `-sdmmc` | 2,324 / 2,334 / 2,335 | same |
| `mediatek-lk` | 518 | 518 |
| `netgear-dni` | 265 | 265 |
| `uimage` | 77 | 77 |
| every other rule | ≤ 48 | same |

**Sercomm, valid prefix with a zero sum** (bytes yielded to the sum per scan):

| length | other matches | caps 0 / 1 / NaN / 5000 | per length | listed | `matched` |
|---:|---:|---:|---:|---|---:|
| 64 KiB | 0 | 131,072 each | 2.0 | yes, `verified` | 1 |
| 64 KiB | 64 | 131,072 each | 2.0 | yes, `verified` | 65 |
| 256 KiB | 0 | 524,288 each | 2.0 | yes, `verified` | 1 |
| 256 KiB | 64 | 524,288 each | 2.0 | yes, `verified` | 65 |

A broken header (secondary magic) is rejected before the sum, with 0 bytes yielded.

**RKFW worst case** (an `RKFW` every 4 bytes, no `RKAF`; every match rejected; `maxHits: 0`):

| length | matched = rejected | indexed reads | reads per buffer byte |
|---:|---:|---:|---:|
| 16 KiB | 4,096 | 50,384,894 | 3,075 |
| 32 KiB | 8,192 | 151,089,150 | 4,611 |
| 64 KiB | 16,384 | 352,497,662 | 5,379 |

Per byte, the work tends to a constant of about 6 K reads once the 16 KiB windows stop being clipped at the
buffer end. So it is linear in length, but with a large constant. Elapsed time, *descriptive only and not an
acceptance criterion* (median of 3, unproxied, JIT-dependent): 19.3 s at 256 KiB and 7.1 s at 1 MiB, against about
10 ms for the inert control. `netgear-dni` dense (`device:` every 7 bytes, 64 KiB): 9,362 matches, 2,850,262
reads (43.5 per byte).

## Evidence

**Unit regression** (`packages/core/test/signatures.test.ts`, suite *remaining integrity walks: no unlisted match
pays payload-sized work*, 7 tests):

- Sercomm is anchored at 0. Under caps `default, 0, 1, 0.5, -1, Infinity, NaN, 5000`, at 16 and 64 KiB, with 0 or
  64 other matches, it is listed exactly once at offset 0 as `verified`, with decoded `meta`. Counters, id set and
  every listed row equal the uncapped scan. Sum bytes are the same for every cap and at most 2 × length.
- A nonzero sum stays listed as `consistent` under every cap. A broken header is rejected, counted in
  `rejectedByRule`, and never reaches the sum.
- `maxHits: NaN` on a Sercomm image equals `maxHits: 5000` (the legacy listing, bbc8872).
- For every registry rule, per-match work on raw magic is equal at 80 and 160 KiB and at most 0x5000.
  **RED check:** temporarily widening RKFW's window to `buf.length` fails it with
  `rkfw: expected 140363 to be 57803`. Reverted.
- Eight stacked valid `mediatek-lk`, `mediatek-brom-nor` and `realtek-cvimg-cs6c` headers each declare the rest of
  the buffer. Capped and uncapped work differs by at most 64 B per header between 64 and 256 KiB, against the
  ~192 KiB per header that a payload walk would add. Per header the work stays within 4 × header size + 256. Only
  the first row is listed under `maxHits: 0`, all 8 uncapped, none rejected.

**Compiled old/new comparison:** baseline `da3d24f` `dist/` against this change, on 10 inert fixtures (Sercomm
valid / 64 other magics / bad sum / bad header / shifted, 16 stacked uImages, dense RKFW, RKFW with RKAF, dense
DNI, mixed magics) × 8 caps × 3 `highConfidenceOnly` settings. All **240** whole-result `JSON.stringify` and
`inferIdentity` comparisons are identical, and every buffer's SHA-256 is unchanged. Compiled `signatures.js`
differs by comment lines only (old `f713b34d…2194`, new `22387e9b…7e38`).

Harness files are in the session scratchpad and are transient, so they are listed by hash: `measure.mjs`
`aeece92c…eed1e`, `compare.mjs` `0fe11b94…b12`, `rkfw-time.mjs` `fea9486e…1992`, `result.json` `328107df…5d04`.

Gates: core build, and core tests **820 passed / 24 files**; `pnpm check` passed. In `pnpm biome`, every pre-step
passed (NUL, comment-glob, web mock, slice-denominator, agent-surface). `biome check` found one formatting error,
in `.impeccable/hook.cache.json`, a local, git-excluded editor cache that was rewritten during the session and is
not part of this change. `biome check packages apps scripts` passes (705 files).

## Limits

The inputs are synthetic bytes only. No live firmware, corpus, container, deployed UI or device was used. This
unit gives no new budget for listed or uncapped rows, and it gives no global work bound: the RKFW window stays the
largest fixed per-match cost, and it can be amplified by dense magics. A sum, CRC or MD5 that was not computed for
an omitted row is a question this scan did not ask, never a negative or a clean result.
