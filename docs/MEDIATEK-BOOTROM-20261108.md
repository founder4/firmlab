# MediaTek generic BootROM envelope subset — 2026-11-08

Follow-up: [bounded local digest verification](MEDIATEK-DIGEST-20261108.md) now supplies native SHA-256 through
the API intake wrapper. The standalone parser/scanner described here still do not verify it; default pure core
without a trusted capability remains unverified. This document records the structural subset and its acceptance.

This closes only the **generic NOR/SD/eMMC device + BRLYT + GFH** part of the deferred MediaTek container gap,
for the U-Boot `mtk_image` producer with the default `hdroffset=0`. Rules `mediatek-brom-nor`,
`mediatek-brom-emmc` and `mediatek-brom-sdmmc` identify an envelope matching that bounded producer contract.
They do not identify a physical device, chip, CPU architecture, the actual boot medium, the manufacturer of the
enclosing firmware, bootability, security configuration, integrity or authenticity. The existing
`mediatek-lk` subset ([MEDIATEK-HEADERS-20261108.md](MEDIATEK-HEADERS-20261108.md)) is unchanged. Generic uImage
detection and incidental `MTK`, `SF_BOOT`, `BRLYT` or `FILE_INFO` strings are not evidence of this format.

## Primary sources and revision

Same pin as the LK subset: tag `v2026.10` → tag object `a58e2b7af42c179ace2c6210de0a219fa3f3cf3c` → commit
`5508406582f6f7120dce0c4b3059819a41788db2` (`git ls-remote https://github.com/u-boot/u-boot.git 'refs/tags/v2026.10*'`).

- [`tools/mtk_image.h`](https://github.com/u-boot/u-boot/blob/5508406582f6f7120dce0c4b3059819a41788db2/tools/mtk_image.h)
  (SHA-256 `b262f936…6918`): `union gen_boot_header`, `struct brom_layout_header`, `enum brlyt_img_type`,
  `struct gen_device_header`, every `gfh_*` record, `GFH_HEADER_MAGIC`, flash/signature type constants and the
  BROM_CFG bits. The header states "all fields are little-endian".
- [`tools/mtk_image.c`](https://github.com/u-boot/u-boot/blob/5508406582f6f7120dce0c4b3059819a41788db2/tools/mtk_image.c)
  (SHA-256 `35b594a7…c328`): `mtk_brom_parse_imagename` (keys `media`, `hdroffset`, `arm64`; blank trimming;
  invalid/missing media refused), `mtk_image_check_params` (zero load address refused), `mtk_image_vrec_header`
  (0xff fill of device + GFH area, `SHA256_SUM_LEN` returned as padding), `put_brom_layout_header`,
  `put_ghf_common_header`, `put_ghf_header`, `put_hash`, `mtk_image_set_gen_header`, and the tool's own weaker
  `mtk_image_verify_gen_header`.
- [`doc/README.mediatek`](https://github.com/u-boot/u-boot/blob/5508406582f6f7120dce0c4b3059819a41788db2/doc/README.mediatek)
  (SHA-256 `56288e5e…3f8c`): only for the option-string syntax and the media names. Its flash, boot,
  installation and acquisition instructions were not followed.

**The README is historical where it disagrees with the source.** Its BPi-R2 SD table shows a 512-byte device
header, a **1536-byte** BRLYT area and the preloader at `0x800`; the source's `gen_device_header` is
`0x200 + 0x400 = 0x600` bytes, and every generated output places GFH at `0x600`. The README also does not
document the `hdroffset` or `arm64` keys at all. Layout and sizes below come from the source and were confirmed
on tool output, never from the README.

Source and tool bytes were reused (copied, not modified) from the LK campaign evidence into the new external
directory `/Users/agfil/orca/campaign-evidence/mediatek-bootrom-20261108/`; old artifacts were not altered.
No upstream code was copied into production; the parser is an independently written byte-only core helper with
no new dependency.

## Accepted field contract

Offsets are relative to the matched envelope; every word is unsigned little-endian; all sizes are compared as
unsigned JS numbers without 32-bit wrapping. `T` is the declared total size.

| Offset | Width | Field and acceptance |
| --- | --- | --- |
| 0 | 12 | Device name `SF_BOOT` / `EMMC_BOOT` / `SDMMC_BOOT`, one NUL, then `0xff` (snprintf into the 0xff-filled area). |
| 12 | 4 | Device header version, exactly 1. |
| 16 | 4 | Device header size, exactly `0x200` (`sizeof(union gen_boot_header)`). |
| 20 | 492 | Rest of the device header: all `0xff`. |
| 0x200 | 8 | `BRLYT` NUL-padded to 8 (strncpy). |
| 0x208 | 4 | BRLYT version 1. |
| 0x20c | 4 | `header_size`: exactly `0x600`. Any other value (e.g. `hdroffset + 0x600`) is **unsupported**, not decoded. |
| 0x210 | 4 | `total_size` = `T`. |
| 0x214 | 4 | `BRLYT_MAGIC 0x42424242`. |
| 0x218 | 4 | Type `0x10007` NOR / `0x10005` eMMC / `0x10008` SD, and must match the device name (one `hdr_media` writes both). NAND `0x10002` / SNAND `0x10009` refused as out of scope. |
| 0x21c | 4 | `header_size_2` copy, equal to `header_size`. |
| 0x220 | 4 | `total_size_2` copy, equal to `total_size`. |
| 0x224 | 4 | `unused`: `0xffffffff` (not written for the generic path). |
| 0x228 | 984 | Rest of the 0x400-byte BRLYT area: all `0xff`. |
| 0x600 | 0x300 | GFH (`sizeof(struct gfh_header)` = 56 + 12 + 100 + 532 + 20 + 48), compared byte-for-byte against the `put_ghf_header` template below. |
| 0x900 | `T - 0x920` | Payload, at least 1 byte (the producer refuses an empty input). Not interpreted. |
| `T - 32` | 32 | SHA-256 field over `[0x600, T - 32)`. Located and reported, **not verified**. |

GFH template (record offsets relative to `0x600`; each common header is `magic_version = 0x4d4d4d | ver << 24`,
`u16 size`, `u16 type`; everything not listed is zero):

- `FILE_INFO` @0, ver 1, size 56, type 0: name `FILE_INFO` NUL-padded to 12, `unused` 1, `file_type` 1,
  `flash_type` 5 (GEN; 2 = NAND refused), `sig_type` 1 (SHA256; 0 = NONE refused as never written),
  `load_addr` = `-a` − 0x300 (free, except `0xfffffd00`, i.e. `-a 0`, which the producer refuses),
  `total_size` = `T − 0x600`, `max_size` = `T`, `hdr_size` 0x300, `sig_size` 32, `jump_offset` 0x300, `processed` 1.
- `BL_INFO` @56, ver 1, size 12, type 1: `attr` 1.
- `BROM_CFG` @68, **ver 3**, size 100, type 7: `cfg_bits` `0x190`, and `usbdl_by_kcol0_timeout_ms` 5000; with
  `arm64=1`, `cfg_bits` `0x1190` and `jump_bl_arm64` (@153) `0x64`. Any other combination is refused.
- `BL_SEC_KEY` @168, ver 1, size 0x214, type 3 (zero key area).
- `ANTI_CLONE` @700, ver 1, size 20, type 2: `ac_offset` 0x10, `ac_len` 0x80.
- `BROM_SEC_CFG` @720, ver 1, size 48, type 8: `cfg_bits` 3, zero customer name.

The reported `loadAddress` is `load_addr + jump_offset` mod 2³², which is what the tool's own lister prints and
equals the `-a` value. `arm64JumpFlag` reports the stored BROM_CFG request only — it is **not** an architecture
attribution (the tool's own lister prints "Architecture: ARM" for the `arm64=1` output, because it reads a
process global, not the header). BROM_SEC_CFG/anti-clone values are fixed producer constants checked for
equality; no security interpretation is made of them.

Order of refusal: offset → device header (512 bytes available, name, version, size, fill) → BRLYT (0x600
available, name, version, magic, type, media agreement, header_size, copies, unused, fill) → declared size
(`T == 0x900` named as the `-s` variant, else `T >= 0x921`) → GFH (0x900 available, magic/version, flash type,
signature type, load address, max/total sizes, BROM_CFG bits, template) → `T <= remaining`. Every refusal carries a
reason; a truncated or unsupported candidate is rejected before any tier is assigned, never reported as clean.
The parser reads through a `DataView` at `byteOffset + offset`, never past the view, accepts nonzero embedded
offsets, and ignores bytes beyond `T`.

**Explicitly unsupported (refused, not guessed):** nonzero `hdroffset` (BRLYT `header_size`/`total_size` shift
while GFH sizes do not; the parser names the observed `header_size` but does not infer the offset); the
header-only `mkimage -s` output, whose digest is written at `0x8e0`, inside BROM_SEC_CFG; NAND/SNAND device
headers and BRLYT/GFH NAND types; MT7621; LK; any other generator or field value.

## Integrity

Core contains no vetted synchronous SHA-256, and this task forbids adding a dependency, hand-coding crypto, or
importing `node:crypto` into the browser-safe core. The parser therefore reports the digest field
(`digest: { algorithm, offset, length: 32, coveredStart: 0x600, coveredEnd: T − 32, hex, verified: false }`) and
the scanner meta says `digest: 'not_verified'`; the strongest tier is `consistent`, and the rationale states that
the SHA-256 field is present but not verified. A changed payload byte or a zeroed digest **still parses**, and the
tests pin exactly that. Even a verified digest would establish only that the covered bytes match a value stored
beside them — never authenticity. The tool's own `-l` verifier does not check the digest either.

## Independent generator acceptance

Local image `sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42`
(`firmlab-campaign-20261108/firmware:trixie-304e663`, inspected, not pulled, built or tagged) was used only for its
Python and shell. The tool is the same extracted Debian `u-boot-tools_2026.10~rc5-1_arm64.deb`
(SHA-256 `39de53b2…f41d`) as the LK campaign: `usr/bin/mkimage` SHA-256 `3a38e693…21b6`, `mkimage -V` →
**2026.10-rc5**, upstream `a06e89ab05eaa2b8344d521319399333cd760ae5`, whose `mtk_image.c`/`.h` were already shown
byte-identical to the pinned final release. It is an independently packaged upstream binary, not a fresh build of
the final-release executable. No compiler, cross-compiler, bootloader or firmware build was used.

```sh
cd /Users/agfil/orca/campaign-evidence/mediatek-bootrom-20261108
docker run --rm --network none --read-only --mount type=bind,src=$PWD,dst=/evidence \
  --entrypoint /usr/bin/python3 sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42 \
  -I /evidence/scripts/generate.py                              # → generator.log, fixtures/generation-log.json
docker run --rm --network none --read-only --mount type=bind,src=$PWD,dst=/evidence,readonly \
  --entrypoint /bin/sh sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42 \
  /evidence/scripts/list.sh                                     # → mkimage-list.log (tool's own lister)
node scripts/acceptance.mjs <worktree>/packages/core/dist .     # → generator-acceptance.log, host Node
```

No ports, no network, read-only root; only the evidence directory was mounted. Representative invocation:
`mkimage -T mtk_image -a 0x201000 -n 'media=nor' -d payload.bin nor.bin`. Payloads are inert byte patterns
(the shared 257-byte `0..255, 0xa5` payload, SHA-256 `b23f2086…8a9c`, and `i & 0xff` for other sizes); nothing
generated was executed.

Generated with exit 0 and **accepted** (each original, and embedded at offset 7 with 41 trailing bytes, gives the
same parse; scanner `consistent` at 7, `maxHits: 0`): `media=nor|emmc|sdmmc`; `arm64=1` (flag true) and
`arm64=0`; explicit `hdroffset=0`; `' media = nor ; lkname=ignored;nandinfo=2k+64'` (byte-identical to the plain
NOR output); payload sizes 1, 2, 3, 4, 31, 32, 33, 257, 4099; addresses 1, `0x2ff` (stored `load_addr`
`0xffffffff`), `0x300` (stored 0), `0x301`, `0x201000`, `0xffffffff`. The external SHA-256 of `[0x600, T − 32)`
matched the stored digest on every one (host Python `hashlib`, evidence only, not product code). File hashes of all 17 distinct accepted
outputs are pinned in the helper test, and a test-only re-statement of `mtk_image_set_gen_header` reproduces each
byte-for-byte; the complete 2593-byte NOR output is embedded as base64 (SHA-256
`e90664dda0beec0b9af8e8dfc17a693407e711128caef3e75f0059815464c9e9`).

Generated with exit 0 and **refused with a reason**: `hdroffset=0x1000` and `hdroffset=4` (`header_size`
`0x1600`/`0x604`; their hashes are also pinned and reproduced), `-s` (`2304` bytes), `media=snand;nandinfo=2k+64`,
`media=nand;nandinfo=2g:2k+64`, `lk=1` (the LK parser accepts it; the BootROM rules do not), `mt7621=1`.
Producer refusals (exit 1, recorded as such, not acceptance): `-a 0` and `-a 0x100000000` ("Load Address must be
set"), an empty input ("is empty, bailing out", leaving a 2304-byte unpopulated file that the parser refuses),
a missing media key and `media=spi`. The tool's own lister accepts the `-s` and `hdroffset=0x1000` outputs and
rejects `hdroffset=4`; this parser is deliberately stricter than that verifier. All results: **ALL PASS**.
`artifacts.sha256` covers sources, tool, package, scripts, payloads, outputs and every log
(`generator.log`, `mkimage-list.log`, `generator-acceptance.log`, `baseline-red.log`, `focused-green.log`,
`core-*.log`, `biome.log`).

## Regression validation and limits

Before implementation the new tests failed against base `d146035` (missing helper and rules: 40 failed /
128 passed across the two files, `baseline-red.log`). The helper tests cover every truncation length of two real
layouts, a one-bit flip at every one of the `0x900` header bytes (only the free load-address word survives),
named endian/magic/version/size/copy/type/media/NAND/signature-type/BROM_CFG/load-address-zero refusals,
oversized, signed-negative (`0x80000000`) and wrapping declared sizes, honest unverified digests, embedded and
`Uint8Array` view offsets, invalid offsets, trailing bytes, a no-throw mutation fuzz, and LK/BootROM disjointness.
The scanner tests add positive/negative fixtures for all three rules to the exhaustive rejecting-rule denominator
table, keep an embedded hit past a zero listing cap while counting a malformed candidate, count every truncated
candidate, show nothing else matches a complete envelope, and refuse incidental strings, bare NUL-terminated
names, uImage magic and LK headers. `matched`, `rejected`, `rejectedByRule` and caps are unchanged in mechanism.

```sh
pnpm --filter @firmlab/core run test mediatek-image signatures   # 168 tests / 2 files
pnpm --filter @firmlab/core test                                # 652 tests / 21 files
pnpm --filter @firmlab/core check
pnpm --filter @firmlab/core build
pnpm exec biome check packages/core/src/signatures.ts packages/core/src/mediatek-image.ts \
  packages/core/test/signatures.test.ts packages/core/test/mediatek-image.test.ts
git diff --check
```

These are host-tool and generated-byte checks; there is no real-device, real-firmware or boot coverage claim,
and this is not complete MediaTek family coverage. Metadata travels only in the existing optional scanner `meta`
record; no persisted required field, identity/class mapping, API or web surface changed.

Deferred (for the coordinator-owned `docs/BACKLOG.md`): nonzero `hdroffset` envelopes, the `-s` header-only
variant, NAND/SNAND device headers and their BRLYT/GFH, MT7621 SPL, non-U-Boot producers and GFH layouts,
and all security/authentication, runtime and device attribution. Local SHA-256 verification was deferred by this
structural task and is now implemented separately through an injected vetted API capability; see the follow-up
link above. It does not relax the unsupported parser variants or authenticate the unkeyed digest.

The producer-output subset also deliberately refuses flashed/partitioned SD/eMMC disk images that replace
erased device-header bytes with an MBR at 0x1be..0x1ff. It does not interpret partition tables. Nested supported
envelopes can produce overlapping hits (outer envelope and inner payload envelope); scanner overlap resolution
remains the caller's responsibility, and each listed hit consumes its own bounded digest work if eligible.
