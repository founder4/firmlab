# MediaTek LK legacy header subset — 2026-11-08

This closes only the 512-byte LK part of the vendor-header backlog gap. Rule `mediatek-lk` identifies a
container matching the bounded U-Boot legacy producer contract. It does not identify a physical device,
architecture, manufacturer of the enclosing firmware, bootability, security configuration or authenticity.
Generic uImage detection and incidental `MTK` strings are not evidence of this format.

## Primary sources and revision

The annotated U-Boot tag `v2026.10` resolves through tag object
`a58e2b7af42c179ace2c6210de0a219fa3f3cf3c` to immutable commit
`5508406582f6f7120dce0c4b3059819a41788db2`, resolved with:

```sh
git ls-remote https://github.com/u-boot/u-boot.git 'refs/tags/v2026.10*'
```

Sources read at that commit:

- [`tools/mtk_image.h`](https://github.com/u-boot/u-boot/blob/5508406582f6f7120dce0c4b3059819a41788db2/tools/mtk_image.h):
  `union lk_hdr` and `LK_PART_MAGIC` establish the layout and magic.
- [`tools/mtk_image.c`](https://github.com/u-boot/u-boot/blob/5508406582f6f7120dce0c4b3059819a41788db2/tools/mtk_image.c):
  `mtk_brom_parse_imagename`, `mtk_image_check_params`, `mtk_image_vrec_header` and
  `mtk_image_set_header` establish the accepted subset's producer semantics.
- [`doc/README.mediatek`](https://github.com/u-boot/u-boot/blob/5508406582f6f7120dce0c4b3059819a41788db2/doc/README.mediatek):
  distinguishes LK legacy headers from the separate device/BRLYT/GFH BootROM envelope. Its flash, boot,
  installation and firmware acquisition instructions were not followed.

Source bytes and SHA-256 manifests are retained outside the repository in
`/Users/agfil/orca/campaign-evidence/mediatek-headers-20261108/` (working copy also under
`/tmp/firmlab-mtk-20261108/`). No upstream implementation was copied into production code; the parser is
an independently authored, byte-only core helper with no new dependency.

## Accepted field contract

All offsets are relative to the matched header, and all words are unsigned little-endian.

| Offset | Width | Field and acceptance |
| --- | --- | --- |
| 0 | 4 | `LK_PART_MAGIC = 0x58881688`, bytes `88 16 88 58`. |
| 4 | 4 | Payload size, excluding the 512-byte header; must fit actual remaining bytes. Zero is valid. |
| 8 | 32 | Name, NUL-terminated and otherwise NUL-padded; empty and non-ASCII names are valid. |
| 40 | 4 | Load address, nonzero as required by the producer's parameter check. No memory-map inference. |
| 44 | 4 | Mode, nonzero as required by the producer's source comment. Producer emits `0xffffffff`. |
| 48 | 464 | Reserved area remains `0xff` from producer initialization; other layouts are unsupported. |

The README says the name maximum is 32, but the generator first uses `snprintf` into a 32-byte buffer:
only 31 name **bytes** survive, followed by NUL. Names longer than that are truncated by the generator;
they are not rejected at the CLI. A fully occupied 32-byte field without NUL is outside this subset.
The generator places no printable-ASCII restriction on names. Metadata is decoded as UTF-8 with replacement
for incomplete sequences, including a multibyte character cut by the generator's 31-byte limit; this is
presentation of the stored bytes, not evidence that the original name is recoverable losslessly.

Ordinary generation refuses an empty input file, but `mkimage -s` creates a valid header-only image with
payload size zero. The parser therefore accepts zero rather than inventing a nonempty-payload invariant.
An address of zero is refused by the producer and parser. Other nonzero addresses and modes establish no
runtime or hardware validity; mode values other than `0xffffffff` follow the source's explicit nonzero
requirement, not an assertion that this tool emits them.

The helper validates safe integer offsets before reading, accounts for `Uint8Array.byteOffset`, and uses
`payloadSize <= remaining - 512` without 32-bit addition/wrapping. It accepts embedded headers at nonzero
offsets and ignores bytes beyond the declared image, which can belong to another object. A missing header
or declared payload returns an explicit unavailable/exceeds-remaining reason, never a clean result.

There is **no checksum or hash field** in this LK header. The strongest emitted tier is `consistent`;
changing an in-bounds payload byte cannot be detected by this header. No integrity or authentication
verification is claimed. Structural rejection follows the existing scanner path before the listing cap,
preserving `matched`, `rejected`, `rejectedByRule`, and the complete surviving rule-id denominator.
Metadata uses the existing optional record; no required persisted field or classification mapping changed.

## Independent generator acceptance

The specified local image was inspected first:

```text
sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42
```

It contained Python and `dpkg-deb`, but neither `mkimage` nor a compiler. Inspected local tools and SDK
images also lacked a usable compiler. No image was pulled or shared tag changed. Instead, the public host
tool package
[`u-boot-tools_2026.10~rc5-1_arm64.deb`](https://deb.debian.org/debian/pool/main/u/u-boot/u-boot-tools_2026.10~rc5-1_arm64.deb)
was downloaded to the temporary evidence directory and extracted there with `dpkg-deb -x` inside the
container. This did not install a package on the host or container root filesystem; no `apt` was used.
`mkimage -V` reports **2026.10-rc5**. Its upstream revision is
`a06e89ab05eaa2b8344d521319399333cd760ae5`; downloaded `mtk_image.c` **and** `mtk_image.h` at that revision
compare byte-for-byte equal to the pinned final release files. The acceptance used that independently
packaged upstream tool, not a fresh build of the final-release executable.

All tool execution used a disposable container with `--network none --read-only`, no published ports,
and only the temporary evidence source/tool/fixture directory bind-mounted for outputs. The payload was
constructed locally as bytes 0 through 255 followed by `0xa5` (257 inert bytes). It was never executed.
The representative generation command, inside that container, was:

```sh
/evidence/tool/usr/bin/mkimage -T mtk_image -a 0x81000000 \
  -n 'lk=1;lkname=synthetic' -d /evidence/fixtures/payload.bin /evidence/fixtures/normal.bin
```

The retained `generate.py` runs nine variants using this invocation shape:

```sh
docker run --rm --network none --read-only \
  --mount type=bind,src=/tmp/firmlab-mtk-20261108,dst=/evidence \
  --entrypoint /usr/bin/python3 \
  sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42 \
  /evidence/generate.py
```

All nine generated outputs passed the compiled pure parser and scanner (`acceptance.mjs`): normal name,
31-byte name, 32-byte input name, 80-byte input name, empty name, default `U-Boot` name, UTF-8 name,
UTF-8 truncated mid-character, and `-s` zero payload. Their original and embedded-at-offset-7 forms,
with arbitrary trailing bytes, produce the same parsed fields; scanner hits remain `consistent` at 7.
Nonzero addresses 1, `0x81000000`, and `0xffffffff` are represented. Separate probes observed empty-input
refusal and zero/wrapped-to-zero load-address refusal. Failed probes are retained as such, not acceptance.

The complete 769-byte normal output is embedded as base64 in the helper test, with its SHA-256 asserted:
`3829f6203fa47e0a9a71bebcf67311cb47e19211246c9baef3c35771f6a1b689`.
Its synthetic payload hash is `b23f2086c41b555319b29654f82c18db7793c8a9628688e71c91cb20c5138a9c`.
Source hashes, tool/package hashes, fixture hashes, generation scripts and logs remain in the external
evidence directory. No firmware or binary sample was acquired, built, booted, flashed or executed.

## Regression validation and limits

Before implementation, the new tests failed against the baseline (missing helper and missing scanner rule),
with the baseline-red log retained externally. Tests cover every truncated header and payload boundary,
bad magic/endian, sizes beyond the actual view (including unsigned-addition overflow cases), zero load
address/mode, all 464 reserved-byte mutations, unsupported non-NUL names/padding, valid empty/maximum/UTF-8
names, zero payload, embedded/view offsets, arbitrary trailing data, unchanged input and absent integrity.
The scanner tests add positive/negative fixtures to its exhaustive rejecting-rule denominator table, exercise
truncation rejections with a zero listing cap, and refuse incidental strings or generic uImage as LK evidence.

Executed gates (all passed):

```sh
pnpm --filter @firmlab/core run test mediatek-image signatures  # 129 tests / 2 files
pnpm --filter @firmlab/core test                               # 613 tests / 21 files
pnpm --filter @firmlab/core check
pnpm --filter @firmlab/core build
pnpm exec biome check packages/core/src/signatures.ts packages/core/src/mediatek-image.ts \
  packages/core/test/signatures.test.ts packages/core/test/mediatek-image.test.ts
```

The full core suite passes **613 tests across 21 files**. The coordinator owns repository-wide integration
and final gates. These are generated-byte and host-tool format checks; there is no real-device or real-firmware
coverage claim.

Deferred: generic BootROM NOR/SD/eMMC device+BRLYT+GFH envelopes, non-U-Boot LK layouts (including different
reserved areas or full-width non-NUL names), NAND/SNAND, MT7621 SPL, security/authentication interpretation,
and all runtime/device attribution. The bounded LK result must not be read as completed MTK family coverage.
`docs/BACKLOG.md` remains coordinator-owned; its vendor-header item should retain those limits when updated.
