# Realtek legacy cvimg header subset — 2026-11-08

This closes only a narrow part of the Realtek vendor-header gap. Rules `realtek-cvimg-cs6c` and
`realtek-cvimg-cr6c` identify a 16-byte header whose fields fit the legacy Realtek SDK host tool `cvimg` for
its `linux` (`cs6c`) and `linux-ro` (`cr6c`) options. A match is a container boundary. It does not identify a
chip, device, vendor of the enclosing firmware, architecture, bootability, security configuration or
authenticity. The declared start and burn addresses are reported as data only: they are not a claim that
anything loads, runs or is flashed there.

`csys`/`csro` remain **unsupported** (see below). The earlier OpenWrt `mkcsysimg` `CSYS` format is the
ADM/Edimax container and establishes nothing about these lowercase signatures.

## Primary sources and provenance

Both repositories are **unofficial public mirrors**. Neither is an official Realtek publication or an
authenticated release; the code is treated as vendor-authored by its own attribution only. Immutable commits
were resolved with `git ls-remote <repo> HEAD refs/heads/master` and the files read at that commit:

- Producer — `cgoder/openwrt_rtk` at `d237e45ee480ee7e75c80a4c61e1a335a0a77755`:
  [`rtk_openwrt_sdk/tools/rtk-tools/src/cvimg.c`](https://github.com/cgoder/openwrt_rtk/blob/d237e45ee480ee7e75c80a4c61e1a335a0a77755/rtk_openwrt_sdk/tools/rtk-tools/src/cvimg.c)
  (author line David Hsu, realtek.com.tw; `$Id: cvimg.c,v 1.4 2009/06/12`), SHA-256
  `266cf6f18abc97a464c0aad938688c2771f28a4041f0f07d97d99baa38370bd7`;
  [`src/apmib.h`](https://github.com/cgoder/openwrt_rtk/blob/d237e45ee480ee7e75c80a4c61e1a335a0a77755/rtk_openwrt_sdk/tools/rtk-tools/src/apmib.h),
  `4c7a5f4df1d861dbb12e0455d69c49bacf7ad12d8bf36b6868ab722b7941bbb0`;
  [`tools/rtk-tools/Makefile`](https://github.com/cgoder/openwrt_rtk/blob/d237e45ee480ee7e75c80a4c61e1a335a0a77755/rtk_openwrt_sdk/tools/rtk-tools/Makefile),
  `942b4a1c80ea38be08efe69f84c2a1a563d861cc6b5549468519a521370b8d2b`. (`src/Makefile` does not exist.)
- Independent consumer — `jameshilliard/WECB-VZ-GPL` at `adfad80b3144c788efb636d5acfcdd6ed91b3d79`:
  [`rtl819x/bootcode/boot/init/rtk.h`](https://github.com/jameshilliard/WECB-VZ-GPL/blob/adfad80b3144c788efb636d5acfcdd6ed91b3d79/rtl819x/bootcode/boot/init/rtk.h),
  `b93d203a8c3f0337c9ae56b80a55aa088406d27b6fbded6a18ef7562226730d9`;
  [`eth_tftpd.c`](https://github.com/jameshilliard/WECB-VZ-GPL/blob/adfad80b3144c788efb636d5acfcdd6ed91b3d79/rtl819x/bootcode/boot/init/eth_tftpd.c),
  `6e4159dddd32ee7a328e651c6de5a919b58c802d9e12012d15fe9ad3186236a1`.

Only these host-tool/header/bootcode source files were fetched; no SDK or firmware tree was cloned or
downloaded. Their flash, boot, TFTP and upgrade logic was read as data and not followed. Copies and hashes
are in `/Users/agfil/orca/campaign-evidence/realtek-cvimg-20261108/` (`MANIFEST.md`, `SHA256SUMS.sources`,
read-only `producer/cvimg.c` and `producer/apmib.h` with their original names). No vendor code was copied into
the product: `packages/core/src/realtek-image.ts` is an independently written, byte-only parser with no
dependency, built from the facts below.

## Field facts read from the code

`apmib.h` declares `IMG_HEADER_T` as `unsigned char signature[4]` followed by `unsigned int startAddr`,
`burnAddr`, `len`, under `__attribute__((packed))` (`__PACK__`, non-WIN32): **16 bytes**, no padding. The
consumer's `rtk.h` declares the same four fields with `unsigned long` (32-bit on the bootcode's target) and no
packing; 4 + 3×4 has no padding either, so both sides agree on 16 bytes.

The producer writes each word as `DWORD_SWAP(value)`, an unconditional byte reversal; on a little-endian build
host that stores the words **big-endian**. The consumer reads `Header.len` natively, with no swap, and its
alternative checksum branch composes 16-bit words as `y | x << 8`, i.e. big-endian. The supported subset is
therefore big-endian words; a build on a big-endian host would emit the reverse and is not covered.

Signature selection (`apmib.h`): `FW_HEADER = "cs6c"` and `FW_HEADER_WITH_ROOT = "cr6c"` under
`CONFIG_RTL_8196C || CONFIG_RTL_8198 || CONFIG_RTL_819XD || CONFIG_RTL_8196E || CONFIG_RTL_8881A`.
`main` copies `FW_HEADER` for `argv[1] == "linux"` and `FW_HEADER_WITH_ROOT` for `"linux-ro"`. The Makefile's
`Host/Compile` builds `cvimg.c` only with `-DCOMPACT_FILENAME_BUFFER -DHOME_GATEWAY` plus one of
`CONFIG_RTL_8196C`, `CONFIG_RTL_8196E`, `CONFIG_RTL_819XD` or `CONFIG_RTL_8881A` — all of which select these
two strings. The consumer's `rtk.h` defines the same `cs6c`/`cr6c` pair for its RTL8196C and RTL8198 bootcode
configurations. These macro names are build configuration, not a claim about the device a hit came from: the
same tool's `signature` option copies any four bytes from the command line.

Length and padding (ordinary `linux`/`linux-ro` path): `size = input + 16 + 2`, incremented by one if odd;
the input is placed after the header, the buffer is zero-filled, and `len = size - 16`. So
`len = input + 2 (+1 if input is odd)`: **always even and at least 2**; an empty input yields `len = 2`. The
16-bit checksum (`WORD_SWAP` of the two's-complement 16-bit word sum over the input bytes) is written at
`buf[size - 16 - 2]`, the **last two bytes of the declared region**; an odd input leaves one zero pad byte
just before it. `startAddr` and `burnAddr` are `sscanf("%x")` arguments, written unchanged with no range,
alignment or nonzero check. The consumer walks concatenated headers at `offset + 16 + len` and sums 16-bit
words over the `len` bytes after each header.

## Accepted contract

| Offset | Width | Field and acceptance |
| --- | --- | --- |
| 0 | 4 | Exactly `cs6c` (`linux`) or `cr6c` (`linux-ro`), case-sensitive. |
| 4 | 4 | `startAddr`, big-endian u32. Any value; reported as data only. |
| 8 | 4 | `burnAddr`, big-endian u32. Any value; reported as data only. |
| 12 | 4 | `len`, big-endian u32: even, ≥ 2, and `len <= remaining - 16`. |

The parser reads only these 16 bytes: constant time per hit, no payload loop. It checks the offset is a safe
integer inside the view, honours `Uint8Array.byteOffset`, compares `len` by subtraction (no 32-bit addition),
and accepts headers at any offset with any trailing bytes (which may be another image). A missing header or a
region past the end of the buffer is an explicit rejection, counted in `rejected`/`rejectedByRule` before the
listing cap like every other rule; earlier rules, the id set, LK and BootROM behaviour are unchanged.

Reported (optional metadata, existing record, nothing persisted is rewritten): `size` (16 + len),
`declaredLength`, `producerOption`, `startAddr`, `burnAddr`, `checksumOffset` and `checksum: 'not_verified'`.
The checksum's value is never read. **The checksum is present, not verified**; the strongest tier is
`consistent` (85), whatever the checksum holds. That is not integrity or authenticity.

Not supported, deliberately: `csys`/`csro` (selected only by the default branch, which the Makefile never
compiles, and the same letters as unrelated `CSYS` usage), `cs6b`/`cr6b`, `r6cr`/`root`, `boot`, `w6c*`/`web*`,
`allp`/`ALL1`/`ALL2` and `vmlinux`/`vmlinuxhdr` outputs. `fix_chksum` is not separately interpreted or validated:
its history cannot be recovered from a header-only structural match. Compatible even-length outputs may match
this ordinary layout, including outputs byte-identical to an ordinary image plus permitted trailing bytes.
Its rewritten `len` can place the actual old checksum elsewhere; `checksumOffset` reports the ordinary-layout
convention, not evidence of where every producer invocation wrote a checksum. An odd `len` is refused because
the ordinary path cannot write one; no impossible provenance rejection or ban on trailing bytes is implied.

## Validation

Focused tests were written first and observed failing (module missing; seven new scanner cases failing), then
passing. `realtek-image.test.ts` has 15 cases; `signatures.test.ts` gained 2 positive and 2 negative rubric cases
and 3 bounds suites. Core then passed in full, plus `check`, `build`, the NUL check and Biome on the four touched
files: 790 core tests, against 768 before.

### Actual generator

The two permitted images (`sha256:758b44ca…f82b42`, `sha256:df539ca2…d4d311`, both arm64) were inspected first
with `--network none --read-only` and contain **no C compiler** (only `arm-none-eabi-as`/`ld`). The coordinator
then got the official Zig 0.15.2 Linux aarch64 archive (49,471,996 bytes, SHA-256
`958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f`, matching the official index) into a sibling
evidence directory, without installing anything on the host or in an image. It compiled the **unmodified**
`cvimg.c`/`apmib.h` inside the `758b44ca` container (`--network none --read-only`, tmpfs only):

```sh
zig cc -target aarch64-linux-musl -O0 -DDEFFILEMODE=0666 \
  -DCOMPACT_FILENAME_BUFFER -DHOME_GATEWAY -DCONFIG_RTL_8196C /src/cvimg.c -o /out/cvimg-rtl8196c
```

The flags are the Makefile's `HOST_CFLAGS` and its first config. `-DDEFFILEMODE=0666` is the one portability
change, and it is a define, not a source patch: musl does not provide that glibc file-mode macro, which `main`
uses only to `chmod` its output (the first compile diagnostic is retained). The binary has SHA-256
`2545d9f1fd01142009b791edfb00bb79b19b9cf47fe5b66a410d23241621bd21`. Generator outputs were read as bytes and never
executed. No firmware was involved.

**Worker run** (this task, same binary and container; `/tool`, `/payloads` and `/scripts` read-only, only `/out`
writable): `linux` and `linux-ro` over inert payloads of 0, 1, 2, 3, 5, 6, 257 and 65537 bytes at `80500000 30000`,
plus `0 0` and `ffffffff ffffffff` on 3 bytes; the `signature` option writing `cs6c`, `csys` and `csro`; and
`root` as a control. That gives 24 outputs. `acceptance.mjs` read all of them and the coordinator's
5-byte canary through the compiled parser and scanner: **25 of 25 as expected**. All 20 `cs6c`/`cr6c` outputs
parse with the exact `len` formula, file size, addresses, payload bytes and zero pad on odd inputs. Each also
scans `consistent` at an odd embedded offset inside a sub-view with trailing bytes, and is rejected when one
byte short. `signature cs6c` is byte-identical to `linux`. `csys`, `csro` and `r6cr` are refused. The `root`
control ran out of its own buffer on a 5-byte input: it writes `fs_len` at payload offset 8 and segfaulted after
printing success. That is a producer defect on an out-of-scope path, kept in the log, not acceptance.

**Coordinator matrix** (its own commands, not counted as the worker's): 7 sizes × 2 options × 4 address pairs
= 56 outputs, plus 4 user-signature controls. `replay-coordinator.mjs` accepted **56 of 56** with exact
signature, `len`, size, addresses, checksum location and scanner tier. It refused all 4 controls. One evidence
defect was found: on case-insensitive APFS, `unsupported-csys.bin` and `unsupported-CSYS.bin` are one file. So
the `csys` row's recorded hash no longer matches the bytes on disk, which are the `CSYS` control. The worker
run's separate `signature-csys-p5.bin` covers the lowercase refusal.

Seven small outputs (five from the worker run, two from the coordinator) are embedded in the test as base64,
each with its SHA-256 asserted, together with the generator's own `csys` output as a refusal case. The other
fixtures (truncations, zero/odd/oversized `len`, little-endian fields, view offsets) are built from the facts
above, because no generator run emits them. The checksum is **located, never verified**. The odd-padding case
is the reason `bodyLength` is called that: `len - 2` cannot tell an odd input plus its zero pad from an even
input that ends in zero.

Scripts, payloads, outputs, logs and hashes are in `/Users/agfil/orca/campaign-evidence/realtek-cvimg-20261108/`
(`worker-scripts/`, `worker-generator/`, `coordinator-generator/`, `MANIFEST.md`). Not established: big-endian
build hosts, other configurations' signatures, `fix_chksum`/`vmlinux*` outputs, real firmware samples, and any
device, runtime or authenticity property.

Coordinator evidence correction: the original APFS collision is retained. A new offline run uses distinct
`coordinator-casefix/control-lower-csys.bin` and `control-upper-csys.bin`; both reproduce their original recorded
row hashes exactly (see `coordinator-casefix/adjudication.json`). The coordinator's compiled Node 22 parser/scanner
acceptance then passes all 56 supported outputs and four distinct controls, reading those corrected files for
the two collided names. It also checks embedded views, truncation and unchanged consistent tier after checksum
mutation. This repairs durable evidence, not product behavior; the original matrix is not described as hash-clean.

Independent review found and minimized that provenance ambiguity with the actual host tool: an empty ordinary
`linux` image followed by `de ad c0 de` stays byte-identical after `fix_chksum` (SHA-256
`eb8a0ec0dcafcd955a95b4f6e7041776c4f8f42d2315c3aa18ff7fc2062e7a8c`). The compatible header remains
consistent/85 with checksum unverified. The parser behavior is unchanged; the correction narrows the source
comment and documentation claim. Raw independent evidence is in the campaign state's
`review-realtek-ui-evidence/generator/minimal-fix-result.json`.
