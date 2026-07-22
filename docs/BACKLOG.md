# FirmLab — running backlog

Flat ledger of surfaced-but-unimplemented work. Append here whenever something is deferred; the prioritized
rationale lives in [`METHODOLOGY-GAPS.md`](METHODOLOGY-GAPS.md) and the phase status in the project memory.

Status: `▶ building` · `▢ planned` · `◐ partial` · `— out of scope`.

## Dynamic & runtime (FSTM 7–8) — the biggest gap
- ✅ **webprobe** — drives the booted service for command-injection (marker/nonce) + path-traversal (`/etc/passwd`); a reproduced hit → `confirmed_in_emulation`. `providers/webprobe.ts` + `/webprobe` route + panel. Validated against a real vulnerable HTTP server. _Follow-up: auth-bypass / default-creds checks, POST-body injection._
- ▢ **Interactive GDB in emulation** — breakpoints on unsafe fns (`memcpy`/`strcpy`), crash dumps (wairz `run_gdb_command`).
- ▢ **Symbolic reachability (angr)** — one question per taint lead: is the sink reachable from an input-controlled source? Turns `needs_runtime_reproduction` into a verdict without an exploit.
- ▢ **Cross-binary dataflow** — extend the single-binary taint scaffold (wairz `trace_dataflow` / `cross_binary_dataflow` / stack+global layout).
- ▢ **Library-level fuzz harness** — cross-compile a harness against an extracted `.so` to fuzz a specific exported fn; `patch_function_return` to stub a blocking check (wairz `harness-build`).
- ▢ **cmplog / compcov** — magic-byte solving for AFL++.
- ▢ **Prebuilt guest-arch libdesock** — so the network fuzz harness works out-of-the-box, not only with `FIRMLAB_DESOCK`.

## UEFI / BIOS deep analysis
- ✅ **chipsec Secure Boot / NVRAM posture** — offline NVRAM variable enumeration + SecureBoot/SetupMode/CustomMode reading + documented test-key detection (DO NOT TRUST / Snakeoil / AMI Test), all from `uefi decode`'s `nvram_*.nvram.lst`. Honest degradation: a state not among the extractable vars → `unknown`, never assumed secure. Validated in-container on real OVMF VARS (chipsec 1.13.16 surfaces only CustomMode from the OVMF auth-store, so the posture honestly reports the rest `unknown`; real vendor firmware extracts the full set). `providers/chipsec.ts` (`parseNvramVariables` / `interpretSecureBoot` / `detectTestKey` / `secureBootFindings`, unit-tested).
- ▢ **Curated `FIRMLAB_UEFI_IOC` feed / FwHunt integration** — advanced implants (LoJax/MoonBounce/CosmicStrand/BlackLotus) are NOT reliably GUID-detectable; FwHunt deliberately uses code-pattern (esil/hex_strings) rules to avoid false positives, and there are no stable public file-GUIDs for these families. So do NOT ship a hand-guessed GUID feed — the honest path is integrating `fwhunt-scan` (opt-in, like Ghidra/AFL++) to run real FwHunt rules against carved modules. The existing `FIRMLAB_UEFI_IOC` GUID/name hook stays for operator-supplied IOCs.
- ▢ **LogoFAIL image-parser bug class** + SMM callout analysis (efiXplorer-class).
- ▢ **SPI protected-range / BIOS-lock posture.**

## Static analysis (FSTM 3–5)
- ✅ **Rootfs security audit** (firmwalker/FACT-class) — `providers/fsaudit.ts`: weak/empty/legacy creds, extra UID-0, init-spawned root shells / telnetd, permissive ssh/telnet/ftp, notable key material (hashes redacted).
- ✅ **Certificate analysis** — `providers/certs.ts`: embedded X.509 via Node crypto — expired, weak RSA, test/self-signed, embedded CA.
- ✅ **Component dependency map** — `providers/compmap.ts`: rootfs ELF → DT_NEEDED graph (rabin2; unresolved + orphans surfaced).
- ✅ **U-Boot / bootloader** — `providers/uboot.ts`: decode the env + audit posture (init=/bin/sh, interruptible autoboot, net-boot, serial console).

## Comparison / n-day
- ▢ **Function-level decompilation diff** (BinDiff/Diaphora-style) to localize a patched vuln (wairz `diff_decompilation`).
- ▢ **Kernel module (.ko) CVE surface** — correlate kernel/modules to CVEs beyond userland SBOM.

## RTOS / bare-metal
- ✅ **RTOS blob analysis** — `providers/rtos.ts`: Cortex-M vector table, base-address recovery, flash/RAM memory map, RTOS-kernel detection. (Task enumeration = a deeper follow-up.)
- ▢ **Peripheral / MMIO fuzzing** (Fuzzware / µEmu / P2IM) — exercise the HAL, not just boot.
- ▢ **RTOS task enumeration** — walk pxCurrentTCB/thread lists (deeper than the current static blob analysis).

## Emulation UX
- ✅ **Service enumeration** — `providers/servicemap.ts`: statically map the network daemons the rootfs starts (inittab/inetd/SysV/systemd) = boot-time attack surface.
- ✅ **Saved emulation presets** — `routes/presets.ts` + `emulation_preset` store table + `PresetsPanel`: save/run/delete named emulation configs.
- ▢ **Interactive/introspectable emulation** — `run_command_in_emulation`, self-diagnostics (`diagnose_emulation_environment`) on a LIVE boot (service-enum above is static).

## Recon & acquisition
- ✅ **FCC-ID lookup** — `providers/fcc.ts`: extract FCC IDs + link to public filings (fccid.io + FCC OET). Schematics/changelog lookup still open.
- ▢ **Phase-6 Capture** — OTA interception & carving from a live update (designed, `CAPTURE-DESIGN.md`).
- ▢ **Live-device UART bridge** — host-side serial → containerized backend (wairz UART bridge). Software foothold into hardware.

## External intelligence
- ▢ **Vendor-PSIRT / CNA sources** — no single free API; per-vendor adapters.
- ▢ **Hardened egress** — proxy / slirp4netns for the research allowlist.
- ▢ **Corpus OSV/NVD/KEV cache** — reproducibility + ToS-friendly, avoid re-querying.

## Reporting & integration
- ▢ **PDF export** of reports.
- ▢ **External MCP tool surface** — expose FirmLab's providers as MCP tools so any agent (Claude Code/Desktop, Cursor…) can drive the workbench (wairz is MCP-first). Strategic; providers are already clean seams.

## Autonomous workers — the *opacidad* section (see [`AUTONOMOUS-WORKERS.md`](AUTONOMOUS-WORKERS.md))
Surfaced by the two-pass app-vs-autonomous experiment (15 firmwares). Ordered by payoff; §refs into the design doc.
- ✅ **W0 · Triage/identity worker** — entropy-gated, device-class-aware image identity in `@firmlab/core` (`structure.ts inferIdentity` + `signatures.ts` esp-parttable/picobin recognizers + `mcu.ts parsePicobin`). Ordered class decision: `esp-parttable@0x8000→esp-soc` (arch from the ESP image-header `chip_id` — authoritative Xtensa-vs-RISC-V), `PICOBIN→baremetal` (ISA from the IMAGE_TYPE item, never the chip name), `UEFI→uefi-bios`, `FIT(dtb@0)+UBI→openwrt-fit-ubi`, strong-fs/uimage→`embedded-linux`, **whole-image entropy gate→`encrypted`** (before any 2-byte magic), corroborated JFFS2 node stream (≥4 valid node types)→`embedded-linux`. Kills the jffs2 2-byte false-positive. `FirmwareClass` gained the 4 new classes; `Architecture` gained `xtensa`; `ImageIdentity.classRationale` carries the honest "why / not Linux" line; preflight routes the new classes to `static-only`. **Validated on the real corpus: all 6 classes correct.** _Follow-up: precise ESP arch/app inventory belongs to W6; per-class UI banner still open (see below)._
- ✅ **W1 · Extraction worker** — recursive, format-graph carver in `apps/api/src/providers/carve.ts` (pure, unit-tested): `parseFitImages` (FDT walk → sub-image data ranges), `parseUbiVolumes` (PEB-size detect + per-volume LEB reassembly + names from the layout volume, **skips the empty overlay instead of aborting**), `pickRootfsVolume` (largest SquashFS, never `wifi_fw`), `planCarve` (FIT→UBI→SquashFS loop + step trace). `runRecursiveCarve` extracts via `unsquashfs`/`sasquatch`, degrading honestly (a carved-but-unextracted volume is a real result, never "0 files"). `extract.ts` routes `openwrt-fit-ubi` here + falls back when binwalk finds no rootfs; `ExtractResult.carveTrace` is the chain-of-evidence. **Validated on the real 111 MB GL.iNet FIT: selects `ubi_rootfs` (97 MB SquashFS) out of [wifi_fw, kernel, ubi_rootfs].** _Follow-up: the `unsquashfs` tail needs an in-container run to confirm the 7553-inode extraction; add cpio/jffs2/ubifs terminal-format handlers + ESP partition carve._
- ✅ **W9 · Orchestrator (opacity controller)** — `opacidad.ts` (+ pure `opacidad-plan.ts` / `opacidad-narrative.ts`, unit-tested) + `routes/opacidad.ts` + `OpacidadPanel` on a new "Autonomous scan" section. From W0's class it plans the ordered worker chain, runs the EXISTING providers feeding W1's rootfs forward, syncs findings under each route's source, and composes the reasoning trace (findings summary + `source→sink→privilege` attack path + honest gaps). Narrative is deterministic by default, LLM-phrased when `FIRMLAB_AGENT` is on (reorganizes real facts, never invents). Honest by construction: not-built deep workers (W6/W8/W4) → `not-built`, rootfs-less stage → `skipped`, absent tool → `degraded`; "0 findings" is never "clean". **Validated end-to-end on the real corpus** (DVRF Linux chain with certs/uboot/fcc on real bytes; GL.iNet W1 carve running inside W9 on the real 111 MB FIT down to the 97 MB SquashFS; ESP32→W6 not-built). _Follow-up: LLM-narrative validated only offline; re-plan on a new lead (currently a fixed per-class DAG) is the next depth._
- ✅ **W6 · ESP/IoT-SoC worker** — `apps/api/src/providers/esp.ts` (pure, unit-tested): `parsePartitionTable` (0xAA50 entries @0x8000 → app/ota/nvs/spiffs/coredump inventory), `parseNvsRegion` (4096-byte NVS pages → 32-byte `ns/type/span/crc/key/data` entries, multi-span blob reassembly, **entry-state bitmap** written/erased + superseded-duplicate detection, blob_data/blob_idx pairing), `assessSecurePosture` (Flash-Enc/Secure-Boot/anti-rollback inferred from a plaintext app image, honest `unknown` when indeterminate). `analyzeEsp` composes → `critical` NVS key material (full value in evidence, redacted title), `high` stale/erased-recoverable entries, `high` OFF posture, `info` partition inventory. Wired into W9 (`provider:'esp'`, `esp-soc` → built). **Validated on the real ESP32 dump: recovers the exact 32-byte signing key `98a39f0b…8877e893` from NVS ns=4 `privkey` blob_data, the erased credential lineage `aaronf→aaron→founder3→founder4`, and Flash-Enc/Secure-Boot/anti-rollback OFF.** _Follow-up: `nvs_keys`-encrypted NVS, coredump parsing, live eFuse reads for definitive posture._
- ▢ **W7 · Bare-metal/RTOS worker** — vector table + **load-base recovery** + decode-routine/flag extraction (solved the RP2040 CTF; app saw 0 findings).
- ✅ **W8 · Encrypted-blob worker** — `apps/api/src/providers/encrypted.ts` (pure, unit-tested): `parseOtaHeader` (big-endian length field, plaintext ASCII tags, framed `AA55…16…55AA` IV block, ciphertext-body offset — each degrades honestly to null on an unframed blob), `classifyCipher` (16-byte IV ⇒ 128-bit block ⇒ AES; high-entropy body + no repeated 16-byte blocks + IV ⇒ CBC/CTR; repeated blocks ⇒ ECB; reuses core `windowEntropy`). `analyzeEncrypted` → `high`/`static_confirmed` cipher diagnosis (IV in evidence), `high`/**`blocked_by_security`** "unrecoverable without the key" verdict with the key-recovery path named, `info` plaintext-metadata leak. Never a silent empty — even a headerless high-entropy blob gets the verdict. Wired into W9 (`provider:'encrypted'`, `encrypted` → built). **Validated on the real GE800 OTA: length 0x036212d9, `fw-type:Cloud`, the exact 16-byte IV `4c5e831f…8bf7da1` @ 0x116, body entropy 8.00, AES-128 CBC/CTR — matching the §7.5 headline.** _Follow-up: known-plaintext crib detection; bootloader-key extraction is Phase-6 capture._
- ▢ **W4 · Web attack-surface worker** — enumerate rpcd/oui-httpd/luci/cgi handlers, resolve validators/ACLs/`no-auth-methods`, **taint web-param→uci→`os.execute`/`io.popen`/`sed` sinks**, model config-restore→uci bypass. (Found the GL.iNet Tor root-RCE + WR940N httpd cmdi.)
- ▢ **W2 component-fingerprint CVE** — SBOM over **bundled/statically-linked components** (pppd, Go modules) not just the package manifest → the pppd CVE-2020-8597 pre-auth RCE the app missed on WR940N (0 CVEs).
- ▢ **W3 secret extraction + offline cracking** — parse device stores (NVS/nvram/shadow) + FP-triage (minisign pubkeys, placeholders) + hashcat on `/etc/shadow`. (root:sohoadmin, nvram admin/admin.)
- ▢ **UI: honest-degradation banner** — "0 findings" must be distinguishable from "pipeline never reached rootfs / class not applicable"; per-class "what can I even run" up front.

## Deployment — build architecture
- ▢ **Invert the image layering** — `Dockerfile.firmware` is `FROM firmlab:latest` (tools layered ON TOP of the app), so ANY app-code change rebuilds ALL heavy tool layers (incl. the ~20-min AFL++ QEMU compile). Restructure to a `firmlab-tools` base (tools only) + the app copied on top, so app changes are a fast final layer. Big win for iteration speed.

## Deployment — tool-recipe fixes (ALL RESOLVED 2026-07-21)
- ✅ **libnvram cross-build** — missing target libc headers; add `libc6-dev-{mipsel,mips,armel,arm64}-cross`. All 4 guest `.so` build + present in deploy. Unlocks chroot-service.
- ✅ **firmadyne kernels** — the raw-repo path 404s; kernels live in GitHub Releases (`pr0v3rbs/FirmAE_kernel-v4.1` v1.0). 4 kernels present in deploy. Unlocks full-system.
- ✅ **Ghidra** — two bugs: (a) `api.github.com/releases/latest` was rate-limited mid-build → pin a DIRECT release URL; (b) Debian bookworm has no JDK 21 (Ghidra 12.x needs it) → fetch a portable Temurin JDK 21 from Adoptium. Also fixed the app detection (`tools.ts` ran the JVM with a 4s probe timeout → reported absent → refused to run; now detected by PATH existence).
- All six heavy tools (chipsec, Renode, AFL++, libnvram, firmadyne kernels, Ghidra) now install + activate in the deploy.

## Out of scope (by design / hardware)
- — Weaponized exploitation (ROP / shellcode / PoC) — FirmLab proves reachability + drafts disclosure, no PoCs.
- — JTAG/SWD/SPI extraction, chip-off, side-channel/glitching, BLE/ZigBee/Wi-Fi/SDR — hardware lab / Phase-6 dongle.
