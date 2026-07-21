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
- ▢ **Interactive/introspectable emulation** — `run_command_in_emulation`, `enumerate_emulation_services`, self-diagnostics (`diagnose_emulation_environment`).
- ▢ **Saved emulation presets.**

## Recon & acquisition
- ▢ **FCC-ID / schematics / changelog lookup** (recon enrichment).
- ▢ **Phase-6 Capture** — OTA interception & carving from a live update (designed, `CAPTURE-DESIGN.md`).
- ▢ **Live-device UART bridge** — host-side serial → containerized backend (wairz UART bridge). Software foothold into hardware.

## External intelligence
- ▢ **Vendor-PSIRT / CNA sources** — no single free API; per-vendor adapters.
- ▢ **Hardened egress** — proxy / slirp4netns for the research allowlist.
- ▢ **Corpus OSV/NVD/KEV cache** — reproducibility + ToS-friendly, avoid re-querying.

## Reporting & integration
- ▢ **PDF export** of reports.
- ▢ **External MCP tool surface** — expose FirmLab's providers as MCP tools so any agent (Claude Code/Desktop, Cursor…) can drive the workbench (wairz is MCP-first). Strategic; providers are already clean seams.

## Deployment — tool-recipe fixes (activated 2026-07-21; these 3 failed to install, degrade honestly)
- ▢ **Ghidra install** — the `api.github.com/releases/latest` grep for the download URL came back empty in the build (unauthenticated API rate-limit / asset-name drift). Pin a known Ghidra version URL or pass a GITHUB_TOKEN build-arg. (radare2 covers triage meanwhile.)
- ▢ **libnvram cross-build** — the firmadyne libnvram Makefile build failed under the arm64 host cross-compilers. Fix the CC/flags (or vendor a prebuilt per-arch `.so`). Unlocks the chroot-service rung.
- ▢ **firmadyne kernels** — the `pr0v3rbs/FirmAE/raw/master/binaries/<k>` URLs 404'd (repo layout changed). Find the current kernel asset URLs. Unlocks full-system boot.
- Note: chipsec + Renode + AFL++ DID activate successfully in the deploy.

## Out of scope (by design / hardware)
- — Weaponized exploitation (ROP / shellcode / PoC) — FirmLab proves reachability + drafts disclosure, no PoCs.
- — JTAG/SWD/SPI extraction, chip-off, side-channel/glitching, BLE/ZigBee/Wi-Fi/SDR — hardware lab / Phase-6 dongle.
