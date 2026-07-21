# FirmLab — methodology coverage & gap analysis

_Mapping FirmLab's automated pipeline against recognized firmware / IoT pentest methodologies, to find the
techniques and phases that neither the agents nor a manual workflow are covering yet._

Reference methodologies (reputable, widely used):

- **OWASP Firmware Security Testing Methodology (FSTM)** — 9 stages, the de-facto firmware assessment playbook.
  <https://scriptingxss.gitbook.io/firmware-security-testing-methodology>
- **OWASP IoT Security Testing Guide (ISTG)** — 8 component-based categories (hardware, wireless, firmware,
  services, interfaces, UI). <https://owasp.org/www-project-iot-security-testing-guide/>
- **OWASP IoT Security Verification Standard (ISVS)** — the "what to verify" companion to FSTM's "how".
- UEFI/BIOS ecosystem: Binarly **FwHunt** rules, **efiXplorer**/efiseek (Ghidra/IDA), UEFITool, CHIPSEC; known
  implant families (LoJax, MosaicRegressor, MoonBounce, CosmicStrand, BlackLotus) and **LogoFAIL**.
- Practitioner references: Payatu, Attify, Quarkslab, NCC Group, ONEKEY/EMBA, Eclypsium; academic firmware-fuzzing
  surveys (bare-metal fuzzing, STAFF stateful taint-assisted full-system fuzzing).

Legend: **✅ automated** (an agent/provider does it) · **◐ partial / manual** · **✗ gap** (neither automated nor
part of the current manual workflow).

---

## 1. OWASP FSTM — stage-by-stage coverage

| FSTM stage | FirmLab today | State |
|---|---|---|
| **1 · Information gathering & recon** | Provenance fingerprint (`providers/provenance.ts`: vendor/model/version/CN/banners); OSINT — OSV + NVD + CISA KEV + security.txt (`research/*`). FCC-ID / schematics / changelog lookup **not** done. | ◐ |
| **2 · Obtaining firmware** | Manual upload only. OTA interception + carving is **designed** (`docs/CAPTURE-DESIGN.md`, `FIRMLAB_CAPTURE`) but not built. No pull-from-vendor, no update-endpoint discovery. | ◐ |
| **3 · Analyzing firmware** | Entropy profile, signature map, structure ribbon, class/arch identity, MCU fingerprint (`@firmlab/core`). Strong. | ✅ |
| **4 · Extracting the filesystem** | binwalk + squashfs/jffs2/ubifs/cramfs/cpio extractors (`providers/extract.ts`). | ✅ |
| **5 · Analyzing filesystem contents** | Secrets classifier, gitleaks, SBOM (syft) + CVE (grype/OSV/NVD/KEV), binary hardening (checksec-equivalent via radare2), Ghidra triage. **No config-file heuristics à la firmwalker** beyond secrets; no binary **taint SAST surfaced as findings** (the scaffold exists in `agent/zeroday.ts` but isn't a first-class filesystem pass). | ✅ / ◐ |
| **6 · Emulating firmware** | Full ladder: qemu-user → chroot+libnvram → full-system (firmadyne) → Renode (RTOS) → chipsec (UEFI, offline). Best-in-class here. | ✅ |
| **7 · Dynamic analysis** | AFL++ fuzzing (file/stdin/network), auto-run under isolation, zero-day taint scaffold. **The emulated web UI / services are never driven** — no command-injection/authz/traversal/XXE testing of the booted daemon (no ZAP/commix/nuclei equivalent). No **update-mechanism** testing (signature/downgrade). No **bootloader** interaction (U-Boot env, `init=/bin/sh`). | ◐ |
| **8 · Runtime analysis** | Fuzzing crashes are reproduced, but there is **no debugger-driven runtime** (gdb breakpoints on `memcpy`/`strcpy`), **no dynamic instrumentation** (Frida), and **no symbolic execution** (angr/Triton) to prove reachability of a taint path. | ✗ |
| **9 · Binary exploitation** | Not done — **by design**. FirmLab's honest boundary is *reachability & proof-state*, not weaponization (no ROP/shellcode/PoC). Worth keeping, but "exploitability confirmed" is a proof rung we stop short of. | ✗ (intentional) |

**Net:** FirmLab is strong on FSTM 3–6 and the recon/OSINT half of 1. The real gaps are the **back half of the
dynamic side (7–8)**: actually *driving* the emulated attack surface, and runtime/symbolic techniques that turn a
static lead into a proven-reachable finding.

---

## 2. OWASP ISTG — component coverage

| ISTG category | FirmLab today | State |
|---|---|---|
| **FW · Firmware** (installed + update mechanism) | Installed-firmware analysis is thorough. **Update-mechanism testing (signature verification, downgrade/rollback protection) is absent.** | ◐ |
| **MEM · Memory** (readout protection, at-rest crypto, key extraction) | Embedded key material + effectively-public detection (`providers/keys.ts`). Encryption-at-rest is inferred from entropy but **RDP/readout-protection posture is not assessed** (needs the chip/vector table). | ◐ |
| **INT · Internal interfaces** (JTAG/UART/SPI/I²C) | **✗** — hardware-bound; out of a software workbench's reach (but see Capture below). |
| **PHY · Physical interfaces** (USB/Ethernet/DMA) | **✗** — hardware-bound. |
| **WRLS · Wireless** (Wi-Fi/BLE/ZigBee/SDR) | **✗ today**; radio capture backends (BLE/Zigbee dongles) are **designed** in Capture. |
| **PROC · Processing** (side-channel, fault injection/glitching) | **✗** — lab hardware. |
| **DES · Data-exchange services** (MQTT/CoAP/network protos) | Network daemons can be fuzzed (desock), but **protocol-aware service testing is not done.** | ◐ |
| **UI · User/companion app & cloud API** | **✗** — no companion-app / cloud-API assessment. |

**Net:** the hardware/radio categories (INT/PHY/WRLS/PROC) are legitimately out of scope for a pure-software tool;
Phase-6 Capture is the honest bridge (a dongle → a transport). The **reachable software gaps** are update-mechanism
integrity (FW), readout-protection posture (MEM), protocol-aware service testing (DES), and companion-app/cloud (UI).

---

## 3. Firmware-class-specific gaps

**UEFI / BIOS** (we just shipped `providers/chipsec.ts`: FV/module inventory + IOC-feed hook + embedded-app lead):

- **✗ Threat-rule scanning.** The industry approach is **FwHunt** (Binarly) YARA-like rules and **efiXplorer** SMM
  analysis — detect known implant families (LoJax, MosaicRegressor, MoonBounce, CosmicStrand, BlackLotus) and
  classes of bug, not just enumerate modules. Our `FIRMLAB_UEFI_IOC` hook should be **fed by a curated feed of
  these public families** (this also closes the "curated IOC feed" debt).
- **✗ Secure Boot / NVRAM posture** (SecureBoot/SetupMode, PK/KEK/db/dbx, **Microsoft test keys** = "DO NOT TRUST").
  chipsec exposes this offline; our provider parses modules but not the variable store yet.
- **✗ LogoFAIL-class** image-parser bugs, **SW SMI handler** callouts (SMM `CommBuffer` not validated), and
  **SPI protected-range/BIOS-lock** posture — the high-value UEFI findings.

**RTOS / bare-metal** (Renode works):

- **✗ Peripheral-model coverage & symbolic peripheral fuzzing** (µEmu / P2IM / Fuzzware style) — booting is not the
  same as exercising the firmware against fuzzed MMIO. Our Renode boot proves liveness; it doesn't fuzz the HAL.

**Embedded-Linux** (the strong path):

- **◐ Cross-version binary diffing for n-day** — we have image `diff.ts`, but not **BinDiff/BinExport-style
  function-level diffing** to localize a patched vuln between two firmware versions.
- **✗ Kernel/module vuln surface** — the kernel `.ko`s and version aren't correlated to CVEs the way userland SBOM is.

---

## 4. The gaps worth building (prioritized, software-reachable)

Ordered by value ÷ effort, each mapped to where it lands in the architecture. All keep the proof-state discipline
(a technique either *confirms* reachability or is honestly a *lead*).

1. **Drive the emulated attack surface (FSTM-7).** Once `chroot-service`/`full-system` boots a daemon, point a
   lightweight active scanner at it: templated checks for command injection, auth bypass, path traversal, and the
   classic router-CGI sinks — the natural upgrade of the taint scaffold from *static lead* → *reproduced in the
   sandbox* (`confirmed_in_emulation`). New `providers/webprobe.ts`, driven by agent node ②. **Highest value** —
   it's the missing half of what makes FirmLab's emulation ladder pay off.
2. **UEFI threat-rule + Secure Boot posture (chipsec++).** Ship a curated `FIRMLAB_UEFI_IOC` feed of public implant
   families and add offline Secure-Boot/NVRAM parsing + test-key detection. Reuses the chipsec provider; closes two
   debt items at once. Consider importing **FwHunt** rule GUIDs as the feed.
3. **Symbolic reachability (FSTM-8).** Wrap **angr** to answer one honest question per taint lead: *is the sink
   reachable from an input-controlled source?* Turns `needs_runtime_reproduction` into a defensible verdict without
   a full exploit. New opt-in `providers/symexec.ts`, gated like Ghidra/AFL++.
4. **Update-mechanism integrity (ISTG-FW).** Statically test the update path: is the image **signed**? is signature
   verification **present in the updater binary** (imports of verify routines)? is there **downgrade protection**?
   High-signal, fully static, no new heavy deps.
5. **Function-level n-day diffing.** Add BinExport/Diaphora-style function diffing to `diff.ts` so a two-version
   upload localizes the changed (likely-patched) function — the fastest route to an n-day.
6. **Bootloader/U-Boot analysis.** Parse the U-Boot environment, default `bootargs`, and unlocked consoles
   (`init=/bin/sh`, `bootdelay`, unauthenticated `mmc`/`tftp`) — a common, cheap, high-value finding.
7. **Advanced fuzzing.** cmplog/compcov (magic-byte solving) and a prebuilt guest-arch **libdesock** so the network
   harness works out-of-the-box (existing fuzzing debt). Stateful/full-system firmware fuzzing (Fuzzware/µEmu) is
   the research frontier for the RTOS path.

**Explicitly out of pure-software scope** (belongs to Phase-6 Capture with the right dongle, or a hardware lab):
JTAG/UART/SPI extraction & chip-off (ISTG-INT/MEM), USB/DMA (PHY), Wi-Fi/BLE/ZigBee/SDR (WRLS), side-channel &
glitching (PROC). Weaponized exploitation (FSTM-9) stays out by design — FirmLab proves reachability and drafts
disclosure; it does not ship PoCs.

---

## 5. What FirmLab already does that most manual workflows don't

Worth stating, so the gaps read in context: cross-image **corpus reachability priors**, an enforced
**proof-state machine** (static → emulation → full-system, never conflating sandbox with device), **OS-primitive
session isolation** for auto-run without a nested container, and a **cited external-intel** track with an egress
ledger. The gaps above are about *breadth of technique*; the discipline is already ahead of a typical manual
assessment.

---

## 6. Ideas from peer tooling (wairz review)

Reviewing **wairz** (a mature MCP-first firmware workbench: 90+ AI tools, PostgreSQL, Ghidra/QEMU/AFL++) surfaced
concrete mechanisms worth adopting — most reinforce the gaps above, a few are new:

- **MCP tool surface.** wairz exposes its analysis as ~90 MCP tools any external agent (Claude Code/Desktop, Cursor,
  Codex…) can drive, with dynamic project switching and `notifications/tools/list_changed` on context change.
  FirmLab has a strong *internal* agent but no *external* MCP surface — exposing the providers as MCP tools would let
  any agent operate the workbench. Strategic, and cheap given the providers are already clean seams.
- **Library/function-level fuzz harness.** Beyond whole-binary fuzzing, wairz **cross-compiles a harness linked
  against an extracted `.so`** to fuzz a specific exported function, plus `patch_function_return` to stub a blocking
  check (checksum/auth gate) so the fuzzer reaches the target. Deeper than our current per-class harnesses.
- **Concrete RTOS deep-analysis tools** (sharpens §3): `detect_rtos_kernel`, `enumerate_rtos_tasks`,
  `analyze_vector_table`, `recover_base_address`, `analyze_memory_map` — pyelftools/heuristics on the raw blob. This
  is the "task enumeration / base-address / memory-map" gap, made concrete.
- **Interactive emulation + self-diagnostics.** `run_command_in_emulation`, `enumerate_emulation_services`,
  `run_gdb_command`, and `diagnose_emulation_environment` / `troubleshoot_emulation` — the emulation isn't just
  booted, it's *driven and introspected*. Pairs with the FSTM-7/8 gaps (webprobe, GDB runtime).
- **Deeper filesystem security analyzers**: `analyze_init_scripts`, `analyze_config_security`,
  `check_filesystem_permissions`, `analyze_certificate`, `extract_bootloader_env`, `get_component_map` — the
  firmwalker/FACT-class heuristics + a bins/libs/scripts dependency graph. Several are cheap, high-signal static wins.
- **Cross-binary dataflow** (`trace_dataflow`, `cross_binary_dataflow`, `get_stack_layout`, `get_global_layout`) —
  extends our single-binary taint scaffold to follow data across binaries.
- **Live-device UART bridge.** A host-side serial bridge (TCP:9999) lets the containerized backend reach a physical
  device's UART console — a pragmatic, software-side foothold into hardware that fits Phase-6 Capture.
- **Kind-aware tool visibility.** Tools tagged `applies_to=(linux|rtos|unknown)`; the UI hides irrelevant ones. We
  gate recipes by class already — formalizing per-kind capability visibility (incl. the coverage checklist) is tidy.

Not adopting wholesale (different identity): wairz is MCP-first + Postgres/Redis + cloud (Fargate/Batch); FirmLab
stays local-first with its own proof-state agent and OS-primitive isolation. The *techniques* above transfer; the
architecture doesn't need to.

---

_Sources: OWASP FSTM & ISTG (owasp.org / scriptingxss.gitbook.io), Payatu ISTG guide, Binarly FwHunt & efiXplorer,
NorthSec UART/SPI/JTAG extraction, bare-metal firmware-fuzzing surveys (Fuzzware/µEmu/P2IM, STAFF). Retrieved
2026-07-21._
