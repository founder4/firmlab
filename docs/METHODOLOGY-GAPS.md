# FirmLab — methodology coverage & gap analysis

_Mapping FirmLab's automated pipeline against recognized firmware / IoT pentest methodologies, to find the
techniques and phases that neither the agents nor a manual workflow are covering yet._

**Two dates, deliberately separate.** The reference methodologies were retrieved **2026-07-21**; FirmLab's own
column was re-measured against the code on **2026-07-28**. They drifted apart in one week and the drift ran in
the direction that matters least visibly: this document had gone on listing as gaps six of the seven things §4
told the project to build, all of which had shipped. A gap analysis that under-reports its own tool is worse than
none, because it is the document consulted to decide what to build next — it was steering work at capabilities
that already existed. **Re-measure this file's FirmLab column whenever a §4 item lands**; the methodology column
only changes when OWASP does.

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
| **1 · Information gathering & recon** | Provenance fingerprint (`providers/provenance.ts`); OSINT — OSV + NVD + CISA KEV + security.txt (`research/*`); **FCC-ID extraction + public-filing links** (`providers/fcc.ts`); the **device tree** read as the firmware's own statement of the hardware it expects (`providers/devicetree.ts`), which is better evidence than the heuristic MCU fingerprint. Schematics / changelog lookup off the FCC filing still manual. | ✅ |
| **2 · Obtaining firmware** | Manual upload, **plus the whole Capture lane** (`FIRMLAB_CAPTURE`, legs 6.0–6.6): LAN discovery, mitmproxy OTA interception, ARP-spoof positioning, a LAN capture agent, BLE Nordic-DFU and Zigbee OTA-cluster reassembly, capturability preflight, and auto-ingest through the normal upload intake with a provenance row. No pull-from-vendor and no update-endpoint discovery. | ✅ |
| **3 · Analyzing firmware** | Entropy profile, signature map, structure ribbon, class/arch identity, MCU fingerprint (`@firmlab/core`). Strong. | ✅ |
| **4 · Extracting the filesystem** | binwalk + squashfs/jffs2/ubifs/cramfs/cpio (`providers/extract.ts`), a **second-pass recovery** for the blobs binwalk leaves (`extract-recover.ts`), and a **diagnosis** that separates a damaged image from a missing extractor (`extract-diagnose.ts`). binwalk v2 is still the only carver. | ✅ |
| **5 · Analyzing filesystem contents** | Secrets classifier, gitleaks, SBOM (syft) + CVE (grype/OSV/NVD/KEV), binary hardening, Ghidra triage — **plus** the firmwalker/FACT-class misconfiguration audit (`fsaudit.ts`), certificate analysis (`certs.ts`), the DT_NEEDED component graph (`compmap.ts`), U-Boot environment posture (`uboot.ts`), **kernel posture** (`kernelposture.ts`), and web-handler taint surfaced as first-class findings (`webtaint.ts`, W4). | ✅ |
| **6 · Emulating firmware** | Full ladder: qemu-user → chroot+libnvram → **full-system (firmadyne), which boots real firmware** → Renode (RTOS) → chipsec (UEFI, offline). Forwarded ports are read from the firmware's own config (`portmap.ts`) and probed **in the protocol each port speaks** (TLS handshake for HTTPS; listen, don't speak, for SSH/telnet). Best-in-class here. | ✅ |
| **7 · Dynamic analysis** | The booted service **is** driven now: `webprobe.ts` reproduces command injection (marker/nonce) and path traversal against the live daemon → `confirmed_in_emulation`. **Update-mechanism integrity** is answered statically (`updatepath.ts`, ISTG-FW, see §2). AFL++ fuzzing (file/stdin/network) under OS-primitive isolation. Open: auth-bypass / default-creds / POST-body injection; protocol-aware service testing (MQTT/CoAP); and **the emulated guest often has no reachable network at all** (see §3). U-Boot posture is read from the env, never interacted with on a live console. | ◐ |
| **8 · Runtime analysis** | **`symreach.ts`** (angr) answers one checkable question per sink — is the call site reachable from the entry point under symbolic argv/stdin — and **`dynprobe.ts`** breakpoints that exact call site under gdb-multiarch against qemu's gdbstub, feeds a cyclic pattern, and reads the registers at the fault: sink executed → crashed → *the faulting PC is input bytes at offset N*, self-evidencing. This produced the workbench's first `confirmed_in_emulation` memory-safety finding. Still absent: **dynamic instrumentation of the running firmware** (Frida — the only Frida here is an operator-side TLS-unpin template for Capture, a different thing), and stdin/multi-input search beyond one cyclic argv pattern. | ✅ / ◐ |
| **9 · Binary exploitation** | Not done — **by design**. FirmLab's honest boundary is *reachability & proof-state*, not weaponization (no ROP/shellcode/PoC). Worth keeping, but "exploitability confirmed" is a proof rung we stop short of. | ✗ (intentional) |

**Net:** the 2026-07-21 reading of this table — *"strong on 3–6, the real gaps are the back half of the dynamic
side"* — is no longer true, and the back half is where the year's work went. FSTM 7–8 now have real answers with
real proof states. What remains is narrower and of a different kind: on stage 7 the limit is **reach** (the guest
boots and configures only loopback, so a driven attack surface often has nothing to drive — §3), and on stage 8
it is **breadth of input channel** rather than absence of technique.

---

## 2. OWASP ISTG — component coverage

| ISTG category | FirmLab today | State |
|---|---|---|
| **FW · Firmware** (installed + update mechanism) | Installed-firmware analysis is thorough. **Update-mechanism testing shipped** (`providers/updatepath.ts`): does the update path authenticate what it flashes, is verification present in the updater binary, is there rollback protection — all three from bytes alone, and every answer scoped to what was read. Its own header states the refusal that matters: *"no verification symbols found" is never "the firmware is unsigned"*, since verification routinely lives in the bootloader, in mask ROM, in a stripped static blob, or server-side. | ✅ |
| **MEM · Memory** (readout protection, at-rest crypto, key extraction) | Embedded key material + effectively-public detection (`keys.ts`), unsalted-hash lookup against public tables (`hashlookup.ts`, never cracking). Encryption-at-rest inferred from entropy; **RDP/readout-protection posture still not assessed** (needs the chip/vector table). | ◐ |
| **INT · Internal interfaces** (JTAG/UART/SPI/I²C) | **✗** — hardware-bound. The one software-reachable foothold, a host-side UART bridge, is designed and unbuilt. |
| **PHY · Physical interfaces** (USB/Ethernet/DMA) | **✗** — hardware-bound. |
| **WRLS · Wireless** (Wi-Fi/BLE/ZigBee/SDR) | BLE (Nordic DFU) and Zigbee (OTA cluster 0x0019) **backends are built and validated** — reassembling a provided capture into the exact firmware needs no dongle, which is the half that can be tested anywhere. The live sniff (nRF52840 / CC2531) is the radio adapter and is hardware-gated. Wi-Fi/SDR untouched. | ◐ |
| **PROC · Processing** (side-channel, fault injection/glitching) | **✗** — lab hardware. |
| **DES · Data-exchange services** (MQTT/CoAP/network protos) | Network daemons can be fuzzed (desock) and driven over HTTP (`webprobe`), but **protocol-aware service testing is still not done**. | ◐ |
| **UI · User/companion app & cloud API** | **✗** — no companion-app / cloud-API assessment. |

**Net:** FW closed this week. The hardware categories (INT/PHY/PROC) stay legitimately out of scope for a pure-software
tool; WRLS moved from ✗ to ◐ because Capture's reassembly path is real and the remaining half is a dongle. The
**reachable software gaps** are now readout-protection posture (MEM), protocol-aware service testing (DES), and
companion-app/cloud (UI).

---

## 3. Firmware-class-specific gaps

**UEFI / BIOS** — `chipsec.ts` (FV/module inventory, offline NVRAM + Secure Boot posture + test-key detection) and
`fwhunt.ts` (rizin + fwhunt-scan + the pinned binarly-io corpus, 108 rules) both ship:

- ✅ **Threat-rule scanning** — FwHunt whole-image *and* per-module passes. The honesty work here was the
  denominator, not the numerator: a rule only runs when the image carries the volume it is scoped to, so every
  scan emits `rulesRun`/`rulesInCorpus`/`rulesNotApplicable` and a clean scan is titled *"which is not 'no
  implant'"*. FirmLab ships the scanner and the rules **as data and authors neither** — a match is attributed to
  the rule, never restated as FirmLab's own verdict.
- ✅ **Secure Boot / NVRAM posture** — SecureBoot/SetupMode/CustomMode read from `uefi decode`'s NVRAM lists, with
  documented test-key detection (DO NOT TRUST / Snakeoil / AMI Test). A state not among the extractable variables
  is `unknown`, never assumed secure.
- ✗ **LogoFAIL-class** image-parser bugs, **SW SMI handler** callouts (SMM `CommBuffer` not validated), and
  **SPI protected-range / BIOS-lock** posture — the remaining high-value UEFI findings, and now the whole of this
  category's technique gap.
- ◐ Three allocation defects the real runs exposed, all cheap: the module budget is spent **alphabetically**, the
  2 `target: bootloader` rules examine nothing (FirmLab does not carve an OS bootloader off an ESP), and chipsec's
  carve is discarded so fwhunt re-carves the same modules.

**RTOS / bare-metal** (Renode boots; `rtos.ts` recovers the vector table, base address and memory map):

- ✗ **Peripheral-model coverage & symbolic peripheral fuzzing** (µEmu / P2IM / Fuzzware) — booting is not the same
  as exercising the firmware against fuzzed MMIO. The Renode boot proves liveness; it does not fuzz the HAL.
- ✗ **Task enumeration** — walking `pxCurrentTCB` / thread lists, deeper than the current static blob analysis.

**Embedded-Linux** (the strong path):

- ✅ **Function-level n-day diffing** — `funcdiff.ts` pairs binaries by path, hash-compares, then fingerprints every
  function on both sides and matches symbols first, structure second; `funcdiff-text.ts` renders a unified diff of
  the decompiled bodies for the tightest changes. Two refusals carry the design: above a 40% recompile threshold
  the candidate list is **withheld** (a 400-entry list has no localizing power), and a changed function is reported
  as a fact, never as "the security patch".
- ✅ **Kernel posture** — `kernelposture.ts` reads the kernel's own security properties, and refuses to read the
  absence of a `CONFIG_` token as the absence of a feature (measured: the corpus's 2.6.x vendor kernels carry zero
  such tokens; an answer only becomes `off` when an anchor proves we were looking in the right place).
- ✗ **Kernel/module vuln surface** — the version and the `.ko`s are still not correlated to CVEs the way userland
  SBOM is. `kernelposture` says how the kernel is *configured*; nothing says which *known bugs* it carries.
- ✗ **The emulated guest has no network.** The firmware boots and its vendor init configures only loopback,
  because the LAN comes up through switch hardware `-M malta` does not emulate. Everything on the driven-attack-surface
  side of FSTM-7 is bounded by this, which is why it heads §4.

---

## 4. The gaps worth building (prioritized, software-reachable)

**The 2026-07-21 list is delivered.** Six of its seven items shipped inside the week, each with in-container
validation on real bytes recorded in `BACKLOG.md`: ① drive the emulated attack surface → `webprobe.ts`;
② UEFI threat-rule + Secure Boot → `fwhunt.ts` + `chipsec.ts`; ③ symbolic reachability → `symreach.ts`;
④ update-mechanism integrity → `updatepath.ts`; ⑤ function-level diffing → `funcdiff.ts`; ⑥ U-Boot → `uboot.ts`.
Only ⑦ (advanced fuzzing) survives, below as #7.

What follows is re-derived from what is actually open, same ordering rule — value ÷ effort, every item keeping the
proof-state discipline. Note the shift in *kind*: the old list was seven absent techniques, and half of this one is
capabilities that work spending their budget on the wrong questions.

1. **Network inference, the way firmadyne/FirmAE do it.** The last gap on the emulation ladder, and it gates more
   than itself: `webprobe`, service enumeration and any protocol-aware testing all need a reachable daemon, and
   today they often have none. The data is already captured — the firmadyne kernels trace every `execve`, so the
   console carries the interfaces and addresses the firmware *tries* to configure. Two-pass: observe what it wants,
   re-run with a NIC/VLAN that matches. Until then `confirmed_full_system` honestly means the system booted.
2. **Spend the bounded budgets on the right axis.** Three caps allocate by a property that is not the one that
   matters, and all three are ranking changes over machinery that already works: the finding cap is
   **severity-blind** (30 of 60 slots to `info` sinks while 76 `medium` overflow candidates drop); the probe rank
   measures **answerability, not interest** (DVRF's budget went to 4 KB samba helpers while `stack_bof_01`, the one
   binary known to crash, waited behind them); the UEFI module budget is spent **alphabetically**. Cheapest value
   in the ledger.
3. **Kernel / module CVE surface.** Close the asymmetry in §3: userland gets SBOM → grype/OSV/NVD, the kernel gets
   posture only. A 2.6.31 kernel with a known-vulnerable driver set is a durable static finding.
4. **A general rule lane over the rootfs.** `fsaudit` covers the classic firmwalker checklist, but there is no way
   to run an arbitrary rule set over an extraction — every question the audit does not already ask has to become a
   provider. _Content search, the other half this item carried until 2026-07-28, shipped that day as
   `providers/fssearch.ts` with a web surface and an MCP tool; the entry is left narrowed rather than deleted so the
   remaining half stays visible._
5. **Cross-binary dataflow.** Extend the single-binary taint scaffold to follow data across binaries; W4 already
   proves the shape is right within one.
6. **Interactive / introspectable emulation.** `run_command_in_emulation`, service enumeration on a LIVE boot,
   `diagnose_emulation_environment`. Pairs directly with #1 — much of diagnosing a boot is running one command in it.
7. **Advanced fuzzing** (the survivor). cmplog/compcov magic-byte solving, a prebuilt guest-arch **libdesock** so the
   network harness works without `FIRMLAB_DESOCK`, and an input side for the fuzzer. Stateful/full-system firmware
   fuzzing (Fuzzware/µEmu) remains the research frontier for the RTOS path.
8. **The remaining UEFI findings** — LogoFAIL image-parser class, SMM callout analysis (efiXplorer-class), SPI
   protected-range / BIOS-lock posture.
9. **Libraries are permanently unasked.** Filtering `.so` out of the reachability queue is right for the question as
   posed, and leaves a vulnerable library as a candidate nothing will ever settle. Loading the `.so` and starting
   symbolically from an exported function is a distinct rung, not a variant of this one.

**A policy debt, not a technique gap.** Two CVE sources with different evidentiary standards run on the same image:
grype (via a syft manifest) accepts `CVE-2016-2148` for busybox 1.18.4, while the curated `component-cve.ts` table
declines that exact CVE because NVD backs it with an open range and no enumerated CPE. Each row names its source, so
nothing contradicts anything, and the broader net is arguably right when a manifest exists — but which standard
applies is currently an accident of which provider ran, and should be a written decision.

**Explicitly out of pure-software scope** (belongs to Phase-6 Capture with the right dongle, or a hardware lab):
JTAG/UART/SPI extraction & chip-off (ISTG-INT/MEM), USB/DMA (PHY), Wi-Fi/SDR (WRLS), side-channel & glitching (PROC).
Weaponized exploitation (FSTM-9) stays out by design — FirmLab proves reachability and drafts disclosure; it does not
ship PoCs.

---

## 5. What FirmLab already does that most manual workflows don't

Worth stating, so the gaps read in context: cross-image **corpus reachability priors**, an enforced **proof-state
machine** (static → emulation → full-system, never conflating sandbox with device), **coverage as a first-class
result** (an empty findings list carries the sentence saying which stages ran and what the count does not cover),
**OS-primitive session isolation** for auto-run without a nested container, a **cited external-intel** track with an
egress ledger, and a **filesystem browser** so the operator can open the bytes a finding cites instead of trusting
it — which exists because one backlog entry had to be withdrawn after being written from a filename without opening
the file. The gaps above are about *breadth of technique*; the discipline is already ahead of a typical manual
assessment.

---

## 6. Ideas from peer tooling (wairz review)

Reviewing **wairz** (a mature MCP-first firmware workbench: 90+ AI tools, PostgreSQL, Ghidra/QEMU/AFL++) surfaced
concrete mechanisms worth adopting. Re-checked 2026-07-28 — four have since been built:

- ✅ **MCP tool surface.** `apps/api/src/mcp/server.ts` exposes the workbench over stdio, with answers already shaped
  by their proof state and coverage (`mcp/format.ts`), so an external agent inherits the honesty contract rather than
  having to reconstruct it.
- ✅ **Deeper filesystem security analyzers** — `analyze_init_scripts` / `analyze_config_security` /
  `check_filesystem_permissions` / `analyze_certificate` / `extract_bootloader_env` / `get_component_map` landed as
  `fsaudit.ts`, `certs.ts`, `uboot.ts` and `compmap.ts`.
- ✅ **Concrete RTOS deep-analysis tools** — `detect_rtos_kernel` / `analyze_vector_table` / `recover_base_address` /
  `analyze_memory_map` are `rtos.ts`. `enumerate_rtos_tasks` is the one still open (§3).
- ✅ **The runtime half** — `run_gdb_command` is `dynprobe.ts`, driving gdb-multiarch against qemu's gdbstub.
- ▢ **Library/function-level fuzz harness.** Cross-compile a harness linked against an extracted `.so` to fuzz a
  specific exported function, plus `patch_function_return` to stub a blocking check (checksum/auth gate) so the
  fuzzer reaches the target. Deeper than the current per-class harnesses; §4 #7 and #9 both point here.
- ▢ **Interactive emulation + self-diagnostics.** `run_command_in_emulation`, `enumerate_emulation_services` on a live
  boot, `diagnose_emulation_environment` / `troubleshoot_emulation` — §4 #6.
- ▢ **Cross-binary dataflow** (`trace_dataflow`, `cross_binary_dataflow`, `get_stack_layout`, `get_global_layout`)
  — §4 #5.
- ▢ **Live-device UART bridge.** A host-side serial bridge lets the containerized backend reach a physical device's
  UART console — the pragmatic software-side foothold into hardware, and the only ISTG-INT item that is not lab work.
- ◐ **Kind-aware tool visibility.** Recipes are gated by device class already (`specsForClass`, which `coverage.ts`
  reads so the banner and the scan cannot disagree); formalizing per-kind capability visibility in the UI is the
  remaining tidy-up.
- ▢ **capa-style capability inventory** — what a binary *can do* is a different question from what is *wrong* with it,
  and FirmLab currently asks only the second.

Not adopting wholesale (different identity): wairz is MCP-first + Postgres/Redis + cloud (Fargate/Batch); FirmLab
stays local-first with its own proof-state agent and OS-primitive isolation. The *techniques* above transfer; the
architecture doesn't need to.

---

_Sources: OWASP FSTM & ISTG (owasp.org / scriptingxss.gitbook.io), Payatu ISTG guide, Binarly FwHunt & efiXplorer,
NorthSec UART/SPI/JTAG extraction, bare-metal firmware-fuzzing surveys (Fuzzware/µEmu/P2IM, STAFF). Methodologies
retrieved 2026-07-21; FirmLab's coverage column re-measured against the code 2026-07-28._
