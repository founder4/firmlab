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
| **7 · Dynamic analysis** | The booted service **is** driven now: `webprobe.ts` reproduces command injection (marker/nonce) and path traversal against the live daemon → `confirmed_in_emulation`. **Update-mechanism integrity** is answered statically (`updatepath.ts`, ISTG-FW, see §2). AFL++ fuzzing (file/stdin/network) under OS-primitive isolation. **The emulated guest CAN now be made to answer, and it was measured rather than asserted** (2026-08-10, `c37d122`): a third pass boots with `init=/bin/sh`, drives the serial console, reads the guest's own `iptables -L INPUT`, runs the firmware's own `/etc/rc.d/iptables-stop` and reads it again — WR940N **DROP → ACCEPT, guest 80 and 443 answering**, the corpus's first answering forwards. Armed by `FIRMLAB_EMU_CONSOLE`, off by default, reached only when the un-intervened passes had nothing answer, and it earns its OWN ledger row carrying its three `interventions`, never merged into the run's `open` or its reproducibility history. The WDR3600 makes the same transition and still answers nothing — `httpd` never bound there — which is the branch that says the firewall was not the cause. The earlier `FIRMLAB_EMU_REPAIR` route stays INERT for the reason below and is now a candidate for retirement: it appends to the end of `/etc/rc.d/rcS`, and on the WR940N `rcS` emits no `execve` after line 45 of 46, so the appended line is never reached. This row briefly claimed the opposite — the retraction and its evidence are in BACKLOG, and the lesson is that the result's own `ruleset.ran: false` was reporting honestly while the headline read from the port list instead. Open: auth-bypass / default-creds / POST-body injection; protocol-aware service testing (MQTT/CoAP); **driving a web probe inside the boot's live window**, which is now the blocking gap rather than a hypothetical one. U-Boot posture is read from the env, never interacted with on a live console. | ◐ |
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

**Two lists delivered.** The 2026-07-21 list of seven absent techniques shipped six inside the week
(`webprobe`, `fwhunt` + `chipsec`, `symreach`, `updatepath`, `funcdiff`, `uboot`); only advanced fuzzing survived.
Its successor, written 2026-07-28, has now also had **three of its nine items delivered** — and the way they were
delivered is the reason this list is re-derived rather than edited:

- **#1 network inference** was not a gap. Measured 2026-07-30: `inferGuestNetwork` was already pure, exported and
  running two passes (observe → reach). The real blocker was a **boot-time intervention in the guest**, which the
  backlog had recorded and this list had not, and it is now wired. **CORRECTED the same day: the intervention is
  INERT and the reachable-service result attributed to it has been retracted.** The line is written into the booted
  image and `rcS` never reaches it — the kernel's `execve` trace shows `rcS` stopping at line 45 of 46, with zero
  traces of `ping`, `iptables-save` or `iptables-stop` and none of the three markers. The unrepaired control got one
  line FURTHER, so the ports that opened on the repaired boot were nondeterminism, not the repair. See BACKLOG.
- **#2 the bounded budgets** — all three caps fixed (`e8b23c0`, `22a7961`, and the probe rank enabled 2026-07-29
  after measuring it across the corpus). This item was already stale when it was written down as "cheapest value in
  the ledger".
- **#4 a general rule lane** — that is `yarascan`, which has a route, a reader since 2026-07-30, and a real
  yara 4.2.3 in the deployed image. What remains is not the lane but its RULES (below as #2).

The pattern across all three: **the entry named a technique and the actual gap was one layer down** — already built
but unwired, or built and unmeasured, or built and unreadable. That is what shifts the ordering rule below. Value ÷
effort still, but "effort" now weights *finding out what is actually true of the thing* ahead of building, because on
this codebase that step has repeatedly been the whole task.

1. **The corpus is the binding constraint, not the technique — and this is the new #1.** Several built and validated
   capabilities have almost no evidence behind them, and each was discovered separately before the pattern was
   named: **no UEFI image at all**, so every `chipsec`/`fwhunt` branch is tested against fixtures and the whole
   posture reader has never met a vendor BIOS; **2 of 2007 binaries triaged**, so the hardening columns are
   honest-but-blank on 2005 rows; **no yara rule corpus**, so the rule lane reports `no_corpus` on every image; and
   the egress observation found the corpus **barely talks**, which is the finding that should decide the
   interception work rather than a preference. Acquiring three or four images that exercise these — a real UEFI
   dump, something chatty, something with a vendor NVRAM store — buys more than any provider on this list, because
   it converts capabilities that can only report their own limits into capabilities that can answer.
2. **A yara rule corpus this deployment can actually run.** The engine is installed and the reader exists; FirmLab
   ships no signatures **by design**, so "yara is installed" and "this deployment can answer" stay two facts. The
   gap is that nothing tells an operator where to get a corpus, and the honest fix is the FwHunt shape: pin a public
   rule set to a ref, report the denominator (`rulesDeclared`/`rulesApplied`/`rulesLost`), and attribute a match to
   the rule and its author rather than restating it as FirmLab's verdict.
3. **Make the guest repair reach the guest.** Re-derived 2026-07-30 after retracting the claim that it worked:
   the repair appends to the END of `/etc/rc.d/rcS` and on the WR940N `rcS` emits no `execve` after line 45 of 46, so
   nothing appended there is ever reached. Two questions, in order: why `rcS` stops one line short (the guest lives on
   to 95 s of kernel time with `httpd` running, so `rcS` died and the guest did not), and where an intervention CAN be
   staged that the boot actually executes — `/etc/inittab`, a `preInit` ahead of `rcS`, or the kernel command line are
   the candidates firmadyne/FirmAE use. Still the cheapest high-value item, and still not a new technique.
4. **Provider results that exist and cannot be read.** Every panel reads the result of the job IT launched, so a
   chipsec, renode, webprobe, decompile or kernel-posture result sitting in SQLite vanishes from the screen on
   reload. One hydration pattern at ~5 call sites. The same "the data exists and nobody can read it" class as the
   five capabilities closed on 2026-07-30 — which took an afternoon and turned out to be three states, not two.
5. **Kernel / module CVE surface.** Unchanged and still the clean asymmetry: userland gets SBOM → grype/OSV/NVD, the
   kernel gets posture only. A 2.6.31 kernel with a known-vulnerable driver set is a durable static finding.
6. **Interactive / introspectable emulation** — moved UP, because the repair unblocked it. `run_command_in_emulation`
   and service enumeration on a LIVE boot were gated on having a guest that answers, and now one does. Much of
   diagnosing a boot is running one command inside it, which is also how #3 gets settled.
7. **The sweep's ledger is still distorted by uClibc stubs.** `lib/libutil-0.9.30.so` and `lib/libmsglog.so` open the
   WDR3600's 45 listed candidates because `runnable` lets a shared object with an entry point through. The exposure
   key added 2026-07-30 repaired the HEAD of that list and did nothing for the tail. The real predicate is whether
   the entry point is a *program*.
8. **Cross-binary dataflow.** Extend the single-binary taint scaffold across binaries; W4 proves the shape within one.
9. **Advanced fuzzing.** cmplog/compcov magic-byte solving, a prebuilt guest-arch libdesock so the network harness
   works without `FIRMLAB_DESOCK`, and an input side for the fuzzer. Stateful/full-system fuzzing (Fuzzware/µEmu)
   remains the research frontier for the RTOS path.
10. **The remaining UEFI findings** — LogoFAIL image-parser class, SMM callout analysis (efiXplorer-class), SPI
    protected-range / BIOS-lock posture. Deliberately last: all of it is gated on #1, since none of it can be
    validated against a corpus with no UEFI image in it.
11. **Libraries are permanently unasked.** Filtering `.so` out of the reachability queue is right for the question as
    posed, and leaves a vulnerable library as a candidate nothing will ever settle. Loading the `.so` and starting
    symbolically from an exported function is a distinct rung, not a variant of this one.

**A policy debt, not a technique gap.** Two CVE sources with different evidentiary standards run on the same image:
grype (via a syft manifest) accepts `CVE-2016-2148` for busybox 1.18.4, while the curated `component-cve.ts` table
declines that exact CVE because NVD backs it with an open range and no enumerated CPE. Each row names its source, so
nothing contradicts anything, and the broader net is arguably right when a manifest exists — but which standard
applies is currently an accident of which provider ran, and should be a written decision.

**A second policy debt, surfaced 2026-07-30.** An amendment to an operator assertion records no author while a
withdrawal requires one, so a claim can be reworded by someone other than its author and the ledger attributes the
new wording to the original author. In the one surface whose entire purpose is provenance.

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
