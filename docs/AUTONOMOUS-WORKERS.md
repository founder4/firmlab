# FirmLab — Autonomous workers (the *opacidad* section)

_Design doc derived from a controlled two-pass experiment: every firmware in `~/Downloads/firmwares` was
analyzed **twice** — once through the app exactly as an operator drives the frontend (fixed provider pipeline),
and once by an autonomous AI agent given the raw container toolchain and **no** preset pipeline, free to plan,
extract, pivot and reason on technical merit. The delta between the two passes is the specification for a new
app section — **opacidad** — that launches 100 %-autonomous, AI-driven scans built from discrete **workers**
(à la Galert)._

Status of this doc: **design + evidence**. No provider code was changed by the experiment. Deferred build items
are mirrored into [`BACKLOG.md`](BACKLOG.md).

---

## 1. The experiment

- **Corpus:** 15 firmware images spanning the real class spectrum — standard Linux/MIPS (DVRF, TP-Link WR940N),
  modern aarch64 OpenWrt with a FIT/UBI container (GL.iNet BE3600), an encrypted vendor OTA (TP-Link Archer
  GE800 WiFi-7), an ESP32 SoC flash dump, and an RP2040 bare-metal binary (Pico CTF).
- **App pass:** identity on all 15 + the full deep provider chain (extract → sbom → fsaudit → certs → compmap →
  decompile → …) on a 6-image subset, driven through the frontend the way an operator would.
- **Autonomous pass:** 6 parallel agents, one per representative image, each with a shell into the tools
  container (binwalk, sasquatch, unsquashfs, jefferson, ubi_reader, radare2, Ghidra, syft/grype, gitleaks,
  qemu, chipsec…) and a single instruction: analyze correctly and autonomously, ignore any preset limitation,
  use your judgment. Each agent also wrote a "what a correct worker should do" section — those feed §5.

The point was never to grade the firmwares. It was to measure **how much signal the fixed pipeline leaves on the
table**, and to turn that gap into a worker taxonomy.

---

## 2. Head-to-head — app pass vs autonomous pass

| Firmware | Class (real) | App pass | Autonomous pass | Gap |
|---|---|---|---|---|
| **GL.iNet BE3600** | aarch64 OpenWrt 23.05, FIT→UBI→squashfs | **0 files extracted, 0 findings** | Full rootfs recovered via 4-stage carve; **Tor RPC `os.execute` → authenticated root RCE** (the real engagement vector); 408 CVEs (55 crit) incl. EOL tor 0.4.8.9 running as root; empty root shadow | **Total.** App gets nothing; autonomous gets the root-RCE + the whole CVE surface |
| **ESP32** flash dump | Xtensa LX6, ESP-IDF 5.5.2 | **`embedded-linux` / `jffs2` / 0 findings** (wrong class) | Partition table parsed; **32-byte private signing key extracted from NVS** (the device's entire trust anchor, plaintext + printed on UART); stale secrets recovered from erased NVS; Flash-Encryption OFF, Secure-Boot OFF, no anti-rollback → boot-hijack | **Total.** Catastrophic misclass + 0 findings vs full device compromise |
| **TP-Link WR940N** | MIPS Linux | 3 findings, **0 CVEs** | `root:sohoadmin` creds; **pppd CVE-2020-8597 pre-auth RCE** (component fingerprint); httpd command-injection sinks | Huge — missed creds, the pppd CVE, and the web cmdi |
| **DVRF** | MIPS Linux (intentionally vulnerable) | 24 findings (busybox CVEs + certs) | 6 exploitable pwnable binaries (the point of DVRF); `nvram admin/admin` | App got CVE breadth but **missed every actual pwnable** — no binary-level vuln discovery |
| **TP-Link Archer GE800** | Encrypted WiFi-7 OTA | Misclassified, silent extract failure | Correctly diagnosed **AES-128 CBC/CTR, IV @ 0x116, unrecoverable without the key** — stated honestly, with the key-recovery path named | App fails silently; autonomous gives a correct, actionable verdict |
| **Pico "RP2040" CTF** | **RP2350 / RISC-V Hazard3** bare-metal (NOT RP2040/ARM) | **`embedded-linux` / `jffs2` / 0 findings** (wrong class) | Detected PICOBIN `IMAGE_DEF` → RISC-V EXE, corrected the copy-to-RAM load base, reversed the 3-table `ror+sub+xor` `decode()`, **extracted all 6 flags** + UART creds `cR4p!/cR4p!` | App can't touch bare-metal **and would disassemble RISC-V as ARM garbage**; autonomous solved the CTF |

**One-line summary:** on 4 of 6 images the app pass produced *either nothing or a wrong class*, while the
autonomous pass produced the headline finding a human assessor would actually report.

---

## 3. The app's structural limitations

### 3.1 What the app got wrong (results it *did* return, incorrectly)

1. **Identity misclassifies everything non-standard as `embedded-linux` / `jffs2`.** Root cause: the signature
   layer is looser than binwalk and has **no entropy gate**. The JFFS2 magic is 2 bytes (`0x1985`/`0x8519`), so
   it matches coincidentally (165× in the ESP32 dump); a spurious ELF magic in a Xtensa literal pool makes
   binwalk say "ELF" → the class heuristic says "embedded-linux". Encrypted blobs (GE800), SoC dumps (ESP32),
   bare-metal (RP2040) and FIT/UBI containers (GL.iNet) all collapse to the same wrong label.
2. **CVE blindness on real Linux images.** WR940N returned 0 CVEs because SBOM ran without fingerprinting bundled
   components (pppd) — the app maps package manifests but not statically-linked/embedded component versions.
3. **Silent failure instead of an honest verdict.** GE800 (encrypted) and GL.iNet (needs a 4-stage carve)
   returned empty rather than "encrypted, here's the cipher" / "container needs FIT→UBI split".

### 3.2 What the app *cannot* obtain at all (structural gaps)

1. **Multi-stage / recursive extraction.** The pipeline calls one extractor and stops. GL.iNet needs
   **FIT-parse → carve the `ubi` sub-image → split UBI into per-volume LEB-reassembled images → `unsquashfs`
   the correct volume** (`ubi_rootfs`, not `wifi_fw`). `binwalk -Me` refused (needs root) and `ubireader`
   choked on the empty UBIFS overlay — a fixed one-tool pipeline reports "no rootfs" and quits.
2. **Non-Linux classes.** No ESP partition-table/NVS parser, no bare-metal vector-table + load-base recovery, no
   encrypted-OTA cipher identification. These are whole device families the app is blind to.
3. **Semantic vulnerability discovery.** The real bugs were a **lua `os.execute` cmdi gated by a lua-pattern
   validator** (GL.iNet) and a **component-version → CVE** link (WR940N pppd). A secrets-regex + single-binary
   Ghidra view finds neither — you need a web-handler/taint-aware model and a component-fingerprint CVE model.
4. **Reasoning across findings.** The autonomous pass *chained*: "this validator allows `\n` → torrc directive
   injection → the Tor process runs as root → root RCE" and "config-restore writes uci directly → bypasses the
   RPC validator entirely". The app has no step that composes findings into an attack path.
5. **Secret extraction from device stores.** The ESP32 private key lived in **NVS**; nvram creds lived in an
   nvram blob. The app's secret scan is file/regex-based and never parses these key-value stores.

---

## 4. Interface / UX problems observed while driving the frontend

- **No "what class is this and what can I even do?" answer up front.** The operator uploads a blob and is
  offered the *same* provider buttons regardless of class; for ESP32/RP2040/encrypted, most of them are no-ops
  that return empty without saying "not applicable to this class".
- **Every stage is a manual click with no chaining.** Extract → then remember to run SBOM → then fsaudit → then
  decompile. Nothing auto-advances when a stage produces the input the next one needs, and nothing tells you
  the *order* that matters for this image.
- **Empty results are indistinguishable from "clean".** "0 findings" reads as "secure" when it actually means
  "the pipeline never reached the rootfs / wrong class". No honest-degradation banner at the UI level.
- **No place to see the *reasoning*.** The value in the autonomous pass was the narrative (why the finding is
  real, what the exploit path is). The app surfaces findings as flat rows with no chain-of-evidence.

---

## 5. The *opacidad* workers

The autonomous pass decomposes cleanly into discrete workers. Each is an **AI-driven unit** that owns a slice of
the toolchain, emits structured findings + a reasoning trace, and declares what it produced *and what it could
not* (honest degradation, preserved). Workers are the Galert analogue: independent, composable, individually
observable.

| # | Worker | Owns | Kills the gap |
|---|---|---|---|
| **W0** | **Triage / identity** | entropy gate + arch/class detection (linux / openwrt-fit-ubi / esp-soc / baremetal / uefi / encrypted / rtos) | §3.1(1) jffs2 false-positive; routes every downstream worker |
| **W1** | **Extraction** | recursive, format-graph-driven carve: FIT→UBI→volume→squashfs, sasquatch fallback, cpio/jffs2/ubifs, ESP partition table; loops until a real rootfs or a terminal blob | §3.2(1) multi-stage extraction |
| **W2** | **SBOM / CVE** | `syft dir:` over opkg/dpkg manifest **+ bundled Go/embedded modules** → grype/OSV/NVD/KEV; component fingerprinting (pppd, openssl, tor) | §3.1(2), §3.2(3b) — the 408-CVE breadth, the pppd CVE |
| **W3** | **Credentials / secrets** | fsaudit + gitleaks **+ FP-triage** (minisign pubkeys, placeholders) **+ store parsers** (NVS, nvram, shadow) **+ offline cracking** (hashcat on `/etc/shadow`) | §3.2(5) — ESP32 NVS key, nvram admin/admin, root:sohoadmin |
| **W4** | **Web attack-surface** | enumerate rpcd/oui-httpd/luci/cgi handlers, resolve validators + ACLs + `no-auth-methods`, **taint web-param → uci → `os.execute`/`io.popen`/`sed` sinks**, model config-restore bypass | §3.2(3a),(4) — the GL.iNet Tor root-RCE, WR940N httpd cmdi |
| **W5** | **Binary-vuln** | arch-aware Ghidra/r2 fleet: decompile + taint the network daemons, checksec, locate pwnables | DVRF's 6 pwnables; WR940N httpd internals |
| **W6** | **ESP / IoT-SoC** | parse ESP partition table, dump + parse NVS (extract keys!), read Flash-Encryption / Secure-Boot eFuse posture, recover stale/erased entries | §3.2(2) — ESP32 trust-anchor key, boot-hijack posture |
| **W7** | **Bare-metal / RTOS** | **boot-header/PICOBIN parse to learn arch** (RP2350 = Cortex-M33 **vs** RISC-V Hazard3 — pick the wrong ISA and disassembly is garbage), vector table + copy-to-RAM load-base recovery, RTOS-kernel detect, decode-routine/flag extraction | §3.2(2) — the RP2350/RISC-V solve |
| **W8** | **Encrypted-blob** | entropy + header analysis, identify cipher/mode/IV, name the key-recovery path, **honest "unrecoverable without key"** | §3.1(3) — GE800 AES-128 verdict |
| **W9** | **Orchestrator (the opacity controller)** | plans which workers to run from W0's class, chains them (each worker's output feeds the next), **reasons across findings into an attack path**, writes the narrative report | §3.2(4) — the cross-finding reasoning the app has no step for |

### Orchestration model

```
        ┌─────────────┐
upload →│ W0 Triage   │→ class + entropy + arch
        └──────┬──────┘
               │ class-routed plan (W9 decides the DAG)
        ┌──────▼───────────────────────────────────────┐
        │ W9 Orchestrator  (the "opacidad" AI loop)     │
        │  • picks workers by class                     │
        │  • feeds each worker's output into the next   │
        │  • re-plans when a worker surfaces a new lead  │
        │  • composes findings → attack path + narrative │
        └──┬────────┬────────┬────────┬────────┬────────┘
      linux│    soc │  bare  │  enc   │  (all) │
        ┌──▼──┐  ┌──▼──┐  ┌──▼──┐  ┌──▼──┐  ┌──▼──┐
        │ W1  │  │ W6  │  │ W7  │  │ W8  │  │ W2  │  W3/W4/W5 fan out
        │extr │  │ esp │  │bare │  │ enc │  │sbom │  from a recovered rootfs
        └─────┘  └─────┘  └─────┘  └─────┘  └─────┘
```

- **Opacity = the operator doesn't configure providers.** They drop a firmware, hit *Autonomous scan*, and W9
  drives the whole toolchain — planning, extracting, pivoting, reasoning, reporting — the way the 6 agents did.
- **Every worker preserves honest degradation.** "Encrypted, need the key", "reached only `wifi_fw` volume",
  "class = bare-metal, no rootfs" are first-class outputs, never a silent empty.
- **The reasoning trace is the product.** W9 emits the chain-of-evidence (source → sink → privilege → path),
  which is exactly what the flat-rows UI is missing (§4).

### Implementation seam

The existing providers are already clean pure-function seams — each worker is mostly an **AI planner wrapping
one or more existing providers plus the gap tools** (NVS parser, FIT/UBI splitter, web-handler taint model).
W9 is a new orchestration agent (the LLM path is already wired: `FIRMLAB_AGENT=1` + DeepSeek). This is additive:
*opacidad* sits beside the current manual pipeline, not replacing it.

---

## 6. Phasing (proposed)

1. **W0 + W1 first** — an entropy-gated, arch-aware identity + a recursive multi-stage extractor kill the two
   most damaging bugs (jffs2 false-positive, "no rootfs" on FIT/UBI) and immediately fix 4 of the 6 images.
2. **W9 skeleton** — a class-routed orchestrator that just *chains the existing providers* in the right order and
   writes a narrative. Big UX win (§4) with no new analysis code.
3. **W6 (ESP) + W7 (bare-metal) + W8 (encrypted)** — the new device-family workers; each is self-contained.
4. **W4 (web taint) + W2 component-fingerprint** — the semantic-vuln depth; highest skill, highest payoff
   (these produced the two root-RCE headlines).

Deferred build items recorded in [`BACKLOG.md`](BACKLOG.md).

---

## 7. Per-firmware evidence appendix (ground truth for future sessions)

_The full technical substance recovered by the autonomous pass, so a future session has the ground truth without
re-running the agents. Each entry = what the image actually is, what was found, and the exact app-gap it exposes._

### 7.1 GL.iNet BE3600 (the crown jewel — app returned 0 files/0 findings)
- **Identity:** WiFi-7 travel router, **aarch64** (`aarch64_cortex-a53_neon-vfpv4`), SoC **Qualcomm IPQ5300**
  (OpenWrt target `ipq53xx/generic`), **OpenWrt 23.05-SNAPSHOT**, GL.iNet **BE3600** fw **4.9.0**
  (`/etc/glversion`), rootfs built 2026-06-23.
- **Container:** outer file is a **FIT image** (Flattened Image Tree) — an FDT v17 (`magic 0xd00dfeed`,
  totalsize ~111 MB) with the whole payload inlined. Two sub-images: `/images/script` (82 B @ off 188, the
  u-boot flash script) and **`/images/ubi`** (111,280,128 B @ **off 420**, type=firmware/arch=ARM/comp=none,
  magic `UBI#`).
- **Extraction chain (4 stages the app cannot do):** FIT-parse (Python FDT walker) → `dd` carve the UBI →
  reassemble LEBs per volume via ubi_reader API (128 KB PEB, 4 volumes: `wifi_fw`=SquashFS WiFi blob,
  `kernel`=FIT, **`ubi_rootfs`=SquashFS-xz 97 MB = the OpenWrt rootfs**, `rootfs_data`=empty UBIFS overlay) →
  stock `unsquashfs` the `ubi_rootfs` volume (SquashFS 4.0, xz, 7553 inodes). `binwalk -Me` **refused**
  (needs `--run-as=root`); `ubireader_extract_files` alone **failed** ("UBIFS Fatal: Super block error") tripping
  on the empty `rootfs_data` — a one-tool pipeline reports "no rootfs" here.
- **HEADLINE — Tor RPC command-injection → authenticated root RCE (the engagement vector):**
  `/usr/lib/oui-httpd/rpc/tor` → `replace_country()` line 45:
  `os.execute("echo \"ExitNodes " .. countries .. "\" >> /etc/tor/torrc")`. Taint: `M.set_config(params)` →
  `params.countries` (JSON array) → stored in uci `tor.global.countries` → read back by `replace_country()`.
  Runs **as root** (handler commits root-owned `/etc/config/firewall`, restarts `/etc/init.d/tor`, appends to
  root-owned `/etc/tor/torrc`; torrc sets `User root`). Only guardrail = the generic `valid_rpc_args` regex in
  `/usr/lib/lua/oui/rpc.lua`: **`^[%w%.%s%-_:#/]-$`** — there is **no `tor.lua` validator** in
  `/usr/share/gl-validator.d/`, so tor uses the default. Empirically it **blocks** `; | & $ \` " ( ) { }` but
  **allows newline** (`%s`) plus `/ : . -` → (a) **newline → torrc directive injection** into a root Tor process
  (arbitrary directives, e.g. `ClientTransportPlugin … exec …`), and (b) **any non-RPC writer of
  `tor.global.countries` — notably config backup/restore / uci import — bypasses the regex entirely → classic
  shell-metachar injection → direct root RCE.** Reachability = **authenticated** (`tor` **not** in `oui-httpd`
  `no-auth-methods`). Contrast: `/usr/lib/oui-httpd/rpc/diag` (ping/traceroute) **is hardened** (argv-array
  `ngx.pipe.spawn`) — vendor fixed the easy sink, left the tor `os.execute` string-concat. Other sinks:
  `wg_client:21` `io.popen(". "..helper.."; get_partner")`, `edgerouter:120`.
- **Weak auth defaults:** root shadow field empty (`root:::…`); dropbear `PasswordAuth 'on'` +
  `RootPasswordAuth 'on'` on port 22 (factory state, set on first-boot web setup — window is real).
- **No hardcoded secrets (clean):** all 12 gitleaks hits are FPs — dnscrypt `RWQ…` = minisign **public** keys,
  wg_client `8OCH…` = `@in-example` placeholder, sendsms `5f4dcc3b…` = commented-out MD5 of "password". (This is
  exactly the FP-triage W3 must do.)
- **CVE surface (syft→grype, 2019 pkgs, 408 findings: 55 Critical / 150 High / 178 Medium):** **tor 0.4.8.9**
  self-reports *"insecure or unsupported… upgrade!"* (EOL) **and runs as root**; OpenSSL 3.0.13 (32 CVEs, e.g.
  CVE-2024-6119); nginx 1.26.1 (19, primary remote surface); curl 8.6.0 (38); busybox 1.36.1 (CVE-2022-48174);
  python 3.11.7 (61); ffmpeg (18). Much Critical/High volume = transitive Go-module deps inside
  tailscale/adguardhome/zerotier binaries. Artifacts left in `/work/glinet/` (`rootfs.ubi`, `vols/`, `rootfs/`,
  `sbom.json`, `grype.txt`).

### 7.2 ESP32 flash dump (app: `embedded-linux`/`jffs2`/0 findings — catastrophic misclass)
- **Identity:** ESP32 **Xtensa LX6** LE, 8 MB SPI dump, **ESP-IDF v5.5.2**, Arduino core.
- **Structure:** partition table @ **0x8000** parsed → nvs / otadata / app0 / app1 / spiffs / coredump.
- **HEADLINE — private signing key extracted from NVS:** 32-byte privkey
  `98a39f0bc9018423d3f5359f0009a03f70fa4bbb578816fc6b1a9aad8877e893` — the device's **entire trust anchor**, in
  plaintext in unencrypted flash **and** printed over UART → full impersonation.
- **Stale-secret recovery:** erased NVS entries still readable — credential lineage aaron→aaronf→founder3→founder4.
- **Posture:** **Flash Encryption OFF, Secure Boot OFF, no anti-rollback** → boot-hijack via the empty `app1`.
- **App-gap root cause (the jffs2 FP, reproduced):** JFFS2 2-byte magic matched **165×** coincidentally +
  a spurious ELF magic at **0x7F4F4** inside an Xtensa literal pool → binwalk labels ELF → class = embedded-linux.
  The Linux/jffs2 lens misses the partition table, ESP app format, bootloader, NVS (the key!), and Xtensa arch.

### 7.3 TP-Link WR940N (app: 3 findings, 0 CVEs)
- **Identity:** MIPS Linux SOHO router. **Creds:** `root:sohoadmin`.
- **HEADLINE:** bundled **pppd** → **CVE-2020-8597** (EAP pre-auth stack overflow, remote RCE) — only found by
  **component fingerprinting** the binary version, which the app's manifest-only SBOM misses. Plus **httpd
  command-injection sinks** (web-param → shell).

### 7.4 DVRF — Damn Vulnerable Router Firmware (app: 24 findings, all busybox CVEs + certs)
- **Identity:** MIPS Linux, intentionally vulnerable. **Autonomous:** 6 exploitable **pwnable binaries**
  (stack BOF etc. — the actual purpose of DVRF) + `nvram admin/admin`. App got CVE breadth but **zero** of the
  pwnables → the app has no binary-level vuln discovery.

### 7.5 TP-Link Archer GE800 (app: silent extract failure)
- **Identity:** encrypted **WiFi-7 OTA**. **Autonomous verdict:** **AES-128 CBC/CTR, IV @ 0x116**,
  **unrecoverable without the key** — stated honestly, with the key-recovery path named (bootloader key /
  known-plaintext). The correct answer is a *diagnosis*, not an empty result.

### 7.6 Pico "RP2040" CTF (app: `embedded-linux`/`jffs2`/0 findings — wrong arch entirely)
- **Identity (corrected):** **NOT RP2040 / NOT embedded-Linux.** Raspberry Pi **Pico 2 / RP2350** baremetal on
  the **RISC-V Hazard3** cores (not ARM Cortex-M). Evidence: PICOBIN `IMAGE_DEF` markers, image-type = RISC-V EXE,
  `-march=rv32ima_zicsr_…_zbkb_zca_zcb_zcmp` build strings, machine-mode trap handler (`mret`/`csrr`), repo
  string `therealdreg/rp2350-simple-psram-project`. **Arch:** RV32IMAC(+B/Zcb), LE, **no filesystem**.
- **Memory/format:** flash XIP @ `0x10000000`, SRAM @ `0x20000000` (520 KB). Raw `.bin` (242,456 B, **not** UF2).
  **`copy_to_ram`** build — payload linked at SRAM `0x20000000`, copied at boot; runtime `0x20000000` ↔ flash
  offset **`0x110`** (this 16-byte skew initially hid the flag tables). PICOBIN block: start marker `0xFFFFDED3`
  @ 0x014, end `0xAB123579` @ 0x030; items `IMAGE_TYPE`(0x42 RISC-V EXE), `LOAD_MAP`(0x44). Pico SDK **2.2.0**
  (git `a1438dff…` = SDK build info, **not** a flag).
- **HEADLINE — all 6 CTF flags recovered.** Single deobfuscator `decode(ch,out,size)` @ RAM ~`0x20000862`, three
  tables (`tableA@flash 0x21D00`, `tableB@0x2C900`, `tableC@0x27300`, row = `ch*256`):
  `out[i] = tableC[ch*256+i] XOR ((ror8(tableA[ch*256+i], (i%7)+1) − tableB[ch*256+i]) & 0xFF)`
  (`i%7` via divide-magic `0x24924925`). Validated: correct `ror8` yields a clean **50-digit decimal** for all 6
  real `ch`; wrong rotation for none.

  | Menu | Challenge | ch | Flag |
  |---|---|---|---|
  | `s` | long short — GPIO2–5 to GND | 68 | `96014158765174452892714828160571667902711251285203` |
  | `c` | in-order crazy baud rates | 16 | `80408635455125293713436145994736656171816354677046` |
  | `p` | dumb PSRAM heap overflow | 36 | `13857095311951358710628913087029756290747461562243` |
  | `o` | not-so-dumb PSRAM heap overflow | 28 | `11461193409101464082480452818970324849251463656266` |
  | `u` | PSRAM heap use-after-free | 15 | `64573874491721157470525211162960004503601913391566` |
  | `l` | PIO put LED on | 35 | `29812880816911609471268467426151769151612352687456` |

- **Other:** UART login `user: cR4p!` / `password: cR4p!`; "CTF PASSWORD" is **runtime-derived per device** from
  the flash unique-ID (not statically recoverable); heap guard magic `0x69CAFE69`; a 32-digit decimal @ flash
  `0x21CDC` in the trap handler is a **decoy**, not a flag. CTF "HARDWAREHACKINGESCON2026" by David Reguera (Dreg).
- **Tooling caveats worth persisting:** Ghidra 12.1.2's **decompiler native is missing for linux_arm64** in this
  container (decompilation fails; disassembly works) — algorithm was reconstructed from the instruction listing +
  re-implementation. radare2's **RISC-V compressed-instruction decoding mis-splits** some 32-bit ops. Renode can
  model an RP2350 (Hazard3, UART, GPIO, PIO, PSRAM) → booting it and driving the UART menu would print the flags
  (a dynamic cross-check).

---

## 8. Implementation spec — the changes, the tools, and the bug each corrects

_Concrete build guidance so a future session can start coding without re-deriving. Format: **worker → what to
build → where in the code → tool/dependency → the exact bug it corrects → acceptance test.**_

> Providers are pure functions + a runner emitting `syncFindings(imageId, source, drafts)`. Each worker is an
> AI-planner wrapping existing providers + the gap tools below. LLM path is already wired
> (`FIRMLAB_AGENT=1` + DeepSeek `deepseek-v4-flash`, `loadLlmConfig`).

### W0 · Triage / identity  — **highest leverage**
- **Build:** an **entropy gate** + arch/class classifier that emits one of
  `linux | openwrt-fit-ubi | esp-soc | baremetal-armcm | baremetal-riscv | uefi | encrypted | rtos`.
- **Where:** `@firmlab/core` signature/class layer (the current heuristic that outputs `embedded-linux`/`jffs2`).
- **Tools:** existing entropy profile in core; add PICOBIN/ESP-partition/FIT/UBI magic recognizers; **an
  encrypted gate** (whole-file Shannon entropy > ~7.9 + no valid container header → `encrypted`, not a fs).
- **Corrects:** §3.1(1) — the **2-byte JFFS2 magic false-positive with no entropy gate** (165× coincidental in
  ESP32; spurious ELF magic in a Xtensa/RISC-V literal pool → `embedded-linux`). Must **not** trust a 2-byte
  magic without an entropy/structure corroboration.
- **Acceptance:** ESP32 → `esp-soc`; Pico → `baremetal-riscv` (PICOBIN `IMAGE_TYPE`=RISC-V, **not** ARM by name);
  GE800 → `encrypted`; GL.iNet → `openwrt-fit-ubi`; DVRF/WR940N → `linux`. None returns `jffs2`.

### W1 · Extraction  — recursive, multi-stage
- **Build:** a **format-graph** carver that loops: FIT-parse → locate `ubi` sub-image → **split UBI into
  per-volume LEB-reassembled images** → pick the rootfs volume (largest SquashFS, not `wifi_fw`) → `unsquashfs`;
  fall back to `sasquatch` for vendor SquashFS; skip empty UBIFS overlays instead of aborting.
- **Where:** `providers/extract.ts` (today calls one extractor and stops).
- **Tools:** already in container — Python FDT walker for FIT, `ubi_reader` API for LEB reassembly, `unsquashfs`
  + `sasquatch`. Do **not** rely on `binwalk -Me` (needs root; refused on GL.iNet).
- **Corrects:** §3.2(1) — GL.iNet returned **0 files** because the pipeline can't chain FIT→UBI→volume→squashfs
  and `ubireader_extract_files` aborts on the empty `rootfs_data` UBIFS volume.
- **Acceptance:** GL.iNet → `ubi_rootfs` recovered (SquashFS 4.0 xz, 7553 inodes) → downstream providers run.

### W9 · Orchestrator (opacity controller)  — Phase-2, biggest UX win per unit effort
- **Build:** a class-routed AI loop that (a) picks workers from W0's class, (b) **chains** them (each output feeds
  the next), (c) **re-plans** on a new lead, (d) **composes findings into an attack path + narrative**.
- **Where:** new orchestration agent alongside `agent/` (reuse the wired DeepSeek path).
- **Corrects:** §3.2(4) + §4 — no step composes findings (the "validator allows `\n` → torrc injection → root Tor
  → RCE" chain); every stage is a manual click; "0 findings" ≠ "clean".
- **Acceptance:** on GL.iNet, emits the source→sink→privilege→path narrative for the Tor cmdi automatically.

### W6 · ESP / IoT-SoC
- **Build:** ESP partition-table parser (@0x8000) + **NVS key-value store parser** (extract keys, recover
  erased/stale entries) + Flash-Encryption/Secure-Boot **eFuse posture** reader.
- **Where:** new `providers/esp.ts`; W0 routes `esp-soc` here.
- **Tools:** `esptool` / `parttool` / a small NVS reader (add to `Dockerfile.tools`; no NVS parser today).
- **Corrects:** §3.2(2)/(5) — ESP32's **NVS private signing key** + stale secrets are invisible to a file/regex
  secret scan; posture (Flash-Enc/Secure-Boot OFF) needs eFuse reads.
- **Acceptance:** ESP32 → surfaces the 32-byte privkey + "Flash Encryption OFF / Secure Boot OFF / no anti-rollback".

### W7 · Bare-metal / RTOS
- **Build:** boot-header/**PICOBIN parser to learn the ISA** (RP2350 Cortex-M33 **vs** RISC-V Hazard3 from
  `IMAGE_TYPE`), copy-to-RAM **load-base recovery** (flash 0x110 ↔ SRAM 0x20000000), then decode-routine + flag
  extraction; RP2040 = 256-byte boot2 + CRC32 + vector table @ 0x100.
- **Where:** `providers/rtos.ts` (today = Cortex-M vector table only); `core/mcu`.
- **Tools:** Ghidra (disassembly OK) + Renode (RP2350 dynamic cross-check). **Note the container caveats:** Ghidra
  linux_arm64 **decompiler native missing**; r2 RISC-V compressed mis-splits — plan around disassembly + re-impl.
- **Corrects:** §3.2(2) — app picks **ARM by name** and would disassemble **RISC-V as garbage**; wrong load base
  offsets every xref.
- **Acceptance:** Pico → class `baremetal-riscv`, correct load base, `decode()` located.

### W8 · Encrypted-blob
- **Build:** entropy + header analysis → identify **cipher/mode/IV**, name the key-recovery path, emit an honest
  **"unrecoverable without key"** finding (never a silent empty).
- **Where:** new `providers/encrypted.ts`; W0 routes `encrypted` here.
- **Corrects:** §3.1(3) — GE800 currently **fails silently**; the correct output is the AES-128 CBC/CTR, IV@0x116
  diagnosis.
- **Acceptance:** GE800 → "encrypted, AES-128, need key; recovery via bootloader key / known-plaintext".

### W4 · Web attack-surface  — highest skill, produced the two RCE headlines
- **Build:** enumerate `rpcd`/`oui-httpd`/`luci`/`cgi` handlers, resolve each object's validator +
  ACL + `no-auth-methods`, model the **default `valid_rpc_args` lua-pattern semantics** (that `%s` permits
  newline), and **taint web-param → uci config value → `os.execute`/`io.popen`/`ngx.pipe.spawn(string)`/`sed`
  sinks**; also model **config-restore → uci → shell** (bypasses the RPC validator).
- **Where:** new `providers/webtaint.ts` (static; distinct from the dynamic `providers/webprobe.ts`).
- **Corrects:** §3.2(3a)/(4) — the GL.iNet Tor root-RCE + WR940N httpd cmdi are invisible to secrets-regex +
  single-binary Ghidra.
- **Acceptance:** GL.iNet → flags `rpc/tor replace_country os.execute` as newline-injectable + restore-bypass RCE.

### W2 · Component-fingerprint CVE  (extend SBOM)
- **Build:** fingerprint **bundled / statically-linked component versions** (pppd, openssl, tor, busybox, Go
  modules), not only the package manifest, then grype/OSV/NVD/KEV.
- **Where:** `providers/sbom.ts` + `research/*`.
- **Corrects:** §3.1(2) — WR940N returned **0 CVEs**; the pppd **CVE-2020-8597** pre-auth RCE is only reachable
  by version-fingerprinting the binary. Also recovers the GL.iNet EOL-tor-as-root signal.
- **Acceptance:** WR940N → pppd CVE-2020-8597 surfaced; GL.iNet → 400+ CVEs incl. EOL tor.

### W3 · Secret extraction + offline cracking
- **Build:** parse device **stores** (NVS, nvram, `/etc/shadow`) + **FP-triage** (minisign pubkeys, `@in-example`
  placeholders, commented MD5s) + **hashcat** on shadow hashes.
- **Where:** extend `providers/fsaudit.ts` + core secret classifier; add hashcat to `Dockerfile.tools`.
- **Corrects:** §3.2(5) + the GL.iNet **12 gitleaks FPs** (all benign) — the scan needs triage to avoid crying
  wolf, and store-parsing to find real creds (root:sohoadmin, nvram admin/admin).
- **Acceptance:** WR940N → `root:sohoadmin`; DVRF → `nvram admin/admin`; GL.iNet → 12 hits correctly triaged FP.

### UI · Honest-degradation banner (cross-cutting)
- **Build:** distinguish "0 findings" from "pipeline never reached rootfs / class not applicable"; show per-class
  "what can I even run" up front; surface the W9 reasoning trace (source→sink→privilege→path), not flat rows.
- **Corrects:** §4 — empty == "clean" is dangerously misleading (GL.iNet/GE800/ESP32/Pico all read "clean").

---

## 9. Re-run — app vs autonomous, second pass (2026-07-22)

The experiment was re-run after W0–W9 shipped, to measure whether *opacidad* closed the pass-1 delta. **App pass:**
all 15 firmwares driven as a normal operator (upload → one-click Autonomous scan) on the deployed `firmlab`
(build `028ca16`, all workers). **Autonomous pass:** 15 blind free-form agents, one per image, raw `firmlab-auton`
toolchain, no preset, ~100k-token budget each (actual: 15/15 done, 0 errors, 516,747 tokens total ≈ 34k/agent —
all finished under the cap, so nothing was truncated by it).

**Verdict: substantial improvement.** In pass 1, on 4 of 6 ground-truth images the app returned *nothing or the
wrong class*. This run, those 4 are fixed — the app now reproduces the pass-1 autonomous headlines directly:

| Image | Pass-1 app | App now (opacidad) | Status |
|---|---|---|---|
| GL.iNet BE3600 | 0 files / 0 findings | `openwrt-fit-ubi`, 641 findings; **tor `os.execute`→uci→root** (`web-taint-cmdi`) + restore-bypass; 486 CVEs (55 crit); empty root shadow | **CLOSED** |
| ESP32 dump | `embedded-linux`/jffs2/0 | `esp-soc`/xtensa; NVS privkey `98a39f0b…`; stale lineage; Flash-Enc/Secure-Boot OFF | **CLOSED** |
| GE800 OTA | silent extract failure | `encrypted`; cipher diagnosis + honest "unrecoverable without key" | **CLOSED** |
| Pico "RP2040" | `embedded-linux`/jffs2/0 (ARM) | `baremetal`/**riscv** (correct class + ISA) | **Identity CLOSED**; flag extraction still open (W7-deeper) |
| WR940N | 3 findings / 0 CVEs | 7 findings: root md5 hash, telnet/httpd autostart, hardening — **still 0 CVEs** | **PARTIAL** — pppd component-CVE missed |
| DVRF | 24 findings | 25 findings (18 CVEs) | **UNCHANGED** — no binary pwnables (W5 shallow) |

**Remaining gaps, pinned by this run (all now in `BACKLOG.md`):**
1. **Component-fingerprint CVE (W2)** — 0 CVEs on WR940N *and* WDR3600; agent finds pppd CVE-2020-8597 on both.
2. **eCos/RTOS classification (W0)** — both Xiaomi repeaters are eCos 3.6.10 on MT7628 but the app calls them
   `embedded-linux`.
3. **Deep bare-metal solve (W7)** — Pico class/ISA now correct, but no decode-routine / flag extraction.
4. **Binary pwnables (W5)** — DVRF still yields no memory-corruption findings.
5. **Auxiliary-partition secrets (W1/W3)** — BeanView cloud pairing secret (plaintext JFFS2), Tenda RSA private
   key both missed; the carve only scans the rootfs volume.
6. **Corrupt/decoy honest verdict** — Asus hollow image (93% zeros): agent diagnosed it, app returned a silent 0.

Net: the gap moved from "the app is blind on modern/non-Linux classes" to "the app matches a budget-limited agent,
minus six specific depth features." On the closed images the app now *equals or exceeds* what a 34k-token agent
recovers (e.g. GL.iNet 641 findings / 486 CVEs vs the agent's budget-limited 4).

### 9.1 Gaps addressed (2026-07-22, same session)

All six re-run gaps were then implemented (each a self-contained, unit-tested commit; the app now closes them
without an autonomous agent):

1. **W2 component-fingerprint CVE** (`providers/component-cve.ts`) — fingerprints bundled pppd/openssl by the
   version string in the binary → **pppd 2.4.2–2.4.8 → CVE-2020-8597** (WR940N + WDR3600) + openssl Heartbleed.
2. **W0 eCos/RTOS classification** (`core/structure.ts` + `rtos.ts`) — eCos monoliths (both Xiaomi) now classify
   as `rtos`, not `embedded-linux`, with the version/RedBoot/app surfaced.
3. **W7 plaintext flag/credential extraction** (`rtos.ts`) — bare-metal images emit `baremetal-flag` findings for
   cleartext tokens (obfuscated flags still need manual reversing — stated honestly).
4. **W5 binary-vuln sweep** (`providers/binvuln.ts`) — every rootfs ELF scanned for unbounded-copy + no-canary
   stack-overflow candidates (the DVRF pwnables).
5. **W3 embedded-private-key by content** (`fsaudit.ts`) — a PEM key inside any file is flagged regardless of
   filename. **Extended (`auxsecrets.ts`) to scan sibling (non-rootfs) partitions** — Tenda's 1024-bit RSA key in
   `jffs2-root-0/-1/version/privkey.pem` now surfaces (validated in-container). Honesty correction: **BeanView's
   `private_key.pem`/`devinfo` are PUBLIC keys, not a cloud secret** — the autonomous "cleartext cloud pairing
   secret" headline was an overstatement; the scan correctly leaves public keys alone.
6. **Corrupt/decoy verdict** (`providers/decoy.ts`) — a hollow image (claimed fs + no rootfs + mostly zeros)
   emits a `corrupt-decoy` finding instead of a silent 0 (Asus).

Deferred remainders (in `BACKLOG.md`): aux-partition *extraction* (BeanView cloud secret), on-device
decode-routine reversing (Pico flags), nvram parser + `/etc/shadow` cracking, and angr symbolic reachability to
upgrade W5 candidates to confirmed.
