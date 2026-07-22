# FirmLab roadmap

Phased development plan. Checked items ship in this branch; the rest is the ordered backlog for the next
long work session, grounded in a precise review of the current tree (file references included).

---

## Shipped (phases 0–2)

**Phase 0 — deploy consolidation & honesty**
- [x] Docker build fixes (CI=true; copy `apps/api/node_modules` into runtime; radare2 per-arch `.deb`; gitleaks per-arch).
- [x] Health "auth-gated" state — `FIRMLAB_TRUSTED_PROXY=1` → `/health.trustedProxy`; UI shows `🔒 auth-gated`.
- [x] First `apps/web` tests (pure client helpers).

**Phase 1 — frontend + mobile browser support**
- [x] Off-canvas drawer nav (hamburger + backdrop) on narrow viewports; desktop unchanged.
- [x] `100dvh` shell, 860/520px breakpoints, single-column grids, `.table-wrap` horizontal scroll, larger touch targets.

**Phase 2 — wire the installed toolchain**
- [x] **SBOM & CVEs** tab — syft + grype as a persisted job (severity tally, CVE table, package list).
- [x] **Binaries** tab — radare2 static triage (headers/arch, NX/canary/PIC, imports, symbols, strings); rootfs-confined path.

---

## Precision review — findings driving the backlog

| # | Finding | Where | Consequence |
|---|---------|-------|-------------|
| F1 | Arch/endianness inferred **only** from a raw ELF signature hit | `packages/core/src/structure.ts:163` (`inferArch`) | Packed images (uImage/squashfs) stay `arch: unknown` → emulation menu can't pick a QEMU target |
| F2 | Job runner is fire-and-forget, **no concurrency cap** | `apps/api/src/providers/jobs.ts` (`startJob`) | Parallel binwalk `-Me` + syft + QEMU can exhaust CPU/RAM |
| F3 | **No data retention / quota** — cleared only on explicit DELETE | `apps/api/src/routes/images.ts:122` | `firmlab-data` grows unbounded (large images + carved rootfs) |
| F4 | `gitleaks` installed but **unwired** | `tools.ts` detects it; no provider | Secrets tab is raw-image string heuristic only |
| F5 | `analyzeHeadless` (Ghidra) detected but **unwired** | `tools.ts` | No decompilation beyond r2 triage |
| F6 | Only **31 signature rules**, thin crypto/cert/dtb coverage | `packages/core/src/signatures.ts` | Misses device trees, kernel configs, vendor headers, key material |
| F7 | Web tests cover **only pure helpers**; no component/interaction tests | `apps/web` (no jsdom setup) | Regressions in panels/drawer/job-polling go uncaught |
| F8 | `samples/` empty — **no e2e fixture** exercising extract→sbom→triage | `samples/.gitkeep` | No integration guard for the provider chain |
| ~~F9~~ | ~~Full-system QEMU & Renode recipes are non-runnable placeholders~~ — **resolved**: Renode boots for real (route + web "Boot under Renode" button + agent executor), and chroot/full-system are launchable from the web too | `routes/renode.ts`, `agent/session.ts`, `components/SimulationMenu.tsx` | Every ladder rung the deployment supports is now runnable, not just user-mode |
| F10 | API has **no auth/rate-limit of its own** | `apps/api/src/index.ts` | Defense-in-depth relies entirely on the external proxy |

---

## Phase 3 — Analysis depth & trustworthy identity

- [x] **F1 — Arch/endianness refinement.** uImage `ih_arch` decoder in `inferArch`; post-extraction rootfs ELF
  probing (modal vote) persists an authoritative arch/endianness. *(wave 1)*
- [x] **gitleaks deep scan (F4).** `providers/gitleaks.ts` + route as a job, folded into the Secrets tab; matches
  redacted; verified in the firmware image (2 findings on a planted key). *(wave 1)*
- [x] **Firmware diff.** `providers/diff.ts` + route + Diff tab: identity, SBOM package/CVE deltas, rootfs file
  add/remove/change (by path+size). *(wave 1)*
- [x] **Findings report export.** `providers/report.ts` + route: self-contained HTML (identity, secrets, SBOM/CVEs,
  triage) as a download. *(wave 3)*
- [ ] **Ghidra decompilation (F5, optional heavy).** Wire `analyzeHeadless` as a decompile job behind a capability
  flag; opt-in (image ships without Ghidra). *Deferred — heavy, low marginal value over r2 triage.*

## Phase 4 — Reliability & platform

- [x] **Bounded job queue (F2).** `FIRMLAB_MAX_CONCURRENT_JOBS` (default 2); overflow persists as `queued`. *(wave 2)*
- [x] **Data retention & quota (F3).** `FIRMLAB_MAX_IMAGE_AGE_DAYS` + `FIRMLAB_MAX_DATA_BYTES` (oldest-first eviction);
  swept at startup, on a timer, and after upload; `/storage` usage on the Dashboard. *(wave 2)*
- [x] **Multi-image management — search + tags + bulk delete.** Filter by filename/arch/class/tag; per-row tag
  chips; row checkboxes + "Delete selected". *(waves 2, 5)*
- [x] **Signature pack expansion (F6).** +12 magics (ext/f2fs/erofs/cramfs-be, IKCFG/bzImage/arm64 Image,
  lzop/7z/rar/android-sparse/cpio-odc), offset-anchored, each tested. *(wave 2)*
- [x] **Ghidra decompilation (F5).** `analyzeHeadless` post-script job behind the capability probe; Binaries tab
  pseudocode viewer; degrades to `available:false` (image ships without the ~1.5 GB Ghidra layer). *(wave 4)*
- [~] **Full-system emulation (F9).** Guided per-arch qemu-system recipe (correct machine/binary from the refined
  arch). *Auto-boot + interactive shell deferred by design* — the planner deliberately surfaces guided recipes
  rather than one-click boots that would silently fail; a true interactive console needs a websocket/PTY transport.

## Phase 5 — Quality, testing & hardening

- [x] **Web component/interaction tests (F7).** jsdom + @testing-library; cover the Dashboard filter, the mobile
  drawer toggle, and the auth-gated health pill. *(wave 3)*
- [x] **Mobile polish.** PWA manifest + icon + theme-color (add-to-home-screen); touch tooltips on the entropy chart. *(wave 3)*
- [x] **API defense-in-depth (F10).** Always-on security headers; opt-in `FIRMLAB_API_TOKEN` / `FIRMLAB_RATE_LIMIT`
  / `FIRMLAB_STRICT_CSP`. *(wave 4)*
- [x] **Structured errors & toasts.** Global toast surface; job failures + upload/tag errors raise toasts. *(wave 4)*
- [x] **Content-hash file diff.** Extractor hashes files (≤8 MB); diff flags content changes, not just size. *(wave 6)*
- [x] **E2E fixture & integration test (F8).** `apps/api/scripts/integration.mjs` builds a synthetic SquashFS
  firmware and runs extract → arch → sbom → gitleaks → decompile in the firmware image (12 assertions). It caught a
  real bug: binwalk refuses to extract as root without `--run-as=root` (the container runs as root), so real
  extraction was silently failing in the deployed image — now fixed. *(wave 6)*

---

## Shipped this session (waves 1–6)

Arch refinement · gitleaks deep-scan · firmware diff (with content hashes) · report export · bounded job queue ·
data retention/quota · image search/tags/bulk-delete · +12 signatures · Ghidra decompile · API defense-in-depth ·
toasts · web component tests · PWA + entropy touch · per-arch emulation recipes. Verified against real tools in the
firmware image where applicable; 70+ tests; biome clean; committed in slices.

## Remaining backlog

A true interactive/full-system emulation console — auto-booting arbitrary firmware needs per-image kernel/dtb
assembly, and a live shell needs a websocket/PTY transport the API doesn't have yet. This is a project of its own;
the planner deliberately ships guided per-arch recipes instead of one-click boots that would silently fail.

---

## Phase 6+ — Firmware engine with conscious autonomy (next direction)

Perfect a single domain: turn the click-driven workbench into a specialized firmware engine — more data, more
control, more depth, and autonomy *with consciousness* (a deterministic skeleton the agent reasons within, not
a blank agent loop). Carved from the parent platform (Galert), FirmLab's edge is being deterministic, local,
visual, and — uniquely — stateful: a persistent corpus that learns the domain across images. Gated behind
`FIRMLAB_AGENT`; with it off, FirmLab stays local-only, no-network, deterministic.

Phased so Phases 0–1 ship value with **no LLM at all** (first-class binaries table, live-building dossier
panel, hardened emulation ladder as deterministic providers, the persistent corpus), then Phases 2–4 layer the
agent onto that base: copilot → decision nodes → zero-day + per-session isolation.

Shipped: **Phase 0** (proof-states + findings, binaries table, deterministic preflight, dossier, emulation
ladder providers), **Phase 1** (persistent cross-image corpus, cross-refs, Level-1 rule watchlist, corpus web
views), **Phase 2** (the read-only copilot: DeepSeek-first multi-provider LLM layer, proof-state discipline,
dossier panel — all flag-gated), **Phase 3** (the decision nodes: ① triage + ② target-selection as
structured-output LLM nodes on a deterministic orchestrator, a governor with hard step/token/USD/time caps, an
auditable+resumable session transcript, emulation gated behind human approval, and the retention↔session guard
so a live session pins its image — all flag-gated), **Phase 4** (the zero-day node ④ reasoning sink→source over a
deterministic taint scaffold and constructing a trigger — candidates only, never a proven bug; per-session
isolation via OS primitives — prlimit + unshare -n network namespace + guaranteed teardown — so emulation
auto-runs WITHOUT a human gate when the blast radius is fully contained; Level-2 corpus priors into node ④; an
opt-in AFL++ fuzzing provider). Next: broaden class coverage (Renode/RTOS, UEFI/chipsec) and node ⑤ synthesis.

**Phase 4 — zero-day + isolation (implemented).** Node ④ (`agent/zeroday.ts`) reasons about a reachable vuln from
a deterministic taint scaffold (`providers/taint.ts`: the dangerous sinks a binary imports, the attacker sources,
CGI hints) plus Level-2 corpus priors, and constructs a trigger — but the proof-state machine binds it to
CANDIDATES (`needs_runtime_reproduction`); only a real trigger run upgrades, and that is code's call. Per-session
isolation (`providers/isolate.ts`) bounds the blast radius with OS primitives instead of a nested container —
`prlimit` (CPU/RAM/fsize/fd caps), `unshare -n` (empty network namespace), a throwaway workdir with guaranteed
teardown, composed without a shell. At isolation level `full` emulation auto-runs with no approval (contained
radius); otherwise the Phase-3 approval gate is kept — honest degradation (`unshare -n` needs CAP_SYS_ADMIN). An
opt-in AFL++ provider (`providers/fuzz.ts`) fuzzes under the sandbox, degrading to `available:false` when absent,
like Ghidra. Env: `FIRMLAB_ISOLATE_CPU/_MEM_MB/_FSIZE_MB/_WALL_SECONDS`. `/api/agent/config` reports
`phase4: {isolation, fuzzing, autoRun}`. Validated end-to-end in the firmware image (mock LLM for ①②④): full
transcript through node ④, a command-injection candidate from the real radare2 scaffold, and a real qemu-user run
auto-executed under netns+rlimits with no approval — proof-state honest. AFL++ and Renode are both integrated and
validated against real firmware (a real coverage-guided crash; a real Contiki boot on an emulated STM32F4). The
`uefi-bios` class now has its own offline analysis track too (chipsec `providers/chipsec.ts`) — no faked coverage.

**Phase 5.0/5.1 — external intelligence (implemented).** The first internet-touching capability, behind its OWN
flag `FIRMLAB_RESEARCH` (separate from `FIRMLAB_AGENT`; unset → zero external egress, local-only preserved). A
deterministic provenance fingerprint (`providers/provenance.ts`: vendor/model/version/URLs/CN/banners from analysis
strings + rootfs banner files) + an allowlisted OSV.dev correlation (`providers/osv.ts`: SBOM component+version →
published advisories; only names+versions leave, never bytes) + a cited synthesis brief (`agent/intel.ts`, DeepSeek
by default). Every fetch passes an allowlist choke point (`research/config.ts`) and an egress ledger
(`research/egress.ts`) states exactly what leaves and what never does. A published advisory for a present component
is a lead, not a confirmed bug — reachability is decided per-image. Web: an "External intelligence" panel in the
dossier. Validated end-to-end in the container with REAL services: syft SBOM (194 pkgs) → real OSV (70 published
advisories, e.g. apt 2.6.1 → DEBIAN-CVE-2011-3374) → provenance (acme-networks/v1.2.3 from /etc/issue) → real
DeepSeek brief. Env: `FIRMLAB_RESEARCH`, `FIRMLAB_RESEARCH_ALLOWLIST`, `FIRMLAB_RESEARCH_TIMEOUT_MS`.

**Phase 5.2/5.3 — key provenance + responsible disclosure (implemented).** 5.2 (`providers/keys.ts`) surfaces
embedded key material from the analysis AND a bounded rootfs scan (keys live compressed inside the FS, invisible at
image level): an embedded private key is effectively public (extractable), and corpus reuse (`sharedInImages`)
proves it directly — values redacted, never a cracking service. 5.3 (`providers/securitytxt.ts`) discovers the
vendor disclosure contact via RFC 9116 (/.well-known/security.txt) but ONLY for domains the operator allowlisted
(others are reported "not checked — add to allowlist", no surprise egress); the intel brief drafts the report with
that contact — the human sends it. Validated with a real security.txt (cloudflare → hackerone contact) and an
embedded dropbear key flagged effectively-public.

**OSINT sources #2 + #3 — NVD + CISA KEV (implemented, validated with real services).** Two more allowlisted
research agents with the same discipline. **NVD** (`providers/nvd.ts`) fills OSV's gap: a keyword search of the
National Vulnerability Database for the components OSV can't map to an ecosystem (busybox, dropbear, kernel, vendor
daemons) — only a name+version leave, capped for NVD's anonymous rate limit with an honest count of what wasn't
queried (`NVD_API_KEY` lifts the cap). **CISA KEV** (`providers/kev.ts`) downloads the public Known-Exploited-
Vulnerabilities catalog and cross-references the discovered CVEs LOCALLY — nothing about the firmware leaves — to
flag which are exploited in the wild; the brief surfaces KEV CVEs first, still marked reachability-unverified.
Default allowlist widened to `api.osv.dev` + `services.nvd.nist.gov` + `www.cisa.gov`; the egress ledger declares
NVD (keywords) and KEV (download-only). Validated live: real NVD (HTTP 200, CVSS severity parsed) + real KEV
(~1650-entry catalog, Log4Shell `CVE-2021-44228` matched → Log4j2, ransomware=Known). Not yet: vendor-PSIRT/CNA
sources (no single free API), a downloadable disclosure-report generator, hardened egress (proxy/netns), corpus
OSV/KEV cache.

### Phase-4 tech debt — paid down

- **✅ Node ④'s trigger is now delivered to the target** (debt #3, the big one). `providers/trigger.ts` plans a
  delivery from the candidate's source class (CGI env / stdin / argv): command-injection appends a `;echo <marker>;`
  payload (the marker in stdout = injection reproduced), overflow sends an oversized input (a crash signal =
  memory-unsafety reproduced). The session runs it under isolation and upgrades the SPECIFIC finding honestly.
  Validated end-to-end: a real overflow target crashed under the delivered trigger (SIGSEGV) → the candidate went
  `needs_runtime_reproduction` → `confirmed_in_emulation`.
- **✅ Node ⑤ (synthesis) wired into the session** (debt #5) — a cited narrative over the confirmed findings runs as
  the session's closing step (governor-bounded), recorded in the transcript, after both the auto-run and the
  approval paths.
- **✅ Rootless network namespace** (debt #2) — `detectIsolation` now falls back to `unshare -rn` (a user namespace
  mapping to root, then a fresh netns), so `full` isolation works WITHOUT `CAP_SYS_ADMIN` on hosts that allow
  unprivileged user namespaces. Caveat: some container runtimes (e.g. Docker/OrbStack default) block `unshare`
  entirely, so there it still needs `--cap-add=SYS_ADMIN` or degrades honestly to `partial` (approval kept).
- **✅ AFL++ fuzzing** (debt #1) — `providers/fuzz.ts` runs coverage-guided qemu-mode AFL++ under isolation, with a
  seed corpus + a `rabin2`-mined dictionary, and records a `fuzz-crash` finding (`confirmed_in_emulation`) for each
  reproduced crash. Validated end-to-end **twice** against a real AFL++ (built `afl-qemu-trace`): (1) a planted
  magic-prefix NULL-deref was discovered by coverage feedback in ~4k execs → SIGSEGV → confirmed finding; (2) a real
  known firmware — OpenWrt 23.05.5 aarch64 `busybox` — was instrumented for 257k execs with an honest 0-crash result.
  Two fixes the real binary forced: `-m none` (a qemu-mode fork dies under an `--as` cap) and `QEMU_LD_PREFIX=<rootfs>`
  (dynamically-linked firmware binaries need their own loader/libs, which static test targets masked). Still opt-in:
  no `afl-fuzz` → honest `available:false`.
- **✅ Fuzzing — per-class harnesses** (beyond file-input `@@`). The input-delivery method is now chosen for the
  target, not fixed: `file` (parser reads a path via `@@`), `stdin` (filter/CLI reads stdin — AFL feeds it, no `@@`),
  and `network` (socket daemon — a desock preload redirects the daemon's socket I/O to the fuzzed stdin). Auto-selects
  the network harness for daemon/CGI names, else `file`; the caller/UI can override. desock is opt-in and arch-specific
  (`FIRMLAB_DESOCK` → a guest-arch libdesock); absent → the network harness degrades honestly to raw stdin with a note,
  never pretending the socket was fuzzed. `FuzzResult` carries the `harness` used. Validated against a real AFL++: a
  stdin-reading crasher is reproduced under the `stdin` harness (input delivered on stdin) but NOT under `file`
  (stdin left empty) — the harness distinction, proven. Command builder + harness picker + desock detection are pure
  and unit-tested; a `harness` selector is wired through the `/fuzz` route and the web `FuzzPanel`.
- **✅ RTOS/Renode** (debt #4) — `providers/renode.ts` boots a real MCU firmware under Renode and decides "booted" from
  the actual UART bytes (per-UART file backend), never assumption; it discovers the right UART by following the
  platform `.repl`'s `using` include graph, and degrades honestly to `blocked_by_platform` without Renode or a
  matching platform. Validated end-to-end with a real known sample — Contiki OS on an emulated STM32F4 Discovery
  (Renode's canonical demo ELF) booted and printed `Contiki 3.x started` on uart4 → `confirmed_in_emulation`. Runs
  under `full` isolation (netns + cpu + wall-clock caps); the `--as`/`--fsize` caps are skipped because .NET's GC and
  Renode's mmap'd emulation files abort under them.
- **✅ Renode per-MCU auto-identification — broadened** (was a hardcoded 7-family regex map). A pure MCU fingerprint
  (`@firmlab/core` `fingerprintMcu`, unit-tested) reads the evidence static analysis never mined: the memory map
  (ELF load LMAs / SRAM, or a raw image's ARM Cortex-M vector table → flash+RAM bases) and the plain strings the
  credential scan drops (vendor/SDK/CMSIS/RTOS markers → STM32F*/L*/G*/H*, nRF5x, EFR32/EFM32, TI CC13xx/26xx, SAMD,
  Kinetis, LPC, i.MX RT, GD32(V), CH32(V), ESP32(-C/-H), SiFive/RISC-V, PIC32, MSP430; the Cortex-M core; Zephyr/
  FreeRTOS/Contiki/RIOT/…). Selection is now **catalog-aware** (`selectPlatform` scores every `.repl` Renode actually
  ships by token specificity, board-over-cpu, and a curated known-good tie-break), so coverage tracks the install,
  not a family list. Honest: no vendor family match → `blocked_by_platform` (naming the detected MCU) — and NO
  generic-core fallback, because real Renode ships no bare `cortex-mN.repl` and a core without the SoC's peripherals
  could never boot. Validated **in-container against real Renode v1.16.1 (216 bundled platforms)**: the real STM32F4
  Discovery demo ELF fingerprints to `stm32f4`/cortex-m4/contiki and boots for real (`Contiki 3.x started` on uart4 →
  `confirmed_in_emulation`); seven families (incl. EFR32MG, ATSAMD51, SiFive FE310 — beyond the old three) each
  auto-map to a real bundled `.repl`; an unknown MCU blocks honestly.
  Sub-family precision: a **part-specific board** now wins over a family board or a bare cpu — the fingerprint exposes
  the STM32 part core with the `stm32` prefix stripped (`stm32h753zi` → `h753`) since Renode's boards name themselves
  inconsistently, so `STM32H753` → `boards/nucleo_h753zi.repl` (the exact SoC + peripherals) instead of a generic
  cpu. Validated against the real 216-platform catalog with no regression to the STM32F4 Contiki boot.
- **✅ Agent RTOS/Renode path — validated end-to-end.** A mock-LLM driver (`apps/api/scripts/mock-llm.mjs` +
  `apps/api/scripts/agent-renode-e2e.mjs`) drives a full conscious-autonomy session over a real RTOS ELF against a
  real Renode: node ① triage → preflight → node ② picks the `rtos-renode` rung → zero-day skipped (no rootfs) →
  the Phase-4 executor auto-runs under full isolation and **boots Contiki under Renode** → `confirmed_in_emulation`.
  Asserts the transcript, including that the executor dispatches the RTOS rung to Renode and not the user-mode
  emulator (agent-level guard for the split-brain fix). This closes the deferred F7-adjacent hardening (paired with
  the new `FuzzPanel`/`SimulationMenu` web component tests).
- **✅ UEFI/chipsec — the `uefi-bios` analysis track (`providers/chipsec.ts`).** A `uefi-bios` image has no Linux
  rootfs and no MCU to emulate, so its track is chipsec's OFFLINE decode: parse the firmware volumes, carve every
  EFI module, and reason about the inventory from the real bytes. A separate provider from Renode (not emulation);
  proof tops out at `static_confirmed` — a fact about the image, never a device claim. The preflight routes
  `uefi-bios` → the `uefi-chipsec` strategy (or `static-only` if chipsec is absent, degrading honestly), never to a
  qemu rung; it surfaces as a recipe in the Simulation menu and its own `/chipsec` route + status. Findings: an
  `info`/`static_confirmed` module inventory, an `info`/`needs_runtime_reproduction` embedded-application lead
  (bootkit vector — a review lead, not a verdict), and a `critical` IOC match against a `FIRMLAB_UEFI_IOC`-pointed
  known-bad-module feed (opt-in like `FIRMLAB_DESOCK`; empty built-in — no fabricated detections). The `.UEFI.lst`
  parser, the type summary, and the scan are pure + unit-tested. Validated **in-container against real chipsec
  1.13.16 on a real OVMF image**: 2 firmware volumes, 131 EFI modules with an exact type histogram (109 DXE_DRIVER,
  13 PEIM, 2 APPLICATION…), the embedded-app lead firing on UiApp + Shell, and a non-UEFI blob blocking honestly
  (`blocked_by_platform`, no fabricated tree).

### Remaining backlog

- chipsec follow-ups: parse Secure Boot posture from offline NVRAM (SecureBoot/SetupMode/test-key PK) when the
  image carries the variable store; ship a curated `FIRMLAB_UEFI_IOC` feed of public UEFI-implant GUIDs.
- Fuzzing: ship a prebuilt guest-arch libdesock (per common arch) so the network harness works out-of-the-box, not
  only when `FIRMLAB_DESOCK` is provided; cmplog/compcov for magic-byte solving.
- External-intelligence: vendor-PSIRT/CNA sources (OSV + NVD + CISA KEV now integrated), a downloadable disclosure-report generator,
  hardened egress (proxy/slirp4netns), corpus OSV cache.
- Rebuild `firmlab-firmware:latest` on the next deploy so the image matches HEAD.

## Phase 6 — Capture & acquisition (6.0–6.3 shipped; 6.4+ designed)

Close the loop *before* analysis: acquire firmware from a **live device** in-flight (intercept an OTA update the
moment you press "Update" in the vendor app), carve the blob out of the traffic, and auto-ingest it into the
workbench. FirmLab's second network-touching lane (after `FIRMLAB_RESEARCH`), gated behind **`FIRMLAB_CAPTURE`**.
Built on the patterns already here: **capture backends** auto-detected like tools (network proxy, ARP/DNS spoof,
BLE/Zigbee radios — plug a dongle, gain a transport), a **capturability ladder + preflight** with honest
acquisition proof-states, a **guided, human-triggered, time-boxed session** with guaranteed teardown (mirrors the
agent session + isolation), and a **learning loop** — captured versions accumulate in the corpus into an OTA
timeline with cross-version diff and per-vendor priors. Full plan (backends, ladder, on-path/Docker reality,
transports HTTP/HTTPS/BLE/Zigbee, data model, web UX, phased 6.0–6.6): [`docs/CAPTURE-DESIGN.md`](CAPTURE-DESIGN.md).

- [x] **6.0 — Discovery + backend detection + provenance schema.** The capture lane's foundation, gated by
  `FIRMLAB_CAPTURE` (off → nothing touches the wire). A **backend registry** (`capture/backends.ts`) auto-detects
  the six backends the way `tools.ts` detects tools — read-only probes of PATH (mitmproxy/bettercap), this
  process's Linux capabilities (NET_ADMIN/NET_RAW for spoof positioning), attached USB (BLE/Zigbee sniffer VID/PIDs),
  and serial adapters — each degrading honestly with the reason and what would unlock it, never a fabricated
  capability. A **discovery provider** (`providers/discover.ts`, pure parsers + a runner) sweeps the LAN passively
  (arp-scan preferred, nmap fallback), maps MAC → vendor by OUI, enriches with mDNS (avahi-browse), and makes a
  never-asserted device-type guess with a confidence. New non-image-scoped tables (`capture_sessions`, `devices`)
  + the `capture_provenance` schema; routes `GET /capture/{status,backends,devices}` + `POST /capture/discover`
  (gated by the flag AND a per-scan operator acknowledgement) + `GET /capture/discover/:scanId`; a top-level
  **Capture** web section (backend table + honest transport ceiling + device radar). Discovery is passive —
  nothing is intercepted. Validated end-to-end: backends probe honestly, the ack/flag gates return 400, and a
  scan with no arp-scan/nmap degrades to a session `error` with the reason (zero fabricated devices).
- [x] **6.1 — Network capture (proxy) + auto-ingest.** The core acquire→analyze loop. `providers/flowscore.ts`
  scores each intercepted response 0..100 for "is this an OTA blob?" from `@firmlab/core` magic signatures +
  entropy + Content-Type + size + URL heuristics (pure, unit-tested). `capture/proxy.ts` runs mitmproxy (mitmdump)
  on-path with an embedded addon that logs flow metadata to a manifest + saves plausibly-firmware bodies; FirmLab
  does the authoritative scoring, persists each flow (`capture_flows`), and stages the candidates as carved.
  `capture/ingest.ts` feeds a carved blob through the EXACT upload intake (`analyzeImageBuffer` → an `images` row →
  structure/secrets/corpus) and writes a `capture_provenance` row linking the image to how it was acquired. Routes
  `POST /capture/session` (arm, flag + ack) + `GET /capture/session/:id` (status + live scored flow feed) +
  `POST …/ingest` + `POST …/teardown` (guaranteed, time-boxed). The Capture web section gains a per-device Capture
  button, a scored flow feed, and one-click ingest. Dockerfile.tools adds mitmproxy. **Validated end-to-end against
  the real API:** a synthetic captured SquashFS OTA scored 100 → carved → ingested → a normal analyzed workbench
  image + a `capture_provenance` row (endpoint/transport/tls); an HTML flow scored 0 and was rejected. The live
  mitmdump spawn over a positioned proxy is validated on the deploy (like the emulation ladder).
- [x] **6.2 — Active on-path (spoof) + LAN capture agent.** So capture works without router config, and so it
  works from Docker. `capture/spoof.ts` arms bettercap to ARP-spoof a SINGLE target onto FirmLab (availability =
  the on-path-spoof backend probe; pure `buildBettercapArgs`), composed with the 6.1 proxy — a session now chooses
  positioning (operator gateway → nothing spawned · active spoof · honest `manual` when neither is available) and
  teardown restores ARP on every path. The LAN capture agent (design §5c, the durable Docker answer):
  `capture/agent.ts` + token-authed `POST /capture/agent/{session,flow}` land a remote agent's carved flows into a
  session (scored by the same `flowscore`, ingestable by the same path); `apps/api/scripts/capture-agent.mjs` is
  the reference agent that runs mitmproxy + bettercap on a LAN box and streams candidates over the token channel.
  Off unless `FIRMLAB_CAPTURE_AGENT_TOKEN` is set. **Validated vs the real API:** an agent session + a streamed
  SquashFS OTA scored 100 → carved → ingested; a tokenless request → 401; positioning honestly degraded to `manual`
  on a host without spoof caps.
- [x] **6.3 — Capturability ladder + preflight + pinning metadata + Frida unpin template.** `capture/preflight.ts`
  (pure, unit-tested): for a chosen target it ranks the viable capture strategies cheapest-and-most-complete first
  (network http/https need positioning + proxy; a radio transport needs its dongle and is its own position) and
  states the honest **acquisition proof-state** ceiling — `captured_plaintext` / `metadata_only` /
  `blocked_by_pinning` / `blocked_needs_hardware` — with what would unlock more. `realizedCeiling` computes a live
  session's ceiling from its ACTUAL flows, so "pinned" is a fact observed on the wire (the proxy addon now logs a
  `tls-pinned` flow when a client refuses the CA), not a guess. `capture/frida.ts` ships a universal Android
  TLS-unpinning Frida template, served at `GET /capture/frida-unpin`; `GET /capture/preflight/:deviceId` returns
  the capturability card. Web: a per-device **Preflight** button renders the ladder + ceiling + unlock hint, and a
  pinned session surfaces the Frida download. **Validated vs the real API:** the preflight honestly returns
  `metadata_only` + "Install mitmproxy" on a host with no proxy/positioning; the Frida template downloads (3 hooks:
  SSLContext / OkHttp CertificatePinner / Conscrypt TrustManagerImpl).
- [ ] **6.4–6.6** — BLE backend (nRF52840 DFU) · Zigbee backend (OTA cluster) · learning surface (OTA timeline +
  cross-version diff + per-vendor priors).

**Phase 3 — decision nodes (implemented).** The agent now *chooses branches* on top of the deterministic
skeleton, never the mechanics. The orchestrator (`agent/session.ts`) drives triage ① → deterministic extraction
(if the agent chose it, via the same job the user clicks) → deterministic preflight → target-selection ② →
pause for human approval before any emulation. Each node writes an `agent_step` (structured input, decision,
rationale, tokens) to an auditable transcript; the governor (`agent/governor.ts`) halts the run at the first
cap hit. Node ② is hard-bounded by the preflight: a requested emulation rung is *clamped* down to what the
deployment can actually run (`clampRung`), so the honesty ceiling is enforced in code. Env: `FIRMLAB_AGENT_MAX_STEPS`
(8), `FIRMLAB_AGENT_MAX_TOKENS` (120000), `FIRMLAB_AGENT_MAX_USD` (0.5), `FIRMLAB_AGENT_MAX_SECONDS` (300). Web:
the **Agent** tab shows the live transcript, the governor gauge, and the approve/decline emulation gate.
Validated end-to-end in the firmware image (a mock LLM stands in for the key-less environment): flag-off inert,
full session lifecycle, live rung clamping, real binwalk extraction + qemu-user emulation, and the retention guard.

Full plan — the deterministic-skeleton architecture, the five agent nodes, the emulation ladder, the
proof-state machine, the persistent corpus, the copilot provider config (§10), and the phase roadmap:
[`docs/AGENT-DESIGN.md`](AGENT-DESIGN.md).
