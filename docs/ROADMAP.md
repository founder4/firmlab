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
| F9 | Full-system QEMU & Renode recipes are **non-runnable placeholders** | `apps/api/src/providers/emulate.ts:96,115` | Only user-mode emulation actually runs |
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
auto-executed under netns+rlimits with no approval — proof-state honest. RTOS/Renode and UEFI/chipsec are
recognized (preflight detects Renode) but not yet integrated — no faked coverage.

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
DeepSeek brief. Env: `FIRMLAB_RESEARCH`, `FIRMLAB_RESEARCH_ALLOWLIST`, `FIRMLAB_RESEARCH_TIMEOUT_MS`. Not yet:
5.2 (published key provenance), 5.3 (disclosure contact discovery + report draft), sources beyond OSV.

### Known limitations & tech debt (pay down gradually)

Recorded so they're solved piece by piece, not forgotten:

- **AFL++ fuzzing is wired but unexercised.** `providers/fuzz.ts` builds the command and runs under isolation, but
  the heavy AFL++ layer isn't baked into the image, so no reproduced crash has actually upgraded a candidate.
  *Next:* an opt-in AFL++ Docker layer + per-class harness; validate that a real crash → `confirmed_in_emulation`.
- **Isolation needs `CAP_SYS_ADMIN` for the network namespace.** Without it, `unshare -n` fails and isolation
  degrades to `partial` (rlimits only) → the approval gate is kept. *Next:* rootless netns (`unshare -rn` /
  slirp4netns) so `full` isolation works without the broad cap; decide the homelab compose capability posture.
- **Node ④'s trigger isn't delivered to the target.** The isolated auto-run executes the binary generically
  (runs/crashes) rather than driving the constructed trigger into the sink, so confirmation is coarse. *Next:*
  per-class harnesses (CGI env, stdin, socket) that actually deliver the trigger, enabling an honest
  `static_confirmed` → `confirmed_in_emulation` upgrade tied to the specific candidate.
- **RTOS/Renode and UEFI/chipsec not integrated** — only detected. *Next:* a Renode provider for Cortex-M and a
  chipsec pass for UEFI images.
- **Node ⑤ (synthesis) not wired into the session.** The Phase-2 copilot covers ③/⑤ read-only, but the session
  doesn't yet close with a cited narrative over the confirmed findings. *Next:* run ⑤ as the session's final step.
- **The local `firmlab-firmware:latest` image is one fix behind** (Phase 4 validated via a mounted fresh dist); a
  rebuild/deploy bakes it.

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
