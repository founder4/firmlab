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

## Phase 3 — Analysis depth & trustworthy identity (start here)

- [ ] **F1 — Arch/endianness refinement.** Add a uImage `ih_arch` decoder (U-Boot header byte 29) to `inferArch`;
  after extraction, decode the first rootfs ELF's `e_machine` and persist a refined identity. *Where:*
  `packages/core/src/structure.ts`, `apps/api/src/providers/extract.ts`, image identity persistence in `store.ts`.
  *Accept:* a uImage+squashfs sample resolves a concrete arch; emulation menu marks the matching QEMU recipe runnable.
- [ ] **gitleaks deep scan (F4).** New `providers/gitleaks.ts` + `routes/secrets` job; fold results into the Secrets tab
  alongside the core heuristic (source file + rule + line). *Accept:* verified in the firmware image against a rootfs
  with a planted key; degrades gracefully when absent.
- [ ] **Firmware diff.** Compare two images: package/CVE deltas, added/removed/changed rootfs files (by hash),
  structure & identity changes. New API route + a diff view. *Accept:* two versions of one firmware produce a readable delta.
- [ ] **Findings report export.** Per-image HTML (self-contained) summarizing identity, structure, secrets, SBOM/CVEs,
  triage. *Accept:* one-click download; opens standalone.
- [ ] **Ghidra decompilation (F5, optional heavy).** Wire `analyzeHeadless` as a decompile job behind a capability flag;
  keep it opt-in (image ships without Ghidra by default).

## Phase 4 — Reliability & platform

- [ ] **Bounded job queue (F2).** Cap concurrent jobs (env-configurable), queue the rest, surface queued state in the UI.
  *Where:* `apps/api/src/providers/jobs.ts` + jobs route/UI. *Accept:* N+1 heavy jobs run at most N at once.
- [ ] **Data retention & quota (F3).** Configurable max age / max total size for images+extracts; a sweep on startup and
  on a timer; show volume usage in the UI. *Accept:* old artifacts pruned; usage visible.
- [ ] **Multi-image management.** Tags, search/filter, sort on the Dashboard; bulk delete. *Where:* `pages/Dashboard.tsx`,
  images route.
- [ ] **Signature pack expansion (F6).** Add device tree (DTB), kernel config (`IKCFG`), more vendor/bootloader and
  key/cert magics, each with a unit test. *Where:* `packages/core/src/signatures.ts` + tests.
- [ ] **Interactive emulation.** Beyond user-mode auto-run: a console/shell into the emulated rootfs; guided full-system
  QEMU boot (kernel/dtb assembly) making F9 recipes actually runnable.

## Phase 5 — Quality, testing & hardening

- [ ] **Web component/interaction tests (F7).** Add jsdom + @testing-library; cover the tab router, the drawer toggle,
  and job-polling panels (mocked API). *Accept:* CI-meaningful coverage of the interactive surface.
- [ ] **E2E fixture & integration test (F8).** Commit a small, license-clean synthetic firmware (or a build script) and an
  integration test that runs extract → sbom → triage in the firmware image. *Accept:* one command proves the chain.
- [ ] **API defense-in-depth (F10).** Optional in-process token/rate-limit + security headers, so a misconfigured proxy
  isn't the only guard. *Accept:* opt-in, off by default for pure-local use.
- [ ] **Structured errors & toasts.** Replace ad-hoc `String(err)` panels with consistent error surfaces and retry.

---

## Suggested execution order for the long session

1. **F1 arch refinement** (unblocks emulation UX; touches core+api, well-contained).
2. **gitleaks deep scan** (completes the Secrets story; mirrors the SBOM/triage job pattern).
3. **Bounded job queue (F2)** + **retention/quota (F3)** (reliability before piling on features).
4. **Firmware diff** (headline analysis feature).
5. **Web tests + e2e fixture (F7/F8)** (lock in everything above).

Each item is independently shippable and verifiable in the firmware image, so the session can commit in slices.
