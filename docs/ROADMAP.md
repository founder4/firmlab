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
- [x] **Multi-image management — search.** Filter by filename/arch/class on the Dashboard. *(wave 2)*
- [ ] **Multi-image management — tags & bulk delete.** *Next.*
- [x] **Signature pack expansion (F6).** +12 magics (ext/f2fs/erofs/cramfs-be, IKCFG/bzImage/arm64 Image,
  lzop/7z/rar/android-sparse/cpio-odc), offset-anchored, each tested. *(wave 2)*
- [ ] **Interactive emulation (F9).** Console/shell into the emulated rootfs; guided full-system QEMU boot
  (kernel/dtb assembly) making the system-qemu recipes runnable. *Deferred — large, per-image platform assembly.*

## Phase 5 — Quality, testing & hardening

- [x] **Web component/interaction tests (F7).** jsdom + @testing-library; cover the Dashboard filter, the mobile
  drawer toggle, and the auth-gated health pill. *(wave 3)*
- [x] **Mobile polish.** PWA manifest + icon + theme-color (add-to-home-screen); touch tooltips on the entropy chart. *(wave 3)*
- [ ] **E2E fixture & integration test (F8).** Commit a synthetic firmware (or build script) + an integration test that
  runs extract → sbom → triage in the firmware image. *Next.*
- [ ] **API defense-in-depth (F10).** Optional in-process token/rate-limit + security headers. *Next.*
- [ ] **Structured errors & toasts.** Replace ad-hoc `String(err)` panels with a consistent error surface + retry. *Next.*

---

## Shipped this session (waves 1–3)

Arch refinement · gitleaks deep-scan · firmware diff · report export · bounded job queue · data retention/quota ·
image search · +12 signatures · web component tests · PWA + entropy touch. All verified against real tools in the
firmware image where applicable; 70+ tests; biome clean; committed in slices.

## Remaining backlog (next session)

Ghidra (F5) · interactive/full-system emulation (F9) · e2e Docker fixture (F8) · API defense-in-depth (F10) ·
structured errors/toasts · image tags & bulk delete · content-hash file diff.
