# FirmLab roadmap

Status of the phased development plan. Checked items ship in this branch.

## Phase 0 — Deploy consolidation & honesty
- [x] Docker build fixes so the image actually builds & runs end-to-end:
  - `CI=true` in the build stage (pnpm 11 aborted a modules-dir purge without a TTY).
  - Copy `apps/api/node_modules` into the runtime stage (pnpm workspace deps live there, not the hoisted root).
  - `radare2` installed from the official `.deb` per build arch (dropped from Debian bookworm repos).
  - `gitleaks` downloaded for the build arch (was hard-pinned to `x64`, broke on arm64).
- [x] **Health indicator "auth-gated" state** — `FIRMLAB_TRUSTED_PROXY=1` makes the API report `trustedProxy`, and the
  UI shows `🔒 auth-gated` instead of the alarming `⚠ bound to network` when the workbench sits behind an
  authenticating reverse proxy (Traefik + forward-auth).
- [x] First `apps/web` tests (pure client helpers: `fmtBytes`, `fmtHex`, `categoryColor`).
- [ ] Register `firmlab` in the homelab `boot-reconcile.sh` (ops task, outside this repo).

## Phase 1 — Frontend + mobile browser support
- [x] Responsive app shell: the sidebar collapses into an off-canvas **drawer** with a hamburger toggle and a
  backdrop on narrow viewports; desktop layout unchanged.
- [x] `100dvh` shell height so the mobile browser's URL bar doesn't clip the layout.
- [x] Breakpoints at 860px (tablet) and 520px (phone): single-column stat/grids, tighter padding, larger touch
  targets on nav items, tabs, and buttons.
- [x] Wide tables wrapped in horizontal-scroll containers (`.table-wrap`) so the page body never scrolls sideways.
- [ ] Touch tooltips on the entropy chart (currently mouse-only; not broken on touch, just no hover readout).
- [ ] PWA-lite: `manifest.webmanifest` + icons for "add to home screen" standalone display.

## Phase 2 — Wire the installed toolchain
- [x] **SBOM & CVEs** tab: `syft` inventories the extracted rootfs, `grype` matches N-day CVEs; severity tally,
  CVE table (with fix versions), and package list. Runs as a persisted job; degrades gracefully when a tool
  or the rootfs is absent.
- [x] **Binaries** tab: `radare2` static triage of a chosen rootfs binary — headers/arch, NX/canary/PIC, imports,
  symbols, and strings. Path is confined to the extracted rootfs (no traversal).
- [ ] `gitleaks` deep secret scan of the extracted rootfs, folded into the Secrets tab (today Secrets is the
  core's raw-image string heuristic only).
- [ ] Ghidra `analyzeHeadless` decompilation (optional heavy layer; image ships without it by default).

## Phase 3 — Analysis depth
- [ ] Diff two firmware images (packages / CVEs / secrets / structure deltas across versions).
- [ ] Guided full-system QEMU boot (kernel/dtb assembly) with a console, beyond today's user-mode auto-run.
- [ ] Per-image findings report export (HTML/PDF).

## Phase 4 — Platform
- [ ] Multi-image management: tags, search, retention/cleanup of the `firmlab-data` volume.
- [ ] Interactive emulation: shell into the emulated rootfs, probe network services.
