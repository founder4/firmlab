# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

FirmLab is a local-first firmware analysis workbench: a pure TypeScript analysis engine, a Fastify API that
wraps optional external tools (binwalk, radare2/Ghidra, syft/grype, gitleaks, QEMU, Renode, AFL++, angr,
chipsec, gdb-multiarch) as runtime-detected *providers*, and a React workbench. pnpm workspaces, Node ≥ 22
(uses `node:sqlite`), ESM, strict TypeScript everywhere.

## Commands

```bash
pnpm install
pnpm --filter @firmlab/core build     # ALWAYS build core first — api/web import it from dist/

pnpm build            # pnpm -r run build
pnpm check            # pnpm -r run check  (typecheck only; api/web build core first themselves)
pnpm test             # pnpm -r run test   (vitest, all three packages)
pnpm biome            # lint + format check       (pnpm biome:fix to write)

pnpm dev:api          # node --watch apps/api/dist/index.js  → 127.0.0.1:8799 (needs `--filter @firmlab/api build` first)
pnpm dev:web          # vite → 127.0.0.1:5174, proxies /api and /health to :8799
```

Single test file / pattern (extra args pass straight to `vitest run`):

```bash
pnpm --filter @firmlab/api  run test dynprobe          # matches src/providers/dynprobe.test.ts
pnpm --filter @firmlab/core run test signatures
pnpm --filter @firmlab/web  run test SimulationMenu
```

Tests live beside the code in `apps/api/src/**/*.test.ts` and `apps/web/src/**/*.test.tsx`; core's are in
`packages/core/test/`. There are no vitest config files except `apps/web/vite.config.ts` (jsdom + Testing
Library).

**Real-tool validation.** Unit tests deliberately never require the actual tool. Anything tool-backed is
validated in-container instead:

```bash
docker run --rm firmlab-firmware node apps/api/scripts/integration.mjs   # extract → sbom → gitleaks → decompile
node apps/api/scripts/mock-llm.mjs                                       # canned LLM for driving the agent
API_BASE=… FW_PATH=… node apps/api/scripts/agent-renode-e2e.mjs          # agent → Renode RTOS boot, end to end
```

## Architecture

Three layers, dependency arrow pointing down. Web talks only to the API; the API composes core; core knows
nothing about either.

- **`packages/core` (`@firmlab/core`)** — pure, zero runtime deps: entropy, signature carving, structure map,
  strings/secrets, filesystem model, MCU fingerprint, and the shared domain types (`FirmwareClass`,
  `Architecture`, `ProofState`, `Finding`). Device-class inference lives in `structure.ts`. Anything computable
  from bytes alone belongs here, and must stay pure and unit-tested.
- **`apps/api`** — Fastify + `node:sqlite` (WAL). `routes/` (thin HTTP) → `providers/` (the work) → `store.ts`
  (persistence). `tools.ts` answers "what can this deployment do?" by probing binaries at runtime.
- **`apps/web`** — Vite + React, HashRouter, hand-rolled SVG/DOM visuals (no chart library), all styling in the
  single `src/theme.css` token system. `src/api.ts` is the typed client; `pages/ImageDetail.tsx` maps URL
  sections to analysis panels.

Flow: upload → `analyzeImageBuffer` (core bundle, entropy window sized so sample count stays ~2048) → identity
+ analysis persisted as JSON on the image row, so every view loads from cache and the raw bytes are re-read only
for extraction/emulation. Anything slow runs as a **job** (`providers/jobs.ts`): a SQLite row moving
queued → running → done/error with streamed log lines, bounded by `FIRMLAB_MAX_CONCURRENT_JOBS` (default 2), so
results survive a restart and the UI polls instead of blocking.

### The proof-state discipline — the project's central invariant

Every finding carries a `ProofState` and code, never a model, decides it:

`needs_runtime_reproduction` (a lead) · `static_confirmed` (the property is literally in the bytes) ·
`confirmed_in_emulation` (proves the sandbox, **never** the physical device) · `confirmed_full_system` ·
`blocked_by_platform` / `blocked_by_security` (the question was asked and could not be answered — **not** a
negative) · `false_positive`.

Two rules follow, and most of the codebase's shape exists to enforce them:

1. **An empty findings list never means "clean."** `providers/coverage.ts` computes, per image, which stages the
   device class routes to, which actually ran, and the sentence stating what the count does and does not cover.
   It reads `specsForClass` — the same plan the autonomous scan executes — so the banner and the scan cannot
   disagree.
2. **Absence of a tool is not absence of a problem.** A provider whose tool is missing returns
   `available: false` / degrades honestly; it never fabricates or silently skips.
3. **An empty result must say why.** `providers/extract-diagnose.ts` is the worked example: `rootfsPath: null`
   covered three situations needing three different responses (volumes came out but none is a rootfs; a
   filesystem was carved and could not be opened; nothing came out), so it reads what is on disk and returns the
   verdict. A truncated image and a missing extractor produce the *same* message from unsquashfs and need
   opposite responses, so the diagnosis separates them from the bytes.
4. **A bound is not an answer.** Any cap that truncates (findings, ELFs scanned, probe budget) states what it
   dropped and by what rule — and it must not truncate by arrival order, which makes the *set* an artifact of
   directory layout. See `selectFindings` in `binvuln.ts`.

**Claiming a CVE.** The curated table in `component-cve.ts` matches a fingerprinted version against a
hand-verified range. Ranges come from the NVD CVE API queried against the version in hand, never from recall, and
where NVD's CPE range is open below the rule sets its own floor — an unbounded-below range is a CPE modelling
artifact, not evidence that a decade-older codebase contains the bug. A CVE NVD backs only with an open range and
no enumerated CPE is left out (see the rejected CVE-2016-2148 comment). `sbom`/grype applies a broader standard
on the same images; both are labelled by source.

### Findings ledger

`syncFindings(imageId, source, drafts)` deletes and re-inserts only that `source`'s rows, so re-running a
provider is idempotent and leaves other sources untouched. Per-binary results use a `binary:<path>`-style source
so distinct targets don't clobber each other (see `symreach`, where a manual probe's source also carries the
sink set — a bug fixed once already). Normalizers in `findings-normalize.ts` are pure; `findings.ts` binds them
to the store.

### The autonomous scan (`opacidad`, W9)

`opacidad.ts` is the orchestrator: from the device class it plans an ordered chain of workers, runs them feeding
each stage's output into the next, re-plans dynamically from *leads* (`opacidad-leads.ts` — e.g. a reachable
sink becomes a `reproduce-crash` dynprobe spec), and composes findings into an attack-path narrative
(`opacidad-narrative.ts`). Routing is pure data in `opacidad-plan.ts` (`specsForClass`), unit-testable without
the store. It **chains existing providers** rather than adding analysis; a class whose deep worker isn't built
is reported `not-built`, a stage lacking a rootfs is `skipped`.

### Optional layers, each behind its own flag

- `FIRMLAB_AGENT=1` (+ an LLM key) — copilot and the agent skeleton (`agent/`): deterministic orchestrator, LLM
  only at the judgment nodes, `governor.ts` hard caps (steps/tokens/USD/wall-time), human-approval gate unless
  the blast radius is contained by `providers/isolate.ts`. `llm.ts` is raw `fetch`, no SDK; DeepSeek by default,
  OpenAI-compatible and Anthropic also supported.
- `FIRMLAB_RESEARCH=1` — the only internet-touching analysis lane (`research/`): OSV/NVD/KEV, provenance,
  security.txt, behind a domain allowlist and an egress ledger. Deliberately a *separate* flag from the agent.
- `FIRMLAB_CAPTURE=1` — the on-the-wire lane (`capture/`): LAN discovery, mitmproxy OTA interception, BLE/Zigbee.
- `apps/api/src/mcp/server.ts` — the workbench exposed as an MCP server over stdio, so an agent can drive the
  providers and get answers already shaped with their proof state and coverage (`mcp/format.ts`).

With every flag off: no network, no cost, deterministic behaviour.

## Adding things

- **New signature** → a rule in `packages/core/src/signatures.ts` + a test.
- **New tool** → a `ToolSpec` in `apps/api/src/tools.ts`; it appears in Capabilities automatically. Set
  `timeoutMs` for slow probes (a JVM or an angr import will be misreported as absent under the 4 s default).
- **New provider** → `providers/<name>.ts` with the decision/parsing logic **pure and exported** (that's what the
  unit tests exercise) and a thin runner that shells out; a route in `routes/<name>.ts` that `startJob`s it and
  calls `syncFindings` under a stable source; register the route in `apps/api/src/index.ts`. Providers are pure
  w.r.t. findings — the route (or W9) syncs them, using the same source string both ways.
- **Pure logic that a test must reach cannot live in a module that imports `store.js`** — vitest cannot resolve
  `node:sqlite` and the test file will not even load. That is why `opacidad-plan.ts`, `opacidad-leads.ts`,
  `findings-normalize.ts`, `extract-diagnose.ts` and `mergeNvdCandidates` (in `providers/nvd.ts`, not
  `research/run.ts`) sit where they do. Put the decision in a sibling module and let the store-bound one bind it.
- **New analysis view** → an endpoint plus a section in `apps/web/src/pages/ImageDetail.tsx` and the nav group in
  `App.tsx`.

## Traps this codebase has already paid for

- **A comment that was true when written.** `dynprobe-run.ts` pinned one gdb port because "one probe runs at a
  time per job" — true per job, false once W9 scheduled probes in two concurrent scans, and the second probe then
  reported a platform block. `parseGdbOutput` inferred "attached" from a `Remote debugging using` line that
  `gdb -batch` never prints, so an attached-and-clean run was reported as a harness failure. Both passed their
  tests, because the fixtures were written from the same assumption as the code.
- **A literal NUL byte in a source file passes every gate.** `tsc`, `biome` and `vitest` all accept it silently;
  what it breaks is everything else — `file` reports the source as `data`, and **grep skips the file without
  saying so**, which is how a large, correct change can look like it was never made. It arrives naturally: a NUL
  is a good composite-map-key separator because it cannot occur in the fields being joined. Write it as `\u0000`,
  never as the byte. `pnpm biome` now runs `scripts/check-nul.sh` first, which refuses one and names the line via
  `cat -v` (grep cannot). It caught three instances on 2026-07-28 alone, one of them shipped since `8b159f6` and
  one inside the guard's own comment block — a file is at its most dangerous *before* its first commit, which is
  why the check scans untracked files too.

- **A guard is only as good as its SUCCESS path, and that is the path nobody runs.** Four instances in one day.
  `deploy.sh`'s anti-squatter check assigned an `lsof` pipeline under `set -euo pipefail`, and lsof exits 1 when
  it matches nothing — so a *clean* port aborted every deploy while a squatted one sailed through; it stayed
  invisible because the zombie it was written for was always listening. The `ERR` trap added to surface that was
  itself not inherited into functions or subshells without `set -E`, so it printed nothing for the very bug it
  existed for. `teardown()` in `emulate-system.ts` shells out to `pkill`, **which is not installed in the
  container**, and caught the ENOENT in the same branch as "matched nothing" — logging *"Teardown complete
  (emulators killed)"* while sweeping nothing, for as long as the module has existed. Exercise the branch where
  the guard finds nothing wrong, and check that a tool you shell out to is actually there.

- **A required field is a claim about data you may not own.** Provider results are JSON persisted on a job row and
  re-read for as long as the image exists, so a stored result is data written by an OLDER build. Declaring a
  newly-added field required made the web types assert something they could not know; `nvd.uncheckedIdentities.map`
  threw on a result stored two commits earlier and took down the whole image view for 3 of 4 images. **A field
  added to a persisted result type is optional forever** — which turns the crash into a compile error and, in
  that instance, located it immediately.

- **A fixed port is a shared resource pretending to be a local one.** Paid for twice: `dynprobe-run.ts` pinned gdb
  port 14500, and `emulate-system.ts` based its qemu forwards on 8080. In both cases a survivor from another run
  owned the port, and in the second the probe connected to *it* and returned `confirmed_full_system` for a boot
  that had reached `NR_IRQS`. Ask the OS for a free port per run.
- **Validating against real bytes finds what tests do not.** Every defect above surfaced by running the thing
  in-container against a real image, and several were introduced *by the fix for the previous one* (a readiness
  check that connected to a gdbstub consumed the single accept it was checking for). Run it, read the output, and
  treat the first result as a hypothesis.

- **A green suite proves the code is consistent with its fixtures, not that it can run.** The full-system rung had
  passing unit tests while being unable to boot anything at all: no code path built the disk image it was handed,
  the kernel filename was `vmlinux.${arch}.4` where firmadyne ships `vmlinux.mipseb.4`, big-endian MIPS was given
  the little-endian emulator, and `-device e1000` demanded a ROM the Debian packages do not ship. **Four wrong
  assumptions stacked, each hidden behind the one in front**, and each surfaced only when the one before it was
  fixed — so the first error message you get is rarely the only thing wrong. The same run then exposed three
  defects in the fix itself, including a console cap that evicted the very boot markers the verdict is read from.
  Budget for the second, third and fourth failure, and re-run after every fix.

## Data & deployment

Everything persists under one data root (`FIRMLAB_DATA_DIR`, default `./data`): `images/`, `extract/`,
`capture/`, `firmlab.db`. Local-only is enforced in three places — API defaults to `127.0.0.1`, the Vite dev
server binds loopback, the repo compose publishes `127.0.0.1:8799:8799`. In Docker the in-container bind is
`0.0.0.0` (required for publishing) and `FIRMLAB_LOOPBACK_PUBLISH=1` keeps the UI's local-only indicator honest.

Image chain is **inverted on purpose** — the multi-GB toolchain is the base, the app goes on top:

```
Dockerfile.tools    → firmlab-tools:latest      (rebuild only when a tool recipe changes; --tools)
Dockerfile.firmware → firmlab-firmware:latest   (FROM firmlab-tools + the built app)   ← deployed
Dockerfile          → firmlab:latest            (lean, no tools, for local dev)
```

`scripts/deploy.sh` builds, tags, rolls out and verifies in one step (`--check` reports drift only). Every image
is stamped with its git commit (label + `FIRMLAB_BUILD` → `/health`), because "the container matches the image"
proves internal consistency, not freshness — see the 2026-07-18 incident in `docs/DEPLOYMENT.md`. The deployed
homelab container publishes no host port, so reach it from inside:
`docker exec firmlab curl -fsS http://127.0.0.1:8799/health`. Beware a stray `pnpm dev:api` squatting on host
`:8799` — `deploy.sh` checks for exactly that.

## Conventions

- Conventional commits, lowercase subject, often scoped (`fix(dynprobe): …`). Frequently a `docs:` commit
  records an in-container validation right after the feature. **No `Co-Authored-By` or other attribution
  trailers** — the history has been stripped of them once already.
- Module-level doc comments are load-bearing here: most files open with a paragraph explaining *why* the design
  is what it is, and what it refuses to claim. Match that when adding files.
- Record anything surfaced but not implemented in `docs/BACKLOG.md` as you go; the prioritized rationale lives in
  `docs/METHODOLOGY-GAPS.md` (FSTM/ISTG coverage mapping).
- Biome: single quotes, semicolons, trailing commas, 2-space indent, 120 cols. `tsconfig.base.json` is strict
  plus `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes` and `verbatimModuleSyntax` — relative imports
  need the `.js` extension in api/core.

Docs: `docs/ARCHITECTURE.md` (layers), `docs/AGENT-DESIGN.md` (the autonomy plan, Spanish),
`docs/AUTONOMOUS-WORKERS.md` (the app-vs-autonomous experiment that justifies the W0–W9 workers),
`docs/CAPTURE-DESIGN.md`, `docs/DEPLOYMENT.md` (Spanish), `docs/ROADMAP.md`.
