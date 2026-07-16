# FirmLab architecture

## Layers

```
┌──────────────────────────────────────────────────────────────┐
│ apps/web  (React + Vite)                                      │
│   Dashboard · Overview · Structure · Entropy · Filesystem ·   │
│   Secrets · Simulation · Capabilities                         │
│   Visual components: EntropyChart, StructureMap, FsTree,      │
│   SimulationMenu (all pure SVG/DOM, no chart lib)             │
└───────────────▲──────────────────────────────────────────────┘
                │ same-origin /api (loopback)
┌───────────────┴──────────────────────────────────────────────┐
│ apps/api  (Fastify + node:sqlite)                             │
│   routes: images · analysis · jobs · emulate · tools          │
│   providers: extract (binwalk), emulate (qemu/renode planner  │
│     + user-mode runner), jobs (in-proc runner)                │
│   store: images + cached analysis + jobs (SQLite, WAL)        │
│   tools: runtime capability detection                         │
└───────────────▲──────────────────────────────────────────────┘
                │ pure functions (bytes in, structured data out)
┌───────────────┴──────────────────────────────────────────────┐
│ packages/core  (@firmlab/core — zero external deps)           │
│   entropy · signatures · structure · strings · filesystem ·   │
│   binwalk (output parser) · analyze (one-shot bundle)         │
└──────────────────────────────────────────────────────────────┘
```

## Design decisions

**Deterministic core, optional tools.** Everything that can be computed from bytes alone lives in
`@firmlab/core` and is unit-tested. External tools (binwalk, radare2, QEMU…) are providers behind runtime
detection, so the product degrades gracefully instead of hard-failing when a tool is absent. This is the
inverse of a tool-first design: the workbench is useful with nothing installed and *better* with the full
image.

**Static analysis on upload, cached.** The moment an image lands, the API runs the core bundle
(`analyzeBuffer`) and persists identity + analysis JSON. Every view then loads instantly from cache; the image
bytes are only re-read for extraction/emulation. Entropy uses an adaptive window so the sample count stays
~2048 regardless of image size.

**Jobs for anything slow.** Extraction and emulation run as persisted jobs (SQLite rows) with streamed logs,
so the UI polls status without blocking a request and results survive a restart.

**Emulation as a planner + a runner.** `planEmulation` turns identity (+ extracted rootfs) into ranked,
arch-aware recipes with concrete commands and a runnable flag. Only user-mode QEMU is auto-executed (bounded
by a timeout + output cap); full-system boot and Renode need per-image kernel/platform assembly and are
surfaced as guided recipes rather than one-click actions that would silently fail.

**Local-only, enforced in three places.** The API defaults to `127.0.0.1`; the Vite dev server binds
loopback; the compose publish is `127.0.0.1:8799:8799`. In Docker the in-container bind is `0.0.0.0` (required
for port publishing) but `FIRMLAB_LOOPBACK_PUBLISH=1` keeps the health/indicator honest.

## Data model

- `images` — id, filename, path, size, sha256, status, identityJson, analysisJson
- `jobs` — id, imageId, kind (`extract|binwalk|sbom|emulate|decompile`), status, log, resultJson, error

## Extending

- **New signature** → add a rule to `SIGNATURE_RULES` in `packages/core/src/signatures.ts` (+ a test).
- **New tool** → add a `ToolSpec` in `apps/api/src/tools.ts`; it appears in Capabilities automatically.
- **New emulation mode** → add a recipe branch in `apps/api/src/providers/emulate.ts`.
- **New analysis view** → add an endpoint in `routes/analysis.ts` and a tab in `apps/web/src/pages/ImageDetail.tsx`.
