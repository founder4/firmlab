# FirmLab architecture

## Layers

```
┌──────────────────────────────────────────────────────────────────┐
│ apps/web  (React + Vite, HashRouter)                              │
│   Dashboard · Overview · ImageDetail (Structure · Entropy ·       │
│   Filesystem · Secrets · SBOM/CVE · Simulation) · Agents ·        │
│   Corpus · Capture · Capabilities · Settings                      │
│   Visual components: EntropyChart, StructureMap, FsTree,          │
│   SimulationMenu, SbomGraph… (all pure SVG/DOM, no chart lib)      │
└───────────────▲────────────────────────────────────────────────────┘
                │ same-origin /api (loopback)
┌───────────────┴────────────────────────────────────────────────────┐
│ apps/api  (Fastify + node:sqlite)                                  │
│   routes/    46 thin HTTP modules → startJob + syncFindings        │
│   providers/ 86 modules — the actual work, runtime-detected tools  │
│     extract · sbom · gitleaks · diff · ghidra · emulate · renode · │
│     chipsec · fwhunt · fuzz · isolate · taint · trigger ·          │
│     preflight · report · keys · provenance · osv · kernelposture…  │
│   agent/     session orchestrator, decision nodes, governor        │
│              (FIRMLAB_AGENT)                                       │
│   research/  provenance/OSV/security.txt, egress ledger            │
│              (FIRMLAB_RESEARCH)                                    │
│   capture/   LAN discovery, mitmproxy OTA, BLE/Zigbee reassembly    │
│              (FIRMLAB_CAPTURE)                                     │
│   mcp/       the same providers over the Model Context Protocol    │
│   store.ts:  images · jobs · findings · corpus · agent sessions    │
│              (SQLite, WAL)                                         │
│   tools.ts:  runtime capability detection                          │
└───────────────▲────────────────────────────────────────────────────┘
                │ pure functions (bytes in, structured data out)
┌───────────────┴────────────────────────────────────────────────────┐
│ packages/core  (@firmlab/core — zero external deps)                │
│   entropy · signatures · structure · strings · filesystem ·        │
│   MCU fingerprint · binwalk (output parser) · analyze (bundle)     │
└──────────────────────────────────────────────────────────────────┘
```

## Design decisions

**Deterministic core, optional tools.** Everything that can be computed from bytes alone lives in
`@firmlab/core` and is unit-tested. External tools (binwalk, radare2/Ghidra, QEMU, Renode, syft/grype,
gitleaks, chipsec, AFL++, angr, gdb-multiarch…) are providers behind runtime detection, so the product degrades
gracefully instead of hard-failing when a tool is absent. This is the inverse of a tool-first design: the
workbench is useful with nothing installed and *better* with the full image.

**Static analysis on upload, cached.** The moment an image lands, the API runs the core bundle
(`analyzeImageBuffer`) and persists identity + analysis JSON. Every view then loads instantly from cache; the
image bytes are only re-read for extraction/emulation. Entropy uses an adaptive window so the sample count
stays ~2048 regardless of image size.

**Jobs for anything slow.** Extraction, SBOM, emulation and everything else that shells out runs as a
persisted job (`providers/jobs.ts`): a SQLite row moving queued → running → done/error with streamed log
lines, bounded by `FIRMLAB_MAX_CONCURRENT_JOBS` (default 2), so the UI polls status without blocking a
request. Completed results survive a restart. Queued/running rows do too, but their process-local executable
closures do not: startup marks those jobs as interrupted and the operator must retry them; FirmLab does not
claim to resume work it cannot rehydrate.

**The proof-state discipline.** Every finding carries an explicit `ProofState`, decided by code — never by a
model — and an empty findings list never means "clean": `providers/coverage.ts` computes, per image, which
stages the device class routes to, which actually ran, and states what the count does and does not cover. This
is the project's central invariant; see `CLAUDE.md` for the full state machine.

**Emulation as a ranked ladder.** A deterministic preflight turns identity (+ extracted rootfs, + installed
emulators) into ranked, arch-aware recipes and the honest proof-state ceiling each can claim: qemu-user →
chroot+libnvram → full-system (firmadyne, boots real firmware) → Renode (RTOS/MCU) → chipsec (UEFI, offline).
The runner only claims what it actually reproduced.

**Local-only, enforced in three places.** The API defaults to `127.0.0.1`; the Vite dev server binds
loopback; the compose publish is `127.0.0.1:8799:8799`. In Docker the in-container bind is `0.0.0.0` (required
for port publishing) but `FIRMLAB_LOOPBACK_PUBLISH=1` keeps the health/indicator honest. `FIRMLAB_AGENT`,
`FIRMLAB_RESEARCH` and `FIRMLAB_CAPTURE` are three separate, independent flags — each is the only thing that
turns on its own kind of network access, and turning all three off leaves a deterministic, offline workbench.

## The three "corpora" — one word, three unrelated things

The name is overloaded in the code, the CLI and the docs, and the three have nothing to do with each other. Where
the context does not make it obvious, use the qualified name:

| Qualified name | What it is | Where it lives |
|---|---|---|
| **persistent corpus** (*corpus persistente*) | cross-image occurrences — which credential, component or artifact appears in which image — read back as PRIORS, never as conclusions | `apps/api/src/corpus.ts`, tables `*_occurrence` / `reachability_prior` in `firmlab.db` |
| **validation corpus** (*corpus de validación*) | the locked set of firmware samples the coverage matrix and its gates are measured over | `ops/corpus/validation-samples.lock.json`, `scripts/corpus-matrix.mjs`, `scripts/corpus-campaign.mjs` |
| **YARA rule corpus** (*corpus de reglas YARA*) | the pinned third-party + local rule set the scanner applies | `ops/yara/corpus.lock.json`, `scripts/sync-yara-corpus.sh` |

`pnpm corpus:matrix`, `corpus:campaign` and `corpus:reindex` are not one family: the first two are the validation
corpus, the third rebuilds the persistent one. The CLI names are kept as they are — they are in muscle memory and
in `docs/` — so the disambiguation lives here and in each module's own header.

## Data model

The core tables in `firmlab.db` (SQLite, WAL): `images` (identity + analysis JSON, cached per upload), `jobs`
(queued/running/done/error, streamed log, result JSON — one row per provider run), `findings` (the ledger every
provider writes to via `syncFindings`, one `source` per provider so re-runs are idempotent), `binaries`
(per-ELF inventory), `agent_sessions` (the agent's auditable/resumable transcripts), and the persistent-corpus
tables (`*_occurrence`, `reachability_prior` — see "The three corpora" above). `store.ts` owns the schema and
is the only module allowed to import `node:sqlite`.

## Extending

The exact recipe for adding a signature, tool, provider or analysis view — including why pure decision logic
has to live in a module that doesn't import `store.js` — is kept in one place, `CLAUDE.md`'s "Adding things"
section, rather than duplicated here where it would drift.
