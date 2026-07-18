# FirmLab

A **local-only firmware analysis workbench**. Upload a firmware image and get an immediate visual breakdown:
a binwalk-style **structure map**, an **entropy graph**, inferred **identity** (class / arch / endianness /
filesystems), **secret & credential** hits, the extracted **root filesystem tree**, and an arch-aware
**simulation menu** for emulating the image.

FirmLab is a focused sibling of a larger pentest platform, carved down to the firmware domain and rebuilt
around **visualization** and **interactive emulation**. It is designed to run on your machine in Docker and is
**never** meant to be exposed to the internet — the API binds to loopback and the container publish is
loopback-only.

## Why it works without heavy tools

The analysis engine (`@firmlab/core`) is pure TypeScript: entropy profiling, magic-signature carving, the
structure map, identity inference, and secret extraction all run with **zero external dependencies**. So the
workbench gives real value the moment it starts — even on a laptop with nothing installed.

External tools are **optional enhancements**, auto-detected at runtime:

| Tool | Unlocks |
|---|---|
| `binwalk` | Format-aware carving + real filesystem extraction |
| `unsquashfs` / `sasquatch` / `jefferson` / `ubireader` | Filesystem extraction per type |
| `radare2` / Ghidra `analyzeHeadless` | Binary triage + decompilation |
| `syft` / `grype` | SBOM + N-day CVE matching |
| `gitleaks` | Deep secret scan of the extracted rootfs |
| `qemu-*-static` / `qemu-system-*` / `renode` | User-mode, full-system, and RTOS emulation |

The **Capabilities** page shows exactly what the current deployment has.

## Quick start (Docker — recommended)

```bash
# Static-analysis workbench (no firmware toolchain, tiny image):
docker compose up --build
# → http://127.0.0.1:8799   (loopback only)

# Full capabilities (binwalk, QEMU, radare2, syft/grype, gitleaks):
docker build -t firmlab:latest .
docker build -f Dockerfile.firmware -t firmlab-firmware .
# then set `image: firmlab-firmware` in docker-compose.yml and `docker compose up`
```

For the homelab rollout (build + tag + deploy + verify in one step), use `scripts/deploy.sh` — see
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), which also documents how to tell which commit is running.

## Quick start (local dev)

```bash
pnpm install
pnpm --filter @firmlab/core build          # build the engine (web + api consume it)

# terminal 1 — API on 127.0.0.1:8799
pnpm --filter @firmlab/api build && pnpm dev:api

# terminal 2 — web dev server on 127.0.0.1:5174 (proxies /api → :8799)
pnpm dev:web
```

## Tour

- **Dashboard** — drag-drop a firmware image; it's analyzed locally on upload.
- **Overview** — inferred class/arch/filesystems, signature + secret counts, entropy signal.
- **Structure** — the binwalk graphical view: a proportional, color-by-category ribbon of the image.
- **Entropy** — Shannon entropy across offset, high-entropy bands shaded, 7.2 compressed/encrypted floor.
- **Filesystem** — run extraction (needs binwalk), then browse the recovered rootfs; setuid binaries badged.
- **Secrets** — hardcoded credentials, private keys, tokens, connection strings, vendor default markers.
- **Simulation** — arch/class-aware ranked emulation recipes (user-mode QEMU, full-system QEMU, Renode), each
  showing whether it's runnable here and the exact command; launch a user-mode proof against the rootfs.

## Architecture

```
packages/core   @firmlab/core — pure analysis engine (entropy, signatures, structure, strings, filesystem)
apps/api        @firmlab/api  — Fastify + node:sqlite; intake, cached analysis, jobs, providers, emulation
apps/web        @firmlab/web  — Vite + React; the visual workbench
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the deeper design, and
[`docs/AGENT-DESIGN.md`](docs/AGENT-DESIGN.md) for the planned autonomous-orchestration layer (an optional,
flag-gated agent that drives the providers as tools while the deterministic core stays the source of truth).

## Safety

Defensive / research tool. Analyze only firmware you own or are authorized to assess. FirmLab binds to
loopback by design — do not change the publish binding to expose it.
