# syntax=docker/dockerfile:1
#
# FirmLab base image — the static-analysis workbench (structure map, entropy, strings/secrets, identity,
# filesystem model, emulation planner). Runs with NO firmware toolchain: the @firmlab/core engine is pure
# TypeScript. For real extraction/decompilation/emulation, build Dockerfile.firmware, which layers the heavy
# tools on top of this image.
#
# Local-only: the API binds 127.0.0.1 inside the container; docker-compose publishes it to the host loopback.

# === Stage 1: build the monorepo ===
FROM node:22-bookworm-slim AS build
WORKDIR /app
# Non-interactive: pnpm 11 otherwise aborts a modules-dir purge for lack of a TTY during the build step.
ENV CI=true
RUN corepack enable
COPY pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
RUN pnpm install --frozen-lockfile=false
COPY . .
RUN pnpm --filter @firmlab/core run build \
  && pnpm --filter @firmlab/api run build \
  && pnpm --filter @firmlab/web run build

# === Stage 2: runtime ===
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
# Local-only by default; override FIRMLAB_HOST only if you understand the exposure.
ENV FIRMLAB_HOST=0.0.0.0
ENV FIRMLAB_PORT=8799
ENV FIRMLAB_DATA_DIR=/data
ENV FIRMLAB_WEB_DIST=/app/apps/web/dist

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/core/dist ./packages/core/dist
COPY --from=build /app/packages/core/package.json ./packages/core/
COPY --from=build /app/apps/api/dist ./apps/api/dist
COPY --from=build /app/apps/api/package.json ./apps/api/
# Ghidra headless post-script (used only when the optional Ghidra layer is present; harmless otherwise).
COPY --from=build /app/apps/api/ghidra-scripts ./apps/api/ghidra-scripts
# Integration test harness (run in the firmware image: node apps/api/scripts/integration.mjs).
COPY --from=build /app/apps/api/scripts ./apps/api/scripts
# pnpm workspace: the API's runtime deps live in apps/api/node_modules (symlinks into the root .pnpm store),
# not the hoisted root node_modules — copy them so @fastify/* et al. resolve at runtime.
COPY --from=build /app/apps/api/node_modules ./apps/api/node_modules
COPY --from=build /app/apps/web/dist ./apps/web/dist

VOLUME /data
EXPOSE 8799
CMD ["node", "apps/api/dist/index.js"]
