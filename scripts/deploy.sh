#!/usr/bin/env bash
#
# FirmLab deploy — build, tag and roll out in a single step.
#
# Why this script exists: the image chain is two-stage (firmlab:latest -> firmlab-firmware:latest) and the
# homelab compose consumes the `:latest` tag. Building by hand under some other tag and forgetting to promote
# it silently leaves the old image serving — which is exactly what happened on 2026-07-18 (see
# docs/DEPLOYMENT.md). Here build and tag are the same action, so they cannot drift apart.
#
# Every image is stamped with the git commit it was built from, so what is running is always answerable:
#   docker inspect firmlab --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
#
# Usage:
#   scripts/deploy.sh                 build + deploy + verify
#   scripts/deploy.sh --check         report drift only, change nothing
#   scripts/deploy.sh --build-only    build and tag, do not touch the running container
#   scripts/deploy.sh --allow-dirty   permit building from a dirty working tree (stamped -dirty)
#
# Env overrides:
#   COMPOSE_FILE   compose file to roll out   (default: ~/homelab/firmlab/docker-compose.yml)
#   CONTAINER      container name to verify   (default: firmlab)
#   BASE_IMAGE     base image tag             (default: firmlab:latest)
#   FW_IMAGE       firmware image tag         (default: firmlab-firmware:latest)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$HOME/homelab/firmlab/docker-compose.yml}"
CONTAINER="${CONTAINER:-firmlab}"
BASE_IMAGE="${BASE_IMAGE:-firmlab:latest}"
FW_IMAGE="${FW_IMAGE:-firmlab-firmware:latest}"
REVISION_LABEL='org.opencontainers.image.revision'

CHECK_ONLY=0
BUILD_ONLY=0
ALLOW_DIRTY=0
for arg in "$@"; do
  case "$arg" in
    --check)       CHECK_ONLY=1 ;;
    --build-only)  BUILD_ONLY=1 ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    -h|--help)     sed -n '3,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown flag: $arg (try --help)" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

cd "$REPO_ROOT"

# --- what we are about to ship -------------------------------------------------------------------
HEAD_SHA="$(git rev-parse HEAD)"
HEAD_REF="$(git rev-parse --abbrev-ref HEAD)"
DIRTY=0
git diff --quiet && git diff --cached --quiet || DIRTY=1
REVISION="$HEAD_SHA"
[ "$DIRTY" -eq 1 ] && REVISION="${HEAD_SHA}-dirty"

# The 2026-07-18 failure in one guard: work that lives only on another branch is not what you are
# deploying. Surface any branch that is ahead of HEAD instead of letting it stay invisible.
AHEAD="$(git for-each-ref --format='%(refname:short)' refs/heads \
  | while read -r ref; do
      [ "$ref" = "$HEAD_REF" ] && continue
      if git merge-base --is-ancestor HEAD "$ref" 2>/dev/null; then
        n="$(git rev-list --count "HEAD..$ref")"
        # A branch pointing at the same commit is not ahead — only report real divergence.
        if [ "$n" -gt 0 ]; then echo "  $ref (+$n commits)"; fi
      fi
    done || true)"

say "repo      $REPO_ROOT"
say "commit    $HEAD_SHA ($HEAD_REF)$([ "$DIRTY" -eq 1 ] && echo ' — DIRTY')"
if [ -n "$AHEAD" ]; then
  warn "hay ramas por delante de HEAD — ¿seguro que despliegas lo que quieres?"
  printf '%s\n' "$AHEAD" >&2
fi

# --- drift report --------------------------------------------------------------------------------
running_revision() {
  docker inspect "$CONTAINER" --format "{{index .Config.Labels \"$REVISION_LABEL\"}}" 2>/dev/null || true
}

RUNNING_REV="$(running_revision)"
if [ -n "$RUNNING_REV" ]; then
  if [ "$RUNNING_REV" = "$REVISION" ]; then
    say "desplegado  $RUNNING_REV (al día)"
  else
    warn "desplegado  ${RUNNING_REV:-<sin sellar>} != repo $REVISION  → DESFASADO"
  fi
else
  warn "el contenedor '$CONTAINER' no está sellado (imagen anterior a este script) o no existe"
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  exit 0
fi

if [ "$DIRTY" -eq 1 ] && [ "$ALLOW_DIRTY" -eq 0 ]; then
  die "árbol sucio: commitea, descarta, o usa --allow-dirty (se sellará como -dirty)"
fi

# --- build: tagging is part of the build, never a separate step you can forget --------------------
say "construyendo $BASE_IMAGE"
docker build --label "$REVISION_LABEL=$REVISION" -t "$BASE_IMAGE" .

say "construyendo $FW_IMAGE"
docker build --label "$REVISION_LABEL=$REVISION" -f Dockerfile.firmware -t "$FW_IMAGE" .

BUILT_ID="$(docker image inspect "$FW_IMAGE" --format '{{.Id}}')"
say "imagen      $BUILT_ID"

if [ "$BUILD_ONLY" -eq 1 ]; then
  say "--build-only: no se toca el contenedor"
  exit 0
fi

# --- roll out ------------------------------------------------------------------------------------
[ -f "$COMPOSE_FILE" ] || die "no existe el compose: $COMPOSE_FILE (usa COMPOSE_FILE=...)"
say "desplegando con $COMPOSE_FILE"
docker compose -f "$COMPOSE_FILE" up -d

# --- verify: the container must run the image we just built, and be healthy -----------------------
say "esperando healthcheck..."
for _ in $(seq 1 60); do
  status="$(docker inspect "$CONTAINER" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || echo missing)"
  case "$status" in
    healthy|none) break ;;
    unhealthy)    die "el contenedor arrancó unhealthy — revisa: docker logs $CONTAINER" ;;
  esac
  sleep 2
done
[ "$status" = "healthy" ] || [ "$status" = "none" ] || die "el healthcheck no pasó a healthy (estado: $status)"

RUN_ID="$(docker inspect "$CONTAINER" --format '{{.Image}}')"
[ "$RUN_ID" = "$BUILT_ID" ] || die "el contenedor corre $RUN_ID pero se construyó $BUILT_ID — el tag no llegó"

RUNNING_REV="$(running_revision)"
[ "$RUNNING_REV" = "$REVISION" ] || die "sello desplegado ($RUNNING_REV) != repo ($REVISION)"

say "OK — $CONTAINER healthy, corriendo $REVISION"
