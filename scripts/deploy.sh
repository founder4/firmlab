#!/usr/bin/env bash
#
# FirmLab deploy — build, tag and roll out in a single step.
#
# Why this script exists: the homelab compose consumes the `firmlab-firmware:latest` tag, so building by hand under
# some other tag and forgetting to promote it silently leaves the OLD image serving — which is exactly what happened
# on 2026-07-18 (see docs/DEPLOYMENT.md). Here build + tag + roll-out + verify are one action, so they cannot drift.
#
# Inverted layering: the heavy toolchain lives in the firmlab-tools base (Dockerfile.tools); the deploy image
# (Dockerfile.firmware) is just the built app copied ON TOP of it. So a normal app change rebuilds only the thin
# app layer — the multi-GB tools are cached. The tools base is rebuilt only on `--tools` (or when it is missing).
# `--tools` rebuilds with the recipe matching the Debian release of the existing tools image (12 → Dockerfile.tools,
# 13 → Dockerfile.trixie) and refuses any candidate older than it, or one that lost a tool the current image had.
# It PROMOTES on success, even with --build-only: to build and validate a candidate without promoting it, use
# scripts/tools-candidate.sh, which applies the same checks under a unique tag and never retags anything.
#
# Every image is stamped with the git commit it was built from (a label AND the FIRMLAB_BUILD env → /health):
#   docker inspect firmlab --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
#   curl -s .../health | jq .build
#
# Usage:
#   scripts/deploy.sh                 build app image + deploy + verify (uses the existing tools base)
#   scripts/deploy.sh --tools         ALSO rebuild the firmlab-tools base first (heavy; when a tool recipe changed)
#   scripts/deploy.sh --check         report drift + port squatters only, change nothing
#   scripts/deploy.sh --build-only    build and tag, do not touch the running container
#   scripts/deploy.sh --allow-dirty   permit a dirty --build-only image (stamped with its content fingerprint)
#
# Env overrides:
#   COMPOSE_FILE   compose file to roll out   (default: ~/homelab/firmlab/docker-compose.yml)
#   CONTAINER      container name to verify   (default: firmlab)
#   TOOLS_IMAGE    tools base image tag       (default: firmlab-tools:latest)
#   FW_IMAGE       deploy image tag           (default: firmlab-firmware:latest)
#   GRYPE_DB_REFRESH  explicit Grype DB cache key for --tools (default: current UTC timestamp)

# `-E` is the load-bearing letter. `set -e` kills the script wherever a command returns non-zero and by default
# does so SILENTLY — the anti-squatter guard died on an lsof that simply found nothing, and the only symptom was
# three lines of output and an exit code, which took a `bash -x` session to locate. An ERR trap fixes that, but a
# plain `trap … ERR` is NOT inherited by shell functions, subshells or command substitutions, which is precisely
# where that abort happened: the first version of this line printed nothing for the very bug it was written for.
# `-E` (errtrace) propagates it. Aborting is still right; being quiet about it is not.
set -Eeuo pipefail

trap 'status=$?; printf "\033[1;31m[x]\033[0m deploy.sh abortó en la línea %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2' ERR

TOOLS_IID_FILE=""
cleanup() {
  if [ -n "$TOOLS_IID_FILE" ]; then
    rm -f -- "$TOOLS_IID_FILE"
  fi
}
trap cleanup EXIT

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$HOME/homelab/firmlab/docker-compose.yml}"
CONTAINER="${CONTAINER:-firmlab}"
TOOLS_IMAGE="${TOOLS_IMAGE:-firmlab-tools:latest}"
FW_IMAGE="${FW_IMAGE:-firmlab-firmware:latest}"
REVISION_LABEL='org.opencontainers.image.revision'

CHECK_ONLY=0
BUILD_ONLY=0
ALLOW_DIRTY=0
REBUILD_TOOLS=0
for arg in "$@"; do
  case "$arg" in
    --check)       CHECK_ONLY=1 ;;
    --build-only)  BUILD_ONLY=1 ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    --tools)       REBUILD_TOOLS=1 ;;
    -h|--help)     sed -n '3,34p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown flag: $arg (try --help)" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# Image facts, the local-base guard and the 28-probe offline inventory live beside this script so
# tools-candidate.sh validates a candidate by exactly the rules this script promotes one by.
# shellcheck source=scripts/tools-candidate-lib.sh
. "$REPO_ROOT/scripts/tools-candidate-lib.sh"

cd "$REPO_ROOT"

# --- what we are about to ship -------------------------------------------------------------------
HEAD_SHA="$(git rev-parse HEAD)"
HEAD_REF="$(git rev-parse --abbrev-ref HEAD)"
DIRTY=0
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  DIRTY=1
fi
REVISION="$HEAD_SHA"
if [ "$DIRTY" -eq 1 ]; then
  # `HEAD-dirty` is not an identity: every uncommitted tree on the same commit receives that same string, and the
  # old --check therefore called two different builds "up to date". Hash the complete tracked diff plus every
  # untracked, non-ignored file. The path is part of each untracked entry so equal bytes at different destinations
  # are different trees. `git hash-object --stdin` keeps this portable anywhere Git itself can run.
  DIRTY_FINGERPRINT="$({
    git diff --binary HEAD
    while IFS= read -r -d '' file; do
      printf 'untracked %s %s\n' "$(git hash-object "$file")" "$file"
    done < <(git ls-files --others --exclude-standard -z)
  } | git hash-object --stdin | cut -c1-12)"
  REVISION="${HEAD_SHA}-dirty-${DIRTY_FINGERPRINT}"
fi

# The 2026-07-18 failure in one guard: work that lives only on another branch is not what you are
# deploying. Surface any branch that is ahead of HEAD instead of letting it stay invisible.
AHEAD="$(git for-each-ref --format='%(refname:short)' refs/heads \
  | while read -r ref; do
      [ "$ref" = "$HEAD_REF" ] && continue
      if git merge-base --is-ancestor HEAD "$ref" 2>/dev/null; then
        n="$(git rev-list --count "HEAD..$ref")"
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

# --- port squatter: something OTHER than the container answering on 8799 -------------------------
# The compose publishes NO host port (Traefik reaches the container over proxy_net), so anything listening on
# host:8799 is by definition not this deployment. A leftover `pnpm dev:api` there is the worst kind of stale: it
# serves a plausible-looking FirmLab from an old tree and an old DB, so you verify a deploy against the wrong
# process and believe it. Docker's own forwarder (docker-proxy / com.docker.backend) is exempt — that IS a
# published container port, which only means the compose was changed to publish one.
check_port_squatter() {
  local port="${1:-8799}" listeners=""
  # `|| true` is load-bearing: lsof exits 1 when NOTHING matches, and under `set -euo pipefail` that status
  # propagates out of the assignment and aborts the script — so a CLEAN port killed the deploy while a squatted
  # one sailed through. The guard was only ever exercised against the zombie it was written for, so it shipped
  # with its success path inverted and stayed invisible until the zombie was killed. "No listeners" is the normal
  # answer here, not a failure.
  if command -v lsof >/dev/null 2>&1; then
    listeners="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $1" (pid "$2", user "$3")"}' | sort -u || true)"
  elif command -v ss >/dev/null 2>&1; then
    listeners="$(ss -lptnH "sport = :$port" 2>/dev/null | sed 's/.*users:((//; s/)).*//' | tr -d '"' | sort -u || true)"
  else
    return 0  # no way to look: say nothing rather than imply the port is clean
  fi
  [ -n "$listeners" ] || return 0

  # A host-networked container (the capture lane) listens on host:$port ITSELF, so the listener is this
  # deployment, not a squatter. A real zombie still cannot hide: the container would fail to bind and the health
  # check below would not see the new build.
  if [ "$(docker inspect "$CONTAINER" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null || true)" = host ]; then
    return 0
  fi

  local foreign
  foreign="$(printf '%s\n' "$listeners" | grep -viE 'docker-proxy|com\.docker|vpnkit' || true)"
  if [ -n "$foreign" ]; then
    warn "algo AJENO al contenedor escucha en el puerto $port:"
    printf '%s\n' "$foreign" | sed 's/^/    /' >&2
    warn "el compose no publica puertos, así que eso NO es este deploy — un 'pnpm dev:api' zombi sirve un"
    warn "FirmLab creíble desde otro árbol y otra DB. Mátalo antes de verificar nada contra localhost:$port."
  fi
}
check_port_squatter 8799

if [ "$CHECK_ONLY" -eq 1 ]; then
  exit 0
fi

if [ "$DIRTY" -eq 1 ] && [ "$BUILD_ONLY" -eq 0 ]; then
  die "árbol sucio: un despliegue debe salir de un commit reproducible; usa --build-only --allow-dirty sólo para una imagen local"
fi
if [ "$DIRTY" -eq 1 ] && [ "$ALLOW_DIRTY" -eq 0 ]; then
  die "árbol sucio: commitea o usa --build-only --allow-dirty (se sellará con la huella del contenido)"
fi

# --- build: tagging is part of the build, never a separate step you can forget --------------------
# The tools base is heavy; build it only when asked (--tools) or when it does not exist yet. An explicit --tools
# means "refresh and prove the baked catalogue": its volatile cache key invalidates only the recipe's final Grype
# layer, and the network-disabled verification must pass before the firmware image can be built. The first
# automatic build of a missing tools image keeps the optional-tool contract — a failed DB bake remains an honest
# degraded image rather than making an otherwise useful first deployment impossible — but only where nothing newer
# would be replaced: Dockerfile.tools is Debian 12, so a missing tag beside a Debian 13 deployment is refused.
TOOLS_PRESENT=0
if docker image inspect "$TOOLS_IMAGE" >/dev/null 2>&1; then
  TOOLS_PRESENT=1
else
  RUNNING_IMAGE="$(docker inspect "$CONTAINER" --format '{{.Image}}' 2>/dev/null || true)"
  if [ -n "$RUNNING_IMAGE" ]; then
    RUNNING_DEBIAN="$(image_debian_major "$RUNNING_IMAGE")" \
      || die "no se pudo leer la versión Debian de la imagen que corre $CONTAINER ($RUNNING_IMAGE)"
    [ -n "$RUNNING_DEBIAN" ] && [ "$RUNNING_DEBIAN" -le 12 ] \
      || die "falta $TOOLS_IMAGE y $CONTAINER corre Debian ${RUNNING_DEBIAN:-desconocido}: restaura la etiqueta de su base en vez de construir Dockerfile.tools (Debian 12)"
  fi
fi

if [ "$REBUILD_TOOLS" -eq 1 ]; then
  GRYPE_DB_REFRESH="${GRYPE_DB_REFRESH:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
  CURRENT_TOOLS_LAYER=""
  CURRENT_DEBIAN=""
  CURRENT_INVENTORY=""
  if [ "$TOOLS_PRESENT" -eq 1 ]; then
    CURRENT_TOOLS_LAYER="$(image_last_layer "$TOOLS_IMAGE")"
    [ -n "$CURRENT_TOOLS_LAYER" ] || die "no se pudo identificar la última capa de $TOOLS_IMAGE"
    CURRENT_DEBIAN="$(image_debian_major "$TOOLS_IMAGE")" || die "no se pudo leer /etc/os-release de $TOOLS_IMAGE"
    [ -n "$CURRENT_DEBIAN" ] || die "$TOOLS_IMAGE no declara una versión Debian reconocible; no se elige receta a ciegas"
  fi
  case "$CURRENT_DEBIAN" in
    ''|12) TOOLS_DOCKERFILE=Dockerfile.tools ;;
    13)    TOOLS_DOCKERFILE=Dockerfile.trixie ;;
    *)     die "$TOOLS_IMAGE es Debian $CURRENT_DEBIAN y ninguna receta lo reconstruye sin cambiar de versión" ;;
  esac
  require_local_bases "$TOOLS_DOCKERFILE"
  if [ "$TOOLS_PRESENT" -eq 1 ]; then
    say "inventariando offline las capacidades de $TOOLS_IMAGE (Debian $CURRENT_DEBIAN)"
    CURRENT_INVENTORY="$(image_capabilities "$TOOLS_IMAGE")" || exit 1
  fi
  say "construyendo $TOOLS_IMAGE con $TOOLS_DOCKERFILE (base pesada de tools)"
  TOOLS_IID_FILE="$(mktemp "${TMPDIR:-/tmp}/firmlab-tools-iid.XXXXXX")"
  docker build --iidfile "$TOOLS_IID_FILE" --build-arg "GRYPE_DB_REFRESH=$GRYPE_DB_REFRESH" -f "$TOOLS_DOCKERFILE" .
  TOOLS_CANDIDATE="$(tr -d '\r\n' < "$TOOLS_IID_FILE")"
  case "$TOOLS_CANDIDATE" in
    sha256:*) ;;
    *) die "docker build no dejó un ID de imagen válido en $TOOLS_IID_FILE" ;;
  esac
  CANDIDATE_DEBIAN="$(image_debian_major "$TOOLS_CANDIDATE")" || die "no se pudo leer /etc/os-release de $TOOLS_CANDIDATE"
  [ -n "$CANDIDATE_DEBIAN" ] || die "$TOOLS_CANDIDATE no declara una versión Debian reconocible"
  if [ -n "$CURRENT_DEBIAN" ] && [ "$CANDIDATE_DEBIAN" -lt "$CURRENT_DEBIAN" ]; then
    die "la candidata es Debian $CANDIDATE_DEBIAN y $TOOLS_IMAGE es Debian $CURRENT_DEBIAN; no se degrada la base"
  fi
  say "inventariando offline las capacidades de la candidata $TOOLS_CANDIDATE (Debian $CANDIDATE_DEBIAN)"
  CANDIDATE_INVENTORY="$(image_capabilities "$TOOLS_CANDIDATE")" || exit 1
  printf '%s\n' "$CANDIDATE_INVENTORY" | sed 's/^/    /'
  if [ -n "$CURRENT_INVENTORY" ]; then
    REGRESSIONS="$(capability_regressions "$CURRENT_INVENTORY" "$CANDIDATE_INVENTORY")"
    [ -z "$REGRESSIONS" ] \
      || die "la candidata perdió capacidades que $TOOLS_IMAGE sí tenía: $(printf '%s' "$REGRESSIONS" | tr '\n' ';'); no se promociona"
  fi
  warn "el inventario prueba presencia y respuesta acotada, no que cada herramienta funcione: ejecuta el smoke real antes de desplegar"
  say "verificando offline la base Grype candidata $TOOLS_CANDIDATE"
  docker run --rm --network none \
    -e GRYPE_DB_AUTO_UPDATE=false \
    -e GRYPE_CHECK_FOR_APP_UPDATE=false \
    -e GRYPE_DB_VALIDATE_AGE=false \
    "$TOOLS_CANDIDATE" \
    bash -c 'set -o pipefail; grype db status >/dev/null && test -n "$(find "$GRYPE_DB_CACHE_DIR" -name vulnerability.db -size +100M -print -quit)"'
  CANDIDATE_TOOLS_LAYER="$(image_last_layer "$TOOLS_CANDIDATE")"
  [ -n "$CANDIDATE_TOOLS_LAYER" ] || die "no se pudo identificar la última capa de $TOOLS_CANDIDATE"
  if [ -n "$CURRENT_TOOLS_LAYER" ] && [ "$CANDIDATE_TOOLS_LAYER" = "$CURRENT_TOOLS_LAYER" ]; then
    die "la capa final de Grype no cambió; se conserva $TOOLS_IMAGE sin promover la candidata"
  fi
  docker tag "$TOOLS_CANDIDATE" "$TOOLS_IMAGE"
  rm -f -- "$TOOLS_IID_FILE"
  TOOLS_IID_FILE=""
elif [ "$TOOLS_PRESENT" -eq 0 ]; then
  say "construyendo $TOOLS_IMAGE (base pesada de tools; no existía)"
  docker build -f Dockerfile.tools -t "$TOOLS_IMAGE" .
else
  say "reusando $TOOLS_IMAGE (usa --tools para reconstruirla)"
fi

say "construyendo $FW_IMAGE (app sobre la base de tools, rev $REVISION)"
docker build --label "$REVISION_LABEL=$REVISION" --build-arg "GIT_SHA=$REVISION" \
  --build-arg "TOOLS_IMAGE=$TOOLS_IMAGE" -f Dockerfile.firmware -t "$FW_IMAGE" .

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

# --- verify: the container must run the image we just built, be healthy, and serve this revision --
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

# Poll, never ask once: with no HEALTHCHECK in the image the wait above exits on its first pass (status `none`), so
# a single request here landed before the server was listening and warned `/health build ()` on EVERY deploy —
# a verification that could never confirm the build it exists to confirm.
SERVED_BUILD=""
for _ in $(seq 1 30); do
  SERVED_BUILD="$(docker exec "$CONTAINER" sh -c 'curl -fsS http://127.0.0.1:8799/health' 2>/dev/null | grep -o '"build":"[^"]*"' | cut -d'"' -f4 || true)"
  [ -n "$SERVED_BUILD" ] && break
  sleep 1
done
[ "$SERVED_BUILD" = "$REVISION" ] || warn "/health build ($SERVED_BUILD) != $REVISION (el sello del label sí coincide)"

say "OK — $CONTAINER healthy, corriendo $REVISION (/health build: ${SERVED_BUILD:-?})"
