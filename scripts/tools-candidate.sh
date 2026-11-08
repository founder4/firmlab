#!/usr/bin/env bash
#
# Build and validate a tools-base CANDIDATE under its own unique tag — and stop there.
#
# Why this exists beside `deploy.sh --tools`: that path is the promotion path. Even with --build-only it retags
# `firmlab-tools:latest` the moment its guards pass, and it takes the recipe's private bases (the retained pre-trixie
# tools, the Renode build) only by their default names. A host that no longer holds those names could not produce
# a Debian 13 candidate at all, and the only way to try one was a command that also promotes it. This script is
# the half that does not promote: it builds one disposable tag, runs exactly the checks deploy.sh would run before
# promoting (same library, same 28-probe table pinned to apps/api/src/tools.ts), and writes down what it was built
# from and what it answered. It never runs `docker tag`, compose, or anything against a running container.
#
# What a passing report proves, and what it does not. It proves the candidate is the Debian release it claims, kept
# every capability the baseline answered under bounded offline probes, and carries a valid Grype database that is
# not the baseline's final layer. It does NOT prove each tool works: the real-container smoke (integration,
# FreeRTOS, security-runtime-smoke.py; docs/DEPLOYMENT.md) is still required, and promotion remains a separate,
# operator decision taken through deploy.sh.
#
# Usage:
#   scripts/tools-candidate.sh --tag REPO:TAG [--baseline REF] [--recipe FILE]
#                              [--retained REF] [--renode REF] [--report DIR] [--allow-dirty]
#
#   --tag       the candidate's tag. Must name an explicit, non-`latest` tag that does not exist yet and is not a
#               shared ref (firmlab-tools, firmlab-firmware, firmlab, homelab-rollback/*, homelab-candidate/*).
#   --baseline  image whose inventory the candidate must not regress (default: firmlab-tools:latest)
#   --recipe    Dockerfile (default: Dockerfile.trixie)
#   --retained  local image for the recipe's RETAINED_IMAGE build ARG (default: the recipe's own default)
#   --renode    local image for the recipe's RENODE_IMAGE build ARG    (default: the recipe's own default)
#   --report    directory for inputs.tsv, inventory-*.txt and verdict.txt (default: a new mktemp directory)
#
# Env: GRYPE_DB_REFRESH  explicit cache key for the recipe's final Grype layer (default: candidate-<UTC timestamp>)
#
# Exit status: 0 accepted, 1 refused before or during the build, 4 built but rejected (the tag is left for
# inspection — it is unique by construction, so leaving it cannot shadow anything).
set -Eeuo pipefail

trap 'status=$?; printf "\033[1;31m[x]\033[0m tools-candidate.sh abortó en la línea %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2' ERR

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG=""
BASELINE="firmlab-tools:latest"
RECIPE="Dockerfile.trixie"
REPORT=""
ALLOW_DIRTY=0
# Overrides as `NAME=ref` lines: macOS still ships bash 3.2, which has no associative arrays.
OVERRIDES=""

usage() { sed -n '19,36p' "${BASH_SOURCE[0]}"; }
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --tag)         TAG="${2:?--tag needs a value}"; shift 2 ;;
    --baseline)    BASELINE="${2:?--baseline needs a value}"; shift 2 ;;
    --recipe)      RECIPE="${2:?--recipe needs a value}"; shift 2 ;;
    --retained)    OVERRIDES+="RETAINED_IMAGE=${2:?--retained needs a value}"$'\n'; shift 2 ;;
    --renode)      OVERRIDES+="RENODE_IMAGE=${2:?--renode needs a value}"$'\n'; shift 2 ;;
    --report)      REPORT="${2:?--report needs a value}"; shift 2 ;;
    --allow-dirty) ALLOW_DIRTY=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
  esac
done

# shellcheck source=scripts/tools-candidate-lib.sh
. "$REPO_ROOT/scripts/tools-candidate-lib.sh"

# The refusal is by NAME, before Docker is asked anything: a candidate tag that collides with a shared ref would
# silently move it at `docker build -t`, which is a promotion by another name.
candidate_tag_refusal() {
  local tag="$1" name repo
  shift
  [ -n "$tag" ] || { echo "falta --tag"; return 0; }
  case "$tag" in *@*) echo "$tag es un digest, no una etiqueta"; return 0 ;; esac
  name="${tag##*/}"
  case "$name" in *:*) ;; *) echo "$tag no nombra una etiqueta explícita (docker usaría :latest)"; return 0 ;; esac
  [ "${name##*:}" != latest ] || { echo "$tag usa :latest, que es la etiqueta que consumen los despliegues"; return 0; }
  repo="${tag%:*}"
  repo="${repo#docker.io/}"
  repo="${repo#library/}"
  case "$repo" in
    firmlab-tools|firmlab-firmware|firmlab|homelab-rollback/*|homelab-candidate/*)
      echo "$tag está en un repositorio compartido ($repo); una candidata vive en su propio repositorio"; return 0 ;;
  esac
  local other
  for other in "$@"; do
    [ "$tag" != "$other" ] || { echo "$tag es también una de las imágenes de entrada"; return 0; }
  done
}

cd "$REPO_ROOT"
[ -f "$RECIPE" ] || die "no existe la receta $RECIPE"

override_for() { awk -F= -v n="$1" '$1 == n { v = substr($0, length(n) + 2) } END { print v }' <<< "$OVERRIDES"; }
# shellcheck disable=SC2046  # one input ref per line, none contains whitespace
REFUSAL="$(candidate_tag_refusal "$TAG" "$BASELINE" $(cut -s -d= -f2- <<< "$OVERRIDES"))"
[ -z "$REFUSAL" ] || die "$REFUSAL; no se construye"
if docker image inspect "$TAG" >/dev/null 2>&1; then
  die "$TAG ya existe; una candidata nunca sobrescribe una etiqueta (elige otra)"
fi

if [ -n "$(git status --porcelain --untracked-files=normal)" ] && [ "$ALLOW_DIRTY" -eq 0 ]; then
  die "árbol sucio: la candidata debe salir de un commit; usa --allow-dirty para una prueba local (se sella -dirty)"
fi
REVISION="$(git rev-parse HEAD)"
[ -z "$(git status --porcelain --untracked-files=normal)" ] || REVISION="${REVISION}-dirty"

# Resolve every `FROM ${ARG}` base: an override replaces the recipe default, and an override for an ARG the recipe
# does not take is refused rather than silently ignored (a typo would otherwise build from the default name).
BASES=""
BUILD_ARGS=()
while IFS='=' read -r arg default; do
  [ -n "$arg" ] || continue
  ref="$(override_for "$arg")"
  [ -z "$ref" ] || BUILD_ARGS+=(--build-arg "$arg=$ref")
  ref="${ref:-$default}"
  [ -n "$ref" ] || die "$RECIPE toma una imagen base de $arg sin valor por defecto ni sustitución; no se construye"
  docker image inspect "$ref" >/dev/null 2>&1 \
    || die "falta la imagen local $ref ($arg); no se deja que BuildKit la busque en un registro"
  BASES+="$arg=$ref"$'\n'
done < <(recipe_base_args "$RECIPE")
while IFS='=' read -r arg _; do
  [ -n "$arg" ] || continue
  grep -q "^$arg=" <<< "$BASES" || die "$RECIPE no toma ninguna base de $arg; se rechaza la sustitución"
done <<< "$OVERRIDES"
[ -z "$BASES" ] || require_docker_driver "$RECIPE"

if [ -z "$REPORT" ]; then
  REPORT="$(mktemp -d "${TMPDIR:-/tmp}/firmlab-tools-candidate.XXXXXX")"
fi
mkdir -p "$REPORT"
image_id() { docker image inspect "$1" --format '{{.Id}}'; }
{
  printf 'role\tref\tid\n'
  printf 'revision\t%s\t-\n' "$REVISION"
  printf 'recipe\t%s\t%s\n' "$RECIPE" "$(git hash-object "$RECIPE")"
  while IFS='=' read -r arg ref; do
    [ -z "$arg" ] || printf '%s\t%s\t%s\n' "$arg" "$ref" "$(image_id "$ref")"
  done <<< "$BASES"
} > "$REPORT/inputs.tsv"

BASELINE_DEBIAN=""
BASELINE_INVENTORY=""
BASELINE_LAYER=""
if docker image inspect "$BASELINE" >/dev/null 2>&1; then
  printf 'baseline\t%s\t%s\n' "$BASELINE" "$(image_id "$BASELINE")" >> "$REPORT/inputs.tsv"
  BASELINE_DEBIAN="$(image_debian_major "$BASELINE")" || die "no se pudo leer /etc/os-release de $BASELINE"
  BASELINE_LAYER="$(image_last_layer "$BASELINE")"
  say "inventariando offline la base $BASELINE (Debian ${BASELINE_DEBIAN:-desconocido})"
  BASELINE_INVENTORY="$(image_capabilities "$BASELINE")" || exit 1
  printf '%s\n' "$BASELINE_INVENTORY" > "$REPORT/inventory-baseline.txt"
else
  warn "no existe $BASELINE: sin inventario de referencia, la candidata sólo se describe, no se compara"
  printf 'baseline\t%s\tabsent\n' "$BASELINE" >> "$REPORT/inputs.tsv"
fi

GRYPE_DB_REFRESH="${GRYPE_DB_REFRESH:-candidate-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
IID_FILE="$REPORT/candidate.iid"
say "construyendo la candidata $TAG con $RECIPE (no se promociona)"
docker build --iidfile "$IID_FILE" -t "$TAG" \
  --label "org.opencontainers.image.revision=$REVISION" \
  --build-arg "GRYPE_DB_REFRESH=$GRYPE_DB_REFRESH" ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} -f "$RECIPE" .
CANDIDATE="$(tr -d '\r\n' < "$IID_FILE")"
case "$CANDIDATE" in sha256:*) ;; *) die "docker build no dejó un ID de imagen válido en $IID_FILE" ;; esac
printf 'candidate\t%s\t%s\n' "$TAG" "$CANDIDATE" >> "$REPORT/inputs.tsv"
printf 'grype_db_refresh\t%s\t-\n' "$GRYPE_DB_REFRESH" >> "$REPORT/inputs.tsv"

# From here on every failure is a REJECTION of a built image, recorded in the verdict, not a refusal to build.
REASONS=()
CANDIDATE_DEBIAN="$(image_debian_major "$CANDIDATE")" || die "no se pudo leer /etc/os-release de $CANDIDATE"
if [ -z "$CANDIDATE_DEBIAN" ]; then
  REASONS+=("la candidata no declara una versión Debian reconocible")
elif [ -n "$BASELINE_DEBIAN" ] && [ "$CANDIDATE_DEBIAN" -lt "$BASELINE_DEBIAN" ]; then
  REASONS+=("la candidata es Debian $CANDIDATE_DEBIAN y $BASELINE es Debian $BASELINE_DEBIAN")
fi
say "inventariando offline la candidata $CANDIDATE (Debian ${CANDIDATE_DEBIAN:-desconocido})"
CANDIDATE_INVENTORY="$(image_capabilities "$CANDIDATE")" || exit 1
printf '%s\n' "$CANDIDATE_INVENTORY" > "$REPORT/inventory-candidate.txt"
printf '%s\n' "$CANDIDATE_INVENTORY" | sed 's/^/    /'
if [ -n "$BASELINE_INVENTORY" ]; then
  REGRESSIONS="$(capability_regressions "$BASELINE_INVENTORY" "$CANDIDATE_INVENTORY")"
  [ -z "$REGRESSIONS" ] || REASONS+=("perdió capacidades que $BASELINE sí tenía: $(printf '%s' "$REGRESSIONS" | tr '\n' ';')")
fi
say "verificando offline la base Grype de la candidata"
if ! docker run --rm --network none \
  -e GRYPE_DB_AUTO_UPDATE=false -e GRYPE_CHECK_FOR_APP_UPDATE=false -e GRYPE_DB_VALIDATE_AGE=false \
  "$CANDIDATE" \
  bash -c 'set -o pipefail; grype db status && test -n "$(find "$GRYPE_DB_CACHE_DIR" -name vulnerability.db -size +100M -print -quit)"' \
  > "$REPORT/grype-db-status.txt" 2>&1; then
  REASONS+=("la base Grype no es válida offline (grype-db-status.txt)")
fi
CANDIDATE_LAYER="$(image_last_layer "$CANDIDATE")"
if [ -z "$CANDIDATE_LAYER" ]; then
  REASONS+=("no se pudo identificar la última capa de la candidata")
elif [ -n "$BASELINE_LAYER" ] && [ "$CANDIDATE_LAYER" = "$BASELINE_LAYER" ]; then
  REASONS+=("la capa final de Grype es la misma que la de $BASELINE")
fi

if [ "${#REASONS[@]}" -gt 0 ]; then
  { echo "rejected"; printf -- '- %s\n' "${REASONS[@]}"; } > "$REPORT/verdict.txt"
  printf '\033[1;31m[x]\033[0m candidata %s rechazada:\n' "$TAG" >&2
  printf '    %s\n' "${REASONS[@]}" >&2
  say "informe en $REPORT"
  exit 4
fi
{
  echo "accepted"
  echo "- Debian $CANDIDATE_DEBIAN, inventario sin regresiones, base Grype válida offline, capa final nueva"
  echo "- falta el smoke real (integración, FreeRTOS, security-runtime-smoke.py) y la promoción es otra decisión"
} > "$REPORT/verdict.txt"
warn "el inventario prueba presencia y respuesta acotada, no que cada herramienta funcione: ejecuta el smoke real"
say "candidata $TAG ($CANDIDATE) aceptada sin promoción; informe en $REPORT"
