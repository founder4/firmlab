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
# from and what it answered. It creates only fresh private input aliases, never promotes, and never touches
# a running container.
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
#   --report    new directory for inputs.tsv, inventory-*.txt and verdict.txt (default: mktemp; reuse is refused)
#
# Env: GRYPE_DB_REFRESH  explicit cache key for the recipe's final Grype layer (default: candidate-<UTC timestamp>)
#
# Exit status: 0 accepted, 1 refused before or during the build, 4 built but rejected (the tag is left for
# inspection — it is unique by construction, so leaving it cannot shadow anything).
set -Eeuo pipefail
BUILT=0

# Unexpected post-build failures have the same durable rejection contract as explicit validation failures.
on_error() {
  local status="$1" line="$2" command="$3"
  if [ "$BUILT" -eq 1 ]; then
    reject_candidate "falló la validación en línea $line (exit $status): $command"
  fi
  printf '[x] tools-candidate.sh abortó en línea %s (exit %s): %s\n' "$line" "$status" "$command" >&2
}
trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG=""
BASELINE="firmlab-tools:latest"
RECIPE="Dockerfile.trixie"
REPORT=""
ALLOW_DIRTY=0
# Overrides as `NAME=ref` lines: macOS still ships bash 3.2, which has no associative arrays.
OVERRIDES=""

usage() { sed -n '/^# Usage:/,/^# Exit status:/p' "${BASH_SOURCE[0]}"; }
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { [ "$BUILT" -eq 0 ] || reject_candidate "$*"; printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

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
  repo="${repo#index.docker.io/}"
  repo="${repo#registry-1.docker.io/}"
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

# Each invocation owns a fresh report. An old accepted verdict must never describe a failed new attempt.
if [ -z "$REPORT" ]; then
  REPORT="$(mktemp -d "${TMPDIR:-/tmp}/firmlab-tools-candidate.XXXXXX")"
else
  [ ! -e "$REPORT" ] || die "el informe $REPORT ya existe; elige un directorio nuevo (no se reutiliza un veredicto)"
  mkdir -p "$(dirname "$REPORT")"
  mkdir "$REPORT"
fi

write_verdict() {
  local state="$1"
  shift
  { printf '%s\n' "$state"; printf -- '- %s\n' "$@"; } > "$REPORT/verdict.tmp"
  mv "$REPORT/verdict.tmp" "$REPORT/verdict.txt"
}
reject_candidate() {
  write_verdict rejected "$@"
  printf '[x] candidata %s rechazada: %s\n' "$TAG" "$*" >&2
  say "informe en $REPORT"
  exit 4
}

if [ -n "$(git status --porcelain --untracked-files=normal)" ] && [ "$ALLOW_DIRTY" -eq 0 ]; then
  die "árbol sucio: usa --allow-dirty para sellar también el contenido local"
fi
REVISION="$(git rev-parse HEAD)"
SOURCE_FINGERPRINT="$(source_fingerprint)"
[ -z "$(git status --porcelain --untracked-files=normal)" ] || REVISION="${REVISION}-dirty-${SOURCE_FINGERPRINT}"

# Resolve the baseline exactly once. Every fact and probe below uses that immutable image ID.
BASELINE_ID="$(candidate_image_id "$BASELINE")" || die "no existe una referencia local válida para la base $BASELINE"
BASELINE_DEBIAN="$(image_debian_major "$BASELINE_ID")" || die "no se pudo leer /etc/os-release de $BASELINE"
case "$BASELINE_DEBIAN" in 12|13) ;; *) die "la base $BASELINE no declara una versión Debian compatible (12/13)" ;; esac
BASELINE_LAYER="$(candidate_last_layer "$BASELINE_ID")" || die "no se pudo leer la capa final de $BASELINE"
[ -n "$BASELINE_LAYER" ] || die "la base $BASELINE no tiene una capa final reconocible"
say "inventariando offline la base $BASELINE_ID (Debian $BASELINE_DEBIAN)"
BASELINE_INVENTORY="$(image_capabilities "$BASELINE_ID")" || die "inventario de referencia incompleto o inválido"
printf '%s\n' "$BASELINE_INVENTORY" > "$REPORT/inventory-baseline.txt"

# The raw sha256 ID is NOT a usable FROM on the tested BuildKit (it resolves docker.io/library/sha256).
# Freeze each ARG behind a fresh private alias; validate the alias before and after the build. These names are
# never reused or overwritten. Docker has no atomic create-if-absent tag API: this assumes a non-hostile daemon.
BASES=""
BUILD_ARGS=()
while IFS='=' read -r arg default; do
  [ -n "$arg" ] || continue
  ref="$(override_for "$arg")"
  ref="${ref:-$default}"
  [ -n "$ref" ] || die "$RECIPE toma una imagen base de $arg sin valor por defecto ni sustitución; no se construye"
  id="$(candidate_image_id "$ref")" \
    || die "falta la imagen local válida $ref ($arg); no se deja que BuildKit la busque en un registro"
  BASES+="$arg"$'\t'"$ref"$'\t'"$id"$'\n'
done < <(recipe_base_args "$RECIPE")
while IFS='=' read -r arg _; do
  [ -n "$arg" ] || continue
  awk -F '\t' -v n="$arg" '$1 == n { found=1 } END { exit !found }' <<< "$BASES" \
    || die "$RECIPE no toma ninguna base de $arg; se rechaza la sustitución"
done <<< "$OVERRIDES"
candidate_recipe_sources_known "$RECIPE" || die "la receta no declara todas sus bases de forma verificable"
# Unlike deploy's historical compatibility path, a candidate refuses unknown builders too.
BUILDER="$(candidate_docker_builder)" || die "no se pudo verificar un builder local con driver docker"
ALIAS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/firmlab-candidate-input.XXXXXXXX")"
ALIAS_TOKEN="$(basename "$ALIAS_DIR" | tr '[:upper:]' '[:lower:]')-$$"
ALIASES=""
while IFS=$'\t' read -r arg ref id; do
  [ -n "$arg" ] || continue
  alias="firmlab-candidate-input/$ALIAS_TOKEN:$(printf '%s' "$arg" | tr '[:upper:]' '[:lower:]')"
  docker image inspect "$alias" >/dev/null 2>&1 && die "el alias privado $alias ya existe; no se sobrescribe"
  docker tag "$id" "$alias"
  [ "$(candidate_image_id "$alias")" = "$id" ] || die "el alias $alias no conserva $id"
  ALIASES+="$arg"$'\t'"$alias"$'\t'"$id"$'\n'
  BUILD_ARGS+=(--build-arg "$arg=$alias")
done <<< "$BASES"
rmdir "$ALIAS_DIR"
{
  printf 'role\tref\tid\n'
  printf 'revision\t%s\t-\n' "$REVISION"
  printf 'source_fingerprint\tsha256\t%s\n' "$SOURCE_FINGERPRINT"
  printf 'recipe\t%s\t%s\n' "$RECIPE" "$(git hash-object "$RECIPE")"
  printf 'builder\t%s\tdocker\n' "$BUILDER"
  printf 'baseline\t%s\t%s\n' "$BASELINE" "$BASELINE_ID"
  printf '%s' "$BASES"
  while IFS=$'\t' read -r arg alias id; do
    [ -z "$arg" ] || printf '%s_build_ref\t%s\t%s\n' "$arg" "$alias" "$id"
  done <<< "$ALIASES"
} > "$REPORT/inputs.tsv"

verify_aliases() {
  local arg alias id actual
  while IFS=$'\t' read -r arg alias id; do
    [ -n "$arg" ] || continue
    actual="$(candidate_image_id "$alias")" || return 1
    [ "$actual" = "$id" ] || return 1
  done <<< "$ALIASES"
}
verify_aliases || die "cambió una entrada privada antes de construir"
[ "$(source_fingerprint)" = "$SOURCE_FINGERPRINT" ] || die "cambió el contenido fuente antes de construir"
GRYPE_DB_REFRESH="${GRYPE_DB_REFRESH:-candidate-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
IID_FILE="$REPORT/candidate.iid"
say "construyendo la candidata $TAG con $RECIPE (no se promociona)"
docker build --builder "$BUILDER" --pull=false --iidfile "$IID_FILE" -t "$TAG" \
  --label "org.opencontainers.image.revision=$REVISION" \
  --build-arg "GRYPE_DB_REFRESH=$GRYPE_DB_REFRESH" ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} -f "$RECIPE" .
BUILT=1
CANDIDATE="$(tr -d '\r\n' < "$IID_FILE")"
valid_candidate_id "$CANDIDATE" || reject_candidate "docker build no dejó un ID de imagen válido en $IID_FILE"
printf 'candidate\t%s\t%s\n' "$TAG" "$CANDIDATE" >> "$REPORT/inputs.tsv"
printf 'grype_db_refresh\t%s\t-\n' "$GRYPE_DB_REFRESH" >> "$REPORT/inputs.tsv"

REASONS=()
verify_aliases || REASONS+=("cambió una entrada privada durante la construcción; identidad no verificada")
[ "$(source_fingerprint)" = "$SOURCE_FINGERPRINT" ] || REASONS+=("cambió el contenido fuente durante la construcción")
[ "$(candidate_image_id "$TAG")" = "$CANDIDATE" ] || REASONS+=("la etiqueta candidata no conserva el ID construido")
CANDIDATE_DEBIAN=""
if ! CANDIDATE_DEBIAN="$(image_debian_major "$CANDIDATE")"; then
  REASONS+=("no se pudo leer /etc/os-release de la candidata")
elif [ "$CANDIDATE_DEBIAN" != 12 ] && [ "$CANDIDATE_DEBIAN" != 13 ]; then
  REASONS+=("la candidata no declara una versión Debian reconocible")
elif [ "$CANDIDATE_DEBIAN" -lt "$BASELINE_DEBIAN" ]; then
  REASONS+=("la candidata es Debian $CANDIDATE_DEBIAN y $BASELINE es Debian $BASELINE_DEBIAN")
fi
say "inventariando offline la candidata $CANDIDATE (Debian ${CANDIDATE_DEBIAN:-desconocido})"
if CANDIDATE_INVENTORY="$(image_capabilities "$CANDIDATE")"; then
  printf '%s\n' "$CANDIDATE_INVENTORY" > "$REPORT/inventory-candidate.txt"
  printf '%s\n' "$CANDIDATE_INVENTORY" | sed 's/^/    /'
  REGRESSIONS="$(capability_regressions "$BASELINE_INVENTORY" "$CANDIDATE_INVENTORY")"
  [ -z "$REGRESSIONS" ] || REASONS+=("perdió capacidades que $BASELINE sí tenía: $(printf '%s' "$REGRESSIONS" | tr '\n' ';')")
else
  REASONS+=("no se pudo inventariar la candidata: sondeos incompletos o no acotados (bash/timeout)")
fi
say "verificando offline la base Grype de la candidata"
verify_candidate_grype "$CANDIDATE" > "$REPORT/grype-db-status.txt" 2>&1 \
  || REASONS+=("la base Grype no es válida offline (grype-db-status.txt)")
CANDIDATE_LAYER=""
if ! CANDIDATE_LAYER="$(candidate_last_layer "$CANDIDATE")" || [ -z "$CANDIDATE_LAYER" ]; then
  REASONS+=("no se pudo identificar la última capa de la candidata")
elif [ "$CANDIDATE_LAYER" = "$BASELINE_LAYER" ]; then
  REASONS+=("la capa final de Grype es la misma que la de $BASELINE")
fi
[ "${#REASONS[@]}" -eq 0 ] || reject_candidate "${REASONS[@]}"
write_verdict accepted \
  "Debian $CANDIDATE_DEBIAN, inventario sin regresiones, base Grype válida offline, capa final nueva respecto a $BASELINE_ID" \
  "falta el smoke real (integración, FreeRTOS, security-runtime-smoke.py) y la promoción es otra decisión"
warn "el inventario prueba presencia y respuesta acotada, no que cada herramienta funcione: ejecuta el smoke real"
say "candidata $TAG ($CANDIDATE) aceptada sin promoción; informe en $REPORT"
