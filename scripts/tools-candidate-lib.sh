# shellcheck shell=bash
#
# Image facts and the offline capability inventory shared by scripts/deploy.sh (which may promote a tools candidate)
# and scripts/tools-candidate.sh (which never does). One copy, because the probe table is pinned against
# apps/api/src/tools.ts by scripts/deploy-grype-refresh.test.mjs, and two copies would let the script that promotes
# and the script that only validates disagree about what "the candidate kept every tool" means.
#
# Sourced, never executed. The caller defines `die` and runs under `set -Eeuo pipefail`.
# Inventory failures return nonzero with stderr diagnostics; callers own exit status and verdict publication.
image_last_layer() {
  docker image inspect "$1" --format '{{range .RootFS.Layers}}{{println .}}{{end}}' \
    | awk 'NF { last = $0 } END { if (last != "") print last }'
}

# The Debian major an image actually runs, from its /etc/os-release — never inferred from a tag. Empty when the image
# is not a Debian the recipes know, which callers treat as "do not choose a recipe blind".
image_debian_major() {
  docker run --rm --network none --entrypoint cat "$1" /etc/os-release \
    | awk -F= '{ gsub(/"/, "", $2) } $1 == "ID" { id = $2 } $1 == "VERSION_ID" { v = $2 }
               END { if (id == "debian" && v ~ /^[0-9]+$/) print v }'
}

# Every FROM that takes its image from a global build ARG names a locally supplied base (the retained pre-trixie
# tools, the Renode build). Those names exist on no registry, so when one is missing BuildKit resolves it on Docker
# Hub instead — where anyone may publish `homelab-rollback/firmlab-tools`. Print each one as `NAME=default`, in
# recipe order, so the caller can refuse before the build starts; public bases are pinned by digest in the recipe
# itself. An empty default (`NAME=`) is refused unless the caller supplies the ARG.
recipe_base_args() {
  awk '
    toupper($1) == "ARG" && !from_seen { split($2, kv, "="); defaults[kv[1]] = substr($2, length(kv[1]) + 2) }
    toupper($1) == "FROM" {
      from_seen = 1
      ref = ($2 ~ /^--platform=/) ? $3 : $2
      if (ref ~ /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/) { gsub(/[${}]/, "", ref); print ref "=" defaults[ref] }
    }
  ' "$1"
}

recipe_local_bases() {
  recipe_base_args "$1" | cut -d= -f2-
}

# Only the `docker` driver reads the local image store; a docker-container builder would pull the same names.
require_docker_driver() {
  local driver
  driver="$(docker buildx inspect 2>/dev/null | awk '$1 == "Driver:" { print $2; exit }' || true)"
  [ -z "$driver" ] || [ "$driver" = docker ] \
    || die "el builder activo usa el driver '$driver', que no ve las imágenes locales de $1; usa el builder 'docker'"
}

require_local_bases() {
  local base found=0
  while IFS= read -r base; do
    found=1
    [ -n "$base" ] || die "$1 toma una imagen base de un ARG sin valor por defecto; no se construye"
    docker image inspect "$base" >/dev/null 2>&1 \
      || die "falta la imagen local $base que exige $1; restáurala (docs/DEPLOYMENT.md, base Debian 13) — no se deja que BuildKit la busque en un registro"
  done < <(recipe_local_bases "$1")
  [ "$found" -eq 1 ] || return 0
  require_docker_driver "$1"
}

# The capability inventory a tools candidate must not regress. It mirrors TOOLS in apps/api/src/tools.ts — id, probe
# budget in seconds ('-' = presence only, as `detectByExistence`) and the exact probe command — and
# scripts/deploy-grype-refresh.test.mjs fails when the two tables drift. It answers what the Capabilities panel would
# report, which is presence and a prompt answer: NOT that the tool works. analyzeHeadless in particular is only found
# on PATH, so the real-container smoke (docs/DEPLOYMENT.md) remains required before promotion.
TOOL_PROBES="$(cat <<'EOF'
binwalk 4 binwalk --help
unsquashfs 4 unsquashfs -help
sasquatch 4 sasquatch -help
jefferson 4 jefferson --help
lzop 4 lzop --version
ubireader_extract_files 4 ubireader_extract_files --help
cpio 4 cpio --version
radare2 4 radare2 -v
analyzeHeadless - analyzeHeadless
syft 4 syft version
grype 4 grype version
gitleaks 4 gitleaks version
qemu-mipsel-static 4 qemu-mipsel-static -version
qemu-mips-static 4 qemu-mips-static -version
qemu-arm-static 4 qemu-arm-static -version
qemu-aarch64-static 4 qemu-aarch64-static -version
qemu-system-mips 4 qemu-system-mips -version
qemu-system-mipsel 4 qemu-system-mipsel -version
qemu-system-arm 4 qemu-system-arm -version
qemu-system-aarch64 4 qemu-system-aarch64 -version
mkfs.ext2 4 mkfs.ext2 -V
renode 4 renode --version
chipsec 4 chipsec_util --help
angr 30 "${FIRMLAB_ANGR_PYTHON:-python3}" -c 'import angr; print("angr", angr.__version__)'
yara 4 yara --version
openssl 4 openssl version
gdb-multiarch 4 gdb-multiarch --version
fwhunt 15 "${FIRMLAB_FWHUNT_PYTHON:-python3}" -c 'import fwhunt_scan, rzpipe; print("fwhunt-scan ok")'
EOF
)"

# Runs inside the image under --network none and prints `<id> ok|present|missing|timeout|error [detail]` per probe.
# Each probe is bounded by coreutils timeout (TERM at its budget, KILL 2 s later), so a hung tool cannot hold the
# deploy; an image without `timeout` is refused outright rather than reported as missing every tool.
# shellcheck disable=SC2016  # expanded inside the container, not here
PROBE_SCRIPT='
command -v timeout >/dev/null 2>&1 || { echo "la imagen no tiene timeout: no se puede acotar ningún sondeo" >&2; exit 3; }
while read -r id budget probe; do
  [ -n "$id" ] || continue
  eval "set -- $probe"
  if [ "$budget" = - ]; then
    if command -v "$1" >/dev/null 2>&1; then echo "$id present (solo presencia: no se ejecuta)"; else echo "$id missing"; fi
    continue
  fi
  status=0
  timeout -k 2 "$budget" "$@" </dev/null >/dev/null 2>&1 || status=$?
  case "$status" in
    0) echo "$id ok" ;;
    124|137) echo "$id timeout ${budget}s" ;;
    127) echo "$id missing" ;;
    *) echo "$id error exit=$status" ;;
  esac
done <<< "$1"
'

image_capabilities() {
  local inventory
  inventory="$(docker run --rm --network none \
    -e GRYPE_DB_AUTO_UPDATE=false -e GRYPE_DB_VALIDATE_AGE=false \
    -e GRYPE_CHECK_FOR_APP_UPDATE=false -e SYFT_CHECK_FOR_APP_UPDATE=false \
    --entrypoint bash "$1" -c "$PROBE_SCRIPT" probe "$TOOL_PROBES")" \
    || { echo "no se pudo inventariar offline las capacidades de $1" >&2; return 1; }
  # A probe loop that died half way must not read as "the rest are missing".
  [ "$(awk '{ print $1 }' <<< "$inventory")" = "$(awk '{ print $1 }' <<< "$TOOL_PROBES")" ] \
    || { echo "inventario incompleto de $1: $(awk 'NF' <<< "$inventory" | wc -l | tr -d ' ') de $(awk 'NF' <<< "$TOOL_PROBES" | wc -l | tr -d ' ') sondeos" >&2; return 1; }
  awk '$2 != "ok" && $2 != "present" && $2 != "missing" && $2 != "timeout" && $2 != "error" { bad=1 }
       END { exit bad }' <<< "$inventory" || { echo "inventario con estados desconocidos de $1" >&2; return 1; }
  printf '%s\n' "$inventory"
}

# Lines of the candidate inventory for every tool the current image answered and the candidate does not.
capability_regressions() {
  awk 'NR == FNR { if ($2 == "ok" || $2 == "present") had[$1] = 1; next }
       ($1 in had) && $2 != "ok" && $2 != "present" { $1 = $1; print }' <(printf '%s\n' "$1") <(printf '%s\n' "$2")
}

# Candidate-only strict identity and builder checks. deploy.sh keeps its historical unknown-driver compatibility.
valid_candidate_id() { [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]; }
candidate_image_id() {
  local id
  id="$(docker image inspect "$1" --format '{{.Id}}')" || return 1
  valid_candidate_id "$id" || return 1
  printf '%s\n' "$id"
}
candidate_last_layer() {
  local layer
  layer="$(image_last_layer "$1")" || return 1
  valid_candidate_id "$layer" || return 1
  printf '%s\n' "$layer"
}
candidate_docker_builder() {
  local facts driver name
  facts="$(docker buildx inspect 2>/dev/null)" || return 1
  driver="$(awk '$1 == "Driver:" { print $2; exit }' <<< "$facts")"
  name="$(awk '$1 == "Name:" { print $2; exit }' <<< "$facts")"
  [ "$driver" = docker ] && [ -n "$name" ] || { echo "builder desconocido o driver no local: ${driver:-unknown}" >&2; return 1; }
  printf '%s\n' "$name"
}

# Candidate recipes may use local ARG bases, earlier stages, scratch, or digest-pinned external bases.
# An unrecognised FROM expression must not silently escape the local-input guard. This does not change deploy.
candidate_recipe_sources_known() {
  awk '
    toupper($1) == "FROM" {
      i = ($2 ~ /^--platform=/) ? 3 : 2
      ref = $i
      if (ref == "") { bad=1; next }
      variable = ref ~ /^\$[A-Za-z_][A-Za-z0-9_]*$/ || ref ~ /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/
      digest = ref; sub(/^.*@sha256:/, "", digest)
      pinned = ref ~ /@sha256:/ && length(digest) == 64 && digest !~ /[^0-9a-f]/
      if (!(variable || ref == "scratch" || (ref in stages) || pinned)) {
        print "FROM no reconocido o sin digest: " ref > "/dev/stderr"; bad=1
      }
      if (toupper($(i+1)) == "AS") stages[$(i+2)]=1
      count++
    }
    END { exit (bad || !count) }
  ' "$1"
}

# A candidate recipe must be a HEAD-tracked regular file inside this physical worktree. Canonicalize the
# parent once so a symlinked parent cannot redirect Docker later; never dereference a recipe symlink.
# Tracked local edits remain supported under --allow-dirty. New/external/ignored-untracked recipes need a commit.
candidate_recipe_path() {
  local requested="$1" parent relative mode
  [ -f "$requested" ] && [ ! -L "$requested" ] || return 1
  parent="$(cd "$(dirname "$requested")" && pwd -P)" || return 1
  relative="$parent/$(basename "$requested")"
  case "$relative" in "$REPO_ROOT"/*) relative="${relative#"$REPO_ROOT"/}" ;; *) return 1 ;; esac
  case "$relative" in *$'\t'*|*$'\n'*) return 1 ;; esac
  mode="$(git ls-tree HEAD -- ":(literal)$relative" | awk '{ print $1 }')" || return 1
  case "$mode" in 100644|100755) ;; *) return 1 ;; esac
  git ls-files --error-unmatch -- ":(literal)$relative" >/dev/null 2>&1 || return 1
  printf '%s\n' "$relative"
}

recipe_bytes_unchanged() {
  [ ! -L "$RECIPE" ] && [ -f "$RECIPE" ] || return 1
  [ "$(candidate_recipe_path "$RECIPE")" = "$RECIPE" ] || return 1
  [ "$(git hash-object --no-filters -- "$RECIPE")" = "$RECIPE_HASH" ]
}

# Normalize only Docker Hub's supported host aliases and implicit library/latest spelling. Other registries
# stay distinct. This name guard complements Docker's actual existing-ref inspection; it does not replace it.
candidate_normalized_ref() {
  local ref="$1" repo name
  case "$ref" in docker.io/*) ref="${ref#docker.io/}" ;;
    index.docker.io/*) ref="${ref#index.docker.io/}" ;;
    registry-1.docker.io/*) ref="${ref#registry-1.docker.io/}" ;; esac
  name="${ref##*/}"
  case "$name" in *:*) ;; *) ref="$ref:latest" ;; esac
  repo="${ref%:*}"
  case "$repo" in library/*) ref="${ref#library/}" ;; esac
  printf '%s\n' "$ref"
}

# Include tracked content/modes/deletions and untracked nonignored content/names/modes (also symlink targets).
# Git's binary diff supplies the tracked portion. Optional recipe bytes also bypass Git filters/status hints.
# No source path is expanded through shell word splitting.
source_fingerprint() {
  {
    if [ -n "${1:-}" ]; then
      printf 'recipe\0%s\0' "$1"
      git hash-object --no-filters -- "$1" || return 1
    fi
    git diff --binary --no-ext-diff --no-textconv HEAD -- || return 1
    git ls-files --others --exclude-standard -z | while IFS= read -r -d '' file; do
      printf 'untracked\0%s\0' "$file"
      if [ -L "$file" ]; then
        printf 'symlink\0'; readlink "$file" || return 1
      elif [ -f "$file" ]; then
        if [ -x "$file" ]; then printf '100755\0'; else printf '100644\0'; fi
        git hash-object --no-filters -- "$file" || return 1
      else
        return 1
      fi
    done
  } | shasum -a 256 | awk '{ print $1 }'
}

# A bounded offline status check. JSON fields must describe a known valid database, and the recorded file must
# actually be present and substantial. Presence/status is not a vulnerability scan; the synthetic fixture is separate.
verify_candidate_grype() {
  local check
  check="$(cat <<'GRYPE_CHECK'
set -euo pipefail
status=$(grype db status -o json)
printf '%s\n' "$status"
printf '%s' "$status" | python3 -c '
import json, re, sys, os
s = json.load(sys.stdin)
assert s.get("valid") is True
assert isinstance(s.get("schemaVersion"), str) and re.fullmatch(r"v?[0-9]+(?:\.[0-9]+)*", s["schemaVersion"])
assert isinstance(s.get("built"), str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", s["built"])
p = s.get("path")
assert isinstance(p, str) and os.path.isfile(p) and os.path.getsize(p) > 100 * 1024 * 1024
'
GRYPE_CHECK
)"
  docker run --rm --network none \
    -e GRYPE_DB_AUTO_UPDATE=false -e GRYPE_CHECK_FOR_APP_UPDATE=false -e GRYPE_DB_VALIDATE_AGE=false \
    --entrypoint timeout "$1" -k 2 30 bash -c "$check"
}
